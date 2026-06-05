//! TRON DNS-tree peer discovery.
//!
//! Parity target: `org.tron.p2p.dns.sync.Client` + `org.tron.p2p.dns.tree.*`
//! from tronprotocol/libp2p. The third peer-discovery source alongside
//! config-supplied seeds and Kademlia DHT (the only one that actually
//! works through arbitrary NATs without seeds responding to UDP).
//!
//! ## URL format
//!
//! ```text
//!   tree://{base32_compressed_pubkey}@{domain}
//! ```
//!
//! The pubkey signs the root entry. The domain is queried for TXT
//! records that form a Merkle-DAG of peer endpoints.
//!
//! ## Tree shape (all TXT records under one domain)
//!
//! ```text
//!   {domain}        → "tree-root-v1:{base64(DnsRoot proto)}"
//!   {hash}.{domain} → "tree-branch:{hash1},{hash2},..." (interior)
//!                   | "nodes:{base64(EndPoints proto)}"  (leaf)
//!                   | "tree://..."                       (link to another tree)
//! ```
//!
//! Where each `{hash}` is `base32(keccak256(child_entry_text)[..16])[..26]`.
//!
//! ## Implementation choices vs java-tron
//!
//! * **Root signature: verified, fail-open (N-15).** Java-tron signs the
//!   root's secp256k1 signature over the Java-protobuf `textFormat` of
//!   the inner `TreeRoot` message. [`verify_root_signature`] reconstructs
//!   that content and checks the signature recovers the tree's compressed
//!   pubkey (carried base32 in the URL). Because the exact Java textFormat
//!   can't be validated against the live tree offline, a mismatch
//!   currently **logs a loud warning and continues** rather than
//!   rejecting — discovery is a *hint*, and every peer is still validated
//!   at the TCP handshake (genesis / chain check, see N-5/N-30). To make
//!   it fail-closed, have [`resolve`] return `DnsError::InvalidRoot` on
//!   the `Err` arm — do that once the format is confirmed against the
//!   live mainnet tree (`live_dns_tree.rs`), or it would reject the real
//!   tree on a format mismatch.
//! * **No link-tree following.** Tree URLs encountered in entries are
//!   logged and skipped. Mainnet's main tree is self-contained and
//!   doesn't appear to use link-trees in production.
//! * **No periodic refresh.** Like our kad bootstrap, [`resolve`] is
//!   one-shot at startup. The mainnet tree is updated rarely (sequence
//!   numbers tick at human-scale rates), so re-resolving every node
//!   restart is acceptable. Adding a refresh loop is straightforward
//!   if/when needed.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use prost::Message;
use tracing::{debug, warn};
use tron_proto::{DnsRoot, EndPoints};

use tron_crypto::hash::keccak256;
use tron_crypto::signature::RecoverableSignature;

/// Parsed `tree://{pubkey}@{domain}` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeUrl {
    /// Base32-encoded compressed secp256k1 pubkey (33 bytes → 53 chars
    /// after stripping padding). Used to verify the root signature.
    pub base32_pubkey: String,
    /// DNS domain that hosts the tree (e.g. `main.trondisco.net`).
    pub domain: String,
}

/// Errors surfaced by [`resolve`].
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("invalid tree URL: {0}")]
    InvalidUrl(String),
    #[error("DNS lookup failed for {name}: {err}")]
    LookupFailed { name: String, err: String },
    #[error("DNS record {name} has no TXT entries")]
    NoTxt { name: String },
    #[error("malformed root entry: {0}")]
    InvalidRoot(String),
    #[error("malformed entry at {hash}: {reason}")]
    InvalidEntry { hash: String, reason: String },
}

/// Parse a `tree://{pubkey}@{domain}` URL.
pub fn parse_tree_url(url: &str) -> Result<TreeUrl, DnsError> {
    let rest = url.strip_prefix("tree://").ok_or_else(|| {
        DnsError::InvalidUrl(format!("missing tree:// scheme: {url}"))
    })?;
    let (pubkey, domain) = rest.split_once('@').ok_or_else(|| {
        DnsError::InvalidUrl(format!("missing @ separator: {url}"))
    })?;
    if pubkey.is_empty() || domain.is_empty() {
        return Err(DnsError::InvalidUrl(format!(
            "empty pubkey or domain: {url}"
        )));
    }
    Ok(TreeUrl {
        base32_pubkey: pubkey.to_string(),
        domain: domain.to_string(),
    })
}

/// Java protobuf `TextFormat.escapeBytes`: printable ASCII kept as-is
/// (with `"`, `\`, and whitespace escaped), everything else as `\ooo`
/// octal. Base32 hashes (A-Z, 2-7) pass through unchanged.
fn escape_proto_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03o}")),
        }
    }
    out
}

/// Reconstruct the bytes java-tron signs for the root: the Java-protobuf
/// `TextFormat` of the inner `TreeRoot` message — fields in field-number
/// order (`eRoot`, `lRoot`, `seq`), proto3 defaults omitted, each line
/// terminated by `\n`. `trailing_newline=false` drops the final newline
/// (the one detail of Java's printer we can't confirm offline).
fn tree_root_sign_content(e_root: &[u8], l_root: &[u8], seq: i32, trailing_newline: bool) -> Vec<u8> {
    let mut s = String::new();
    if !e_root.is_empty() {
        s.push_str(&format!("eRoot: \"{}\"\n", escape_proto_bytes(e_root)));
    }
    if !l_root.is_empty() {
        s.push_str(&format!("lRoot: \"{}\"\n", escape_proto_bytes(l_root)));
    }
    if seq != 0 {
        s.push_str(&format!("seq: {seq}\n"));
    }
    if !trailing_newline && s.ends_with('\n') {
        s.pop();
    }
    s.into_bytes()
}

/// Verify the root's secp256k1 signature recovers the compressed pubkey
/// carried (base32, RFC4648, unpadded) in the `tree://` URL. (N-15)
///
/// Returns `Err` with a human-readable reason on any decode/parse/mismatch
/// failure. The caller decides the policy (currently fail-open — see the
/// module docs).
fn verify_root_signature(
    e_root: &[u8],
    l_root: &[u8],
    seq: i32,
    signature: &[u8],
    base32_pubkey: &str,
) -> Result<(), String> {
    let stripped = base32_pubkey.trim_end_matches('=');
    let expected = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, stripped)
        .ok_or_else(|| "base32 pubkey decode failed".to_string())?;
    if expected.len() != 33 {
        return Err(format!(
            "expected 33-byte compressed pubkey, got {}",
            expected.len()
        ));
    }
    let sig =
        RecoverableSignature::from_bytes(signature).map_err(|e| format!("signature parse: {e}"))?;
    // Hedge the one offline-unverifiable detail (Java's trailing newline)
    // by accepting either variant — a forger still needs the real key to
    // produce a valid signature for *either* content.
    for trailing in [true, false] {
        let content = tree_root_sign_content(e_root, l_root, seq, trailing);
        let hash = keccak256(&content);
        if let Ok(uncompressed) = sig.recover_uncompressed_pubkey(&hash) {
            // Compress the recovered key: [0x02|Y-parity] || X.
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02 | (uncompressed[64] & 1);
            compressed[1..].copy_from_slice(&uncompressed[1..33]);
            if compressed[..] == expected[..] {
                return Ok(());
            }
        }
    }
    Err("root signature does not match the tree's pubkey".to_string())
}

/// Walk the tree at `tree_url` and return every IPv4 endpoint found.
///
/// `query_timeout` is per individual DNS lookup; the overall walk takes
/// at most `query_timeout * (branches + 1)`. A well-formed mainnet tree
/// is shallow (a handful of branches, hundreds of leaves), so a 3-5s
/// per-query budget keeps total walk time under 30s in practice.
///
/// Returns `Ok([])` if the tree contains only IPv6 endpoints (we don't
/// dial v6 from the TCP side) or only link entries we can't follow.
pub async fn resolve(
    tree_url: &str,
    query_timeout: Duration,
) -> Result<Vec<SocketAddr>, DnsError> {
    let tree = parse_tree_url(tree_url)?;
    let resolver = build_resolver()
        .map_err(|e| DnsError::LookupFailed {
            name: tree.domain.clone(),
            err: format!("resolver init: {e}"),
        })?;

    // Step 1: fetch root TXT.
    let root_txt = lookup_txt(&resolver, &tree.domain, query_timeout).await?;
    let root_payload = root_txt.strip_prefix("tree-root-v1:").ok_or_else(|| {
        DnsError::InvalidRoot(format!("missing tree-root-v1: prefix: {root_txt}"))
    })?;
    let root_bytes = base64_url_decode(root_payload)
        .map_err(|e| DnsError::InvalidRoot(format!("base64 decode: {e}")))?;
    let dns_root = DnsRoot::decode(&*root_bytes)
        .map_err(|e| DnsError::InvalidRoot(format!("proto decode: {e}")))?;
    let tree_root = dns_root
        .tree_root
        .ok_or_else(|| DnsError::InvalidRoot("missing treeRoot field".into()))?;

    // Verify the root signature recovers the tree's URL pubkey (N-15).
    // Fail-open: a mismatch is logged loudly but we still walk the tree —
    // discovery is a hint and peers are re-validated at the TCP handshake.
    // See module docs for how to make this fail-closed.
    match verify_root_signature(
        &tree_root.e_root,
        &tree_root.l_root,
        tree_root.seq,
        &dns_root.signature,
        &tree.base32_pubkey,
    ) {
        Ok(()) => debug!(domain = tree.domain.as_str(), "dns: root signature verified"),
        Err(e) => warn!(
            domain = tree.domain.as_str(),
            error = %e,
            "dns: root signature NOT verified — proceeding anyway (peers are still validated \
             at the TCP handshake). If this fires against the real mainnet tree, the signed \
             textFormat reconstruction needs adjustment before going fail-closed."
        ),
    }

    let e_root = std::str::from_utf8(&tree_root.e_root)
        .map_err(|_| DnsError::InvalidRoot("eRoot not UTF-8".into()))?
        .to_string();

    debug!(
        domain = tree.domain.as_str(),
        e_root = e_root.as_str(),
        seq = tree_root.seq,
        "dns: root parsed"
    );

    // Step 2: walk the entry-root subtree iteratively (worklist of
    // pending hashes). Branch entries push children onto the queue;
    // node entries flush endpoints to `out`.
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut pending: VecDeque<String> = VecDeque::new();
    pending.push_back(e_root);
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut branches_walked = 0usize;
    let mut leaves_walked = 0usize;

    while let Some(hash) = pending.pop_front() {
        if !visited.insert(hash.clone()) {
            continue;
        }
        let label = format!("{hash}.{}", tree.domain);
        let txt = match lookup_txt(&resolver, &label, query_timeout).await {
            Ok(t) => t,
            Err(e) => {
                warn!(label = label.as_str(), error = ?e, "dns: child lookup failed; continuing");
                continue;
            }
        };

        if let Some(rest) = txt.strip_prefix("tree-branch:") {
            branches_walked += 1;
            for child in rest.split(',') {
                let child = child.trim();
                if !child.is_empty() {
                    pending.push_back(child.to_string());
                }
            }
        } else if let Some(rest) = txt.strip_prefix("nodes:") {
            leaves_walked += 1;
            let payload = rest.trim_matches('"');
            let bytes = match base64_url_decode(payload) {
                Ok(b) => b,
                Err(e) => {
                    warn!(hash = hash.as_str(), error = %e, "dns: nodes entry base64 decode failed");
                    continue;
                }
            };
            let endpoints = match EndPoints::decode(&*bytes) {
                Ok(e) => e,
                Err(e) => {
                    warn!(hash = hash.as_str(), error = %e, "dns: nodes entry proto decode failed");
                    continue;
                }
            };
            for ep in endpoints.nodes {
                if let Some(addr) = parse_ipv4_endpoint(&ep) {
                    out.push(addr);
                }
            }
        } else if txt.starts_with("tree://") {
            // Link to another tree — skip for now (see module doc).
            debug!(hash = hash.as_str(), "dns: link entry skipped");
        } else {
            warn!(hash = hash.as_str(), txt = %&txt[..txt.len().min(60)],
                  "dns: unknown entry type");
        }
    }

    debug!(
        branches = branches_walked,
        leaves = leaves_walked,
        endpoints = out.len(),
        "dns: tree walk complete"
    );

    Ok(out)
}

/// Build a hickory resolver from `/etc/resolv.conf` (Linux/macOS) or
/// the OS-supplied DNS settings. Falls back to a hard-coded Google DNS
/// if the system config is unreadable — DNS-discovery is recoverable,
/// so we prefer "best-effort + log" over "fail startup".
fn build_resolver(
) -> Result<hickory_resolver::AsyncResolver<hickory_resolver::name_server::GenericConnector<hickory_resolver::name_server::TokioRuntimeProvider>>, String> {
    use hickory_resolver::config::*;
    use hickory_resolver::TokioAsyncResolver;
    match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => Ok(r),
        Err(e) => {
            warn!(error = %e, "dns: system resolver init failed; falling back to 8.8.8.8");
            Ok(TokioAsyncResolver::tokio(
                ResolverConfig::google(),
                ResolverOpts::default(),
            ))
        }
    }
}

/// Look up a single TXT record and return its joined string content.
/// TRON DNS entries are short enough to fit in one record but DNS
/// chunks them into ≤255-byte segments, so we concatenate.
async fn lookup_txt(
    resolver: &hickory_resolver::AsyncResolver<
        hickory_resolver::name_server::GenericConnector<
            hickory_resolver::name_server::TokioRuntimeProvider,
        >,
    >,
    name: &str,
    query_timeout: Duration,
) -> Result<String, DnsError> {
    let resp = tokio::time::timeout(query_timeout, resolver.txt_lookup(name))
        .await
        .map_err(|_| DnsError::LookupFailed {
            name: name.into(),
            err: "query timeout".into(),
        })?
        .map_err(|e| DnsError::LookupFailed {
            name: name.into(),
            err: format!("{e}"),
        })?;
    let record = resp.iter().next().ok_or_else(|| DnsError::NoTxt {
        name: name.into(),
    })?;
    let mut out = String::new();
    for chunk in record.iter() {
        out.push_str(&String::from_utf8_lossy(chunk));
    }
    Ok(out)
}

/// Java uses `Base64.getUrlEncoder()` and strips trailing `=` padding.
/// `base64::Engine` standard `URL_SAFE_NO_PAD` decoder matches.
fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Tolerate trailing padding either way — strip then decode unpadded.
    let trimmed = s.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed)
}

/// Build a `SocketAddr` from a proto `Endpoint`. IPv4 only. Returns
/// `None` for invalid ports, unparseable IP strings, or IPv6-only
/// entries.
fn parse_ipv4_endpoint(ep: &tron_proto::Endpoint) -> Option<SocketAddr> {
    if ep.port <= 0 || ep.port > 65535 {
        return None;
    }
    let s = std::str::from_utf8(&ep.address).ok()?;
    if s.is_empty() {
        return None;
    }
    let ip: std::net::IpAddr = s.parse().ok()?;
    Some(SocketAddr::new(ip, ep.port as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_signature_round_trips_and_rejects_tampering() {
        // Self-consistency: sign a TreeRoot's content with a test key and
        // confirm `verify_root_signature` accepts it, and rejects a
        // tampered field or a different advertised pubkey. (This proves
        // the recover/compress/compare logic; it does NOT prove the
        // textFormat matches java-tron — that needs the live test.)
        let priv_key = [0x11u8; 32];
        let e_root = b"FDXN3SN67NA5DKA4J2GOK7BVQI";
        let l_root: &[u8] = b""; // empty link root → omitted from content
        let seq = 42i32;

        let content = tree_root_sign_content(e_root, l_root, seq, true);
        let hash = keccak256(&content);
        let sig = RecoverableSignature::sign_prehash(&priv_key, &hash).unwrap();
        let uncompressed = sig.recover_uncompressed_pubkey(&hash).unwrap();
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02 | (uncompressed[64] & 1);
        compressed[1..].copy_from_slice(&uncompressed[1..33]);
        let url_pubkey = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &compressed);

        // Valid signature accepted.
        assert!(verify_root_signature(e_root, l_root, seq, &sig.to_bytes(), &url_pubkey).is_ok());
        // Tampered seq recovers a different key → rejected.
        assert!(
            verify_root_signature(e_root, l_root, seq + 1, &sig.to_bytes(), &url_pubkey).is_err()
        );
        // Wrong advertised pubkey → rejected.
        let other = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &[0x02u8; 33]);
        assert!(verify_root_signature(e_root, l_root, seq, &sig.to_bytes(), &other).is_err());
    }

    #[test]
    fn parse_tree_url_happy() {
        let url = "tree://AKMQMNAJJBL73LXWPXDI4I5ZWWIZ4AWO34DWQ636QOBBXNFXH3LQS@main.trondisco.net";
        let parsed = parse_tree_url(url).unwrap();
        assert_eq!(parsed.base32_pubkey, "AKMQMNAJJBL73LXWPXDI4I5ZWWIZ4AWO34DWQ636QOBBXNFXH3LQS");
        assert_eq!(parsed.domain, "main.trondisco.net");
    }

    #[test]
    fn parse_tree_url_rejects_bad_input() {
        assert!(parse_tree_url("http://foo@bar").is_err(), "wrong scheme");
        assert!(parse_tree_url("tree://noseparator").is_err(), "no @");
        assert!(parse_tree_url("tree://@host").is_err(), "empty pubkey");
        assert!(parse_tree_url("tree://key@").is_err(), "empty domain");
    }

    #[test]
    fn parse_ipv4_endpoint_handles_edge_cases() {
        use tron_proto::Endpoint;
        // Valid IPv4
        let ep = Endpoint {
            address: b"10.0.0.1".to_vec(),
            port: 18888,
            node_id: vec![],
            address_ipv6: vec![],
        };
        assert_eq!(
            parse_ipv4_endpoint(&ep),
            Some(SocketAddr::from(([10, 0, 0, 1], 18888)))
        );
        // Bad port
        let ep = Endpoint {
            address: b"10.0.0.1".to_vec(),
            port: 0,
            node_id: vec![],
            address_ipv6: vec![],
        };
        assert!(parse_ipv4_endpoint(&ep).is_none());
        // Empty address (IPv6-only entry)
        let ep = Endpoint {
            address: vec![],
            port: 18888,
            node_id: vec![],
            address_ipv6: b"::1".to_vec(),
        };
        assert!(parse_ipv4_endpoint(&ep).is_none());
        // Non-ASCII address
        let ep = Endpoint {
            address: vec![0xFF, 0xFE, 0xFD],
            port: 18888,
            node_id: vec![],
            address_ipv6: vec![],
        };
        assert!(parse_ipv4_endpoint(&ep).is_none());
    }

    #[test]
    fn base64_url_decode_matches_java() {
        // The live mainnet root starts with `Cjs...` and decodes to a
        // valid DnsRoot proto. We don't ship the full payload as a test
        // fixture (it changes when the tree is republished), but verify
        // the decoder accepts URL-safe base64 with or without padding.
        let decoded = base64_url_decode("SGVsbG8gV29ybGQ").unwrap();
        assert_eq!(decoded, b"Hello World");
        // Padded form should also decode.
        let decoded = base64_url_decode("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(decoded, b"Hello World");
        // URL-safe alphabet (`-` instead of `+`, `_` instead of `/`).
        let decoded = base64_url_decode("AAAA_w").unwrap();
        assert_eq!(decoded, &[0, 0, 0, 0xff]);
    }
}
