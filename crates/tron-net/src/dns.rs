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
//! * **No signature verification yet.** Java-tron verifies the root's
//!   secp256k1 signature over the Java-protobuf `textFormat` of the
//!   inner `TreeRoot` message. Reproducing that textual format
//!   precisely in Rust is fragile (proto-reflect-driven, ordering
//!   matters, escape rules matter), and discovery is a *hint* not a
//!   security boundary — TCP handshake validates each peer separately.
//!   A malicious DNS could waste a few connection attempts; it can't
//!   compromise sync correctness. Tracked as TODO; would slot in here
//!   without changing the public API.
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
