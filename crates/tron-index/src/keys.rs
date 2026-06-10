//! Index key codecs.
//!
//! Every index entry lives in **one** RocksDB keyspace, partitioned by a
//! 1-byte namespace prefix. The plan (working/INDEXER_PLAN.md §6.1)
//! sketched column families; we use namespace-prefixed keys in a single
//! instance instead so the cursor can commit atomically with rows across
//! every namespace through the existing `KvBackend::write_batch` — the
//! node's whole storage layer is instance-per-store with no CF support,
//! and a prefix partition gives the same scan isolation (namespaces are
//! disjoint key ranges; an iterator over one never wades through
//! another).
//!
//! Within a namespace the skeleton is:
//!
//! ```text
//! ns(1) ‖ addr(21) ‖ height_desc(8) ‖ txidx(4) [‖ subidx(4)]
//! ```
//!
//! `height_desc = u64::MAX − height` (big-endian), so a *forward* byte
//! scan of an address's range yields **newest-first** — the dominant
//! query order — with zero sorting at read time. `txidx` is the
//! transaction's position in its block; `subidx` is the log's /
//! internal-tx's position within the transaction. Together they make
//! every key unique, totally ordered, and decodable back into a
//! `(height, txidx)` pointer for detail hydration.

/// Namespace prefixes. Meta sorts first so the (small) bookkeeping
/// range never interleaves with row scans.
pub const NS_META: u8 = 0x00;
pub const NS_NATIVE: u8 = 0x01;
pub const NS_TRC20: u8 = 0x02;
pub const NS_INTERNAL: u8 = 0x03;
pub const NS_LOGS: u8 = 0x04;
pub const NS_TRC721: u8 = 0x05;

/// Raw 21-byte TRON address (`0x41` + 20 bytes).
pub type Addr = [u8; 21];

/// Inverted big-endian height: byte order == descending numeric order.
#[inline]
pub fn height_desc(height: i64) -> [u8; 8] {
    (u64::MAX - height as u64).to_be_bytes()
}

/// Reverse of [`height_desc`].
#[inline]
pub fn height_from_desc(desc: [u8; 8]) -> i64 {
    (u64::MAX - u64::from_be_bytes(desc)) as i64
}

/// `ns ‖ addr` — the scan prefix for one address's history in one
/// namespace.
pub fn addr_prefix(ns: u8, addr: &Addr) -> Vec<u8> {
    let mut k = Vec::with_capacity(22);
    k.push(ns);
    k.extend_from_slice(addr);
    k
}

fn row_key(ns: u8, addr: &Addr, height: i64, txidx: u32, subidx: Option<u32>) -> Vec<u8> {
    let mut k = Vec::with_capacity(38);
    k.push(ns);
    k.extend_from_slice(addr);
    k.extend_from_slice(&height_desc(height));
    k.extend_from_slice(&txidx.to_be_bytes());
    if let Some(s) = subidx {
        k.extend_from_slice(&s.to_be_bytes());
    }
    k
}

/// `idx_native` key: 34 bytes.
pub fn native_key(addr: &Addr, height: i64, txidx: u32) -> Vec<u8> {
    row_key(NS_NATIVE, addr, height, txidx, None)
}

/// `idx_trc20` key: 38 bytes (`subidx` = log index within the tx).
pub fn trc20_key(addr: &Addr, height: i64, txidx: u32, logidx: u32) -> Vec<u8> {
    row_key(NS_TRC20, addr, height, txidx, Some(logidx))
}

/// `idx_internal` key: 38 bytes (`subidx` = internal-tx index).
pub fn internal_key(addr: &Addr, height: i64, txidx: u32, itxidx: u32) -> Vec<u8> {
    row_key(NS_INTERNAL, addr, height, txidx, Some(itxidx))
}

/// `idx_trc721` key: 38 bytes (`subidx` = log index within the tx).
pub fn trc721_key(addr: &Addr, height: i64, txidx: u32, logidx: u32) -> Vec<u8> {
    row_key(NS_TRC721, addr, height, txidx, Some(logidx))
}

/// `idx_logs` key (`scope = "all"` only): contract-and-topic0-first so
/// event search scans one contract+signature range. 70 bytes.
pub fn logs_key(
    contract: &Addr,
    topic0: &[u8; 32],
    height: i64,
    txidx: u32,
    logidx: u32,
) -> Vec<u8> {
    let mut k = Vec::with_capacity(70);
    k.push(NS_LOGS);
    k.extend_from_slice(contract);
    k.extend_from_slice(topic0);
    k.extend_from_slice(&height_desc(height));
    k.extend_from_slice(&txidx.to_be_bytes());
    k.extend_from_slice(&logidx.to_be_bytes());
    k
}

/// Decoded pointer half of a row key — everything response assembly
/// needs to hydrate details from `BlockStore` / transaction-info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyParts {
    pub height: i64,
    pub txidx: u32,
    /// Log / internal-tx index. `None` for `idx_native` keys.
    pub subidx: Option<u32>,
}

/// Decoded [`logs_key`] (70 bytes): contract + topic0 + pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogKeyParts {
    pub contract: Addr,
    pub topic0: [u8; 32],
    pub height: i64,
    pub txidx: u32,
    pub logidx: u32,
}

/// Decode a row key produced by [`logs_key`]. `None` for malformed
/// lengths / namespaces.
pub fn decode_logs_key(key: &[u8]) -> Option<LogKeyParts> {
    if key.len() != 70 || key[0] != NS_LOGS {
        return None;
    }
    let mut contract = [0u8; 21];
    contract.copy_from_slice(&key[1..22]);
    let mut topic0 = [0u8; 32];
    topic0.copy_from_slice(&key[22..54]);
    let mut desc = [0u8; 8];
    desc.copy_from_slice(&key[54..62]);
    let mut txidx = [0u8; 4];
    txidx.copy_from_slice(&key[62..66]);
    let mut logidx = [0u8; 4];
    logidx.copy_from_slice(&key[66..70]);
    Some(LogKeyParts {
        contract,
        topic0,
        height: height_from_desc(desc),
        txidx: u32::from_be_bytes(txidx),
        logidx: u32::from_be_bytes(logidx),
    })
}

/// Decode a row key produced by [`native_key`] / [`trc20_key`] /
/// [`internal_key`]. Returns `None` for malformed lengths.
pub fn decode_row_key(key: &[u8]) -> Option<KeyParts> {
    if key.len() != 34 && key.len() != 38 {
        return None;
    }
    let mut desc = [0u8; 8];
    desc.copy_from_slice(&key[22..30]);
    let mut txidx = [0u8; 4];
    txidx.copy_from_slice(&key[30..34]);
    let subidx = if key.len() == 38 {
        let mut s = [0u8; 4];
        s.copy_from_slice(&key[34..38]);
        Some(u32::from_be_bytes(s))
    } else {
        None
    };
    Some(KeyParts {
        height: height_from_desc(desc),
        txidx: u32::from_be_bytes(txidx),
        subidx,
    })
}

// ---------------------------------------------------------------------------
// Meta keys (NS_META)
// ---------------------------------------------------------------------------

fn meta_key(name: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + name.len());
    k.push(NS_META);
    k.extend_from_slice(name);
    k
}

/// `u32` BE — bumped on any change a reader could mis-interpret.
pub fn meta_format_version() -> Vec<u8> {
    meta_key(b"format_version")
}

/// `u64` BE hash of the *effective* capture set (post-precedence).
pub fn meta_scope_fingerprint() -> Vec<u8> {
    meta_key(b"scope_fingerprint")
}

/// The live-edge cursor, one composite value: `height(8 BE)` followed
/// optionally by the canonical block id (32 bytes) recorded when that
/// height was indexed. One key (instead of a height/id pair) makes the
/// pairing drift-proof by construction: an update without an id
/// *clears* the id, so reorg detection can never be armed with another
/// height's id.
pub fn meta_cursor() -> Vec<u8> {
    meta_key(b"cursor")
}

/// `i64` BE — lowest indexed height (`indexed_from`). The backward
/// (backfill) edge under head-first ordering; equals the floor once
/// backfill completes.
pub fn meta_back_edge() -> Vec<u8> {
    meta_key(b"back_edge")
}

/// `i64` BE — the effective floor recorded at init
/// (`max(BlockIndexStore::lowest(), start_height)`).
pub fn meta_floor() -> Vec<u8> {
    meta_key(b"floor")
}

/// Recent-ring entry: canonical block id (32 bytes) recorded when
/// height `h` was indexed. Only maintained near the head (reorg
/// territory); pruned as the ring advances.
pub fn meta_id_at(height: i64) -> Vec<u8> {
    let mut k = meta_key(b"id_at/");
    k.extend_from_slice(&(height as u64).to_be_bytes());
    k
}

/// Recent-ring entry: the exact row keys written for height `h`
/// (length-prefixed list). Unwinding a reorg deletes precisely these —
/// exact even though the old chain's block-num-keyed transaction-info
/// gets overwritten by the new chain.
pub fn meta_keys_at(height: i64) -> Vec<u8> {
    let mut k = meta_key(b"keys_at/");
    k.extend_from_slice(&(height as u64).to_be_bytes());
    k
}

/// Token-metadata cache entry for a TRC20 contract.
pub fn meta_token(contract: &Addr) -> Vec<u8> {
    let mut k = meta_key(b"token/");
    k.extend_from_slice(contract);
    k
}

/// Encode the per-height key list stored under [`meta_keys_at`].
pub fn encode_key_list(keys: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + keys.iter().map(|k| 2 + k.len()).sum::<usize>());
    out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for k in keys {
        out.extend_from_slice(&(k.len() as u16).to_be_bytes());
        out.extend_from_slice(k);
    }
    out
}

/// Decode [`encode_key_list`]. Returns `None` on truncation.
pub fn decode_key_list(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.len() < 4 {
        return None;
    }
    let count = u32::from_be_bytes(bytes[..4].try_into().ok()?) as usize;
    let mut out = Vec::with_capacity(count.min(4096));
    let mut at = 4usize;
    for _ in 0..count {
        if at + 2 > bytes.len() {
            return None;
        }
        let len = u16::from_be_bytes(bytes[at..at + 2].try_into().ok()?) as usize;
        at += 2;
        if at + len > bytes.len() {
            return None;
        }
        out.push(bytes[at..at + len].to_vec());
        at += len;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Addr {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(b);
        a
    }

    #[test]
    fn height_desc_roundtrips_and_inverts_order() {
        for h in [0i64, 1, 1_000_000, 84_210_003, i64::MAX - 1] {
            assert_eq!(height_from_desc(height_desc(h)), h);
        }
        // Higher height → byte-smaller key → sorts first (newest-first).
        assert!(height_desc(100) < height_desc(99));
    }

    #[test]
    fn key_order_matches_tuple_order() {
        // The ordering property the whole pagination model rests on:
        // byte order of keys == (addr, height desc, txidx, subidx) order.
        let a = addr(1);
        let b = addr(2);
        let mut keys = vec![
            trc20_key(&b, 5, 0, 0),
            trc20_key(&a, 5, 0, 1),
            trc20_key(&a, 5, 1, 0),
            trc20_key(&a, 6, 9, 9),
            trc20_key(&a, 5, 0, 0),
        ];
        keys.sort();
        assert_eq!(
            keys,
            vec![
                trc20_key(&a, 6, 9, 9), // newest height first
                trc20_key(&a, 5, 0, 0),
                trc20_key(&a, 5, 0, 1),
                trc20_key(&a, 5, 1, 0),
                trc20_key(&b, 5, 0, 0), // other address after
            ]
        );
    }

    #[test]
    fn decode_row_key_roundtrips() {
        let a = addr(7);
        let k = native_key(&a, 84_210_003, 17);
        assert_eq!(
            decode_row_key(&k),
            Some(KeyParts { height: 84_210_003, txidx: 17, subidx: None })
        );
        let k = internal_key(&a, 3, 2, 9);
        assert_eq!(
            decode_row_key(&k),
            Some(KeyParts { height: 3, txidx: 2, subidx: Some(9) })
        );
        assert_eq!(decode_row_key(b"short"), None);
    }

    #[test]
    fn key_list_roundtrips() {
        let keys = vec![vec![1u8, 2, 3], vec![], vec![0xff; 38]];
        assert_eq!(decode_key_list(&encode_key_list(&keys)), Some(keys));
        assert_eq!(decode_key_list(&[0, 0]), None);
        assert_eq!(decode_key_list(&encode_key_list(&[])), Some(vec![]));
    }

    #[test]
    fn namespaces_are_disjoint_ranges() {
        let a = addr(0xee);
        let n = native_key(&a, 1, 0);
        let t = trc20_key(&a, 1, 0, 0);
        let i = internal_key(&a, 1, 0, 0);
        let m = meta_cursor();
        assert!(m < n && n < t && t < i);
    }
}
