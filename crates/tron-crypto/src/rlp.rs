//! Minimal RLP (Recursive Length Prefix) encoder used by the state-trie
//! node encoding. Matches `org.tron.common.crypto.Hash.encodeElement` and
//! the surrounding RLP helpers ported from ethereumJ.
//!
//! Scope for v1: byte-string encoding only (single elements). List encoding
//! is provided as a thin helper because trie nodes are lists of items.
//! Decoder is not implemented yet — adding when state-trie load paths land.

const OFFSET_SHORT_ITEM: u8 = 0x80;
const OFFSET_LONG_ITEM: u8 = 0xb7;
const OFFSET_SHORT_LIST: u8 = 0xc0;
const OFFSET_LONG_LIST: u8 = 0xf7;
const SIZE_THRESHOLD: usize = 56;

/// Encode a single byte string.
///
/// * Empty → `[0x80]`
/// * Single byte `[0x00..0x7f]` → unchanged
/// * 1..55 bytes → `[0x80+len, ..data..]`
/// * 56+ bytes → `[0xb7+len_of_len, ..len_be.., ..data..]`
pub fn encode_element(src: &[u8]) -> Vec<u8> {
    if src.is_empty() {
        return vec![OFFSET_SHORT_ITEM];
    }
    if src.len() == 1 && src[0] < OFFSET_SHORT_ITEM {
        return src.to_vec();
    }
    if src.len() < SIZE_THRESHOLD {
        let mut out = Vec::with_capacity(1 + src.len());
        out.push(OFFSET_SHORT_ITEM + src.len() as u8);
        out.extend_from_slice(src);
        return out;
    }
    encode_long_prefix(OFFSET_LONG_ITEM, src.len(), src)
}

/// Encode an unsigned integer per RLP rules: minimum-byte big-endian
/// representation (no leading zeros), wrapped via `encode_element`.
/// `0` is encoded as the empty byte string `[0x80]`.
pub fn encode_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return encode_element(&[]);
    }
    let be = n.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    encode_element(&be[first..])
}

/// Alias for [`encode_element`] used at call sites whose intent is
/// "encode this byte string", not "encode this single element".
pub fn encode_bytes(src: &[u8]) -> Vec<u8> {
    encode_element(src)
}

/// Encode a list of already-RLP-encoded items.
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Vec::with_capacity(payload_len + 9);
    if payload_len < SIZE_THRESHOLD {
        out.push(OFFSET_SHORT_LIST + payload_len as u8);
    } else {
        let len_bytes = be_bytes(payload_len);
        out.push(OFFSET_LONG_LIST + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn encode_long_prefix(base: u8, len: usize, payload: &[u8]) -> Vec<u8> {
    let len_bytes = be_bytes(len);
    let mut out = Vec::with_capacity(1 + len_bytes.len() + payload.len());
    out.push(base + len_bytes.len() as u8);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(payload);
    out
}

/// Big-endian length encoding with no leading zeros (matches java-tron's
/// `tmpLength >> 8` loop in `Hash.encodeElement`).
fn be_bytes(mut n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    // Determine length-of-length.
    let mut tmp = n;
    let mut len_of_len = 0;
    while tmp != 0 {
        len_of_len += 1;
        tmp >>= 8;
    }
    let mut out = vec![0u8; len_of_len];
    for i in (0..len_of_len).rev() {
        out[i] = (n & 0xff) as u8;
        n >>= 8;
    }
    out
}
