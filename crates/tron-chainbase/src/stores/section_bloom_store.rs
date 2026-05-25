//! SectionBloomStore — directory name `section-bloom`.
//!
//! Holds bloom filters per (section, bit_index) for fast `eth_getLogs`
//! queries.
//!
//! Key:   **lowercase hex** UTF-8 bytes of `section * 1_000_000 + bit_index`
//!        in **decimal** (java-tron: `Long.toHexString(keyLong).getBytes()`
//!        where `keyLong = section * 1_000_000L + bitIndex`).
//! Value: zlib-deflated `BitSet.toByteArray()` bytes
//!        (java-tron: `ByteUtil.compress(bitSet.toByteArray())` —
//!        `Deflater()` no-arg = zlib wrapper, default compression).
//!
//! **Encoding trap (key)**: the composition is *decimal arithmetic*,
//! not a bit-shift. Section 1, bit 0 → `1_000_000` → `"f4240"`, not
//! `0x1000000` → `"1000000"`.
//!
//! **Encoding trap (value)**: java compresses with zlib; raw bytes
//! won't decode on a java-tron node.

use std::io::{Read, Write};
use std::sync::Arc;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::backend::KvBackend;

pub const DB_NAME: &str = "section-bloom";

pub struct SectionBloomStore {
    backend: Arc<dyn KvBackend>,
}

impl SectionBloomStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Build the canonical key. java-tron composes
    /// `section * 1_000_000 + bit_index` in decimal, then renders it
    /// with `Long.toHexString` (no-leading-zero, lowercase).
    pub fn key_for(section: u32, bit_index: u32) -> Vec<u8> {
        let composed = (section as u64) * 1_000_000 + (bit_index as u64);
        format!("{composed:x}").into_bytes()
    }

    /// Write a bloom row. `bitset_bytes` is the raw `BitSet.toByteArray()`
    /// payload (little-endian within each byte, trailing-zero-trimmed).
    /// We zlib-compress on the way down to match java-tron's
    /// `ByteUtil.compress`.
    pub fn put(&self, section: u32, bit_index: u32, bitset_bytes: &[u8]) {
        let k = Self::key_for(section, bit_index);
        let compressed = compress(bitset_bytes);
        self.backend.put(&k, &compressed);
    }

    /// Read + decompress. Returns `None` if the row is absent or the
    /// stored value isn't valid zlib (treat corrupted as missing —
    /// matches java-tron which throws `EventBloomException` and the
    /// caller logs + skips).
    pub fn get(&self, section: u32, bit_index: u32) -> Option<Vec<u8>> {
        let k = Self::key_for(section, bit_index);
        let raw = self.backend.get(&k)?;
        decompress(&raw).ok()
    }
}

fn compress(input: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::with_capacity(input.len()), Compression::default());
    encoder.write_all(input).expect("zlib write to Vec never fails");
    encoder.finish().expect("zlib finish on in-memory writer never fails")
}

fn decompress(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(input);
    let mut out = Vec::with_capacity(input.len() * 2);
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    #[test]
    fn round_trip_compresses_on_disk() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = SectionBloomStore::new(backend.clone());
        // Pattern with obvious repetition so the compressed payload is
        // visibly smaller than the input (sanity-check we actually
        // deflated rather than echoed).
        let payload = vec![0xAA; 256];
        store.put(0, 0, &payload);
        let raw = backend.get(b"0").expect("row written");
        assert!(
            raw.len() < payload.len(),
            "compressed payload ({} bytes) should be smaller than input ({} bytes)",
            raw.len(),
            payload.len()
        );
        let round = store.get(0, 0).expect("decompressed read");
        assert_eq!(round, payload);
    }

    #[test]
    fn get_returns_none_for_corrupt_value() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = SectionBloomStore::new(backend.clone());
        // Write garbage directly; decompress will fail → None.
        backend.put(b"0", b"not-zlib");
        assert!(store.get(0, 0).is_none());
    }
}
