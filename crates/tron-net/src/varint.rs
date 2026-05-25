//! Protobuf-style varint encoding for the TRON P2P length-prefix layer.
//!
//! java-tron's transport uses Netty's `ProtobufVarint32LengthFieldPrepender`
//! + `ProtobufVarint32FrameDecoder`. Each TCP frame is
//!
//! ```text
//! [varint length of (type byte + payload)]
//! [type byte]
//! [payload bytes]
//! ```
//!
//! The varint encodes the **inner length** in protobuf's "base-128"
//! format: little-endian 7-bit groups, high bit set on every byte except
//! the last (which has high bit cleared).
//!
//! For 32-bit lengths the encoding is **1–5 bytes**. We restrict to
//! `u32` because that's what `ProtobufVarint32*` accepts — values up to
//! `0x7fffffff` (2 GiB). Anything beyond that is a protocol violation.

use bytes::{Buf, BufMut, BytesMut};

/// Maximum encoded length of a `u32` varint (5 bytes: 4×7 + 4 bits).
pub const MAX_VARINT32_BYTES: usize = 5;

/// Write `value` as a protobuf varint into `dst`. Returns the number of
/// bytes written (1..=5).
pub fn encode_varint32(dst: &mut BytesMut, mut value: u32) -> usize {
    let mut written = 0;
    while value >= 0x80 {
        dst.put_u8(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
        written += 1;
    }
    dst.put_u8(value as u8);
    written + 1
}

/// Attempt to decode a `u32` varint from the front of `src`.
///
/// * `Ok(Some((value, bytes_consumed)))` — successfully decoded; caller
///   should advance `src` by `bytes_consumed`.
/// * `Ok(None)` — `src` doesn't yet contain a complete varint (need more
///   bytes). Common case for partial reads.
/// * `Err(VarintError)` — protocol violation (too long, or overflow).
pub fn decode_varint32(src: &[u8]) -> Result<Option<(u32, usize)>, VarintError> {
    let mut value: u32 = 0;
    let mut shift = 0u32;
    for (i, &b) in src.iter().enumerate() {
        if i >= MAX_VARINT32_BYTES {
            return Err(VarintError::TooLong);
        }
        let bits = (b & 0x7f) as u32;
        // Check for overflow on the final byte slot.
        if shift >= 32 {
            return Err(VarintError::Overflow);
        }
        value |= bits << shift;
        if b & 0x80 == 0 {
            // High bit clear → final byte.
            return Ok(Some((value, i + 1)));
        }
        shift += 7;
    }
    Ok(None)
}

/// Convenience for `Buf` sources: read a varint, advancing the buffer
/// past the consumed bytes. Returns `Ok(None)` for short input.
pub fn read_varint32_from_buf<B: Buf>(src: &mut B) -> Result<Option<u32>, VarintError> {
    // Peek into the chunk(s) by collecting up to 5 bytes into a small array.
    let mut scratch = [0u8; MAX_VARINT32_BYTES];
    let mut n = 0;
    while n < MAX_VARINT32_BYTES && src.has_remaining() {
        scratch[n] = src.chunk()[0];
        src.advance(1);
        n += 1;
        if scratch[n - 1] & 0x80 == 0 {
            // We've read a complete varint into scratch[..n]; decode it.
            let (v, consumed) = decode_varint32(&scratch[..n])?
                .expect("we just confirmed the final byte was present");
            assert_eq!(consumed, n);
            return Ok(Some(v));
        }
    }
    if n == MAX_VARINT32_BYTES {
        return Err(VarintError::TooLong);
    }
    // Ran out of bytes mid-varint; the bytes we consumed are "lost"
    // for this API. Callers that need restartable parsing should use
    // [`decode_varint32`] over a `&[u8]` slice instead.
    Ok(None)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VarintError {
    #[error("varint is longer than 5 bytes (protocol violation)")]
    TooLong,
    #[error("varint value overflows u32")]
    Overflow,
}
