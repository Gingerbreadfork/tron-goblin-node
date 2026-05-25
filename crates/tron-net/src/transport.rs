//! Tokio `Framed` codec implementing the TRON P2P wire format.
//!
//! Outgoing pipeline: caller pushes `(MessageType, payload bytes)` →
//! codec writes `[varint length][type byte][payload]`. Length is the
//! number of bytes that follow (i.e. `1 + payload.len()`).
//!
//! Incoming pipeline: codec reads `[varint length]` then waits for that
//! many bytes → yields `(MessageType, payload bytes)`. Unknown type
//! bytes are surfaced as an error rather than silently dropped.
//!
//! Frame size cap: by default `MAX_FRAME_BYTES` (10 MiB). java-tron has
//! similar limits to bound memory per peer.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::message_type::{MessageType, MessageTypeError};
use crate::varint::{decode_varint32, encode_varint32, VarintError};

/// Maximum size of a single frame's *inner* bytes (type + payload).
/// 10 MiB — large enough for full blocks, small enough to bound RAM.
pub const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// A decoded frame ready for the application layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: MessageType,
    pub payload: Bytes,
}

/// Codec that frames TRON P2P messages over a byte stream.
///
/// Implements both [`Encoder<Frame>`] and [`Decoder<Item = Frame>`] so a
/// single `Framed<Stream, TronFrameCodec>` does bidirectional framing.
#[derive(Debug, Default)]
pub struct TronFrameCodec {
    /// Number of bytes the *next* frame body will be, once known.
    /// `None` means we haven't decoded the varint length yet.
    expected_body: Option<usize>,
}

impl TronFrameCodec {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Encoder<Frame> for TronFrameCodec {
    type Error = FrameError;
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), FrameError> {
        let body_len = 1usize.checked_add(frame.payload.len()).ok_or(FrameError::TooLarge)?;
        if body_len > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        let body_len_u32 =
            u32::try_from(body_len).map_err(|_| FrameError::TooLarge)?;
        // Reserve worst-case prefix + body.
        dst.reserve(5 + body_len);
        encode_varint32(dst, body_len_u32);
        dst.put_u8(frame.ty.as_byte());
        dst.extend_from_slice(&frame.payload);
        Ok(())
    }
}

impl Decoder for TronFrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        // Phase 1: read the length varint if we don't have it yet.
        if self.expected_body.is_none() {
            match decode_varint32(src)? {
                Some((len, consumed)) => {
                    if (len as usize) > MAX_FRAME_BYTES {
                        return Err(FrameError::TooLarge);
                    }
                    src.advance(consumed);
                    self.expected_body = Some(len as usize);
                }
                None => return Ok(None), // need more bytes
            }
        }

        // Phase 2: wait for the body.
        let body_len = self.expected_body.expect("set above");
        if body_len == 0 {
            // Zero-length frame is malformed — there's no type byte.
            self.expected_body = None;
            return Err(FrameError::EmptyFrame);
        }
        if src.len() < body_len {
            return Ok(None);
        }

        let mut body = src.split_to(body_len).freeze();
        self.expected_body = None;
        let ty_byte = body[0];
        let ty = MessageType::from_byte(ty_byte)?;
        body.advance(1);
        Ok(Some(Frame { ty, payload: body }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame exceeds {} bytes", MAX_FRAME_BYTES)]
    TooLarge,
    #[error("zero-length frame (no message type byte)")]
    EmptyFrame,
    #[error(transparent)]
    BadType(#[from] MessageTypeError),
    #[error(transparent)]
    BadVarint(#[from] VarintError),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}
