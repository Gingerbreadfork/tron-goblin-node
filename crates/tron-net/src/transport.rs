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
//!
//! Aggregate cap: the per-frame limit alone bounds RAM at
//! `peers × MAX_FRAME_BYTES` — 200 peers each mid-buffering a 10 MiB frame
//! is ~2 GiB pinned. An optional [`InboundByteBudget`] (N-3) adds a single
//! process-wide ceiling on bytes being buffered across *all* connections:
//! the codec reserves a frame's body size from the shared budget before
//! accumulating it and releases the reservation when the frame is handed
//! up (or the connection drops). A peer whose frame would push the global
//! total over the ceiling is shed with [`FrameError::BudgetExceeded`].

use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::codec::{Decoder, Encoder};

use crate::message_type::{MessageType, MessageTypeError};
use crate::varint::{decode_varint32, encode_varint32, VarintError};

/// Maximum size of a single frame's *inner* bytes (type + payload).
/// 10 MiB — large enough for full blocks, small enough to bound RAM.
pub const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// Process-wide budget on inbound frame bytes being buffered concurrently
/// across all peer connections (N-3). Clone-cheap (Arc-shared semaphore);
/// create **one** and hand the same handle to every connection so they
/// draw from a common pool.
///
/// A codec configured with a budget (via
/// [`TronFrameCodec::set_budget`] / `PeerConnection::with_inbound_budget`)
/// reserves a frame's declared body length from the budget the moment it
/// learns the length, holds the reservation while the body streams in, and
/// releases it when the completed frame is handed to the application (or
/// the codec is dropped — the reservation is RAII). When the pool is
/// exhausted, the offending read fails with [`FrameError::BudgetExceeded`]
/// rather than letting unbounded bytes pile up.
#[derive(Clone, Debug)]
pub struct InboundByteBudget {
    sem: Arc<Semaphore>,
}

impl InboundByteBudget {
    /// Create a budget that allows up to `max_bytes` of inbound frame body
    /// to be buffered concurrently across all connections sharing it.
    pub fn new(max_bytes: usize) -> Self {
        let permits = max_bytes.min(Semaphore::MAX_PERMITS);
        Self {
            sem: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Try to reserve `n` bytes without blocking. Returns the RAII permit
    /// (released on drop) or `None` if the budget is exhausted.
    fn try_reserve(&self, n: usize) -> Option<OwnedSemaphorePermit> {
        let n = u32::try_from(n).ok()?;
        self.sem.clone().try_acquire_many_owned(n).ok()
    }

    /// Bytes currently free in the budget. Primarily for metrics / tests.
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }
}

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
    /// Optional process-wide inbound-bytes budget (N-3). `None` = no
    /// aggregate cap (per-frame `MAX_FRAME_BYTES` still applies).
    budget: Option<InboundByteBudget>,
    /// Live reservation against [`Self::budget`] for the frame currently
    /// being buffered. Held from the moment we learn the body length until
    /// the frame is yielded (or this codec is dropped — RAII release).
    reservation: Option<OwnedSemaphorePermit>,
}

impl TronFrameCodec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a shared inbound-bytes budget (N-3). All codecs sharing one
    /// [`InboundByteBudget`] draw from a common pool.
    pub fn set_budget(&mut self, budget: InboundByteBudget) {
        self.budget = Some(budget);
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
                    let len = len as usize;
                    if len > MAX_FRAME_BYTES {
                        return Err(FrameError::TooLarge);
                    }
                    // Reserve this body's bytes from the shared budget before
                    // buffering it (N-3). The reservation is held until the
                    // frame is yielded below (or the codec drops). A zero-length
                    // body needs no reservation — it errors out in phase 2.
                    if len > 0 {
                        if let Some(budget) = &self.budget {
                            match budget.try_reserve(len) {
                                Some(permit) => self.reservation = Some(permit),
                                None => return Err(FrameError::BudgetExceeded),
                            }
                        }
                    }
                    src.advance(consumed);
                    self.expected_body = Some(len);
                }
                None => return Ok(None), // need more bytes
            }
        }

        // Phase 2: wait for the body.
        let body_len = self.expected_body.expect("set above");
        if body_len == 0 {
            // Zero-length frame is malformed — there's no type byte.
            self.expected_body = None;
            self.reservation = None;
            return Err(FrameError::EmptyFrame);
        }
        if src.len() < body_len {
            return Ok(None);
        }

        let mut body = src.split_to(body_len).freeze();
        self.expected_body = None;
        // Frame is leaving the read buffer — release its byte reservation so
        // the next frame (here or on another peer) can use the budget.
        self.reservation = None;
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
    #[error("inbound byte budget exhausted (too many bytes in flight across peers)")]
    BudgetExceeded,
    #[error("zero-length frame (no message type byte)")]
    EmptyFrame,
    #[error(transparent)]
    BadType(#[from] MessageTypeError),
    #[error(transparent)]
    BadVarint(#[from] VarintError),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_frame(ty: MessageType, payload: Vec<u8>) -> BytesMut {
        let mut enc = TronFrameCodec::new();
        let mut buf = BytesMut::new();
        enc.encode(
            Frame {
                ty,
                payload: Bytes::from(payload),
            },
            &mut buf,
        )
        .expect("encode");
        buf
    }

    #[test]
    fn budget_releases_after_frame_is_yielded() {
        let budget = InboundByteBudget::new(1_000);
        let mut codec = TronFrameCodec::new();
        codec.set_budget(budget.clone());

        let mut src = encode_frame(MessageType::Block, vec![0u8; 50]);
        let frame = codec.decode(&mut src).expect("decode ok").expect("a frame");
        assert_eq!(frame.ty, MessageType::Block);
        assert_eq!(frame.payload.len(), 50);
        // Reservation released once the frame is handed up.
        assert_eq!(budget.available(), 1_000);

        // A second frame still fits — the budget recovered.
        let mut src2 = encode_frame(MessageType::Block, vec![1u8; 50]);
        assert!(codec.decode(&mut src2).expect("decode ok").is_some());
        assert_eq!(budget.available(), 1_000);
    }

    #[test]
    fn budget_exhaustion_sheds_the_frame() {
        // Budget smaller than the frame body → the read is shed.
        let budget = InboundByteBudget::new(64);
        let mut codec = TronFrameCodec::new();
        codec.set_budget(budget.clone());

        let mut src = encode_frame(MessageType::Block, vec![0u8; 200]);
        let err = codec.decode(&mut src).expect_err("should be shed");
        assert!(matches!(err, FrameError::BudgetExceeded));
        // No reservation leaked.
        assert_eq!(budget.available(), 64);
    }

    #[test]
    fn budget_held_across_partial_body_then_released() {
        let budget = InboundByteBudget::new(1_000);
        let mut codec = TronFrameCodec::new();
        codec.set_budget(budget.clone());

        let full = encode_frame(MessageType::Block, vec![9u8; 100]);
        // body_len = 1 (type) + 100 = 101. Feed everything except the last
        // 10 body bytes so phase 2 must wait.
        let split_at = full.len() - 10;
        let mut src = BytesMut::from(&full[..split_at]);
        assert!(codec.decode(&mut src).expect("decode ok").is_none(), "needs more bytes");
        // Reservation is held while the body streams in.
        assert_eq!(budget.available(), 1_000 - 101);

        // Deliver the remaining bytes → frame completes, reservation freed.
        src.extend_from_slice(&full[split_at..]);
        assert!(codec.decode(&mut src).expect("decode ok").is_some());
        assert_eq!(budget.available(), 1_000);
    }

    #[test]
    fn shared_budget_caps_two_codecs_together() {
        // Two connections sharing one budget draw from the same pool: once
        // codec A is mid-buffering a large frame, codec B can be shed.
        let budget = InboundByteBudget::new(150);
        let mut a = TronFrameCodec::new();
        a.set_budget(budget.clone());
        let mut b = TronFrameCodec::new();
        b.set_budget(budget.clone());

        // A starts a 100-byte body but doesn't finish it (hold the reservation).
        let full_a = encode_frame(MessageType::Block, vec![0u8; 100]);
        let keep = full_a.len() - 5;
        let mut src_a = BytesMut::from(&full_a[..keep]);
        assert!(a.decode(&mut src_a).expect("ok").is_none());
        assert_eq!(budget.available(), 150 - 101);

        // B now wants a 100-byte body too — only 49 bytes free → shed.
        let mut src_b = encode_frame(MessageType::Block, vec![1u8; 100]);
        assert!(matches!(
            b.decode(&mut src_b).expect_err("shed"),
            FrameError::BudgetExceeded
        ));

        // A finishes → frees its reservation → B can now proceed.
        src_a.extend_from_slice(&full_a[keep..]);
        assert!(a.decode(&mut src_a).expect("ok").is_some());
        assert_eq!(budget.available(), 150);
        let mut src_b2 = encode_frame(MessageType::Block, vec![2u8; 100]);
        assert!(b.decode(&mut src_b2).expect("ok").is_some());
    }
}
