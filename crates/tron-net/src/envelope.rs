//! Wire envelope: `[type_byte][payload_bytes...]`.
//!
//! There is **no length prefix** at this layer — the surrounding TCP-frame
//! codec (java-tron uses Netty + `tron-p2p`'s framing; we'll use a Tokio
//! `LengthDelimitedCodec` when the transport lands) provides one frame
//! per call. This module just adds/strips the single type byte.
//!
//! Source: `org.tron.common.overlay.message.Message.getSendBytes`.

use tron_crypto::hash::sha256;

use crate::message_type::{MessageType, MessageTypeError};

/// Prepend the type byte to an already-encoded protobuf payload.
pub fn encode_envelope(ty: MessageType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(ty.as_byte());
    out.extend_from_slice(payload);
    out
}

/// Strip the type byte. Returns the parsed type plus a borrow of the rest.
///
/// Errors:
/// * [`EnvelopeError::Empty`] if `bytes` is empty.
/// * [`EnvelopeError::UnknownType`] if the leading byte is not a defined
///   `MessageType`.
pub fn decode_envelope(bytes: &[u8]) -> Result<(MessageType, &[u8]), EnvelopeError> {
    let (head, rest) = bytes.split_first().ok_or(EnvelopeError::Empty)?;
    let ty = MessageType::from_byte(*head)?;
    Ok((ty, rest))
}

/// **Message id** used for inventory dedup. Java-tron's
/// `Message.getMessageId()` hashes the payload *without* the type byte:
/// ```text
/// Sha256Hash.of(isECKeyCryptoEngine, getData())  // getData() returns the
///                                                  // payload sans type
/// ```
///
/// Hashing the envelope (with the type byte) is a subtle but
/// consensus-affecting bug in any reimplementation, because peers compare
/// these ids in `INVENTORY` exchanges.
#[inline]
pub fn message_id(payload_without_type: &[u8]) -> [u8; 32] {
    sha256(payload_without_type)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("envelope is empty")]
    Empty,
    #[error(transparent)]
    UnknownType(#[from] MessageTypeError),
}
