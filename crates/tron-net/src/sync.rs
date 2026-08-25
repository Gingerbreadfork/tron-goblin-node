//! TRON sync-protocol message helpers.
//!
//! The sync protocol uses four wire message types (see
//! [`MessageType`]):
//!
//! ```text
//!   syncing node                  peer-with-chain
//!   ───────────                   ───────────────
//!         │  SyncBlockChain { ids: my_summary }
//!         │ ────────────────────────────────▶
//!         │
//!         │  BlockChainInventory { ids: blocks_you_need, remain_num }
//!         │ ◀──────────────────────────────────────────────────────
//!         │
//!         │  FetchInvData { type: BLOCK, ids: [block_id_bytes, …] }
//!         │ ─────────────────────────────────────────────────────▶
//!         │
//!         │  Block (one frame per requested block, in order)
//!         │ ◀────────────────────────────────────────────────
//!         │
//!         │  (loop until remain_num == 0)
//! ```
//!
//! Payload types come from the existing `tron-proto`:
//!
//! | Wire message type      | Payload proto                    |
//! |------------------------|----------------------------------|
//! | `SyncBlockChain`       | `ChainInventory`                 |
//! | `BlockChainInventory`  | `ChainInventory`                 |
//! | `FetchInvData`         | `Inventory` (type=BLOCK)         |
//! | `Block`                | `Block`                          |
//!
//! This module supplies the low-level send/receive helpers. The
//! decision loop ("which block to fetch next, when to stop") lives in
//! the application layer (e.g. `tron-replay`'s `sync` subcommand) so
//! `tron-net` doesn't have to depend on the executor.

use bytes::Bytes;
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tron_proto::block_inventory;
use tron_proto::chain_inventory;
use tron_proto::inventory::InventoryType;
use tron_proto::{Block, BlockInventory, ChainInventory, Inventory};
use tron_types::BlockId;

use crate::message_type::MessageType;
use crate::peer::PeerConnection;
use crate::transport::{Frame, FrameError};

/// Send a `SyncBlockChain` carrying our known-chain summary.
///
/// `summary` is the list of block ids the local node has — typically a
/// small set: genesis, a few recent ancestors of head, and head itself.
/// java-tron sends a logarithmically-spaced summary; for v1 we accept
/// whatever the caller hands us.
pub async fn send_sync_request<S>(
    conn: &mut PeerConnection<S>,
    summary: &[BlockId],
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // java-tron's `SyncBlockChainMessage` extends `BlockInventoryMessage`
    // — the wire payload is `BlockInventory{ ids, type=SYNC }`, NOT
    // `ChainInventory`. (Wire bytes happen to coincide when
    // `remain_num = 0` because both field-2 entries are varint(0),
    // but encoding the right proto avoids ambiguity and makes the
    // `type=SYNC` discriminator explicit.)
    let payload = BlockInventory {
        ids: summary
            .iter()
            .map(|id| block_inventory::BlockId {
                hash: id.as_bytes().to_vec(),
                number: id.num() as i64,
            })
            .collect(),
        r#type: block_inventory::Type::Sync as i32,
    };
    conn.send_frame(Frame {
        ty: MessageType::SyncBlockChain,
        payload: Bytes::from(payload.encode_to_vec()),
    })
    .await
}

/// Await a `BlockChainInventory` frame and decode its payload.
///
/// Returns `Err(SyncError::UnexpectedFrame)` if the next frame isn't
/// the expected type — callers that need to tolerate interleaved
/// inventory/ping frames must wrap this in their own filter.
pub async fn recv_chain_inventory<S>(
    conn: &mut PeerConnection<S>,
) -> Result<ChainInventory, SyncError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = conn.next_frame().await?.ok_or(SyncError::PeerClosed)?;
    if frame.ty != MessageType::BlockChainInventory {
        return Err(SyncError::UnexpectedFrame {
            expected: MessageType::BlockChainInventory,
            got: frame.ty,
        });
    }
    ChainInventory::decode(frame.payload).map_err(|e| SyncError::Decode(e.to_string()))
}

/// Request a batch of blocks by id. Each id is the 32-byte BlockId
/// (with the num-prefix). Peer is expected to reply with one `Block`
/// frame per id, in order.
pub async fn send_fetch_inv_data<S>(
    conn: &mut PeerConnection<S>,
    block_id_bytes: &[Vec<u8>],
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // java-tron drops a peer whose FetchInvData repeats a hash, so a block
    // re-announced before its first fetch went out must not appear twice.
    let mut seen = std::collections::HashSet::with_capacity(block_id_bytes.len());
    let ids: Vec<Vec<u8>> = block_id_bytes
        .iter()
        .filter(|id| seen.insert(id.as_slice()))
        .cloned()
        .collect();
    let payload = Inventory {
        r#type: InventoryType::Block as i32,
        ids,
    };
    conn.send_frame(Frame {
        ty: MessageType::FetchInvData,
        payload: Bytes::from(payload.encode_to_vec()),
    })
    .await
}

/// Await a single `Block` frame.
pub async fn recv_block<S>(conn: &mut PeerConnection<S>) -> Result<Block, SyncError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = conn.next_frame().await?.ok_or(SyncError::PeerClosed)?;
    if frame.ty != MessageType::Block {
        return Err(SyncError::UnexpectedFrame {
            expected: MessageType::Block,
            got: frame.ty,
        });
    }
    Block::decode(frame.payload).map_err(|e| SyncError::Decode(e.to_string()))
}

/// Convenience for serving the provider side in tests: send one Block.
pub async fn send_block<S>(conn: &mut PeerConnection<S>, block: &Block) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    conn.send_frame(Frame {
        ty: MessageType::Block,
        payload: Bytes::from(block.encode_to_vec()),
    })
    .await
}

/// Convenience for the provider side: send a BlockChainInventory reply.
pub async fn send_chain_inventory<S>(
    conn: &mut PeerConnection<S>,
    inv: &ChainInventory,
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    conn.send_frame(Frame {
        ty: MessageType::BlockChainInventory,
        payload: Bytes::from(inv.encode_to_vec()),
    })
    .await
}

/// Build the `ChainInventory` reply for a peer syncing FROM us.
///
/// `ids` runs from the common ancestor onward — java-tron includes the
/// shared block as the first id so the peer can verify the link — and
/// `remain_num` is how many further blocks we hold beyond this batch.
pub fn chain_inventory_from_ids(ids: &[BlockId], remain_num: i64) -> ChainInventory {
    ChainInventory {
        ids: ids
            .iter()
            .map(|id| chain_inventory::BlockId {
                hash: id.as_bytes().to_vec(),
                number: id.num() as i64,
            })
            .collect(),
        remain_num,
    }
}

/// Await a `SyncBlockChain` request (provider side). Returns the
/// requester's chain summary as a [`BlockInventory`].
///
/// java-tron's `SyncBlockChainMessage` extends `BlockInventoryMessage`, so the
/// wire payload is a `BlockInventory` (`ids` + `type=SYNC`), NOT a
/// `ChainInventory`. The two share the same field-1 (`ids`) layout, but field 2
/// differs: `BlockInventory.type` (enum) vs `ChainInventory.remain_num`
/// (int64). Decoding the request as `ChainInventory` would misread the `type`
/// enum as `remain_num` — harmless only while `Type::SYNC == 0`, but wrong in
/// principle. Decode the proto java actually sends.
pub async fn recv_sync_request<S>(conn: &mut PeerConnection<S>) -> Result<BlockInventory, SyncError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = conn.next_frame().await?.ok_or(SyncError::PeerClosed)?;
    if frame.ty != MessageType::SyncBlockChain {
        return Err(SyncError::UnexpectedFrame {
            expected: MessageType::SyncBlockChain,
            got: frame.ty,
        });
    }
    BlockInventory::decode(frame.payload).map_err(|e| SyncError::Decode(e.to_string()))
}

/// Await a `FetchInvData` (provider side). Returns the requested ids.
pub async fn recv_fetch_inv_data<S>(conn: &mut PeerConnection<S>) -> Result<Inventory, SyncError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = conn.next_frame().await?.ok_or(SyncError::PeerClosed)?;
    if frame.ty != MessageType::FetchInvData {
        return Err(SyncError::UnexpectedFrame {
            expected: MessageType::FetchInvData,
            got: frame.ty,
        });
    }
    Inventory::decode(frame.payload).map_err(|e| SyncError::Decode(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("peer closed the connection")]
    PeerClosed,
    #[error("unexpected frame type: expected {expected:?}, got {got:?}")]
    UnexpectedFrame {
        expected: MessageType,
        got: MessageType,
    },
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("decode: {0}")]
    Decode(String),
}
