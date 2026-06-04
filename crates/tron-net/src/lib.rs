//! Wire framing for the TRON P2P protocol.
//!
//! Every TRON message sent over the wire is a one-byte **type tag** followed
//! by a protobuf-encoded payload. This crate owns the type-tag enum and the
//! envelope encode/decode logic. TCP-layer concerns (length prefixing,
//! connection setup, peer discovery) live in a higher layer and are
//! deferred until the rest of the node has shape.
//!
//! Source: `org.tron.common.overlay.message.Message.getSendBytes` —
//! `ArrayUtils.add(this.getData(), 0, type)` prepends the type byte at
//! position 0 of the payload. There is no length prefix at this layer.

pub mod discover;
pub mod dns;
pub mod envelope;
pub mod hello;
pub mod kad;
pub mod message_type;
pub mod peer;
pub mod sync;
pub mod transport;
pub mod varint;

pub use discover::{
    bootstrap as bootstrap_discovery, decode_packet as decode_discover_packet,
    encode_packet as encode_discover_packet, DiscoverError, KAD_FIND_NODE, KAD_NEIGHBORS,
    KAD_PING, KAD_PONG,
};
pub use dns::{parse_tree_url, resolve as resolve_dns_tree, DnsError, TreeUrl};
pub use kad::{KadHandle, KadService, Node as KadNode, RoutingTable};

pub use envelope::{decode_envelope, encode_envelope, message_id, EnvelopeError};
pub use hello::{
    build_hello, to_wire_block_id, HelloInputs, MAINNET_P2P_VERSION, MAINNET_SEEDS,
    NILE_P2P_VERSION, SHASTA_P2P_VERSION,
};
pub use message_type::{MessageType, MessageTypeError};
pub use peer::{
    DisconnectReason, HandshakeError, HandshakeOutcome, Libp2pHelloInputs, PeerConnection,
    TronState, DEFAULT_HANDSHAKE_TIMEOUT,
};
pub use sync::{
    recv_block, recv_chain_inventory, recv_fetch_inv_data, recv_sync_request, send_block,
    send_chain_inventory, send_fetch_inv_data, send_sync_request, SyncError,
};
pub use transport::{Frame, FrameError, TronFrameCodec, MAX_FRAME_BYTES};
pub use varint::{decode_varint32, encode_varint32, VarintError, MAX_VARINT32_BYTES};
