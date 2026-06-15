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
//!
//! ## Security boundary: plaintext, unauthenticated (no TLS) (N-38)
//!
//! The TRON P2P protocol is **cleartext** — there is no transport
//! encryption and no per-peer authentication, matching java-tron /
//! tronprotocol-libp2p. Concretely:
//!
//! * **TCP sync ([`peer`], [`sync`]):** frames travel in the clear; any
//!   on-path observer can read and tamper with them, and a peer's
//!   advertised identity (`node_id`, endpoint) is unverified beyond the
//!   genesis / version handshake checks. The only authenticity guarantee
//!   is *chain-level*: blocks are validated against the local chain
//!   (witness signatures, hashes), so a tampering MITM can stall or feed
//!   junk but cannot forge accepted state. Treat every byte from a peer as
//!   adversarial input — which is why frames are size-capped
//!   ([`MAX_FRAME_BYTES`], [`InboundByteBudget`]), handshakes are
//!   timeout-bounded, and node-ids are length-validated ([`NODE_ID_LEN`]).
//! * **UDP discovery ([`kad`], [`discover`]):** unauthenticated datagrams
//!   with spoofable source IPs; see [`kad`]'s module docs for the bonding /
//!   anti-amplification / rate-limit defenses that make the routing table
//!   trustworthy despite this.
//! * **DNS discovery ([`dns`]):** records are signed (the root signature is
//!   verified) but served over plain DNS; entries are re-validated at the
//!   TCP handshake regardless.
//!
//! There is **no confidentiality** on this network: do not put anything
//! secret on the wire. Operators who need link encryption must tunnel the
//! port (WireGuard / IPsec) — it is out of scope for this crate.

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
    build_hello, to_wire_block_id, HelloInputs, MAINNET_P2P_VERSION, NILE_P2P_VERSION,
    SHASTA_P2P_VERSION,
};
pub use message_type::{MessageType, MessageTypeError};
pub use peer::{
    DisconnectReason, HandshakeError, HandshakeOutcome, Libp2pHelloInputs, PeerConnection,
    TronState, DEFAULT_HANDSHAKE_TIMEOUT, NODE_ID_LEN,
};
pub use sync::{
    recv_block, recv_chain_inventory, recv_fetch_inv_data, recv_sync_request, send_block,
    send_chain_inventory, send_fetch_inv_data, send_sync_request, SyncError,
};
pub use transport::{Frame, FrameError, InboundByteBudget, TronFrameCodec, MAX_FRAME_BYTES};
pub use varint::{decode_varint32, encode_varint32, VarintError, MAX_VARINT32_BYTES};
