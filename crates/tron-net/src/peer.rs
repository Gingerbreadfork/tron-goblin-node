//! Per-peer connection state machine.
//!
//! Mirrors `org.tron.core.net.peer.TronState`:
//!
//! ```text
//! INIT  ──send Hello──▶  HANDSHAKE  ──recv Hello──▶  SYNCING  ──sync done──▶  OK
//! ```
//!
//! The handshake portion (INIT → HANDSHAKE → SYNCING) is what this
//! module implements; the SYNCING → OK transition happens later when
//! the chain-sync layer signals catch-up.
//!
//! Outgoing connections start in `INIT`. Incoming connections start in
//! `INIT` too — both sides race to send Hello first; either order is
//! accepted by java-tron.
//!
//! On a peer-initiated `DisconnectMessage` we record the
//! [`DisconnectReason`] and tear the connection down.

use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tron_proto::libp2p::{
    compress_message::CompressType, CompressMessage, ConnectHelloMessage, DisconnectReasonCode,
    P2pDisconnectMessage,
};
use tron_proto::{DisconnectMessage, Endpoint, HelloMessage, ReasonCode};

use crate::hello::{build_hello, HelloInputs};
use crate::message_type::MessageType;
use crate::transport::{Frame, FrameError, TronFrameCodec, MAX_FRAME_BYTES};

/// Inputs needed for the libp2p-layer (connection-level) Hello.
///
/// This message wraps every TRON peer session and must be exchanged
/// **before** the application-level [`HelloMessage`] gets through. See
/// [`PeerConnection::libp2p_handshake`].
#[derive(Debug, Clone)]
pub struct Libp2pHelloInputs {
    /// Our local endpoint: ip address bytes, port, 64-byte node id.
    pub from: Endpoint,
    /// `Parameter.p2pConfig.networkId` on java-tron. Mainnet uses `11111`.
    pub network_id: i32,
    /// `Parameter.version` — separate from app-level `HelloMessage.version`.
    /// On current mainnet libp2p this is `2` (v0.2 of the connection
    /// protocol, which carries both `version` and `network_id`).
    pub version: i32,
    pub timestamp_ms: i64,
}

/// Connection lifecycle. Matches java-tron's `TronState` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TronState {
    /// Newly accepted/dialed; nothing sent or received yet.
    Init,
    /// We've sent our Hello; awaiting peer's Hello.
    Handshake,
    /// Both Hellos exchanged; chain sync in progress.
    Syncing,
    /// Fully synced and serving requests.
    Ok,
}

/// Default upper bound on how long each handshake read waits for the
/// peer's frame before failing with [`HandshakeError::TimedOut`]. Without
/// it, a peer that opens TCP and then sends nothing pins the task and its
/// file descriptor indefinitely (slowloris — N-1). Override per-connection
/// with [`PeerConnection::with_handshake_timeout`].
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Max time to establish the TCP connection in [`PeerConnection::dial`] before
/// giving up. A bare `TcpStream::connect` to a dead/firewalled host blocks for
/// the OS SYN-retry default (~20-75s on Linux), so without this a startup that
/// dials many unreachable public peers stalls for minutes before finding a live
/// one. A reachable peer completes the TCP handshake in well under a second
/// (one RTT), so 5s is generous while still failing dead hosts fast.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A bidirectional framed connection to a single peer.
pub struct PeerConnection<S> {
    framed: Framed<S, TronFrameCodec>,
    state: TronState,
    /// The Hello the peer sent us. `None` until handshake completes —
    /// also `None` if the peer skipped sending a Hello and jumped
    /// straight to application traffic (current mainnet behavior on
    /// some node versions).
    peer_hello: Option<HelloMessage>,
    /// A frame read during the handshake that turned out NOT to be a
    /// Hello — typically an immediate `BlockInventory` from a peer
    /// that accepted us implicitly. Held here so the next call to
    /// `next_frame` returns it before reading more from the socket.
    early_frame: Option<Frame>,
    /// True once the libp2p handshake completes. Post-handshake,
    /// every frame in BOTH directions is wrapped in a
    /// `CompressMessage` (tronprotocol/libp2p's `UpgradeController`):
    /// outbound `send_frame` packs each frame as
    /// `CompressMessage{type=uncompress, data=[type_byte][payload]}`;
    /// inbound `next_frame` unpacks the same shape and returns the
    /// inner `Frame`. Snappy compression is not yet supported on
    /// either side.
    compress_wrap: bool,
    /// Per-read upper bound applied to both handshake phases. Defaults to
    /// [`DEFAULT_HANDSHAKE_TIMEOUT`]; see
    /// [`PeerConnection::with_handshake_timeout`].
    handshake_timeout: Duration,
}

impl<S> PeerConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap a duplex byte stream (TCP, mock duplex, etc.) into a framed
    /// peer connection in the [`TronState::Init`] state.
    pub fn new(stream: S) -> Self {
        Self {
            framed: Framed::new(stream, TronFrameCodec::new()),
            state: TronState::Init,
            peer_hello: None,
            early_frame: None,
            compress_wrap: false,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    pub fn state(&self) -> TronState {
        self.state
    }

    pub fn peer_hello(&self) -> Option<&HelloMessage> {
        self.peer_hello.as_ref()
    }

    /// Override the handshake read timeout (default
    /// [`DEFAULT_HANDSHAKE_TIMEOUT`]). Builder-style; intended for an
    /// inbound listener that wants a tighter bound, or for tests.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Run the libp2p connection-layer handshake. **Must be called
    /// before [`handshake`]** on every TCP connection to a mainnet peer.
    ///
    /// Wire protocol (each side sends one frame, may interleave):
    /// 1. Send `[type=0xfd][Connect.HelloMessage payload]`
    /// 2. Receive peer's `[type=0xfd]` Hello — verify `network_id`
    ///    matches ours, verify `code == 0` (normal). Anything else is
    ///    refused.
    /// 3. Peer may instead lead with `[type=0xfb]` `P2pDisconnectMessage`
    ///    to refuse us; we surface the reason as `PeerDisconnected`.
    ///
    /// Source: `org.tron.p2p.connection.business.handshake.HandshakeService`
    /// in https://github.com/tronprotocol/libp2p.
    pub async fn libp2p_handshake(
        &mut self,
        local: Libp2pHelloInputs,
    ) -> Result<ConnectHelloMessage, HandshakeError> {
        if self.state != TronState::Init {
            return Err(HandshakeError::WrongState(self.state));
        }

        let local_network_id = local.network_id;

        let outbound = ConnectHelloMessage {
            from: Some(local.from),
            network_id: local.network_id,
            code: 0, // DisconnectCode.NORMAL — "I want to handshake"
            timestamp: local.timestamp_ms,
            version: local.version,
        };
        self.framed
            .send(Frame {
                ty: MessageType::Libp2pHandshakeHello,
                payload: Bytes::from(outbound.encode_to_vec()),
            })
            .await?;

        let frame = self.next_frame_required().await?;

        if frame.ty == MessageType::Libp2pDisconnect {
            let dc = P2pDisconnectMessage::decode(frame.payload)
                .map_err(|e| HandshakeError::Decode(e.to_string()))?;
            return Err(HandshakeError::Libp2pDisconnected(dc.reason));
        }
        if frame.ty != MessageType::Libp2pHandshakeHello {
            return Err(HandshakeError::UnexpectedFrame(frame.ty));
        }

        let peer_hello: ConnectHelloMessage = ConnectHelloMessage::decode(frame.payload)
            .map_err(|e| HandshakeError::Decode(e.to_string()))?;

        // java-tron's handshake check (HandshakeService.processMessage):
        // refuse if the peer's `code` isn't NORMAL or their network_id
        // doesn't match ours.
        if peer_hello.code != 0 {
            return Err(HandshakeError::Libp2pDisconnected(peer_hello.code));
        }
        if peer_hello.network_id != local_network_id {
            return Err(HandshakeError::IncompatibleNetworkId {
                ours: local_network_id,
                theirs: peer_hello.network_id,
            });
        }

        // Post-libp2p-handshake, BOTH directions wrap frames in
        // `CompressMessage`. Enable wrap/unwrap before the app-level
        // Hello so our outbound P2pHello goes through correctly.
        if peer_hello.version >= 1 {
            self.compress_wrap = true;
        }

        // Stay in Init — the app-level `handshake` runs next, which is
        // the one that transitions to Handshake/Syncing.
        Ok(peer_hello)
    }

    /// Run the full handshake from this side. Sends our [`HelloMessage`],
    /// waits for the peer's, validates basic compatibility, and
    /// transitions [`TronState::Init`] → `Handshake` → `Syncing`.
    ///
    /// On success returns a [`HandshakeOutcome`]: `Verified` carries the
    /// peer's chain-checked `HelloMessage`; `ImplicitAccept` means the
    /// peer skipped its reciprocal Hello and went straight to streaming
    /// (its chain id is therefore unverified — see N-5 / N-30).
    pub async fn handshake(
        &mut self,
        local: HelloInputs<'_>,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        if self.state != TronState::Init {
            return Err(HandshakeError::WrongState(self.state));
        }

        // Snapshot the version we're advertising so we can compare to
        // the peer's after we receive their Hello.
        let local_version = local.version;
        let local_genesis = local.genesis;

        let hello = build_hello(local);
        let payload = Bytes::from(hello.encode_to_vec());
        // Route through `send_frame` so the CompressMessage wrap is
        // applied when `compress_wrap` is set. The peer flips its
        // `finishHandshake = true` flag the moment libp2p_handshake
        // completes — every byte we send from now on must be wrapped,
        // including this first app-level Hello, or the peer responds
        // with Libp2pDisconnect(BAD_MESSAGE = 0x0B).
        self.send_frame(Frame {
            ty: MessageType::P2pHello,
            payload,
        })
        .await?;
        self.state = TronState::Handshake;

        let frame = self.next_frame_required().await?;

        // Peer can legally lead with Disconnect to refuse us.
        if frame.ty == MessageType::P2pDisconnect {
            let dc = DisconnectMessage::decode(frame.payload)
                .map_err(|e| HandshakeError::Decode(e.to_string()))?;
            return Err(HandshakeError::PeerDisconnected(
                DisconnectReason::from(dc.reason),
            ));
        }

        // Current mainnet behavior: some peers accept our Hello
        // implicitly and immediately start streaming application
        // traffic (typically `BlockInventory` announcing new blocks
        // since our `head` in the Hello) without sending a reciprocal
        // `P2pHello`. We treat any first frame OTHER than Hello /
        // Disconnect as "implicit accept": handshake succeeds, the
        // peer's Hello data is unavailable (peer_hello stays None),
        // and the early frame is stashed so `next_frame` returns it
        // before reading more from the socket.
        if frame.ty != MessageType::P2pHello {
            // Surface implicit-accept as its own outcome rather than
            // fabricating an `Ok(HelloMessage::default())` — returning a
            // default Hello would tell the caller the peer passed the
            // version / genesis checks when it never sent a Hello at all
            // (N-5). `peer_hello` deliberately stays `None`.
            self.early_frame = Some(frame);
            self.state = TronState::Syncing;
            return Ok(HandshakeOutcome::ImplicitAccept);
        }

        let peer_hello =
            HelloMessage::decode(frame.payload).map_err(|e| HandshakeError::Decode(e.to_string()))?;

        // Compatibility checks. java-tron rejects on either of these
        // with INCOMPATIBLE_VERSION or INCOMPATIBLE_CHAIN.
        if peer_hello.version != local_version {
            return Err(HandshakeError::IncompatibleVersion {
                ours: local_version,
                theirs: peer_hello.version,
            });
        }
        // Fail closed on chain identity: a peer that omits
        // `genesis_block_id` has NOT proved it is on our chain, so treat
        // "missing" the same as "mismatch" (N-30). Real java-tron peers
        // always include it.
        match &peer_hello.genesis_block_id {
            Some(theirs) if theirs.hash == local_genesis.as_bytes() => {}
            _ => return Err(HandshakeError::IncompatibleChain),
        }

        self.peer_hello = Some(peer_hello.clone());
        self.state = TronState::Syncing;
        Ok(HandshakeOutcome::Verified(peer_hello))
    }

    /// Politely terminate the connection with a `DisconnectMessage`.
    pub async fn disconnect(&mut self, reason: ReasonCode) -> Result<(), FrameError> {
        let msg = DisconnectMessage {
            reason: reason as i32,
        };
        let payload = Bytes::from(msg.encode_to_vec());
        self.send_frame(Frame {
            ty: MessageType::P2pDisconnect,
            payload,
        })
        .await
    }

    /// Send an arbitrary application frame after the handshake.
    ///
    /// When `compress_wrap` is enabled (post-libp2p-handshake), the
    /// frame is wrapped in a `CompressMessage` proto before being put
    /// on the wire. Snappy compression is not yet supported on the
    /// send side — every frame is sent with `type = uncompress`.
    pub async fn send_frame(&mut self, frame: Frame) -> Result<(), FrameError> {
        // Outbound-frame trace (debug). Lets a diagnostic run see exactly
        // which app message we sent last before a peer disconnects us (e.g.
        // BAD_PROTOCOL on the sync exchange). Cheap; gated by log level.
        tracing::debug!(ty = ?frame.ty, len = frame.payload.len(), "tx frame");
        if self.compress_wrap {
            let mut inner = Vec::with_capacity(1 + frame.payload.len());
            inner.push(frame.ty.as_byte());
            inner.extend_from_slice(&frame.payload);
            // Match java-tron's `ProtoUtil.compressMessage`: try snappy,
            // keep only if it's smaller than the raw bytes.
            let (compress_ty, data) = {
                let mut enc = snap::raw::Encoder::new();
                match enc.compress_vec(&inner) {
                    Ok(c) if c.len() < inner.len() => (CompressType::Snappy as i32, c),
                    _ => (CompressType::Uncompress as i32, inner),
                }
            };
            let wrapped = CompressMessage {
                r#type: compress_ty,
                data,
            };
            let proto_bytes = wrapped.encode_to_vec();
            // The codec wants `[type_byte][payload]`. We use the first
            // byte of the proto encoding as the codec's "type byte"
            // (always 0x08 or 0x12 — both valid `MessageType` enum
            // values), and pass the rest as the payload. The on-wire
            // result is identical to `[varint_len][proto_bytes]`.
            let ty_byte = proto_bytes[0];
            let ty = MessageType::from_byte(ty_byte).map_err(FrameError::BadType)?;
            return self
                .framed
                .send(Frame {
                    ty,
                    payload: Bytes::from(proto_bytes[1..].to_vec()),
                })
                .await;
        }
        self.framed.send(frame).await
    }

    /// Read the next frame off the wire. `None` on clean EOF.
    ///
    /// If the handshake stashed an `early_frame` (the peer accepted
    /// us implicitly and sent app traffic before any Hello), that
    /// frame is returned first; subsequent calls drain from the
    /// socket as usual.
    ///
    /// When `compress_wrap` is enabled (post-libp2p-handshake), the
    /// frame received from the codec is reassembled as proto bytes,
    /// decoded as `CompressMessage`, and the inner `data` field is
    /// re-split into `[type_byte][payload]` to produce the real
    /// `Frame` the caller expects.
    pub async fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if let Some(f) = self.early_frame.take() {
            return Ok(Some(f));
        }
        let raw = match self.framed.next().await {
            Some(Ok(f)) => f,
            Some(Err(e)) => return Err(e),
            None => return Ok(None),
        };
        if !self.compress_wrap {
            return Ok(Some(raw));
        }
        // Reassemble the proto bytes: `[ty_byte][payload]` IS the
        // serialized `CompressMessage` (the codec only sees the first
        // byte as a "type byte" for routing — actually it's a proto tag).
        let mut proto_bytes = Vec::with_capacity(1 + raw.payload.len());
        proto_bytes.push(raw.ty.as_byte());
        proto_bytes.extend_from_slice(&raw.payload);
        let compressed = CompressMessage::decode(proto_bytes.as_slice())
            .map_err(|e| FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decode CompressMessage: {e}"),
            )))?;
        let data = match CompressType::try_from(compressed.r#type) {
            Ok(CompressType::Uncompress) => compressed.data,
            Ok(CompressType::Snappy) => snappy_decompress_checked(&compressed.data)?,
            Err(_) => {
                return Err(FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown CompressMessage.type {}", compressed.r#type),
                )));
            }
        };
        if data.is_empty() {
            return Err(FrameError::EmptyFrame);
        }
        let inner_ty_byte = data[0];
        let inner_ty = MessageType::from_byte(inner_ty_byte).map_err(FrameError::BadType)?;
        let inner_payload: Bytes = Bytes::from(data[1..].to_vec());
        Ok(Some(Frame {
            ty: inner_ty,
            payload: inner_payload,
        }))
    }

    async fn next_frame_required(&mut self) -> Result<Frame, HandshakeError> {
        // Bound the read so a peer that connects but never sends can't
        // pin this task and its FD forever (N-1). Both handshake phases
        // funnel their reads through here, so one timeout covers both.
        let limit = self.handshake_timeout;
        match tokio::time::timeout(limit, self.next_frame()).await {
            Ok(Ok(Some(f))) => Ok(f),
            Ok(Ok(None)) => Err(HandshakeError::ClosedDuringHandshake),
            Ok(Err(e)) => Err(HandshakeError::from(e)),
            Err(_elapsed) => Err(HandshakeError::TimedOut(limit)),
        }
    }
}

/// Decompress a snappy frame, rejecting a decompression bomb whose
/// declared output exceeds [`MAX_FRAME_BYTES`] *before* allocating (N-4).
/// The on-wire frame is already capped, but snappy can inflate ~10 MiB
/// into hundreds of MiB; `decompress_len` reads only the frame's varint
/// size prefix, so the guard is O(1) and allocation-free.
fn snappy_decompress_checked(data: &[u8]) -> Result<Vec<u8>, FrameError> {
    let declared = snap::raw::decompress_len(data).map_err(|e| {
        FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("snappy decompress_len: {e}"),
        ))
    })?;
    if declared > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    snap::raw::Decoder::new().decompress_vec(data).map_err(|e| {
        FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("snappy decode: {e}"),
        ))
    })
}

/// Outbound-dial convenience for the common case of a real TCP socket.
/// The caller still drives the handshake afterwards.
impl PeerConnection<TcpStream> {
    pub async fn dial(addr: impl tokio::net::ToSocketAddrs) -> Result<Self, std::io::Error> {
        // Bound the TCP connect so a dead/firewalled host fails fast instead of
        // blocking for the OS SYN-retry default — otherwise dialing through a
        // pool of mostly-unreachable public peers stalls startup for minutes.
        let stream = tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp connect timed out")
            })??;
        Ok(Self::new(stream))
    }
}

/// Friendly enum over [`ReasonCode`] for handshake-failure reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectReason(pub i32);

impl From<i32> for DisconnectReason {
    fn from(v: i32) -> Self {
        Self(v)
    }
}

impl std::fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match ReasonCode::try_from(self.0) {
            Ok(r) => write!(f, "{r:?}"),
            Err(_) => write!(f, "unknown reason ({})", self.0),
        }
    }
}

/// Outcome of the app-level [`PeerConnection::handshake`].
///
/// A handshake can complete two ways, and distinguishing them is a
/// chain-safety requirement: an *implicit accept* means the peer never
/// proved it is on our chain, so the caller MUST NOT treat it as
/// verified (see N-5 / N-30).
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeOutcome {
    /// The peer replied with a `P2pHello` that passed the protocol
    /// version and genesis / chain-id checks. The same message is also
    /// retrievable via [`PeerConnection::peer_hello`].
    Verified(HelloMessage),
    /// The peer accepted us implicitly: instead of a reciprocal
    /// `P2pHello` it began streaming application traffic (the first such
    /// frame is stashed and returned by the next
    /// [`PeerConnection::next_frame`]). The handshake therefore did NOT
    /// verify the peer's protocol version or genesis / chain id, and
    /// [`PeerConnection::peer_hello`] stays `None`. Callers must enforce
    /// chain identity another way (e.g. validating delivered blocks
    /// against the local chain) before trusting this peer's stream.
    ImplicitAccept,
}

impl HandshakeOutcome {
    /// `true` if the peer accepted us implicitly (no reciprocal,
    /// chain-verified `P2pHello`).
    pub fn is_implicit_accept(&self) -> bool {
        matches!(self, HandshakeOutcome::ImplicitAccept)
    }

    /// The verified peer `HelloMessage`, or `None` for an implicit accept.
    pub fn hello(&self) -> Option<&HelloMessage> {
        match self {
            HandshakeOutcome::Verified(h) => Some(h),
            HandshakeOutcome::ImplicitAccept => None,
        }
    }

    /// Consume the outcome, returning the verified peer `HelloMessage`,
    /// or `None` for an implicit accept.
    pub fn into_hello(self) -> Option<HelloMessage> {
        match self {
            HandshakeOutcome::Verified(h) => Some(h),
            HandshakeOutcome::ImplicitAccept => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("handshake started in wrong state: {0:?}")]
    WrongState(TronState),
    #[error("peer disconnected during handshake: {0}")]
    PeerDisconnected(DisconnectReason),
    #[error("peer sent unexpected frame type {0:?} instead of Hello")]
    UnexpectedFrame(MessageType),
    #[error("connection closed before peer Hello arrived")]
    ClosedDuringHandshake,
    #[error("no peer frame within handshake timeout ({0:?})")]
    TimedOut(Duration),
    #[error("incompatible p2p version: ours={ours}, theirs={theirs}")]
    IncompatibleVersion { ours: i32, theirs: i32 },
    #[error("incompatible chain (genesis hash mismatch)")]
    IncompatibleChain,
    #[error("peer refused libp2p handshake with code {0} ({})", libp2p_handshake_code_name(*.0))]
    Libp2pDisconnected(i32),
    #[error("incompatible libp2p network id: ours={ours}, theirs={theirs}")]
    IncompatibleNetworkId { ours: i32, theirs: i32 },
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("decode: {0}")]
    Decode(String),
}

/// Map a libp2p `DisconnectReasonCode` integer to its string name.
/// Use this for `P2pDisconnectMessage.reason` (post-handshake disconnects).
/// Do NOT use it for the `code` field of `HelloMessage` — that field
/// is a SEPARATE enum, `DisconnectCode.java`, with completely different
/// numeric values (e.g. `3` is `TIME_BANNED` in `DisconnectCode` but
/// `DUPLICATE_PEER` in `DisconnectReason`). See `libp2p_handshake_code_name`.
#[allow(dead_code)]
fn libp2p_reason_name(code: i32) -> &'static str {
    match DisconnectReasonCode::try_from(code) {
        Ok(r) => r.as_str_name(),
        Err(_) => "UNKNOWN_CODE",
    }
}

/// Map the `code` field of `HelloMessage` (libp2p connection-layer
/// handshake) to its name. Mirrors `org.tron.p2p.connection.business
/// .handshake.DisconnectCode` — values differ from `DisconnectReason`.
fn libp2p_handshake_code_name(code: i32) -> &'static str {
    match code {
        0 => "NORMAL",
        1 => "TOO_MANY_PEERS",
        2 => "DIFFERENT_VERSION",
        3 => "TIME_BANNED",
        4 => "DUPLICATE_PEER",
        5 => "MAX_CONNECTION_WITH_SAME_IP",
        256 => "UNKNOWN",
        _ => "UNKNOWN_CODE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snappy_decompress_checked_round_trips_normal_frames() {
        let original = b"hello snappy world".repeat(64);
        let compressed = snap::raw::Encoder::new().compress_vec(&original).unwrap();
        let got = snappy_decompress_checked(&compressed).expect("normal frame decompresses");
        assert_eq!(got, original);
    }

    #[test]
    fn snappy_decompress_checked_rejects_decompression_bomb() {
        // A tiny compressed frame can declare a huge output. Craft one
        // that decompresses to just over MAX_FRAME_BYTES and confirm it's
        // rejected by size — before any large allocation — rather than
        // ballooning memory.
        let bomb_size = MAX_FRAME_BYTES + 1024 * 1024; // 11 MiB declared
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&vec![0u8; bomb_size])
            .unwrap();
        assert!(
            compressed.len() < MAX_FRAME_BYTES,
            "compressed bomb must still fit the on-wire frame cap"
        );
        assert!(matches!(
            snappy_decompress_checked(&compressed),
            Err(FrameError::TooLarge)
        ));
    }
}
