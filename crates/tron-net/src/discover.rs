//! UDP peer-discovery protocol (Kademlia-style).
//!
//! TRON's libp2p library carries discovery messages over UDP on the
//! same port as the TCP connection layer (18888 on mainnet). The wire
//! format per UDP packet is:
//!
//! ```text
//!   [type_byte (1)] [protobuf-encoded payload]
//! ```
//!
//! There's no length prefix — each UDP datagram is one whole message.
//!
//! ## Message types
//!
//! | Byte | Name           | Proto type                                  |
//! |------|----------------|---------------------------------------------|
//! | 0x01 | KAD_PING       | `protocol.PingMessage`                      |
//! | 0x02 | KAD_PONG       | `protocol.PongMessage`                      |
//! | 0x03 | KAD_FIND_NODE  | `protocol.FindNeighbours`                   |
//! | 0x04 | KAD_NEIGHBORS  | `protocol.Neighbours`                       |
//!
//! Source: `org.tron.p2p.discover.message.MessageType` and the
//! `Discover.proto` schema (vendored in our `tron-proto` crate as the
//! `protocol` module).
//!
//! ## Bootstrap flow
//!
//! [`bootstrap`] runs the canonical sequence against a single seed:
//!
//! 1. Send `PING(from=us, to=seed)` to the seed's UDP port.
//! 2. Wait for `PONG(from=seed, echo=our_ping_bytes)` — proves liveness.
//! 3. Send `FIND_NODE(from=us, targetId=random)` — asks for peers
//!    "close to" `targetId` in XOR-distance over the 64-byte node-id
//!    space.
//! 4. Wait for `NEIGHBORS(from=seed, neighbours=[Endpoint, ...])` —
//!    up to ~16 peers we can dial.
//!
//! Returns the discovered `Endpoint`s. The caller feeds them to the
//! TCP-side connection pool.

use std::net::SocketAddr;
use std::time::Duration;

use prost::Message;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tron_proto::{Endpoint, FindNeighbours, Neighbours, PingMessage, PongMessage};

/// `KAD_PING` — 0x01.
pub const KAD_PING: u8 = 0x01;
/// `KAD_PONG` — 0x02.
pub const KAD_PONG: u8 = 0x02;
/// `KAD_FIND_NODE` — 0x03.
pub const KAD_FIND_NODE: u8 = 0x03;
/// `KAD_NEIGHBORS` — 0x04.
pub const KAD_NEIGHBORS: u8 = 0x04;

/// Largest UDP packet a TRON discovery node will read. Matches
/// `P2pPacketDecoder.MAXSIZE` in libp2p.
pub const UDP_MAX_PACKET_BYTES: usize = 2048;

/// Frame a discovery message: `[type_byte][payload]`. UDP datagrams
/// are self-delimiting so no length prefix is added.
pub fn encode_packet(ty: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(ty);
    out.extend_from_slice(payload);
    out
}

/// Split an incoming UDP datagram into `(type_byte, payload)`. Returns
/// `None` for the malformed-packet cases libp2p silently drops:
/// length `<= 1` (no payload) or `>= UDP_MAX_PACKET_BYTES`.
pub fn decode_packet(buf: &[u8]) -> Option<(u8, &[u8])> {
    if buf.len() <= 1 || buf.len() >= UDP_MAX_PACKET_BYTES {
        return None;
    }
    Some((buf[0], &buf[1..]))
}

/// Build a PING message: "I'm `from`, are you `to`?"
pub fn build_ping(from: Endpoint, to: Endpoint, network_id: i32, timestamp_ms: i64) -> PingMessage {
    PingMessage {
        from: Some(from),
        to: Some(to),
        version: network_id,
        timestamp: timestamp_ms,
    }
}

/// Build a FIND_NODE asking for neighbours close to `target_id`.
/// `target_id` is the 64-byte node-id we want to find — typically a
/// random value at bootstrap time so peers send us a diverse set.
pub fn build_find_node(from: Endpoint, target_id: Vec<u8>, timestamp_ms: i64) -> FindNeighbours {
    FindNeighbours {
        from: Some(from),
        target_id,
        timestamp: timestamp_ms,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoverError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("seed didn't respond within budget")]
    Timeout,
    #[error("malformed UDP packet from seed")]
    MalformedPacket,
    #[error("seed replied with unexpected message type {0:#x} (expected {1:#x})")]
    WrongMessageType(u8, u8),
    #[error("proto decode: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Run a one-shot discovery query against a single seed.
///
/// Times out after `budget` if the seed doesn't respond. On success
/// returns the seed's NEIGHBORS list.
///
/// ## What the seed will validate
///
/// `Endpoint.address` must be the **ASCII string** of an IPv4 (per
/// `NetUtil.validNode`) — same gotcha as the TCP-layer handshake.
/// `Endpoint.node_id` must be 64 bytes (`Constant.NODE_ID_LEN`).
pub async fn bootstrap(
    seed: SocketAddr,
    local: Endpoint,
    network_id: i32,
    timestamp_ms: i64,
    target_id: [u8; 64],
    budget: Duration,
) -> Result<Vec<Endpoint>, DiscoverError> {
    // Build a UDP socket bound to any local port. Mainnet seeds reply
    // to whatever port we sent from.
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(seed).await?;

    // === 1. Send PING.
    let ping = build_ping(
        local.clone(),
        // `to` doesn't need a node_id; the seed cares about (address, port).
        Endpoint {
            address: format!("{}", seed.ip()).into_bytes(),
            port: seed.port() as i32,
            node_id: vec![],
            address_ipv6: vec![],
        },
        network_id,
        timestamp_ms,
    );
    let ping_bytes = encode_packet(KAD_PING, &ping.encode_to_vec());
    sock.send(&ping_bytes).await?;

    // === 2. Wait for PONG.
    let mut buf = vec![0u8; UDP_MAX_PACKET_BYTES];
    let pong_packet = recv_typed(&sock, &mut buf, KAD_PONG, budget).await?;
    let _pong = PongMessage::decode(pong_packet)?;

    // === 3. Send FIND_NODE.
    let find = build_find_node(local, target_id.to_vec(), timestamp_ms);
    let find_bytes = encode_packet(KAD_FIND_NODE, &find.encode_to_vec());
    sock.send(&find_bytes).await?;

    // === 4. Wait for NEIGHBORS.
    let mut buf2 = vec![0u8; UDP_MAX_PACKET_BYTES];
    let neighbours_packet = recv_typed(&sock, &mut buf2, KAD_NEIGHBORS, budget).await?;
    let neighbours = Neighbours::decode(neighbours_packet)?;
    Ok(neighbours.neighbours)
}

/// Receive UDP datagrams until one matches `expected_ty`, or the
/// budget elapses. Non-matching datagrams (e.g. a PING from the seed
/// asking us to prove liveness) are ignored — bootstrap only cares
/// about the reply train.
async fn recv_typed<'a>(
    sock: &UdpSocket,
    buf: &'a mut [u8],
    expected_ty: u8,
    budget: Duration,
) -> Result<&'a [u8], DiscoverError> {
    let mut len = 0usize;
    let outcome = timeout(budget, async {
        loop {
            let n = sock.recv(buf).await.map_err(DiscoverError::Io)?;
            let view = &buf[..n];
            let Some((ty, _payload)) = decode_packet(view) else {
                continue;
            };
            if ty == expected_ty {
                len = n;
                return Ok::<(), DiscoverError>(());
            }
            // Different message — usually a peer-initiated PING. Ignore.
        }
    })
    .await;
    match outcome {
        Ok(Ok(())) => {
            let view = &buf[..len];
            let (ty, payload) = decode_packet(view).ok_or(DiscoverError::MalformedPacket)?;
            debug_assert_eq!(ty, expected_ty);
            Ok(payload)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(DiscoverError::Timeout),
    }
}
