//! Transport-layer tests: varint codec, frame codec, and in-memory
//! two-peer handshake via [`tokio::io::duplex`].

use bytes::{Bytes, BytesMut};
use prost::Message as _;
use tokio_util::codec::{Decoder, Encoder};
use tron_net::{
    decode_varint32, encode_varint32, peer::TronState, varint::VarintError, Frame, HelloInputs,
    MessageType, PeerConnection, TronFrameCodec, MAINNET_P2P_VERSION,
};
use tron_proto::{Endpoint, HelloMessage};
use tron_types::{genesis_block_id, mainnet_inputs, BlockId};

// =============================================================================
// Varint codec
// =============================================================================

#[test]
fn varint_round_trip_typical_values() {
    let cases: &[(u32, &[u8])] = &[
        (0, &[0x00]),
        (1, &[0x01]),
        (127, &[0x7f]),
        (128, &[0x80, 0x01]),
        (300, &[0xac, 0x02]),
        (16_384, &[0x80, 0x80, 0x01]),
        (u32::MAX, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
    ];
    for &(v, expected) in cases {
        let mut buf = BytesMut::new();
        let n = encode_varint32(&mut buf, v);
        assert_eq!(&buf[..], expected, "encode({v})");
        assert_eq!(n, expected.len());

        let decoded = decode_varint32(&buf).unwrap().unwrap();
        assert_eq!(decoded, (v, expected.len()), "decode({v})");
    }
}

#[test]
fn varint_short_input_yields_none() {
    // A partial multi-byte varint should return Ok(None) (need more data).
    let partial = &[0x80, 0x80]; // would need a third byte
    assert_eq!(decode_varint32(partial).unwrap(), None);
}

#[test]
fn varint_too_long_is_protocol_error() {
    // 6 bytes with all continuation bits set is over the 5-byte cap.
    let bad = &[0x80u8; 6];
    assert_eq!(decode_varint32(bad), Err(VarintError::TooLong));
}

// =============================================================================
// Frame codec
// =============================================================================

#[test]
fn frame_encode_emits_varint_then_type_then_payload() {
    let mut codec = TronFrameCodec::new();
    let mut buf = BytesMut::new();
    codec
        .encode(
            Frame {
                ty: MessageType::P2pHello,
                payload: Bytes::from_static(&[0xaa, 0xbb, 0xcc]),
            },
            &mut buf,
        )
        .unwrap();
    // body = 1 type byte + 3 payload bytes = 4. Varint(4) = [0x04].
    assert_eq!(buf[0], 0x04, "varint length prefix");
    assert_eq!(buf[1], 0x20, "MessageType::P2pHello byte");
    assert_eq!(&buf[2..], &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn frame_decode_round_trip() {
    let mut codec = TronFrameCodec::new();
    let mut buf = BytesMut::new();
    let payload = Bytes::from_static(&[1, 2, 3, 4, 5]);
    let frame = Frame {
        ty: MessageType::Trx,
        payload: payload.clone(),
    };
    codec.encode(frame.clone(), &mut buf).unwrap();

    let mut decoder = TronFrameCodec::new();
    let decoded = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded, frame);
    assert!(buf.is_empty());
}

/// **Streaming property**: the decoder must wait for a full frame and
/// return `Ok(None)` while bytes are still arriving. Two partial reads
/// should yield one complete frame.
#[test]
fn frame_decode_handles_partial_buffers() {
    let mut codec = TronFrameCodec::new();
    let mut wire = BytesMut::new();
    let payload = vec![0xab; 200];
    codec
        .encode(
            Frame {
                ty: MessageType::Block,
                payload: Bytes::from(payload.clone()),
            },
            &mut wire,
        )
        .unwrap();

    // Split the wire bytes at an arbitrary mid-point and feed in two chunks.
    let mut decoder = TronFrameCodec::new();
    let split = wire.len() / 2;
    let (first, second) = (wire[..split].to_vec(), wire[split..].to_vec());

    let mut buf = BytesMut::new();
    buf.extend_from_slice(&first);
    let r1 = decoder.decode(&mut buf).unwrap();
    assert!(r1.is_none(), "first half should not yet decode");

    buf.extend_from_slice(&second);
    let r2 = decoder.decode(&mut buf).unwrap().unwrap();
    assert_eq!(r2.ty, MessageType::Block);
    assert_eq!(r2.payload.len(), 200);
}

#[test]
fn frame_decode_rejects_unknown_type_byte() {
    // Wire: varint(1) = 0x01, then a gap byte 0x0a (no defined MessageType).
    let mut buf = BytesMut::from(&[0x01u8, 0x0au8][..]);
    let mut decoder = TronFrameCodec::new();
    let err = decoder.decode(&mut buf).err().unwrap();
    assert!(format!("{err}").contains("0x0a"), "error: {err}");
}

// =============================================================================
// Handshake (in-memory duplex)
// =============================================================================

fn local_hello_inputs(version: i32, genesis: BlockId) -> HelloInputs<'static> {
    HelloInputs {
        from: Endpoint {
            address: b"127.0.0.1".to_vec(),
            address_ipv6: Vec::new(),
            port: 18888,
            node_id: vec![0xab; 64],
        },
        version,
        timestamp_ms: 1_700_000_000_000,
        genesis,
        solid: genesis,
        head: genesis,
        node_type: 0,
        lowest_block_num: 0,
        code_version: b"tron-goblin/0.0.1",
    }
}

/// Two peers, both speaking mainnet, complete the handshake. End state on
/// both sides is `Syncing`.
#[tokio::test]
async fn two_peers_handshake_over_duplex() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_stream, b_stream) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_stream);
    let mut b = PeerConnection::new(b_stream);

    let a_inputs = local_hello_inputs(MAINNET_P2P_VERSION, genesis);
    let b_inputs = local_hello_inputs(MAINNET_P2P_VERSION, genesis);

    // Run both handshakes concurrently — each side awaits the other's Hello.
    let (ra, rb) = tokio::join!(a.handshake(a_inputs), b.handshake(b_inputs));
    let peer_a_saw = ra.unwrap().into_hello().expect("verified hello");
    let peer_b_saw = rb.unwrap().into_hello().expect("verified hello");
    assert_eq!(peer_a_saw.version, MAINNET_P2P_VERSION);
    assert_eq!(peer_b_saw.version, MAINNET_P2P_VERSION);
    assert_eq!(a.state(), TronState::Syncing);
    assert_eq!(b.state(), TronState::Syncing);
}

/// One peer claims mainnet (11111), the other claims a different version.
/// Both should reject with `IncompatibleVersion`.
#[tokio::test]
async fn handshake_rejects_version_mismatch() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_stream, b_stream) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_stream);
    let mut b = PeerConnection::new(b_stream);

    let a_inputs = local_hello_inputs(MAINNET_P2P_VERSION, genesis);
    let b_inputs = local_hello_inputs(99_999, genesis);

    let (ra, rb) = tokio::join!(a.handshake(a_inputs), b.handshake(b_inputs));
    assert!(matches!(
        ra,
        Err(tron_net::HandshakeError::IncompatibleVersion { ours: 11_111, theirs: 99_999 })
    ));
    assert!(matches!(
        rb,
        Err(tron_net::HandshakeError::IncompatibleVersion { ours: 99_999, theirs: 11_111 })
    ));
}

/// Two peers on different chains (different genesis IDs) reject with
/// `IncompatibleChain`.
#[tokio::test]
async fn handshake_rejects_chain_mismatch() {
    let mainnet_genesis = genesis_block_id(&mainnet_inputs());
    let fake_genesis = BlockId::from_raw([0xff; 32]);

    let (a_stream, b_stream) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_stream);
    let mut b = PeerConnection::new(b_stream);

    let a_inputs = local_hello_inputs(MAINNET_P2P_VERSION, mainnet_genesis);
    let b_inputs = local_hello_inputs(MAINNET_P2P_VERSION, fake_genesis);

    let (ra, rb) = tokio::join!(a.handshake(a_inputs), b.handshake(b_inputs));
    assert!(matches!(ra, Err(tron_net::HandshakeError::IncompatibleChain)));
    assert!(matches!(rb, Err(tron_net::HandshakeError::IncompatibleChain)));
}

/// **N-30 regression.** A peer that replies with a `P2pHello` carrying no
/// `genesis_block_id` has not proved it is on our chain. The handshake
/// must fail closed with `IncompatibleChain` rather than skipping the
/// check (the old code only compared the hash when one was present).
#[tokio::test]
async fn handshake_rejects_missing_genesis() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_stream, b_stream) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_stream);
    let mut b = PeerConnection::new(b_stream);

    // B answers with a version-compatible Hello that omits the genesis
    // id entirely.
    let crafted = HelloMessage {
        version: MAINNET_P2P_VERSION,
        genesis_block_id: None,
        ..Default::default()
    };
    let b_fut = async {
        b.next_frame().await.unwrap(); // drain A's Hello
        b.send_frame(Frame {
            ty: MessageType::P2pHello,
            payload: Bytes::from(crafted.encode_to_vec()),
        })
        .await
        .unwrap();
    };
    let (ra, _) = tokio::join!(
        a.handshake(local_hello_inputs(MAINNET_P2P_VERSION, genesis)),
        b_fut
    );
    assert!(matches!(
        ra,
        Err(tron_net::HandshakeError::IncompatibleChain)
    ));
    assert!(a.peer_hello().is_none());
}

/// **N-5 regression.** A peer that skips its reciprocal Hello and jumps
/// straight to application traffic is an *implicit accept*. The handshake
/// must surface that as a distinct [`tron_net::HandshakeOutcome`] — never
/// a fabricated default Hello — leave `peer_hello` empty, and stash the
/// early frame for the next `next_frame`.
#[tokio::test]
async fn handshake_surfaces_implicit_accept_without_fabricated_hello() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_stream, b_stream) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_stream);
    let mut b = PeerConnection::new(b_stream);

    let b_fut = async {
        b.next_frame().await.unwrap(); // drain A's Hello
        // Stream an application frame instead of replying with a Hello.
        b.send_frame(Frame {
            ty: MessageType::P2pPing,
            payload: Bytes::from_static(b"ping"),
        })
        .await
        .unwrap();
    };
    let (ra, _) = tokio::join!(
        a.handshake(local_hello_inputs(MAINNET_P2P_VERSION, genesis)),
        b_fut
    );

    let outcome = ra.expect("implicit accept is not a handshake error");
    assert!(outcome.is_implicit_accept());
    assert!(outcome.hello().is_none());
    assert!(a.peer_hello().is_none(), "must not fabricate a peer Hello");
    assert_eq!(a.state(), TronState::Syncing);

    // The stashed early frame is delivered before any further socket read.
    let early = a.next_frame().await.unwrap().unwrap();
    assert_eq!(early.ty, MessageType::P2pPing);
    assert_eq!(&early.payload[..], b"ping");
}

/// After a successful handshake, both sides can send arbitrary frames.
#[tokio::test]
async fn post_handshake_can_exchange_application_frames() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_stream, b_stream) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_stream);
    let mut b = PeerConnection::new(b_stream);
    let (ra, rb) = tokio::join!(
        a.handshake(local_hello_inputs(MAINNET_P2P_VERSION, genesis)),
        b.handshake(local_hello_inputs(MAINNET_P2P_VERSION, genesis))
    );
    ra.unwrap();
    rb.unwrap();

    // A sends a Ping (well — a synthetic ping payload).
    a.send_frame(Frame {
        ty: MessageType::P2pPing,
        payload: Bytes::from_static(b"hi"),
    })
    .await
    .unwrap();
    let frame = b.next_frame().await.unwrap().unwrap();
    assert_eq!(frame.ty, MessageType::P2pPing);
    assert_eq!(&frame.payload[..], b"hi");
}

/// Real-TCP variant of [`two_peers_handshake_over_duplex`]: bind a
/// loopback listener, dial it, complete the handshake from both sides.
/// This is the test that proves the codec works against real Tokio
/// sockets, not just in-memory duplex pipes.
#[tokio::test]
async fn handshake_completes_over_real_loopback_tcp() {
    use tokio::net::{TcpListener, TcpStream};

    let genesis = genesis_block_id(&mainnet_inputs());
    // Bind to ":0" so the OS picks a free port — no flake from collisions.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_genesis = genesis;
    let server = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        let mut conn = PeerConnection::new(stream);
        conn.handshake(local_hello_inputs(MAINNET_P2P_VERSION, server_genesis))
            .await
    });

    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut conn = PeerConnection::new(stream);
        conn.handshake(local_hello_inputs(MAINNET_P2P_VERSION, genesis))
            .await
    });

    let server_result = server.await.unwrap();
    let client_result = client.await.unwrap();
    let server_saw = server_result.unwrap().into_hello().expect("verified hello");
    let client_saw = client_result.unwrap().into_hello().expect("verified hello");
    assert_eq!(server_saw.version, MAINNET_P2P_VERSION);
    assert_eq!(client_saw.version, MAINNET_P2P_VERSION);
}

/// **On-wire form check**: manually parse a frame written by the
/// encoder side and assert it's the expected `[varint][type][HelloMessage]`
/// shape. Drop the read half explicitly so the peer's handshake exits
/// with `ClosedDuringHandshake` rather than blocking forever.
#[tokio::test]
async fn hello_message_round_trips_through_frame_codec() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_stream, b_stream) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_stream);

    let inputs = local_hello_inputs(MAINNET_P2P_VERSION, genesis);

    // Reader side: pull bytes off b_stream until we have a full frame,
    // then drop the stream so the peer sees EOF on its read.
    let read_fut = async move {
        use tokio::io::AsyncReadExt;
        let mut stream = b_stream;
        let mut buf = vec![0u8; 4096];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                panic!("eof before frame");
            }
            total += n;
            let mut bm = BytesMut::from(&buf[..total]);
            let mut codec = TronFrameCodec::new();
            if let Some(frame) = codec.decode(&mut bm).unwrap() {
                // Explicitly drop `stream` here so the writer side sees EOF
                // on its next read.
                drop(stream);
                return frame;
            }
        }
    };

    let (read_result, hs_result) = tokio::join!(read_fut, a.handshake(inputs));
    assert_eq!(read_result.ty, MessageType::P2pHello);
    let hello = HelloMessage::decode(read_result.payload).unwrap();
    assert_eq!(hello.version, MAINNET_P2P_VERSION);
    assert_eq!(
        hello.genesis_block_id.as_ref().unwrap().hash,
        genesis.as_bytes()
    );
    assert!(
        matches!(
            hs_result,
            Err(tron_net::HandshakeError::ClosedDuringHandshake)
        ),
        "expected ClosedDuringHandshake, got {hs_result:?}"
    );
}
