//! Wire-format parity tests against `MessageTypes.java` and
//! `Message.getSendBytes` in java-tron.

use hex_literal::hex;
use prost::Message;
use tron_net::{
    build_hello, decode_envelope, encode_envelope, message_id, to_wire_block_id, EnvelopeError,
    HelloInputs, MessageType, MessageTypeError, MAINNET_P2P_VERSION,
};
use tron_proto::{Endpoint, HelloMessage, PongMessage};
use tron_types::{genesis_block_id, mainnet_inputs};

// --- Type byte parity -------------------------------------------------------

/// Pin every single tag byte. If any of these change, every existing
/// java-tron peer will reject this node on the wire.
#[test]
fn message_type_bytes_match_java_tron() {
    assert_eq!(MessageType::First.as_byte(),               0x00);
    assert_eq!(MessageType::Trx.as_byte(),                 0x01);
    assert_eq!(MessageType::Block.as_byte(),               0x02);
    assert_eq!(MessageType::Trxs.as_byte(),                0x03);
    assert_eq!(MessageType::Blocks.as_byte(),              0x04);
    assert_eq!(MessageType::BlockHeaders.as_byte(),        0x05);
    assert_eq!(MessageType::Inventory.as_byte(),           0x06);
    assert_eq!(MessageType::FetchInvData.as_byte(),        0x07);
    assert_eq!(MessageType::SyncBlockChain.as_byte(),      0x08);
    assert_eq!(MessageType::BlockChainInventory.as_byte(), 0x09);
    assert_eq!(MessageType::ItemNotFound.as_byte(),        0x10);
    assert_eq!(MessageType::FetchBlockHeaders.as_byte(),   0x11);
    assert_eq!(MessageType::BlockInventory.as_byte(),      0x12);
    assert_eq!(MessageType::TrxInventory.as_byte(),        0x13);
    assert_eq!(MessageType::PbftCommitMsg.as_byte(),       0x14);
    assert_eq!(MessageType::P2pHello.as_byte(),            0x20);
    assert_eq!(MessageType::P2pDisconnect.as_byte(),       0x21);
    assert_eq!(MessageType::P2pPing.as_byte(),             0x22);
    assert_eq!(MessageType::P2pPong.as_byte(),             0x23);
    assert_eq!(MessageType::DiscoverPing.as_byte(),        0x30);
    assert_eq!(MessageType::DiscoverPong.as_byte(),        0x31);
    assert_eq!(MessageType::DiscoverFindPeer.as_byte(),    0x32);
    assert_eq!(MessageType::DiscoverPeers.as_byte(),       0x33);
    assert_eq!(MessageType::PbftMsg.as_byte(),             0x34);
    // libp2p connection-layer types — same wire format, distinct byte
    // range. `KeepAlivePing` repurposes the old `Last` sentinel byte.
    assert_eq!(MessageType::Libp2pDisconnect.as_byte(),     0xfb);
    assert_eq!(MessageType::Libp2pStatus.as_byte(),         0xfc);
    assert_eq!(MessageType::Libp2pHandshakeHello.as_byte(), 0xfd);
    assert_eq!(MessageType::Libp2pKeepAlivePong.as_byte(),  0xfe);
    assert_eq!(MessageType::Libp2pKeepAlivePing.as_byte(),  0xff);
}

#[test]
fn message_type_from_byte_round_trips_every_known_value() {
    for b in [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x34, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ] {
        let ty = MessageType::from_byte(b).expect("known type");
        assert_eq!(ty.as_byte(), b, "round trip failed for 0x{:02x}", b);
    }
}

#[test]
fn message_type_from_byte_rejects_gaps() {
    // These bytes are in the gaps between defined types and must error.
    // 0xfe is now Libp2pKeepAlivePong; gap moved to 0xfa (one below libp2p range).
    for b in [0x0a, 0x0f, 0x15, 0x1f, 0x24, 0x2f, 0x35, 0x80, 0xfa] {
        assert_eq!(
            MessageType::from_byte(b),
            Err(MessageTypeError::UnknownByte(b))
        );
    }
}

#[test]
fn range_predicates_match_java_tron_semantics() {
    // is_p2p
    assert!(MessageType::P2pHello.is_p2p());
    assert!(MessageType::P2pDisconnect.is_p2p());
    assert!(MessageType::P2pPing.is_p2p());
    assert!(MessageType::P2pPong.is_p2p());
    assert!(!MessageType::Trx.is_p2p());
    assert!(!MessageType::DiscoverPing.is_p2p());

    // is_tron
    assert!(MessageType::First.is_tron());
    assert!(MessageType::Trx.is_tron());
    assert!(MessageType::PbftCommitMsg.is_tron());
    assert!(!MessageType::P2pHello.is_tron());
    assert!(!MessageType::DiscoverPing.is_tron());
    assert!(!MessageType::PbftMsg.is_tron());

    // is_pbft (single value)
    assert!(MessageType::PbftMsg.is_pbft());
    assert!(!MessageType::PbftCommitMsg.is_pbft());

    // is_discover
    assert!(MessageType::DiscoverPing.is_discover());
    assert!(MessageType::DiscoverPong.is_discover());
    assert!(MessageType::DiscoverFindPeer.is_discover());
    assert!(MessageType::DiscoverPeers.is_discover());
    assert!(!MessageType::P2pHello.is_discover());
}

// --- Envelope framing -------------------------------------------------------

#[test]
fn envelope_prepends_type_byte() {
    let payload = b"hello-payload";
    let wire = encode_envelope(MessageType::P2pHello, payload);
    assert_eq!(wire[0], 0x20);
    assert_eq!(&wire[1..], payload);
}

#[test]
fn envelope_round_trips() {
    let pong = PongMessage { from: None, echo: 1, timestamp: 1_700_000_000_000 };
    let payload = pong.encode_to_vec();
    let wire = encode_envelope(MessageType::P2pPong, &payload);

    let (ty, rest) = decode_envelope(&wire).unwrap();
    assert_eq!(ty, MessageType::P2pPong);
    let decoded = PongMessage::decode(rest).unwrap();
    assert_eq!(decoded, pong);
}

#[test]
fn envelope_decode_empty_errors() {
    assert_eq!(decode_envelope(&[]), Err(EnvelopeError::Empty));
}

#[test]
fn envelope_decode_unknown_type_errors() {
    let bad = [0x0a, 0x00, 0x00]; // 0x0a is in a gap
    match decode_envelope(&bad) {
        Err(EnvelopeError::UnknownType(MessageTypeError::UnknownByte(0x0a))) => {}
        other => panic!("expected UnknownType(0x0a), got {:?}", other),
    }
}

#[test]
fn hello_message_envelope_round_trips() {
    // Construct a plausible HelloMessage. The shape matters more than the
    // values here — we want to confirm the proto + envelope stack works
    // end-to-end for the message every connection starts with.
    let hello = HelloMessage {
        from: Some(Endpoint {
            address: b"127.0.0.1".to_vec(),
            address_ipv6: Vec::new(),
            port: 18888,
            node_id: vec![0xab; 64],
        }),
        version: 11111, // mainnet
        timestamp: 1_700_000_000_000,
        genesis_block_id: None,
        solid_block_id: None,
        head_block_id: None,
        address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
        signature: vec![0u8; 65],
        node_type: 1,
        lowest_block_num: 0,
        code_version: b"4.8.2".to_vec(),
    };
    let payload = hello.encode_to_vec();
    let wire = encode_envelope(MessageType::P2pHello, &payload);

    let (ty, rest) = decode_envelope(&wire).unwrap();
    assert_eq!(ty, MessageType::P2pHello);
    let decoded = HelloMessage::decode(rest).unwrap();
    assert_eq!(decoded, hello);
}

// --- HelloMessage assembly --------------------------------------------------

#[test]
fn p2p_version_constants_match_java_tron() {
    assert_eq!(MAINNET_P2P_VERSION, 11_111);
    assert_eq!(tron_net::NILE_P2P_VERSION, 201_910_292);
    assert_eq!(tron_net::SHASTA_P2P_VERSION, 1);
}

/// Building a HelloMessage against the *real* mainnet genesis BlockId and
/// running it through the full envelope codec. This is the most
/// integration-heavy test in the suite — it exercises Base58Check (in
/// genesis asset addresses), SHA-256 (in tx merkle hash), the BlockId
/// num-prefix overwrite, the HelloMessage proto, and the type-tag
/// envelope. If anything in the stack regresses, this fires.
#[test]
fn mainnet_hello_message_roundtrips_via_envelope() {
    let genesis = genesis_block_id(&mainnet_inputs());

    let from = Endpoint {
        address: b"127.0.0.1".to_vec(),
        address_ipv6: Vec::new(),
        port: 18888,
        node_id: vec![0xab; 64],
    };
    let hello = build_hello(HelloInputs {
        from,
        version: MAINNET_P2P_VERSION,
        timestamp_ms: 1_700_000_000_000,
        genesis,
        // For a fresh node, solid == head == genesis until we've synced.
        solid: genesis,
        head: genesis,
        node_type: 0,
        lowest_block_num: 0,
        code_version: b"tron-goblin/0.0.1",
    });

    // Genesis block id round-trips intact: hash bytes match, number
    // extracted from those bytes equals the explicit number field.
    let wire_gid = hello.genesis_block_id.as_ref().unwrap();
    assert_eq!(wire_gid.hash.len(), 32);
    assert_eq!(wire_gid.number, 0);
    assert_eq!(&wire_gid.hash[0..8], &[0u8; 8]); // first 8 bytes = block num = 0
    assert_eq!(wire_gid.hash, genesis.as_bytes());

    // Wrap in the envelope; type byte must be 0x20 (P2pHello).
    let payload = hello.encode_to_vec();
    let wire = encode_envelope(MessageType::P2pHello, &payload);
    assert_eq!(wire[0], 0x20);

    // Round-trip back to the typed message.
    let (ty, rest) = decode_envelope(&wire).unwrap();
    assert_eq!(ty, MessageType::P2pHello);
    let decoded = HelloMessage::decode(rest).unwrap();
    assert_eq!(decoded, hello);
}

#[test]
fn to_wire_block_id_preserves_number_redundantly() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let wire = to_wire_block_id(genesis);
    // The number is duplicated: in the first 8 bytes of `hash` AND in the
    // explicit `number` field. java-tron does it this way; matching the
    // redundancy is part of the wire format.
    let mut be = [0u8; 8];
    be.copy_from_slice(&wire.hash[0..8]);
    assert_eq!(i64::from_be_bytes(be), wire.number);
}

// --- Message id -------------------------------------------------------------

/// `Message.getMessageId()` hashes the payload **only**, not the envelope.
/// This is the value peers use to dedup in `INVENTORY` exchanges.
#[test]
fn message_id_hashes_payload_not_envelope() {
    let payload = b"some-protobuf-bytes";
    let id_of_payload = message_id(payload);

    // Hashing the envelope (type byte + payload) would produce a different
    // hash and silently break inventory dedup against java-tron peers.
    let envelope = encode_envelope(MessageType::Trx, payload);
    let id_of_envelope = tron_crypto::hash::sha256(&envelope);
    assert_ne!(id_of_payload, id_of_envelope);
}
