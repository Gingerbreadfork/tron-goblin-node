//! Unit tests for the UDP discovery framing + a live mainnet UDP probe.

use prost::Message;
use tron_net::{
    decode_discover_packet, encode_discover_packet, KAD_FIND_NODE, KAD_NEIGHBORS, KAD_PING,
    KAD_PONG,
};
use tron_proto::{Endpoint, FindNeighbours, PingMessage};

#[test]
fn frame_then_decode_round_trips_ping() {
    let ping = PingMessage {
        from: Some(Endpoint {
            address: b"127.0.0.1".to_vec(),
            port: 18888,
            node_id: vec![0xaa; 64],
            address_ipv6: vec![],
        }),
        to: Some(Endpoint {
            address: b"1.2.3.4".to_vec(),
            port: 18888,
            node_id: vec![],
            address_ipv6: vec![],
        }),
        version: 11111,
        timestamp: 1_700_000_000_000,
    };
    let payload = ping.encode_to_vec();
    let packet = encode_discover_packet(KAD_PING, &payload);

    assert_eq!(packet[0], KAD_PING);
    let (ty, body) = decode_discover_packet(&packet).unwrap();
    assert_eq!(ty, KAD_PING);
    let decoded = PingMessage::decode(body).unwrap();
    assert_eq!(decoded, ping);
}

#[test]
fn decode_rejects_empty_or_oversized_packets() {
    // 1 byte (type only, no payload): rejected
    assert!(decode_discover_packet(&[0x01]).is_none());
    // empty: rejected
    assert!(decode_discover_packet(&[]).is_none());
    // 2048+ bytes: rejected (matches libp2p's MAXSIZE guard)
    let big = vec![0x01u8; 2048];
    assert!(decode_discover_packet(&big).is_none());
    // Just at the upper limit (2047): accepted
    let just_ok = vec![0x01u8; 2047];
    assert!(decode_discover_packet(&just_ok).is_some());
}

#[test]
fn pinned_opcode_bytes_match_libp2p_kad_enum() {
    // org.tron.p2p.discover.message.MessageType — pinned values.
    assert_eq!(KAD_PING, 0x01);
    assert_eq!(KAD_PONG, 0x02);
    assert_eq!(KAD_FIND_NODE, 0x03);
    assert_eq!(KAD_NEIGHBORS, 0x04);
}

#[test]
fn find_node_proto_round_trips() {
    let from = Endpoint {
        address: b"127.0.0.1".to_vec(),
        port: 18888,
        node_id: vec![0x11; 64],
        address_ipv6: vec![],
    };
    let f = FindNeighbours {
        from: Some(from),
        target_id: vec![0x22; 64],
        timestamp: 42,
    };
    let bytes = f.encode_to_vec();
    let decoded = FindNeighbours::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, f);
}
