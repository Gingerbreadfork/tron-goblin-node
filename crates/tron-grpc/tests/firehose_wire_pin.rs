//! Wire-format pin for `tronfirehose.Entry`.
//!
//! These bytes are a DURABLE ON-DISK FORMAT, not just a gRPC wire
//! shape: every firehose segment under `<data_dir>/firehose/` stores
//! prost-encoded `Entry` payloads, and the segment magic (`TRNFH001`)
//! is the only version gate. Renumbering or repurposing a field in
//! `proto/firehose.proto` would make old segments decode into wrong
//! fields with no error — this test turns that mistake into a loud CI
//! failure. If you change the proto INTENTIONALLY (additive fields
//! only!), extend this golden rather than weakening it; breaking
//! changes must bump both the segment magic and the proto package.

use prost::Message as _;
use tron_grpc::firehose_proto as fh;

#[test]
fn entry_encoding_is_pinned() {
    let entry = fh::Entry {
        seq: 7,
        event: Some(fh::entry::Event::Apply(fh::BlockApplied {
            height: 84_210_003,
            block_id: vec![0xAA; 2],
            parent_id: vec![0xBB; 2],
            timestamp_ms: 1_700_000_003_000,
            witness: vec![0x41, 0x01],
            solidified_height: 84_209_984,
            txinfo_missing: true,
            txs: vec![fh::Tx {
                txid: vec![0x9F, 0x3A],
                contract_type: 31,
                success: true,
                from: vec![0x41, 0x02],
                to: vec![0x41, 0x03],
                amount: 1_000_000_000,
                asset: "1002000".into(),
                vm_contract: vec![0x41, 0x04],
                logs: vec![fh::Log {
                    address: vec![0xA6, 0x14],
                    topics: vec![vec![0xDD, 0xF2]],
                    data: vec![0x3B, 0x9A],
                }],
                internal_txs: vec![fh::InternalTx {
                    caller: vec![0x41, 0x05],
                    transfer_to: vec![0x41, 0x06],
                    call_value: 77,
                    token_id: "1000016".into(),
                    rejected: true,
                }],
            }],
        })),
    };
    assert_eq!(
        hex::encode(entry.encode_to_vec()),
        "0807126908d3e293281202aaaa1a02bbbb20b8e795ffbc312a02410130c0e29328380142480a029f3a101f1801220241022a024103308094ebdc033a0731303032303030420241044a0c0a02a6141202ddf21a023b9a52150a02410512024106184d2207313030303031362801",
        "tronfirehose.Entry wire bytes changed — this is a durable on-disk format; \
         see the module docs before touching proto/firehose.proto"
    );
}

#[test]
fn unwind_encoding_is_pinned() {
    let entry = fh::Entry {
        seq: 9,
        event: Some(fh::entry::Event::Unwind(fh::Unwind { to_height: 84_210_000 })),
    };
    assert_eq!(hex::encode(entry.encode_to_vec()), "08091a0508d0e29328");
}
