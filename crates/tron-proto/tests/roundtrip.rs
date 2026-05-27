//! Wire-format roundtrip tests for the generated protobuf types.
//!
//! These don't validate against a captured mainnet block (that arrives with
//! the DB-explorer milestone) — they pin the encoded layout of synthetic
//! messages so any future codegen regression is caught immediately.

use prost::Message;
use prost_types::Any;
use tron_crypto::hash::sha256;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract, Raw};
use tron_proto::{Account, Block, BlockHeader, TransferContract};

#[test]
fn empty_account_encodes_to_empty_bytes() {
    // proto3: a message with all default-valued fields serialises to zero
    // bytes. java-tron relies on this for empty values in stores.
    let acct = Account::default();
    let bytes = acct.encode_to_vec();
    assert_eq!(bytes.len(), 0);

    let decoded = Account::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, acct);
}

#[test]
fn transfer_contract_roundtrip() {
    let tc = TransferContract {
        owner_address: hex::decode("412e988a386a799f506693793c6a5af6b54dfaabfb").unwrap(),
        to_address: hex::decode("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap(),
        amount: 1_000_000, // 1 TRX in sun
    };

    let bytes = tc.encode_to_vec();
    let decoded = TransferContract::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, tc);
}

#[test]
fn transaction_raw_roundtrip_carries_any_wrapped_contract() {
    let tc = TransferContract {
        owner_address: hex::decode("412e988a386a799f506693793c6a5af6b54dfaabfb").unwrap(),
        to_address: hex::decode("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap(),
        amount: 1_000_000,
    };

    let contract = Contract {
        r#type: ContractType::TransferContract as i32,
        // TRON wraps each contract in google.protobuf.Any; the type_url is
        // the fully-qualified protobuf message name with the standard
        // `type.googleapis.com/` prefix.
        parameter: Some(Any {
            type_url: "type.googleapis.com/protocol.TransferContract".to_string(),
            value: tc.encode_to_vec(),
        }),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id: 0,
    };

    let raw = Raw {
        ref_block_bytes: vec![0xab, 0xcd],
        ref_block_num: 0,
        ref_block_hash: vec![0u8; 8],
        expiration: 1_700_000_000_000,
        auths: Vec::new(),
        data: Vec::new(),
        contract: vec![contract],
        scripts: Vec::new(),
        timestamp: 1_700_000_000_000,
        fee_limit: 0,
    };

    let bytes = raw.encode_to_vec();
    let decoded = Raw::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, raw);

    // Inner TransferContract is recoverable end-to-end.
    let inner_bytes = &decoded.contract[0].parameter.as_ref().unwrap().value;
    let inner_tc = TransferContract::decode(inner_bytes.as_slice()).unwrap();
    assert_eq!(inner_tc.amount, 1_000_000);
}

/// In java-tron the **transaction id** is `sha256(raw_data.toByteArray())`.
/// Two encodings of the same `Raw` must produce the same txid — protobuf
/// non-determinism in field ordering would break this invariant.
#[test]
fn transaction_id_is_deterministic_across_encodings() {
    let raw = Raw {
        ref_block_bytes: vec![1, 2],
        ref_block_num: 42,
        ref_block_hash: vec![3, 4, 5, 6, 7, 8, 9, 10],
        expiration: 1_700_000_000_000,
        auths: Vec::new(),
        data: vec![0xde, 0xad, 0xbe, 0xef],
        contract: Vec::new(),
        scripts: Vec::new(),
        timestamp: 1_700_000_000_000,
        fee_limit: 50_000,
    };
    let txid_a = sha256(&raw.encode_to_vec());
    let txid_b = sha256(&raw.encode_to_vec());
    let txid_c = sha256(&raw.clone().encode_to_vec());
    assert_eq!(txid_a, txid_b);
    assert_eq!(txid_a, txid_c);
}

/// Protobuf `map<K,V>` fields must serialise deterministically — they're
/// hashed into state roots (Account.asset/assetV2 land in account capsule
/// bytes; ProposalCreateContract.parameters lands in tx-id input). prost's
/// default is `HashMap`, which iterates in random order; `build.rs` opts
/// every map into `BTreeMap` via `config.btree_map(["."])` to match
/// java-tron's `LinkedHashMap`/`TreeMap` semantics. Without that override,
/// two encodings of the same Account would produce different bytes and the
/// byte-exact RocksDB compatibility claim breaks for any account with
/// multiple TRC-10 assets.
#[test]
fn account_with_multiple_assets_encodes_deterministically() {
    // Build the same logical Account two ways — populating the asset map
    // in opposite insertion orders. Under HashMap the iteration order is
    // a function of (insertion order, hasher state); under BTreeMap it's
    // always sorted by key.
    let mut a = Account::default();
    a.asset.insert("ZZZ-coin".to_string(), 1);
    a.asset.insert("AAA-coin".to_string(), 2);
    a.asset.insert("MMM-coin".to_string(), 3);
    a.asset_v2.insert("1000003".to_string(), 30);
    a.asset_v2.insert("1000001".to_string(), 10);
    a.asset_v2.insert("1000002".to_string(), 20);

    let mut b = Account::default();
    b.asset.insert("AAA-coin".to_string(), 2);
    b.asset.insert("MMM-coin".to_string(), 3);
    b.asset.insert("ZZZ-coin".to_string(), 1);
    b.asset_v2.insert("1000001".to_string(), 10);
    b.asset_v2.insert("1000002".to_string(), 20);
    b.asset_v2.insert("1000003".to_string(), 30);

    let bytes_a1 = a.encode_to_vec();
    let bytes_a2 = a.encode_to_vec();
    let bytes_b = b.encode_to_vec();

    // Same instance, encoded twice — must match (rules out per-call RNG).
    assert_eq!(bytes_a1, bytes_a2);
    // Two instances populated in different orders — must match (rules out
    // insertion-order dependence). This is the bit that fails with HashMap.
    assert_eq!(bytes_a1, bytes_b);

    // And the bytes must round-trip back to an equivalent Account.
    let decoded = Account::decode(bytes_a1.as_slice()).unwrap();
    assert_eq!(decoded.asset.get("AAA-coin"), Some(&2));
    assert_eq!(decoded.asset_v2.get("1000002"), Some(&20));
}

/// Same property for `map<int64, int64>` (ProposalCreateContract.parameters,
/// Proposal.parameters). Distinct from the string-keyed asset map because
/// prost's codegen for `map<int64, V>` takes a different path internally.
#[test]
fn proposal_parameters_encode_deterministically() {
    use tron_proto::ProposalCreateContract;

    let mut a = ProposalCreateContract {
        owner_address: hex::decode("412e988a386a799f506693793c6a5af6b54dfaabfb").unwrap(),
        ..Default::default()
    };
    a.parameters.insert(99, 1_000);
    a.parameters.insert(1, 100);
    a.parameters.insert(42, 500);

    let mut b = ProposalCreateContract {
        owner_address: hex::decode("412e988a386a799f506693793c6a5af6b54dfaabfb").unwrap(),
        ..Default::default()
    };
    b.parameters.insert(1, 100);
    b.parameters.insert(42, 500);
    b.parameters.insert(99, 1_000);

    assert_eq!(a.encode_to_vec(), b.encode_to_vec());
}

#[test]
fn block_with_no_transactions_roundtrips() {
    let block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: None,
            witness_signature: Vec::new(),
        }),
    };
    let bytes = block.encode_to_vec();
    let decoded = Block::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, block);
}
