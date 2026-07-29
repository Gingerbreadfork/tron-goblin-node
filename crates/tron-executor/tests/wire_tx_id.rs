//! Regression: on the block-apply path the transaction id AND the
//! signature-recovery preimage come from the tx's ORIGINAL wire bytes
//! (java `TransactionCapsule.getRawHash` = sha256 of the raw_data bytes
//! as encoded, unknown fields included), threaded in via
//! [`tron_types::TxWireInfo`]. A prost re-encode drops unknown raw_data
//! fields, hashing a different preimage — the recovered "signer" becomes
//! garbage and a tx the network accepted is falsely rejected with
//! PermissionDenied.

use std::sync::Arc;

use prost::Message as _;
use tron_chainbase::{AccountStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_executor::{
    execute_block_with_config_and_wire, ExecConfig, StateBackends, TxOutcome,
};
use tron_proto::transaction::{contract::ContractType, Contract, Raw as TxRaw};
use tron_proto::{block_header::Raw as BlockHeaderRaw, Account, Block, BlockHeader, TransferContract};
use tron_types::tx_wire_infos_from_block_bytes;

const PRIV: [u8; 32] = [0x5a; 32];

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> StateBackends {
    StateBackends {
        accounts: mem(),
        witnesses: mem(),
        votes: mem(),
        delegation: mem(),
        delegated_resources: mem(),
        delegated_resource_account_index: None,
        dyn_props: mem(),
        proposals: mem(),
        name_index: mem(),
        id_index: mem(),
        asset_v1: mem(),
        asset_v2: mem(),
        contracts: mem(),
        abi: mem(),
        exchange_v1: mem(),
        exchange_v2: mem(),
        market_orders: mem(),
        market_account: mem(),
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
        reward_vi: None,
    }
}

fn derive_address(priv_key: &[u8; 32]) -> [u8; 21] {
    let dummy = [0x42u8; 32];
    let sig = tron_crypto::signature::RecoverableSignature::sign_prehash(priv_key, &dummy).unwrap();
    let pubkey = sig.recover_uncompressed_pubkey(&dummy).unwrap();
    let h = tron_crypto::hash::keccak256(&pubkey[1..]);
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].copy_from_slice(&h[12..]);
    a
}

fn seed_account(state: &StateBackends, raw_address: [u8; 21], balance: i64) {
    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(raw_address),
            &Account {
                address: raw_address.to_vec(),
                balance,
                ..Default::default()
            },
        )
        .unwrap();
}

/// `tag(field, wiretype=2) || varint(len) || payload`.
fn ld_field(field_num: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![(field_num << 3) | 2];
    let mut len = payload.len() as u64;
    loop {
        let mut b = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            b |= 0x80;
        }
        out.push(b);
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Build the wire bytes of a block holding one signed transfer whose
/// raw_data ends with an UNKNOWN varint field (field 20, `a0 01 03` — the
/// energy-rental builder pattern), signed over the WIRE id like the real
/// network. Returns `(block_bytes, wire_id, reencode_id)`.
fn block_with_unknown_field_tx(owner: [u8; 21], to: [u8; 21]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let tc = TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount: 1_000,
    };
    let raw = TxRaw {
        contract: vec![Contract {
            r#type: ContractType::TransferContract as i32,
            parameter: Some(prost_types::Any {
                type_url: "type.googleapis.com/protocol.TransferContract".into(),
                value: tc.encode_to_vec(),
            }),
            ..Default::default()
        }],
        // expiration 0 skips the block-apply expiration window (synthetic
        // test fixture; canonical txs always carry one).
        ..Default::default()
    };
    let mut raw_bytes = raw.encode_to_vec();
    let reencode_id = tron_crypto::hash::sha256(&raw_bytes);
    raw_bytes.extend_from_slice(&[0xa0, 0x01, 0x03]); // unknown field 20
    let wire_id = tron_crypto::hash::sha256(&raw_bytes);

    let sig = tron_crypto::signature::RecoverableSignature::sign_prehash(&PRIV, &wire_id).unwrap();
    let tx_wire = [
        ld_field(1, &raw_bytes),
        ld_field(2, &sig.to_bytes().to_vec()),
    ]
    .concat();

    let header = BlockHeader {
        raw_data: Some(BlockHeaderRaw {
            number: 1,
            timestamp: 1_700_000_000_000,
            witness_address: vec![0x41; 21],
            ..Default::default()
        }),
        ..Default::default()
    };
    // transactions = Block field 1, block_header = Block field 2. Assembled
    // by hand so the tx span keeps the unknown bytes a `Block::encode` of
    // the decoded struct would drop.
    let block_bytes = [
        ld_field(1, &tx_wire),
        ld_field(2, &header.encode_to_vec()),
    ]
    .concat();
    (block_bytes, wire_id, reencode_id)
}

fn exec_cfg() -> ExecConfig {
    ExecConfig {
        // The decoded-side trie check would (correctly) flag the re-encode
        // mismatch — the sync driver runs the raw-bytes check instead; not
        // what this test exercises.
        verify_tx_trie: false,
        ..ExecConfig::unsigned()
    }
}

#[test]
fn wire_tx_id_makes_unknown_field_tx_verify_like_java() {
    let owner = derive_address(&PRIV);
    let to = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0x77);
        a
    };
    let state = fresh_state();
    seed_account(&state, owner, 10_000_000);
    seed_account(&state, to, 1);

    let (block_bytes, wire_id, reencode_id) = block_with_unknown_field_tx(owner, to);
    let block = Block::decode(block_bytes.as_slice()).unwrap();
    let wire = tx_wire_infos_from_block_bytes(&block_bytes).expect("well-formed block bytes");
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].tx_id, Some(wire_id));
    assert_ne!(wire_id, reencode_id);

    let report =
        execute_block_with_config_and_wire(&state, &block, None, &exec_cfg(), Some(&wire))
            .expect("block applies");
    let res = &report.tx_results[0];
    // The id is the WIRE id (what mainnet explorers show for this tx)...
    assert_eq!(res.tx_id, wire_id);
    // ...and signature recovery over that preimage finds the owner in the
    // default permission → the tx SUCCEEDS, matching java.
    assert!(
        matches!(res.outcome, TxOutcome::Success),
        "expected Success, got {:?}",
        res.outcome
    );
}

#[test]
fn without_wire_info_the_reencode_preimage_rejects_the_same_tx() {
    // Control: hashing the prost re-encode instead recovers a garbage signer
    // → false PermissionDenied.
    let owner = derive_address(&PRIV);
    let to = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0x77);
        a
    };
    let state = fresh_state();
    seed_account(&state, owner, 10_000_000);
    seed_account(&state, to, 1);

    let (block_bytes, _wire_id, reencode_id) = block_with_unknown_field_tx(owner, to);
    let block = Block::decode(block_bytes.as_slice()).unwrap();

    let report = execute_block_with_config_and_wire(&state, &block, None, &exec_cfg(), None)
        .expect("block applies (tx rejected inside)");
    let res = &report.tx_results[0];
    assert_eq!(res.tx_id, reencode_id, "fallback id is the re-encode hash");
    assert!(
        matches!(
            &res.outcome,
            TxOutcome::Invalid(tron_actuator::ActuatorError::PermissionDenied(_))
        ),
        "expected PermissionDenied, got {:?}",
        res.outcome
    );
}

#[test]
fn canonical_tx_ids_are_identical_with_and_without_wire_info() {
    // No-op proof for the common case: a canonical tx (no unknown fields)
    // must produce byte-identical tx ids and outcomes through both paths.
    let owner = derive_address(&PRIV);
    let to = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0x66);
        a
    };
    let tc = TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount: 500,
    };
    let raw = TxRaw {
        contract: vec![Contract {
            r#type: ContractType::TransferContract as i32,
            parameter: Some(prost_types::Any {
                type_url: "type.googleapis.com/protocol.TransferContract".into(),
                value: tc.encode_to_vec(),
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut tx = tron_proto::Transaction {
        raw_data: Some(raw),
        ..Default::default()
    };
    tron_types::sign_transaction(&mut tx, &PRIV).unwrap();
    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 1,
                timestamp: 1_700_000_000_000,
                witness_address: vec![0x41; 21],
                ..Default::default()
            }),
            ..Default::default()
        }),
        transactions: vec![tx],
    };
    let block_bytes = block.encode_to_vec();
    let wire = tx_wire_infos_from_block_bytes(&block_bytes).unwrap();

    let state_a = fresh_state();
    seed_account(&state_a, owner, 10_000_000);
    seed_account(&state_a, to, 1);
    let with_wire =
        execute_block_with_config_and_wire(&state_a, &block, None, &exec_cfg(), Some(&wire))
            .unwrap();

    let state_b = fresh_state();
    seed_account(&state_b, owner, 10_000_000);
    seed_account(&state_b, to, 1);
    let without_wire =
        execute_block_with_config_and_wire(&state_b, &block, None, &exec_cfg(), None).unwrap();

    assert_eq!(with_wire.tx_results[0].tx_id, without_wire.tx_results[0].tx_id);
    assert!(matches!(with_wire.tx_results[0].outcome, TxOutcome::Success));
    assert!(matches!(without_wire.tx_results[0].outcome, TxOutcome::Success));
}
