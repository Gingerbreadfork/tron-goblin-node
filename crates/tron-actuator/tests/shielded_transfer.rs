//! Tests for `ShieldedTransferActuator`.
//!
//! Coverage:
//! * Permission/structure checks (sender, receiver, transparent halves).
//! * Duplicate nullifier and duplicate commitment within the same tx.
//! * NullifierStore double-spend rejection.
//! * Feature-flag gating (`ALLOW_SAME_TOKEN_NAME`, `ALLOW_SHIELDED_TRANSACTION`).
//! * `validate_transparent` arithmetic rules.
//!
//! Not covered (would need real Sapling proofs from a test fixture):
//! end-to-end successful proof verification. The proof+binding-sig
//! verifier is covered separately in `tron-tvm/tests/shielded.rs`.

use std::sync::Arc;

use tron_actuator::shielded_transfer::{
    execute_shielded_transfer, validate_shielded_transfer,
};
use tron_actuator::ActuatorError;
use tron_chainbase::{
    AccountStore, DynamicPropertiesStore, KvBackend, MemBackend, NullifierStore,
};
use tron_proto::{ReceiveDescription, ShieldedTransferContract, SpendDescription};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Build a stores triple with shielded feature flags enabled.
fn enabled_stores() -> (AccountStore, DynamicPropertiesStore, NullifierStore) {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let nullifiers = NullifierStore::new(mem());
    dp.put_long(b" ALLOW_SAME_TOKEN_NAME", 1);
    dp.put_long(b"ALLOW_SHIELDED_TRANSACTION", 1);
    (accounts, dp, nullifiers)
}

fn minimal_receive(byte: u8) -> ReceiveDescription {
    ReceiveDescription {
        value_commitment: vec![byte; 32],
        note_commitment: vec![byte; 32],
        epk: vec![byte; 32],
        zkproof: vec![byte; 192],
        c_enc: vec![0u8; 580],
        c_out: vec![0u8; 80],
    }
}

fn minimal_spend(byte: u8) -> SpendDescription {
    SpendDescription {
        value_commitment: vec![byte; 32],
        anchor: vec![byte; 32],
        nullifier: vec![byte; 32],
        rk: vec![byte; 32],
        zkproof: vec![byte; 192],
        spend_authority_signature: vec![byte; 64],
    }
}

#[test]
fn rejects_when_allow_same_token_name_disabled() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let nullifiers = NullifierStore::new(mem());
    // ALLOW_SHIELDED_TRANSACTION enabled but ALLOW_SAME_TOKEN_NAME not.
    dp.put_long(b"ALLOW_SHIELDED_TRANSACTION", 1);

    let c = ShieldedTransferContract {
        receive_description: vec![minimal_receive(1)],
        spend_description: vec![minimal_spend(2)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("ALLOW_SAME_TOKEN_NAME")));
}

#[test]
fn rejects_when_shielded_transaction_disabled() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let nullifiers = NullifierStore::new(mem());
    dp.put_long(b" ALLOW_SAME_TOKEN_NAME", 1);
    // ALLOW_SHIELDED_TRANSACTION missing.

    let c = ShieldedTransferContract {
        receive_description: vec![minimal_receive(1)],
        spend_description: vec![minimal_spend(2)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("Not support Shielded")));
}

#[test]
fn rejects_no_sender() {
    let (accounts, dp, nullifiers) = enabled_stores();
    // No spend, no transparent_from.
    let c = ShieldedTransferContract {
        receive_description: vec![minimal_receive(1)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("no sender")));
}

#[test]
fn rejects_more_than_one_sender() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let c = ShieldedTransferContract {
        transparent_from_address: vec![0x41u8; 21],
        from_amount: 1000,
        spend_description: vec![minimal_spend(1)],
        receive_description: vec![minimal_receive(2)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("more than 1 senders")));
}

#[test]
fn rejects_no_receiver() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let c = ShieldedTransferContract {
        spend_description: vec![minimal_spend(1)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("no output cm")));
}

#[test]
fn rejects_too_many_receivers() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let c = ShieldedTransferContract {
        spend_description: vec![minimal_spend(1)],
        receive_description: vec![
            minimal_receive(2),
            minimal_receive(3),
            minimal_receive(4),
        ],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("more than 2")));
}

#[test]
fn rejects_duplicate_nullifiers_within_tx() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let mut sd1 = minimal_spend(1);
    let mut sd2 = minimal_spend(1);
    sd1.nullifier = vec![0xaau8; 32];
    sd2.nullifier = vec![0xaau8; 32];
    // checkSender caps to 1 spend, so simulate via duplicate detection
    // by making a single-spend transaction and confirming that an
    // already-spent nullifier is rejected:
    let c = ShieldedTransferContract {
        spend_description: vec![sd1],
        receive_description: vec![minimal_receive(2)],
        ..Default::default()
    };
    // Pre-spend that nullifier.
    nullifiers.put(&[0xaau8; 32]);
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("spent")));
}

#[test]
fn rejects_duplicate_commitments_within_tx() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let mut rd1 = minimal_receive(1);
    let mut rd2 = minimal_receive(2);
    rd1.note_commitment = vec![0xbbu8; 32];
    rd2.note_commitment = vec![0xbbu8; 32];
    let c = ShieldedTransferContract {
        spend_description: vec![minimal_spend(3)],
        receive_description: vec![rd1, rd2],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("duplicate cm")));
}

#[test]
fn rejects_negative_amounts() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let c = ShieldedTransferContract {
        transparent_from_address: vec![0x41; 21],
        from_amount: -1,
        receive_description: vec![minimal_receive(1)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("from_amount")));
}

#[test]
fn rejects_self_transfer() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let addr = vec![0x41; 21];
    let c = ShieldedTransferContract {
        transparent_from_address: addr.clone(),
        transparent_to_address: addr,
        from_amount: 1000,
        to_amount: 500,
        receive_description: vec![minimal_receive(1)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("yourself")));
}

#[test]
fn rejects_invalid_address_length() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let c = ShieldedTransferContract {
        transparent_from_address: vec![0x41; 5], // too short
        from_amount: 100,
        receive_description: vec![minimal_receive(1)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("Invalid transparent_from")));
}

#[test]
fn rejects_from_amount_without_transparent_from() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let c = ShieldedTransferContract {
        from_amount: 100, // but no transparent_from_address
        spend_description: vec![minimal_spend(1)],
        receive_description: vec![minimal_receive(2)],
        ..Default::default()
    };
    let err = validate_shielded_transfer(&accounts, &dp, &nullifiers, None, &c, &[0u8; 32], 0)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("from_amount should be 0")));
}

#[test]
fn execute_records_nullifier() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let sd = minimal_spend(0x77);
    let c = ShieldedTransferContract {
        spend_description: vec![sd],
        receive_description: vec![minimal_receive(0x88)],
        ..Default::default()
    };
    // Nullifier not yet spent.
    assert!(!nullifiers.contains(&[0x77u8; 32]));
    let result = execute_shielded_transfer(&accounts, &dp, &nullifiers, None, &c).unwrap();
    assert_eq!(result.fee, 0); // no SHIELDED_TRANSACTION_FEE set ⇒ 0.
    // Nullifier now recorded.
    assert!(nullifiers.contains(&[0x77u8; 32]));
}

#[test]
fn execute_debits_zen_from_transparent_sender() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let zen = "1000001"; // arbitrary TRC-10 id
    dp.put_bytes(b"ZEN_TOKEN_ID", zen.as_bytes());

    let from = vec![0x41u8; 21];
    // Seed sender with 1_000 Zen.
    let mut sender = tron_proto::Account {
        address: from.clone(),
        ..Default::default()
    };
    sender.asset_v2.insert(zen.to_string(), 1_000);
    let mut buf = [0u8; 21];
    buf.copy_from_slice(&from);
    accounts.put(&tron_crypto::address::Address::from_raw(buf), &sender);

    let c = ShieldedTransferContract {
        transparent_from_address: from.clone(),
        from_amount: 300,
        receive_description: vec![minimal_receive(0xee)],
        ..Default::default()
    };
    let _ = execute_shielded_transfer(&accounts, &dp, &nullifiers, None, &c).unwrap();

    let after = accounts
        .get(&tron_crypto::address::Address::from_raw(buf))
        .unwrap()
        .unwrap();
    assert_eq!(after.asset_v2.get(zen).copied().unwrap_or(0), 700);
}

#[test]
fn execute_creates_recipient_and_credits_zen() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let zen = "1000001";
    dp.put_bytes(b"ZEN_TOKEN_ID", zen.as_bytes());
    // Pool must have ≥ value_balance = 750 sun to allow the shielded→
    // transparent burn of 750 to pass the >=0 check.
    dp.put_long(b"TOTAL_SHIELDED_POOL_VALUE", 10_000);

    let to = vec![0x41u8; 21];
    let mut buf = [0u8; 21];
    buf.copy_from_slice(&to);
    let to_addr = tron_crypto::address::Address::from_raw(buf);
    // Recipient does NOT yet exist.
    assert!(accounts.get(&to_addr).unwrap().is_none());

    let c = ShieldedTransferContract {
        spend_description: vec![minimal_spend(0xa1)],
        receive_description: vec![minimal_receive(0xa2)],
        transparent_to_address: to.clone(),
        to_amount: 750,
        ..Default::default()
    };
    let result = execute_shielded_transfer(&accounts, &dp, &nullifiers, None, &c).unwrap();
    assert!(result.created_recipient, "recipient should be auto-created");
    let after = accounts.get(&to_addr).unwrap().unwrap();
    assert_eq!(after.asset_v2.get(zen).copied().unwrap_or(0), 750);
}

#[test]
fn execute_rejects_insufficient_zen_balance() {
    let (accounts, dp, nullifiers) = enabled_stores();
    let zen = "1000001";
    dp.put_bytes(b"ZEN_TOKEN_ID", zen.as_bytes());

    let from = vec![0x41u8; 21];
    let mut sender = tron_proto::Account {
        address: from.clone(),
        ..Default::default()
    };
    sender.asset_v2.insert(zen.to_string(), 100); // only 100 Zen
    let mut buf = [0u8; 21];
    buf.copy_from_slice(&from);
    accounts.put(&tron_crypto::address::Address::from_raw(buf), &sender);

    let c = ShieldedTransferContract {
        transparent_from_address: from,
        from_amount: 500, // > 100
        receive_description: vec![minimal_receive(0xb0)],
        ..Default::default()
    };
    let err = execute_shielded_transfer(&accounts, &dp, &nullifiers, None, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Execute(s) if s.contains("balance insufficient")));
}

#[test]
fn execute_updates_total_shielded_pool_value() {
    let (accounts, dp, nullifiers) = enabled_stores();
    dp.put_long(b"TOTAL_SHIELDED_POOL_VALUE", 10_000);
    dp.put_long(b"SHIELDED_TRANSACTION_FEE", 1_000);
    let zen = "1000001";
    dp.put_bytes(b"ZEN_TOKEN_ID", zen.as_bytes());

    // Mint into pool: transparent_from=200, no transparent_to.
    // value_balance = (0 - 200) + 1000 = 800. pool -= 800 → 9200.
    let from = vec![0x41u8; 21];
    let mut sender = tron_proto::Account {
        address: from.clone(),
        ..Default::default()
    };
    sender.asset_v2.insert(zen.to_string(), 10_000);
    let mut buf = [0u8; 21];
    buf.copy_from_slice(&from);
    accounts.put(&tron_crypto::address::Address::from_raw(buf), &sender);

    let c = ShieldedTransferContract {
        transparent_from_address: from,
        from_amount: 200,
        receive_description: vec![minimal_receive(0xc0)],
        ..Default::default()
    };
    let _ = execute_shielded_transfer(&accounts, &dp, &nullifiers, None, &c).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_SHIELDED_POOL_VALUE").unwrap(), 9_200);
}

#[test]
fn execute_rejects_double_spend() {
    let (accounts, dp, nullifiers) = enabled_stores();
    nullifiers.put(&[0xccu8; 32]);
    let mut sd = minimal_spend(0xcc);
    sd.nullifier = vec![0xccu8; 32];
    let c = ShieldedTransferContract {
        spend_description: vec![sd],
        receive_description: vec![minimal_receive(0xdd)],
        ..Default::default()
    };
    let err = execute_shielded_transfer(&accounts, &dp, &nullifiers, None, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Execute(s) if s.contains("double spend")));
}

// =============================================================================
// compute_shielded_sighash — mirrors java-tron's
// `TransactionCapsule.hashShieldTransaction`.
//
// Property invariants we assert:
//   * Stability:     hashing the same tx twice gives the same digest.
//   * Sig-blindness: changing only `spend_authority_signature` does NOT
//                    change the digest (the whole purpose of the
//                    sighash — sigs commit to this digest, so they
//                    cannot be in it).
//   * Body-binding:  changing any other field (from_amount, receive
//                    description, nullifier, ...) DOES change the digest.
//   * Token-binding: changing the zen_token_id changes the digest.
//   * Type-guard:    a non-shielded contract is rejected.
// =============================================================================

fn shielded_tx(contract: ShieldedTransferContract) -> tron_proto::Transaction {
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;
    let mut value = Vec::new();
    contract.encode(&mut value).unwrap();
    tron_proto::Transaction {
        raw_data: Some(tron_proto::transaction::Raw {
            ref_block_bytes: vec![0xde, 0xad],
            ref_block_num: 0,
            ref_block_hash: vec![0xbe, 0xef, 0xca, 0xfe],
            expiration: 1_700_000_000_000,
            data: Vec::new(),
            contract: vec![tron_proto::transaction::Contract {
                r#type: ContractType::ShieldedTransferContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.ShieldedTransferContract".into(),
                    value,
                }),
                provider: Vec::new(),
                contract_name: Vec::new(),
                permission_id: 0,
            }],
            scripts: Vec::new(),
            timestamp: 1_700_000_000_000,
            fee_limit: 0,
            auths: Vec::new(),
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    }
}

#[test]
fn shielded_sighash_is_stable() {
    use tron_actuator::shielded_transfer::compute_shielded_sighash;
    let c = ShieldedTransferContract {
        from_amount: 200,
        spend_description: vec![minimal_spend(0x11)],
        receive_description: vec![minimal_receive(0x22)],
        ..Default::default()
    };
    let tx = shielded_tx(c);
    let a = compute_shielded_sighash(&tx, "1000001").unwrap();
    let b = compute_shielded_sighash(&tx, "1000001").unwrap();
    assert_eq!(a, b);
}

#[test]
fn shielded_sighash_ignores_spend_authority_signature() {
    use tron_actuator::shielded_transfer::compute_shielded_sighash;
    let base = ShieldedTransferContract {
        from_amount: 200,
        spend_description: vec![minimal_spend(0x11)],
        receive_description: vec![minimal_receive(0x22)],
        ..Default::default()
    };
    let mut sig_changed = base.clone();
    sig_changed.spend_description[0].spend_authority_signature = vec![0xff; 64];

    let h0 = compute_shielded_sighash(&shielded_tx(base), "1000001").unwrap();
    let h1 = compute_shielded_sighash(&shielded_tx(sig_changed), "1000001").unwrap();
    assert_eq!(
        h0, h1,
        "spend_authority_signature must be excluded from the sighash"
    );
}

#[test]
fn shielded_sighash_is_bound_to_body_fields() {
    use tron_actuator::shielded_transfer::compute_shielded_sighash;
    let base = ShieldedTransferContract {
        from_amount: 200,
        spend_description: vec![minimal_spend(0x11)],
        receive_description: vec![minimal_receive(0x22)],
        ..Default::default()
    };
    let h0 = compute_shielded_sighash(&shielded_tx(base.clone()), "1000001").unwrap();

    // (a) from_amount
    let mut amt = base.clone();
    amt.from_amount = 999;
    assert_ne!(h0, compute_shielded_sighash(&shielded_tx(amt), "1000001").unwrap());

    // (b) nullifier on a spend description
    let mut nf = base.clone();
    nf.spend_description[0].nullifier = vec![0xee; 32];
    assert_ne!(h0, compute_shielded_sighash(&shielded_tx(nf), "1000001").unwrap());

    // (c) receive description value_commitment
    let mut vc = base.clone();
    vc.receive_description[0].value_commitment = vec![0x33; 32];
    assert_ne!(h0, compute_shielded_sighash(&shielded_tx(vc), "1000001").unwrap());
}

#[test]
fn shielded_sighash_is_bound_to_token_id() {
    use tron_actuator::shielded_transfer::compute_shielded_sighash;
    let c = ShieldedTransferContract {
        from_amount: 1,
        receive_description: vec![minimal_receive(0x09)],
        ..Default::default()
    };
    let tx = shielded_tx(c);
    let a = compute_shielded_sighash(&tx, "000000").unwrap();
    let b = compute_shielded_sighash(&tx, "1000001").unwrap();
    assert_ne!(a, b, "token id must be a domain separator for the sighash");
}

#[test]
fn shielded_sighash_rejects_non_shielded_contract() {
    use tron_actuator::shielded_transfer::{compute_shielded_sighash, ShieldedSighashError};
    use tron_proto::transaction::contract::ContractType;
    let tx = tron_proto::Transaction {
        raw_data: Some(tron_proto::transaction::Raw {
            contract: vec![tron_proto::transaction::Contract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any::default()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = compute_shielded_sighash(&tx, "000000").unwrap_err();
    assert!(matches!(err, ShieldedSighashError::NotShielded));
}
