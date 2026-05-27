//! Tests for `check_transaction_permission`.

use std::sync::Arc;

use hex_literal::hex;
use prost::Message;
use prost_types::Any;
use tron_actuator::permission::{check_transaction_permission, PermissionError};
use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract, Raw as TxRaw};
use tron_proto::{permission::PermissionType, Account, Key, Permission, Transaction, TransferContract};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");
const BOB_PRIV: [u8; 32] =
    hex!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
const BOB: [u8; 21] = hex!("41639d6caadb5617d324c1ad0becb16262fc58ce5f");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn put_account(accounts: &AccountStore, addr: [u8; 21], account: Account) {
    accounts.put(&Address::from_raw(addr), &account);
}

fn make_transfer_tx(owner: [u8; 21], to: [u8; 21], permission_id: i32) -> Transaction {
    let tc = TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount: 100,
    };
    Transaction {
        raw_data: Some(TxRaw {
            ref_block_bytes: vec![0, 1],
            ref_block_num: 0,
            ref_block_hash: vec![0u8; 8],
            expiration: 1_700_000_000_000,
            auths: Vec::new(),
            data: Vec::new(),
            contract: vec![Contract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                provider: Vec::new(),
                contract_name: Vec::new(),
                permission_id,
            }],
            scripts: Vec::new(),
            timestamp: 1_700_000_000_000,
            fee_limit: 0,
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    }
}

#[test]
fn missing_signature_is_rejected() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            ..Default::default()
        },
    );
    let tx = make_transfer_tx(ALICE, BOB, 0);
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(matches!(err, PermissionError::MissingSignature));
}

#[test]
fn default_permission_accepts_owner_signature() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 0);
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .expect("Alice's own signature should satisfy default owner permission");
}

#[test]
fn wrong_signer_is_rejected() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 0);
    // Bob signs Alice's transaction; default permission has only Alice's key.
    tron_types::sign_transaction(&mut tx, &BOB_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(matches!(err, PermissionError::SignerNotInPermission(_)));
}

#[test]
fn explicit_owner_permission_with_two_of_three_threshold_accepts_two_signers() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    // Owner-permission requires 2-of-3: Alice, Bob, and a third never-signed party.
    let third = hex!("41dddddddddddddddddddddddddddddddddddddddd");
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            owner_permission: Some(Permission {
                r#type: PermissionType::Owner as i32,
                id: 0,
                permission_name: "owner".to_string(),
                threshold: 2,
                parent_id: 0,
                operations: Vec::new(),
                keys: vec![
                    Key {
                        address: ALICE.to_vec(),
                        weight: 1,
                    },
                    Key {
                        address: BOB.to_vec(),
                        weight: 1,
                    },
                    Key {
                        address: third.to_vec(),
                        weight: 1,
                    },
                ],
            }),
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 0);
    // First Alice signs.
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    // Then Bob signs the same tx body — sigs are over `tx_id`, so both
    // signatures cover the same hash.
    tron_types::sign_transaction(&mut tx, &BOB_PRIV).unwrap();
    assert_eq!(tx.signature.len(), 2);
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .expect("2-of-3 should pass with two valid signers");
}

#[test]
fn below_threshold_is_rejected() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            owner_permission: Some(Permission {
                r#type: PermissionType::Owner as i32,
                id: 0,
                permission_name: "owner".to_string(),
                threshold: 2, // require 2
                parent_id: 0,
                operations: Vec::new(),
                keys: vec![
                    Key {
                        address: ALICE.to_vec(),
                        weight: 1,
                    },
                    Key {
                        address: BOB.to_vec(),
                        weight: 1,
                    },
                ],
            }),
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 0);
    // Only Alice signs — weight 1 < threshold 2.
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        PermissionError::BelowThreshold {
            weight: 1,
            threshold: 2
        }
    ));
}

#[test]
fn active_permission_must_be_active_type() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    // Active permission slot configured but typed as Owner — a misuse.
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            active_permission: vec![Permission {
                r#type: PermissionType::Owner as i32, // wrong type
                id: 2,
                permission_name: "wrong".to_string(),
                threshold: 1,
                parent_id: 0,
                operations: vec![0xffu8; 32],
                keys: vec![Key {
                    address: ALICE.to_vec(),
                    weight: 1,
                }],
            }],
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 2);
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(matches!(err, PermissionError::PermissionTypeMismatch));
}

#[test]
fn active_permission_operations_must_allow_contract_type() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    // Operations bitmap allows nothing.
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            active_permission: vec![Permission {
                r#type: PermissionType::Active as i32,
                id: 2,
                permission_name: "active".to_string(),
                threshold: 1,
                parent_id: 0,
                operations: vec![0u8; 32], // no bits set
                keys: vec![Key {
                    address: ALICE.to_vec(),
                    weight: 1,
                }],
            }],
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 2);
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(matches!(err, PermissionError::OperationsDisallowedContract));
}

#[test]
fn too_many_signatures_is_rejected() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"TOTAL_SIGN_NUM", 1);
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 0);
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    tron_types::sign_transaction(&mut tx, &BOB_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(matches!(err, PermissionError::TooManySigs { .. }));
}

#[test]
fn duplicate_signer_is_rejected() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"TOTAL_SIGN_NUM", 5);
    // Permission has 2 keys so we're allowed 2 signatures structurally —
    // the test exercises the post-keys-count duplicate detector.
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            owner_permission: Some(Permission {
                r#type: PermissionType::Owner as i32,
                id: 0,
                permission_name: "owner".to_string(),
                threshold: 2,
                parent_id: 0,
                operations: Vec::new(),
                keys: vec![
                    Key {
                        address: ALICE.to_vec(),
                        weight: 1,
                    },
                    Key {
                        address: BOB.to_vec(),
                        weight: 1,
                    },
                ],
            }),
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 0);
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    // Alice signs twice — copy the deterministic ECDSA sig.
    let sig0 = tx.signature[0].clone();
    tx.signature.push(sig0);
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(
        matches!(err, PermissionError::DuplicateSigner(_)),
        "got {err:?}"
    );
}

// =============================================================================
// CA-C1: resolve_permission matches actives by `Permission.id`, NOT by
// array index. Without this fix, an account whose `active_permission`
// vector had non-contiguous IDs (e.g. from an imported snapshot, or
// from a pre-CA-C2 writer) would silently authorize the WRONG
// permission for any given `permission_id`. java-tron's
// `AccountCapsule.getPermissionById` does the same iterate-and-match.
// =============================================================================

#[test]
fn resolve_finds_active_by_id_even_when_array_order_doesnt_match() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    // Account with TWO actives. Critically, the array order is
    // reversed: the entry at index 0 has id=3, and the entry at
    // index 1 has id=2. Pre-fix this would resolve `permission_id=2`
    // to `active_permission[0]` (which has id=3), authorizing the
    // wrong permission. Post-fix, the resolver finds the entry whose
    // `id` field actually equals 2.
    //
    // The id=2 permission has Alice as the only key. The id=3
    // permission has Bob as the only key. If the resolver picked the
    // wrong one, a tx signed by Alice with `permission_id=2` would
    // fail (because the array[0] permission expects Bob).
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            active_permission: vec![
                // Index 0 — id=3, Bob's key.
                Permission {
                    r#type: PermissionType::Active as i32,
                    id: 3,
                    permission_name: "bob_active".to_string(),
                    threshold: 1,
                    parent_id: 0,
                    operations: vec![0xffu8; 32],
                    keys: vec![Key {
                        address: BOB.to_vec(),
                        weight: 1,
                    }],
                },
                // Index 1 — id=2, Alice's key.
                Permission {
                    r#type: PermissionType::Active as i32,
                    id: 2,
                    permission_name: "alice_active".to_string(),
                    threshold: 1,
                    parent_id: 0,
                    operations: vec![0xffu8; 32],
                    keys: vec![Key {
                        address: ALICE.to_vec(),
                        weight: 1,
                    }],
                },
            ],
            ..Default::default()
        },
    );

    // Alice signs a tx claiming permission_id=2 (her permission).
    let mut tx = make_transfer_tx(ALICE, BOB, 2);
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    // Resolver must find the id=2 permission (Alice's) even though
    // it's at array index 1, not 0.
    check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .expect("should resolve by id, not by array index");
}

#[test]
fn resolve_returns_not_found_when_no_active_has_matching_id() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    // One active, id=2. Tx asks for permission_id=3 — must fail
    // cleanly (NOT silently fall through to a different active).
    put_account(
        &accounts,
        ALICE,
        Account {
            address: ALICE.to_vec(),
            balance: 1_000,
            active_permission: vec![Permission {
                r#type: PermissionType::Active as i32,
                id: 2,
                permission_name: "active".to_string(),
                threshold: 1,
                parent_id: 0,
                operations: vec![0xffu8; 32],
                keys: vec![Key {
                    address: ALICE.to_vec(),
                    weight: 1,
                }],
            }],
            ..Default::default()
        },
    );
    let mut tx = make_transfer_tx(ALICE, BOB, 3); // no such id
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    let contract = tx.raw_data.as_ref().unwrap().contract[0].clone();
    let err = check_transaction_permission(
        &accounts,
        &dp,
        &tx,
        &contract,
        ContractType::TransferContract,
    )
    .unwrap_err();
    assert!(matches!(err, PermissionError::PermissionIdNotFound(3)));
}
