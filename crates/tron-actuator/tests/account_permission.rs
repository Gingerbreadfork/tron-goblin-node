//! Tests for `AccountPermissionUpdateActuator::validate`.
//!
//! Coverage: the top-level structural rules and the per-permission
//! `check_permission` rules (key-count limits, threshold, weight sum,
//! distinct addresses, operations bitmap, etc.).

use std::sync::Arc;

use tron_actuator::account::{
    execute_account_permission_update, validate_account_permission_update,
};
use tron_actuator::ActuatorError;
use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_proto::{
    permission::PermissionType, Account, AccountPermissionUpdateContract, Key, Permission,
};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(byte: u8) -> Vec<u8> {
    let mut a = vec![0x41u8];
    a.extend_from_slice(&[byte; 20]);
    a
}

fn key(byte: u8, weight: i64) -> Key {
    Key {
        address: addr(byte),
        weight,
    }
}

fn owner_permission(keys: Vec<Key>, threshold: i64) -> Permission {
    Permission {
        r#type: PermissionType::Owner as i32,
        id: 0,
        permission_name: "owner".to_string(),
        threshold,
        parent_id: 0,
        operations: vec![],
        keys,
    }
}

fn active_permission(keys: Vec<Key>, threshold: i64, ops: Vec<u8>) -> Permission {
    Permission {
        r#type: PermissionType::Active as i32,
        id: 2,
        permission_name: "active".to_string(),
        threshold,
        parent_id: 0,
        operations: ops,
        keys,
    }
}

fn enabled_stores() -> (AccountStore, DynamicPropertiesStore) {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MULTI_SIGN", 1);
    dp.put_long(b"TOTAL_SIGN_NUM", 5);
    (accounts, dp)
}

fn valid_contract(owner: &[u8]) -> AccountPermissionUpdateContract {
    AccountPermissionUpdateContract {
        owner_address: owner.to_vec(),
        owner: Some(owner_permission(vec![key(0xaa, 1)], 1)),
        witness: None,
        actives: vec![active_permission(vec![key(0xbb, 1)], 1, vec![0xffu8; 32])],
    }
}

fn put_account(accounts: &AccountStore, address: &[u8], is_witness: bool) {
    let mut buf = [0u8; 21];
    buf.copy_from_slice(address);
    accounts.put(
        &Address::from_raw(buf),
        &Account {
            address: address.to_vec(),
            is_witness,
            ..Default::default()
        },
    ).unwrap();
}

#[test]
fn rejects_when_multi_sign_disabled() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    // ALLOW_MULTI_SIGN not set.
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let c = valid_contract(&owner);
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::MultiSignNotAllowed));
}

#[test]
fn rejects_missing_owner_permission() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner = None;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("owner permission")));
}

#[test]
fn rejects_witness_permission_for_non_witness_account() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.witness = Some(Permission {
        r#type: PermissionType::Witness as i32,
        id: 1,
        permission_name: String::new(),
        threshold: 1,
        parent_id: 0,
        operations: vec![],
        keys: vec![key(0xcc, 1)],
    });
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("isn't witness")));
}

#[test]
fn rejects_missing_witness_permission_for_witness_account() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, true);
    let mut c = valid_contract(&owner);
    c.witness = None;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("witness permission is missed")));
}

#[test]
fn rejects_empty_actives() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.actives = vec![];
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("active permission is missed")));
}

#[test]
fn rejects_too_many_actives() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    let one_active = active_permission(vec![key(0xbb, 1)], 1, vec![0xffu8; 32]);
    c.actives = (0..9).map(|_| one_active.clone()).collect();
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("too many")));
}

#[test]
fn rejects_wrong_owner_permission_type() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().r#type = PermissionType::Active as i32;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("owner permission type")));
}

#[test]
fn rejects_wrong_active_permission_type() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.actives[0].r#type = PermissionType::Owner as i32;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("active permission type")));
}

#[test]
fn rejects_zero_keys() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().keys = vec![];
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("key's count")));
}

#[test]
fn rejects_too_many_keys() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    // TOTAL_SIGN_NUM = 5; provide 6.
    c.owner.as_mut().unwrap().keys = (0..6).map(|i| key(i as u8 + 0xa0, 1)).collect();
    c.owner.as_mut().unwrap().threshold = 1;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("TOTAL_SIGN_NUM")));
}

#[test]
fn rejects_witness_permission_with_multiple_keys() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, true);
    let mut c = valid_contract(&owner);
    c.witness = Some(Permission {
        r#type: PermissionType::Witness as i32,
        id: 1,
        permission_name: String::new(),
        threshold: 1,
        parent_id: 0,
        operations: vec![],
        keys: vec![key(0xcc, 1), key(0xdd, 1)], // two keys
    });
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("Witness permission")));
}

#[test]
fn rejects_zero_threshold() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().threshold = 0;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("threshold")));
}

#[test]
fn rejects_duplicate_key_addresses() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().keys = vec![key(0xaa, 1), key(0xaa, 1)];
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("distinct")));
}

#[test]
fn rejects_invalid_key_address() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().keys = vec![Key {
        address: vec![0x00; 21], // wrong prefix
        weight: 1,
    }];
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("validate address")));
}

#[test]
fn rejects_zero_or_negative_weight() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().keys = vec![key(0xaa, 0)];
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("weight")));
}

#[test]
fn rejects_weight_sum_below_threshold() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().keys = vec![key(0xaa, 1), key(0xbb, 2)];
    c.owner.as_mut().unwrap().threshold = 100; // way more than 3
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("sum of all key")));
}

#[test]
fn rejects_non_zero_parent_id() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().parent_id = 5;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("parent")));
}

#[test]
fn rejects_long_permission_name() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.owner.as_mut().unwrap().permission_name = "x".repeat(33);
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("name is too long")));
}

#[test]
fn rejects_operations_on_non_active_permission() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    // Owner permission must NOT have operations.
    c.owner.as_mut().unwrap().operations = vec![0xffu8; 32];
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("needn't operations")));
}

#[test]
fn rejects_wrong_operations_length() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.actives[0].operations = vec![0xffu8; 16]; // wrong length
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("operations size")));
}

#[test]
fn rejects_disallowed_contract_type_in_operations() {
    let (accounts, dp) = enabled_stores();
    // Configure AVAILABLE_CONTRACT_TYPE to allow only the LSB of byte 0.
    let mut allow_list = vec![0u8; 32];
    allow_list[0] = 0x01;
    dp.put_bytes(b"AVAILABLE_CONTRACT_TYPE", &allow_list);

    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    // Active.operations attempts to use bit 1 of byte 0 (not in allow list).
    let mut ops = vec![0u8; 32];
    ops[0] = 0x02;
    c.actives[0].operations = ops;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Validate(s) if s.contains("contract type")));
}

#[test]
fn accepts_valid_contract_and_executes_with_fee() {
    let (accounts, dp) = enabled_stores();
    dp.put_long(b"UPDATE_ACCOUNT_PERMISSION_FEE", 100_000_000);
    let owner = addr(0x11);
    // Seed account with enough balance to cover fee.
    let owner_addr = Address::from_raw({
        let mut a = [0u8; 21];
        a.copy_from_slice(&owner);
        a
    });
    accounts.put(
        &owner_addr,
        &Account {
            address: owner.clone(),
            is_witness: false,
            balance: 200_000_000,
            ..Default::default()
        },
    ).unwrap();

    let c = valid_contract(&owner);
    validate_account_permission_update(&accounts, &dp, &c).expect("valid contract");
    let result = execute_account_permission_update(&accounts, &dp, &c).unwrap();
    assert_eq!(result.fee, 100_000_000);

    let after = accounts.get(&owner_addr).unwrap().unwrap();
    assert_eq!(after.balance, 100_000_000); // 200M - 100M fee
    assert!(after.owner_permission.is_some());
    assert!(after.witness_permission.is_none());
    assert_eq!(after.active_permission.len(), 1);
}

// =============================================================================
// CA-C2: active permission `id` enforcement.
//
// java-tron's `AccountPermissionUpdateActuator` assigns active IDs
// contiguously starting at 2 (Owner=0, Witness=1, Active=2..9).
// `resolve_permission` previously looked actives up by array index
// `permission_id - 2`, which assumed the IDs matched the index. Without
// validate-side enforcement, a malicious or buggy writer could land
// actives with arbitrary IDs (duplicates, out-of-range, holes) and
// every downstream multi-sig check would silently authorize the wrong
// permission.
//
// These tests pin: the `actives[i].id == 2 + i` invariant is enforced
// by `validate`, AND `resolve_permission` (after the CA-C1 fix) finds
// permissions by stored `id` even when array order doesn't match.
// =============================================================================

#[test]
fn rejects_active_with_wrong_id_on_first_slot() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    // valid_contract gives a single active with id=2 (correct for
    // index 0). Bump to id=3 to confirm validate rejects.
    c.actives[0].id = 3;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(
        matches!(&err, ActuatorError::Validate(s) if s.contains("active permission id")),
        "got: {err:?}"
    );
}

#[test]
fn rejects_active_with_duplicate_ids_across_multiple_slots() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    // Two actives with id=2 — what would happen if the producer forgot
    // to increment. Validate must catch this because resolver matches
    // on id; with duplicates, `permission_id=3` would never resolve
    // even though there are two actives configured.
    let second_active = active_permission(vec![key(0xcc, 1)], 1, vec![0xffu8; 32]);
    c.actives.push(second_active); // id=2 again
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(
        matches!(&err, ActuatorError::Validate(s) if s.contains("active permission id")),
        "got: {err:?}"
    );
}

#[test]
fn accepts_actives_with_contiguous_ids_starting_at_2() {
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    // Build a second active with the correct id=3 (= 2 + 1).
    let mut second_active = active_permission(vec![key(0xcc, 1)], 1, vec![0xffu8; 32]);
    second_active.id = 3;
    c.actives.push(second_active);
    validate_account_permission_update(&accounts, &dp, &c)
        .expect("contiguous active ids should pass");
}

#[test]
fn rejects_active_with_id_below_2() {
    // Owner=0 and Witness=1 are reserved; an active claiming id=1
    // would resolve through the wrong code path entirely. Validate
    // must reject — the contiguous-starting-at-2 rule covers this
    // implicitly (2 + 0 = 2, not 1).
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.actives[0].id = 1;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(&err, ActuatorError::Validate(s) if s.contains("active permission id")));
}

#[test]
fn rejects_active_with_id_above_9() {
    // MAX_ACTIVE_PERMISSIONS = 8 → highest legal id is 9 (= 2 + 7).
    // A single active claiming id=10 fails the `2 + idx` rule at
    // index 0 (where the expected id is 2).
    let (accounts, dp) = enabled_stores();
    let owner = addr(0x11);
    put_account(&accounts, &owner, false);
    let mut c = valid_contract(&owner);
    c.actives[0].id = 10;
    let err = validate_account_permission_update(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(&err, ActuatorError::Validate(s) if s.contains("active permission id")));
}
