//! Tests for `compute_account_state_root`.

use tron_crypto::address::Address;
use tron_proto::Account;
use tron_types::{
    compute_account_state_root, AccountState, KECCAK_EMPTY_STORAGE_ROOT,
};

fn addr(byte: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    Address::from_raw(a)
}

#[test]
fn empty_trie_root_is_keccak_empty_storage_root() {
    let root = compute_account_state_root(&[]);
    assert_eq!(root, KECCAK_EMPTY_STORAGE_ROOT);
}

#[test]
fn root_is_deterministic_for_same_inputs() {
    let a = addr(0x01);
    let b = addr(0x02);
    let acct_a = Account {
        address: a.as_bytes().to_vec(),
        balance: 1_000_000,
        ..Default::default()
    };
    let acct_b = Account {
        address: b.as_bytes().to_vec(),
        balance: 500_000,
        ..Default::default()
    };

    let root1 = compute_account_state_root(&[(a, acct_a.clone()), (b, acct_b.clone())]);
    let root2 = compute_account_state_root(&[(a, acct_a.clone()), (b, acct_b.clone())]);
    assert_eq!(root1, root2);
}

#[test]
fn root_is_order_independent() {
    let a = addr(0x01);
    let b = addr(0x02);
    let acct_a = Account {
        address: a.as_bytes().to_vec(),
        balance: 1_000_000,
        ..Default::default()
    };
    let acct_b = Account {
        address: b.as_bytes().to_vec(),
        balance: 500_000,
        ..Default::default()
    };

    // Insertion order shouldn't matter — a Patricia trie's root is a
    // function of the key/value set, not the insertion sequence.
    let root1 = compute_account_state_root(&[(a, acct_a.clone()), (b, acct_b.clone())]);
    let root2 = compute_account_state_root(&[(b, acct_b), (a, acct_a)]);
    assert_eq!(root1, root2);
}

#[test]
fn root_changes_when_balance_changes() {
    let a = addr(0x01);
    let acct_a = Account {
        address: a.as_bytes().to_vec(),
        balance: 1_000_000,
        ..Default::default()
    };
    let acct_a_richer = Account {
        balance: 2_000_000,
        ..acct_a.clone()
    };

    let r1 = compute_account_state_root(&[(a, acct_a)]);
    let r2 = compute_account_state_root(&[(a, acct_a_richer)]);
    assert_ne!(r1, r2);
}

#[test]
fn root_changes_when_new_account_added() {
    let a = addr(0x01);
    let b = addr(0x02);
    let acct_a = Account {
        address: a.as_bytes().to_vec(),
        balance: 1_000_000,
        ..Default::default()
    };
    let acct_b = Account {
        address: b.as_bytes().to_vec(),
        balance: 500_000,
        ..Default::default()
    };
    let r1 = compute_account_state_root(&[(a, acct_a.clone())]);
    let r2 = compute_account_state_root(&[(a, acct_a), (b, acct_b)]);
    assert_ne!(r1, r2);
}

#[test]
fn account_state_rlp_encodes_4_tuple_with_minimal_uints() {
    let s = AccountState {
        nonce: 0,
        balance: 0x42,
        storage_root: [0xaa; 32],
        code_hash: [0xbb; 32],
    };
    let rlp = s.rlp_encode();
    // Minimum: list header + 0x80 (nonce=0) + 0x42 (balance fits in one byte < 0x80) +
    // 0xa0 + 32 bytes (storage_root) + 0xa0 + 32 bytes (code_hash).
    // Total payload = 1 + 1 + 33 + 33 = 68 bytes → long-list header.
    // List header: 0xf8, 0x44 (68).
    assert_eq!(rlp[0], 0xf8);
    assert_eq!(rlp[1], 68);
    assert_eq!(rlp[2], 0x80); // nonce=0 encoded as empty string
    assert_eq!(rlp[3], 0x42); // balance fits in one byte
    assert_eq!(rlp[4], 0xa0); // 32-byte string header
    assert_eq!(&rlp[5..37], &[0xaa; 32]);
    assert_eq!(rlp[37], 0xa0);
    assert_eq!(&rlp[38..70], &[0xbb; 32]);
}

#[test]
fn empty_account_state_has_canonical_constants() {
    let empty = AccountState::empty();
    assert_eq!(empty.nonce, 0);
    assert_eq!(empty.balance, 0);
    assert_eq!(empty.storage_root, KECCAK_EMPTY_STORAGE_ROOT);
    assert_eq!(empty.code_hash, tron_crypto::hash::KECCAK_EMPTY);
}

// === Per-contract storage root ============================================

use tron_types::compute_storage_root;

#[test]
fn empty_storage_root_is_keccak_empty_constant() {
    assert_eq!(compute_storage_root(&[]), KECCAK_EMPTY_STORAGE_ROOT);
}

#[test]
fn storage_root_is_deterministic_and_order_independent() {
    let mut k1 = [0u8; 32];
    k1[31] = 0x07;
    let mut k2 = [0u8; 32];
    k2[31] = 0x42;
    let v1 = vec![0u8; 32];
    let mut v2 = [0u8; 32];
    v2[31] = 0xff;
    let v2 = v2.to_vec();

    let rows_a = vec![(k1, v1.clone()), (k2, v2.clone())];
    let rows_b = vec![(k2, v2), (k1, v1)];
    let r1 = compute_storage_root(&rows_a);
    let r2 = compute_storage_root(&rows_b);
    assert_eq!(r1, r2);
}

#[test]
fn different_slot_values_produce_different_roots() {
    let mut key = [0u8; 32];
    key[31] = 1;
    let v_a = vec![0xaa; 32];
    let v_b = vec![0xbb; 32];
    let r_a = compute_storage_root(&[(key, v_a)]);
    let r_b = compute_storage_root(&[(key, v_b)]);
    assert_ne!(r_a, r_b);
}

#[test]
fn account_state_root_uses_supplied_storage_root() {
    let a = addr(0xc1);
    let acct = Account {
        address: a.as_bytes().to_vec(),
        balance: 1_000,
        code_hash: vec![0xab; 32],
        ..Default::default()
    };

    // Two roots: one with KECCAK_EMPTY storage, one with a non-empty
    // synthetic storage root. They must differ.
    let r_empty =
        tron_types::compute_account_state_root_with_storage(&[(a, acct.clone())], |_| None);
    let custom_root = [0x55u8; 32];
    let r_custom = tron_types::compute_account_state_root_with_storage(
        &[(a, acct)],
        |query| {
            if query == &a {
                Some(custom_root)
            } else {
                None
            }
        },
    );
    assert_ne!(r_empty, r_custom);
}
