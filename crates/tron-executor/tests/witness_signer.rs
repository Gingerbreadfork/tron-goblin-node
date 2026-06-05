//! Block-signature authorization with java-tron's `allowMultiSign` /
//! witness-permission delegation (`BlockCapsule.validateSignature`).
//!
//! When `ALLOW_MULTI_SIGN == 1` (the mainnet default for years) an SR may
//! sign blocks with a delegated witness-permission key instead of its
//! account key (cold/hot key separation). The signature must then recover
//! to `witness_permission.keys[0].address`, not the witness account
//! address. Validating against the account address — the `None` override
//! to `verify_witness_signature` — rejects every such block, which silently
//! broke live mainnet sync (~1/4 of blocks) until `expected_block_signer`
//! was wired into both the sync accept path and the executor.

use std::sync::Arc;

use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_crypto::signature::public_key_from_private;
use tron_executor::{expected_block_signer, StateBackends};
use tron_proto::{block_header::Raw as BlockHeaderRaw, Account, Block, BlockHeader, Key, Permission};
use tron_types::{sign_block, verify_witness_signature, BlockValidateError};

// The two distinct keys at play: the SR account key, and the delegated
// block-signing (witness-permission) key.
const ACCOUNT_PRIV: [u8; 32] = [0x11; 32];
const PERM_PRIV: [u8; 32] = [0x22; 32];

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
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
    }
}

fn addr_of(priv_key: &[u8; 32]) -> Address {
    let pubkey = public_key_from_private(priv_key).expect("pubkey");
    Address::from_uncompressed_pubkey(&pubkey).expect("address")
}

/// Minimal block produced by `witness_address`, signed by `signer_priv`.
fn signed_block(num: i64, witness_address: &Address, signer_priv: &[u8; 32]) -> Block {
    let mut block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: num,
                timestamp: 1_700_000_000_000,
                witness_address: witness_address.as_bytes().to_vec(),
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    };
    sign_block(&mut block, signer_priv).expect("sign");
    block
}

fn set_multi_sign(state: &StateBackends, on: bool) {
    DynamicPropertiesStore::new(state.dyn_props.clone())
        .put_long(b"ALLOW_MULTI_SIGN", i64::from(on));
}

/// Seed the producer account. `permission_key = Some(k)` gives it a witness
/// permission whose first key is `k`; `None` leaves it without one.
fn seed_account(state: &StateBackends, account: &Address, permission_key: Option<&Address>) {
    let witness_permission = permission_key.map(|k| Permission {
        keys: vec![Key { address: k.as_bytes().to_vec(), weight: 1 }],
        ..Default::default()
    });
    AccountStore::new(state.accounts.clone())
        .put(
            account,
            &Account {
                address: account.as_bytes().to_vec(),
                witness_permission,
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn multisign_block_signed_by_witness_permission_key_validates() {
    let state = fresh_state();
    let account_addr = addr_of(&ACCOUNT_PRIV);
    let perm_addr = addr_of(&PERM_PRIV);
    assert_ne!(account_addr.as_bytes(), perm_addr.as_bytes(), "keys must differ");

    set_multi_sign(&state, true);
    seed_account(&state, &account_addr, Some(&perm_addr));

    // Block claims `account_addr` as its witness but is signed by the
    // delegated key — exactly what ~7 of mainnet's 27 SRs do.
    let block = signed_block(83_316_753, &account_addr, &PERM_PRIV);

    // The fix: the expected signer resolves to the witness-permission key…
    let expected = expected_block_signer(&block, &state).expect("expected signer");
    assert_eq!(expected.as_bytes(), perm_addr.as_bytes());
    // …so the block validates.
    verify_witness_signature(&block, Some(&expected)).expect("delegated-key block must validate");

    // Regression guard for the original bug: the old `None` path demanded
    // the account key, producing the exact mainnet-sync rejection.
    match verify_witness_signature(&block, None) {
        Err(BlockValidateError::WitnessMismatch { recovered, expected }) => {
            assert_eq!(recovered.as_bytes(), perm_addr.as_bytes());
            assert_eq!(expected.as_bytes(), account_addr.as_bytes());
        }
        other => panic!("expected WitnessMismatch from the None path, got {other:?}"),
    }
}

#[test]
fn multisign_without_witness_permission_falls_back_to_account_key() {
    let state = fresh_state();
    let account_addr = addr_of(&ACCOUNT_PRIV);

    set_multi_sign(&state, true);
    seed_account(&state, &account_addr, None); // account exists, no witness perm

    let block = signed_block(1, &account_addr, &ACCOUNT_PRIV);
    let expected = expected_block_signer(&block, &state).expect("expected signer");
    assert_eq!(expected.as_bytes(), account_addr.as_bytes());
    verify_witness_signature(&block, Some(&expected)).expect("direct-sign block must validate");
}

#[test]
fn multisign_disabled_always_expects_the_account_key() {
    let state = fresh_state();
    let account_addr = addr_of(&ACCOUNT_PRIV);
    let perm_addr = addr_of(&PERM_PRIV);

    // Multi-sign OFF, but the account DOES carry a witness permission — it
    // must be ignored (java-tron consults it only when allowMultiSign==1).
    set_multi_sign(&state, false);
    seed_account(&state, &account_addr, Some(&perm_addr));

    let block = signed_block(1, &account_addr, &ACCOUNT_PRIV);
    let expected = expected_block_signer(&block, &state).expect("expected signer");
    assert_eq!(expected.as_bytes(), account_addr.as_bytes());
    verify_witness_signature(&block, Some(&expected)).expect("account-key block must validate");
}

#[test]
fn multisign_missing_account_falls_back_to_witness_address() {
    let state = fresh_state();
    let account_addr = addr_of(&ACCOUNT_PRIV);

    set_multi_sign(&state, true);
    // No account row seeded — fall back to the witness address itself.
    let block = signed_block(1, &account_addr, &ACCOUNT_PRIV);
    let expected = expected_block_signer(&block, &state).expect("expected signer");
    assert_eq!(expected.as_bytes(), account_addr.as_bytes());
}
