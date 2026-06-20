//! Focused end-to-end tests for the VOTEWITNESS (0xd8) opcode.
//!
//! These deploy a contract that lays out a length-prefixed witness array
//! and amount array in memory exactly the way solc emits a
//! `witnesses[] / amounts[]` pair, then executes VOTEWITNESS, and assert
//! the host receives the right `(address, amount)` pairs and casts them
//! (java `Program.voteWitness` → `VoteWitnessProcessor`). A second test
//! covers a validation failure (votes exceeding the voter's TRON power),
//! proving it returns 0 and leaves the prior votes untouched — matching
//! java's commit-only-on-success child repository.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::Frozen;
use tron_proto::{Account, Witness};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

const TRX_PRECISION: i64 = 1_000_000;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
    dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    dynamic_properties.save_latest_block_header_timestamp(1_700_000_000_000);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
        abi: None,
    }
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn register_witness(stores: &VmStores, addr: [u8; 21]) {
    stores
        .witnesses
        .put(
            &Address::from_raw(addr),
            &Witness {
                address: addr.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
}

fn install_caller(stores: &VmStores, addr: [u8; 21], balance: i64) {
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance,
                ..Default::default()
            },
        )
        .unwrap();
}

fn trigger(from: [u8; 21], to: [u8; 21]) -> tron_proto::TriggerSmartContract {
    tron_proto::TriggerSmartContract {
        owner_address: from.to_vec(),
        contract_address: to.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    }
}

/// `PUSH32 <word>` (0x7f + 32 bytes).
fn push32(word: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x7f];
    out.extend_from_slice(&word);
    out
}

fn word_from_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// A 32-byte word whose low 20 bytes are the witness's EVM address
/// (TRON address minus its `0x41` prefix). java `DataWord.toTronAddress`
/// reads exactly these last 20 bytes and re-prefixes `0x41`.
fn word_from_witness(addr: [u8; 21]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&addr[1..]);
    w
}

/// Emit `MSTORE(offset, word)` — push the value, then the offset, then
/// MSTORE (handler pops `[offset, value]`, offset on top).
fn mstore(offset: u64, word: [u8; 32]) -> Vec<u8> {
    let mut bc = push32(word);
    bc.extend(push32(word_from_u64(offset)));
    bc.push(0x52); // MSTORE
    bc
}

/// Build bytecode that writes the two arrays to memory and runs
/// VOTEWITNESS, persisting the success flag to storage slot 0.
///
/// Memory layout:
///   witness array @ `witness_off`: [len][w0][w1]...
///   amount  array @ `amount_off` : [len][a0][a1]...
fn vote_bytecode(
    witness_off: u64,
    amount_off: u64,
    witnesses: &[([u8; 21], u64)],
) -> Vec<u8> {
    let mut bc = Vec::new();
    let n = witnesses.len() as u64;

    // witness array: length word, then one word per witness address.
    bc.extend(mstore(witness_off, word_from_u64(n)));
    for (i, (w, _)) in witnesses.iter().enumerate() {
        bc.extend(mstore(witness_off + 32 + (i as u64) * 32, word_from_witness(*w)));
    }
    // amount array: length word, then one word per amount.
    bc.extend(mstore(amount_off, word_from_u64(n)));
    for (i, (_, a)) in witnesses.iter().enumerate() {
        bc.extend(mstore(amount_off + 32 + (i as u64) * 32, word_from_u64(*a)));
    }

    // Stack (top→bottom): amountArrayLength, amountArrayOffset,
    // witnessArrayLength, witnessArrayOffset. Push bottom→top.
    bc.extend(push32(word_from_u64(witness_off)));
    bc.extend(push32(word_from_u64(n)));
    bc.extend(push32(word_from_u64(amount_off)));
    bc.extend(push32(word_from_u64(n)));
    bc.push(0xd8); // VOTEWITNESS
    bc.extend(push32(word_from_u64(0)));
    bc.push(0x55); // SSTORE slot 0 = success flag
    bc.push(0x00); // STOP
    bc
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, frozen: i64) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance: 0,
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                // TRON power backing the votes (legacy v1 frozen).
                frozen: vec![Frozen {
                    frozen_balance: frozen,
                    expire_time: 0,
                }],
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn vote_witness_casts_decoded_pairs() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa1);
    let contract = tron_addr(0xc1);
    let w0 = tron_addr(0x11);
    let w1 = tron_addr(0x22);
    register_witness(&stores, w0);
    register_witness(&stores, w1);

    // Two witnesses, 3 + 5 = 8 votes → needs 8 TRX of power.
    let bc = vote_bytecode(0x00, 0x100, &[(w0, 3), (w1, 5)]);
    install_contract(&stores, contract, bc, 10 * TRX_PRECISION);
    install_caller(&stores, caller, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller, contract),
        2_000_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "VOTEWITNESS must succeed; got {outcome:?}"
    );

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract))
        .unwrap()
        .unwrap();
    // The host received the right (address, amount) pairs and cast them.
    let cast: std::collections::BTreeMap<Vec<u8>, i64> = acct
        .votes
        .iter()
        .map(|v| (v.vote_address.clone(), v.vote_count))
        .collect();
    let mut expect = std::collections::BTreeMap::new();
    expect.insert(w0.to_vec(), 3i64);
    expect.insert(w1.to_vec(), 5i64);
    assert_eq!(cast, expect, "votes must match the decoded array pairs");

    // VotesStore mirrors the cast as `new_votes`.
    let capsule = stores
        .votes
        .as_ref()
        .unwrap()
        .get(&Address::from_raw(contract))
        .unwrap()
        .expect("votes capsule written");
    let new_votes: std::collections::BTreeMap<Vec<u8>, i64> = capsule
        .new_votes
        .iter()
        .map(|v| (v.vote_address.clone(), v.vote_count))
        .collect();
    assert_eq!(new_votes, expect, "new_votes must mirror the cast votes");
}

#[test]
fn vote_witness_rejects_when_exceeding_tron_power_without_mutating() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa2);
    let contract = tron_addr(0xc2);
    let w0 = tron_addr(0x33);
    register_witness(&stores, w0);

    // Vote 100 TRX but only 1 TRX of power → java's sum-vs-tronPower check
    // throws ContractExeException → false, no mutation.
    let bc = vote_bytecode(0x00, 0x100, &[(w0, 100)]);
    install_contract(&stores, contract, bc, 1 * TRX_PRECISION);
    install_caller(&stores, caller, 1_000_000_000);

    // Pre-seed a prior vote that must survive the rejected re-vote.
    let mut acct = stores
        .accounts
        .get(&Address::from_raw(contract))
        .unwrap()
        .unwrap();
    acct.votes.push(tron_proto::Vote {
        vote_address: tron_addr(0xee).to_vec(),
        vote_count: 7,
    });
    stores.accounts.put(&Address::from_raw(contract), &acct).unwrap();

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller, contract),
        2_000_000,
    );
    // The opcode pushed 0 (failure) but the contract itself still STOPs
    // successfully — only the internal vote is rejected.
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "contract must still finish; got {outcome:?}"
    );

    let after = stores
        .accounts
        .get(&Address::from_raw(contract))
        .unwrap()
        .unwrap();
    assert_eq!(
        after.votes.len(),
        1,
        "the prior vote must be untouched by a rejected VOTEWITNESS"
    );
    assert_eq!(after.votes[0].vote_address, tron_addr(0xee).to_vec());
    assert_eq!(after.votes[0].vote_count, 7);
    // No VotesStore row was written for the rejected re-vote.
    assert!(
        stores
            .votes
            .as_ref()
            .unwrap()
            .get(&Address::from_raw(contract))
            .unwrap()
            .is_none(),
        "a rejected vote must not write a VotesStore row"
    );
}

#[test]
fn vote_witness_rejects_unregistered_witness_without_mutating() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa3);
    let contract = tron_addr(0xc3);
    // w0 is NOT registered as a witness → java getWitness == null →
    // ContractExeException → false.
    let w0 = tron_addr(0x44);

    let bc = vote_bytecode(0x00, 0x100, &[(w0, 1)]);
    install_contract(&stores, contract, bc, 10 * TRX_PRECISION);
    install_caller(&stores, caller, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller, contract),
        2_000_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let after = stores
        .accounts
        .get(&Address::from_raw(contract))
        .unwrap()
        .unwrap();
    assert!(
        after.votes.is_empty(),
        "no votes should be cast for an unregistered witness"
    );
}
