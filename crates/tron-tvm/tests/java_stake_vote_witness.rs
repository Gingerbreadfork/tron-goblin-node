//! VOTEWITNESS (0xd8) failure modes pinned by java-tron's
//! `framework/src/test/java/org/tron/common/runtime/vm/VoteTest.java`.
//!
//! `VoteTest.testVoteWithException` asserts three REVERTs from the calling
//! contract: insufficient TRON Power, a target that is not a witness, and a
//! witness/amount list-size mismatch. The first two are already pinned by
//! `tests/vote_opcode.rs`; the third is the one `Program.voteWitness` handles
//! specially, and it sits next to a fourth case the java source separates but
//! the test cannot reach through solidity — the in-memory array LENGTH WORD
//! disagreeing with the length pushed on the stack.
//!
//! The two are deliberately different outcomes in java:
//!
//! * length word != stack length → `BytecodeExecutionException`, which is a
//!   HALT: execution stops and all remaining energy is spent.
//! * witness count != amount count → a plain `return false`, so the opcode
//!   pushes 0 and the contract keeps running.
//!
//! Collapsing either into the other changes both the transaction's
//! `contractResult` and its energy charge, so both are pinned here.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::Frozen;
use tron_proto::{Account, TriggerSmartContract, Vote, Witness};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

const TRX_PRECISION: i64 = 1_000_000;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
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
                is_jobs: true,
                ..Default::default()
            },
        )
        .unwrap();
}

fn push32(word: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x7f];
    out.extend_from_slice(&word);
    out
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_witness(addr: [u8; 21]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&addr[1..]);
    w
}

fn mstore(offset: u64, word: [u8; 32]) -> Vec<u8> {
    let mut bc = push32(word);
    bc.extend(push32(word_u64(offset)));
    bc.push(0x52);
    bc
}

/// Build a VOTEWITNESS call with independent control over each array's
/// in-memory length word and the length pushed on the stack, so the two
/// `Program.voteWitness` rejection paths can be driven separately.
struct VoteCall {
    witness_off: u64,
    amount_off: u64,
    witnesses: Vec<[u8; 21]>,
    amounts: Vec<u64>,
    /// Length word written at `witness_off`; defaults to `witnesses.len()`.
    witness_len_word: Option<u64>,
    /// Length pushed as the stack operand; defaults to `witnesses.len()`.
    witness_len_stack: Option<u64>,
}

impl VoteCall {
    fn bytecode(&self) -> Vec<u8> {
        let mut bc = Vec::new();
        let w_n = self.witnesses.len() as u64;
        let a_n = self.amounts.len() as u64;

        bc.extend(mstore(
            self.witness_off,
            word_u64(self.witness_len_word.unwrap_or(w_n)),
        ));
        for (i, w) in self.witnesses.iter().enumerate() {
            bc.extend(mstore(
                self.witness_off + 32 + (i as u64) * 32,
                word_witness(*w),
            ));
        }
        bc.extend(mstore(self.amount_off, word_u64(a_n)));
        for (i, a) in self.amounts.iter().enumerate() {
            bc.extend(mstore(self.amount_off + 32 + (i as u64) * 32, word_u64(*a)));
        }

        // Stack, bottom → top: witnessArrayOffset, witnessArrayLength,
        // amountArrayOffset, amountArrayLength.
        bc.extend(push32(word_u64(self.witness_off)));
        bc.extend(push32(word_u64(self.witness_len_stack.unwrap_or(w_n))));
        bc.extend(push32(word_u64(self.amount_off)));
        bc.extend(push32(word_u64(a_n)));
        bc.push(0xd8); // VOTEWITNESS
        bc.extend(push32(word_u64(0)));
        bc.push(0x55); // SSTORE slot 0 = pushed flag
        bc.push(0x00); // STOP
        bc
    }
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
                frozen: vec![Frozen {
                    frozen_balance: frozen,
                    expire_time: 0,
                }],
                votes: vec![Vote {
                    // A prior vote no rejected re-vote may disturb.
                    vote_address: tron_addr(0xee).to_vec(),
                    vote_count: 7,
                }],
                ..Default::default()
            },
        )
        .unwrap();
}

fn run(stores: &VmStores, caller: [u8; 21], contract: [u8; 21]) -> VmOutcome {
    stores
        .accounts
        .put(
            &Address::from_raw(caller),
            &Account {
                address: caller.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        &TriggerSmartContract {
            owner_address: caller.to_vec(),
            contract_address: contract.to_vec(),
            ..Default::default()
        },
        2_000_000,
    )
}

fn pushed_flag(stores: &VmStores, addr: [u8; 21]) -> u8 {
    let key = tron_chainbase::StorageRowStore::compose_key(&Address::from_raw(addr), &[0u8; 32]);
    match stores.storage.get(&key).unwrap() {
        Some(bytes) => bytes[31],
        None => 0,
    }
}

fn votes_of(stores: &VmStores, addr: [u8; 21]) -> Vec<Vote> {
    stores
        .accounts
        .get(&Address::from_raw(addr))
        .unwrap()
        .unwrap()
        .votes
}

/// `VoteTest.testVoteWithException`'s "List size not match" case: two witness
/// addresses against a single amount. `Program.voteWitness` returns false
/// WITHOUT throwing, so the opcode pushes 0, execution continues to the
/// `SSTORE`, and no vote is cast or cleared.
#[test]
fn vote_witness_array_length_mismatch_pushes_zero_and_keeps_running() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa1);
    let contract = tron_addr(0xc1);
    let w0 = tron_addr(0x11);
    let w1 = tron_addr(0x22);
    register_witness(&stores, w0);
    register_witness(&stores, w1);

    let call = VoteCall {
        witness_off: 0x00,
        amount_off: 0x100,
        witnesses: vec![w0, w1],
        amounts: vec![3],
        witness_len_word: None,
        witness_len_stack: None,
    };
    install_contract(&stores, contract, call.bytecode(), 10 * TRX_PRECISION);

    let outcome = run(&stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "a size mismatch is a soft false, not a halt; got {outcome:?}"
    );
    assert_eq!(
        pushed_flag(&stores, contract),
        0,
        "VOTEWITNESS must push 0 on a size mismatch"
    );
    assert_eq!(
        votes_of(&stores, contract),
        vec![Vote {
            vote_address: tron_addr(0xee).to_vec(),
            vote_count: 7,
        }],
        "the pre-existing vote must survive untouched"
    );
    assert!(
        stores
            .votes
            .as_ref()
            .unwrap()
            .get(&Address::from_raw(contract))
            .unwrap()
            .is_none(),
        "a rejected vote writes no VotesStore record"
    );
}

/// The sibling rejection in `Program.voteWitness`, checked one line earlier:
/// `memoryLoad(witnessArrayOffset).intValueSafe() != witnessArrayLength`
/// throws `BytecodeExecutionException`. That is a HALT, not a pushed 0 — the
/// contract never reaches its `SSTORE` and the transaction spends all its
/// energy.
#[test]
fn vote_witness_length_word_disagreeing_with_the_stack_halts() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa2);
    let contract = tron_addr(0xc2);
    let w0 = tron_addr(0x33);
    let w1 = tron_addr(0x44);
    register_witness(&stores, w0);
    register_witness(&stores, w1);

    let call = VoteCall {
        witness_off: 0x00,
        amount_off: 0x100,
        witnesses: vec![w0, w1],
        amounts: vec![3, 5],
        // Memory says one element; the stack operand says two.
        witness_len_word: Some(1),
        witness_len_stack: Some(2),
    };
    install_contract(&stores, contract, call.bytecode(), 10 * TRX_PRECISION);

    let outcome = run(&stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Halt { .. }),
        "a length-word mismatch must halt, not push 0; got {outcome:?}"
    );
    assert_eq!(
        pushed_flag(&stores, contract),
        0,
        "the halt happens before the SSTORE, so slot 0 stays clear"
    );
    assert_eq!(
        votes_of(&stores, contract),
        vec![Vote {
            vote_address: tron_addr(0xee).to_vec(),
            vote_count: 7,
        }],
        "a halted transaction commits no vote change"
    );
}

/// The control for both: matched lengths and matched length words cast the
/// votes. `VoteTest.testVote` pins that the account's vote list carries the
/// amounts verbatim (1000 to each of two witnesses) while the witnesses'
/// own `vote_count` stays put until the next maintenance cycle.
#[test]
fn vote_witness_matched_lengths_cast_votes_without_touching_witness_counts() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa3);
    let contract = tron_addr(0xc3);
    let w0 = tron_addr(0x55);
    let w1 = tron_addr(0x66);
    register_witness(&stores, w0);
    register_witness(&stores, w1);

    let call = VoteCall {
        witness_off: 0x00,
        amount_off: 0x100,
        witnesses: vec![w0, w1],
        amounts: vec![1000, 1000],
        witness_len_word: None,
        witness_len_stack: None,
    };
    install_contract(&stores, contract, call.bytecode(), 5000 * TRX_PRECISION);

    let outcome = run(&stores, caller, contract);
    assert!(matches!(outcome, VmOutcome::Success { .. }), "{outcome:?}");
    assert_eq!(pushed_flag(&stores, contract), 1);

    let cast: std::collections::BTreeMap<Vec<u8>, i64> = votes_of(&stores, contract)
        .into_iter()
        .map(|v| (v.vote_address, v.vote_count))
        .collect();
    let mut expect = std::collections::BTreeMap::new();
    expect.insert(w0.to_vec(), 1000i64);
    expect.insert(w1.to_vec(), 1000i64);
    assert_eq!(cast, expect, "the prior vote is replaced by the new pair set");

    for w in [w0, w1] {
        assert_eq!(
            stores
                .witnesses
                .get(&Address::from_raw(w))
                .unwrap()
                .unwrap()
                .vote_count,
            0,
            "a witness's own vote_count only moves at maintenance"
        );
    }
}
