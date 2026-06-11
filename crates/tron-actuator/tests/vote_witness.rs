//! Parity tests for `vote_witness` against
//! `org.tron.core.actuator.VoteWitnessActuator`.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{
    execute_vote_witness, validate_vote_witness, ActuatorError, MAX_VOTE_NUMBER, TRX_PRECISION,
};
use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, VotesStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::Frozen;
use tron_proto::vote_witness_contract::Vote as ContractVote;
use tron_proto::{Account, AccountType, Vote as AccountVote, VoteWitnessContract, Witness};

/// **One backend per store** — java-tron writes each store to a distinct
/// directory so they have separate keyspaces. Sharing a single backend
/// here would let AccountStore and WitnessStore (both 21-byte-address-
/// keyed) overwrite each other, masking the very check we're testing.
fn fresh() -> (AccountStore, WitnessStore, VotesStore) {
    let acct: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let witn: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let vote: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    (
        AccountStore::new(acct),
        WitnessStore::new(witn),
        VotesStore::new(vote),
    )
}

fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const SR1: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const SR2: [u8; 21] = hex!("4171b0af54e0a1182a5e0947d6a64f3b22740ef318");

fn put_account(accounts: &AccountStore, address: [u8; 21], frozen_balance: i64) {
    accounts.put(
        &addr(address),
        &Account {
            address: address.to_vec(),
            balance: 0,
            r#type: AccountType::Normal as i32,
            frozen: if frozen_balance > 0 {
                vec![Frozen {
                    frozen_balance,
                    expire_time: 0,
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        },
    ).unwrap();
}

fn register_witness(witnesses: &WitnessStore, address: [u8; 21]) {
    witnesses.put(
        &addr(address),
        &Witness {
            address: address.to_vec(),
            vote_count: 0,
            pub_key: Vec::new(),
            url: String::new(),
            total_produced: 0,
            total_missed: 0,
            latest_block_num: 0,
            latest_slot_num: 0,
            is_jobs: false,
        },
    ).unwrap();
}

fn vote(addr: [u8; 21], count: i64) -> ContractVote {
    ContractVote {
        vote_address: addr.to_vec(),
        vote_count: count,
    }
}

fn vote_contract(owner: [u8; 21], votes: Vec<ContractVote>) -> VoteWitnessContract {
    VoteWitnessContract {
        owner_address: owner.to_vec(),
        votes,
        support: true,
    }
}

// --- Constants pinned ------------------------------------------------------

#[test]
fn constants_match_java_tron() {
    assert_eq!(MAX_VOTE_NUMBER, 30); // ChainConstant.MAX_VOTE_NUMBER
    assert_eq!(TRX_PRECISION, 1_000_000); // 1 TRX = 1e6 sun
}

// --- validate --------------------------------------------------------------

#[test]
fn validate_rejects_invalid_owner_address() {
    let (accounts, witnesses, _votes) = fresh();
    let contract = vote_contract([0u8; 21], vec![vote(SR1, 1)]); // 0x00 prefix
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::InvalidOwnerAddress)
    );
}

#[test]
fn validate_rejects_empty_vote_list() {
    let (accounts, witnesses, _votes) = fresh();
    let contract = vote_contract(ALICE, Vec::new());
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::EmptyVoteList)
    );
}

#[test]
fn validate_rejects_too_many_votes() {
    let (accounts, witnesses, _votes) = fresh();
    let votes: Vec<_> = (0..31).map(|_| vote(SR1, 1)).collect();
    let contract = vote_contract(ALICE, votes);
    assert!(matches!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::TooManyVotes { got: 31, max: 30 })
    ));
}

#[test]
fn validate_rejects_invalid_vote_address() {
    let (accounts, witnesses, _votes) = fresh();
    put_account(&accounts, ALICE, TRX_PRECISION);
    let bad = [0u8; 21]; // wrong prefix
    let contract = vote_contract(ALICE, vec![vote(bad, 1)]);
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::InvalidVoteAddress)
    );
}

#[test]
fn validate_rejects_non_positive_vote_count() {
    let (accounts, witnesses, _votes) = fresh();
    put_account(&accounts, ALICE, TRX_PRECISION);
    let contract = vote_contract(ALICE, vec![vote(SR1, 0)]);
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::NonPositiveVoteCount)
    );
    let contract = vote_contract(ALICE, vec![vote(SR1, -1)]);
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::NonPositiveVoteCount)
    );
}

#[test]
fn validate_rejects_candidate_with_no_account() {
    let (accounts, witnesses, _votes) = fresh();
    put_account(&accounts, ALICE, TRX_PRECISION);
    // SR1 registered as witness but has no account → must be rejected.
    register_witness(&witnesses, SR1);
    let contract = vote_contract(ALICE, vec![vote(SR1, 1)]);
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::CandidateAccountMissing)
    );
}

#[test]
fn validate_rejects_candidate_with_no_witness_record() {
    let (accounts, witnesses, _votes) = fresh();
    put_account(&accounts, ALICE, TRX_PRECISION);
    put_account(&accounts, SR1, 0); // SR1 has account but not registered
    let contract = vote_contract(ALICE, vec![vote(SR1, 1)]);
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::CandidateWitnessMissing)
    );
}

#[test]
fn validate_rejects_missing_owner_account() {
    let (accounts, witnesses, _votes) = fresh();
    // Alice never funded; SR1 set up properly.
    put_account(&accounts, SR1, 0);
    register_witness(&witnesses, SR1);
    let contract = vote_contract(ALICE, vec![vote(SR1, 1)]);
    assert_eq!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::OwnerAccountMissing)
    );
}

/// **Critical consensus rule**: a voter can only cast as many votes as
/// they have TRON power for. `tron_power = sum(frozen.balance)`, and
/// each vote count is multiplied by `TRX_PRECISION` (1e6) for comparison.
///
/// So a voter with 5 TRX frozen (5_000_000 sun) can cast at most 5 votes total.
#[test]
fn validate_rejects_votes_exceeding_tron_power() {
    let (accounts, witnesses, _votes) = fresh();
    put_account(&accounts, ALICE, 5 * TRX_PRECISION); // 5 TRX frozen
    put_account(&accounts, SR1, 0);
    register_witness(&witnesses, SR1);
    let contract = vote_contract(ALICE, vec![vote(SR1, 6)]); // 6 votes needs 6 TRX
    match validate_vote_witness(&accounts, &witnesses, &contract) {
        Err(ActuatorError::InsufficientTronPower {
            tron_power,
            required,
        }) => {
            assert_eq!(tron_power, 5_000_000);
            assert_eq!(required, 6_000_000);
        }
        other => panic!("expected InsufficientTronPower, got {other:?}"),
    }
}

#[test]
fn validate_accepts_votes_exactly_at_tron_power_limit() {
    let (accounts, witnesses, _votes) = fresh();
    put_account(&accounts, ALICE, 5 * TRX_PRECISION);
    put_account(&accounts, SR1, 0);
    register_witness(&witnesses, SR1);
    let contract = vote_contract(ALICE, vec![vote(SR1, 5)]); // exact
    assert!(validate_vote_witness(&accounts, &witnesses, &contract).is_ok());
}

#[test]
fn validate_sums_across_multiple_candidates() {
    let (accounts, witnesses, _votes) = fresh();
    put_account(&accounts, ALICE, 5 * TRX_PRECISION);
    put_account(&accounts, SR1, 0);
    put_account(&accounts, SR2, 0);
    register_witness(&witnesses, SR1);
    register_witness(&witnesses, SR2);
    // 3 + 2 = 5 TRX of votes total, exactly matching tron power.
    let contract = vote_contract(ALICE, vec![vote(SR1, 3), vote(SR2, 2)]);
    assert!(validate_vote_witness(&accounts, &witnesses, &contract).is_ok());

    // 3 + 3 = 6 → exceeds limit.
    let contract = vote_contract(ALICE, vec![vote(SR1, 3), vote(SR2, 3)]);
    assert!(matches!(
        validate_vote_witness(&accounts, &witnesses, &contract),
        Err(ActuatorError::InsufficientTronPower { .. })
    ));
}

// --- execute ----------------------------------------------------------------

#[test]
fn execute_records_votes_on_account_and_in_votes_store() {
    let (accounts, _witnesses, votes_store) = fresh();
    put_account(&accounts, ALICE, 10 * TRX_PRECISION);

    let contract = vote_contract(ALICE, vec![vote(SR1, 4), vote(SR2, 3)]);
    let delegation = DelegationStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    execute_vote_witness(&accounts, &votes_store, &delegation, &dp, None, &contract).unwrap();

    // Account got the new votes.
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.votes.len(), 2);
    assert_eq!(alice.votes[0].vote_address, SR1.to_vec());
    assert_eq!(alice.votes[0].vote_count, 4);
    assert_eq!(alice.votes[1].vote_count, 3);

    // VotesStore has new_votes; old_votes empty (first vote).
    let v = votes_store.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(v.address, ALICE.to_vec());
    assert!(v.old_votes.is_empty());
    assert_eq!(v.new_votes.len(), 2);
    assert_eq!(v.new_votes[1].vote_count, 3);
}

/// **Critical behavior**: re-voting moves the previous `new_votes` into
/// `old_votes`-effective state on the *next* maintenance cycle. java-tron
/// captures the pre-vote account state by reading `account.votes` into
/// `old_votes` when creating a VotesCapsule from scratch. So the FIRST
/// vote captures (account.votes=empty) as old_votes; a SECOND vote
/// (against an already-existing VotesCapsule) just replaces new_votes
/// without disturbing old_votes. Pinned here.
#[test]
fn execute_preserves_old_votes_when_revoting() {
    let (accounts, _witnesses, votes_store) = fresh();
    // Alice already has votes recorded on her account (e.g. from before).
    let mut alice = Account {
        address: ALICE.to_vec(),
        balance: 0,
        r#type: AccountType::Normal as i32,
        frozen: vec![Frozen {
            frozen_balance: 10 * TRX_PRECISION,
            expire_time: 0,
        }],
        votes: vec![AccountVote {
            vote_address: SR1.to_vec(),
            vote_count: 2,
        }],
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();

    // First call to execute: creates VotesCapsule with old_votes = account.votes (SR1=2).
    let c1 = vote_contract(ALICE, vec![vote(SR2, 5)]);
    let delegation = DelegationStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    execute_vote_witness(&accounts, &votes_store, &delegation, &dp, None, &c1).unwrap();

    let v = votes_store.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(v.old_votes.len(), 1);
    assert_eq!(v.old_votes[0].vote_address, SR1.to_vec());
    assert_eq!(v.new_votes.len(), 1);
    assert_eq!(v.new_votes[0].vote_address, SR2.to_vec());

    // Second call: VotesStore now exists, so old_votes is preserved
    // (still SR1=2) and new_votes is replaced with the second contract's
    // entries. Java-tron does NOT advance old_votes on re-vote; that
    // happens at maintenance.
    let c2 = vote_contract(ALICE, vec![vote(SR1, 3)]);
    execute_vote_witness(&accounts, &votes_store, &delegation, &dp, None, &c2).unwrap();

    let v = votes_store.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(v.old_votes.len(), 1, "old_votes preserved across re-vote");
    assert_eq!(v.old_votes[0].vote_address, SR1.to_vec());
    assert_eq!(v.old_votes[0].vote_count, 2);
    assert_eq!(v.new_votes[0].vote_count, 3);

    // And the account.votes reflects the latest cast.
    alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.votes.len(), 1);
    assert_eq!(alice.votes[0].vote_count, 3);
}

#[test]
fn execute_clears_old_votes_on_account_before_adding_new_ones() {
    let (accounts, _witnesses, votes_store) = fresh();
    // Account has 3 existing votes; new contract has 1. Result must be 1, not 4.
    let alice = Account {
        address: ALICE.to_vec(),
        balance: 0,
        r#type: AccountType::Normal as i32,
        frozen: vec![Frozen {
            frozen_balance: 10 * TRX_PRECISION,
            expire_time: 0,
        }],
        votes: vec![
            AccountVote {
                vote_address: SR1.to_vec(),
                vote_count: 1,
            },
            AccountVote {
                vote_address: SR2.to_vec(),
                vote_count: 1,
            },
            AccountVote {
                vote_address: SR1.to_vec(),
                vote_count: 1,
            },
        ],
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();

    let c = vote_contract(ALICE, vec![vote(SR1, 5)]);
    let delegation = DelegationStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    execute_vote_witness(&accounts, &votes_store, &delegation, &dp, None, &c).unwrap();

    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.votes.len(), 1);
    assert_eq!(alice.votes[0].vote_count, 5);
}
