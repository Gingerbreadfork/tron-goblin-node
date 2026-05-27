//! Error-path tests for the three proposal actuators:
//!   * `ProposalCreate`  — only witnesses can propose
//!   * `ProposalApprove` — only witnesses can approve; add/remove dual
//!   * `ProposalDelete`  — only the proposer can cancel
//!
//! Java reference: `ProposalCreateActuatorTest` (9), `ProposalApproveActuatorTest`
//! (10), `ProposalDeleteActuatorTest` (8). Our `full_layer.rs` had a
//! single happy-path round-trip; these tests cover witness gating,
//! double-approve, post-expiration rejection, and proposer-only delete.

use std::collections::BTreeMap;
use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{proposal, ActuatorError};
use tron_chainbase::{
    dynamic_properties_keys, AccountStore, DynamicPropertiesStore, KvBackend, MemBackend,
    ProposalStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    proposal::State as ProposalState, Account, AccountType, Proposal, ProposalApproveContract,
    ProposalCreateContract, ProposalDeleteContract, Witness,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const CAROL: [u8; 21] = hex!("41cccccccccccccccccccccccccccccccccccccccc");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

struct Ctx {
    accounts: AccountStore,
    witnesses: WitnessStore,
    proposals: ProposalStore,
    dp: DynamicPropertiesStore,
}

fn ctx() -> Ctx {
    Ctx {
        accounts: AccountStore::new(mem()),
        witnesses: WitnessStore::new(mem()),
        proposals: ProposalStore::new(mem()),
        dp: DynamicPropertiesStore::new(mem()),
    }
}

fn put_account(ctx: &Ctx, who: [u8; 21]) {
    ctx.accounts.put(
        &addr(who),
        &Account {
            address: who.to_vec(),
            balance: 100_000_000,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    );
}

fn put_witness(ctx: &Ctx, who: [u8; 21]) {
    put_account(ctx, who);
    ctx.witnesses.put(
        &addr(who),
        &Witness {
            address: who.to_vec(),
            url: "https://example.test".into(),
            ..Default::default()
        },
    );
}

fn one_param() -> BTreeMap<i64, i64> {
    let mut p = BTreeMap::new();
    p.insert(0, 100); // ChainParameter id 0 = MAINTENANCE_TIME_INTERVAL
    p
}

// ============================================================
// ProposalCreate
// ============================================================

#[test]
fn create_rejects_missing_owner_account() {
    let ctx = ctx();
    let c = ProposalCreateContract {
        owner_address: ALICE.to_vec(),
        parameters: one_param(),
    };
    let err = proposal::validate_proposal_create(&ctx.accounts, &ctx.witnesses, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing), "got: {err:?}");
}

#[test]
fn create_rejects_non_witness_proposer() {
    let ctx = ctx();
    put_account(&ctx, ALICE); // account exists, but Alice is not a witness
    let c = ProposalCreateContract {
        owner_address: ALICE.to_vec(),
        parameters: one_param(),
    };
    let err = proposal::validate_proposal_create(&ctx.accounts, &ctx.witnesses, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::WitnessMissing), "got: {err:?}");
}

#[test]
fn create_rejects_empty_parameters_map() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    let c = ProposalCreateContract {
        owner_address: ALICE.to_vec(),
        parameters: BTreeMap::new(),
    };
    let err = proposal::validate_proposal_create(&ctx.accounts, &ctx.witnesses, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::EmptyProposalParameters),
        "got: {err:?}"
    );
}

#[test]
fn create_assigns_sequential_ids_and_records_proposer() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    put_witness(&ctx, BOB);
    let c1 = ProposalCreateContract {
        owner_address: ALICE.to_vec(),
        parameters: one_param(),
    };
    let c2 = ProposalCreateContract {
        owner_address: BOB.to_vec(),
        parameters: one_param(),
    };
    proposal::validate_proposal_create(&ctx.accounts, &ctx.witnesses, &c1).unwrap();
    proposal::execute_proposal_create(&ctx.proposals, &ctx.dp, &c1).unwrap();
    proposal::validate_proposal_create(&ctx.accounts, &ctx.witnesses, &c2).unwrap();
    proposal::execute_proposal_create(&ctx.proposals, &ctx.dp, &c2).unwrap();
    let p1 = ctx.proposals.get(1).unwrap().unwrap();
    let p2 = ctx.proposals.get(2).unwrap().unwrap();
    assert_eq!(p1.proposer_address, ALICE);
    assert_eq!(p2.proposer_address, BOB);
    assert_eq!(p1.state, ProposalState::Pending as i32);
    assert_eq!(
        ctx.dp
            .get_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM)
            .unwrap_or(0),
        2
    );
}

// ============================================================
// ProposalApprove
// ============================================================

fn seed_proposal(ctx: &Ctx, id: i64, proposer: [u8; 21], expire_at: i64) {
    ctx.proposals.put(
        id,
        &Proposal {
            proposal_id: id,
            proposer_address: proposer.to_vec(),
            parameters: one_param(),
            expiration_time: expire_at,
            create_time: 0,
            approvals: Vec::new(),
            state: ProposalState::Pending as i32,
        },
    );
    ctx.dp.put_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM, id);
}

#[test]
fn approve_rejects_missing_owner_account() {
    let ctx = ctx();
    seed_proposal(&ctx, 1, ALICE, 1_000_000);
    let c = ProposalApproveContract {
        owner_address: BOB.to_vec(),
        proposal_id: 1,
        is_add_approval: true,
    };
    let err = proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn approve_rejects_non_witness_voter() {
    let ctx = ctx();
    put_account(&ctx, BOB); // account exists, not a witness
    seed_proposal(&ctx, 1, ALICE, 1_000_000);
    let c = ProposalApproveContract {
        owner_address: BOB.to_vec(),
        proposal_id: 1,
        is_add_approval: true,
    };
    let err = proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, ActuatorError::WitnessMissing));
}

#[test]
fn approve_rejects_unknown_proposal_id() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    let c = ProposalApproveContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 99,
        is_add_approval: true,
    };
    let err = proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalMissing));
}

#[test]
fn approve_rejects_expired_proposal() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    ctx.dp.save_latest_block_header_timestamp(2_000_000);
    seed_proposal(&ctx, 1, ALICE, 1_000_000); // expired
    let c = ProposalApproveContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
        is_add_approval: true,
    };
    let err = proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalExpired));
}

#[test]
fn approve_rejects_canceled_proposal() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    let mut p = Proposal {
        proposal_id: 1,
        proposer_address: ALICE.to_vec(),
        parameters: one_param(),
        expiration_time: 5_000_000,
        create_time: 0,
        approvals: Vec::new(),
        state: ProposalState::Canceled as i32,
    };
    p.state = ProposalState::Canceled as i32;
    ctx.proposals.put(1, &p);
    ctx.dp.put_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM, 1);
    let c = ProposalApproveContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
        is_add_approval: true,
    };
    let err = proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalCanceled));
}

#[test]
fn approve_rejects_double_add_approval() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    seed_proposal(&ctx, 1, ALICE, 5_000_000);
    let c = ProposalApproveContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
        is_add_approval: true,
    };
    // First add succeeds.
    proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap();
    proposal::execute_proposal_approve(&ctx.proposals, &c).unwrap();
    // Second add to the same proposal by the same voter is duplicate.
    let err = proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalDuplicateApproval));
}

#[test]
fn approve_rejects_remove_when_not_previously_approved() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    seed_proposal(&ctx, 1, ALICE, 5_000_000);
    let c = ProposalApproveContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
        is_add_approval: false, // remove
    };
    // Alice never approved, so removing is rejected.
    let err = proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalDuplicateApproval));
}

#[test]
fn approve_add_then_remove_round_trips_to_empty_approvals() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    seed_proposal(&ctx, 1, ALICE, 5_000_000);
    let c_add = ProposalApproveContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
        is_add_approval: true,
    };
    let c_remove = ProposalApproveContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
        is_add_approval: false,
    };
    proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c_add,
    )
    .unwrap();
    proposal::execute_proposal_approve(&ctx.proposals, &c_add).unwrap();
    proposal::validate_proposal_approve(
        &ctx.accounts,
        &ctx.witnesses,
        &ctx.proposals,
        &ctx.dp,
        &c_remove,
    )
    .unwrap();
    proposal::execute_proposal_approve(&ctx.proposals, &c_remove).unwrap();
    let p = ctx.proposals.get(1).unwrap().unwrap();
    assert!(p.approvals.is_empty());
}

#[test]
fn approve_multiple_witnesses_accumulate_in_order() {
    let ctx = ctx();
    put_witness(&ctx, ALICE);
    put_witness(&ctx, BOB);
    put_witness(&ctx, CAROL);
    seed_proposal(&ctx, 1, ALICE, 5_000_000);
    for who in [ALICE, BOB, CAROL] {
        let c = ProposalApproveContract {
            owner_address: who.to_vec(),
            proposal_id: 1,
            is_add_approval: true,
        };
        proposal::validate_proposal_approve(
            &ctx.accounts,
            &ctx.witnesses,
            &ctx.proposals,
            &ctx.dp,
            &c,
        )
        .unwrap();
        proposal::execute_proposal_approve(&ctx.proposals, &c).unwrap();
    }
    let p = ctx.proposals.get(1).unwrap().unwrap();
    assert_eq!(p.approvals.len(), 3);
    assert_eq!(p.approvals[0], ALICE);
    assert_eq!(p.approvals[1], BOB);
    assert_eq!(p.approvals[2], CAROL);
}

// ============================================================
// ProposalDelete
// ============================================================

#[test]
fn delete_rejects_missing_owner_account() {
    let ctx = ctx();
    seed_proposal(&ctx, 1, ALICE, 5_000_000);
    let c = ProposalDeleteContract {
        owner_address: BOB.to_vec(),
        proposal_id: 1,
    };
    let err =
        proposal::validate_proposal_delete(&ctx.accounts, &ctx.proposals, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn delete_rejects_unknown_proposal_id() {
    let ctx = ctx();
    put_account(&ctx, ALICE);
    let c = ProposalDeleteContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 99,
    };
    let err =
        proposal::validate_proposal_delete(&ctx.accounts, &ctx.proposals, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalMissing));
}

#[test]
fn delete_rejects_expired_proposal() {
    let ctx = ctx();
    put_account(&ctx, ALICE);
    ctx.dp.save_latest_block_header_timestamp(2_000_000);
    seed_proposal(&ctx, 1, ALICE, 1_000_000); // expired
    let c = ProposalDeleteContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
    };
    let err =
        proposal::validate_proposal_delete(&ctx.accounts, &ctx.proposals, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalExpired));
}

#[test]
fn delete_rejects_already_canceled_proposal() {
    let ctx = ctx();
    put_account(&ctx, ALICE);
    let p = Proposal {
        proposal_id: 1,
        proposer_address: ALICE.to_vec(),
        parameters: one_param(),
        expiration_time: 5_000_000,
        create_time: 0,
        approvals: Vec::new(),
        state: ProposalState::Canceled as i32,
    };
    ctx.proposals.put(1, &p);
    ctx.dp.put_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM, 1);
    let c = ProposalDeleteContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
    };
    let err =
        proposal::validate_proposal_delete(&ctx.accounts, &ctx.proposals, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ProposalCanceled));
}

#[test]
fn delete_rejects_non_proposer_owner() {
    let ctx = ctx();
    put_account(&ctx, ALICE);
    put_account(&ctx, BOB);
    seed_proposal(&ctx, 1, ALICE, 5_000_000); // proposed by Alice
    let c = ProposalDeleteContract {
        owner_address: BOB.to_vec(), // Bob tries to delete
        proposal_id: 1,
    };
    let err =
        proposal::validate_proposal_delete(&ctx.accounts, &ctx.proposals, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NotProposalOwner));
}

#[test]
fn delete_marks_proposal_canceled() {
    let ctx = ctx();
    put_account(&ctx, ALICE);
    seed_proposal(&ctx, 1, ALICE, 5_000_000);
    let c = ProposalDeleteContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
    };
    proposal::validate_proposal_delete(&ctx.accounts, &ctx.proposals, &ctx.dp, &c).unwrap();
    proposal::execute_proposal_delete(&ctx.proposals, &c).unwrap();
    let p = ctx.proposals.get(1).unwrap().unwrap();
    assert_eq!(p.state, ProposalState::Canceled as i32);
}
