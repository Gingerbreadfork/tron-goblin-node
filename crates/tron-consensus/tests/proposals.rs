//! Tests for `activate_expired_proposals`.

use std::sync::Arc;

use tron_chainbase::{DynamicPropertiesStore, KvBackend, MemBackend, ProposalStore};
use tron_consensus::{activate_expired_proposals, parameter_id_to_key};
use tron_proto::{proposal::State as ProposalState, Proposal};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn make_proposal(id: i64, params: Vec<(i64, i64)>, expiration: i64, approvals: usize) -> Proposal {
    let mut p = Proposal {
        proposal_id: id,
        proposer_address: vec![0x41; 21],
        parameters: params.into_iter().collect(),
        expiration_time: expiration,
        create_time: 0,
        approvals: vec![],
        state: ProposalState::Pending as i32,
    };
    for i in 0..approvals {
        // Make each "approval" a distinct 21-byte address.
        let mut addr = vec![0x41u8];
        addr.extend_from_slice(&[(i as u8) + 0xa0; 20]);
        p.approvals.push(addr);
    }
    p
}

#[test]
fn proposal_approved_when_meets_threshold_and_expired() {
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    // Active witnesses = 27, threshold = ⌈27 × 0.7⌉ = 19
    proposals.put(
        1,
        &make_proposal(
            1,
            vec![(3, 50_000)], // TRANSACTION_FEE = 50_000
            1_700_000_000_000,
            20, // > 19 threshold
        ),
    ).unwrap();

    let now = 1_700_000_010_000; // past expiration
    let report = activate_expired_proposals(&proposals, &dp, now, 27).unwrap();
    assert_eq!(report.approved, vec![1]);
    assert!(report.disapproved.is_empty());
    assert_eq!(report.parameter_updates, vec![(1, 3, 50_000)]);

    // Proposal state in store should now be Approved.
    let after = proposals.get(1).unwrap().unwrap();
    assert_eq!(after.state, ProposalState::Approved as i32);

    // The parameter value should be live in DynamicPropertiesStore.
    let val = dp.get_long(b"TRANSACTION_FEE").unwrap();
    assert_eq!(val, 50_000);
}

#[test]
fn proposal_disapproved_when_under_threshold_and_expired() {
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    proposals.put(
        2,
        &make_proposal(2, vec![(3, 99_000)], 1_700_000_000_000, 5),
    ).unwrap();

    let now = 1_700_000_010_000;
    let report = activate_expired_proposals(&proposals, &dp, now, 27).unwrap();
    assert!(report.approved.is_empty());
    assert_eq!(report.disapproved, vec![2]);
    assert!(report.parameter_updates.is_empty());

    // Parameter must NOT have been written.
    assert!(dp.get_long(b"TRANSACTION_FEE").is_none());

    let after = proposals.get(2).unwrap().unwrap();
    assert_eq!(after.state, ProposalState::Disapproved as i32);
}

#[test]
fn proposal_not_yet_expired_stays_pending() {
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    proposals.put(
        3,
        &make_proposal(3, vec![(3, 1)], 1_700_000_100_000, 25), // expires in future
    ).unwrap();

    let now = 1_700_000_000_000; // before expiration
    let report = activate_expired_proposals(&proposals, &dp, now, 27).unwrap();
    assert!(report.approved.is_empty());
    assert!(report.disapproved.is_empty());

    let after = proposals.get(3).unwrap().unwrap();
    assert_eq!(after.state, ProposalState::Pending as i32);
}

#[test]
fn already_terminal_proposals_are_left_alone() {
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    let mut already_approved = make_proposal(4, vec![(3, 5)], 1, 20);
    already_approved.state = ProposalState::Approved as i32;
    proposals.put(4, &already_approved).unwrap();

    let report = activate_expired_proposals(&proposals, &dp, 1_000, 27).unwrap();
    assert!(report.approved.is_empty());
    assert!(report.disapproved.is_empty());
    // Parameter must NOT have been re-applied.
    assert!(dp.get_long(b"TRANSACTION_FEE").is_none());
}

#[test]
fn multiple_proposals_processed_in_id_order() {
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    // Two pending proposals — id=2 sets TRANSACTION_FEE=20, id=1 sets it to 10.
    // Both expire, both approved. id=1 should be processed first (ascending order),
    // so the final value should be 20 (id=2 overwrites).
    proposals.put(
        1,
        &make_proposal(1, vec![(3, 10)], 1_700_000_000_000, 20),
    ).unwrap();
    proposals.put(
        2,
        &make_proposal(2, vec![(3, 20)], 1_700_000_000_000, 20),
    ).unwrap();

    let report = activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, 27).unwrap();
    assert_eq!(report.approved, vec![1, 2]);
    assert_eq!(dp.get_long(b"TRANSACTION_FEE").unwrap(), 20);
}

#[test]
fn unknown_parameter_id_is_silently_dropped() {
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    proposals.put(
        5,
        &make_proposal(
            5,
            vec![(999_999, 42)], // not in parameter_id_to_key table
            1_700_000_000_000,
            20,
        ),
    ).unwrap();

    let report = activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, 27).unwrap();
    assert_eq!(report.approved, vec![5]); // still approved
    assert!(
        report.parameter_updates.is_empty(),
        "unknown parameter id should not produce an update"
    );
}

#[test]
fn parameter_id_to_key_pinned_values() {
    // Spot-check critical ids against java's `ProposalUtil.ProposalType`
    // enum — including its gaps and naming quirks.
    assert_eq!(parameter_id_to_key(0), Some(&b"MAINTENANCE_TIME_INTERVAL"[..]));
    assert_eq!(parameter_id_to_key(11), Some(&b"ENERGY_FEE"[..]));
    // Leading-space java key typo, canonical forever.
    assert_eq!(parameter_id_to_key(15), Some(&b" ALLOW_SAME_TOKEN_NAME"[..]));
    // No ALLOW_ prefix on java's disk key.
    assert_eq!(parameter_id_to_key(30), Some(&b"CHANGE_DELEGATION"[..]));
    assert_eq!(parameter_id_to_key(59), Some(&b"ALLOW_TVM_VOTE"[..]));
    assert_eq!(parameter_id_to_key(72), Some(&b"ALLOW_DYNAMIC_ENERGY"[..]));
    assert_eq!(
        parameter_id_to_key(94),
        Some(&b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION"[..])
    );
    // Java enum gaps must NOT map to anything.
    assert_eq!(parameter_id_to_key(27), None);
    assert_eq!(parameter_id_to_key(28), None);
    assert_eq!(parameter_id_to_key(34), None);
    assert_eq!(parameter_id_to_key(50), None);
    assert_eq!(parameter_id_to_key(9999), None);
}
