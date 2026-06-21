//! Tests for `activate_expired_proposals`.

use std::sync::Arc;

use tron_chainbase::{DynamicPropertiesStore, KvBackend, MemBackend, ProposalStore};
use tron_consensus::{activate_expired_proposals, parameter_id_to_key};
use tron_crypto::address::Address;
use tron_proto::{proposal::State as ProposalState, Proposal};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Active SR set whose addresses match `make_proposal`'s generated approvers
/// (`0x41 ‖ (i+0xa0)×20`), so every approver counts toward the threshold.
fn active_set(n: usize) -> Vec<Address> {
    (0..n)
        .map(|i| {
            let mut a = [0u8; 21];
            a[0] = 0x41;
            for b in &mut a[1..] {
                *b = (i as u8) + 0xa0;
            }
            Address::from_raw(a)
        })
        .collect()
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

    // Active witnesses = 27, threshold = floor(27 × 7/10) = 18
    proposals.put(
        1,
        &make_proposal(
            1,
            vec![(3, 50_000)], // TRANSACTION_FEE = 50_000
            1_700_000_000_000,
            20, // > 18 threshold
        ),
    ).unwrap();

    let now = 1_700_000_010_000; // past expiration
    let report = activate_expired_proposals(&proposals, &dp, now, &active_set(27)).unwrap();
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
    let report = activate_expired_proposals(&proposals, &dp, now, &active_set(27)).unwrap();
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
    let report = activate_expired_proposals(&proposals, &dp, now, &active_set(27)).unwrap();
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

    let report = activate_expired_proposals(&proposals, &dp, 1_000, &active_set(27)).unwrap();
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

    let report = activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active_set(27)).unwrap();
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

    let report = activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active_set(27)).unwrap();
    assert_eq!(report.approved, vec![5]); // still approved
    assert!(
        report.parameter_updates.is_empty(),
        "unknown parameter id should not produce an update"
    );
}

#[test]
fn approvals_from_inactive_witnesses_are_not_counted() {
    // java hasMostApprovals counts only approvals from witnesses CURRENTLY in
    // the active set. A proposal with 20 approvers none of whom are active
    // sees 0 approvals → disapproved (the old approvals.len() path would have
    // counted 20 ≥ threshold and approved it).
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    proposals
        .put(6, &make_proposal(6, vec![(3, 7)], 1_700_000_000_000, 20))
        .unwrap();
    // Active set in a disjoint 0xc0.. range — none match the 0xa0.. approvers.
    let active: Vec<Address> = (0..27)
        .map(|i| {
            let mut a = [0u8; 21];
            a[0] = 0x41;
            a[1..].fill(0xc0u8.wrapping_add(i as u8));
            Address::from_raw(a)
        })
        .collect();
    let report =
        activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active).unwrap();
    assert_eq!(report.disapproved, vec![6]);
    assert!(report.approved.is_empty());
}

#[test]
fn threshold_is_floor_of_seventy_percent() {
    // floor(27 * 7 / 10) == 18, NOT the ceiling 19: exactly 18 active
    // approvals must APPROVE (the old ⌈n·0.7⌉ rejected 18).
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    proposals
        .put(7, &make_proposal(7, vec![(3, 9)], 1_700_000_000_000, 18))
        .unwrap();
    let report =
        activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active_set(27)).unwrap();
    assert_eq!(report.approved, vec![7], "18 of 27 meets floor(0.7n)=18");
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

#[test]
fn total_energy_limit_target_divisor_reads_live_ratio() {
    // Fix #1: java's saveTotalEnergyLimit/saveTotalEnergyLimit2 divide by the
    // LIVE getAdaptiveResourceLimitTargetRatio(), not a hardcoded 14400. With
    // adaptive energy off (mainnet) the ratio is its init seed 14400; once a
    // ratio-changing proposal (or ALLOW_ADAPTIVE_ENERGY) has moved it, a later
    // TOTAL_ENERGY_LIMIT proposal must derive the target from the NEW ratio.
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    // Seed a non-default ratio (e.g. proposal 33 wrote 24*60*2 = 2880).
    dp.put_long(b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO", 2_880);

    // TOTAL_ENERGY_LIMIT(17) = 90_000_000_000 → target = value / 2880.
    proposals
        .put(
            10,
            &make_proposal(10, vec![(17, 90_000_000_000)], 1_700_000_000_000, 20),
        )
        .unwrap();

    let report =
        activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active_set(27)).unwrap();
    assert_eq!(report.approved, vec![10]);
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_LIMIT").unwrap(), 90_000_000_000);
    assert_eq!(
        dp.get_long(b"TOTAL_ENERGY_TARGET_LIMIT").unwrap(),
        90_000_000_000 / 2_880,
        "target must divide by the live ratio (2880), not 14400"
    );
}

#[test]
fn total_energy_limit_target_uses_default_ratio_when_unset() {
    // With no ratio key present, the chainbase getter returns its init-seed
    // default (14400), so the derived target matches java's pre-adaptive
    // behaviour exactly.
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    proposals
        .put(
            11,
            &make_proposal(11, vec![(17, 50_000_000_000)], 1_700_000_000_000, 20),
        )
        .unwrap();
    activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active_set(27)).unwrap();
    assert_eq!(
        dp.get_long(b"TOTAL_ENERGY_TARGET_LIMIT").unwrap(),
        50_000_000_000 / 14_400
    );
}

#[test]
fn allow_adaptive_energy_activation_sets_derived_keys() {
    // Fix #2: the 0 -> 1 transition of ALLOW_ADAPTIVE_ENERGY(21) re-seeds the
    // adaptive sub-state — ratio=2880, target=totalEnergyLimit/2880,
    // multiplier=50 (java ProposalService.process lines 128-141).
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    // A TOTAL_ENERGY_LIMIT must already be present for the target derivation.
    dp.put_long(b"TOTAL_ENERGY_LIMIT", 90_000_000_000);

    proposals
        .put(20, &make_proposal(20, vec![(21, 1)], 1_700_000_000_000, 20))
        .unwrap();

    activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active_set(27)).unwrap();

    assert_eq!(dp.get_long(b"ALLOW_ADAPTIVE_ENERGY").unwrap(), 1);
    assert_eq!(
        dp.get_long(b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO").unwrap(),
        2_880
    );
    assert_eq!(
        dp.get_long(b"TOTAL_ENERGY_TARGET_LIMIT").unwrap(),
        90_000_000_000 / 2_880
    );
    assert_eq!(
        dp.get_long(b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER").unwrap(),
        50
    );
}

#[test]
fn allow_adaptive_energy_activation_is_idempotent() {
    // java guards the whole block on `getAllowAdaptiveEnergy() == 0`, so a
    // second activation (flag already 1) must NOT re-write the derived keys —
    // we pre-set them to sentinel values and confirm they are untouched.
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    dp.put_long(b"TOTAL_ENERGY_LIMIT", 90_000_000_000);
    dp.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1); // already enabled
    // Sentinel values that the (skipped) derived writes would otherwise clobber.
    dp.put_long(b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO", 7_777);
    dp.put_long(b"TOTAL_ENERGY_TARGET_LIMIT", 8_888);
    dp.put_long(b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER", 9_999);

    proposals
        .put(21, &make_proposal(21, vec![(21, 1)], 1_700_000_000_000, 20))
        .unwrap();

    let report =
        activate_expired_proposals(&proposals, &dp, 1_700_000_010_000, &active_set(27)).unwrap();
    // Still recorded as an approved parameter update for the report.
    assert_eq!(report.approved, vec![21]);
    assert_eq!(report.parameter_updates, vec![(21, 21, 1)]);
    // Derived keys untouched (guard skipped them).
    assert_eq!(
        dp.get_long(b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO").unwrap(),
        7_777
    );
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_TARGET_LIMIT").unwrap(), 8_888);
    assert_eq!(
        dp.get_long(b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER").unwrap(),
        9_999
    );
}

#[test]
fn memo_fee_proposal_appends_history() {
    // Fix #3: MEMO_FEE(68) appends `,expiration:value` to MEMO_FEE_HISTORY,
    // keyed on the proposal's expiration time (java ProposalService.process
    // lines 294-300). The default history is the init seed "0:0".
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    let expiration = 1_700_000_000_000;
    proposals
        .put(30, &make_proposal(30, vec![(68, 1_000_000)], expiration, 20))
        .unwrap();

    activate_expired_proposals(&proposals, &dp, expiration + 10_000, &active_set(27)).unwrap();

    assert_eq!(dp.get_long(b"MEMO_FEE").unwrap(), 1_000_000);
    assert_eq!(
        dp.memo_fee_history(),
        format!("0:0,{}:{}", expiration, 1_000_000)
    );
}
