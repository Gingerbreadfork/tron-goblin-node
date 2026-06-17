//! Vote/TRON-Power helpers shared by the actuator layer and the TVM
//! stake-opcode host (`tron-actuator` depends on this crate, so logic
//! both sides must execute byte-identically lives here).

use tron_chainbase::{StoreError, VotesStore};
use tron_crypto::address::Address;
use tron_proto::{Account, Vote, Votes};

/// `ChainConstant.TRX_PRECISION` — 1 TRX = 1,000,000 sun.
pub const TRX_PRECISION: i64 = 1_000_000;

/// `ResourceCode::TRON_POWER` — the v2 stake type that belongs to the
/// NEW resource model and is excluded from old-model TRON Power.
const TRON_POWER_TYPE: i32 = 2;

/// The account's TRON Power — a verbatim port of java-tron's
/// `AccountCapsule.getTronPower()`:
///
/// ```java
/// long tp = 0;
/// for (frozen : account.frozen)            tp += frozen.frozenBalance;   // legacy v1 bandwidth
/// tp += accountResource.frozenBalanceForEnergy.frozenBalance;            // legacy v1 energy
/// tp += account.delegatedFrozenBalanceForBandwidth;                      // v1 delegated out
/// tp += accountResource.delegatedFrozenBalanceForEnergy;
/// tp += Σ frozenV2[type != TRON_POWER].amount;                           // Stake 2.0 stakes
/// tp += account.delegatedFrozenV2BalanceForBandwidth;                    // v2 delegated out
/// tp += accountResource.delegatedFrozenV2BalanceForEnergy;
/// ```
///
/// Delegating resources OUT keeps the voting power with the delegator,
/// which is why the `delegated_*` (not `acquired_*`) fields count. The
/// `TRON_POWER`-typed frozenV2 entries belong to the NEW resource model
/// (`getAllTronPower`) and are deliberately excluded, exactly as in java
/// — mainnet runs with `ALLOW_NEW_RESOURCE_MODEL = 0`.
pub fn tron_power(account: &Account) -> i64 {
    let mut tp: i64 = account
        .frozen
        .iter()
        .map(|f| f.frozen_balance)
        .sum::<i64>();
    if let Some(res) = &account.account_resource {
        tp = tp.saturating_add(
            res.frozen_balance_for_energy
                .as_ref()
                .map(|f| f.frozen_balance)
                .unwrap_or(0),
        );
        tp = tp.saturating_add(res.delegated_frozen_balance_for_energy);
        tp = tp.saturating_add(res.delegated_frozen_v2_balance_for_energy);
    }
    tp = tp.saturating_add(account.delegated_frozen_balance_for_bandwidth);
    tp = tp.saturating_add(
        account
            .frozen_v2
            .iter()
            .filter(|f| f.r#type != TRON_POWER_TYPE)
            .map(|f| f.amount)
            .sum::<i64>(),
    );
    tp = tp.saturating_add(account.delegated_frozen_v2_balance_for_bandwidth);
    tp
}

/// java-tron's `AccountCapsule.getAllTronPower` (in sun) — the
/// NEW-resource-model power source. The `old_tron_power` field selects how
/// legacy power folds in:
///
/// * `-1` → not yet initialized: V1 + V2 TRON_POWER-typed frozen only;
/// * `0`  → legacy `getTronPower()` (every other frozen source) plus the
///          two TRON_POWER components;
/// * `>0` → stored old power plus the two TRON_POWER components.
///
/// Only reachable when `supportAllowNewResourceModel()` is active;
/// mainnet runs with `ALLOW_NEW_RESOURCE_MODEL = 0`, where the vote path
/// uses [`tron_power`] instead.
pub fn all_tron_power(account: &Account) -> i64 {
    let tron_power_v1 = account
        .tron_power
        .as_ref()
        .map(|f| f.frozen_balance)
        .unwrap_or(0);
    let tron_power_v2: i64 = account
        .frozen_v2
        .iter()
        .filter(|f| f.r#type == TRON_POWER_TYPE)
        .map(|f| f.amount)
        .sum();
    let folded = tron_power_v1.saturating_add(tron_power_v2);
    match account.old_tron_power {
        -1 => folded,
        0 => tron_power(account).saturating_add(folded),
        old => old.saturating_add(folded),
    }
}

/// Port of java-tron's `updateVote` (identical in
/// `UnfreezeBalanceV2Actuator` and the TVM `UnfreezeBalanceV2Processor`;
/// the mainnet path — `ALLOW_NEW_RESOURCE_MODEL = 0` — so the new-model
/// clear/skip branches are unreachable and the power source is
/// `getTronPower()`).
///
/// After an unstake the account may hold more votes than its remaining
/// TRON Power backs. java reduces every vote PROPORTIONALLY:
///
/// ```java
/// newVoteCount = (long) ((double) vote.getVoteCount()
///                        / totalVote * ownedTronPower / TRX_PRECISION);
/// ```
///
/// double-precision left-to-right, truncated toward zero — replicated
/// exactly (Rust f64 is the same IEEE-754 binary64). Votes that reduce
/// to zero are dropped. The trimmed list replaces both the account's
/// votes and the VotesStore record's `new_votes` (with `old_votes`
/// captured from the account's pre-trim list when no record exists
/// yet), so the next maintenance debits the difference from each
/// witness's `vote_count`.
///
/// The caller persists `account` afterwards; this only writes the
/// VotesStore record.
pub fn update_vote_after_unstake(
    votes_store: &VotesStore,
    owner: &Address,
    account: &mut Account,
) -> Result<(), StoreError> {
    if account.votes.is_empty() {
        return Ok(());
    }
    let total_vote: i64 = account.votes.iter().map(|v| v.vote_count).sum();
    if total_vote == 0 {
        return Ok(());
    }
    let owned_tron_power = tron_power(account);
    // java compares in sun: `ownedTronPower >= totalVote * TRX_PRECISION`
    // (i128 here only to be overflow-safe; values can't reach it).
    if (owned_tron_power as i128) >= (total_vote as i128) * (TRX_PRECISION as i128) {
        return Ok(());
    }

    let mut votes_record = match votes_store.get(owner)? {
        Some(v) => v,
        None => Votes {
            address: owner.as_bytes().to_vec(),
            old_votes: account.votes.clone(),
            new_votes: Vec::new(),
        },
    };

    let mut trimmed: Vec<Vote> = Vec::with_capacity(account.votes.len());
    for vote in &account.votes {
        let new_count = ((vote.vote_count as f64) / (total_vote as f64)
            * (owned_tron_power as f64)
            / (TRX_PRECISION as f64)) as i64;
        if new_count > 0 {
            trimmed.push(Vote {
                vote_address: vote.vote_address.clone(),
                vote_count: new_count,
            });
        }
    }
    votes_record.new_votes = trimmed.clone();
    votes_store.put(owner, &votes_record)?;
    account.votes = trimmed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tron_chainbase::{KvBackend, MemBackend};
    use tron_proto::account::{FreezeV2, Frozen};

    fn addr(n: u8) -> Address {
        let mut raw = [0u8; 21];
        raw[0] = 0x41;
        raw[20] = n;
        Address::from_raw(raw)
    }

    fn vote(w: u8, count: i64) -> Vote {
        Vote {
            vote_address: addr(w).as_bytes().to_vec(),
            vote_count: count,
        }
    }

    #[test]
    fn tron_power_sums_every_java_component() {
        let account = Account {
            frozen: vec![Frozen {
                frozen_balance: 1_000_000,
                expire_time: 0,
            }],
            delegated_frozen_balance_for_bandwidth: 2_000_000,
            delegated_frozen_v2_balance_for_bandwidth: 3_000_000,
            frozen_v2: vec![
                FreezeV2 {
                    r#type: 0,
                    amount: 4_000_000,
                },
                FreezeV2 {
                    r#type: 1,
                    amount: 5_000_000,
                },
                // TRON_POWER-typed stake: excluded (new-model only).
                FreezeV2 {
                    r#type: 2,
                    amount: 100_000_000,
                },
            ],
            account_resource: Some(tron_proto::account::AccountResource {
                frozen_balance_for_energy: Some(Frozen {
                    frozen_balance: 6_000_000,
                    expire_time: 0,
                }),
                delegated_frozen_balance_for_energy: 7_000_000,
                delegated_frozen_v2_balance_for_energy: 8_000_000,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(tron_power(&account), 36_000_000);
    }

    #[test]
    fn unstake_trims_votes_proportionally_with_java_float_math() {
        let votes_store = VotesStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
        let owner = addr(99);
        // 100 TRX staked, but votes total 300 → trim each to 1/3 (floor).
        let mut account = Account {
            address: owner.as_bytes().to_vec(),
            frozen_v2: vec![FreezeV2 {
                r#type: 1,
                amount: 100 * TRX_PRECISION,
            }],
            votes: vec![vote(1, 200), vote(2, 99), vote(3, 1)],
            ..Default::default()
        };
        update_vote_after_unstake(&votes_store, &owner, &mut account).unwrap();
        // java: (double) v / 300 * 100_000_000 / 1_000_000, truncated:
        //   200 → 66.66.. → 66 ; 99 → 33.0 → 33 ; 1 → 0.33 → 0 (dropped)
        assert_eq!(
            account.votes,
            vec![vote(1, 66), vote(2, 33)],
            "proportional trim must match java's double math"
        );
        let rec = votes_store.get(&owner).unwrap().unwrap();
        assert_eq!(rec.old_votes, vec![vote(1, 200), vote(2, 99), vote(3, 1)]);
        assert_eq!(rec.new_votes, account.votes);
    }

    #[test]
    fn unstake_with_sufficient_power_leaves_votes_alone() {
        let votes_store = VotesStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
        let owner = addr(98);
        let mut account = Account {
            address: owner.as_bytes().to_vec(),
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 500 * TRX_PRECISION,
            }],
            votes: vec![vote(1, 500)],
            ..Default::default()
        };
        update_vote_after_unstake(&votes_store, &owner, &mut account).unwrap();
        assert_eq!(account.votes, vec![vote(1, 500)]);
        assert!(votes_store.get(&owner).unwrap().is_none(), "no record written");
    }
}
