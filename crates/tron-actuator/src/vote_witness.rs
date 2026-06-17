//! `VoteWitnessContract` actuator — cast votes for SR candidates.
//!
//! Source: `org.tron.core.actuator.VoteWitnessActuator`.
//!
//! Deferred behaviors (documented inline; tracked for follow-up):
//!
//! 1. **New resource model (`supportAllowNewResourceModel`)** — uses
//!    `getAllTronPower` (adds `oldTronPower` + TRON_POWER-typed v2
//!    stakes). Mainnet runs with `ALLOW_NEW_RESOURCE_MODEL = 0`, so the
//!    live path is `getTronPower()` — fully ported in
//!    [`tron_power_old_model`].
//! 2. **`oldTronPowerIsNotInitialized` / `initializeOldTronPower`** —
//!    one-shot migration step in java-tron, only reachable under the
//!    new resource model. Trivial to add once that path is in.

use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, VotesStore, WitnessStore,
};
use tron_crypto::address::{Address, ADDRESS_LENGTH, ADDRESS_PREFIX_MAINNET};
use tron_proto::{Vote as AccountVote, Votes, VoteWitnessContract};

use crate::ActuatorError;

/// `ChainConstant.MAX_VOTE_NUMBER` — maximum SR candidates a single
/// `VoteWitnessContract` may name.
pub const MAX_VOTE_NUMBER: i32 = 30;

/// `ChainConstant.TRX_PRECISION` — 1 TRX = 1,000,000 sun. The contract
/// expresses `vote_count` in TRX units; multiply by this to compare
/// against an account's sun-denominated `tron_power`.
pub const TRX_PRECISION: i64 = 1_000_000;

/// Validate a [`VoteWitnessContract`] against current state.
///
/// Rules (in the order java-tron applies them):
///
/// 1. Owner address is a valid 21-byte mainnet address.
/// 2. `votes.len()` is in `1..=30`.
/// 3. For every entry:
///    - vote_address is a valid 21-byte mainnet address,
///    - vote_count > 0,
///    - an `Account` exists at vote_address,
///    - a `Witness` exists at vote_address.
/// 4. The owner's `Account` exists.
/// 5. `sum(vote_count) * TRX_PRECISION ≤ owner.tron_power`.
///
/// Does not mutate any store.
pub fn validate_vote_witness(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    contract: &VoteWitnessContract,
) -> Result<(), ActuatorError> {
    let owner =
        decode_address(&contract.owner_address).ok_or(ActuatorError::InvalidOwnerAddress)?;

    let n = contract.votes.len();
    if n == 0 {
        return Err(ActuatorError::EmptyVoteList);
    }
    if n > MAX_VOTE_NUMBER as usize {
        return Err(ActuatorError::TooManyVotes {
            got: n,
            max: MAX_VOTE_NUMBER as usize,
        });
    }

    let mut sum: i64 = 0;
    for v in &contract.votes {
        let candidate = decode_address(&v.vote_address).ok_or(ActuatorError::InvalidVoteAddress)?;
        if v.vote_count <= 0 {
            return Err(ActuatorError::NonPositiveVoteCount);
        }
        // Account must exist at the candidate address. (Witness account
        // creation isn't free — every SR has a regular Account too.)
        if accounts.get(&candidate)?.is_none() {
            return Err(ActuatorError::CandidateAccountMissing);
        }
        if !witnesses.contains(&candidate)? {
            return Err(ActuatorError::CandidateWitnessMissing);
        }
        sum = sum
            .checked_add(v.vote_count)
            .ok_or(ActuatorError::Overflow)?;
    }

    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let required = sum
        .checked_mul(TRX_PRECISION)
        .ok_or(ActuatorError::Overflow)?;
    let tron_power = old_tron_power(&owner_account);
    if required > tron_power {
        return Err(ActuatorError::InsufficientTronPower {
            tron_power,
            required,
        });
    }

    Ok(())
}

/// Apply the vote. Caller must have passed [`validate_vote_witness`] first.
///
/// Effects:
/// * Pending voter rewards are settled FIRST (java-tron's
///   `mortgageService.withdrawReward(ownerAddress)` at the top of
///   `VoteWitnessActuator.execute`). Reward windows are computed against
///   the votes that were live while the cycles ran, so the settle must
///   happen before the vote list changes — and it also advances the
///   voter's `begin/end_cycle` markers + `account_vote` snapshot in
///   `DelegationStore`, state java mutates on every re-vote.
/// * `owner_account.votes` is replaced with the new vote list.
/// * `VotesStore[owner]` records both the previous (`old_votes`) and new
///   (`new_votes`) vote lists. If the owner had no previous entry, the
///   account's current votes are taken as `old_votes` (matching java-tron's
///   "create with current account votes" branch).
pub fn execute_vote_witness(
    accounts: &AccountStore,
    votes_store: &VotesStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    reward_vi: Option<&tron_chainbase::RewardViStore>,
    contract: &VoteWitnessContract,
) -> Result<(), ActuatorError> {
    let owner =
        decode_address(&contract.owner_address).ok_or(ActuatorError::InvalidOwnerAddress)?;

    tron_tvm::reward::withdraw_reward_actuator(&owner, accounts, delegation, dyn_props, reward_vi)?;

    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let mut votes_capsule = match votes_store.get(&owner)? {
        Some(v) => v,
        None => Votes {
            address: owner.as_bytes().to_vec(),
            old_votes: owner_account.votes.clone(),
            new_votes: Vec::new(),
        },
    };

    // Java behavior: clear both the account's votes and the votes-store
    // new_votes, then re-add each entry.
    owner_account.votes.clear();
    votes_capsule.new_votes.clear();

    for v in &contract.votes {
        let entry = AccountVote {
            vote_address: v.vote_address.clone(),
            vote_count: v.vote_count,
        };
        owner_account.votes.push(entry.clone());
        votes_capsule.new_votes.push(entry);
    }

    accounts.put(&owner, &owner_account)?;
    votes_store.put(&owner, &votes_capsule)?;

    Ok(())
}

/// The account's TRON Power — java-tron's `AccountCapsule.getTronPower()`
/// (the live path on mainnet, where `ALLOW_NEW_RESOURCE_MODEL = 0`).
/// Implemented in [`tron_tvm::votes::tron_power`], shared with the TVM
/// stake opcodes.
///
/// Summing only the legacy `frozen` list (the previous implementation)
/// under-counted every Stake-2.0 staker to ~zero, which made our
/// validation REJECT virtually every modern `VoteWitnessContract` that
/// mainnet accepted — votes silently never landed, and witness
/// `vote_count`s drifted below java-tron's at every maintenance.
fn old_tron_power(account: &tron_proto::Account) -> i64 {
    tron_tvm::votes::tron_power(account)
}

fn decode_address(bytes: &[u8]) -> Option<Address> {
    if bytes.len() != ADDRESS_LENGTH || bytes[0] != ADDRESS_PREFIX_MAINNET {
        return None;
    }
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf.copy_from_slice(bytes);
    Some(Address::from_raw(buf))
}

/// Convenience helper: also exposed publicly so block-executor code can
/// compute power without going through `validate_vote_witness`.
pub fn tron_power_old_model(account: &tron_proto::Account) -> i64 {
    old_tron_power(account)
}
