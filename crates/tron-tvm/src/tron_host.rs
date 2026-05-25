//! TronDatabaseExt — real chainbase reads for the TRON Host extensions.
//!
//! ## How the bridge works (resolved 2026-05-25)
//!
//! 1. `TronHostExt` + `TronDatabaseExt` traits live in our forked
//!    `revm-context-interface` (`src/tron_ext.rs`). Both have default
//!    no-op method bodies so Ethereum-only setups keep compiling.
//! 2. Our forked `revm-context::Host for Context<...>` adds the
//!    `DB: Database + TronDatabaseExt` bound and overrides the TRON
//!    methods to delegate to `self.journaled_state.db().tron_*()`.
//! 3. [`TronDatabase`] below provides the real
//!    [`TronDatabaseExt`] impl that reads `asset_v2`, `code_hash`,
//!    and `frozen` entries from `AccountStore`.
//! 4. Foreign DB types in upstream revm (`CacheDB`, `BenchmarkDB`,
//!    `InMemoryDB`) reach the bound via the [`TronCompat<DB>`] wrapper
//!    exported from `revm-context-interface` — tests pass
//!    `TronCompat(some_db)` to `with_db()` and get a no-op TRON impl
//!    automatically.
//!
//! End-to-end proof: see `crates/tron-tvm/tests/tokenbalance_real_data.rs`
//! — TOKENBALANCE opcode now returns the real `asset_v2` balance from
//! AccountStore (not the default zero).

use revm::context_interface::TronDatabaseExt;
use revm::primitives::Address;
use tron_chainbase::DelegatedResourceStore;
use tron_crypto::address::Address as TronAddress;

use crate::database::{evm_to_tron_address, TronDatabase};

impl TronDatabaseExt for TronDatabase {
    fn tron_token_balance(&self, address: Address, token_id: i64) -> i64 {
        let tron_addr = evm_to_tron_address(&address);
        let Ok(Some(account)) = self.accounts.get(&tron_addr) else {
            return 0;
        };
        // `Account.asset_v2` is keyed by decimal-string token_id (matches
        // java-tron's `Map<String, Long>` representation).
        account
            .asset_v2
            .get(&token_id.to_string())
            .copied()
            .unwrap_or(0)
    }

    fn tron_is_contract(&self, address: Address) -> bool {
        let tron_addr = evm_to_tron_address(&address);
        match self.accounts.get(&tron_addr) {
            Ok(Some(account)) => !account.code_hash.is_empty(),
            _ => false,
        }
    }

    fn tron_freeze_expire_time(
        &self,
        caller_address: Address,
        target_address: Address,
        resource_type: u32,
    ) -> i64 {
        let caller = evm_to_tron_address(&caller_address);
        let target = evm_to_tron_address(&target_address);
        if caller.as_bytes() == target.as_bytes() {
            return self_freeze_expire(self, &caller, resource_type);
        }
        delegate_freeze_expire(self, &caller, &target, resource_type)
    }

    // ---- State-mutating Stake 1.0 / 2.0 opcode bridges ----
    //
    // Each method routes to the matching actuator primitive. The
    // actuators take typed-store references and a proto contract;
    // we build the contract from the EVM-side args, then call the
    // actuator. Success returns 1 (or the withdrawn amount), failure
    // returns 0 — matches java-tron's `OperationActions.*` push.
    //
    // When the staking stores haven't been attached
    // (`with_staking_stores` not called), every method returns 0
    // so read-only setups (eth_call, debug_traceCall, unit tests)
    // see the original "skipped, no mutation" behaviour.

    fn tron_take_last_balance_delta(&mut self) -> (Address, i64) {
        self.last_balance_delta
            .take()
            .unwrap_or((Address::ZERO, 0))
    }

    fn tron_freeze(
        &mut self,
        caller: Address,
        frozen_balance: i64,
        frozen_duration: i64,
        resource_type: u32,
        receiver_address: Option<Address>,
    ) -> i64 {
        let _ = receiver_address; // v1 didn't really use it on chain
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        if frozen_balance <= 0 || frozen_balance < TRX_PRECISION || resource_type > 2 {
            return 0;
        }
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        if account.balance < frozen_balance {
            return 0;
        }
        account.balance -= frozen_balance;
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        // v1: duration in days. The opcode handler currently passes
        // `0` for duration (java-tron's `FREEZE` opcode doesn't
        // expose duration on the EVM stack — actuator derives it
        // from chain params). Default to 3 days (the chain-minimum)
        // so the resulting Frozen entry has a sensible expiration.
        let duration_days = frozen_duration.max(3);
        let expire = now + duration_days * FROZEN_PERIOD_MS / 3;
        if let Some(existing) = account.frozen.first_mut() {
            existing.frozen_balance = match existing.frozen_balance.checked_add(frozen_balance) {
                Some(v) => v,
                None => return 0,
            };
            existing.expire_time = expire;
        } else {
            account.frozen.push(tron_proto::account::Frozen {
                frozen_balance,
                expire_time: expire,
            });
        }
        self.accounts.put(&owner, &account);
        let weight = frozen_balance / TRX_PRECISION;
        match resource_type {
            0 => dyn_props.add_total_net_weight(weight),
            1 => dyn_props.add_total_energy_weight(weight),
            _ => {}
        }
        // Tell the Host to debit the caller's journaled balance so
        // subsequent BALANCE / commit observes the post-freeze view.
        self.last_balance_delta = Some((caller, -frozen_balance));
        1
    }

    fn tron_unfreeze(
        &mut self,
        caller: Address,
        resource_type: u32,
        receiver_address: Option<Address>,
    ) -> i64 {
        let _ = receiver_address;
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        if account.frozen.is_empty() {
            return 0;
        }
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        if !account.frozen.iter().any(|f| f.expire_time <= now) {
            return 0;
        }
        let mut unlocked: i64 = 0;
        account.frozen.retain(|f| {
            if f.expire_time <= now {
                unlocked = unlocked.saturating_add(f.frozen_balance);
                false
            } else {
                true
            }
        });
        account.balance = match account.balance.checked_add(unlocked) {
            Some(v) => v,
            None => return 0,
        };
        self.accounts.put(&owner, &account);
        let weight = unlocked / TRX_PRECISION;
        match resource_type {
            0 => dyn_props.add_total_net_weight(-weight),
            1 => dyn_props.add_total_energy_weight(-weight),
            _ => {}
        }
        // Credit the unlocked amount back to the caller's journaled
        // balance.
        if unlocked > 0 {
            self.last_balance_delta = Some((caller, unlocked));
        }
        1
    }

    fn tron_vote_witness(&mut self, caller: Address, witnesses: &[(Address, i64)]) -> i64 {
        let Some(votes_store) = self.votes.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        let Ok(Some(mut owner_account)) = self.accounts.get(&owner) else {
            return 0;
        };
        let mut votes_capsule = match votes_store.get(&owner) {
            Ok(Some(v)) => v,
            _ => tron_proto::Votes {
                address: owner.as_bytes().to_vec(),
                old_votes: owner_account.votes.clone(),
                new_votes: Vec::new(),
            },
        };
        owner_account.votes.clear();
        votes_capsule.new_votes.clear();
        for (witness_addr, count) in witnesses {
            let witness_tron = evm_to_tron_address(witness_addr);
            let entry = tron_proto::Vote {
                vote_address: witness_tron.as_bytes().to_vec(),
                vote_count: *count,
            };
            owner_account.votes.push(tron_proto::Vote {
                vote_address: witness_tron.as_bytes().to_vec(),
                vote_count: *count,
            });
            votes_capsule.new_votes.push(entry);
        }
        self.accounts.put(&owner, &owner_account);
        votes_store.put(&owner, &votes_capsule);
        1
    }

    fn tron_withdraw_reward(&mut self, caller: Address) -> i64 {
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        let ready_at = account.latest_withdraw_time + WITNESS_ALLOWANCE_FROZEN_TIME_MS;
        if account.latest_withdraw_time > 0 && now < ready_at {
            return 0;
        }
        if account.allowance == 0 {
            return 0;
        }
        let allowance = account.allowance;
        account.balance = match account.balance.checked_add(allowance) {
            Some(v) => v,
            None => return 0,
        };
        account.allowance = 0;
        account.latest_withdraw_time = now;
        self.accounts.put(&owner, &account);
        // Credit the withdrawn allowance to the caller's journaled
        // balance.
        if allowance > 0 {
            self.last_balance_delta = Some((caller, allowance));
        }
        allowance
    }

    fn tron_freeze_balance_v2(
        &mut self,
        caller: Address,
        frozen_balance: i64,
        resource_type: u32,
    ) -> i64 {
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        if frozen_balance <= 0 || frozen_balance < TRX_PRECISION || resource_type > 2 {
            return 0;
        }
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        if account.balance < frozen_balance {
            return 0;
        }
        account.balance -= frozen_balance;
        let resource = resource_type as i32;
        let old_resource_balance = account
            .frozen_v2
            .iter()
            .find(|f| f.r#type == resource)
            .map(|f| f.amount)
            .unwrap_or(0);
        let slot = account.frozen_v2.iter_mut().find(|f| f.r#type == resource);
        match slot {
            Some(f) => {
                f.amount = match f.amount.checked_add(frozen_balance) {
                    Some(v) => v,
                    None => return 0,
                };
            }
            None => {
                account.frozen_v2.push(tron_proto::account::FreezeV2 {
                    r#type: resource,
                    amount: frozen_balance,
                });
            }
        }
        self.accounts.put(&owner, &account);
        let new_resource_balance = old_resource_balance.saturating_add(frozen_balance);
        let weight_delta =
            new_resource_balance / TRX_PRECISION - old_resource_balance / TRX_PRECISION;
        if weight_delta != 0 {
            match resource {
                0 => dyn_props.add_total_net_weight(weight_delta),
                1 => dyn_props.add_total_energy_weight(weight_delta),
                _ => {}
            }
        }
        // Debit the caller's journaled balance to match the on-stake
        // move.
        self.last_balance_delta = Some((caller, -frozen_balance));
        1
    }

    fn tron_unfreeze_balance_v2(
        &mut self,
        caller: Address,
        unfreeze_balance: i64,
        resource_type: u32,
    ) -> i64 {
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        if unfreeze_balance <= 0 || resource_type > 2 {
            return 0;
        }
        let owner = evm_to_tron_address(&caller);
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        let resource = resource_type as i32;
        // Find the matching FreezeV2 slot and subtract.
        let slot = account.frozen_v2.iter_mut().find(|f| f.r#type == resource);
        let old_resource_balance = slot.as_ref().map(|f| f.amount).unwrap_or(0);
        if old_resource_balance < unfreeze_balance {
            return 0;
        }
        if let Some(f) = slot {
            f.amount -= unfreeze_balance;
        }
        // Append an unfreezing entry — matures after the chain's
        // unfreeze delay.
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        let delay_ms = dyn_props
            .get_long(b"UNFREEZE_DELAY_DAYS")
            .map(|d| d.max(0) * 24 * 60 * 60 * 1000)
            .unwrap_or(14 * 24 * 60 * 60 * 1000);
        account.unfrozen_v2.push(tron_proto::account::UnFreezeV2 {
            r#type: resource,
            unfreeze_amount: unfreeze_balance,
            unfreeze_expire_time: now + delay_ms,
        });
        self.accounts.put(&owner, &account);
        // Shrink chain-wide weight by the unfrozen amount.
        let weight_delta = (old_resource_balance - unfreeze_balance) / TRX_PRECISION
            - old_resource_balance / TRX_PRECISION;
        if weight_delta != 0 {
            match resource {
                0 => dyn_props.add_total_net_weight(weight_delta),
                1 => dyn_props.add_total_energy_weight(weight_delta),
                _ => {}
            }
        }
        1
    }

    fn tron_cancel_all_unfreeze_v2(&mut self, caller: Address) -> i64 {
        let owner = evm_to_tron_address(&caller);
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        if account.unfrozen_v2.is_empty() {
            return 0;
        }
        // Re-stake every pending unfreeze entry into the matching
        // FreezeV2 slot. Mirrors `CancelAllUnfreezeV2Actuator.execute`.
        let pending: Vec<tron_proto::account::UnFreezeV2> = std::mem::take(&mut account.unfrozen_v2);
        for u in pending {
            let slot = account.frozen_v2.iter_mut().find(|f| f.r#type == u.r#type);
            match slot {
                Some(f) => {
                    f.amount = f.amount.saturating_add(u.unfreeze_amount);
                }
                None => account.frozen_v2.push(tron_proto::account::FreezeV2 {
                    r#type: u.r#type,
                    amount: u.unfreeze_amount,
                }),
            }
        }
        self.accounts.put(&owner, &account);
        1
    }

    fn tron_withdraw_expire_unfreeze(&mut self, caller: Address) -> i64 {
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        let mut withdrawn: i64 = 0;
        account.unfrozen_v2.retain(|u| {
            if u.unfreeze_expire_time != 0 && u.unfreeze_expire_time <= now {
                withdrawn = withdrawn.saturating_add(u.unfreeze_amount);
                false
            } else {
                true
            }
        });
        if withdrawn == 0 {
            return 0;
        }
        account.balance = match account.balance.checked_add(withdrawn) {
            Some(v) => v,
            None => return 0,
        };
        self.accounts.put(&owner, &account);
        // Credit the swept matured-unfreeze amount to the caller's
        // journaled balance.
        if withdrawn > 0 {
            self.last_balance_delta = Some((caller, withdrawn));
        }
        withdrawn
    }

    fn tron_delegate_resource(
        &mut self,
        caller: Address,
        balance: i64,
        receiver_address: Address,
        resource_type: u32,
        _lock: bool,
        _lock_period: i64,
    ) -> i64 {
        let Some(resources) = self.delegated_resources.as_ref() else {
            return 0;
        };
        if balance <= 0 || resource_type > 1 {
            return 0;
        }
        let owner = evm_to_tron_address(&caller);
        let receiver = evm_to_tron_address(&receiver_address);
        if owner.as_bytes() == receiver.as_bytes() {
            return 0;
        }
        let resource = resource_type as i32;
        let Ok(Some(mut owner_account)) = self.accounts.get(&owner) else {
            return 0;
        };
        // Debit owner's FreezeV2 by `balance` for this resource type.
        let slot = owner_account
            .frozen_v2
            .iter_mut()
            .find(|f| f.r#type == resource);
        let have = slot.as_ref().map(|f| f.amount).unwrap_or(0);
        if have < balance {
            return 0;
        }
        if let Some(f) = slot {
            f.amount -= balance;
        }
        // Credit receiver's `delegated_frozenV2_balance_for_*`.
        let mut receiver_account = match self.accounts.get(&receiver) {
            Ok(Some(a)) => a,
            _ => return 0,
        };
        match resource {
            0 => {
                receiver_account.acquired_delegated_frozen_v2_balance_for_bandwidth =
                    receiver_account
                        .acquired_delegated_frozen_v2_balance_for_bandwidth
                        .saturating_add(balance);
                owner_account.delegated_frozen_v2_balance_for_bandwidth = owner_account
                    .delegated_frozen_v2_balance_for_bandwidth
                    .saturating_add(balance);
            }
            1 => {
                // Energy lives on AccountResource (Option). Initialize
                // on first delegation.
                let owner_res =
                    owner_account.account_resource.get_or_insert_with(Default::default);
                owner_res.delegated_frozen_v2_balance_for_energy = owner_res
                    .delegated_frozen_v2_balance_for_energy
                    .saturating_add(balance);
                let receiver_res = receiver_account
                    .account_resource
                    .get_or_insert_with(Default::default);
                receiver_res.acquired_delegated_frozen_v2_balance_for_energy = receiver_res
                    .acquired_delegated_frozen_v2_balance_for_energy
                    .saturating_add(balance);
            }
            _ => {}
        }
        self.accounts.put(&owner, &owner_account);
        self.accounts.put(&receiver, &receiver_account);
        // Write the DelegatedResource record so receiver-side reads see
        // the delegation. v2-unlocked key = (from, to).
        let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(&owner, &receiver);
        let mut record = resources.get_raw(&key).ok().flatten().unwrap_or_default();
        record.from = owner.as_bytes().to_vec();
        record.to = receiver.as_bytes().to_vec();
        match resource {
            0 => {
                record.frozen_balance_for_bandwidth = record
                    .frozen_balance_for_bandwidth
                    .saturating_add(balance);
            }
            1 => {
                record.frozen_balance_for_energy = record
                    .frozen_balance_for_energy
                    .saturating_add(balance);
            }
            _ => {}
        }
        resources.put_raw(&key, &record);
        1
    }

    fn tron_undelegate_resource(
        &mut self,
        caller: Address,
        balance: i64,
        receiver_address: Address,
        resource_type: u32,
    ) -> i64 {
        let Some(resources) = self.delegated_resources.as_ref() else {
            return 0;
        };
        if balance <= 0 || resource_type > 1 {
            return 0;
        }
        let owner = evm_to_tron_address(&caller);
        let receiver = evm_to_tron_address(&receiver_address);
        let resource = resource_type as i32;
        // Look up the v2 (from, to) delegation; subtract.
        let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(&owner, &receiver);
        let mut record = match resources.get_raw(&key) {
            Ok(Some(r)) => r,
            _ => return 0,
        };
        let amount = match resource {
            0 => record.frozen_balance_for_bandwidth,
            1 => record.frozen_balance_for_energy,
            _ => 0,
        };
        if amount < balance {
            return 0;
        }
        match resource {
            0 => record.frozen_balance_for_bandwidth -= balance,
            1 => record.frozen_balance_for_energy -= balance,
            _ => {}
        }
        resources.put_raw(&key, &record);
        // Credit owner's FreezeV2 back, debit receiver's acquired_*.
        if let Ok(Some(mut owner_account)) = self.accounts.get(&owner) {
            let slot = owner_account
                .frozen_v2
                .iter_mut()
                .find(|f| f.r#type == resource);
            match slot {
                Some(f) => f.amount = f.amount.saturating_add(balance),
                None => owner_account.frozen_v2.push(tron_proto::account::FreezeV2 {
                    r#type: resource,
                    amount: balance,
                }),
            }
            match resource {
                0 => {
                    owner_account.delegated_frozen_v2_balance_for_bandwidth = owner_account
                        .delegated_frozen_v2_balance_for_bandwidth
                        .saturating_sub(balance);
                }
                1 => {
                    if let Some(r) = owner_account.account_resource.as_mut() {
                        r.delegated_frozen_v2_balance_for_energy =
                            r.delegated_frozen_v2_balance_for_energy.saturating_sub(balance);
                    }
                }
                _ => {}
            }
            self.accounts.put(&owner, &owner_account);
        }
        if let Ok(Some(mut receiver_account)) = self.accounts.get(&receiver) {
            match resource {
                0 => {
                    receiver_account.acquired_delegated_frozen_v2_balance_for_bandwidth =
                        receiver_account
                            .acquired_delegated_frozen_v2_balance_for_bandwidth
                            .saturating_sub(balance);
                }
                1 => {
                    if let Some(r) = receiver_account.account_resource.as_mut() {
                        r.acquired_delegated_frozen_v2_balance_for_energy =
                            r.acquired_delegated_frozen_v2_balance_for_energy
                                .saturating_sub(balance);
                    }
                }
                _ => {}
            }
            self.accounts.put(&receiver, &receiver_account);
        }
        1
    }
}

/// Constants pulled from `tron-actuator` (kept inline here so
/// `tron-tvm` doesn't depend on `tron-actuator` — the actuator
/// already depends on `tron-tvm` for shielded verifier keys, a
/// dep we can't cycle back through).
const TRX_PRECISION: i64 = 1_000_000;
const FROZEN_PERIOD_MS: i64 = 3 * 24 * 60 * 60 * 1000;
/// 24 hours — gap between consecutive `withdrawBalance` calls.
const WITNESS_ALLOWANCE_FROZEN_TIME_MS: i64 = 24 * 60 * 60 * 1000;

fn self_freeze_expire(
    db: &TronDatabase,
    owner: &TronAddress,
    resource_type: u32,
) -> i64 {
    let Ok(Some(account)) = db.accounts.get(owner) else {
        return 0;
    };
    match resource_type {
        // Bandwidth: java-tron reads `Account.frozen[0]` (the proto's
        // `frozen_balance` + `expire_time` in ms).
        0 => account
            .frozen
            .first()
            .filter(|f| f.frozen_balance != 0)
            .map(|f| f.expire_time)
            .unwrap_or(0),
        // Energy: `AccountResource.frozen_balance_for_energy`.
        1 => account
            .account_resource
            .as_ref()
            .and_then(|r| r.frozen_balance_for_energy.as_ref())
            .filter(|f| f.frozen_balance != 0)
            .map(|f| f.expire_time)
            .unwrap_or(0),
        _ => 0,
    }
}

/// Delegation lookup is a follow-up — `TronDatabase` doesn't carry a
/// `DelegatedResourceStore` Arc today. java-tron's equivalent reads
/// `DelegatedResourceCapsule` keyed `(from, to)` and returns
/// `expireTimeForBandwidth` / `expireTimeForEnergy`. The precompile
/// path at `crates/tron-tvm/src/precompiles.rs` already has the
/// store-side logic — wire it through here when DB grows the field.
fn delegate_freeze_expire(
    _db: &TronDatabase,
    _caller: &TronAddress,
    _target: &TronAddress,
    _resource_type: u32,
) -> i64 {
    // Silence "unused import" warning while keeping the type alias in
    // scope as a hint to whoever wires this in next.
    let _ = DelegatedResourceStore::v1_key as fn(_, _) -> _;
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tron_chainbase::{AccountStore, CodeStore, KvBackend, MemBackend, StorageRowStore};
    use tron_proto::Account;

    fn make_db() -> TronDatabase {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let accounts = Arc::new(AccountStore::new(backend.clone()));
        let code = Arc::new(CodeStore::new(Arc::new(MemBackend::new())));
        let storage = Arc::new(StorageRowStore::new(Arc::new(MemBackend::new())));
        TronDatabase::new(accounts, code, storage)
    }

    fn tron_addr(byte: u8) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(byte);
        a
    }

    fn evm_addr_from_tron(tron: [u8; 21]) -> Address {
        let mut out = [0u8; 20];
        out.copy_from_slice(&tron[1..]);
        Address::from(out)
    }

    #[test]
    fn token_balance_reads_real_asset_v2_entry() {
        let db = make_db();
        let owner = tron_addr(0xaa);
        let mut acct = Account {
            address: owner.to_vec(),
            balance: 0,
            ..Default::default()
        };
        acct.asset_v2.insert("1000001".to_string(), 12_345);
        db.accounts
            .put(&TronAddress::from_raw(owner), &acct);

        let evm_addr = evm_addr_from_tron(owner);
        assert_eq!(
            TronDatabaseExt::tron_token_balance(&db, evm_addr, 1_000_001),
            12_345,
            "real asset_v2 balance must surface via TronDatabaseExt"
        );
        // Unknown token id → 0.
        assert_eq!(TronDatabaseExt::tron_token_balance(&db, evm_addr, 999), 0);
        // Unknown account → 0.
        assert_eq!(
            TronDatabaseExt::tron_token_balance(&db, evm_addr_from_tron(tron_addr(0xbb)), 1_000_001),
            0
        );
    }

    #[test]
    fn is_contract_returns_true_for_account_with_code() {
        let db = make_db();
        let contract = tron_addr(0xcc);
        let acct = Account {
            address: contract.to_vec(),
            code_hash: vec![0u8; 32], // any non-empty value
            ..Default::default()
        };
        db.accounts
            .put(&TronAddress::from_raw(contract), &acct);
        assert!(
            TronDatabaseExt::tron_is_contract(&db, evm_addr_from_tron(contract)),
            "contract with non-empty code_hash must be is_contract == true"
        );
    }

    #[test]
    fn is_contract_returns_false_for_eoa_and_missing() {
        let db = make_db();
        let eoa = tron_addr(0xdd);
        db.accounts.put(
            &TronAddress::from_raw(eoa),
            &Account {
                address: eoa.to_vec(),
                code_hash: vec![],
                ..Default::default()
            },
        );
        assert!(!TronDatabaseExt::tron_is_contract(&db, evm_addr_from_tron(eoa)));
        assert!(!TronDatabaseExt::tron_is_contract(
            &db,
            evm_addr_from_tron(tron_addr(0xee))
        ));
    }
}
