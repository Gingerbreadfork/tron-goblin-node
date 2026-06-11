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

use crate::database::{evm_to_tron_address, tron_to_evm_address, TronDatabase};

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

    fn tron_root_tx_id(&self) -> revm::primitives::B256 {
        revm::primitives::B256::from(self.root_tx_id)
    }

    fn tron_bump_create_nonce(&mut self) -> u64 {
        let n = self.create_nonce;
        self.create_nonce += 1;
        n
    }

    fn tron_record_created_contract(&mut self, address: Address, creator: Address, is_create2: bool) {
        self.pending_created_contracts
            .insert(address, (creator, is_create2));
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

    fn tron_take_balance_deltas(&mut self) -> Vec<(Address, i64)> {
        std::mem::take(&mut self.pending_balance_deltas)
    }

    /// java-tron `Program.suicide` / `suicide2` -- the chainbase half.
    ///
    /// The EVM journal already handles the TRX balance (owner ->
    /// obtainer, or owner -> burn account for a self-target destroy via
    /// the journal-cfg redirect) and the destroy/no-op decision. This
    /// bridge ports everything java does on its `Repository`:
    ///
    /// * `canSuicide` (pre-#94) / `canSuicide2` (#94) validation --
    ///   outstanding v1/v2 delegations (or, under #94, unexpired frozen
    ///   v1) make the whole frame REVERT (`-1`).
    /// * `withdrawRewardAndCancelVote` (gated `ALLOW_TVM_VOTE`): settle
    ///   pending voter rewards, clear votes + the votes-store row, fold
    ///   `allowance` into balance (EVM-side via the delta channel).
    /// * TRC-10 sweep (gated `ALLOW_TVM_TRANSFER_TRC10`): every
    ///   `asset_v2` entry moves to the inheritor.
    /// * Frozen v1 (gated `ALLOW_TVM_FREEZE`): total-weight accounting,
    ///   frozen balances credited to the inheritor as TRX; owner's
    ///   frozen rows cleared under #94 (pre-#94 the row is deleted
    ///   anyway).
    /// * Frozen v2 (gated `ALLOW_TVM_FREEZE_V2`): frozen entries move to
    ///   the inheritor, usage windows merge (`unDelegateIncrease`),
    ///   expired unfreezes credit the inheritor as TRX, owner's v2
    ///   state cleared.
    ///
    /// The inheritor is the burn account when `obtainer == owner`
    /// (java's blackhole), the obtainer otherwise. A non-destroying
    /// self-target suicide (#94, pre-existing contract) is a pure no-op
    /// after validation -- java `suicide2` returns right after the
    /// internal-tx record.
    fn tron_suicide(&mut self, owner: Address, obtainer: Address, will_destroy: bool) -> i64 {
        use tron_types::resource::{self as res, ResourceKind, ResourceGates};

        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0; // read-only setup: nothing to validate or move
        };
        let owner_t = evm_to_tron_address(&owner);
        let obtainer_t = evm_to_tron_address(&obtainer);
        let Ok(Some(mut owner_account)) = self.accounts.get(&owner_t) else {
            return 0;
        };

        let now_ms = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        let allow_freeze = dyn_props.get_long(b"ALLOW_TVM_FREEZE").unwrap_or(0) == 1;
        let allow_freeze_v2 = dyn_props.get_long(b"ALLOW_TVM_FREEZE_V2").unwrap_or(0) == 1;
        let allow_vote = dyn_props.get_long(b"ALLOW_TVM_VOTE").unwrap_or(0) == 1;
        let allow_trc10 = dyn_props.get_long(b"ALLOW_TVM_TRANSFER_TRC10").unwrap_or(0) == 1;
        let restriction = dyn_props
            .get_long(b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION")
            .unwrap_or(0)
            == 1;

        // ---- validation: canSuicide (pre-#94) / canSuicide2 (#94) ----
        let delegated_v1_clear = owner_account.delegated_frozen_balance_for_bandwidth == 0
            && owner_account
                .account_resource
                .as_ref()
                .map(|r| r.delegated_frozen_balance_for_energy)
                .unwrap_or(0)
                == 0;
        let frozen_v1_unexpired = owner_account
            .frozen
            .iter()
            .any(|f| f.expire_time > now_ms)
            || owner_account
                .account_resource
                .as_ref()
                .and_then(|r| r.frozen_balance_for_energy.as_ref())
                .map(|f| f.frozen_balance > 0 && f.expire_time > now_ms)
                .unwrap_or(false);
        let freeze_v1_ok = if !allow_freeze {
            true
        } else if restriction {
            // canSuicide2's freezeV1Check: unexpired frozen ALSO blocks.
            !frozen_v1_unexpired && delegated_v1_clear
        } else {
            // canSuicide's freezeCheck: delegations only.
            delegated_v1_clear
        };
        let freeze_v2_ok = !allow_freeze_v2 || {
            let delegated_clear = owner_account.delegated_frozen_v2_balance_for_bandwidth == 0
                && owner_account
                    .account_resource
                    .as_ref()
                    .map(|r| r.delegated_frozen_v2_balance_for_energy)
                    .unwrap_or(0)
                    == 0;
            let unfrozen_pending = owner_account
                .unfrozen_v2
                .iter()
                .any(|u| u.unfreeze_expire_time > now_ms);
            delegated_clear && !unfrozen_pending
        };
        if !(freeze_v1_ok && freeze_v2_ok) {
            return -1;
        }

        // java bumps the nonce in `suicide`/`suicide2` AFTER the
        // `canSuicide`/`canSuicide2` validation (the opcode action validates,
        // then calls the handler whose first act is `increaseNonce`). It fires
        // even on the self-target path (the `owner == obtainer` check comes
        // after `increaseNonce`), so bump before the self-target early return.
        self.note_internal_tx_nonce();

        let self_target = owner_t == obtainer_t;
        if self_target && !will_destroy {
            // suicide2 on a pre-existing contract with itself as the
            // beneficiary: validated, recorded, otherwise untouched.
            return 0;
        }

        // The burn account inherits on a self-target destroy.
        let inheritor_t = if self_target {
            tron_crypto::address::Address::from_raw(BLACKHOLE_ADDRESS)
        } else {
            obtainer_t
        };

        // ---- withdrawRewardAndCancelVote (suicide: always; suicide2:
        //      only on the transfer path -- both reach here) ----
        if allow_vote {
            if let Some(delegation) = self.delegation.clone() {
                let _ = crate::reward::withdraw_reward(
                    &owner_t,
                    &self.accounts,
                    &delegation,
                    &dyn_props,
                    self.reward_vi.as_deref(),
                );
                // Re-read: withdraw_reward may have grown the allowance.
                if let Ok(Some(acc)) = self.accounts.get(&owner_t) {
                    owner_account = acc;
                }
            }
            if !owner_account.votes.is_empty() {
                if let Some(votes_store) = self.votes.as_ref() {
                    let mut votes_row = match votes_store.get(&owner_t) {
                        Ok(Some(v)) => {
                            let mut v = v;
                            v.new_votes.clear();
                            v
                        }
                        _ => tron_proto::Votes {
                            address: owner_t.as_bytes().to_vec(),
                            old_votes: owner_account.votes.clone(),
                            new_votes: Vec::new(),
                        },
                    };
                    votes_row.address = owner_t.as_bytes().to_vec();
                    votes_store
                        .put(&owner_t, &votes_row)
                        .expect("db error in tron_suicide writing votes row");
                }
                owner_account.votes.clear();
                owner_account.old_tron_power = 0;
            }
            // Fold allowance into balance: chainbase keeps the
            // allowance/latest-withdraw fields, the EVM journal gets the
            // balance credit. java truncates the withdraw time to whole
            // seconds (block timestamp word * 1000).
            let allowance = owner_account.allowance;
            if allowance != 0 {
                self.pending_balance_deltas.push((owner, allowance));
            }
            owner_account.allowance = 0;
            owner_account.latest_withdraw_time = (now_ms / 1000) * 1000;
        }

        // Make sure the inheritor exists on chain (java
        // `createAccountIfNotExist`).
        let mut inheritor_account = match self.accounts.get(&inheritor_t) {
            Ok(Some(acc)) => acc,
            _ => tron_proto::Account {
                address: inheritor_t.as_bytes().to_vec(),
                create_time: now_ms,
                ..Default::default()
            },
        };

        // ---- TRC-10 sweep ----
        if allow_trc10 {
            for (token, amount) in std::mem::take(&mut owner_account.asset_v2) {
                if amount == 0 {
                    continue;
                }
                let slot = inheritor_account.asset_v2.entry(token).or_insert(0);
                *slot = slot.saturating_add(amount);
            }
        }

        // ---- frozen v1 ----
        if allow_freeze {
            let frozen_bw = owner_account
                .frozen
                .first()
                .map(|f| f.frozen_balance)
                .unwrap_or(0);
            let frozen_energy = owner_account
                .account_resource
                .as_ref()
                .and_then(|r| r.frozen_balance_for_energy.as_ref())
                .map(|f| f.frozen_balance)
                .unwrap_or(0);
            dyn_props.add_total_net_weight(-frozen_bw / TRX_PRECISION);
            dyn_props.add_total_energy_weight(-frozen_energy / TRX_PRECISION);
            let total = frozen_bw.saturating_add(frozen_energy);
            if total != 0 {
                self.pending_balance_deltas
                    .push((tron_to_evm_address(&inheritor_t), total));
            }
            if restriction {
                // java clearOwnerFreeze (only under #94 -- pre-#94 the
                // whole row is deleted at commit anyway).
                owner_account.frozen.clear();
                if let Some(r) = owner_account.account_resource.as_mut() {
                    r.frozen_balance_for_energy = None;
                }
            }
        }

        // ---- frozen v2 ----
        if allow_freeze_v2 {
            let gates = ResourceGates {
                support_unfreeze_delay: dyn_props.support_unfreeze_delay(),
                support_allow_cancel_all_unfreeze_v2: dyn_props
                    .support_allow_cancel_all_unfreeze_v2(),
            };
            let now_slot = dyn_props.head_slot();

            // Transfer frozen v2 entries by type.
            for f in owner_account.frozen_v2.iter().filter(|f| f.amount > 0) {
                let slot = inheritor_account
                    .frozen_v2
                    .iter_mut()
                    .find(|i| i.r#type == f.r#type);
                match slot {
                    Some(i) => i.amount = i.amount.saturating_add(f.amount),
                    None => inheritor_account.frozen_v2.push(tron_proto::account::FreezeV2 {
                        r#type: f.r#type,
                        amount: f.amount,
                    }),
                }
            }

            // Merge usage windows into the inheritor (java
            // updateUsageForDelegated + unDelegateIncrease).
            res::update_usage(&mut owner_account, ResourceKind::Bandwidth, now_slot, gates);
            res::set_latest_time(&mut owner_account, ResourceKind::Bandwidth, now_slot);
            if res::usage(&owner_account, ResourceKind::Bandwidth) > 0 {
                let usage = res::usage(&owner_account, ResourceKind::Bandwidth);
                res::undelegate_increase(
                    &mut inheritor_account,
                    &owner_account,
                    usage,
                    ResourceKind::Bandwidth,
                    now_slot,
                    gates,
                );
            }
            res::update_usage(&mut owner_account, ResourceKind::Energy, now_slot, gates);
            res::set_latest_time(&mut owner_account, ResourceKind::Energy, now_slot);
            if res::usage(&owner_account, ResourceKind::Energy) > 0 {
                let usage = res::usage(&owner_account, ResourceKind::Energy);
                res::undelegate_increase(
                    &mut inheritor_account,
                    &owner_account,
                    usage,
                    ResourceKind::Energy,
                    now_slot,
                    gates,
                );
            }

            // Expired unfreezes credit the inheritor as TRX.
            let expired: i64 = owner_account
                .unfrozen_v2
                .iter()
                .filter(|u| u.unfreeze_amount > 0 && u.unfreeze_expire_time <= now_ms)
                .map(|u| u.unfreeze_amount)
                .sum();
            if expired > 0 {
                self.pending_balance_deltas
                    .push((tron_to_evm_address(&inheritor_t), expired));
                // java's conditional second `increaseNonce`
                // ("withdrawExpireUnfreezeWhileSuiciding"). Only `suicide2`
                // (selfdestruct restriction active) takes this transfer path;
                // the pre-restriction `suicide` does not, so gate on
                // `restriction` to avoid an over-bump in that historical case.
                if restriction {
                    self.note_internal_tx_nonce();
                }
            }

            // clearOwnerFreezeV2.
            owner_account.frozen_v2.clear();
            owner_account.unfrozen_v2.clear();
            res::set_usage(&mut owner_account, ResourceKind::Bandwidth, 0);
            res::set_new_window_size(&mut owner_account, ResourceKind::Bandwidth, 0);
            res::set_usage(&mut owner_account, ResourceKind::Energy, 0);
            res::set_new_window_size(&mut owner_account, ResourceKind::Energy, 0);
        }

        self.accounts
            .put(&owner_t, &owner_account)
            .expect("db error in tron_suicide writing owner account");
        if inheritor_t != owner_t {
            self.accounts
                .put(&inheritor_t, &inheritor_account)
                .expect("db error in tron_suicide writing inheritor account");
        }
        0
    }

    fn tron_freeze(
        &mut self,
        caller: Address,
        frozen_balance: i64,
        frozen_duration: i64,
        resource_type: u32,
        receiver_address: Option<Address>,
    ) -> i64 {
        // java `Program.freeze` bumps the nonce at the top of the handler,
        // before its validate (`increaseNonce` precedes `processor.validate`).
        self.note_internal_tx_nonce();
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
        self.accounts
            .put(&owner, &account)
            .expect("db error in TronDatabaseExt::tron_freeze writing owner account");
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
        // java `Program.unfreeze`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
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
        self.accounts
            .put(&owner, &account)
            .expect("db error in TronDatabaseExt::tron_unfreeze writing owner account");
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
        // java `Program.voteWitness`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
        let Some(votes_store) = self.votes.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        // java's `VoteWitnessProcessor.execute` settles pending voter
        // rewards FIRST (`VoteRewardUtil.withdrawReward`) — the reward
        // window must close against the votes as they stood.
        if let (Some(delegation), Some(dyn_props)) =
            (self.delegation.as_ref(), self.dyn_props.as_ref())
        {
            crate::reward::withdraw_reward(&owner, &self.accounts, delegation, dyn_props, self.reward_vi.as_deref())
                .expect("db error in TronDatabaseExt::tron_vote_witness settling rewards");
        }
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
        self.accounts
            .put(&owner, &owner_account)
            .expect("db error in TronDatabaseExt::tron_vote_witness writing owner account");
        votes_store
            .put(&owner, &votes_capsule)
            .expect("db error in TronDatabaseExt::tron_vote_witness writing votes");
        1
    }

    fn tron_withdraw_reward(&mut self, caller: Address) -> i64 {
        // java `Program.withdrawReward`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        // java's TVM `WithdrawRewardProcessor.execute` settles pending
        // voter rewards into `allowance` first (`VoteRewardUtil
        // .withdrawReward`), then drains the allowance. NOTE: unlike the
        // `WithdrawBalanceContract` actuator, the TVM opcode has NO 24h
        // cooldown — its validate only blocks genesis GRs. Our previous
        // guard (`latest_withdraw_time + 24h`) failed withdrawals java
        // accepts.
        if let Some(delegation) = self.delegation.as_ref() {
            crate::reward::withdraw_reward(&owner, &self.accounts, delegation, dyn_props, self.reward_vi.as_deref())
                .expect("db error in TronDatabaseExt::tron_withdraw_reward settling rewards");
        }
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        // java: `if (allowance <= 0) return 0;` AFTER the settle, leaving
        // the account untouched.
        let allowance = account.allowance;
        if allowance <= 0 {
            return 0;
        }
        account.balance = match account.balance.checked_add(allowance) {
            Some(v) => v,
            None => return 0,
        };
        account.allowance = 0;
        account.latest_withdraw_time = now;
        self.accounts
            .put(&owner, &account)
            .expect("db error in TronDatabaseExt::tron_withdraw_reward writing owner account");
        // Credit the withdrawn allowance to the caller's journaled
        // balance.
        self.last_balance_delta = Some((caller, allowance));
        allowance
    }

    fn tron_freeze_balance_v2(
        &mut self,
        caller: Address,
        frozen_balance: i64,
        resource_type: u32,
    ) -> i64 {
        // java `Program.freezeBalanceV2`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
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
        // Weight is floored from `getFrozenV2BalanceWithDelegated` (held +
        // delegated-out), read BEFORE the stake is added — java's
        // `FreezeBalanceV2Processor`. Adding `frozen_balance` to held leaves
        // delegated unchanged, so `new_basis == old_basis + frozen_balance`.
        let old_basis = frozen_v2_basis_with_delegated(&account, resource);
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
        self.accounts
            .put(&owner, &account)
            .expect("db error in TronDatabaseExt::tron_freeze_balance_v2 writing owner account");
        let new_basis = old_basis.saturating_add(frozen_balance);
        let weight_delta = new_basis / TRX_PRECISION - old_basis / TRX_PRECISION;
        if weight_delta != 0 {
            match resource {
                0 => dyn_props.add_total_net_weight(weight_delta),
                1 => dyn_props.add_total_energy_weight(weight_delta),
                2 => dyn_props.add_total_tron_power_weight(weight_delta),
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
        // java `Program.unfreezeBalanceV2`: increaseNonce at the top, before
        // validate. A second bump happens below iff it auto-withdraws an
        // expired unfreeze (`unfreezeExpireBalance > 0`).
        self.note_internal_tx_nonce();
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        if unfreeze_balance <= 0 || resource_type > 2 {
            return 0;
        }
        let owner = evm_to_tron_address(&caller);
        // java's TVM `UnfreezeBalanceV2Processor.execute` settles pending
        // voter rewards first, mirroring the actuator.
        if let Some(delegation) = self.delegation.as_ref() {
            crate::reward::withdraw_reward(&owner, &self.accounts, delegation, dyn_props, self.reward_vi.as_deref())
                .expect(
                    "db error in TronDatabaseExt::tron_unfreeze_balance_v2 settling rewards",
                );
        }
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        // Sweep EXPIRED unfreeze entries into balance (java's
        // `unfreezeExpire`, run on every v2 unstake before the new entry
        // is added). The swept amount is journaled below so the EVM-side
        // balance view matches.
        let mut swept = 0i64;
        account.unfrozen_v2.retain(|u| {
            if u.unfreeze_expire_time <= now {
                swept = swept.saturating_add(u.unfreeze_amount);
                false
            } else {
                true
            }
        });
        account.balance = match account.balance.checked_add(swept) {
            Some(v) => v,
            None => return 0,
        };
        let resource = resource_type as i32;
        // Weight is floored from `getFrozenV2BalanceWithDelegated` (held +
        // delegated-out), read BEFORE the unstake is removed — java's
        // `UnfreezeBalanceV2Processor.updateTotalResourceWeight`.
        let old_basis = frozen_v2_basis_with_delegated(&account, resource);
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
        let delay_ms = dyn_props
            .get_long(b"UNFREEZE_DELAY_DAYS")
            .map(|d| d.max(0) * 24 * 60 * 60 * 1000)
            .unwrap_or(14 * 24 * 60 * 60 * 1000);
        account.unfrozen_v2.push(tron_proto::account::UnFreezeV2 {
            r#type: resource,
            unfreeze_amount: unfreeze_balance,
            unfreeze_expire_time: now + delay_ms,
        });
        // Trim votes the unstake no longer backs (java's `updateVote`,
        // shared with the actuator — see `crate::votes`).
        if let Some(votes_store) = self.votes.as_ref() {
            crate::votes::update_vote_after_unstake(votes_store, &owner, &mut account).expect(
                "db error in TronDatabaseExt::tron_unfreeze_balance_v2 trimming votes",
            );
        }
        self.accounts
            .put(&owner, &account)
            .expect("db error in TronDatabaseExt::tron_unfreeze_balance_v2 writing owner account");
        // Shrink chain-wide weight by the floored basis change (delegated-out
        // unchanged, so `new_basis == old_basis - unfreeze_balance`).
        let weight_delta =
            (old_basis - unfreeze_balance) / TRX_PRECISION - old_basis / TRX_PRECISION;
        if weight_delta != 0 {
            match resource {
                0 => dyn_props.add_total_net_weight(weight_delta),
                1 => dyn_props.add_total_energy_weight(weight_delta),
                2 => dyn_props.add_total_tron_power_weight(weight_delta),
                _ => {}
            }
        }
        // Credit the expired-sweep to the caller's journaled balance.
        if swept > 0 {
            self.last_balance_delta = Some((caller, swept));
            // java's conditional second `increaseNonce`
            // ("withdrawExpireUnfreezeWhileUnfreezing").
            self.note_internal_tx_nonce();
        }
        1
    }

    fn tron_cancel_all_unfreeze_v2(&mut self, caller: Address) -> i64 {
        // java `Program.cancelAllUnfreezeV2Action`: increaseNonce at the top,
        // before validate. A second bump happens below iff it auto-withdraws an
        // expired unfreeze (`WITHDRAW_EXPIRE_BALANCE > 0`).
        self.note_internal_tx_nonce();
        let Some(dyn_props) = self.dyn_props.as_ref() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        let Ok(Some(mut account)) = self.accounts.get(&owner) else {
            return 0;
        };
        if account.unfrozen_v2.is_empty() {
            return 0;
        }
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        // Weight basis (held + delegated-out) per resource, captured BEFORE any
        // pending entry is restored — java's `CancelAllUnfreezeV2Processor`
        // (mirrors our actuator `execute_cancel_all_unfreeze_v2`). EXPIRED entries
        // are withdrawn to balance (NOT re-staked) and don't move the weight (it
        // was already shrunk when they were unfrozen); only not-yet-expired
        // entries are restored to FreezeV2 and bump the weight back.
        let old_net = frozen_v2_basis_with_delegated(&account, 0);
        let old_energy = frozen_v2_basis_with_delegated(&account, 1);
        let old_tp = frozen_v2_basis_with_delegated(&account, 2);
        let (mut restored_net, mut restored_energy, mut restored_tp) = (0i64, 0i64, 0i64);
        let mut withdraw: i64 = 0;
        let pending: Vec<tron_proto::account::UnFreezeV2> = std::mem::take(&mut account.unfrozen_v2);
        for u in pending {
            if u.unfreeze_expire_time <= now {
                // Expired → withdraw to balance.
                withdraw = withdraw.saturating_add(u.unfreeze_amount);
                continue;
            }
            // Not yet expired → restore to the matching FreezeV2 slot.
            match u.r#type {
                0 => restored_net = restored_net.saturating_add(u.unfreeze_amount),
                1 => restored_energy = restored_energy.saturating_add(u.unfreeze_amount),
                2 => restored_tp = restored_tp.saturating_add(u.unfreeze_amount),
                _ => {}
            }
            match account.frozen_v2.iter_mut().find(|f| f.r#type == u.r#type) {
                Some(f) => f.amount = f.amount.saturating_add(u.unfreeze_amount),
                None => account.frozen_v2.push(tron_proto::account::FreezeV2 {
                    r#type: u.r#type,
                    amount: u.unfreeze_amount,
                }),
            }
        }
        if withdraw > 0 {
            account.balance = account.balance.saturating_add(withdraw);
        }
        self.accounts
            .put(&owner, &account)
            .expect("db error in TronDatabaseExt::tron_cancel_all_unfreeze_v2 writing owner account");
        // Restore the chain-wide weight for the re-staked (not-expired) entries
        // (`floor(old + restored) - floor(old)`, byte-identical to java's
        // per-entry fold by telescoping).
        let net_delta = (old_net + restored_net) / TRX_PRECISION - old_net / TRX_PRECISION;
        let energy_delta =
            (old_energy + restored_energy) / TRX_PRECISION - old_energy / TRX_PRECISION;
        let tp_delta = (old_tp + restored_tp) / TRX_PRECISION - old_tp / TRX_PRECISION;
        if net_delta != 0 {
            dyn_props.add_total_net_weight(net_delta);
        }
        if energy_delta != 0 {
            dyn_props.add_total_energy_weight(energy_delta);
        }
        if tp_delta != 0 {
            dyn_props.add_total_tron_power_weight(tp_delta);
        }
        // Journal the expired-sweep balance to the caller (matches the on-chain
        // `setBalance(balance + withdrawExpireBalance)`).
        if withdraw > 0 {
            self.last_balance_delta = Some((caller, withdraw));
            // java's conditional second `increaseNonce`
            // ("withdrawExpireUnfreezeWhileCanceling").
            self.note_internal_tx_nonce();
        }
        1
    }

    fn tron_withdraw_expire_unfreeze(&mut self, caller: Address) -> i64 {
        // java `Program.withdrawExpireUnfreeze`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
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
        self.accounts
            .put(&owner, &account)
            .expect("db error in TronDatabaseExt::tron_withdraw_expire_unfreeze writing owner account");
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
        // java `Program.delegateResource`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
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
        self.accounts
            .put(&owner, &owner_account)
            .expect("db error in TronDatabaseExt::tron_delegate_resource writing owner account");
        self.accounts
            .put(&receiver, &receiver_account)
            .expect("db error in TronDatabaseExt::tron_delegate_resource writing receiver account");
        // Write the DelegatedResource record so receiver-side reads see
        // the delegation. v2-unlocked key = (from, to).
        let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(&owner, &receiver);
        // `Ok(None)` (no prior record) legitimately starts from default, but a
        // real IO error must NOT silently fabricate a fresh record — that would
        // overwrite an existing delegation with divergent state. Fail-stop on
        // IO error, consistent with the sibling `.put(...).expect(...)` writes
        // below (the precompile host has no fallible-return channel).
        let mut record = resources
            .get_raw(&key)
            .expect("db error in TronDatabaseExt::tron_delegate_resource reading delegated resource record")
            .unwrap_or_default();
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
        resources
            .put_raw(&key, &record)
            .expect("db error in TronDatabaseExt::tron_delegate_resource writing delegated resource record");
        1
    }

    fn tron_undelegate_resource(
        &mut self,
        caller: Address,
        balance: i64,
        receiver_address: Address,
        resource_type: u32,
    ) -> i64 {
        // java `Program.unDelegateResource`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
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
        resources
            .put_raw(&key, &record)
            .expect("db error in TronDatabaseExt::tron_undelegate_resource writing delegated resource record");
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
            self.accounts
                .put(&owner, &owner_account)
                .expect("db error in TronDatabaseExt::tron_undelegate_resource writing owner account");
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
            self.accounts
                .put(&receiver, &receiver_account)
                .expect("db error in TronDatabaseExt::tron_undelegate_resource writing receiver account");
        }
        1
    }
}

/// Constants pulled from `tron-actuator` (kept inline here so
/// `tron-tvm` doesn't depend on `tron-actuator` — the actuator
/// already depends on `tron-tvm` for shielded verifier keys, a
/// dep we can't cycle back through).
const TRX_PRECISION: i64 = 1_000_000;

/// Mainnet burn account ("Blackhole",
/// `TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy`) -- the self-target suicide
/// inheritor, java-tron `Repository.getBlackHoleAddress()`.
const BLACKHOLE_ADDRESS: [u8; 21] = [
    0x41, 0x77, 0x94, 0x4d, 0x19, 0xc0, 0x52, 0xb7, 0x3e, 0xe2, 0x28, 0x68, 0x23, 0xaa, 0x83,
    0xf8, 0x13, 0x8c, 0xb7, 0x03, 0x2f,
];

const FROZEN_PERIOD_MS: i64 = 3 * 24 * 60 * 60 * 1000;

/// java-tron `AccountCapsule.getFrozenV2BalanceWithDelegated(resource)` — the
/// held FreezeV2 of `resource` PLUS the balance this account has delegated OUT
/// for that resource. This is the basis the chain-wide weight is floored from in
/// the v2 freeze/unfreeze/cancel paths. Flooring `held` alone (as the old TVM
/// code did) drifts from java for any account that has delegated resources out,
/// since `floor(held + delegated)` ≠ `floor(held)`. For TRON_POWER (resource 2)
/// there is no delegation, so this reduces to `getTronPowerFrozenV2Balance()`.
fn frozen_v2_basis_with_delegated(account: &tron_proto::Account, resource: i32) -> i64 {
    let held: i64 = account
        .frozen_v2
        .iter()
        .filter(|f| f.r#type == resource)
        .map(|f| f.amount)
        .sum();
    let delegated = match resource {
        0 => account.delegated_frozen_v2_balance_for_bandwidth,
        1 => account
            .account_resource
            .as_ref()
            .map(|r| r.delegated_frozen_v2_balance_for_energy)
            .unwrap_or(0),
        _ => 0,
    };
    held.saturating_add(delegated)
}

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
            .put(&TronAddress::from_raw(owner), &acct)
            .unwrap();

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
            .put(&TronAddress::from_raw(contract), &acct)
            .unwrap();
        assert!(
            TronDatabaseExt::tron_is_contract(&db, evm_addr_from_tron(contract)),
            "contract with non-empty code_hash must be is_contract == true"
        );
    }

    #[test]
    fn is_contract_returns_false_for_eoa_and_missing() {
        let db = make_db();
        let eoa = tron_addr(0xdd);
        db.accounts
            .put(
                &TronAddress::from_raw(eoa),
                &Account {
                    address: eoa.to_vec(),
                    code_hash: vec![],
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(!TronDatabaseExt::tron_is_contract(&db, evm_addr_from_tron(eoa)));
        assert!(!TronDatabaseExt::tron_is_contract(
            &db,
            evm_addr_from_tron(tron_addr(0xee))
        ));
    }

    // ---- v2 stake weight: with-delegated basis + TRON_POWER (java parity) ----

    use tron_chainbase::{
        DelegatedResourceStore, DelegationStore, DynamicPropertiesStore, VotesStore,
    };
    use tron_proto::account::{AccountResource, FreezeV2, UnFreezeV2};

    /// A `TronDatabase` wired with the staking stores + an `ALLOW_TVM_FREEZE_V2`
    /// dyn_props so the v2 freeze/unfreeze/cancel bridges execute.
    fn make_staking_db() -> (TronDatabase, Arc<DynamicPropertiesStore>) {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let accounts = Arc::new(AccountStore::new(backend));
        let code = Arc::new(CodeStore::new(Arc::new(MemBackend::new())));
        let storage = Arc::new(StorageRowStore::new(Arc::new(MemBackend::new())));
        let dyn_props = Arc::new(DynamicPropertiesStore::new(Arc::new(MemBackend::new())));
        dyn_props.put_long(b"ALLOW_TVM_FREEZE_V2", 1);
        dyn_props.put_long(b"UNFREEZE_DELAY_DAYS", 14);
        let votes = Arc::new(VotesStore::new(Arc::new(MemBackend::new())));
        let delegated = Arc::new(DelegatedResourceStore::new(Arc::new(MemBackend::new())));
        let delegation = Arc::new(DelegationStore::new(Arc::new(MemBackend::new())));
        let db = TronDatabase::new(accounts, code, storage).with_staking_stores(
            dyn_props.clone(),
            Some(votes),
            delegated,
            delegation,
        );
        (db, dyn_props)
    }

    /// Regression: the TVM `freezeBalanceV2` weight delta must floor the
    /// `getFrozenV2BalanceWithDelegated` basis (held + delegated-OUT), NOT held
    /// alone. With held=0.4 TRX + delegated-out=0.3 TRX (basis 0.7) and a 1.5-TRX
    /// freeze, java adds `floor(2.2)-floor(0.7) = 2`; the old held-only code added
    /// `floor(1.9)-floor(0.4) = 1` — a permanent `TOTAL_ENERGY_WEIGHT` drift.
    #[test]
    fn tvm_freeze_v2_floors_weight_on_with_delegated_basis() {
        let (db, dyn_props) = make_staking_db();
        let owner = tron_addr(0x51);
        db.accounts
            .put(
                &TronAddress::from_raw(owner),
                &Account {
                    address: owner.to_vec(),
                    balance: 100_000_000,
                    frozen_v2: vec![FreezeV2 { r#type: 1, amount: 400_000 }],
                    account_resource: Some(AccountResource {
                        delegated_frozen_v2_balance_for_energy: 300_000,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut db = db;
        let r = db.tron_freeze_balance_v2(evm_addr_from_tron(owner), 1_500_000, 1);
        assert_eq!(r, 1, "freeze should succeed");
        assert_eq!(
            dyn_props.total_energy_weight(),
            2,
            "energy weight must use with-delegated basis: floor(2.2)-floor(0.7)=2 (old held-only bug gave 1)"
        );
    }

    /// Regression: the TVM v2 freeze/unfreeze must update `TOTAL_TRON_POWER_WEIGHT`
    /// for resource TRON_POWER (2) — the old code's `_ => {}` arm dropped it.
    #[test]
    fn tvm_freeze_v2_updates_tron_power_weight() {
        let (db, dyn_props) = make_staking_db();
        let owner = tron_addr(0x52);
        db.accounts
            .put(
                &TronAddress::from_raw(owner),
                &Account { address: owner.to_vec(), balance: 100_000_000, ..Default::default() },
            )
            .unwrap();
        let mut db = db;
        assert_eq!(db.tron_freeze_balance_v2(evm_addr_from_tron(owner), 5_000_000, 2), 1);
        assert_eq!(
            dyn_props.total_tron_power_weight(),
            5,
            "TRON_POWER freeze must bump TOTAL_TRON_POWER_WEIGHT (floor(5e6/1e6)=5)"
        );
        // And unfreezing it back removes the weight.
        assert_eq!(db.tron_unfreeze_balance_v2(evm_addr_from_tron(owner), 5_000_000, 2), 1);
        assert_eq!(dyn_props.total_tron_power_weight(), 0, "unfreeze must restore TP weight");
    }

    /// Regression: TVM `cancelAllUnfreezeV2` must (a) withdraw EXPIRED pending
    /// unfreezes to BALANCE (not re-freeze them) and (b) restore the weight for
    /// the NOT-expired ones. The old code re-froze everything and never touched
    /// the weight.
    #[test]
    fn tvm_cancel_all_unfreeze_v2_splits_expired_and_restores_weight() {
        let (db, dyn_props) = make_staking_db();
        dyn_props.save_latest_block_header_timestamp(1_000_000);
        let owner = tron_addr(0x53);
        db.accounts
            .put(
                &TronAddress::from_raw(owner),
                &Account {
                    address: owner.to_vec(),
                    balance: 10_000_000,
                    // already-counted-out weight is 0 here (no held frozen).
                    unfrozen_v2: vec![
                        // expired (expire <= now) → withdraw to balance.
                        UnFreezeV2 { r#type: 1, unfreeze_amount: 2_000_000, unfreeze_expire_time: 500_000 },
                        // not expired (expire > now) → re-freeze + weight.
                        UnFreezeV2 { r#type: 1, unfreeze_amount: 3_000_000, unfreeze_expire_time: 2_000_000 },
                    ],
                    ..Default::default()
                },
            )
            .unwrap();
        let mut db = db;
        assert_eq!(db.tron_cancel_all_unfreeze_v2(evm_addr_from_tron(owner)), 1);
        let acct = db.accounts.get(&TronAddress::from_raw(owner)).unwrap().unwrap();
        let held_en: i64 = acct.frozen_v2.iter().filter(|f| f.r#type == 1).map(|f| f.amount).sum();
        assert_eq!(held_en, 3_000_000, "only the not-expired entry is re-staked");
        assert!(acct.unfrozen_v2.is_empty(), "pending unfreezes cleared");
        assert_eq!(acct.balance, 12_000_000, "expired 2 TRX withdrawn to balance");
        assert_eq!(
            dyn_props.total_energy_weight(),
            3,
            "weight restored only for the re-staked 3 TRX (floor(3e6/1e6)=3)"
        );
        // java's `cancelAllUnfreezeV2` does TWO increaseNonce here: one at the
        // top + one for the auto-withdrawn expired unfreeze.
        assert_eq!(db.create_nonce, 2, "always-bump + expired-withdraw bump");
    }

    /// Every state-mutating Stake 1.0/2.0 opcode bumps the per-tx
    /// internal-transaction nonce counter once at the top (java
    /// `Program.increaseNonce`, before its `validate`) — so a nested CREATE
    /// later in the same tx derives the java-tron-correct address. Exercised
    /// store-less: the bump fires before each bridge's store guard, then the
    /// bridge returns 0.
    #[test]
    fn staking_opcodes_each_bump_internal_tx_nonce_once() {
        let mut db = make_db();
        let caller = evm_addr_from_tron(tron_addr(0xaa));
        let receiver = evm_addr_from_tron(tron_addr(0xbb));
        assert_eq!(db.create_nonce, 0);
        db.tron_freeze(caller, 1_000_000, 3, 0, None);
        db.tron_unfreeze(caller, 0, None);
        db.tron_freeze_balance_v2(caller, 1_000_000, 0);
        db.tron_unfreeze_balance_v2(caller, 1_000_000, 0);
        db.tron_withdraw_expire_unfreeze(caller);
        db.tron_cancel_all_unfreeze_v2(caller);
        db.tron_delegate_resource(caller, 1_000_000, receiver, 0, false, 0);
        db.tron_undelegate_resource(caller, 1_000_000, receiver, 0);
        db.tron_vote_witness(caller, &[]);
        db.tron_withdraw_reward(caller);
        assert_eq!(
            db.create_nonce, 10,
            "10 staking opcodes, one nonce bump each"
        );
    }

    /// SELFDESTRUCT bumps the nonce once (after `canSuicide` validation, which
    /// java runs in the opcode action before calling the handler). A clean
    /// account with no frozen/delegated balances passes validation.
    #[test]
    fn selfdestruct_bumps_internal_tx_nonce_after_validation() {
        let (db, dyn_props) = make_staking_db();
        dyn_props.save_latest_block_header_timestamp(1_000_000);
        let owner = tron_addr(0x61);
        let obtainer = tron_addr(0x62);
        for a in [owner, obtainer] {
            db.accounts
                .put(
                    &TronAddress::from_raw(a),
                    &Account {
                        address: a.to_vec(),
                        balance: 5_000_000,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let mut db = db;
        let rc = db.tron_suicide(
            evm_addr_from_tron(owner),
            evm_addr_from_tron(obtainer),
            true,
        );
        assert_eq!(rc, 0, "valid suicide returns ok");
        assert_eq!(db.create_nonce, 1, "one bump after canSuicide validation");
    }
}
