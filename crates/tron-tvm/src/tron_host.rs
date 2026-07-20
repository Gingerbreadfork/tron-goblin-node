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

use std::sync::Arc;

use revm::context_interface::TronDatabaseExt;
use revm::primitives::Address;
use tron_chainbase::DelegatedResourceStore;
use tron_crypto::address::Address as TronAddress;

use crate::database::{evm_to_tron_address, tron_to_evm_address, TronDatabase};
use crate::staking_journal::StakingEntry;

// ---- Per-frame rollback journaling for the staking / SELFDESTRUCT bridges ----
//
// Every state-mutating staking / suicide write below goes through one of these
// helpers, which records a reversing entry on the shared `staking_journal`
// (snapshot of the prior row, or the signed weight delta) BEFORE applying the
// mutation. The `Trc10Inspector` unwinds a frame's entries on revert. When no
// journal is attached (read-only / unit-test setups) the helpers fall straight
// through to the underlying store, preserving the historical behaviour.
//
// Snapshotting the CURRENT stored value immediately before each write means a
// LIFO unwind restores the exact pre-frame state even when one frame mutates
// the same row several times (the earliest snapshot wins on restore) — the same
// guarantee `Trc10Inspector::cs_journal` relies on.
impl TronDatabase {
    /// Record a reversing snapshot of `addr`'s current `Account` row WITHOUT
    /// writing anything. Used before an out-of-line account mutation the bridge
    /// doesn't perform via `put_account_journaled` — chiefly the reward settle
    /// (`withdraw_reward_tvm` writes `allowance` straight to the store). On a
    /// LIFO unwind the later post-settle snapshot restores first and this
    /// pre-settle snapshot restores the true pre-frame row last, so both the
    /// settle's and the bridge's account writes are reversed.
    fn snapshot_account(&self, addr: &TronAddress) {
        if let Some(journal) = &self.staking_journal {
            let prior = self.accounts.get(addr).ok().flatten();
            journal.lock().expect("staking journal mutex poisoned").push(
                StakingEntry::Account { addr: *addr, prior },
            );
        }
    }

    /// Record a reversing snapshot of `addr`'s current `Votes` row WITHOUT
    /// writing — used before an out-of-line votes mutation (e.g.
    /// `update_vote_after_unstake`, which writes the votes store itself).
    fn snapshot_votes(&self, addr: &TronAddress) {
        if let Some(journal) = &self.staking_journal {
            if let Some(votes_store) = &self.votes {
                let prior = votes_store.get(addr).ok().flatten();
                journal.lock().expect("staking journal mutex poisoned").push(
                    StakingEntry::Votes { addr: *addr, prior },
                );
            }
        }
    }

    /// Record reversing snapshots of every `DelegationStore` row the TVM
    /// reward settle (`withdraw_reward_tvm` → `VoteRewardUtil.withdrawReward`)
    /// can write for `addr`, WITHOUT writing anything. Must be called BEFORE
    /// the settle. The settle writes at most three rows for the voter:
    /// `set_begin_cycle` (the raw-address key), `set_end_cycle` (the
    /// `end-<hex>` key), and `set_account_vote` for the *next* cycle
    /// (`<current_cycle>-<hex>-account-vote`). It only reads (never writes)
    /// witness-Vi / reward / vote rows, so those need no snapshot.
    ///
    /// The account-vote key depends on the current cycle number, which the
    /// settle reads from `dyn_props`; capture it the same way so the snapshot
    /// covers the exact key the settle will touch.
    ///
    /// java scopes these writes to the frame's `RepositoryImpl.delegationCache`
    /// (`updateBeginCycle` / `updateEndCycle` / `updateAccountVote` →
    /// `putDelegation`), flushed to the parent only on frame `commit()` and
    /// dropped on revert. On a LIFO unwind these snapshots restore the prior
    /// row bytes (or delete a freshly created row), so an inner-frame revert —
    /// even when the top-level tx succeeds — leaves no delegation trace, exactly
    /// as java discards the uncommitted child deposit.
    fn snapshot_delegation_rows(
        &self,
        delegation: &Arc<tron_chainbase::DelegationStore>,
        addr: &TronAddress,
    ) {
        use tron_chainbase::DelegationStore;
        let Some(journal) = &self.staking_journal else {
            return;
        };
        let current_cycle = self
            .dyn_props
            .as_ref()
            .map(|dp| dp.current_cycle_number())
            .unwrap_or(0);
        // The settle writes account_vote at `end_cycle = current_cycle` (the
        // bulk path) — see `withdraw_reward`. The no-live-votes path writes only
        // begin_cycle. Snapshot the union of keys either path can touch.
        let keys = [
            DelegationStore::begin_cycle_key(addr).to_vec(),
            DelegationStore::end_cycle_key(addr),
            DelegationStore::account_vote_key(current_cycle, addr),
        ];
        let mut guard = journal.lock().expect("staking journal mutex poisoned");
        for key in keys {
            let prior = delegation.get_raw(&key).ok().flatten();
            guard.push(StakingEntry::Delegation {
                store: Arc::clone(delegation),
                key,
                prior,
            });
        }
    }

    /// Snapshot `addr`'s current `Account` row (if the journal is attached),
    /// then write `account` to the store.
    fn put_account_journaled(&self, addr: &TronAddress, account: &tron_proto::Account) {
        if let Some(journal) = &self.staking_journal {
            let prior = self.accounts.get(addr).ok().flatten();
            journal.lock().expect("staking journal mutex poisoned").push(
                StakingEntry::Account { addr: *addr, prior },
            );
        }
        self.accounts
            .put(addr, account)
            .expect("db error writing account in staking bridge");
    }

    /// Snapshot `addr`'s current `Votes` row, then write `votes`.
    fn put_votes_journaled(
        &self,
        votes_store: &tron_chainbase::VotesStore,
        addr: &TronAddress,
        votes: &tron_proto::Votes,
    ) {
        if let Some(journal) = &self.staking_journal {
            let prior = votes_store.get(addr).ok().flatten();
            journal.lock().expect("staking journal mutex poisoned").push(
                StakingEntry::Votes { addr: *addr, prior },
            );
        }
        votes_store
            .put(addr, votes)
            .expect("db error writing votes in staking bridge");
    }

    /// Snapshot the current `DelegatedResource` row at `key`, then write
    /// `record` via the raw key.
    fn put_delegated_journaled(
        &self,
        resources: &DelegatedResourceStore,
        key: &[u8],
        record: &tron_proto::DelegatedResource,
    ) {
        if let Some(journal) = &self.staking_journal {
            let prior = resources.get_raw(key).ok().flatten();
            journal.lock().expect("staking journal mutex poisoned").push(
                StakingEntry::DelegatedResource { key: key.to_vec(), prior },
            );
        }
        resources
            .put_raw(key, record)
            .expect("db error writing delegated resource in staking bridge");
    }

    /// Snapshot the two V2 `DelegatedResourceAccountIndex` rows for `(from, to)`
    /// and record a reversing journal entry, to be called BEFORE the bridge
    /// writes (delegate) or clears (undelegate) them. Gives the RPC-only index
    /// the same per-frame revert safety the consensus `DelegatedResource` row
    /// has via `put_delegated_journaled`: a delegate/undelegate in an inner
    /// frame that reverts leaves the index rows untouched, as in java's
    /// discarded child `Repository`. No-op when no journal is attached.
    fn journal_index_rows(
        &self,
        index: &Arc<tron_chainbase::DelegatedResourceAccountIndexStore>,
        from: &tron_crypto::address::Address,
        to: &tron_crypto::address::Address,
    ) {
        use tron_chainbase::DelegatedResourceAccountIndexStore as Idx;
        let Some(journal) = &self.staking_journal else {
            return;
        };
        let from_key = Idx::v2_from_key(from, to).to_vec();
        let to_key = Idx::v2_to_key(from, to).to_vec();
        let from_prior = index.get_raw(&from_key).ok().flatten();
        let to_prior = index.get_raw(&to_key).ok().flatten();
        journal
            .lock()
            .expect("staking journal mutex poisoned")
            .push(StakingEntry::DelegatedResourceIndex {
                index: Arc::clone(index),
                from_key,
                from_prior,
                to_key,
                to_prior,
            });
    }

    /// Apply a `TOTAL_NET_WEIGHT` delta, recording it for reversal.
    fn add_net_weight_journaled(
        &self,
        dyn_props: &tron_chainbase::DynamicPropertiesStore,
        delta: i64,
    ) {
        if delta == 0 {
            return;
        }
        if let Some(journal) = &self.staking_journal {
            journal
                .lock()
                .expect("staking journal mutex poisoned")
                .push(StakingEntry::NetWeight { delta });
        }
        dyn_props.add_total_net_weight_unclamped(delta);
    }

    /// Apply a `TOTAL_ENERGY_WEIGHT` delta, recording it for reversal.
    fn add_energy_weight_journaled(
        &self,
        dyn_props: &tron_chainbase::DynamicPropertiesStore,
        delta: i64,
    ) {
        if delta == 0 {
            return;
        }
        if let Some(journal) = &self.staking_journal {
            journal
                .lock()
                .expect("staking journal mutex poisoned")
                .push(StakingEntry::EnergyWeight { delta });
        }
        dyn_props.add_total_energy_weight_unclamped(delta);
    }

    /// Apply a `TOTAL_TRON_POWER_WEIGHT` delta, recording it for reversal.
    fn add_tron_power_weight_journaled(
        &self,
        dyn_props: &tron_chainbase::DynamicPropertiesStore,
        delta: i64,
    ) {
        if delta == 0 {
            return;
        }
        if let Some(journal) = &self.staking_journal {
            journal
                .lock()
                .expect("staking journal mutex poisoned")
                .push(StakingEntry::TronPowerWeight { delta });
        }
        dyn_props.add_total_tron_power_weight_unclamped(delta);
    }
}

impl TronDatabaseExt for TronDatabase {
    fn tron_token_balance(&self, address: Address, token_id: i64) -> i64 {
        let tron_addr = evm_to_tron_address(&address);
        let Ok(Some(mut account)) = self.accounts.get(&tron_addr) else {
            return 0;
        };
        // An asset-optimized account holds its TRC-10 balances in the separate
        // account-asset store, not inline; merge them so the TOKENBALANCE
        // opcode returns the real balance (java getTokenBalance -> getAssetV2
        // -> importAsset).
        tron_chainbase::import_all_asset(&mut account);
        // `Account.asset_v2` is keyed by decimal-string token_id (matches
        // java-tron's `Map<String, Long>` representation).
        account
            .asset_v2
            .get(&token_id.to_string())
            .copied()
            .unwrap_or(0)
    }

    fn tron_is_contract(&self, address: Address) -> bool {
        // A top-level `CreateSmartContract` deploy: java writes the
        // `SmartContract` row into the invoke's `rootRepository` BEFORE the init
        // code runs (`VMActuator.create` -> `rootRepository.createContract`), so
        // `address(this).isContract` inside the constructor is 1. Our top-level
        // deploy runs as a CALL to a pre-installed Normal-typed account and
        // writes no contract row until commit, so neither branch below would see
        // it. `top_level_deploy_version` is set once per transaction, only by
        // `execute_create`, for exactly that address (and is `None` for trigger
        // txs), so keying on it reproduces java's pre-init-code row.
        if let Some((deploy_addr, _)) = self.top_level_deploy_version {
            if deploy_addr == address {
                return true;
            }
        }
        let tron_addr = evm_to_tron_address(&address);
        // java-tron's ISCONTRACT (0xd4 → `Program.isContract`) returns true iff
        // the contract store holds a SmartContract row for the address
        // (`getContract(addr) != null`). A contract's row and its
        // Contract-typed account are written/deleted together on deploy/
        // selfdestruct, so `AccountType::Contract` is the equivalent signal.
        //
        // Do NOT gate on `Account.code_hash`: snapshot-imported contracts
        // routinely carry an EMPTY code_hash while their runtime code lives in
        // the address-keyed code store (see `basic_ref`'s comment). Gating on
        // code_hash made ISCONTRACT disagree with EXTCODESIZE and wrongly
        // return false for a real contract — reverting valid txs, e.g. SunSwap
        // TokenApprove's `isContract(token)` guard ("SafeERC20: call to
        // non-contract", live at block 83,361,039).
        if let Some(contracts) = &self.contracts {
            if matches!(contracts.get(&tron_addr), Ok(Some(_))) {
                return true;
            }
        }
        matches!(
            self.accounts.get(&tron_addr),
            Ok(Some(account)) if account.r#type == tron_proto::AccountType::Contract as i32
        )
    }

    fn tron_account_exists(&self, address: Address) -> bool {
        let tron_addr = evm_to_tron_address(&address);
        matches!(self.accounts.get(&tron_addr), Ok(Some(_)))
    }

    fn tron_is_precompile(&self, address: Address) -> bool {
        // java's `PrecompiledContracts.getContractForAddress` consults
        // `VMConfig`, which is loaded from the dynamic-properties store, so the
        // dispatch set is height-dependent for everything except 0x01..0x08.
        // With no store attached nothing dispatches, matching a `VMConfig` on
        // which no proposal has been activated.
        let Some(dp) = &self.dyn_props else {
            return false;
        };
        let proposals = crate::proposals::ProposalSet::from_store(dp);
        let addr: [u8; 20] = address.into();
        crate::precompiles::is_active_precompile(&addr, &proposals)
    }

    fn tron_account_exists_or_created(&self, address: Address) -> bool {
        // java `isDeadAccount` reads the IN-FLIGHT Repository, so an account
        // created earlier in THIS tx is visible. The committed-only
        // `tron_account_exists` misses it; also consult the same-tx
        // pending-created set so a same-tx-created inheritor (SELFDESTRUCT) /
        // receiver (FREEZE) is not wrongly treated as dead.
        self.tron_account_exists(address) || self.pending_created_contracts.contains_key(&address)
    }

    fn tron_contract_version(&self, address: Address) -> i32 {
        // The version of the contract whose code a CALL frame is about to
        // execute. java reads `invoke.getDeposit().getContract(codeAddress)
        // .getContractVersion()` (CALL child, `Program.java:1146`) and
        // `deployedContract.getContractVersion()` for the top-level frame
        // (`VMActuator.java:531`). A brand-new top-level CREATE is forced to
        // version 1 (`VMActuator.java:325,415`); we mirror that with the
        // per-tx override below, since the deploy's `SmartContract` row isn't
        // written until commit (so a plain store read would see 0 mid-deploy).
        if let Some((deploy_addr, version)) = self.top_level_deploy_version {
            if deploy_addr == address {
                return version;
            }
        }
        match &self.contracts {
            Some(contracts) => match contracts.get(&evm_to_tron_address(&address)) {
                Ok(Some(c)) => c.version,
                // No contract row (EOA / not-yet-committed deploy) → version 0,
                // matching java's `getContract(addr) == null` default.
                _ => 0,
            },
            None => 0,
        }
    }

    fn tron_allow_tvm_vote(&self) -> bool {
        // java `VMConfig.allowTvmVote()` — the `ALLOW_TVM_VOTE` proposal flag.
        // Gates the FREEZE/UNFREEZE (Stake 1.0) static-call guard.
        match &self.dyn_props {
            Some(dp) => dp.get_long(b"ALLOW_TVM_VOTE").unwrap_or(0) == 1,
            None => false,
        }
    }

    fn tron_allow_multi_sign(&self) -> bool {
        // java `VMConfig.allowMultiSign()` — the `ALLOW_MULTI_SIGN` proposal
        // (#20). Gates CALLTOKEN/TOKENBALANCE tokenId range validation.
        match &self.dyn_props {
            Some(dp) => dp.get_long(b"ALLOW_MULTI_SIGN").unwrap_or(0) == 1,
            None => false,
        }
    }

    fn tron_allow_tvm_solidity_059(&self) -> bool {
        // java `VMConfig.allowTvmSolidity059()` — the `ALLOW_TVM_SOLIDITY_059`
        // proposal (#32). Gates `Program.createAccountIfNotExist`, i.e. whether
        // a contract may create the recipient of a value/TRC-10 transfer.
        match &self.dyn_props {
            Some(dp) => dp.get_long(b"ALLOW_TVM_SOLIDITY_059").unwrap_or(0) == 1,
            None => false,
        }
    }

    fn tron_allow_tvm_constantinople(&self) -> bool {
        // java `VMConfig.allowTvmConstantinople()` — the
        // `ALLOW_TVM_CONSTANTINOPLE` proposal (#26). Selects `TransferException`
        // (consumed-only, TRANSFER_FAILED) over `BytecodeExecutionException`
        // (spend-all, UNKNOWN) when a transfer validation fails.
        match &self.dyn_props {
            Some(dp) => dp.get_long(b"ALLOW_TVM_CONSTANTINOPLE").unwrap_or(0) == 1,
            None => false,
        }
    }

    fn tron_allow_tvm_transfer_trc10(&self) -> bool {
        // java `VMConfig.allowTvmTransferTrc10()` — the
        // `ALLOW_TVM_TRANSFER_TRC10` proposal (#18).
        match &self.dyn_props {
            Some(dp) => dp.get_long(b"ALLOW_TVM_TRANSFER_TRC10").unwrap_or(0) == 1,
            None => false,
        }
    }

    fn tron_allow_tvm_compatible_evm(&self) -> bool {
        // java `VMConfig.allowTvmCompatibleEvm()` — the `ALLOW_TVM_COMPATIBLE_EVM`
        // proposal flag (#66). First half of the per-frame 1/64-retention /
        // GASPRICE version gate.
        match &self.dyn_props {
            Some(dp) => dp.get_long(b"ALLOW_TVM_COMPATIBLE_EVM").unwrap_or(0) == 1,
            None => false,
        }
    }

    fn tron_energy_fee(&self) -> i64 {
        // java `DynamicPropertiesStore.getEnergyFee()` — pushed by BASEFEE and
        // by version-1 GASPRICE.
        match &self.dyn_props {
            Some(dp) => dp.energy_fee(),
            None => 0,
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
    ///
    /// Before `ALLOW_TVM_SOLIDITY_059` an obtainer with no account row
    /// cannot be created, so the inheritance may fail outright: see the
    /// `createAccountIfNotExist` gate below for the `-2` / `-3` returns.
    fn tron_suicide(
        &mut self,
        owner: Address,
        obtainer: Address,
        will_destroy: bool,
        owner_balance: i64,
    ) -> i64 {
        use tron_types::resource::{self as res, ResourceKind, ResourceGates};

        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0; // read-only setup: nothing to validate or move
        };
        let owner_t = evm_to_tron_address(&owner);
        let obtainer_t = evm_to_tron_address(&obtainer);
        let owner_lookup = self.accounts.get(&owner_t);
        // Env-gated entry diagnostic (TRON_TRACE_SUICIDE_TX=<root-tx-hex-prefix>):
        // log every tron_suicide invocation within the matching root tx — its
        // owner/obtainer, the destroy flag, and whether the owner row resolves
        // in the (session-wrapped) AccountStore. A `false` here means the
        // SELFDESTRUCT bails before the TRC-10/freeze sweep, so the inheritor
        // never receives the contract's holdings — the manifestation behind a
        // missing-inheritor-credit divergence. Off by default.
        if let Ok(want_tx) = std::env::var("TRON_TRACE_SUICIDE_TX") {
            let txid: String =
                self.root_tx_id.iter().map(|b| format!("{b:02x}")).collect();
            let want = want_tx.trim().trim_start_matches("0x").to_ascii_lowercase();
            if !want.is_empty() && txid.starts_with(&want) {
                eprintln!(
                    "SUICIDETRACE_ENTRY tx={} owner={} obtainer={} will_destroy={} in_store={}",
                    &txid[..16.min(txid.len())],
                    owner_t.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    obtainer_t.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    will_destroy,
                    matches!(owner_lookup, Ok(Some(_))),
                );
            }
        }
        // java reads the dying contract from the in-flight `Repository`
        // (`getContractState().getAccount(owner)`), which layers same-tx
        // writes — including a contract CREATE/CREATE2-deployed THIS tx — over
        // committed state. Our `self.accounts` is the session-wrapped COMMITTED
        // store and does NOT reflect a same-tx deployment (the revm journal
        // holds it until the final `DatabaseCommit::commit`). A SELFDESTRUCT by
        // a contract created earlier in the SAME tx therefore finds no owner row
        // and used to bail before `createAccountIfNotExist(obtainer)` ran —
        // orphaning the inheritor (java creates it empty and persists it; with
        // no inheritor row our commit-time empty-account skip then prunes the
        // beneficiary revm independently touched, leaving the target missing for
        // later txs). When the owner was created locally this tx, synthesize the
        // empty account the in-flight Repository would have returned (a fresh
        // CREATE contract holds no TRX/TRC-10/freeze until something endows it,
        // so an all-default row is byte-equivalent) and proceed, so the
        // inheritor is created and the freeze/TRC-10 sweep still runs against
        // whatever the row holds.
        let owner_created_locally = self.pending_created_contracts.contains_key(&owner);
        let mut owner_account = match owner_lookup {
            Ok(Some(acc)) => acc,
            // Owner deployed THIS tx but not yet in the committed store: use the
            // empty account the in-flight Repository would return, so the
            // inheritor still gets created and any holdings still sweep.
            Ok(None) if owner_created_locally => tron_proto::Account {
                address: owner_t.as_bytes().to_vec(),
                ..Default::default()
            },
            // No owner row and not a same-tx creation, or a read error: nothing
            // to validate or move (matches the historical bail).
            _ => return 0,
        };

        let now_ms = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        let allow_freeze = dyn_props.get_long(b"ALLOW_TVM_FREEZE").unwrap_or(0) == 1;
        // java derives allowTvmFreezeV2 from supportUnfreezeDelay()
        // (UNFREEZE_DELAY_DAYS > 0) — there is NO ALLOW_TVM_FREEZE_V2 key, so
        // reading it returned false on every real snapshot.
        let allow_freeze_v2 = dyn_props.support_unfreeze_delay();
        let allow_vote = dyn_props.get_long(b"ALLOW_TVM_VOTE").unwrap_or(0) == 1;
        let allow_trc10 = dyn_props.get_long(b"ALLOW_TVM_TRANSFER_TRC10").unwrap_or(0) == 1;
        // java `VMConfig.allowTvmSolidity059()` / `allowTvmConstantinople()` —
        // the gate on `createAccountIfNotExist` and the selector for the
        // failure flavour when the obtainer cannot be created. See the
        // inheritor block below.
        let allow_059 = dyn_props.get_long(b"ALLOW_TVM_SOLIDITY_059").unwrap_or(0) == 1;
        let allow_constantinople = dyn_props
            .get_long(b"ALLOW_TVM_CONSTANTINOPLE")
            .unwrap_or(0)
            == 1;
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
                // Snapshot before the settle writes `allowance` to the store.
                self.snapshot_account(&owner_t);
                // ...and the begin/end-cycle + account-vote rows the settle
                // writes into the delegation store (java's frame-scoped
                // delegationCache — discarded on revert).
                self.snapshot_delegation_rows(&delegation, &owner_t);
                // `VoteRewardUtil.withdrawReward` — gated on ALLOW_TVM_VOTE
                // (the enclosing `allow_vote` already enforces it).
                let _ = crate::reward::withdraw_reward_tvm(
                    &owner_t,
                    &self.accounts,
                    &delegation,
                    &dyn_props,
                    self.reward_vi.as_deref(),
                );
                // Re-read: the settle may have grown the allowance.
                if let Ok(Some(acc)) = self.accounts.get(&owner_t) {
                    owner_account = acc;
                }
            }
            if !owner_account.votes.is_empty() {
                if let Some(votes_store) = self.votes.clone() {
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
                    self.put_votes_journaled(&votes_store, &owner_t, &votes_row);
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
        // `createAccountIfNotExist` -> `createNormalAccount`). A freshly created
        // inheritor is stamped with the head-block timestamp and, when
        // ALLOW_MULTI_SIGN is on, gets the default owner+active[id=2]
        // permission — exactly as java's `createNormalAccount` builds it. An
        // existing inheritor keeps its row untouched.
        //
        // `createAccountIfNotExist` only creates once ALLOW_TVM_SOLIDITY_059
        // (#32) is active. Before it, an obtainer with no row stays absent and
        // java's outcome splits three ways on the dying contract's balance,
        // because `MUtil.transfer` returns at `if (0 == amount)` before it can
        // validate the recipient:
        //
        //  * balance > 0 — `VMUtils.validateForSmartContract` throws "no
        //    ToAccount"; the catch wraps it in a `TransferException` under
        //    ALLOW_TVM_CONSTANTINOPLE (#26) and a `BytecodeExecutionException`
        //    before it. Nothing is inherited and the transaction dies.
        //  * balance == 0 with ALLOW_TVM_TRANSFER_TRC10 — the transfer no-ops,
        //    then `MUtil.transferAllToken` calls `importAllAsset()` on the
        //    obtainer's null `AccountCapsule` and NPEs. An NPE is not a
        //    `ContractValidateException`, so the local catch misses it and
        //    `VMActuator`'s `catch (Throwable)` spends all energy — always the
        //    UNKNOWN flavour, never TRANSFER_FAILED.
        //  * balance == 0 without TRC-10 — java SUCCEEDS, having simply never
        //    created the obtainer. The owner is still destroyed; only the
        //    phantom inheritor row must not appear.
        //
        // Existence is journal-aware to match java's in-flight `Repository`.
        // The self-target path never reaches here with `inheritor_t` set to the
        // obtainer: java's `owner == obtainer` branch bypasses
        // `createAccountIfNotExist` and `MUtil.transfer` entirely, sweeping to
        // the always-present blackhole instead.
        let inheritor_absent = !self.tron_account_exists_or_created(tron_to_evm_address(
            &inheritor_t,
        ));
        let inheritor_uncreatable = !allow_059 && !self_target && inheritor_absent;
        if inheritor_uncreatable {
            if owner_balance > 0 {
                return if allow_constantinople { -2 } else { -3 };
            }
            if allow_trc10 {
                return -3;
            }
        }
        let (mut inheritor_account, inheritor_is_new) = match self.accounts.get(&inheritor_t) {
            Ok(Some(acc)) => (acc, false),
            _ => (
                tron_proto::Account {
                    address: inheritor_t.as_bytes().to_vec(),
                    create_time: now_ms,
                    ..Default::default()
                },
                true,
            ),
        };
        if inheritor_is_new {
            tron_chainbase::apply_default_account_permissions(&mut inheritor_account, &dyn_props);
        }

        // ---- TRC-10 sweep ----
        if allow_trc10 {
            // An asset-optimized contract holds its TRC-10 balances in the
            // account-asset store, not inline; import them before the sweep so
            // SELFDESTRUCT forwards the contract's real token holdings to the
            // inheritor (java AccountCapsule.getAssetMapV2 imports first).
            // Env-gated diagnostic (TRON_TRACE_SUICIDE=<owner-21-byte-tron-hex>):
            // log the dying owner's asset state BEFORE and AFTER import so the
            // lost-token divergence at this exact sweep can be confirmed (whether
            // the loss is asset_optimized=false skipping the store rows, or the
            // store simply having no rows for the owner). Off by default.
            let suicide_trace = std::env::var("TRON_TRACE_SUICIDE").ok().filter(|w| {
                let w = w.trim().trim_start_matches("0x").to_ascii_lowercase();
                let hx: String =
                    owner_t.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                !w.is_empty() && hx == w
            });
            if suicide_trace.is_some() {
                let store_rows = tron_chainbase::account_asset_rows_for_trace(&owner_t);
                eprintln!(
                    "SUICIDETRACE owner={} optimized={} inline_pre={:?} store_rows={:?} \
                     inheritor={} will_destroy={}",
                    owner_t.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    owner_account.asset_optimized,
                    owner_account.asset_v2,
                    store_rows,
                    inheritor_t.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    will_destroy,
                );
            }
            tron_chainbase::import_all_asset(&mut owner_account);
            if suicide_trace.is_some() {
                eprintln!("SUICIDETRACE owner_post_import asset_v2={:?}", owner_account.asset_v2);
            }
            for (token, amount) in std::mem::take(&mut owner_account.asset_v2) {
                if amount == 0 {
                    continue;
                }
                let slot = inheritor_account.asset_v2.entry(token).or_insert(0);
                *slot = slot.saturating_add(amount);
            }
            if suicide_trace.is_some() {
                eprintln!(
                    "SUICIDETRACE inheritor_post_sweep asset_v2={:?}",
                    inheritor_account.asset_v2
                );
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
            self.add_net_weight_journaled(&dyn_props, -frozen_bw / TRX_PRECISION);
            self.add_energy_weight_journaled(&dyn_props, -frozen_energy / TRX_PRECISION);
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
            let harden = dyn_props.allow_harden_resource_calculation();
            res::update_usage(&mut owner_account, ResourceKind::Bandwidth, now_slot, gates, harden);
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
                    harden,
                );
            }
            res::update_usage(&mut owner_account, ResourceKind::Energy, now_slot, gates, harden);
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
                    harden,
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

        self.put_account_journaled(&owner_t, &owner_account);
        // Reaching here with `inheritor_uncreatable` set is java's succeeding
        // sub-case (balance 0, TRC-10 inactive): the obtainer was never created,
        // so no row may be written for it. ALLOW_TVM_FREEZE (#52) requires #32,
        // so the freeze sweeps above cannot have credited it either.
        if inheritor_t != owner_t && !inheritor_uncreatable {
            self.put_account_journaled(&inheritor_t, &inheritor_account);
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
        // java `OperationActions.freezeAction`: once Stake-2.0 freeze-v2 is active
        // (`allowTvmFreezeV2` is wired straight to `supportUnfreezeDelay`), the
        // deprecated V1 FREEZE opcode pushes ZERO and performs no freeze, no
        // weight change, and — because java never reaches `Program.freeze` — no
        // nonce bump. Gate above the nonce bump to match. Without this gate the
        // opcode kept crediting TOTAL_NET_WEIGHT, inflating the chain-wide weight
        // and shrinking every account's net limit.
        if self
            .dyn_props
            .as_ref()
            .map_or(false, |dp| dp.support_unfreeze_delay())
        {
            return 0;
        }
        // java `Program.freeze` bumps the nonce at the top of the handler,
        // before its validate (`increaseNonce` precedes `processor.validate`).
        self.note_internal_tx_nonce();
        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0;
        };
        let Some(resources) = self.delegated_resources.clone() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);

        // ---- java `FreezeBalanceProcessor.validate`, all read-only ----
        //
        // java runs validate + execute inside `getContractState()
        // .newRepositoryChild()` and calls `repository.commit()` only after
        // both succeed (Program.java:1931/1950), so a failing validate leaves
        // NOTHING behind — including the receiver account its own delegation
        // branch may have created. Compute the whole verdict before writing
        // anything, the same shape `tron_vote_witness` uses below.
        let Ok(Some(mut owner_account)) = self.accounts.get(&owner) else {
            return 0;
        };
        if frozen_balance <= 0
            || frozen_balance < TRX_PRECISION
            || frozen_balance > owner_account.balance
        {
            return 0;
        }
        // `FrozenCount must be 0 or 1` — java rejects an owner whose legacy
        // `frozen` list already holds more than one entry.
        if owner_account.frozen.len() > 1 {
            return 0;
        }
        // java's ResourceCode switch accepts only BANDWIDTH(0) / ENERGY(1);
        // TRON_POWER(2) is a Stake-2.0 code and throws here.
        if resource_type != 0 && resource_type != 1 {
            return 0;
        }

        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
        // v1: duration in days. The opcode handler currently passes
        // `0` for duration (java-tron's `FREEZE` opcode doesn't
        // expose duration on the EVM stack — actuator derives it
        // from chain params). Default to 3 days (the chain-minimum)
        // so the resulting Frozen entry has a sensible expiration.
        let duration_days = frozen_duration.max(3);
        let expire = now + duration_days * FROZEN_PERIOD_MS / 3;

        // `!FastByteComparisons.isEqual(ownerAddress, receiverAddress)` selects
        // the delegating branch. A receiver with no account row is created as a
        // normal account (`repo.createNormalAccount`) — stamped with the
        // head-block timestamp and, under ALLOW_MULTI_SIGN, the default
        // owner+active permission — but a Contract-type receiver is then
        // rejected, and java's discarded child Repository takes that fresh row
        // with it. Holding the new row here until the success path below
        // reproduces that atomicity.
        let receiver = receiver_address
            .map(|r| evm_to_tron_address(&r))
            .unwrap_or(owner);
        let delegating = receiver != owner;
        let mut receiver_account = if delegating {
            let acct = match self.accounts.get(&receiver) {
                Ok(Some(a)) => a,
                _ => {
                    let mut a = tron_proto::Account {
                        address: receiver.as_bytes().to_vec(),
                        create_time: now,
                        ..Default::default()
                    };
                    tron_chainbase::apply_default_account_permissions(&mut a, &dyn_props);
                    a
                }
            };
            if acct.r#type == tron_proto::AccountType::Contract as i32 {
                return 0;
            }
            Some(acct)
        } else {
            None
        };

        // ---- java `FreezeBalanceProcessor.execute` ----
        if let Some(receiver_account) = receiver_account.as_mut() {
            // `delegateResource`: insert-or-update the (owner, receiver)
            // DelegatedResource row, then credit the receiver's acquired
            // balance. The v1 key is the bare `from || to` concatenation
            // (`DelegatedResourceCapsule.createDbKey`).
            let key = DelegatedResourceStore::v1_key(&owner, &receiver);
            let mut record = resources
                .get_raw(&key)
                .expect("db error in TronDatabaseExt::tron_freeze reading delegated resource record")
                .unwrap_or_default();
            record.from = owner.as_bytes().to_vec();
            record.to = receiver.as_bytes().to_vec();
            if resource_type == 0 {
                record.frozen_balance_for_bandwidth = record
                    .frozen_balance_for_bandwidth
                    .saturating_add(frozen_balance);
                record.expire_time_for_bandwidth = expire;
                owner_account.delegated_frozen_balance_for_bandwidth = owner_account
                    .delegated_frozen_balance_for_bandwidth
                    .saturating_add(frozen_balance);
                receiver_account.acquired_delegated_frozen_balance_for_bandwidth =
                    receiver_account
                        .acquired_delegated_frozen_balance_for_bandwidth
                        .saturating_add(frozen_balance);
            } else {
                record.frozen_balance_for_energy = record
                    .frozen_balance_for_energy
                    .saturating_add(frozen_balance);
                record.expire_time_for_energy = expire;
                let owner_res = owner_account
                    .account_resource
                    .get_or_insert_with(Default::default);
                owner_res.delegated_frozen_balance_for_energy = owner_res
                    .delegated_frozen_balance_for_energy
                    .saturating_add(frozen_balance);
                let receiver_res = receiver_account
                    .account_resource
                    .get_or_insert_with(Default::default);
                receiver_res.acquired_delegated_frozen_balance_for_energy = receiver_res
                    .acquired_delegated_frozen_balance_for_energy
                    .saturating_add(frozen_balance);
            }
            self.put_delegated_journaled(&resources, &key, &record);
            self.put_account_journaled(&receiver, receiver_account);
        } else if resource_type == 0 {
            // `setFrozenForBandwidth(frozenBalance + getFrozenBalance(),
            // expireTime)`: java REPLACES entry 0 (appending only when the list
            // is empty), carrying the summed balance and the new expiry.
            let existing: i64 = owner_account.frozen.iter().map(|f| f.frozen_balance).sum();
            let merged = tron_proto::account::Frozen {
                frozen_balance: existing.saturating_add(frozen_balance),
                expire_time: expire,
            };
            match owner_account.frozen.first_mut() {
                Some(slot) => *slot = merged,
                None => owner_account.frozen.push(merged),
            }
        } else {
            // `setFrozenForEnergy` lives on AccountResource, NOT the legacy
            // `frozen` list.
            let existing = owner_account
                .account_resource
                .as_ref()
                .and_then(|r| r.frozen_balance_for_energy.as_ref())
                .map(|f| f.frozen_balance)
                .unwrap_or(0);
            owner_account
                .account_resource
                .get_or_insert_with(Default::default)
                .frozen_balance_for_energy = Some(tron_proto::account::Frozen {
                frozen_balance: existing.saturating_add(frozen_balance),
                expire_time: expire,
            });
        }

        // `adjust total resource` sits OUTSIDE the delegating branch in java, so
        // both paths move the chain-global weight.
        let weight = frozen_balance / TRX_PRECISION;
        match resource_type {
            0 => self.add_net_weight_journaled(&dyn_props, weight),
            _ => self.add_energy_weight_journaled(&dyn_props, weight),
        }

        owner_account.balance -= frozen_balance;
        self.put_account_journaled(&owner, &owner_account);
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
        // Unlike FREEZE there is NO Stake-2.0 short-circuit —
        // `OperationActions.unfreezeAction` always calls `Program.unfreeze` — so
        // this path stays live once ALLOW_TVM_FREEZE registers the opcode.
        self.note_internal_tx_nonce();
        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0;
        };
        let Some(resources) = self.delegated_resources.clone() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);

        // ---- java `UnfreezeBalanceProcessor.validate`, all read-only ----
        //
        // As in `tron_freeze`, java validates inside a child Repository that is
        // committed only on success (Program.java:1967/1983), so every rejection
        // below must leave the stores untouched. Both branches reject a resource
        // code outside BANDWIDTH(0) / ENERGY(1).
        if resource_type != 0 && resource_type != 1 {
            return 0;
        }
        let Ok(Some(mut owner_account)) = self.accounts.get(&owner) else {
            return 0;
        };
        let receiver = receiver_address
            .map(|r| evm_to_tron_address(&r))
            .unwrap_or(owner);
        let delegating = receiver != owner;

        // The delegating branch needs the (owner, receiver) DelegatedResource
        // row to exist ("delegated Resource does not exist") with a positive,
        // matured balance for the requested resource.
        let key = DelegatedResourceStore::v1_key(&owner, &receiver);
        let mut record = if delegating {
            let Ok(Some(record)) = resources.get_raw(&key) else {
                return 0;
            };
            let (amount, expire) = if resource_type == 0 {
                (
                    record.frozen_balance_for_bandwidth,
                    record.expire_time_for_bandwidth,
                )
            } else {
                (
                    record.frozen_balance_for_energy,
                    record.expire_time_for_energy,
                )
            };
            if amount <= 0 || expire > now {
                return 0;
            }
            Some(record)
        } else if resource_type == 0 {
            // `getFrozenCount() > 0` and at least one matured entry.
            if owner_account.frozen.is_empty()
                || !owner_account.frozen.iter().any(|f| f.expire_time <= now)
            {
                return 0;
            }
            None
        } else {
            // ENERGY reads `accountResource.frozenBalanceForEnergy`, NOT the
            // legacy `frozen` list.
            let frozen_for_energy = owner_account
                .account_resource
                .as_ref()
                .and_then(|r| r.frozen_balance_for_energy.as_ref());
            let matured = frozen_for_energy
                .map(|f| f.frozen_balance > 0 && f.expire_time <= now)
                .unwrap_or(false);
            if !matured {
                return 0;
            }
            None
        };

        // ---- java `UnfreezeBalanceProcessor.execute` ----
        let unfreeze_balance: i64;
        if let Some(record) = record.as_mut() {
            // Zero the un-delegated resource on the row, give the stake back to
            // the owner's balance, and take the acquired balance off the
            // receiver. `safeAddAcquiredDelegatedFrozenBalanceForX(-v, ..)`
            // clamps at 0 — `Maths.max(0, acquired - v, ..)` — so a receiver
            // whose acquired balance is short (TVM suicide + re-create) floors
            // instead of going negative.
            if resource_type == 0 {
                unfreeze_balance = record.frozen_balance_for_bandwidth;
                record.frozen_balance_for_bandwidth = 0;
                record.expire_time_for_bandwidth = 0;
                owner_account.delegated_frozen_balance_for_bandwidth = owner_account
                    .delegated_frozen_balance_for_bandwidth
                    .saturating_sub(unfreeze_balance);
            } else {
                unfreeze_balance = record.frozen_balance_for_energy;
                record.frozen_balance_for_energy = 0;
                record.expire_time_for_energy = 0;
                let owner_res = owner_account
                    .account_resource
                    .get_or_insert_with(Default::default);
                owner_res.delegated_frozen_balance_for_energy = owner_res
                    .delegated_frozen_balance_for_energy
                    .saturating_sub(unfreeze_balance);
            }
            self.put_delegated_journaled(&resources, &key, record);
            if let Ok(Some(mut receiver_account)) = self.accounts.get(&receiver) {
                if resource_type == 0 {
                    receiver_account.acquired_delegated_frozen_balance_for_bandwidth =
                        (receiver_account.acquired_delegated_frozen_balance_for_bandwidth
                            - unfreeze_balance)
                            .max(0);
                } else {
                    let receiver_res = receiver_account
                        .account_resource
                        .get_or_insert_with(Default::default);
                    receiver_res.acquired_delegated_frozen_balance_for_energy = (receiver_res
                        .acquired_delegated_frozen_balance_for_energy
                        - unfreeze_balance)
                        .max(0);
                }
                self.put_account_journaled(&receiver, &receiver_account);
            }
            owner_account.balance = owner_account.balance.saturating_add(unfreeze_balance);
        } else if resource_type == 0 {
            // Sweep every matured entry out of the legacy `frozen` list.
            let mut unlocked: i64 = 0;
            owner_account.frozen.retain(|f| {
                if f.expire_time <= now {
                    unlocked = unlocked.saturating_add(f.frozen_balance);
                    false
                } else {
                    true
                }
            });
            unfreeze_balance = unlocked;
            owner_account.balance = owner_account.balance.saturating_add(unfreeze_balance);
        } else {
            unfreeze_balance = owner_account
                .account_resource
                .as_ref()
                .and_then(|r| r.frozen_balance_for_energy.as_ref())
                .map(|f| f.frozen_balance)
                .unwrap_or(0);
            owner_account
                .account_resource
                .get_or_insert_with(Default::default)
                .frozen_balance_for_energy = None;
            owner_account.balance = owner_account.balance.saturating_add(unfreeze_balance);
        }

        let weight = unfreeze_balance / TRX_PRECISION;
        match resource_type {
            0 => self.add_net_weight_journaled(&dyn_props, -weight),
            _ => self.add_energy_weight_journaled(&dyn_props, -weight),
        }
        self.put_account_journaled(&owner, &owner_account);

        // java's post-unstake vote reconciliation, gated on ALLOW_TVM_VOTE:
        // once the account's TRON Power no longer covers the votes it has cast,
        // the pending rewards are settled and the whole vote list is dropped.
        // The account is re-read after the settle (which writes `allowance`)
        // before the votes are cleared, exactly as java re-reads from its
        // Repository.
        if self.tron_allow_tvm_vote() && !owner_account.votes.is_empty() {
            let used_tron_power: i64 = owner_account
                .votes
                .iter()
                .map(|v| v.vote_count)
                .fold(0i64, |acc, c| acc.saturating_add(c));
            let required = used_tron_power.saturating_mul(TRX_PRECISION);
            if crate::votes::tron_power(&owner_account) < required {
                if let Some(delegation) = self.delegation.clone() {
                    // Snapshot before the settle writes straight to the stores,
                    // so a frame revert reverses it too.
                    self.snapshot_account(&owner);
                    self.snapshot_delegation_rows(&delegation, &owner);
                    crate::reward::withdraw_reward_tvm(
                        &owner,
                        &self.accounts,
                        &delegation,
                        &dyn_props,
                        self.reward_vi.as_deref(),
                    )
                    .expect("db error in TronDatabaseExt::tron_unfreeze settling rewards");
                }
                if let (Some(votes_store), Ok(Some(mut settled))) =
                    (self.votes.clone(), self.accounts.get(&owner))
                {
                    let votes_row = match votes_store.get(&owner) {
                        Ok(Some(mut row)) => {
                            row.new_votes.clear();
                            row
                        }
                        _ => tron_proto::Votes {
                            address: owner.as_bytes().to_vec(),
                            old_votes: settled.votes.clone(),
                            new_votes: Vec::new(),
                        },
                    };
                    settled.votes.clear();
                    self.put_votes_journaled(&votes_store, &owner, &votes_row);
                    self.put_account_journaled(&owner, &settled);
                }
            }
        }

        // Credit the unlocked amount back to the caller's journaled
        // balance.
        if unfreeze_balance > 0 {
            self.last_balance_delta = Some((caller, unfreeze_balance));
        }
        1
    }

    fn tron_vote_witness(&mut self, caller: Address, witnesses: &[(Address, i64)]) -> i64 {
        // java `Program.voteWitness`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
        let Some(votes_store) = self.votes.clone() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);

        // ---- java `VoteWitnessProcessor.validate` + the pre-cast checks of
        // `execute`, all read-only ----
        //
        // java runs these inside a child `Repository` that is committed only
        // on success, so any failure leaves votes (and the reward settle that
        // `execute` performs first) untouched. We mirror that by validating
        // before mutating anything: the reward settle does not touch the
        // frozen/staked fields that back TRON power, so computing the power
        // here (pre-settle) yields the same value java reads post-settle.

        // `validate`: at most MAX_VOTE_NUMBER witnesses.
        if witnesses.len() > MAX_VOTE_NUMBER {
            return 0;
        }

        let Ok(Some(owner_account)) = self.accounts.get(&owner) else {
            return 0;
        };

        // Merge duplicate witnesses (java's `voteMap`) in first-seen order,
        // dropping zero-count entries and rejecting negative counts; accumulate
        // the total vote count with overflow checks (java `LongMath.checkedAdd`).
        let mut merged: Vec<(TronAddress, i64)> = Vec::with_capacity(witnesses.len());
        let mut sum: i64 = 0;
        for (witness_addr, count) in witnesses {
            let witness_tron = evm_to_tron_address(witness_addr);
            // java removed the commented-out account-existence check; the SR
            // candidate must still have a `Witness` row.
            match self.witnesses.as_ref().map(|w| w.contains(&witness_tron)) {
                Some(Ok(true)) => {}
                _ => return 0,
            }
            if *count < 0 {
                // java throws `ContractExeException` → caught → false.
                return 0;
            }
            if *count == 0 {
                // java `iterator.remove()` — silently dropped.
                continue;
            }
            let Some(next_sum) = sum.checked_add(*count) else {
                return 0;
            };
            sum = next_sum;
            if let Some(existing) = merged.iter_mut().find(|(a, _)| *a == witness_tron) {
                let Some(v) = existing.1.checked_add(*count) else {
                    return 0;
                };
                existing.1 = v;
            } else {
                merged.push((witness_tron, *count));
            }
        }

        // java selects `getAllTronPower()` only under the new resource model
        // (`supportUnfreezeDelay() && supportAllowNewResourceModel()`); the
        // mainnet path (`ALLOW_NEW_RESOURCE_MODEL = 0`) uses `getTronPower()`.
        let tron_power = if let Some(dyn_props) = self.dyn_props.as_ref() {
            let support_new_model =
                dyn_props.get_long(b"ALLOW_NEW_RESOURCE_MODEL").unwrap_or(0) == 1;
            if dyn_props.support_unfreeze_delay() && support_new_model {
                crate::votes::all_tron_power(&owner_account)
            } else {
                crate::votes::tron_power(&owner_account)
            }
        } else {
            crate::votes::tron_power(&owner_account)
        };
        let Some(required) = sum.checked_mul(TRX_PRECISION) else {
            // java `LongMath.checkedMultiply` overflow → ArithmeticException → false.
            return 0;
        };
        if required > tron_power {
            return 0;
        }

        // ---- All checks passed: settle rewards, then cast (java `execute`) ----
        //
        // `VoteRewardUtil.withdrawReward` closes the reward window against the
        // votes as they stood, so it must run before the vote list changes. It
        // mutates the owner's allowance / reward-cycle markers, so re-read the
        // account afterwards before persisting the new votes.
        if let (Some(delegation), Some(dyn_props)) =
            (self.delegation.clone(), self.dyn_props.clone())
        {
            // Snapshot before the settle mutates `allowance` straight to the
            // store, so a frame revert reverses the settle write too.
            self.snapshot_account(&owner);
            self.snapshot_delegation_rows(&delegation, &owner);
            crate::reward::withdraw_reward_tvm(&owner, &self.accounts, &delegation, &dyn_props, self.reward_vi.as_deref())
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
        // java iterates the merged `voteMap` (a `HashMap<ByteString, Long>`),
        // so the persisted vote order is that map's deterministic iteration
        // order, not the input order. Reproduce it byte-for-byte.
        for (witness_tron, count) in java_vote_map_order(merged) {
            let entry = tron_proto::Vote {
                vote_address: witness_tron.as_bytes().to_vec(),
                vote_count: count,
            };
            owner_account.votes.push(entry.clone());
            votes_capsule.new_votes.push(entry);
        }
        self.put_account_journaled(&owner, &owner_account);
        self.put_votes_journaled(&votes_store, &owner, &votes_capsule);
        1
    }

    fn tron_withdraw_reward(&mut self, caller: Address) -> i64 {
        // java `Program.withdrawReward`: increaseNonce at the top, before validate.
        self.note_internal_tx_nonce();
        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        // java `WithdrawRewardProcessor.validate`: a genesis guard
        // representative may not withdraw — validate throws, so the opcode
        // fails before any settle/drain. Return 0 (failure) without mutating,
        // matching java; the handler comment below notes this is the opcode's
        // only validate gate.
        if tron_types::mainnet_witnesses()
            .iter()
            .any(|w| &w.address == owner.as_bytes())
        {
            return 0;
        }
        // java's TVM `WithdrawRewardProcessor.execute` settles pending
        // voter rewards into `allowance` first (`VoteRewardUtil
        // .withdrawReward`, gated on ALLOW_TVM_VOTE), then drains the
        // allowance. NOTE: unlike the `WithdrawBalanceContract` actuator,
        // the TVM opcode has NO 24h cooldown — its validate only blocks
        // genesis GRs. Our previous guard (`latest_withdraw_time + 24h`)
        // failed withdrawals java accepts.
        if let Some(delegation) = self.delegation.clone() {
            // Snapshot before the settle writes `allowance` to the store.
            self.snapshot_account(&owner);
            self.snapshot_delegation_rows(&delegation, &owner);
            crate::reward::withdraw_reward_tvm(&owner, &self.accounts, &delegation, &dyn_props, self.reward_vi.as_deref())
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
        self.put_account_journaled(&owner, &account);
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
        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0;
        };
        let owner = evm_to_tron_address(&caller);
        if frozen_balance <= 0 || frozen_balance < TRX_PRECISION {
            return 0;
        }
        if !stake_v2_resource_valid(&dyn_props, resource_type) {
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
        self.put_account_journaled(&owner, &account);
        let new_basis = old_basis.saturating_add(frozen_balance);
        let weight_delta = new_basis / TRX_PRECISION - old_basis / TRX_PRECISION;
        if weight_delta != 0 {
            match resource {
                0 => self.add_net_weight_journaled(&dyn_props, weight_delta),
                1 => self.add_energy_weight_journaled(&dyn_props, weight_delta),
                2 => self.add_tron_power_weight_journaled(&dyn_props, weight_delta),
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
        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0;
        };
        if unfreeze_balance <= 0 || !stake_v2_resource_valid(&dyn_props, resource_type) {
            return 0;
        }
        let owner = evm_to_tron_address(&caller);
        // java `UnfreezeBalanceV2Processor.validate`: reject (no state change)
        // when the count of still-unfreezing v2 entries (expire_time > now) is
        // already at the UNFREEZE_MAX_TIMES cap (32). java validates before
        // execute, so this precedes the reward settlement + sweep below.
        {
            const UNFREEZE_MAX_TIMES: usize = 32;
            let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
            // java runs `UnfreezeBalanceV2Processor.validate` in a child
            // Repository BEFORE `execute()` settles rewards; a failing validate
            // discards the child so NO reward markers/allowance are written.
            // Mirror that ordering: the unfreezing-count cap AND the
            // frozen-balance existence/sufficiency checks must precede the
            // `withdraw_reward_tvm` settle below — otherwise a soft return-0
            // leaves the settle journaled and it commits on tx success, a
            // DelegationStore/allowance state divergence vs java.
            match self.accounts.get(&owner) {
                Ok(Some(acct)) => {
                    let unfreezing = acct
                        .unfrozen_v2
                        .iter()
                        .filter(|u| u.unfreeze_expire_time > now)
                        .count();
                    if unfreezing >= UNFREEZE_MAX_TIMES {
                        return 0;
                    }
                    // checkExistFrozenBalance + checkUnfreezeBalance: the
                    // resource must hold frozenV2 >= unfreeze_balance (slot
                    // amount, 0 if absent — which fails since unfreeze_balance
                    // is already > 0 here).
                    let frozen = acct
                        .frozen_v2
                        .iter()
                        .find(|f| f.r#type == resource_type as i32)
                        .map(|f| f.amount)
                        .unwrap_or(0);
                    if frozen < unfreeze_balance {
                        return 0;
                    }
                }
                // java's validate throws when the owner account is absent.
                _ => return 0,
            }
        }
        // java's TVM `UnfreezeBalanceV2Processor.execute` settles pending
        // voter rewards first (`VoteRewardUtil.withdrawReward`, gated on
        // ALLOW_TVM_VOTE), mirroring the actuator.
        if let Some(delegation) = self.delegation.clone() {
            // Snapshot before the settle writes `allowance` to the store.
            self.snapshot_account(&owner);
            self.snapshot_delegation_rows(&delegation, &owner);
            crate::reward::withdraw_reward_tvm(&owner, &self.accounts, &delegation, &dyn_props, self.reward_vi.as_deref())
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
        if let Some(votes_store) = self.votes.clone() {
            // Snapshot the votes row before `update_vote_after_unstake` writes it.
            self.snapshot_votes(&owner);
            crate::votes::update_vote_after_unstake(&votes_store, &owner, &mut account).expect(
                "db error in TronDatabaseExt::tron_unfreeze_balance_v2 trimming votes",
            );
        }
        self.put_account_journaled(&owner, &account);
        // Shrink chain-wide weight by the floored basis change (delegated-out
        // unchanged, so `new_basis == old_basis - unfreeze_balance`).
        let weight_delta =
            (old_basis - unfreeze_balance) / TRX_PRECISION - old_basis / TRX_PRECISION;
        if weight_delta != 0 {
            match resource {
                0 => self.add_net_weight_journaled(&dyn_props, weight_delta),
                1 => self.add_energy_weight_journaled(&dyn_props, weight_delta),
                2 => self.add_tron_power_weight_journaled(&dyn_props, weight_delta),
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
        let Some(dyn_props) = self.dyn_props.clone() else {
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
        self.put_account_journaled(&owner, &account);
        // Restore the chain-wide weight for the re-staked (not-expired) entries
        // (`floor(old + restored) - floor(old)`, byte-identical to java's
        // per-entry fold by telescoping).
        let net_delta = (old_net + restored_net) / TRX_PRECISION - old_net / TRX_PRECISION;
        let energy_delta =
            (old_energy + restored_energy) / TRX_PRECISION - old_energy / TRX_PRECISION;
        let tp_delta = (old_tp + restored_tp) / TRX_PRECISION - old_tp / TRX_PRECISION;
        self.add_net_weight_journaled(&dyn_props, net_delta);
        self.add_energy_weight_journaled(&dyn_props, energy_delta);
        self.add_tron_power_weight_journaled(&dyn_props, tp_delta);
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
        let Some(dyn_props) = self.dyn_props.clone() else {
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
        self.put_account_journaled(&owner, &account);
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
        let Some(resources) = self.delegated_resources.clone() else {
            return 0;
        };
        // java `DelegateResourceProcessor.validate` (DelegateResourceProcessor.java:53):
        // `delegateBalance < TRX_PRECISION` is rejected — the delegate amount must
        // be at least 1 TRX (1_000_000 sun). This subsumes the `balance <= 0` case
        // (0 or negative is also < 1 TRX). `resource_type > 1` mirrors java's
        // ResourceCode switch default (only BANDWIDTH=0 / ENERGY=1 are valid).
        const TRX_PRECISION: i64 = 1_000_000;
        if balance < TRX_PRECISION || resource_type > 1 {
            return 0;
        }
        let owner = evm_to_tron_address(&caller);
        let receiver = evm_to_tron_address(&receiver_address);
        if owner.as_bytes() == receiver.as_bytes() {
            return 0;
        }
        let resource = resource_type as i32;
        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0;
        };
        let Ok(Some(mut owner_account)) = self.accounts.get(&owner) else {
            return 0;
        };
        // java `DelegateResourceProcessor.validate`: the owner can only
        // delegate out the frozen-V2 balance NOT already covering its own
        // decayed resource usage — `getFrozenV2BalanceFor{Bandwidth,Energy}()
        // - getV2{Net,Energy}Usage(...)`. Checking only the raw frozen-V2 pool
        // (`have < balance`) over-accepts: an account that has consumed
        // resource has part of its frozen-V2 locked behind that usage, so java
        // rejects a delegation that the raw pool would cover and the opcode
        // reverts. Match java's available-balance computation exactly.
        use tron_types::resource::{
            delegatable_frozen_v2, ResourceGates, ResourceKind,
        };
        let kind = if resource == 0 {
            ResourceKind::Bandwidth
        } else {
            ResourceKind::Energy
        };
        let (total_limit, total_weight) = match kind {
            ResourceKind::Bandwidth => {
                (dyn_props.total_net_limit(), dyn_props.total_net_weight())
            }
            ResourceKind::Energy => (
                dyn_props.total_energy_current_limit(),
                dyn_props.total_energy_weight(),
            ),
        };
        let gates = ResourceGates {
            support_unfreeze_delay: dyn_props.support_unfreeze_delay(),
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        };
        let available = delegatable_frozen_v2(
            &owner_account,
            kind,
            dyn_props.head_slot(),
            total_weight,
            total_limit,
            gates,
            dyn_props.allow_harden_resource_calculation(),
        );
        if available < balance {
            return 0;
        }
        // Debit owner's FreezeV2 by `balance` for this resource type.
        let slot = owner_account
            .frozen_v2
            .iter_mut()
            .find(|f| f.r#type == resource);
        if let Some(f) = slot {
            f.amount -= balance;
        }
        // Credit receiver's `delegated_frozenV2_balance_for_*`.
        let mut receiver_account = match self.accounts.get(&receiver) {
            Ok(Some(a)) => a,
            _ => return 0,
        };
        // java `DelegateResourceProcessor.validate` (DelegateResourceProcessor.java:111):
        // delegating to a contract address is rejected ("Do not allow delegate
        // resources to contract addresses"). Mirror the revert path (return 0, no
        // state mutation) before any balance/record write.
        if receiver_account.r#type == tron_proto::AccountType::Contract as i32 {
            return 0;
        }
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
        self.put_account_journaled(&owner, &owner_account);
        self.put_account_journaled(&receiver, &receiver_account);
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
        self.put_delegated_journaled(&resources, &key, &record);
        // Maintain the bidirectional DelegatedResourceAccountIndex, matching
        // java `DelegateResourceProcessor.delegateResource`: write the two V2
        // index rows stamped with the latest block-header timestamp (java
        // `repo.getDynamicPropertiesStore().getLatestBlockHeaderTimestamp()`).
        // The store is RPC-only — never read into any balance/usage/energy/
        // consensus computation. It is journaled (per-frame revert) AND
        // session-wrapped at the executor (whole-tx revert), exactly like the
        // consensus DelegatedResource row above: a delegate in an inner frame
        // that reverts leaves no index row, matching java's discarded child
        // Repository.
        if let Some(index) = self.delegated_resource_account_index.clone() {
            self.journal_index_rows(&index, &owner, &receiver);
            let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
            index
                .delegate_v2(&owner, &receiver, now)
                .expect("db error writing delegated resource account index in delegate bridge");
        }
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
        let Some(resources) = self.delegated_resources.clone() else {
            return 0;
        };
        if balance <= 0 || resource_type > 1 {
            return 0;
        }
        let owner = evm_to_tron_address(&caller);
        let receiver = evm_to_tron_address(&receiver_address);
        // java `UnDelegateResourceProcessor.validate`: reject when the receiver
        // address equals the owner address ("receiverAddress must not be the
        // same as ownerAddress"). The delegate opcode rejects this too; without
        // the symmetric check here a self-undelegate would execute (and the two
        // account writes would clobber, last-writer-wins on the stale snapshot)
        // where java reverts the frame.
        if owner.as_bytes() == receiver.as_bytes() {
            return 0;
        }
        let resource = resource_type as i32;
        use tron_types::resource::{self as res, ResourceGates, ResourceKind};
        let kind = if resource == 0 {
            ResourceKind::Bandwidth
        } else {
            ResourceKind::Energy
        };
        // Validate: the v2 UNLOCKED (from, to) record must exist with >= balance.
        // java `UnDelegateResourceProcessor.validate` keys `createDbKeyV2(.., false)`.
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
        let Some(dyn_props) = self.dyn_props.clone() else {
            return 0;
        };
        let now_slot = dyn_props.head_slot();
        let gates = ResourceGates {
            support_unfreeze_delay: dyn_props.support_unfreeze_delay(),
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        };
        let harden = dyn_props.allow_harden_resource_calculation();

        // Per-resource acquired-delegated read/write helpers (kind-aware).
        let acquired_v2 = |a: &tron_proto::Account| -> i64 {
            match resource {
                0 => a.acquired_delegated_frozen_v2_balance_for_bandwidth,
                1 => a
                    .account_resource
                    .as_ref()
                    .map(|r| r.acquired_delegated_frozen_v2_balance_for_energy)
                    .unwrap_or(0),
                _ => 0,
            }
        };
        let set_acquired_v2 = |a: &mut tron_proto::Account, v: i64| match resource {
            0 => a.acquired_delegated_frozen_v2_balance_for_bandwidth = v,
            1 => {
                a.account_resource
                    .get_or_insert_with(Default::default)
                    .acquired_delegated_frozen_v2_balance_for_energy = v;
            }
            _ => {}
        };

        // 1. Receiver: decay its usage to `now_slot`, debit acquired, and transfer
        //    the usage that the un-delegated balance was carrying back off the
        //    receiver. java `UnDelegateResourceProcessor.execute` — the missing
        //    `transferUsage`/`newUsage` step here was the bug: zeroing acquired
        //    WITHOUT shedding the matching usage left the receiver over-charged
        //    (its limit dropped but its usage didn't), so it burned TRX where
        //    java covered from stake.
        let mut transfer_usage = 0i64;
        let mut receiver_account = self.accounts.get(&receiver).ok().flatten();
        if let Some(recv) = receiver_account.as_mut() {
            res::update_usage(recv, kind, now_slot, gates, harden);
            let acquired = acquired_v2(recv);
            if acquired < balance {
                // TVM suicide + re-create can leave acquired < balance.
                set_acquired_v2(recv, 0);
            } else {
                let (total_limit, total_weight) = match kind {
                    ResourceKind::Bandwidth => {
                        (dyn_props.total_net_limit(), dyn_props.total_net_weight())
                    }
                    ResourceKind::Energy => (
                        dyn_props.total_energy_current_limit(),
                        dyn_props.total_energy_weight(),
                    ),
                };
                let undelegate_max_usage = if total_weight > 0 {
                    // java UnDelegateResourceProcessor: `(long)((double)balance /
                    // TRX_PRECISION * totalLimit / totalWeight)` — evaluated
                    // LEFT-TO-RIGHT as `((balance/1e6) * totalLimit) / totalWeight`.
                    // Our prior grouping `(balance/1e6) * (totalLimit/totalWeight)`
                    // rounded the limit/weight ratio FIRST, differing from java by
                    // up to 1 after the i64 truncation — a sub-unit energy_usage
                    // drift on heavy delegate/undelegate accounts. Match java's
                    // exact evaluation order.
                    (balance as f64 / TRX_PRECISION as f64 * total_limit as f64
                        / total_weight as f64) as i64
                } else {
                    0
                };
                let all_frozen = match kind {
                    ResourceKind::Bandwidth => res::all_frozen_balance_for_bandwidth(recv),
                    ResourceKind::Energy => res::all_frozen_balance_for_energy(recv),
                };
                let recv_usage = res::usage(recv, kind);
                transfer_usage = if all_frozen > 0 {
                    (recv_usage as f64 * (balance as f64 / all_frozen as f64)) as i64
                } else {
                    0
                };
                transfer_usage = undelegate_max_usage.min(transfer_usage);
                set_acquired_v2(recv, acquired - balance);
            }
            let new_recv_usage = res::usage(recv, kind) - transfer_usage;
            res::set_usage(recv, kind, new_recv_usage);
            res::set_latest_time(recv, kind, now_slot);
        }

        // 2. Decrement the unlocked record (java `addFrozenBalanceFor*(-balance, 0)`).
        match resource {
            0 => record.frozen_balance_for_bandwidth -= balance,
            1 => record.frozen_balance_for_energy -= balance,
            _ => {}
        }
        self.put_delegated_journaled(&resources, &key, &record);

        // 3. Owner: credit FreezeV2 back, debit delegated_*, then fold the
        //    transferred usage in via `unDelegateIncrease`.
        if let Ok(Some(mut owner_account)) = self.accounts.get(&owner) {
            match owner_account.frozen_v2.iter_mut().find(|f| f.r#type == resource) {
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
            if let Some(recv) = receiver_account.as_ref() {
                if transfer_usage > 0 {
                    res::undelegate_increase(
                        &mut owner_account,
                        recv,
                        transfer_usage,
                        kind,
                        now_slot,
                        gates,
                        harden,
                    );
                }
            }
            self.put_account_journaled(&owner, &owner_account);
        }

        // 4. Persist the receiver last (mutated in step 1; java puts it earlier but
        //    it isn't modified after, so the end state matches).
        if let Some(recv) = receiver_account.as_ref() {
            self.put_account_journaled(&receiver, recv);
        }

        // 5. Clear the bidirectional DelegatedResourceAccountIndex once the
        //    delegation record is fully gone, matching java
        //    `UnDelegateResourceProcessor.execute`: it overwrites both V2 rows
        //    with an EMPTY index capsule when `frozenBalanceForBandwidth == 0
        //    && frozenBalanceForEnergy == 0`, which `RepositoryImpl` commits as
        //    a DELETE (`ByteUtil.isNullOrZeroArray` → `store.delete`). The TVM
        //    path has only the single unlocked record, so this is the exact
        //    clear condition. RPC-only; journaled (per-frame revert) and
        //    session-wrapped (whole-tx revert) like the delegate path above.
        if record.frozen_balance_for_bandwidth == 0 && record.frozen_balance_for_energy == 0 {
            if let Some(index) = self.delegated_resource_account_index.clone() {
                self.journal_index_rows(&index, &owner, &receiver);
                index
                    .undelegate_v2(&owner, &receiver)
                    .expect("db error clearing delegated resource account index in undelegate bridge");
            }
        }
        1
    }
}

/// Constants pulled from `tron-actuator` (kept inline here so
/// `tron-tvm` doesn't depend on `tron-actuator` — the actuator
/// already depends on `tron-tvm` for shielded verifier keys, a
/// dep we can't cycle back through).
const TRX_PRECISION: i64 = 1_000_000;

/// `ChainConstant.MAX_VOTE_NUMBER` — most SR candidates one VOTEWITNESS may
/// name (java `VoteWitnessProcessor.validate`).
const MAX_VOTE_NUMBER: usize = 30;

/// Reorder merged `(witness, count)` votes into java's
/// `HashMap<ByteString, Long>` iteration order.
///
/// java-tron's `VoteWitnessProcessor.execute` accumulates votes in a
/// `HashMap` keyed by the witness `ByteString`, then casts them by
/// iterating that map. The persisted `Account.votes` list therefore
/// carries the map's bucket order, not the caller's input order, and the
/// account row's serialized bytes (hence the state root) depend on it.
///
/// `entries` must already be merged and in first-insertion order. This
/// replays the exact `java.util.HashMap` mechanics for those insertions:
///
/// * key hash is `ByteString.hashCode()` spread by `h ^ (h >>> 16)`;
/// * bucket index is `hash & (capacity - 1)`, capacity starting at 16;
/// * a fresh key past the `0.75 * capacity` threshold doubles capacity,
///   with the order-preserving lo/hi split java's `resize` performs;
/// * iteration visits buckets `0..capacity`, each in chain (insertion)
///   order.
fn java_vote_map_order(entries: Vec<(TronAddress, i64)>) -> Vec<(TronAddress, i64)> {
    /// `com.google.protobuf.ByteString.hashCode()` for a 21-byte address:
    /// `h = size; for b in bytes { h = h * 31 + (b as i8) }`, mapped to `1`
    /// when it lands on `0` (protobuf's non-zero-hash guard).
    fn bytestring_hashcode(bytes: &[u8]) -> i32 {
        let mut h: i32 = bytes.len() as i32;
        for &b in bytes {
            h = h.wrapping_mul(31).wrapping_add(b as i8 as i32);
        }
        if h == 0 {
            1
        } else {
            h
        }
    }

    /// `java.util.HashMap.hash(key)`: `(h = key.hashCode()) ^ (h >>> 16)`.
    fn spread(hash: i32) -> i32 {
        hash ^ ((hash as u32) >> 16) as i32
    }

    // Each bucket holds (spread_hash, original index) in chain order.
    let mut capacity: usize = 16;
    let mut threshold: usize = 12; // 0.75 * 16
    let mut buckets: Vec<Vec<(i32, usize)>> = vec![Vec::new(); capacity];
    let mut size: usize = 0;

    for (idx, (addr, _)) in entries.iter().enumerate() {
        let hash = spread(bytestring_hashcode(addr.as_bytes()));
        let bucket = (hash as u32 as usize) & (capacity - 1);
        buckets[bucket].push((hash, idx));
        size += 1;
        if size > threshold {
            // java `resize`: double capacity, split each old bucket into a
            // "lo" chain (stays at index j) and a "hi" chain (moves to
            // j + oldCap), each preserving chain order.
            let old_cap = capacity;
            capacity <<= 1;
            threshold <<= 1;
            let mut next: Vec<Vec<(i32, usize)>> = vec![Vec::new(); capacity];
            for (j, chain) in buckets.into_iter().enumerate() {
                for (hash, eidx) in chain {
                    if (hash as u32 as usize) & old_cap == 0 {
                        next[j].push((hash, eidx));
                    } else {
                        next[j + old_cap].push((hash, eidx));
                    }
                }
            }
            buckets = next;
        }
    }

    let mut ordered = Vec::with_capacity(entries.len());
    let mut taken = vec![false; entries.len()];
    for chain in &buckets {
        for &(_, eidx) in chain {
            taken[eidx] = true;
            ordered.push(entries[eidx].clone());
        }
    }
    debug_assert!(taken.iter().all(|&t| t), "every vote placed in a bucket");
    ordered
}

/// Mainnet burn account ("Blackhole",
/// `TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy`) -- the self-target suicide
/// inheritor, java-tron `Repository.getBlackHoleAddress()`.
const BLACKHOLE_ADDRESS: [u8; 21] = [
    0x41, 0x77, 0x94, 0x4d, 0x19, 0xc0, 0x52, 0xb7, 0x3e, 0xe2, 0x28, 0x68, 0x23, 0xaa, 0x83,
    0xf8, 0x13, 0x8c, 0xb7, 0x03, 0x2f,
];

const FROZEN_PERIOD_MS: i64 = 3 * 24 * 60 * 60 * 1000;

/// Whether `resource_type` is a legal argument to the Stake-2.0
/// freeze/unfreeze opcodes, per the `switch` in java-tron's
/// `FreezeBalanceV2Processor.validate` and `UnfreezeBalanceV2Processor.validate`.
///
/// BANDWIDTH (0) and ENERGY (1) are always legal. TRON_POWER (2) belongs to
/// the new resource model and is legal only while
/// `supportAllowNewResourceModel()` holds — `ALLOW_NEW_RESOURCE_MODEL == 1`,
/// which no mainnet proposal has ever enabled. Anything else falls to the
/// switch's default arm and is rejected outright.
///
/// Delegation has no such branch: `DelegateResourceProcessor` and
/// `UnDelegateResourceProcessor` accept BANDWIDTH and ENERGY only, regardless
/// of the resource model.
fn stake_v2_resource_valid(
    dyn_props: &tron_chainbase::DynamicPropertiesStore,
    resource_type: u32,
) -> bool {
    match resource_type {
        0 | 1 => true,
        2 => dyn_props.get_long(b"ALLOW_NEW_RESOURCE_MODEL").unwrap_or(0) == 1,
        _ => false,
    }
}

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

/// FREEZEEXPIRETIME (0xd7) delegate path — `caller != target`.
///
/// java `Program.freezeExpireTime` (Program.java:2013-2026): look up the
/// `DelegatedResource` row at the V1 key `createDbKey(owner, target)` (=
/// `from || to`, no prefix), and return the per-resource expire time guarded by
/// a non-zero frozen balance:
/// * `resourceCode == 0` (bandwidth) → `expireTimeForBandwidth` iff
///   `frozenBalanceForBandwidth != 0`,
/// * `resourceCode == 1` (energy) → `expireTimeForEnergy` iff
///   `frozenBalanceForEnergy != 0`.
///
/// Returns the raw stored millis (the opcode handler divides by 1000); `0` when
/// no store is attached, no record exists, the resource type is out of range,
/// or the matching frozen balance is zero. Mirrors java's `return 0` fallbacks.
fn delegate_freeze_expire(
    db: &TronDatabase,
    caller: &TronAddress,
    target: &TronAddress,
    resource_type: u32,
) -> i64 {
    let Some(resources) = &db.delegated_resources else {
        return 0;
    };
    // java keys the lookup `createDbKey(owner, target)` — the V1 `from || to`.
    let key = DelegatedResourceStore::v1_key(caller, target);
    let Ok(Some(record)) = resources.get_raw(&key) else {
        return 0;
    };
    match resource_type {
        // Bandwidth.
        0 if record.frozen_balance_for_bandwidth != 0 => record.expire_time_for_bandwidth,
        // Energy.
        1 if record.frozen_balance_for_energy != 0 => record.expire_time_for_energy,
        _ => 0,
    }
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

    /// A from-genesis sync starts with EVERY dynamic property unset, so the
    /// default must be the pre-proposal answer. `ALLOW_TVM_CONSTANTINOPLE` (#26)
    /// selects `TransferException` (consumed-only, TRANSFER_FAILED) over
    /// `BytecodeExecutionException` (spend-all, UNKNOWN), so defaulting it the
    /// wrong way would mislabel every early-chain transfer failure.
    #[test]
    fn allow_tvm_constantinople_reads_the_dynamic_property_and_defaults_off() {
        // No dynamic-properties store attached at all.
        assert!(
            !make_db().tron_allow_tvm_constantinople(),
            "absent store must read as inactive"
        );

        let dp = Arc::new(tron_chainbase::DynamicPropertiesStore::new(Arc::new(
            MemBackend::new(),
        )));
        let db = make_db().with_staking_stores(
            dp.clone(),
            None,
            Arc::new(tron_chainbase::DelegatedResourceStore::new(Arc::new(
                MemBackend::new(),
            ))),
            Arc::new(tron_chainbase::DelegationStore::new(Arc::new(
                MemBackend::new(),
            ))),
        );

        // Key absent -> inactive (the from-genesis starting point).
        assert!(!db.tron_allow_tvm_constantinople());

        // Only the exact value 1 activates it, matching the other proposal gates.
        dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 0);
        assert!(!db.tron_allow_tvm_constantinople());
        dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
        assert!(db.tron_allow_tvm_constantinople());
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
    fn token_balance_imports_asset_optimized_balance_from_store() {
        // Regression for the asset-optimization VM read gap: when mainnet's
        // getAllowAssetOptimization proposal is active, an `asset_optimized`
        // account keeps its TRC-10 balances in the separate `account-asset`
        // store, NOT inline in the Account proto. java reads them through
        // getAssetV2 -> AssetUtil.importAsset on every access; our VM paths
        // must do the same. Before the fix, the VM read inline asset_v2 (= 0)
        // for an optimized holder, so a valid CALLTOKEN/TOKENBALANCE wrongly
        // saw a zero balance (live symptom: "CALLTOKEN sender has 0 of token
        // 1005027" while java had ~8.8e9).
        use tron_chainbase::{set_account_asset_backend, AccountAssetStore};

        let db = make_db();
        let owner = tron_addr(0xc1);

        // Install the process-wide account-asset backend (java
        // AssetUtil.setAccountAssetStore). OnceLock set-once: this is the only
        // setter in this test binary.
        let asset_backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        set_account_asset_backend(asset_backend.clone());

        // Optimized account: EMPTY inline asset_v2, real balance only in the store.
        AccountAssetStore::new(asset_backend)
            .put(&TronAddress::from_raw(owner), b"1005027", 8_888_877_224)
            .unwrap();
        let acct = Account {
            address: owner.to_vec(),
            asset_optimized: true,
            ..Default::default()
        };
        db.accounts
            .put(&TronAddress::from_raw(owner), &acct)
            .unwrap();

        assert_eq!(
            TronDatabaseExt::tron_token_balance(&db, evm_addr_from_tron(owner), 1_005_027),
            8_888_877_224,
            "TOKENBALANCE must import an asset-optimized account's store balance, not read inline 0"
        );
    }

    #[test]
    fn is_contract_true_for_contract_typed_account_with_empty_code_hash() {
        // Regression (block 83,361,039): java-tron's ISCONTRACT checks the
        // contract row (getContract != null) — equivalently AccountType::
        // Contract — NOT code_hash. Snapshot-imported contracts routinely have
        // an EMPTY code_hash (their runtime code lives in the address-keyed
        // code store), so gating on code_hash wrongly returned false and
        // reverted SunSwap TokenApprove's `isContract` guard with
        // "SafeERC20: call to non-contract".
        let db = make_db();
        let contract = tron_addr(0xcc);
        let acct = Account {
            address: contract.to_vec(),
            r#type: tron_proto::AccountType::Contract as i32,
            code_hash: vec![], // EMPTY — the snapshot case
            ..Default::default()
        };
        db.accounts
            .put(&TronAddress::from_raw(contract), &acct)
            .unwrap();
        assert!(
            TronDatabaseExt::tron_is_contract(&db, evm_addr_from_tron(contract)),
            "a Contract-typed account must be is_contract == true even with empty code_hash"
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

    #[test]
    fn is_contract_true_for_top_level_deploy_address() {
        // java `VMActuator.create` writes the `SmartContract` row into the
        // invoke's `rootRepository` BEFORE the constructor runs
        // (`rootRepository.createContract(contractAddress, ...)`), so
        // `address(this).isContract` is 1 inside a top-level constructor. Our
        // top-level deploy writes no contract row until commit, so the deploy
        // address is recognised through `top_level_deploy_version` instead.
        let deploy = tron_addr(0xc7);
        let db = make_db().with_top_level_deploy_version(evm_addr_from_tron(deploy), 1);
        // Deliberately NO account row and NO contract row.
        assert!(
            TronDatabaseExt::tron_is_contract(&db, evm_addr_from_tron(deploy)),
            "the in-flight top-level deploy address must report as a contract"
        );
    }

    #[test]
    fn is_contract_false_for_non_deploy_address_when_top_level_deploy_set() {
        // The deploy-address check must be exact, not a blanket "any address is
        // a contract while a deploy is in flight".
        let deploy = tron_addr(0xc7);
        let other = tron_addr(0xc8);
        let db = make_db().with_top_level_deploy_version(evm_addr_from_tron(deploy), 1);
        assert!(
            !TronDatabaseExt::tron_is_contract(&db, evm_addr_from_tron(other)),
            "an unrelated address must stay false during a top-level deploy"
        );
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

    /// java `DelegateResourceProcessor.validate` (the TVM `DELEGATERESOURCE`
    /// opcode path) caps the delegatable ENERGY at `getFrozenV2BalanceForEnergy()
    /// - v2EnergyUsage`, NOT the raw frozen-V2 pool. An owner that has consumed
    /// energy has part of its frozen-V2 reserved behind that usage, so java
    /// REJECTS (and the opcode reverts → the EnergyManager `require` fails) a
    /// delegation the raw pool would cover. Regression for the 83,555,614
    /// REVERT-vs-SUCCESS divergence (contract 41037b3e2f… delegateEnergy):
    /// before the fix `tron_delegate_resource` checked only the raw pool and
    /// returned success (push 1), so the contract did not revert.
    ///
    /// Setup: `totalEnergyWeight == totalEnergyCurrentLimit` makes the
    /// usage-weight `energy_usage * TRX_PRECISION`; `head_slot == 0 ==
    /// latest_consume_time_for_energy` keeps the usage un-decayed. With a 10-TRX
    /// frozen-V2 pool and an energy_usage of 5 (→ 5 TRX reserved), 6 TRX must be
    /// rejected and 4 TRX must succeed.
    #[test]
    fn tvm_delegate_energy_rejects_over_v2_energy_usage() {
        let (db, dyn_props) = make_staking_db();
        // head_slot = (ts - genesis) / 3000 = 0; latest_consume_time = 0 → no decay.
        dyn_props.save_latest_block_header_timestamp(0);
        dyn_props.save_total_energy_weight(1_000_000_000);
        dyn_props.save_total_energy_current_limit(1_000_000_000);
        let owner = tron_addr(0x60);
        let receiver = tron_addr(0x61);
        let owner_account = Account {
            address: owner.to_vec(),
            frozen_v2: vec![FreezeV2 { r#type: 1, amount: 10_000_000 }],
            account_resource: Some(AccountResource {
                energy_usage: 5,
                latest_consume_time_for_energy: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        db.accounts.put(&TronAddress::from_raw(owner), &owner_account).unwrap();
        db.accounts
            .put(
                &TronAddress::from_raw(receiver),
                &Account { address: receiver.to_vec(), ..Default::default() },
            )
            .unwrap();

        let mut db = db;
        let caller = evm_addr_from_tron(owner);
        let to = evm_addr_from_tron(receiver);

        // 6 TRX > (10 - 5) delegatable → java rejects → opcode pushes 0.
        assert_eq!(
            db.tron_delegate_resource(caller, 6_000_000, to, 1, false, 0),
            0,
            "delegation above frozenV2 - v2EnergyUsage must fail (REVERT in the EnergyManager require)"
        );
        // Owner state untouched on the rejected delegation.
        let owner_after = db.accounts.get(&TronAddress::from_raw(owner)).unwrap().unwrap();
        assert_eq!(
            owner_after.frozen_v2.iter().find(|f| f.r#type == 1).unwrap().amount,
            10_000_000,
            "rejected delegation must not debit the frozen-V2 pool"
        );

        // 4 TRX <= (10 - 5) delegatable → succeeds (push 1), debits the pool.
        assert_eq!(
            db.tron_delegate_resource(caller, 4_000_000, to, 1, false, 0),
            1,
            "delegation within the available frozenV2 - v2EnergyUsage must succeed"
        );
        let owner_after = db.accounts.get(&TronAddress::from_raw(owner)).unwrap().unwrap();
        assert_eq!(
            owner_after.frozen_v2.iter().find(|f| f.r#type == 1).unwrap().amount,
            6_000_000,
            "successful 4-TRX delegation debits the frozen-V2 pool"
        );
    }

    /// java `UnDelegateResourceProcessor.validate` rejects an undelegate whose
    /// receiver equals the owner ("receiverAddress must not be the same as
    /// ownerAddress"), exactly as the delegate opcode does. The guard fires
    /// before any state read, so even a forged self-delegation row is left
    /// untouched and the owner's usage is never decayed. Without the guard the
    /// opcode would process the record and the two account writes would clobber
    /// (last-writer-wins on the stale receiver snapshot) where java reverts.
    #[test]
    fn tvm_self_undelegate_rejected_before_processing() {
        let (db, dyn_props) = make_staking_db();
        // head_slot = 12000/3000 = 4 > latest_consume_time = 0, so step 1's
        // `update_usage` WOULD stamp latest_consume_time = 4; an unchanged 0
        // proves the guard returned before any processing.
        dyn_props.save_latest_block_header_timestamp(12_000);
        dyn_props.save_total_energy_weight(1_000_000_000);
        dyn_props.save_total_energy_current_limit(1_000_000_000);
        let owner = tron_addr(0x73);
        db.accounts
            .put(
                &TronAddress::from_raw(owner),
                &Account {
                    address: owner.to_vec(),
                    frozen_v2: vec![FreezeV2 { r#type: 1, amount: 10_000_000 }],
                    account_resource: Some(AccountResource {
                        acquired_delegated_frozen_v2_balance_for_energy: 5_000_000,
                        energy_usage: 4_000,
                        latest_consume_time_for_energy: 0,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        // Forge a self-delegation row (the delegate opcode forbids creating one)
        // with amount >= the undelegate balance, so the ONLY early return that
        // can fire is the owner == receiver guard.
        let caller = evm_addr_from_tron(owner);
        let owner_tron = evm_to_tron_address(&caller);
        let key = DelegatedResourceStore::v2_unlocked_key(&owner_tron, &owner_tron);
        db.delegated_resources
            .as_ref()
            .unwrap()
            .put_raw(
                &key,
                &tron_proto::DelegatedResource {
                    from: owner_tron.as_bytes().to_vec(),
                    to: owner_tron.as_bytes().to_vec(),
                    frozen_balance_for_energy: 5_000_000,
                    ..Default::default()
                },
            )
            .unwrap();

        let mut db = db;
        // Self-undelegate must be rejected (push 0) despite the present record;
        // without the guard the function runs to completion and returns 1.
        assert_eq!(
            db.tron_undelegate_resource(caller, 1_000_000, caller, 1),
            0,
            "undelegate with receiver == owner must be rejected, matching java validate"
        );
        // The owner's usage was not decayed and its latest_consume_time stays 0
        // (step 1 never ran).
        let owner_after = db.accounts.get(&TronAddress::from_raw(owner)).unwrap().unwrap();
        let res = owner_after.account_resource.unwrap();
        assert_eq!(res.energy_usage, 4_000, "owner usage untouched by rejected self-undelegate");
        assert_eq!(
            res.latest_consume_time_for_energy, 0,
            "no update_usage stamp — the guard returned before processing"
        );
    }

    /// Regression: the TVM v2 freeze/unfreeze must update `TOTAL_TRON_POWER_WEIGHT`
    /// for resource TRON_POWER (2) — the old code's `_ => {}` arm dropped it.
    /// TRON_POWER is only a legal resource code while the new resource model is
    /// active (`FreezeBalanceV2Processor.validate`), so the fixture enables it.
    #[test]
    fn tvm_freeze_v2_updates_tron_power_weight() {
        let (db, dyn_props) = make_staking_db();
        dyn_props.put_long(b"ALLOW_NEW_RESOURCE_MODEL", 1);
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
            5_000_000,
        );
        assert_eq!(rc, 0, "valid suicide returns ok");
        assert_eq!(db.create_nonce, 1, "one bump after canSuicide validation");
    }

    // Re-derive `ByteString.hashCode()` / HashMap spread independently of
    // the implementation so the ordering test is a genuine cross-check.
    fn ref_bytestring_hashcode(bytes: &[u8]) -> i32 {
        let mut h: i32 = bytes.len() as i32;
        for &b in bytes {
            h = h.wrapping_mul(31).wrapping_add(b as i8 as i32);
        }
        if h == 0 {
            1
        } else {
            h
        }
    }

    fn ref_bucket16(addr: &TronAddress) -> usize {
        let hc = ref_bytestring_hashcode(addr.as_bytes());
        let spread = hc ^ ((hc as u32) >> 16) as i32;
        (spread as u32 as usize) & 15
    }

    #[test]
    fn vote_map_order_matches_java_hashmap_buckets() {
        // Eight distinct witnesses (≤ 12 ⇒ HashMap stays at capacity 16, no
        // resize), in an arbitrary insertion order.
        let entries: Vec<(TronAddress, i64)> = (1u8..=8)
            .map(|n| (TronAddress::from_raw(tron_addr(n)), n as i64))
            .collect();

        let ordered = java_vote_map_order(entries.clone());

        // Same multiset of pairs.
        assert_eq!(ordered.len(), entries.len());
        for e in &entries {
            assert!(ordered.contains(e), "every input vote must be present");
        }

        // For a 16-bucket map the iteration order is bucket index ascending,
        // ties broken by insertion order — reproduce that independently.
        let mut expected = entries.clone();
        expected.sort_by_key({
            let order: std::collections::HashMap<TronAddress, usize> = entries
                .iter()
                .enumerate()
                .map(|(i, (a, _))| (*a, i))
                .collect();
            move |(a, _): &(TronAddress, i64)| (ref_bucket16(a), order[a])
        });
        assert_eq!(ordered, expected, "vote order must follow HashMap buckets");
    }

    #[test]
    fn vote_map_order_handles_resize_past_threshold() {
        // 20 distinct keys forces a resize (threshold 12 → capacity 32). The
        // result must still be a permutation carrying every entry exactly once.
        let entries: Vec<(TronAddress, i64)> = (1u8..=20)
            .map(|n| (TronAddress::from_raw(tron_addr(n)), n as i64))
            .collect();
        let ordered = java_vote_map_order(entries.clone());
        assert_eq!(ordered.len(), entries.len());
        for e in &entries {
            assert!(ordered.contains(e));
        }
    }
}
