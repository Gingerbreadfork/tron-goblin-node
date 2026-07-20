//! Module containing the [`JournalInner`] that is part of [`crate::Journal`].
use super::warm_addresses::WarmAddresses;
use bytecode::Bytecode;
use context_interface::{
    context::{SStoreResult, SelfDestructResult, StateLoad},
    journaled_state::{
        account::{JournaledAccount, JournaledAccountTr},
        entry::{JournalEntryTr, SelfdestructionRevertStatus},
        AccountLoad, JournalCheckpoint, JournalLoadError, TransferError,
    },
};
use core::mem;
use database_interface::Database;
use primitives::{
    eip7708::{BURN_LOG_TOPIC, ETH_TRANSFER_LOG_ADDRESS, ETH_TRANSFER_LOG_TOPIC},
    hardfork::SpecId::{self, *},
    hash_map::Entry,
    hints_util::unlikely,
    Address, Bytes, HashMap, HashSet, Log, LogData, StorageKey, StorageValue, B256, KECCAK_EMPTY,
    U256,
};
use state::{Account, EvmState, TransactionId, TransientStorage};
use std::vec::Vec;

/// Configuration for the journal that affects EVM execution behavior.
///
/// This struct bundles the spec ID and EIP-7708 configuration flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct JournalCfg {
    /// The spec ID for the EVM. Spec is required for some journal entries and needs to be set for
    /// JournalInner to be functional.
    ///
    /// If spec is set it assumed that precompile addresses are set as well for this particular spec.
    ///
    /// This spec is used for two things:
    ///
    /// - [EIP-161]: Prior to this EIP, Ethereum had separate definitions for empty and non-existing accounts.
    /// - [EIP-6780]: `SELFDESTRUCT` only in same transaction
    ///
    /// [EIP-161]: https://eips.ethereum.org/EIPS/eip-161
    /// [EIP-6780]: https://eips.ethereum.org/EIPS/eip-6780
    pub spec: SpecId,
    /// TRON fork: when `Some`, overrides the EIP-6780 gate in
    /// [`JournalInner::selfdestruct`] -- TRON gates the restriction on
    /// the `ALLOW_TVM_SELFDESTRUCT_RESTRICTION` proposal (#94), not on
    /// the Cancun opcode spec (which TRON activates separately for
    /// TLOAD/TSTORE/MCOPY). `None` keeps upstream behavior.
    pub tron_selfdestruct_restriction: Option<bool>,
    /// TRON fork: when `Some`, overrides whether SELFDESTRUCT charges the
    /// dead-beneficiary `NEW_ACCT_CALL` (25000) energy top-up — java adds it
    /// only once `ALLOW_ENERGY_ADJUSTMENT` (#81) is active (`getSuicideCost2` /
    /// `getSuicideCost3`); pre-#81 there is no top-up. `None` keeps upstream
    /// (always-charge) behavior for non-TRON execution.
    pub tron_allow_energy_adjustment: Option<bool>,
    /// TRON fork: when `Some`, a destroying SELFDESTRUCT whose
    /// beneficiary is the contract itself credits this address (TRON's
    /// black-hole / burn account) instead of silently zeroing the
    /// balance -- java-tron `Program.suicide` under
    /// `allowTvmTransferTrc10`. `None` keeps upstream burn-by-zeroing.
    pub tron_blackhole: Option<Address>,
    /// TRON fork: when `Some`, the full 256-bit value the `CHAINID` opcode must
    /// push. java `Program.getChainId` returns the genesis block id truncated to
    /// its last 4 bytes once `ALLOW_TVM_COMPATIBLE_EVM` (#60) or
    /// `ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID` (#71) is active, but the FULL
    /// 32-byte genesis id in the Istanbul(#41)..#60 window. `None` falls back to
    /// the `CfgEnv` `chain_id` (upstream EVM behavior).
    pub tron_chain_id_word: Option<U256>,
    /// TRON fork: before `ENERGY_LIMIT_HARD_FORK` (block 4,727,890) a child
    /// `Repository` aliases its ancestor's `Storage` object instead of
    /// deep-copying it (java `RepositoryImpl.getStorage`), so a reverting
    /// frame's writes to an address an ancestor already touched survive the
    /// revert and stay visible to that ancestor. `false` keeps upstream
    /// isolated-storage behavior, where every reverted frame's writes are
    /// discarded.
    pub tron_shared_storage_across_frames: bool,
    /// Whether EIP-7708 (ETH transfers emit logs) is disabled.
    pub eip7708_disabled: bool,
    /// Whether EIP-7708 delayed burn logging is disabled.
    ///
    /// When enabled, revm tracks all self-destructed addresses and emits logs for
    /// accounts that still have remaining balance at the end of the transaction.
    /// This can be disabled for performance reasons as it requires storing and
    /// iterating over all self-destructed accounts. When disabled, the logging
    /// can be done outside of revm when applying accounts to database state.
    pub eip7708_delayed_burn_disabled: bool,
}
/// Inner journal state that contains journal and state changes.
///
/// Spec Id is a essential information for the Journal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct JournalInner<ENTRY> {
    /// The current state
    pub state: EvmState,
    /// Transient storage that is discarded after every transaction.
    ///
    /// See [EIP-1153](https://eips.ethereum.org/EIPS/eip-1153).
    pub transient_storage: TransientStorage,
    /// Emitted logs
    pub logs: Vec<Log>,
    /// The current call stack depth
    pub depth: usize,
    /// The journal of state changes, one for each transaction
    pub journal: Vec<ENTRY>,
    /// Global transaction id that represent number of transactions executed (Including reverted ones).
    /// It can be different from number of `journal_history` as some transaction could be
    /// reverted or had a error on execution.
    ///
    /// This ID is used in `Self::state` to determine if account/storage is touched/warm/cold.
    pub transaction_id: TransactionId,
    /// Journal configuration containing spec ID and EIP-7708 flags.
    pub cfg: JournalCfg,
    /// Warm addresses containing both coinbase and current precompiles.
    pub warm_addresses: WarmAddresses,
    /// Addresses that were self-destructed for the first time in this transaction.
    ///
    /// This is used by [EIP-7708] to emit logs for self-destructed accounts that still
    /// have balance at the end of the transaction.
    ///
    /// The vec is indexed by checkpoint - on revert, entries added after the checkpoint
    /// are removed.
    ///
    /// [EIP-7708]: https://eips.ethereum.org/EIPS/eip-7708
    pub selfdestructed_addresses: Vec<Address>,
    /// TRON fork: set when the ROOT frame raised a `TransferException` (a
    /// transfer/endowment/self-transfer validation failure — see
    /// [`crate::interpreter::InstructionResult::TransferFailed`]). The handler
    /// sets this at the root-return boundary, since `RuntimeImpl.setResultCode`
    /// reads the exception off the root `ProgramResult` alone and a nested
    /// `TransferException` is contained to its own frame; the executor reads it
    /// after the run to record `contractResult TRANSFER_FAILED` instead of a
    /// plain `REVERT`. Transient per-transaction
    /// state, cleared on `commit_tx` / `discard_tx`.
    pub tron_transfer_failed: bool,
    /// TRON fork: for each address whose contract storage has been touched,
    /// the depth of the shallowest still-live frame to touch it. Mirrors which
    /// java-tron `Repository` in the live chain holds the address's `Storage`
    /// object while [`JournalCfg::tron_shared_storage_across_frames`] is set:
    /// pre-fork every live cache entry for an address is the *same* object, so
    /// the only observable fact is which live frame is shallowest. A frame at
    /// depth `d` reverting keeps an address's writes exactly when the recorded
    /// depth is `< d`. Empty and unread when the flag is off.
    pub tron_storage_owner_depth: HashMap<Address, usize>,
}

impl<ENTRY: JournalEntryTr> Default for JournalInner<ENTRY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ENTRY: JournalEntryTr> JournalInner<ENTRY> {
    /// Creates new [`JournalInner`].
    ///
    /// `warm_preloaded_addresses` is used to determine if address is considered warm loaded.
    /// In ordinary case this is precompile or beneficiary.
    pub fn new() -> JournalInner<ENTRY> {
        Self {
            state: HashMap::default(),
            transient_storage: TransientStorage::default(),
            logs: Vec::new(),
            journal: Vec::default(),
            transaction_id: TransactionId::ZERO,
            depth: 0,
            cfg: JournalCfg::default(),
            warm_addresses: WarmAddresses::new(),
            selfdestructed_addresses: Vec::new(),
            tron_transfer_failed: false,
            tron_storage_owner_depth: HashMap::default(),
        }
    }

    /// Returns the logs.
    ///
    /// Before returning, this function emits EIP-7708 logs for any self-destructed
    /// accounts that still have a non-zero balance.
    #[inline]
    pub fn take_logs(&mut self) -> Vec<Log> {
        // EIP-7708: Emit logs for self-destructed accounts with remaining balance
        self.eip7708_emit_burn_remaining_balance_logs();
        mem::take(&mut self.logs)
    }

    /// Prepare for next transaction, by committing the current journal to history, incrementing the transaction id
    /// and returning the logs.
    ///
    /// This function is used to prepare for next transaction. It will save the current journal
    /// and clear the journal for the next transaction.
    ///
    /// `commit_tx` is used even for discarding transactions so transaction_id will be incremented.
    pub fn commit_tx(&mut self) {
        // Clears all field from JournalInner. Doing it this way to avoid
        // missing any field.
        let Self {
            state,
            transient_storage,
            logs,
            depth,
            journal,
            transaction_id,
            cfg,
            warm_addresses,
            selfdestructed_addresses,
            tron_transfer_failed,
            tron_storage_owner_depth,
        } = self;
        // Cfg and state are not changed. They are always set again before execution.
        let _ = cfg;
        let _ = state;
        transient_storage.clear();
        *depth = 0;
        // TRON fork: storage ownership is scoped to a single transaction's frame
        // chain, matching java discarding the whole repository chain per tx.
        tron_storage_owner_depth.clear();

        // Do nothing with journal history so we can skip cloning present journal.
        journal.clear();

        // Clear coinbase address warming for next tx
        warm_addresses.clear_coinbase_and_access_list();
        // increment transaction id.
        transaction_id.increment();

        logs.clear();
        selfdestructed_addresses.clear();
        // TRON fork: the transfer-failed flag is intentionally NOT cleared
        // here. `commit_tx` runs as the LAST step of `execution_result`, AFTER
        // the `ExecutionResult` is built — but the executor reads the flag
        // AFTER `inspect_tx_commit` returns, so clearing here would always lose
        // it. The flag is per-transaction state reset in `JournalInner::new()`
        // (the TRON executor builds a fresh journal per VM transaction). The
        // bytecode-execution-failed flag is read at the same point.
        let _ = tron_transfer_failed;
    }

    /// Discard the current transaction, by reverting the journal entries and incrementing the transaction id.
    pub fn discard_tx(&mut self) {
        // if there is no journal entries, there has not been any changes.
        let Self {
            state,
            transient_storage,
            logs,
            depth,
            journal,
            transaction_id,
            cfg,
            warm_addresses,
            selfdestructed_addresses,
            tron_transfer_failed,
            tron_storage_owner_depth,
        } = self;
        let is_spurious_dragon_enabled = cfg.spec.is_enabled_in(SPURIOUS_DRAGON);
        // iterate over all journals entries and revert our global state
        //
        // TRON fork: whole-transaction discard is unconditional in both eras.
        // java's shared-`Storage` aliasing only ever carries a reverted frame's
        // writes up to a still-live ancestor; when the transaction itself fails
        // java never calls `rootRepository.commit()`, so nothing survives.
        journal.drain(..).rev().for_each(|entry| {
            entry.revert(state, None, is_spurious_dragon_enabled);
        });
        transient_storage.clear();
        *depth = 0;
        tron_storage_owner_depth.clear();
        logs.clear();
        selfdestructed_addresses.clear();
        transaction_id.increment();
        // TRON fork: see `commit_tx` — the flags are read after the run
        // returns, so they are reset in `JournalInner::new()` (fresh per VM tx),
        // not here.
        let _ = tron_transfer_failed;

        // Clear coinbase address warming for next tx
        warm_addresses.clear_coinbase_and_access_list();
    }

    /// Take the [`EvmState`] and clears the journal by resetting it to initial state.
    ///
    /// Note: Precompile addresses and spec are preserved and initial state of
    /// warm_preloaded_addresses will contain precompiles addresses.
    #[inline]
    pub fn finalize(&mut self) -> EvmState {
        // Clears all field from JournalInner. Doing it this way to avoid
        // missing any field.
        let Self {
            state,
            transient_storage,
            logs,
            depth,
            journal,
            transaction_id,
            cfg,
            warm_addresses,
            selfdestructed_addresses,
            tron_transfer_failed,
            tron_storage_owner_depth,
        } = self;
        // Clear coinbase address warming for next tx
        warm_addresses.clear_coinbase_and_access_list();
        selfdestructed_addresses.clear();
        tron_storage_owner_depth.clear();
        // TRON fork: see `commit_tx` — reset in `JournalInner::new()`, not here.
        let _ = tron_transfer_failed;

        let mut state = mem::take(state);

        // Pre-EIP-161 normalization: adjust empty touched accounts so the database
        // layer can always apply post-EIP-161 commit semantics (destroy empty touched
        // accounts). For pre-Spurious Dragon blocks, we prevent destruction by either
        // marking the account as created (materialized) or clearing the touched flag.
        if !cfg.spec.is_enabled_in(SPURIOUS_DRAGON) {
            for acc in state.values_mut() {
                if acc.is_touched()
                    && acc.is_empty()
                    && !acc.is_selfdestructed()
                    && !acc.is_created()
                {
                    if acc.is_loaded_as_not_existing() {
                        // Materialize empty account that didn't exist before.
                        acc.mark_created();
                    } else {
                        // Preserve existing empty account, don't let the DB layer destroy it.
                        acc.unmark_touch();
                    }
                }
            }
        }

        logs.clear();
        transient_storage.clear();

        // clear journal and journal history.
        journal.clear();
        *depth = 0;
        // reset transaction id.
        *transaction_id = TransactionId::ZERO;

        state
    }

    /// Emit EIP-7708 logs for self-destructed accounts that still have balance.
    ///
    /// This should be called before `take_logs()` at the end of transaction execution.
    /// It checks all accounts that were self-destructed in this transaction and emits
    /// a `Burn` log for any that still have a non-zero balance.
    ///
    /// This can happen when an account receives ETH after being self-destructed
    /// in the same transaction.
    ///
    /// Logs are emitted sorted by address in ascending order.
    ///
    /// [EIP-7708](https://eips.ethereum.org/EIPS/eip-7708)
    #[inline]
    pub fn eip7708_emit_burn_remaining_balance_logs(&mut self) {
        if !self.cfg.spec.is_enabled_in(AMSTERDAM)
            || self.cfg.eip7708_disabled
            || self.cfg.eip7708_delayed_burn_disabled
        {
            return;
        }

        // Collect addresses with non-zero balance and sort by address
        let mut addresses_with_balance: Vec<(Address, U256)> = self
            .selfdestructed_addresses
            .iter()
            .filter_map(|address| {
                self.state
                    .get(address)
                    .filter(|account| !account.info.balance.is_zero())
                    .map(|account| (*address, account.info.balance))
            })
            .collect();

        // Sort by address (ascending)
        addresses_with_balance.sort_by_key(|(addr, _)| *addr);

        // Emit logs in sorted order
        for (address, balance) in addresses_with_balance {
            self.eip7708_burn_log(address, balance);
        }
    }

    /// Return reference to state.
    #[inline]
    pub const fn state(&mut self) -> &mut EvmState {
        &mut self.state
    }

    /// Sets SpecId.
    #[inline]
    pub const fn set_spec_id(&mut self, spec: SpecId) {
        self.cfg.spec = spec;
    }

    /// Sets EIP-7708 configuration flags.
    #[inline]
    pub const fn set_eip7708_config(&mut self, disabled: bool, delayed_burn_disabled: bool) {
        self.cfg.eip7708_disabled = disabled;
        self.cfg.eip7708_delayed_burn_disabled = delayed_burn_disabled;
    }

    /// Mark account as touched as only touched accounts will be added to state.
    /// This is especially important for state clear where touched empty accounts needs to
    /// be removed from state.
    #[inline]
    pub fn touch(&mut self, address: Address) {
        if let Some(account) = self.state.get_mut(&address) {
            Self::touch_account(&mut self.journal, address, account);
        }
    }

    /// Mark account as touched.
    #[inline]
    fn touch_account(journal: &mut Vec<ENTRY>, address: Address, account: &mut Account) {
        if !account.is_touched() {
            journal.push(ENTRY::account_touched(address));
            account.mark_touch();
        }
    }

    /// Returns the _loaded_ [Account] for the given address.
    ///
    /// This assumes that the account has already been loaded.
    ///
    /// # Panics
    ///
    /// Panics if the account has not been loaded and is missing from the state set.
    #[inline]
    pub fn account(&self, address: Address) -> &Account {
        self.state
            .get(&address)
            .expect("Account expected to be loaded") // Always assume that acc is already loaded
    }

    /// Set code and its hash to the account.
    ///
    /// Note: Assume account is warm and that hash is calculated from code.
    #[inline]
    pub fn set_code_with_hash(&mut self, address: Address, code: Bytecode, hash: B256) {
        let account = self.state.get_mut(&address).unwrap();
        Self::touch_account(&mut self.journal, address, account);

        self.journal.push(ENTRY::code_changed(address));

        account.info.code_hash = hash;
        account.info.code = Some(code);
    }

    /// Use it only if you know that acc is warm.
    ///
    /// Assume account is warm.
    ///
    /// In case of EIP-7702 code with zero address, the bytecode will be erased.
    #[inline]
    pub fn set_code(&mut self, address: Address, code: Bytecode) {
        if let Some(eip7702_address) = code.eip7702_address() {
            if eip7702_address.is_zero() {
                self.set_code_with_hash(address, Bytecode::default(), KECCAK_EMPTY);
                return;
            }
        }

        let hash = code.hash_slow();
        self.set_code_with_hash(address, code, hash)
    }

    /// Add journal entry for caller accounting.
    #[inline]
    #[deprecated]
    pub fn caller_accounting_journal_entry(
        &mut self,
        address: Address,
        old_balance: U256,
        bump_nonce: bool,
    ) {
        // account balance changed.
        self.journal
            .push(ENTRY::balance_changed(address, old_balance));
        // account is touched.
        self.journal.push(ENTRY::account_touched(address));

        if bump_nonce {
            // nonce changed.
            self.journal.push(ENTRY::nonce_bumped(address));
        }
    }

    /// Increments the balance of the account.
    ///
    /// Mark account as touched.
    #[inline]
    pub fn balance_incr<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        balance: U256,
    ) -> Result<(), DB::Error> {
        let mut account = self.load_account_mut(db, address)?.data;
        account.incr_balance(balance);
        Ok(())
    }

    /// Decrements the balance of the account, returning `false` if
    /// the underlying account had insufficient funds. The decrement
    /// goes through the same `JournaledAccountTr::decr_balance` path
    /// any other balance write uses, so a revert in the enclosing
    /// frame correctly restores the pre-decrement value.
    ///
    /// Used by the TRON fork's state-mutating opcode bridges
    /// (`FREEZE` / `FREEZEBALANCEV2`) to reflect the on-stake balance
    /// debit in revm's journaled view so subsequent BALANCE reads
    /// inside the same EVM run see the post-freeze value AND the
    /// chainbase commit doesn't overwrite the TRON-side staking
    /// fields with a stale (pre-freeze) balance.
    #[inline]
    pub fn balance_decr<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        balance: U256,
    ) -> Result<bool, DB::Error> {
        let mut account = self.load_account_mut(db, address)?.data;
        Ok(account.decr_balance(balance))
    }

    /// Increments the nonce of the account.
    #[inline]
    #[deprecated]
    pub fn nonce_bump_journal_entry(&mut self, address: Address) {
        self.journal.push(ENTRY::nonce_bumped(address));
    }

    /// Transfers balance from two accounts. Returns error if sender balance is not enough.
    ///
    /// # Panics
    ///
    /// Panics if from or to are not loaded.
    #[inline]
    pub fn transfer_loaded(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Option<TransferError> {
        if from == to {
            let from_balance = self.state.get(&to).unwrap().info.balance;
            // Check if from balance is enough to transfer the balance.
            if balance > from_balance {
                return Some(TransferError::OutOfFunds);
            }
            return None;
        }

        if balance.is_zero() {
            Self::touch_account(&mut self.journal, to, self.state.get_mut(&to).unwrap());
            return None;
        }

        // sub balance from
        let from_account = self.state.get_mut(&from).unwrap();
        Self::touch_account(&mut self.journal, from, from_account);
        let from_balance = &mut from_account.info.balance;
        let Some(from_balance_decr) = from_balance.checked_sub(balance) else {
            return Some(TransferError::OutOfFunds);
        };
        *from_balance = from_balance_decr;

        // add balance to
        let to_account = self.state.get_mut(&to).unwrap();
        Self::touch_account(&mut self.journal, to, to_account);
        let to_balance = &mut to_account.info.balance;
        let Some(to_balance_incr) = to_balance.checked_add(balance) else {
            // Overflow of U256 balance is not possible to happen on mainnet. We don't bother to return funds from from_acc.
            return Some(TransferError::OverflowPayment);
        };
        *to_balance = to_balance_incr;

        // add journal entry
        self.journal
            .push(ENTRY::balance_transfer(from, to, balance));

        // EIP-7708: emit ETH transfer log
        self.eip7708_transfer_log(from, to, balance);

        None
    }

    /// Transfers balance from two accounts. Returns error if sender balance is not enough.
    #[inline]
    pub fn transfer<DB: Database>(
        &mut self,
        db: &mut DB,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Result<Option<TransferError>, DB::Error> {
        self.load_account(db, from)?;
        self.load_account(db, to)?;
        Ok(self.transfer_loaded(from, to, balance))
    }

    /// Creates account or returns false if collision is detected.
    ///
    /// There are few steps done:
    /// 1. Make created account warm loaded (AccessList) and this should
    ///    be done before subroutine checkpoint is created.
    /// 2. Check if there is collision of newly created account with existing one.
    /// 3. Mark created account as created.
    /// 4. Add fund to created account
    /// 5. Increment nonce of created account if SpuriousDragon is active
    /// 6. Decrease balance of caller account.
    ///
    /// # Panics
    ///
    /// Panics if the caller is not loaded inside the EVM state.
    /// This should have been done inside `create_inner`.
    #[inline]
    pub fn create_account_checkpoint(
        &mut self,
        caller: Address,
        target_address: Address,
        balance: U256,
        spec_id: SpecId,
    ) -> Result<JournalCheckpoint, TransferError> {
        // Enter subroutine
        let checkpoint = self.checkpoint();

        // Newly created account is present, as we just loaded it.
        let target_acc = self.state.get_mut(&target_address).unwrap();
        let last_journal = &mut self.journal;

        // New account can be created if:
        // Bytecode is not empty.
        // Nonce is not zero
        // Account is not precompile.
        if target_acc.info.code_hash != KECCAK_EMPTY || target_acc.info.nonce != 0 {
            self.checkpoint_revert(checkpoint);
            return Err(TransferError::CreateCollision);
        }

        // set account status to create.
        let is_created_globally = target_acc.mark_created_locally();

        // this entry will revert set nonce.
        last_journal.push(ENTRY::account_created(target_address, is_created_globally));
        target_acc.info.code = None;
        // EIP-161: State trie clearing (invariant-preserving alternative)
        if spec_id.is_enabled_in(SPURIOUS_DRAGON) {
            // nonce is going to be reset to zero in AccountCreated journal entry.
            target_acc.info.nonce = 1;
        }

        // touch account. This is important as for pre SpuriousDragon account could be
        // saved even empty.
        Self::touch_account(last_journal, target_address, target_acc);

        // If balance is zero, we don't need to add any journal entries or emit any logs.
        if balance.is_zero() {
            return Ok(checkpoint);
        }

        // Add balance to created account, as we already have target here.
        let Some(new_balance) = target_acc.info.balance.checked_add(balance) else {
            self.checkpoint_revert(checkpoint);
            return Err(TransferError::OverflowPayment);
        };
        target_acc.info.balance = new_balance;

        // safe to decrement for the caller as balance check is already done.
        let caller_account = self.state.get_mut(&caller).unwrap();
        caller_account.info.balance -= balance;

        // add journal entry of transferred balance
        last_journal.push(ENTRY::balance_transfer(caller, target_address, balance));

        // EIP-7708: emit ETH transfer log
        self.eip7708_transfer_log(caller, target_address, balance);

        Ok(checkpoint)
    }

    /// Makes a checkpoint that in case of Revert can bring back state to this point.
    #[inline]
    pub const fn checkpoint(&mut self) -> JournalCheckpoint {
        let checkpoint = JournalCheckpoint {
            log_i: self.logs.len(),
            journal_i: self.journal.len(),
            selfdestructed_i: self.selfdestructed_addresses.len(),
        };
        self.depth += 1;
        checkpoint
    }

    /// Records the shallowest live frame to touch this address's contract
    /// storage.
    ///
    /// Mirrors java-tron's `RepositoryImpl.getStorageInternal` caching the
    /// address's `Storage` object in the repository the opcode was issued
    /// against. That path runs for reads as well as writes — `Storage.getValue`
    /// returns early on a missing row *before* populating its row cache, so
    /// even a read of an empty slot establishes ownership of the object with no
    /// row cached. Ownership is monotonically non-increasing, so `or_insert`
    /// keeps the shallowest depth without needing a min.
    ///
    /// Only storage opcodes register here. java creates no `Storage` for plain
    /// account loads, `EXTCODESIZE`, or call targets.
    #[inline]
    fn tron_note_storage_touch(&mut self, address: Address) {
        if self.cfg.tron_shared_storage_across_frames {
            self.tron_storage_owner_depth
                .entry(address)
                .or_insert(self.depth);
        }
    }

    /// Commits the checkpoint.
    #[inline]
    pub fn checkpoint_commit(&mut self) {
        if self.cfg.tron_shared_storage_across_frames {
            // TRON fork: java's `commitStorageCache` hands this repository's
            // `Storage` objects to its parent unguarded, so every address this
            // frame owned becomes owned by the parent. Only entries recorded at
            // exactly this depth move down; a shallower owner already outranks
            // this frame and must keep its depth.
            let depth = self.depth;
            let parent_depth = depth.saturating_sub(1);
            for owner_depth in self.tron_storage_owner_depth.values_mut() {
                if *owner_depth == depth {
                    *owner_depth = parent_depth;
                }
            }
        }
        self.depth = self.depth.saturating_sub(1);
    }

    /// Reverts all changes to state until given checkpoint.
    #[inline]
    pub fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        let is_spurious_dragon_enabled = self.cfg.spec.is_enabled_in(SPURIOUS_DRAGON);
        let shared_storage = self.cfg.tron_shared_storage_across_frames;
        // Captured before the decrement below: every comparison is against the
        // depth of the frame being reverted, not its parent's.
        let reverting_depth = self.depth;
        self.depth = self.depth.saturating_sub(1);
        self.logs.truncate(checkpoint.log_i);
        // EIP-7708: Remove selfdestructed addresses added after checkpoint
        self.selfdestructed_addresses
            .truncate(checkpoint.selfdestructed_i);

        if checkpoint.journal_i >= self.journal.len() {
            if shared_storage {
                self.tron_storage_owner_depth
                    .retain(|_, d| *d != reverting_depth);
            }
            return;
        }

        let owner = &self.tron_storage_owner_depth;
        let state = &mut self.state;
        let transient_storage = &mut self.transient_storage;
        // TRON fork, pre-`ENERGY_LIMIT_HARD_FORK` only: entries whose effect
        // outlives this frame because a live shallower frame holds the same
        // java `Storage` object.
        // Retention keeps the storage entries but NOT the `AccountTouched`
        // entry for the owning address, which reverts with the rest of the
        // frame. That is only safe because the state flush skips any account
        // that is not touched: if a retained write's address could end the
        // transaction untouched, the write would be dropped there instead —
        // silently, with no failing test.
        //
        // It holds because every address that can own storage is a frame
        // context, and every context is touched at or above the owning frame's
        // depth: a CALL touches its target even at zero value, DELEGATECALL and
        // CALLCODE inherit an already-touched context, and CREATE touches on
        // account creation. Touch-depth <= owner-depth < reverting-depth, so the
        // touch always survives in a shallower range.
        //
        // The zero-value CALL touch is itself a divergence from java, which
        // gates account creation on ALLOW_TVM_SOLIDITY_059. Removing that
        // divergence at the journal layer would break this invariant, so the two
        // must be changed together.
        let mut retained: Vec<ENTRY> = Vec::new();
        let mut retained_slots: HashSet<(Address, StorageKey)> = HashSet::default();

        self.journal
            .drain(checkpoint.journal_i..)
            .rev()
            .for_each(|entry| {
                if shared_storage {
                    // Ownership is keyed by address, not by slot: java's cache
                    // key is the address, so an ancestor that touched only one
                    // slot of an address still owns writes to its other slots.
                    if let Some((addr, key)) = entry.as_storage_change() {
                        if owner.get(&addr).is_some_and(|d| *d < reverting_depth) {
                            retained_slots.insert((addr, key));
                            retained.push(entry);
                            return;
                        }
                    }
                    // A retained value must keep its slot warm. Reverting the
                    // warming entry marks the slot cold, and the next warm-up
                    // resets `original_value` to `present_value`, which would
                    // make the surviving write compare equal to its original
                    // and be skipped when state is flushed to the store.
                    //
                    // Ordering is guaranteed: `sstore_concrete_error` calls
                    // `sload_concrete_error` first, so a slot's warming entry
                    // strictly precedes its first change in journal order and
                    // therefore follows it in this reversed drain. Collecting
                    // `retained_slots` as we go is sufficient — no second pass.
                    if let Some(slot) = entry.as_storage_warmed() {
                        if retained_slots.contains(&slot) {
                            retained.push(entry);
                            return;
                        }
                    }
                }
                entry.revert(state, Some(transient_storage), is_spurious_dragon_enabled);
            });

        if shared_storage {
            // The drain yields entries in reverse; restore their original
            // relative order. Retained entries deliberately migrate into the
            // parent frame's checkpoint range so they unwind with the frame
            // that owns them — dropping them instead would strand a value that
            // a later ancestor revert must still undo.
            retained.reverse();
            self.journal.extend(retained);
            self.tron_storage_owner_depth
                .retain(|_, d| *d != reverting_depth);
        }
    }

    /// Performs selfdestruct action.
    /// Transfers balance from address to target. Check if target exist/is_cold
    ///
    /// Note: Balance will be lost if address and target are the same BUT when
    /// current spec enables Cancun, this happens only when the account associated to address
    /// is created in the same tx
    ///
    /// # References:
    ///  * <https://github.com/ethereum/go-ethereum/blob/141cd425310b503c5678e674a8c3872cf46b7086/core/vm/instructions.go#L832-L833>
    ///  * <https://github.com/ethereum/go-ethereum/blob/141cd425310b503c5678e674a8c3872cf46b7086/core/state/statedb.go#L449>
    ///  * <https://eips.ethereum.org/EIPS/eip-6780>
    #[inline]
    pub fn selfdestruct<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, JournalLoadError<DB::Error>> {
        let spec = self.cfg.spec;
        let account_load = self.load_account_optional(db, target, false, skip_cold_load)?;
        let is_cold = account_load.is_cold;
        let is_empty = account_load.state_clear_aware_is_empty(spec);

        if address != target {
            // Both accounts are loaded before this point, `address` as we execute its contract.
            // and `target` at the beginning of the function.
            let acc_balance = self.state.get(&address).unwrap().info.balance;

            let target_account = self.state.get_mut(&target).unwrap();
            Self::touch_account(&mut self.journal, target, target_account);
            target_account.info.balance += acc_balance;
        }

        // TRON fork: a self-target destroy redirects the balance to the
        // burn account -- make sure it's loaded before we borrow `address`.
        let tron_burn_target = match self.cfg.tron_blackhole {
            Some(bh) if target == address && bh != address => {
                self.load_account_optional(db, bh, false, false)?;
                Some(bh)
            }
            _ => None,
        };

        let acc = self.state.get_mut(&address).unwrap();
        let balance = acc.info.balance;

        let destroyed_status = if !acc.is_selfdestructed() {
            SelfdestructionRevertStatus::GloballySelfdestroyed
        } else if !acc.is_selfdestructed_locally() {
            SelfdestructionRevertStatus::LocallySelfdestroyed
        } else {
            SelfdestructionRevertStatus::RepeatedSelfdestruction
        };

        // TRON fork: proposal #94 overrides the spec-derived 6780 gate.
        let is_cancun_enabled = self
            .cfg
            .tron_selfdestruct_restriction
            .unwrap_or_else(|| spec.is_enabled_in(CANCUN));

        // EIP-6780 (Cancun hard-fork): selfdestruct only if contract is created in the same tx
        let journal_entry = if acc.is_created_locally() || !is_cancun_enabled {
            // EIP-7708: Track first self-destruction for remaining balance log.
            // Only track when account is actually destroyed and delayed burn is not disabled.
            if destroyed_status == SelfdestructionRevertStatus::GloballySelfdestroyed
                && !self.cfg.eip7708_delayed_burn_disabled
            {
                self.selfdestructed_addresses.push(address);
            }

            acc.mark_selfdestructed_locally();
            acc.info.balance = U256::ZERO;

            // TRON fork: self-target destroy credits the burn account.
            // Encoding the burn account as the journal entry's `target`
            // keeps the revert symmetric (revert subtracts from target).
            let entry_target = if let Some(bh) = tron_burn_target {
                if !balance.is_zero() {
                    let bh_acc = self.state.get_mut(&bh).unwrap();
                    Self::touch_account(&mut self.journal, bh, bh_acc);
                    bh_acc.info.balance += balance;
                    bh
                } else {
                    target
                }
            } else {
                target
            };

            // EIP-7708: emit appropriate log for selfdestruct
            if target != address {
                // Transfer log for balance transferred to different address
                self.eip7708_transfer_log(address, target, balance);
            } else {
                // Burn log for selfdestruct to self
                self.eip7708_burn_log(address, balance);
            }
            Some(ENTRY::account_destroyed(
                address,
                entry_target,
                destroyed_status,
                balance,
            ))
        } else if address != target {
            acc.info.balance = U256::ZERO;
            // EIP-7708: emit appropriate log for selfdestruct
            // Transfer log for balance transferred to different address
            self.eip7708_transfer_log(address, target, balance);
            Some(ENTRY::balance_transfer(address, target, balance))
        } else {
            // State is not changed:
            // * if we are after Cancun upgrade and
            // * Selfdestruct account that is created in the same transaction and
            // * Specify the target is same as selfdestructed account. The balance stays unchanged.
            None
        };

        if let Some(entry) = journal_entry {
            self.journal.push(entry);
        };

        Ok(StateLoad {
            data: SelfDestructResult {
                had_value: !balance.is_zero(),
                target_exists: !is_empty,
                previously_destroyed: destroyed_status
                    == SelfdestructionRevertStatus::RepeatedSelfdestruction,
            },
            is_cold,
        })
    }

    /// Loads account into memory. return if it is cold or warm accessed
    #[inline]
    pub fn load_account<'a, 'db, DB: Database>(
        &'a mut self,
        db: &'db mut DB,
        address: Address,
    ) -> Result<StateLoad<&'a Account>, DB::Error>
    where
        'db: 'a,
    {
        self.load_account_optional(db, address, false, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    /// Loads account into memory. If account is EIP-7702 type it will additionally
    /// load delegated account.
    ///
    /// It will mark both this and delegated account as warm loaded.
    ///
    /// Returns information about the account (If it is empty or cold loaded) and if present the information
    /// about the delegated account (If it is cold loaded).
    #[inline]
    pub fn load_account_delegated<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
    ) -> Result<StateLoad<AccountLoad>, DB::Error> {
        let spec = self.cfg.spec;
        let is_eip7702_enabled = spec.is_enabled_in(SpecId::PRAGUE);
        let account = self
            .load_account_optional(db, address, is_eip7702_enabled, false)
            .map_err(JournalLoadError::unwrap_db_error)?;
        let is_empty = account.state_clear_aware_is_empty(spec);

        let mut account_load = StateLoad::new(
            AccountLoad {
                is_delegate_account_cold: None,
                is_empty,
            },
            account.is_cold,
        );

        // load delegate code if account is EIP-7702
        if let Some(address) = account
            .info
            .code
            .as_ref()
            .and_then(Bytecode::eip7702_address)
        {
            let delegate_account = self
                .load_account_optional(db, address, true, false)
                .map_err(JournalLoadError::unwrap_db_error)?;
            account_load.data.is_delegate_account_cold = Some(delegate_account.is_cold);
        }

        Ok(account_load)
    }

    /// Loads account and its code. If account is already loaded it will load its code.
    ///
    /// It will mark account as warm loaded. If not existing Database will be queried for data.
    ///
    /// In case of EIP-7702 delegated account will not be loaded,
    /// [`Self::load_account_delegated`] should be used instead.
    #[inline]
    pub fn load_code<'a, 'db, DB: Database>(
        &'a mut self,
        db: &'db mut DB,
        address: Address,
    ) -> Result<StateLoad<&'a Account>, DB::Error>
    where
        'db: 'a,
    {
        self.load_account_optional(db, address, true, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    /// Loads account into memory. If account is already loaded it will be marked as warm.
    #[inline]
    pub fn load_account_optional<'a, 'db, DB: Database>(
        &'a mut self,
        db: &'db mut DB,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<StateLoad<&'a Account>, JournalLoadError<DB::Error>>
    where
        'db: 'a,
    {
        let mut load = self.load_account_mut_optional(db, address, skip_cold_load)?;
        if load_code {
            load.data.load_code_preserve_error()?;
        }
        Ok(load.map(|i| i.into_account()))
    }

    /// Loads account into memory. If account is already loaded it will be marked as warm.
    #[inline]
    pub fn load_account_mut<'a, 'db, DB: Database>(
        &'a mut self,
        db: &'db mut DB,
        address: Address,
    ) -> Result<StateLoad<JournaledAccount<'a, DB, ENTRY>>, DB::Error>
    where
        'db: 'a,
    {
        self.load_account_mut_optional(db, address, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    /// Loads account. If account is already loaded it will be marked as warm.
    #[inline]
    pub fn load_account_mut_optional_code<'a, 'db, DB: Database>(
        &'a mut self,
        db: &'db mut DB,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<StateLoad<JournaledAccount<'a, DB, ENTRY>>, JournalLoadError<DB::Error>>
    where
        'db: 'a,
    {
        let mut load = self.load_account_mut_optional(db, address, skip_cold_load)?;
        if load_code {
            load.data.load_code_preserve_error()?;
        }
        Ok(load)
    }

    /// Gets the account mut reference.
    ///
    /// # Load Unsafe
    ///
    /// Use this function only if you know what you are doing. It will not mark the account as warm or cold.
    /// It will not bump transition_id or return if it is cold or warm loaded. This function is useful
    /// when we know account is warm, touched and already loaded.
    ///
    /// It is useful when we want to access storage from account that is currently being executed.
    #[inline]
    pub fn get_account_mut<'a, 'db, DB: Database>(
        &'a mut self,
        db: &'db mut DB,
        address: Address,
    ) -> Option<JournaledAccount<'a, DB, ENTRY>>
    where
        'db: 'a,
    {
        let account = self.state.get_mut(&address)?;
        Some(JournaledAccount::new(
            address,
            account,
            &mut self.journal,
            db,
            self.warm_addresses.access_list(),
            self.transaction_id,
        ))
    }

    /// Loads account. If account is already loaded it will be marked as warm.
    #[inline(never)]
    pub fn load_account_mut_optional<'a, 'db, DB: Database>(
        &'a mut self,
        db: &'db mut DB,
        address: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<JournaledAccount<'a, DB, ENTRY>>, JournalLoadError<DB::Error>>
    where
        'db: 'a,
    {
        let (account, is_cold) = match self.state.entry(address) {
            Entry::Occupied(entry) => {
                let account = entry.into_mut();

                // skip load if account is cold.
                let mut is_cold = account.is_cold_transaction_id(self.transaction_id);

                if unlikely(is_cold) {
                    is_cold = self
                        .warm_addresses
                        .check_is_cold(&address, skip_cold_load)?;

                    // mark it warm.
                    account.mark_warm_with_transaction_id(self.transaction_id);

                    // if it is cold loaded and we have selfdestructed locally it means that
                    // account was selfdestructed in previous transaction and we need to clear its information and storage.
                    if account.is_selfdestructed_locally() {
                        account.selfdestruct();
                        account.unmark_selfdestructed_locally();
                    }
                    account.set_current_info_as_original();

                    // unmark locally created
                    account.unmark_created_locally();

                    // journal loading of cold account.
                    self.journal.push(ENTRY::account_warmed(address));
                }
                (account, is_cold)
            }
            Entry::Vacant(vac) => {
                // Precompiles,  among some other account(access list and coinbase included)
                // are warm loaded so we need to take that into account
                let is_cold = self
                    .warm_addresses
                    .check_is_cold(&address, skip_cold_load)?;

                let account = if let Some(account) = db.basic(address)? {
                    let mut account: Account = account.into();
                    account.transaction_id = self.transaction_id;
                    account
                } else {
                    Account::new_not_existing(self.transaction_id)
                };

                // journal loading of cold account.
                if is_cold {
                    self.journal.push(ENTRY::account_warmed(address));
                }

                (vac.insert(account), is_cold)
            }
        };

        Ok(StateLoad::new(
            JournaledAccount::new(
                address,
                account,
                &mut self.journal,
                db,
                self.warm_addresses.access_list(),
                self.transaction_id,
            ),
            is_cold,
        ))
    }

    /// Loads storage slot.
    #[inline]
    pub fn sload<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, JournalLoadError<DB::Error>> {
        self.tron_note_storage_touch(address);
        self.load_account_mut(db, address)?
            .sload_concrete_error(key, skip_cold_load)
            .map(|s| s.map(|s| s.present_value))
    }

    /// Loads storage slot.
    ///
    /// If account is not present it will return [`JournalLoadError::ColdLoadSkipped`] error.
    #[inline]
    pub fn sload_assume_account_present<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, JournalLoadError<DB::Error>> {
        self.tron_note_storage_touch(address);
        let Some(mut account) = self.get_account_mut(db, address) else {
            return Err(JournalLoadError::ColdLoadSkipped);
        };

        account
            .sload_concrete_error(key, skip_cold_load)
            .map(|s| s.map(|s| s.present_value))
    }

    /// Stores storage slot.
    ///
    /// If account is not present it will load from database
    #[inline]
    pub fn sstore<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        key: StorageKey,
        new: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, JournalLoadError<DB::Error>> {
        self.tron_note_storage_touch(address);
        self.load_account_mut(db, address)?
            .sstore_concrete_error(key, new, skip_cold_load)
    }

    /// Stores storage slot.
    ///
    /// And returns (original,present,new) slot value.
    ///
    /// **Note**: Account should already be present in our state.
    #[inline]
    pub fn sstore_assume_account_present<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        key: StorageKey,
        new: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, JournalLoadError<DB::Error>> {
        self.tron_note_storage_touch(address);
        let Some(mut account) = self.get_account_mut(db, address) else {
            return Err(JournalLoadError::ColdLoadSkipped);
        };

        account.sstore_concrete_error(key, new, skip_cold_load)
    }

    /// Read transient storage tied to the account.
    ///
    /// EIP-1153: Transient storage opcodes
    #[inline]
    pub fn tload(&mut self, address: Address, key: StorageKey) -> StorageValue {
        self.transient_storage
            .get(&(address, key))
            .copied()
            .unwrap_or_default()
    }

    /// Store transient storage tied to the account.
    ///
    /// If values is different add entry to the journal
    /// so that old state can be reverted if that action is needed.
    ///
    /// EIP-1153: Transient storage opcodes
    #[inline]
    pub fn tstore(&mut self, address: Address, key: StorageKey, new: StorageValue) {
        let had_value = if new.is_zero() {
            // if new values is zero, remove entry from transient storage.
            // if previous values was some insert it inside journal.
            // If it is none nothing should be inserted.
            self.transient_storage.remove(&(address, key))
        } else {
            // insert values
            let previous_value = self
                .transient_storage
                .insert((address, key), new)
                .unwrap_or_default();

            // check if previous value is same
            if previous_value != new {
                // if it is different, insert previous values inside journal.
                Some(previous_value)
            } else {
                None
            }
        };

        if let Some(had_value) = had_value {
            // insert in journal only if value was changed.
            self.journal
                .push(ENTRY::transient_storage_changed(address, key, had_value));
        }
    }

    /// Pushes log into subroutine.
    #[inline]
    pub fn log(&mut self, log: Log) {
        self.logs.push(log);
    }

    /// Creates and pushes an EIP-7708 ETH transfer log.
    ///
    /// This emits a LOG3 with the Transfer event signature, matching ERC-20 transfer events.
    /// Only emitted if EIP-7708 is enabled (Amsterdam and later) and balance is non-zero.
    ///
    /// [EIP-7708](https://eips.ethereum.org/EIPS/eip-7708)
    #[inline]
    pub fn eip7708_transfer_log(&mut self, from: Address, to: Address, balance: U256) {
        // Only emit log if EIP-7708 is enabled and balance is non-zero
        if !self.cfg.spec.is_enabled_in(AMSTERDAM) || self.cfg.eip7708_disabled || balance.is_zero()
        {
            return;
        }

        // Create LOG3 with Transfer(address,address,uint256) event signature
        // Topic[0]: Transfer event signature
        // Topic[1]: from address (zero-padded to 32 bytes)
        // Topic[2]: to address (zero-padded to 32 bytes)
        // Data: amount in wei (big-endian uint256)
        let topics = std::vec![
            ETH_TRANSFER_LOG_TOPIC,
            B256::left_padding_from(from.as_slice()),
            B256::left_padding_from(to.as_slice()),
        ];
        let data = Bytes::copy_from_slice(&balance.to_be_bytes::<32>());

        self.logs.push(Log {
            address: ETH_TRANSFER_LOG_ADDRESS,
            data: LogData::new(topics, data).expect("3 topics is valid"),
        });
    }

    /// Creates and pushes an EIP-7708 burn log.
    ///
    /// This emits a LOG2 when a contract self-destructs to itself or when a
    /// self-destructed account still has remaining balance at end of transaction.
    /// Only emitted if EIP-7708 is enabled (Amsterdam and later) and balance is non-zero.
    ///
    /// [EIP-7708](https://eips.ethereum.org/EIPS/eip-7708)
    #[inline]
    pub fn eip7708_burn_log(&mut self, address: Address, balance: U256) {
        // Only emit log if EIP-7708 is enabled and balance is non-zero
        if !self.cfg.spec.is_enabled_in(AMSTERDAM) || self.cfg.eip7708_disabled || balance.is_zero()
        {
            return;
        }

        // Create LOG2 with Burn(address,uint256) event signature
        // Topic[0]: Burn event signature
        // Topic[1]: account address (zero-padded to 32 bytes)
        // Data: amount in wei (big-endian uint256)
        let topics = std::vec![BURN_LOG_TOPIC, B256::left_padding_from(address.as_slice()),];
        let data = Bytes::copy_from_slice(&balance.to_be_bytes::<32>());

        self.logs.push(Log {
            address: ETH_TRANSFER_LOG_ADDRESS,
            data: LogData::new(topics, data).expect("2 topics is valid"),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context_interface::journaled_state::entry::JournalEntry;
    use database_interface::EmptyDB;
    use primitives::{address, HashSet, U256};
    use state::AccountInfo;

    #[test]
    fn test_sload_skip_cold_load() {
        let mut journal = JournalInner::<JournalEntry>::new();
        let test_address = address!("1000000000000000000000000000000000000000");
        let test_key = U256::from(1);

        // Insert account into state
        let account_info = AccountInfo {
            balance: U256::from(1000),
            nonce: 1,
            code_hash: KECCAK_EMPTY,
            code: Some(Bytecode::default()),
            account_id: None,
        };
        journal
            .state
            .insert(test_address, Account::from(account_info));

        // Add storage slot to access list (make it warm)
        let mut access_list = HashMap::default();
        let mut storage_keys = HashSet::default();
        storage_keys.insert(test_key);
        access_list.insert(test_address, storage_keys);
        journal.warm_addresses.set_access_list(access_list);

        // Try to sload with skip_cold_load=true - should succeed because slot is in access list
        let mut db = EmptyDB::new();
        let result = journal.sload_assume_account_present(&mut db, test_address, test_key, true);

        // Should succeed and return as warm
        assert!(result.is_ok());
        let state_load = result.unwrap();
        assert!(!state_load.is_cold); // Should be warm
        assert_eq!(state_load.data, U256::ZERO); // Empty slot
    }

    // ---------------------------------------------------------------------
    // TRON pre-ENERGY_LIMIT_HARD_FORK shared-`Storage` semantics.
    //
    // Pre-fork, java's `RepositoryImpl.getStorage` hands a child repository the
    // *same* `Storage` object as its parent rather than a deep copy, so a
    // reverting frame's writes to an address a live ancestor already touched
    // survive into that ancestor. Each test names the depth of the frame it
    // acts in; `checkpoint()` moves depth 0 -> 1 for the entry frame, matching
    // java passing `rootRepository` itself to the top-level call.
    // ---------------------------------------------------------------------

    const TRON_ADDR: Address = address!("1000000000000000000000000000000000000000");
    const TRON_OTHER_ADDR: Address = address!("2000000000000000000000000000000000000000");

    fn tron_journal(shared_storage: bool) -> (JournalInner<JournalEntry>, EmptyDB) {
        let mut journal = JournalInner::<JournalEntry>::new();
        journal.cfg.tron_shared_storage_across_frames = shared_storage;
        for address in [TRON_ADDR, TRON_OTHER_ADDR] {
            journal.state.insert(
                address,
                Account::from(AccountInfo {
                    balance: U256::from(1000),
                    nonce: 1,
                    code_hash: KECCAK_EMPTY,
                    code: Some(Bytecode::default()),
                    account_id: None,
                }),
            );
        }
        (journal, EmptyDB::new())
    }

    fn present(journal: &JournalInner<JournalEntry>, address: Address, key: U256) -> U256 {
        journal
            .state
            .get(&address)
            .and_then(|a| a.storage.get(&key))
            .map(|s| s.present_value)
            .unwrap_or(U256::ZERO)
    }

    fn original(journal: &JournalInner<JournalEntry>, address: Address, key: U256) -> U256 {
        journal
            .state
            .get(&address)
            .and_then(|a| a.storage.get(&key))
            .map(|s| s.original_value)
            .unwrap_or(U256::ZERO)
    }

    /// An inner frame's write to a slot of an address its caller already wrote
    /// survives the inner frame's revert. This is the core divergence: the two
    /// frames hold one shared java `Storage`, so the revert cannot take the
    /// write back.
    #[test]
    fn tron_pre_fork_inner_revert_keeps_ancestor_owned_storage() {
        let key = U256::from(1);
        for (shared, expected) in [(true, U256::from(2)), (false, U256::from(1))] {
            let (mut journal, mut db) = tron_journal(shared);
            journal.checkpoint(); // depth 1
            journal.sstore(&mut db, TRON_ADDR, key, U256::from(1), false).unwrap();
            let inner = journal.checkpoint(); // depth 2
            journal.sstore(&mut db, TRON_ADDR, key, U256::from(2), false).unwrap();
            journal.checkpoint_revert(inner);
            assert_eq!(
                present(&journal, TRON_ADDR, key),
                expected,
                "shared_storage={shared}"
            );
        }
    }

    /// An inner frame's write to an address *no* ancestor has touched is
    /// discarded on revert in both eras: the inner frame created the `Storage`
    /// object itself, so dropping the repository drops the object.
    #[test]
    fn tron_pre_fork_inner_revert_discards_self_owned_storage() {
        let key = U256::from(1);
        for shared in [true, false] {
            let (mut journal, mut db) = tron_journal(shared);
            journal.checkpoint(); // depth 1, touches nothing
            let inner = journal.checkpoint(); // depth 2
            journal.sstore(&mut db, TRON_ADDR, key, U256::from(9), false).unwrap();
            journal.checkpoint_revert(inner);
            assert_eq!(
                present(&journal, TRON_ADDR, key),
                U256::ZERO,
                "shared_storage={shared}"
            );
        }
    }

    /// Reverting the frame that owns an address discards the whole subtree of
    /// writes to it, and releases its ownership entry.
    #[test]
    fn tron_pre_fork_owner_frame_revert_discards_subtree() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        let outer = journal.checkpoint(); // depth 1
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(1), false).unwrap();
        journal.checkpoint(); // depth 2
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(2), false).unwrap();
        journal.checkpoint_commit();
        journal.checkpoint_revert(outer);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::ZERO);
        assert!(!journal.tron_storage_owner_depth.contains_key(&TRON_ADDR));
    }

    /// A(d1) touches an address, B(d2) does not, C(d3) touches it and commits
    /// into B, then B reverts. Ownership is monotonically non-increasing, so
    /// A still owns the address and the write survives. A naive
    /// `insert(depth)` on touch, or a commit that lowers ownership
    /// unconditionally rather than only for entries at the committing depth,
    /// would leave B owning it and discard the write.
    #[test]
    fn tron_pre_fork_commit_into_non_owner_preserves_shallower_owner() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        journal.checkpoint(); // A, depth 1
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(1), false).unwrap();
        let b = journal.checkpoint(); // B, depth 2
        journal.checkpoint(); // C, depth 3
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(3), false).unwrap();
        journal.checkpoint_commit(); // C commits into B
        assert_eq!(journal.tron_storage_owner_depth.get(&TRON_ADDR), Some(&1));
        journal.checkpoint_revert(b);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::from(3));
    }

    /// Committing a frame hands its `Storage` objects to its parent, so a later
    /// sibling at the same depth reverts against the parent's ownership and its
    /// write survives.
    #[test]
    fn tron_pre_fork_commit_lowers_owner_depth() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        journal.checkpoint(); // depth 1, touches nothing
        journal.checkpoint(); // depth 2
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(1), false).unwrap();
        journal.checkpoint_commit();
        assert_eq!(journal.tron_storage_owner_depth.get(&TRON_ADDR), Some(&1));
        let sibling = journal.checkpoint(); // depth 2 again
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(2), false).unwrap();
        journal.checkpoint_revert(sibling);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::from(2));
    }

    /// A retained entry is re-appended into the parent's checkpoint range, not
    /// dropped, so a later revert of the owning frame still unwinds it. Dropping
    /// it instead would strand the value and flush a phantom write for a
    /// transaction that fully reverted.
    #[test]
    fn tron_pre_fork_retained_entry_unwinds_with_owner() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        let outer = journal.checkpoint(); // depth 1
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(1), false).unwrap();
        let inner = journal.checkpoint(); // depth 2
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(2), false).unwrap();
        journal.checkpoint_revert(inner);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::from(2));
        journal.checkpoint_revert(outer);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::ZERO);
    }

    /// A bare SLOAD establishes ownership: `getStorageInternal` materialises and
    /// caches the `Storage` object for reads as well as writes, and
    /// `Storage.getValue` returns before caching a row when the row is missing,
    /// so reading an empty slot claims the object with no row cached.
    #[test]
    fn tron_pre_fork_ancestor_sload_establishes_ownership() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        journal.checkpoint(); // depth 1
        journal.sload(&mut db, TRON_ADDR, key, false).unwrap();
        let inner = journal.checkpoint(); // depth 2
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(5), false).unwrap();
        journal.checkpoint_revert(inner);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::from(5));
    }

    /// Ownership is keyed by address, not by slot: an ancestor that touched one
    /// slot of an address holds the whole `Storage` object, so an inner frame's
    /// write to a *different* slot of that address also survives.
    #[test]
    fn tron_pre_fork_ownership_is_address_scoped_not_slot_scoped() {
        let touched = U256::from(1);
        let untouched = U256::from(2);
        let (mut journal, mut db) = tron_journal(true);
        journal.checkpoint(); // depth 1
        journal.sstore(&mut db, TRON_ADDR, touched, U256::from(1), false).unwrap();
        let inner = journal.checkpoint(); // depth 2
        journal.sstore(&mut db, TRON_ADDR, untouched, U256::from(7), false).unwrap();
        journal.checkpoint_revert(inner);
        assert_eq!(present(&journal, TRON_ADDR, untouched), U256::from(7));
    }

    /// The SSTORE cost model must see a retained write. java bills RESET (5000)
    /// rather than SET (20000) when the row is already cached, and pre-fork a
    /// reverted frame's rows stay in the shared row cache. Ownership is
    /// established with an SLOAD because a zero-to-zero SSTORE journals its own
    /// entry, which would make the assertion hold with or without retention.
    #[test]
    fn tron_pre_fork_sstore_cost_sees_reverted_row() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        journal.checkpoint(); // depth 1
        journal.sload(&mut db, TRON_ADDR, key, false).unwrap();
        let inner = journal.checkpoint(); // depth 2
        journal.sstore(&mut db, TRON_ADDR, key, U256::ZERO, false).unwrap();
        journal.checkpoint_revert(inner);
        let result = journal
            .sstore(&mut db, TRON_ADDR, key, U256::from(7), false)
            .unwrap();
        assert!(result.data.prev_written_this_tx);
    }

    /// A retained write must keep its slot warm. Reverting the slot's
    /// `StorageWarmed` entry marks it cold; the next warm-up then resets
    /// `original_value` to `present_value`, which makes the surviving write
    /// compare equal to its original and be skipped when state is flushed to
    /// the store. The write would be silently lost with no error anywhere.
    #[test]
    fn tron_pre_fork_retained_slot_stays_warm() {
        let owned = U256::from(1);
        let fresh = U256::from(2);
        let (mut journal, mut db) = tron_journal(true);
        journal.checkpoint(); // depth 1
        journal.sstore(&mut db, TRON_ADDR, owned, U256::from(1), false).unwrap();
        let inner = journal.checkpoint(); // depth 2, first touch of `fresh`
        journal.sstore(&mut db, TRON_ADDR, fresh, U256::from(2), false).unwrap();
        journal.checkpoint_revert(inner);
        // The ancestor reads the slot back, re-warming it if it went cold.
        journal.sload(&mut db, TRON_ADDR, fresh, false).unwrap();
        assert_eq!(present(&journal, TRON_ADDR, fresh), U256::from(2));
        assert_eq!(
            original(&journal, TRON_ADDR, fresh),
            U256::ZERO,
            "original_value must stay 0 so the surviving write is flushed"
        );
    }

    /// A frame reverting keeps writes only to addresses a *live* shallower frame
    /// owns. An untouched second address in the same frame is unaffected.
    #[test]
    fn tron_pre_fork_retention_is_per_address() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        journal.checkpoint(); // depth 1, owns TRON_ADDR only
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(1), false).unwrap();
        let inner = journal.checkpoint(); // depth 2
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(2), false).unwrap();
        journal.sstore(&mut db, TRON_OTHER_ADDR, key, U256::from(3), false).unwrap();
        journal.checkpoint_revert(inner);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::from(2));
        assert_eq!(present(&journal, TRON_OTHER_ADDR, key), U256::ZERO);
    }

    /// The entry frame is depth 1, so a top-level revert always finds
    /// `owner_depth >= 1`, never `< 1`, and discards everything — matching java
    /// never committing `rootRepository` for a failed transaction.
    #[test]
    fn tron_pre_fork_top_level_revert_discards_everything() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(true);
        let top = journal.checkpoint(); // depth 1
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(4), false).unwrap();
        journal.checkpoint_revert(top);
        assert_eq!(present(&journal, TRON_ADDR, key), U256::ZERO);
        assert!(journal.tron_storage_owner_depth.is_empty());
    }

    /// With the flag off the owner map is never populated, so post-fork
    /// execution allocates nothing and takes the unmodified revert path.
    #[test]
    fn tron_post_fork_owner_map_stays_empty() {
        let key = U256::from(1);
        let (mut journal, mut db) = tron_journal(false);
        journal.checkpoint();
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(1), false).unwrap();
        journal.sload(&mut db, TRON_OTHER_ADDR, key, false).unwrap();
        let inner = journal.checkpoint();
        journal.sstore(&mut db, TRON_ADDR, key, U256::from(2), false).unwrap();
        let journal_len_before = journal.journal.len();
        journal.checkpoint_revert(inner);
        assert!(journal.tron_storage_owner_depth.is_empty());
        assert_eq!(present(&journal, TRON_ADDR, key), U256::from(1));
        // Nothing is re-appended, so the journal truncates exactly to the
        // checkpoint index.
        assert_eq!(journal.journal.len(), inner.journal_i);
        assert!(journal_len_before > inner.journal_i);
    }
}
