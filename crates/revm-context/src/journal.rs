//! This module contains [`Journal`] struct and implements [`JournalTr`] trait for it.
//!
//! Entry submodule contains [`JournalEntry`] and [`JournalEntryTr`] traits.
//! and inner submodule contains [`JournalInner`] struct that contains state.
pub mod inner;
pub mod warm_addresses;

pub use context_interface::journaled_state::entry::{JournalEntry, JournalEntryTr};
pub use inner::{JournalCfg, JournalInner};

use bytecode::Bytecode;
use context_interface::{
    context::{SStoreResult, SelfDestructResult, StateLoad},
    journaled_state::{
        account::JournaledAccount, AccountInfoLoad, AccountLoad, JournalCheckpoint,
        JournalLoadError, JournalTr, TransferError,
    },
};
use core::ops::{Deref, DerefMut};
use database_interface::Database;
use primitives::{
    hardfork::SpecId, Address, AddressMap, AddressSet, HashSet, Log, StorageKey, StorageValue,
    B256, U256,
};
use state::{Account, EvmState};
use std::vec::Vec;

/// A journal of state changes internal to the EVM
///
/// On each additional call, the depth of the journaled state is increased (`depth`) and a new journal is added.
///
/// The journal contains every state change that happens within that call, making it possible to revert changes made in a specific call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Journal<DB, ENTRY = JournalEntry>
where
    ENTRY: JournalEntryTr,
{
    /// Database
    pub database: DB,
    /// Inner journal state.
    pub inner: JournalInner<ENTRY>,
}

impl<DB, ENTRY> Deref for Journal<DB, ENTRY>
where
    ENTRY: JournalEntryTr,
{
    type Target = JournalInner<ENTRY>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<DB, ENTRY> DerefMut for Journal<DB, ENTRY>
where
    ENTRY: JournalEntryTr,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<DB, ENTRY: JournalEntryTr> Journal<DB, ENTRY> {
    /// Creates a new JournaledState by copying state data from a JournalInit and provided database.
    /// This allows reusing the state, logs, and other data from a previous execution context while
    /// connecting it to a different database backend.
    pub const fn new_with_inner(database: DB, inner: JournalInner<ENTRY>) -> Self {
        Self { database, inner }
    }

    /// Consumes the [`Journal`] and returns [`JournalInner`].
    ///
    /// If you need to preserve the original journal, use [`Self::to_inner`] instead which clones the state.
    pub fn into_init(self) -> JournalInner<ENTRY> {
        self.inner
    }
}

impl<DB, ENTRY: JournalEntryTr + Clone> Journal<DB, ENTRY> {
    /// Creates a new [`JournalInner`] by cloning all internal state data (state, storage, logs, etc)
    /// This allows creating a new journaled state with the same state data but without
    /// carrying over the original database.
    ///
    /// This is useful when you want to reuse the current state for a new transaction or
    /// execution context, but want to start with a fresh database.
    pub fn to_inner(&self) -> JournalInner<ENTRY> {
        self.inner.clone()
    }
}

impl<DB: Database, ENTRY: JournalEntryTr> JournalTr for Journal<DB, ENTRY> {
    type Database = DB;
    type State = EvmState;
    type JournaledAccount<'a>
        = JournaledAccount<'a, DB, ENTRY>
    where
        ENTRY: 'a,
        DB: 'a;

    fn new(database: DB) -> Journal<DB, ENTRY> {
        Self {
            inner: JournalInner::new(),
            database,
        }
    }

    fn db_and_state(&self) -> (&Self::Database, &Self::State) {
        (&self.database, &self.inner.state)
    }

    #[inline]
    fn db_and_state_mut(&mut self) -> (&mut Self::Database, &mut Self::State) {
        (&mut self.database, &mut self.inner.state)
    }

    fn sload(
        &mut self,
        address: Address,
        key: StorageKey,
    ) -> Result<StateLoad<StorageValue>, <Self::Database as Database>::Error> {
        self.inner
            .sload_assume_account_present(&mut self.database, address, key, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    fn sstore(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
    ) -> Result<StateLoad<SStoreResult>, <Self::Database as Database>::Error> {
        self.inner
            .sstore_assume_account_present(&mut self.database, address, key, value, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    fn tload(&mut self, address: Address, key: StorageKey) -> StorageValue {
        self.inner.tload(address, key)
    }

    fn tstore(&mut self, address: Address, key: StorageKey, value: StorageValue) {
        self.inner.tstore(address, key, value)
    }

    fn log(&mut self, log: Log) {
        self.inner.log(log)
    }

    #[inline]
    fn logs(&self) -> &[Log] {
        &self.inner.logs
    }

    #[inline]
    fn take_logs(&mut self) -> Vec<Log> {
        self.inner.take_logs()
    }

    fn selfdestruct(
        &mut self,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner
            .selfdestruct(&mut self.database, address, target, skip_cold_load)
    }

    #[inline]
    fn warm_access_list(&mut self, access_list: AddressMap<HashSet<StorageKey>>) {
        self.inner.warm_addresses.set_access_list(access_list);
    }

    #[inline]
    fn warm_coinbase_account(&mut self, address: Address) {
        self.inner.warm_addresses.set_coinbase(address);
    }

    #[inline]
    fn warm_precompiles(&mut self, precompiles: &AddressSet) {
        self.inner
            .warm_addresses
            .set_precompile_addresses(precompiles);
    }

    #[inline]
    fn precompile_addresses(&self) -> &AddressSet {
        self.inner.warm_addresses.precompiles()
    }

    /// Returns call depth.
    #[inline]
    fn depth(&self) -> usize {
        self.inner.depth
    }

    #[inline]
    fn set_spec_id(&mut self, spec_id: SpecId) {
        self.inner.cfg.spec = spec_id;
    }

    #[inline]
    fn tron_selfdestruct_restriction_effective(&self) -> bool {
        self.inner
            .cfg
            .tron_selfdestruct_restriction
            .unwrap_or_else(|| self.inner.cfg.spec.is_enabled_in(SpecId::CANCUN))
    }

    #[inline]
    fn tron_precompile_full_output_write(&self) -> bool {
        // Explicitly `Some(false)`, NOT `!tron_selfdestruct_restriction_effective()`:
        // that helper falls back to the spec-derived EIP-6780 rule when the
        // override is absent, so an Ethereum host on a pre-Cancun spec would
        // opt into TRON's pre-#94 precompile write. Only a host that set the
        // TRON override AND set it to "restriction off" gets the full-output
        // write.
        matches!(self.inner.cfg.tron_selfdestruct_restriction, Some(false))
    }

    #[inline]
    fn tron_allow_energy_adjustment_effective(&self) -> bool {
        // `None` → preserve upstream (always-charge) behavior; TRON execution
        // always sets the override from `ALLOW_ENERGY_ADJUSTMENT` (#81).
        self.inner.cfg.tron_allow_energy_adjustment.unwrap_or(true)
    }

    #[inline]
    fn tron_chain_id_word(&self) -> Option<U256> {
        self.inner.cfg.tron_chain_id_word
    }

    #[inline]
    fn tron_account_created_locally(&self, address: Address) -> bool {
        self.inner
            .state
            .get(&address)
            .map(|a| a.is_created_locally())
            .unwrap_or(false)
    }

    #[inline]
    fn tron_account_created_in_tx(&self, address: Address) -> bool {
        // `AccountStatus::Created` (as opposed to the frame-scoped
        // `CreatedLocal`) is set by `create_account_checkpoint` before the init
        // code runs and cleared by the `AccountCreated` journal entry when the
        // creating checkpoint reverts, so it is exactly "created and not
        // rolled back" for the whole transaction.
        self.inner
            .state
            .get(&address)
            .map(|a| a.is_created())
            .unwrap_or(false)
    }

    #[inline]
    fn tron_mark_transfer_failed(&mut self) {
        self.inner.tron_transfer_failed = true;
    }

    #[inline]
    fn tron_transfer_failed(&self) -> bool {
        self.inner.tron_transfer_failed
    }

    #[inline]
    fn set_tron_selfdestruct_overrides(
        &mut self,
        restriction: Option<bool>,
        blackhole: Option<Address>,
        energy_adjustment: Option<bool>,
    ) {
        self.inner.cfg.tron_selfdestruct_restriction = restriction;
        self.inner.cfg.tron_blackhole = blackhole;
        self.inner.cfg.tron_allow_energy_adjustment = energy_adjustment;
    }

    #[inline]
    fn set_tron_chain_id_word(&mut self, word: Option<U256>) {
        self.inner.cfg.tron_chain_id_word = word;
    }

    #[inline]
    fn set_eip7708_config(&mut self, disabled: bool, delayed_burn_disabled: bool) {
        self.inner
            .set_eip7708_config(disabled, delayed_burn_disabled);
    }

    #[inline]
    fn transfer(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Result<Option<TransferError>, DB::Error> {
        self.inner.transfer(&mut self.database, from, to, balance)
    }

    #[inline]
    fn transfer_loaded(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Option<TransferError> {
        self.inner.transfer_loaded(from, to, balance)
    }

    #[inline]
    fn touch_account(&mut self, address: Address) {
        self.inner.touch(address);
    }

    #[inline]
    #[expect(deprecated)]
    fn caller_accounting_journal_entry(
        &mut self,
        address: Address,
        old_balance: U256,
        bump_nonce: bool,
    ) {
        self.inner
            .caller_accounting_journal_entry(address, old_balance, bump_nonce);
    }

    /// Increments the balance of the account.
    #[inline]
    fn balance_incr(
        &mut self,
        address: Address,
        balance: U256,
    ) -> Result<(), <Self::Database as Database>::Error> {
        self.inner
            .balance_incr(&mut self.database, address, balance)
    }

    /// Decrements the balance of the account.
    #[inline]
    fn balance_decr(
        &mut self,
        address: Address,
        balance: U256,
    ) -> Result<bool, <Self::Database as Database>::Error> {
        self.inner
            .balance_decr(&mut self.database, address, balance)
    }

    /// Increments the nonce of the account.
    #[inline]
    #[expect(deprecated)]
    fn nonce_bump_journal_entry(&mut self, address: Address) {
        self.inner.nonce_bump_journal_entry(address)
    }

    #[inline]
    fn load_account(&mut self, address: Address) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_account(&mut self.database, address)
    }

    #[inline]
    fn load_account_mut_skip_cold_load(
        &mut self,
        address: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, JournalLoadError<DB::Error>> {
        self.inner
            .load_account_mut_optional(&mut self.database, address, skip_cold_load)
    }

    #[inline]
    fn load_account_mut_optional_code(
        &mut self,
        address: Address,
        load_code: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, DB::Error> {
        self.inner
            .load_account_mut_optional_code(&mut self.database, address, load_code, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    #[inline]
    fn load_account_with_code(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_code(&mut self.database, address)
    }

    #[inline]
    fn load_account_delegated(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<AccountLoad>, DB::Error> {
        self.inner
            .load_account_delegated(&mut self.database, address)
    }

    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        self.inner.checkpoint()
    }

    #[inline]
    fn checkpoint_commit(&mut self) {
        self.inner.checkpoint_commit()
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        self.inner.checkpoint_revert(checkpoint)
    }

    #[inline]
    fn set_code_with_hash(&mut self, address: Address, code: Bytecode, hash: B256) {
        self.inner.set_code_with_hash(address, code, hash);
    }

    #[inline]
    fn create_account_checkpoint(
        &mut self,
        caller: Address,
        address: Address,
        balance: U256,
        spec_id: SpecId,
    ) -> Result<JournalCheckpoint, TransferError> {
        // Ignore error.
        self.inner
            .create_account_checkpoint(caller, address, balance, spec_id)
    }

    #[inline]
    fn commit_tx(&mut self) {
        self.inner.commit_tx()
    }

    #[inline]
    fn discard_tx(&mut self) {
        self.inner.discard_tx();
    }

    /// Clear current journal resetting it to initial state and return changes state.
    #[inline]
    fn finalize(&mut self) -> Self::State {
        self.inner.finalize()
    }

    #[inline]
    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner
            .sload_assume_account_present(&mut self.database, address, key, skip_cold_load)
    }

    #[inline]
    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner.sstore_assume_account_present(
            &mut self.database,
            address,
            key,
            value,
            skip_cold_load,
        )
    }

    #[inline]
    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, JournalLoadError<<Self::Database as Database>::Error>> {
        let spec = self.inner.cfg.spec;
        self.inner
            .load_account_optional(&mut self.database, address, load_code, skip_cold_load)
            .map(|a| {
                AccountInfoLoad::new(&a.data.info, a.is_cold, a.state_clear_aware_is_empty(spec))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use database_interface::EmptyDB;

    fn journal_with(
        spec: SpecId,
        tron_selfdestruct_restriction: Option<bool>,
    ) -> Journal<EmptyDB, JournalEntry> {
        let mut journal: Journal<EmptyDB, JournalEntry> = Journal::new(EmptyDB::default());
        journal.inner.cfg.spec = spec;
        journal.inner.cfg.tron_selfdestruct_restriction = tron_selfdestruct_restriction;
        journal
    }

    /// The pre-#94 precompile write must key off the TRON override being
    /// PRESENT and false, never off `!tron_selfdestruct_restriction_effective()`.
    ///
    /// That helper falls back to `spec.is_enabled_in(CANCUN)` when the override
    /// is absent, so an upstream Ethereum host on any pre-Cancun spec would
    /// invert to `true` and silently opt into TRON's full-output,
    /// memory-extending write.
    #[test]
    fn precompile_full_output_write_needs_the_tron_override() {
        // No override — an Ethereum host. Truncating write at every spec.
        for spec in [SpecId::BYZANTIUM, SpecId::ISTANBUL, SpecId::CANCUN] {
            let journal = journal_with(spec, None);
            assert!(
                !journal.tron_precompile_full_output_write(),
                "{spec:?}: a host that set no TRON override must keep truncating"
            );
        }

        // The trap this guards: on a pre-Cancun spec the `effective` helper is
        // false, so its negation would wrongly enable the write.
        let pre_cancun = journal_with(SpecId::BYZANTIUM, None);
        assert!(!pre_cancun.tron_selfdestruct_restriction_effective());
        assert!(!pre_cancun.tron_precompile_full_output_write());

        // TRON pre-#94 — the only configuration that gets the full write.
        assert!(journal_with(SpecId::BYZANTIUM, Some(false)).tron_precompile_full_output_write());
        assert!(journal_with(SpecId::CANCUN, Some(false)).tron_precompile_full_output_write());

        // TRON post-#94 — truncating, whatever the spec.
        assert!(!journal_with(SpecId::BYZANTIUM, Some(true)).tron_precompile_full_output_write());
        assert!(!journal_with(SpecId::CANCUN, Some(true)).tron_precompile_full_output_write());
    }
}
