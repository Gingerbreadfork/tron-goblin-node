//! TRON-specific read extensions for the EVM Host.
//!
//! ## Problem this solves
//!
//! Earlier versions added the TRON read methods (`tron_token_balance`,
//! `tron_is_contract`, `tron_freeze_expire_time`) directly to [`Host`]
//! as default impls returning zero. revm-context's blanket
//! `impl Host for Context<...>` never overrides them, so every read-side
//! TRON opcode silently returned 0 against real chainbase data.
//!
//! ## Approach
//!
//! [`TronHostExt`] lives in this crate (so revm-interpreter handlers can
//! depend on it). The Context impl in `tron-tvm` provides the bridge:
//! when the Context's `DB` parameter implements [`TronDatabaseExt`], we
//! delegate `TronHostExt::tron_*` calls to the database. The orphan rule
//! permits this because the trait is local to our fork.
//!
//! The handlers bound `H: Host + TronHostExt`. Construction-time the
//! Context already provides both; instruction-table registration just
//! propagates the additional bound.
//!
//! ## What's here vs deferred
//!
//! Read-side methods are exhaustive — `tron_token_balance`,
//! `tron_is_contract`, `tron_freeze_expire_time` cover every TRON read
//! opcode we've added so far. Write-side opcodes (FREEZE, UNFREEZE,
//! WITHDRAWREWARD, etc.) need `&mut self` + actuator-primitive
//! refactoring before they can plug in here.

use primitives::Address;

/// Read-only TRON extensions to [`crate::host::Host`].
///
/// The default impls return zero / false so any Host that doesn't care
/// about TRON semantics (DummyHost, Ethereum-only setups) compiles
/// unchanged. The Context impl in `tron-tvm` overrides each method to
/// delegate to its [`TronDatabaseExt`] via `self.journaled_state.database()`.
pub trait TronHostExt {
    /// TRC-10 balance of `address` for `token_id`. Default 0.
    #[inline]
    fn tron_token_balance(&self, _address: Address, _token_id: i64) -> i64 {
        0
    }

    /// `true` if `address` is a deployed contract (non-empty bytecode). Default false.
    #[inline]
    fn tron_is_contract(&self, _address: Address) -> bool {
        false
    }

    /// Stake 1.0 frozen-entry expire time. Returns Unix-millis (the
    /// opcode handler divides by 1000 when pushing). Default 0.
    #[inline]
    fn tron_freeze_expire_time(
        &self,
        _caller_address: Address,
        _target_address: Address,
        _resource_type: u32,
    ) -> i64 {
        0
    }
}

/// Database extension that the bridge impl reads from.
///
/// `tron-tvm`'s `TronDatabase` implements this with real chainbase
/// reads. Stock databases (EmptyDB, the upstream test fixtures) get
/// the default zero values.
pub trait TronDatabaseExt {
    /// See [`TronHostExt::tron_token_balance`].
    fn tron_token_balance(&self, _address: Address, _token_id: i64) -> i64 {
        0
    }

    /// See [`TronHostExt::tron_is_contract`].
    fn tron_is_contract(&self, _address: Address) -> bool {
        false
    }

    /// See [`crate::host::Host::tron_account_exists`] — `getAccount(addr) != null`.
    fn tron_account_exists(&self, _address: Address) -> bool {
        false
    }

    /// See [`TronHostExt::tron_freeze_expire_time`].
    fn tron_freeze_expire_time(
        &self,
        _caller_address: Address,
        _target_address: Address,
        _resource_type: u32,
    ) -> i64 {
        0
    }

    // ---- State-mutating opcode bridges ----
    //
    // Each method matches the matching Host method 1:1. Defaults
    // are no-op (return 0) so stock databases keep compiling.
    // tron-tvm's `TronDatabase` overrides with calls into the
    // actuator primitives.

    /// `FREEZE` (0xd5).
    fn tron_freeze(
        &mut self,
        _caller: Address,
        _frozen_balance: i64,
        _frozen_duration: i64,
        _resource_type: u32,
        _receiver_address: Option<Address>,
    ) -> i64 {
        0
    }

    /// `UNFREEZE` (0xd6).
    fn tron_unfreeze(
        &mut self,
        _caller: Address,
        _resource_type: u32,
        _receiver_address: Option<Address>,
    ) -> i64 {
        0
    }

    /// `VOTEWITNESS` (0xd8).
    fn tron_vote_witness(&mut self, _caller: Address, _witnesses: &[(Address, i64)]) -> i64 {
        0
    }

    /// `WITHDRAWREWARD` (0xd9).
    fn tron_withdraw_reward(&mut self, _caller: Address) -> i64 {
        0
    }

    /// `FREEZEBALANCEV2` (0xda).
    fn tron_freeze_balance_v2(
        &mut self,
        _caller: Address,
        _frozen_balance: i64,
        _resource_type: u32,
    ) -> i64 {
        0
    }

    /// `UNFREEZEBALANCEV2` (0xdb).
    fn tron_unfreeze_balance_v2(
        &mut self,
        _caller: Address,
        _unfreeze_balance: i64,
        _resource_type: u32,
    ) -> i64 {
        0
    }

    /// `CANCELALLUNFREEZEV2` (0xdc).
    fn tron_cancel_all_unfreeze_v2(&mut self, _caller: Address) -> i64 {
        0
    }

    /// `WITHDRAWEXPIREUNFREEZE` (0xdd).
    fn tron_withdraw_expire_unfreeze(&mut self, _caller: Address) -> i64 {
        0
    }

    /// `DELEGATERESOURCE` (0xde).
    fn tron_delegate_resource(
        &mut self,
        _caller: Address,
        _balance: i64,
        _receiver_address: Address,
        _resource_type: u32,
        _lock: bool,
        _lock_period: i64,
    ) -> i64 {
        0
    }

    /// `UNDELEGATERESOURCE` (0xdf).
    fn tron_undelegate_resource(
        &mut self,
        _caller: Address,
        _balance: i64,
        _receiver_address: Address,
        _resource_type: u32,
    ) -> i64 {
        0
    }

    /// Side-channel: after a state-mutating bridge call, pull the
    /// (address, signed-delta) pair the bridge wants applied to
    /// revm's journaled balance. `(Address::ZERO, 0)` means "no
    /// balance change for this op". The Host (`impl Host for
    /// Context`) calls this immediately after each `tron_*` mutation
    /// and routes the delta to `journaled_state.balance_incr` /
    /// `balance_decr` so subsequent BALANCE opcodes see the
    /// post-stake balance AND the chainbase commit doesn't clobber
    /// the TRON-side staking fields with a stale account.
    ///
    /// Default returns `(Address::ZERO, 0)` for stock databases.
    /// SELFDESTRUCT chainbase side-effects -- java-tron `Program.suicide`
    /// / `suicide2` minus the EVM-journal balance moves (those stay in
    /// the journal): validation (`canSuicide` / `canSuicide2`), reward
    /// settlement + vote cancellation, TRC-10 sweep, frozen v1/v2
    /// transfer to the inheritor, expired-unfreeze credit.
    ///
    /// `will_destroy` mirrors `is_created_locally || !restriction`.
    /// Returns `0` on success, `-1` when the suicide must REVERT
    /// (outstanding delegations -- java's `canSuicide*` returning false).
    /// Balance changes are reported through
    /// [`tron_take_balance_deltas`](Self::tron_take_balance_deltas).
    fn tron_suicide(&mut self, _owner: Address, _obtainer: Address, _will_destroy: bool) -> i64 {
        0
    }

    /// Drain ALL pending EVM-balance deltas accumulated by the last
    /// bridge call (multi-delta sibling of
    /// [`tron_take_last_balance_delta`](Self::tron_take_last_balance_delta)
    /// -- suicide can move several balances at once).
    fn tron_take_balance_deltas(&mut self) -> Vec<(Address, i64)> {
        Vec::new()
    }

    /// Take (and clear) the single pending EVM-balance delta from the last
    /// bridge call -- the journaled `(address, signed_amount)` a TRON precompile
    /// (freeze/unfreeze/withdraw) asks the Host to apply so subsequent `BALANCE`
    /// reads and the commit observe the post-call view. `(ZERO, 0)` when none.
    fn tron_take_last_balance_delta(&mut self) -> (Address, i64) {
        (Address::ZERO, 0)
    }

    /// See [`crate::host::Host::tron_contract_version`].
    fn tron_contract_version(&self, _address: Address) -> i32 {
        0
    }

    /// See [`crate::host::Host::tron_allow_tvm_vote`].
    fn tron_allow_tvm_vote(&self) -> bool {
        false
    }

    /// See [`crate::host::Host::tron_allow_tvm_compatible_evm`].
    fn tron_allow_tvm_compatible_evm(&self) -> bool {
        false
    }

    /// See [`crate::host::Host::tron_energy_fee`].
    fn tron_energy_fee(&self) -> i64 {
        0
    }

    /// See [`crate::host::Host::tron_root_tx_id`].
    fn tron_root_tx_id(&self) -> primitives::B256 {
        primitives::B256::ZERO
    }

    /// See [`crate::host::Host::tron_bump_create_nonce`]. Post-increment:
    /// returns the current counter value, then advances it by one.
    fn tron_bump_create_nonce(&mut self) -> u64 {
        0
    }

    /// See [`crate::host::Host::tron_record_created_contract`].
    fn tron_record_created_contract(
        &mut self,
        _address: Address,
        _creator: Address,
        _is_create2: bool,
    ) {
    }
}

// ---- No-op impls for revm-internal database types ----
//
// Our forked `revm-context::Host for Context<...>` bounds `DB:
// Database + TronDatabaseExt`. To avoid forcing every downstream user
// to write boilerplate, we provide default-zero impls for the database
// types living in `revm-database-interface` (which we already depend
// on). Types in higher-level revm crates (CacheDB etc.) live above us
// in the dep graph — for those, use [`TronCompat`] to wrap.

impl<E> TronDatabaseExt for database_interface::EmptyDBTyped<E> {}

impl<T: database_interface::DatabaseRef> TronDatabaseExt
    for database_interface::WrapDatabaseRef<T>
{
}

// ---- TronCompat wrapper ----
//
// Wraps any [`Database`] (or [`DatabaseRef`]) and provides the no-op
// `TronDatabaseExt` impl. Used in upstream revm tests that have
// `CacheDB<EmptyDB>` (revm-database lives above us in the dep graph,
// so the impl can't go in revm-context-interface, and the orphan
// rule blocks it in revm-handler too). Wrap with `TronCompat(db)`
// instead of touching the orphan-rule fight in every test file.

use database_interface::{Database, DatabaseCommit};
use primitives::{B256, StorageKey, StorageValue};
use state::{bytecode::Bytecode, Account, AccountId, AccountInfo};

/// Newtype wrapper that gives any [`Database`] a default-zero
/// [`TronDatabaseExt`] impl. Use when the wrapped DB lives in a crate
/// above this one in the dep graph (e.g. `CacheDB` from
/// `revm-database`).
#[derive(Debug, Clone, Default)]
pub struct TronCompat<DB>(pub DB);

impl<DB: Database> Database for TronCompat<DB> {
    type Error = DB::Error;

    fn basic(
        &mut self,
        address: Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        self.0.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.0.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        self.0.storage(address, index)
    }

    fn storage_by_account_id(
        &mut self,
        address: Address,
        account_id: AccountId,
        storage_key: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        self.0.storage_by_account_id(address, account_id, storage_key)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.0.block_hash(number)
    }
}

impl<DB: DatabaseCommit> DatabaseCommit for TronCompat<DB> {
    fn commit(&mut self, changes: primitives::AddressMap<Account>) {
        self.0.commit(changes)
    }

    fn commit_iter(
        &mut self,
        changes: &mut dyn Iterator<Item = (Address, Account)>,
    ) {
        self.0.commit_iter(changes)
    }
}

impl<DB> TronDatabaseExt for TronCompat<DB> {}
