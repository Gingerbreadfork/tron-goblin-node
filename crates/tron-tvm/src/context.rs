//! Interface between precompiles and the surrounding state.
//!
//! A future EVM interpreter will implement [`EvmContext`] over the
//! current execution frame (with the active per-tx [`tron_chainbase::SessionBackend`]
//! that Track 1 introduced). Precompiles take `&dyn EvmContext` and
//! read whatever they need; they don't own state directly.

use tron_chainbase::StoreError;
use tron_crypto::address::Address;
use tron_proto::{Account, DelegatedResource, Witness};

/// What a precompile can ask the surrounding execution frame for.
///
/// Methods return owned values so the interpreter can wrap any kind
/// of borrowed-store or session reference without complicating the
/// trait object's lifetime.
pub trait EvmContext {
    /// The 21-byte address of the EOA or contract that called the
    /// precompile (`msg.sender`).
    fn caller(&self) -> Address;

    /// The 21-byte address of the contract being executed (`address(this)`).
    /// For top-level CALL, this equals the to-address of the
    /// `TriggerSmartContract`.
    fn callee(&self) -> Address;

    /// Read an account by address. Returns `None` if absent.
    fn get_account(&self, address: &Address) -> Result<Option<Account>, EvmContextError>;

    /// Read a witness record by address.
    fn get_witness(&self, address: &Address) -> Result<Option<Witness>, EvmContextError>;

    /// Read a chain-parameter `i64` from `DynamicPropertiesStore` by
    /// raw key bytes. Returns `None` if the key isn't set.
    ///
    /// java-tron's `GetChainParameter` precompile takes a 32-byte
    /// parameter selector (an `i64` index into a hardcoded table) —
    /// see [`crate::precompiles::chain_param`] for the mapping.
    fn chain_parameter_long(&self, key: &[u8]) -> Result<Option<i64>, EvmContextError>;

    /// Latest block number (head). Used by some precompiles to compute
    /// expiry windows.
    fn block_number(&self) -> i64;

    /// The **executing block's** timestamp in milliseconds — what the
    /// `TIMESTAMP` opcode reflects (block N during apply).
    fn block_timestamp_ms(&self) -> i64;

    /// The **committed head's** block timestamp in milliseconds — java's
    /// `getLatestBlockHeaderTimestamp()`, which the resource model's
    /// `getHeadSlot()` reads. During block-N apply this is block N-1 (the head
    /// pointer is only advanced after the tx loop), so it differs from
    /// [`Self::block_timestamp_ms`]. Defaults to `block_timestamp_ms()` for
    /// contexts (mocks / constant calls) where the two coincide.
    fn latest_block_timestamp_ms(&self) -> i64 {
        self.block_timestamp_ms()
    }

    /// Snapshot every registered witness. Used by consensus paths that
    /// need to scan or sum across the entire SR set.
    ///
    /// Returns owned values so the implementer can wrap a session
    /// without lifetime entanglement.
    fn all_witnesses(&self) -> Result<Vec<Witness>, EvmContextError>;

    /// Read a delegated-resource record (the one that
    /// `DelegateResourceContract` writes for the `(from, to)` pair).
    /// Returns `None` if no entry exists.
    ///
    /// This is the v2 layout — the `frozen_balance_for_*` fields hold
    /// the per-resource amounts and `expire_time_for_*` holds the
    /// per-resource expiry. Used by `CheckUnDelegateResource`.
    fn get_delegated_resource(
        &self,
        from: &Address,
        to: &Address,
    ) -> Result<Option<DelegatedResource>, EvmContextError>;

    /// Read the **locked** v2 delegated-resource record for `(from, to)` —
    /// the row a `DelegateResourceContract` with `lock = true` writes under
    /// the locked-prefix key. Distinct from [`Self::get_delegated_resource`]
    /// (which reads the unlocked row). `ResourceV2` sums both.
    ///
    /// Defaults to `None` so callers/mocks that don't model locked
    /// delegations keep compiling; chainbase-backed impls override it.
    fn get_locked_delegated_resource(
        &self,
        _from: &Address,
        _to: &Address,
    ) -> Result<Option<DelegatedResource>, EvmContextError> {
        Ok(None)
    }

    /// Per-contract dynamic energy penalty factor. Returns `0` (no
    /// penalty) for accounts that aren't contracts or that haven't
    /// accumulated penalty. Mirrors java-tron's
    /// `ContractStateStore::getDynamicEnergyFactor`.
    ///
    /// The value is in units of [`crate::energy::DYNAMIC_ENERGY_FACTOR_DECIMAL`]
    /// (so `5_000` means +50%). Returns `0` unless
    /// `ALLOW_DYNAMIC_ENERGY` chain parameter is set.
    fn dynamic_energy_factor(&self, contract: &Address) -> Result<i64, EvmContextError>;

    /// Total claimable reward for `voter`, in sun. Mirrors java-tron's
    /// `MortgageService.queryReward`.
    ///
    /// Includes:
    /// 1. The Vi-accumulator delta across cycles for each witness the
    ///    voter has voted for (the "earned but not yet claimed" share
    ///    of block rewards).
    /// 2. `Account.allowance` — rewards that have already been
    ///    finalized into the account but not yet withdrawn.
    ///
    /// The default implementation returns only `(2)` so the trait stays
    /// usable for callers without a `DelegationStore` handle — chainbase-
    /// backed implementations override this method with the full math.
    fn query_reward(&self, voter: &Address) -> Result<i64, EvmContextError> {
        Ok(self
            .get_account(voter)?
            .map(|a| a.allowance)
            .unwrap_or(0))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvmContextError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}
