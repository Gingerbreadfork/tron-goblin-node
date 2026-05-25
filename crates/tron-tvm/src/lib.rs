//! TRON Virtual Machine port — Phase 1 + Phase 2.
//!
//! ## What's here (consensus-critical, fully tested)
//!
//! ### EVM interpreter (revm-based)
//! `revm` 40.x is wired in as a library dependency (not a maintained
//! fork). TRON-specific extensions plug in via revm's extension points:
//! * [`evm::TronPrecompiles`] — a custom `PrecompileProvider` that
//!   dispatches `0x09`, `0x0a`, and `0x01000005..0x01000015` (plus the
//!   Ethereum-compat extras at `0x0002_0003`, `0x0002_0009`,
//!   `0x0000_0100`) to our [`PrecompileImpl`] registry, falling back
//!   to revm's `EthPrecompiles` for `0x01..=0x08`.
//! * [`database::TronDatabase`] — adapts revm's `Database` /
//!   `DatabaseRef` / `DatabaseCommit` to our `AccountStore`,
//!   `CodeStore`, and `StorageRowStore` (v2 composite-key layout),
//!   handling the 20-byte ↔ 21-byte address conversion.
//! * [`execute::execute_trigger`] — high-level entry point for
//!   `TriggerSmartContract` execution. The block executor calls this.
//!
//! ### Precompile registry
//! Every precompile address from `org.tron.core.vm.PrecompiledContracts`
//! mapped to a typed [`PrecompileImpl`]. The registry round-trips
//! address ↔ impl and has no duplicates (pinned by tests).
//!
//! ### Implemented precompiles (Phase 1 + Phase 2a)
//! * **`BatchValidateSign` (0x09)** — recoverable ECDSA, up to 16 sigs.
//! * **`ValidateMultiSign` (0x0a)** — reads on-chain `Permission`,
//!   sums weighted-key matches, compares to `threshold`. Resolves
//!   owner / witness / active permissions by id.
//! * **`IsSrCandidate`, `VoteCount`, `UsedVoteCount`,
//!   `ReceivedVoteCount`, `TotalVoteCount`** — vote/SR queries.
//! * **`RewardBalance`** — returns `Account.allowance` (the
//!   proper queryReward needs the Vi-accumulator).
//! * **`GetChainParameter`** — 8 selector → key mappings pinned.
//! * **`AvailableUnfreezeV2Size`, `UnfreezableBalanceV2`,
//!   `ExpireUnfreezeBalanceV2`** — read `Account.unfrozen_v2`.
//! * **`DelegatableResource`, `ResourceV2`, `ResourceUsage`,
//!   `TotalResource`, `TotalDelegatedResource`,
//!   `TotalAcquiredResource`** — read `Account.frozen_v2` and the
//!   per-resource delegated/acquired fields.
//! * **`CheckUnDelegateResource`** — reads
//!   `DelegatedResourceStore` and returns the three-word tuple
//!   `(free, max_undelegate, expire)`.
//!
//! ### Energy model
//! * Gas ↔ energy conversion (1:1 currently, but routed through
//!   a helper so a future renormalisation lives in one place).
//! * `energy_fee_in_sun(energy, fee_per_unit)` with overflow checks.
//! * `energy_with_dynamic_penalty(base, factor)` — pinned formula
//!   `effective = base * (DECIMAL + factor) / DECIMAL`.
//! * `effective_energy_cost(base, factor, allow_dynamic)` — combines
//!   the chain-parameter gate with the per-contract factor, falling
//!   back to `base` when the gate is off.
//! * `PrecompileImpl::effective_energy_cost(input, ctx)` — final
//!   charge after applying the per-contract factor read from
//!   `ContractStateStore` via the [`EvmContext`] seam.
//!
//! ### `EvmContext` trait
//! The interface between the (future) EVM interpreter and everything
//! it needs to read: accounts, witnesses, chain parameters, delegated
//! resources, dynamic-energy factors, `all_witnesses` (for
//! `TotalVoteCount` and consensus paths).
//!
//! ## Deliberately deferred (each its own follow-up session)
//!
//! None right now — every previously-deferred item has shipped. Future
//! work flagged in individual files (e.g. `shielded_transfer.rs` for
//! the MerkleContainer note-tree port) is tracked there.

pub mod address;
pub mod context;
pub mod database;
pub mod energy;
pub mod evm;
pub mod execute;
pub mod internal_tx;
pub mod precompiles;
pub mod proposals;
pub mod reward;
pub mod shielded;
pub mod tracer;
pub mod trc10;
pub mod tron_host;

pub use address::PrecompileAddress;
pub use context::{EvmContext, EvmContextError};
pub use energy::{
    effective_energy_cost, energy_fee_in_sun, energy_to_gas, energy_with_dynamic_penalty,
    gas_to_energy, EnergyError, EnergyParams, DYNAMIC_ENERGY_FACTOR_DECIMAL,
};
pub use precompiles::{
    PrecompileError, PrecompileImpl, PrecompileResult, ALL_PRECOMPILES,
};
pub use proposals::ProposalSet;
