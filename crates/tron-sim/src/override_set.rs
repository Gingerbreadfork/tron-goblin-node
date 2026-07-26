//! `OverrideSet` — the state/code/balance/block override model applied to
//! a fork before its calls run.
//!
//! Every application rule is verified against how the TVM actually reads the
//! stores, so an overridden value is read back byte-identically by the VM:
//!
//! - **balance** — read-modify-write `Account.balance`, creating the account
//!   if absent (the VM reads balances straight off the `Account` row).
//! - **code** — the VM loads runtime code **by address** from the code store
//!   (`TronDatabase::basic_ref`), so a code override writes the code store at
//!   the 21-byte address key, stamps `Account.code`/`code_hash`, and ensures a
//!   `SmartContract` row exists (which drives storage-key layout and
//!   snapshot-contract ISCONTRACT semantics).
//! - **state / stateDiff** — composed through the *same* key helpers the VM's
//!   SLOAD uses (`StorageRowStore::compose_key_with_addr_hash`), reading the
//!   contract's v1/v2 version and CREATE2 `trxHash` from the at-height
//!   contract row so a slot written by override is read back byte-identically
//!   for v1, v2, and CREATE2 contracts. `state` is replace-all (enumerate the
//!   contract's existing slots, delete, then write); `stateDiff` merges.
//! - **token_balances** — TRC-10 lives inline on `Account.asset_v2`; the
//!   override folds any asset-optimized balances inline first
//!   (`import_all_asset`) then merges, so a later VM re-import can't clobber it
//!   (inline values win the merge).
//! - **nonce** — accepted and ignored with a warning (TRON has no nonce).

use std::collections::BTreeMap;

use tron_chainbase::{import_all_asset, StorageRowStore};
use tron_crypto::address::Address;
use tron_crypto::hash::keccak256;
use tron_proto::{Account, SmartContract};
use tron_tvm::execute::VmStores;

use crate::error::SimError;

/// Per-account overrides. All fields are optional; only the ones set are
/// applied.
#[derive(Debug, Clone, Default)]
pub struct AccountOverride {
    /// Set `Account.balance` (sun). Creates the account if absent.
    pub balance: Option<i64>,
    /// Runtime bytecode to install at this address.
    pub code: Option<Vec<u8>>,
    /// Replace **all** of the contract's storage with these slots.
    pub state: Option<BTreeMap<[u8; 32], [u8; 32]>>,
    /// Merge these slots into the contract's storage.
    pub state_diff: Option<BTreeMap<[u8; 32], [u8; 32]>>,
    /// TRC-10 balances (token id → amount) merged into `asset_v2`.
    pub token_balances: Option<BTreeMap<i64, i64>>,
    /// Accepted for eth-tooling compatibility, ignored with a warning —
    /// TRON accounts have no nonce.
    pub nonce: Option<u64>,
}

/// Per-synthetic-block environment overrides.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockOverride {
    /// Synthetic block number (BLOCKNUMBER / head number).
    pub number: Option<i64>,
    /// Synthetic block time in **seconds** (TIMESTAMP).
    pub time_s: Option<i64>,
    /// COINBASE — the 20-byte EVM-form producing-witness address.
    pub coinbase: Option<[u8; 20]>,
}

/// A block's overrides: account state plus the block environment.
#[derive(Debug, Clone, Default)]
pub struct OverrideSet {
    pub accounts: BTreeMap<Address, AccountOverride>,
    pub block: Option<BlockOverride>,
}

fn sim_err(e: impl std::fmt::Debug) -> SimError {
    SimError::Backend(format!("{e:?}"))
}

impl OverrideSet {
    /// True when nothing would be applied to the stores (block-only or empty).
    pub fn is_account_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Apply the account overrides to a fork's stores. Block overrides are
    /// consumed separately by the executor (they flow into `VmBlockEnv`, not
    /// the stores — Phase 2 additionally writes the synthetic head into
    /// dyn-props). Returns human-readable warnings (e.g. ignored `nonce`).
    ///
    /// `max_state_slots` caps `state` replace-all enumeration; a contract
    /// with more slots than the cap errors rather than silently truncating.
    pub fn apply(
        &self,
        vm: &VmStores,
        max_state_slots: usize,
    ) -> Result<Vec<String>, SimError> {
        let mut warnings = Vec::new();
        for (addr, ov) in &self.accounts {
            self.apply_account(vm, addr, ov, max_state_slots, &mut warnings)?;
        }
        Ok(warnings)
    }

    fn apply_account(
        &self,
        vm: &VmStores,
        addr: &Address,
        ov: &AccountOverride,
        max_state_slots: usize,
        warnings: &mut Vec<String>,
    ) -> Result<(), SimError> {
        // Load the account (or start a fresh one at this address). Only
        // written back if a balance/code/trc10 override actually touches it.
        let mut acct = vm
            .accounts
            .get(addr)
            .map_err(sim_err)?
            .unwrap_or_else(|| Account {
                address: addr.as_bytes().to_vec(),
                ..Default::default()
            });
        let mut acct_dirty = false;

        if let Some(bal) = ov.balance {
            acct.balance = bal;
            acct_dirty = true;
        }

        if let Some(tokens) = &ov.token_balances {
            // Fold any asset-optimized balances inline first so the merge is
            // against the account's true current TRC-10 map; inline values
            // then win a later VM re-import.
            import_all_asset(&mut acct);
            for (id, amount) in tokens {
                acct.asset_v2.insert(id.to_string(), *amount);
            }
            acct_dirty = true;
        }

        if let Some(code) = &ov.code {
            let hash = keccak256(code);
            vm.code.put(addr.as_bytes(), code).map_err(sim_err)?;
            acct.code = code.clone();
            acct.code_hash = hash.to_vec();
            acct_dirty = true;
            // Ensure a contract row exists so the address is treated as a
            // contract (ISCONTRACT) and its storage keys use a defined layout.
            // A freshly-coded address is v2, non-CREATE2. If a row already
            // exists (real contract at this address), keep its version/trx_hash
            // (they drive the storage-key layout) but refresh its `bytecode`
            // so row reads (getcontract) reflect the override.
            if let Some(contracts) = &vm.contracts {
                match contracts.get(addr).map_err(sim_err)? {
                    Some(mut row) => {
                        row.bytecode = code.clone();
                        contracts.put(addr, &row).map_err(sim_err)?;
                    }
                    None => {
                        contracts
                            .put(
                                addr,
                                &SmartContract {
                                    contract_address: addr.as_bytes().to_vec(),
                                    bytecode: code.clone(),
                                    version: 0,
                                    trx_hash: Vec::new(),
                                    ..Default::default()
                                },
                            )
                            .map_err(sim_err)?;
                    }
                }
            }
        }

        if acct_dirty {
            vm.accounts.put(addr, &acct).map_err(sim_err)?;
        }

        // Storage overrides need the contract's slot-key layout, read AFTER a
        // possible code override created the row.
        if ov.state.is_some() || ov.state_diff.is_some() {
            let (is_v1, trx_hash) = match vm
                .contracts
                .as_ref()
                .and_then(|c| c.get(addr).ok().flatten())
            {
                Some(sc) => (sc.version == 1, sc.trx_hash),
                None => (false, Vec::new()),
            };
            let addr_hash = StorageRowStore::addr_hash(addr, &trx_hash);

            // `state` = replace-all: clear the contract's existing slots first.
            // The enumeration is BOUNDED — fetch at most cap+1 rows so a
            // contract with millions of slots can't be materialized (OOM)
            // before the cap rejects it.
            if let Some(state) = &ov.state {
                if state.len() > max_state_slots {
                    return Err(SimError::Backend(format!(
                        "state replace-all for {} supplies {} slots > cap {}; use stateDiff",
                        hex_addr(addr),
                        state.len(),
                        max_state_slots
                    )));
                }
                let existing = vm
                    .storage
                    .scan_prefix_by_addr_hash_bounded(&addr_hash, max_state_slots.saturating_add(1))
                    .map_err(sim_err)?;
                if existing.len() > max_state_slots {
                    return Err(SimError::Backend(format!(
                        "state replace-all for {} spans more than the cap of {} existing slots; \
                         use stateDiff to set individual slots instead",
                        hex_addr(addr),
                        max_state_slots
                    )));
                }
                for (key, _) in existing {
                    vm.storage.delete(&key).map_err(sim_err)?;
                }
                for (slot, value) in state {
                    let key = StorageRowStore::compose_key_with_addr_hash(&addr_hash, slot, is_v1);
                    vm.storage.put(&key, value).map_err(sim_err)?;
                }
            }

            // `stateDiff` = merge the given slots on top (also capped, so a
            // giant merge can't grow the overlay unbounded).
            if let Some(diff) = &ov.state_diff {
                if diff.len() > max_state_slots {
                    return Err(SimError::Backend(format!(
                        "stateDiff for {} supplies {} slots > cap {}",
                        hex_addr(addr),
                        diff.len(),
                        max_state_slots
                    )));
                }
                for (slot, value) in diff {
                    let key = StorageRowStore::compose_key_with_addr_hash(&addr_hash, slot, is_v1);
                    vm.storage.put(&key, value).map_err(sim_err)?;
                }
            }
        }

        if ov.nonce.is_some() {
            warnings.push(format!(
                "nonce override for {} ignored — TRON accounts have no nonce",
                hex_addr(addr)
            ));
        }

        Ok(())
    }
}

fn hex_addr(addr: &Address) -> String {
    let mut s = String::with_capacity(42);
    for b in addr.as_bytes() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
