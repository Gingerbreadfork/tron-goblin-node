//! Per-VM-frame rollback journal for the staking / SELFDESTRUCT opcode
//! bridges.
//!
//! ## Why this exists
//!
//! The Stake-1.0/2.0 opcode bridges and `SELFDESTRUCT` in
//! [`crate::tron_host`] write state DIRECTLY to the chainbase stores
//! (`AccountStore`, `VotesStore`, `DelegatedResourceStore`, and the
//! chain-global `TOTAL_*_WEIGHT` accumulators in `DynamicPropertiesStore`).
//! Those writes are NOT revm journal entries, so revm's per-frame
//! `checkpoint_revert` never undoes them. Their only other rollback —
//! `tron-executor`'s per-TRANSACTION `VmSession` — is applied once, on the
//! top-level VM outcome, and so only covers a WHOLE-tx revert.
//!
//! java-tron scopes every VM call/create frame's staking/suicide side
//! effects to that frame's child `Repository`, committed to the parent ONLY
//! on frame success and discarded on frame revert. So a staking op inside an
//! inner CALL/CREATE frame that REVERTS leaves no trace — even when the
//! top-level transaction frame SUCCEEDS. Without a per-frame rollback we
//! leak those inner-frame writes (the callee's `frozen` / `frozen_v2` /
//! `unfrozen_v2` / votes / `delegated_*` fields, `Votes` /
//! `DelegatedResource` rows, and the global `TOTAL_*_WEIGHT` accumulators)
//! into committed state — a silent divergence the contractRet tripwire can't
//! see, since the tx succeeds on both nodes.
//!
//! ## How it works
//!
//! Every staking/suicide bridge write records a reversing entry here BEFORE
//! it mutates the store (prior-value snapshot for the row stores; the signed
//! delta for the weight accumulators). The [`crate::trc10::Trc10Inspector`]
//! owns the same `Arc<Mutex<StakingJournal>>`: at each `call`/`create` it
//! records `len()` into a per-frame start-marker stack, and at
//! `call_end`/`create_end` for a frame that reverted/halted it unwinds (LIFO)
//! every entry pushed within that frame's subtree — so even an ANCESTOR
//! revert undoes a succeeded descendant's writes, exactly as java discards
//! the uncommitted child deposit. This mirrors the `committed` / `cs_journal`
//! mechanism that already covers the CALLTOKEN / `ContractState` out-of-band
//! writes.

use std::sync::{Arc, Mutex};

use tron_chainbase::{
    AccountStore, DelegatedResourceStore, DynamicPropertiesStore, VotesStore,
};
use tron_crypto::address::Address as TronAddress;
use tron_proto::{Account, DelegatedResource, Votes};

/// One reversible mutation made by a staking / suicide bridge. Each variant
/// captures whatever is needed to restore the affected store to its
/// pre-write value.
#[derive(Debug, Clone)]
pub enum StakingEntry {
    /// Prior full `Account` row (`None` = the row did not exist before, so
    /// restoring deletes it).
    Account {
        addr: TronAddress,
        prior: Option<Account>,
    },
    /// Prior `Votes` row (`None` = absent before → restore deletes it).
    Votes {
        addr: TronAddress,
        prior: Option<Votes>,
    },
    /// Prior `DelegatedResource` row keyed by the raw store key
    /// (`None` = absent before → restore deletes it).
    DelegatedResource {
        key: Vec<u8>,
        prior: Option<DelegatedResource>,
    },
    /// `TOTAL_NET_WEIGHT` was bumped by `delta`; reverse subtracts it.
    NetWeight { delta: i64 },
    /// `TOTAL_ENERGY_WEIGHT` was bumped by `delta`.
    EnergyWeight { delta: i64 },
    /// `TOTAL_TRON_POWER_WEIGHT` was bumped by `delta`.
    TronPowerWeight { delta: i64 },
}

/// A flat LIFO log of [`StakingEntry`] reversers. Shared (via
/// `Arc<Mutex<_>>`) between the host (writer) and the inspector (frame
/// boundaries + unwind).
#[derive(Debug, Default)]
pub struct StakingJournal {
    entries: Vec<StakingEntry>,
}

impl StakingJournal {
    /// A fresh, empty journal wrapped for sharing.
    pub fn new_shared() -> Arc<Mutex<StakingJournal>> {
        Arc::new(Mutex::new(StakingJournal::default()))
    }

    /// Record one reversing entry (the host calls this BEFORE each write).
    pub fn push(&mut self, entry: StakingEntry) {
        self.entries.push(entry);
    }

    /// Current journal length — captured by the inspector at each frame entry.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Pop and reverse every entry down to `start` (LIFO), restoring the
    /// affected store rows / weight accumulators to their pre-frame values.
    /// Called by the inspector for a frame whose subtree reverted.
    pub fn unwind_to(
        &mut self,
        start: usize,
        accounts: &AccountStore,
        votes: Option<&VotesStore>,
        delegated_resources: &DelegatedResourceStore,
        dyn_props: &DynamicPropertiesStore,
    ) {
        while self.entries.len() > start {
            let Some(entry) = self.entries.pop() else {
                break;
            };
            Self::reverse(entry, accounts, votes, delegated_resources, dyn_props);
        }
    }

    fn reverse(
        entry: StakingEntry,
        accounts: &AccountStore,
        votes: Option<&VotesStore>,
        delegated_resources: &DelegatedResourceStore,
        dyn_props: &DynamicPropertiesStore,
    ) {
        match entry {
            StakingEntry::Account { addr, prior } => match prior {
                Some(row) => accounts
                    .put(&addr, &row)
                    .expect("db error reversing staking-journal account write"),
                None => accounts
                    .delete(&addr)
                    .expect("db error reversing staking-journal account create"),
            },
            StakingEntry::Votes { addr, prior } => {
                if let Some(store) = votes {
                    match prior {
                        Some(row) => store
                            .put(&addr, &row)
                            .expect("db error reversing staking-journal votes write"),
                        None => store
                            .delete(&addr)
                            .expect("db error reversing staking-journal votes create"),
                    }
                }
            }
            StakingEntry::DelegatedResource { key, prior } => match prior {
                Some(row) => delegated_resources
                    .put_raw(&key, &row)
                    .expect("db error reversing staking-journal delegated-resource write"),
                // No prior row: the bridge only ever WRITES delegated-resource
                // rows via `put_raw` (it never deletes), and a missing-row
                // restore would need a raw delete. The delegate bridge always
                // starts from `unwrap_or_default()`, so a first-time write has
                // `prior = None`; reversing it must clear the row. Delete by
                // writing the default (all-zero) record — byte-identical to a
                // never-written key for every downstream read (`get_raw` of a
                // zeroed record yields a record whose balances are 0, the same
                // the bridge treats as "no delegation"). A true key delete isn't
                // exposed on the store; the zeroed record is the faithful
                // equivalent java reaches by discarding the child deposit.
                None => delegated_resources
                    .put_raw(&key, &DelegatedResource::default())
                    .expect("db error reversing staking-journal delegated-resource create"),
            },
            StakingEntry::NetWeight { delta } => {
                dyn_props.add_total_net_weight_unclamped(-delta)
            }
            StakingEntry::EnergyWeight { delta } => {
                dyn_props.add_total_energy_weight_unclamped(-delta)
            }
            StakingEntry::TronPowerWeight { delta } => {
                dyn_props.add_total_tron_power_weight_unclamped(-delta)
            }
        }
    }
}

/// Convenience handle bundling the shared journal so the host can record
/// snapshots without re-locking for each helper. `None` on read-only setups
/// (eth_call / unit tests) where there are no frames to unwind.
pub type SharedStakingJournal = Arc<Mutex<StakingJournal>>;
