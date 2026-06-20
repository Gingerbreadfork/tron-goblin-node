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
    AccountStore, DelegatedResourceAccountIndexStore, DelegatedResourceStore,
    DynamicPropertiesStore, VotesStore,
};
use tron_crypto::address::Address as TronAddress;
use tron_proto::{Account, DelegatedResource, DelegatedResourceAccountIndex, Votes};

/// One reversible mutation made by a staking / suicide bridge. Each variant
/// captures whatever is needed to restore the affected store to its
/// pre-write value.
///
/// `Debug` is hand-written: the `DelegatedResourceIndex` variant carries an
/// `Arc` to the index store (which is not itself `Debug`), so the derive can't
/// be used; the manual impl prints the row keys/priors and elides the handle.
#[derive(Clone)]
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
    /// Prior state of the two bidirectional `DelegatedResourceAccountIndex`
    /// rows a DELEGATE/UNDELEGATERESOURCE opcode touched. This index is
    /// RPC-only (never read into consensus), and unlike the other staking
    /// stores it is NOT threaded through `reverse`, so the entry carries its
    /// own `Arc` to the store. Reversing restores each row to its prior value
    /// (or deletes it when it was absent). Gives the index the same per-frame
    /// revert parity the consensus `DelegatedResource` row gets — a delegate in
    /// an inner frame that reverts leaves no index row, as in java's dropped
    /// child Repository.
    DelegatedResourceIndex {
        index: Arc<DelegatedResourceAccountIndexStore>,
        from_key: Vec<u8>,
        from_prior: Option<DelegatedResourceAccountIndex>,
        to_key: Vec<u8>,
        to_prior: Option<DelegatedResourceAccountIndex>,
    },
    /// `TOTAL_NET_WEIGHT` was bumped by `delta`; reverse subtracts it.
    NetWeight { delta: i64 },
    /// `TOTAL_ENERGY_WEIGHT` was bumped by `delta`.
    EnergyWeight { delta: i64 },
    /// `TOTAL_TRON_POWER_WEIGHT` was bumped by `delta`.
    TronPowerWeight { delta: i64 },
}

impl std::fmt::Debug for StakingEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StakingEntry::Account { addr, prior } => f
                .debug_struct("Account")
                .field("addr", addr)
                .field("prior", prior)
                .finish(),
            StakingEntry::Votes { addr, prior } => f
                .debug_struct("Votes")
                .field("addr", addr)
                .field("prior", prior)
                .finish(),
            StakingEntry::DelegatedResource { key, prior } => f
                .debug_struct("DelegatedResource")
                .field("key", key)
                .field("prior", prior)
                .finish(),
            StakingEntry::DelegatedResourceIndex {
                from_key,
                from_prior,
                to_key,
                to_prior,
                ..
            } => f
                .debug_struct("DelegatedResourceIndex")
                .field("from_key", from_key)
                .field("from_prior", from_prior)
                .field("to_key", to_key)
                .field("to_prior", to_prior)
                .finish_non_exhaustive(),
            StakingEntry::NetWeight { delta } => {
                f.debug_struct("NetWeight").field("delta", delta).finish()
            }
            StakingEntry::EnergyWeight { delta } => {
                f.debug_struct("EnergyWeight").field("delta", delta).finish()
            }
            StakingEntry::TronPowerWeight { delta } => f
                .debug_struct("TronPowerWeight")
                .field("delta", delta)
                .finish(),
        }
    }
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
            StakingEntry::DelegatedResourceIndex {
                index,
                from_key,
                from_prior,
                to_key,
                to_prior,
            } => {
                // Restore each of the two index rows to its pre-write value.
                // The store exposes a true `delete_raw`, so an absent prior is
                // reversed by deleting (not the zeroed-default workaround the
                // DelegatedResource store needs).
                for (key, prior) in [(from_key, from_prior), (to_key, to_prior)] {
                    match prior {
                        Some(row) => index.put_raw(&key, &row).expect(
                            "db error reversing staking-journal delegated-resource-index write",
                        ),
                        None => index.delete_raw(&key).expect(
                            "db error reversing staking-journal delegated-resource-index create",
                        ),
                    }
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::{KvBackend, MemBackend};

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn addr(b: u8) -> TronAddress {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(b);
        TronAddress::from_raw(a)
    }

    // Dummy stores for the `unwind_to` params the index reversal doesn't use.
    fn other_stores() -> (AccountStore, DelegatedResourceStore, DynamicPropertiesStore) {
        (
            AccountStore::new(mem()),
            DelegatedResourceStore::new(mem()),
            DynamicPropertiesStore::new(mem()),
        )
    }

    /// A DelegatedResourceIndex entry whose rows were ABSENT before the write
    /// (a fresh delegation) is reversed by DELETING both rows — matching java's
    /// discarded child Repository on an inner-frame revert.
    #[test]
    fn delegated_resource_index_revert_deletes_fresh_rows() {
        let index = Arc::new(DelegatedResourceAccountIndexStore::new(mem()));
        let (from, to) = (addr(0x11), addr(0x22));
        let from_key = DelegatedResourceAccountIndexStore::v2_from_key(&from, &to).to_vec();
        let to_key = DelegatedResourceAccountIndexStore::v2_to_key(&from, &to).to_vec();

        // Simulate the bridge: snapshot priors (None), journal, then write.
        let mut journal = StakingJournal::default();
        journal.push(StakingEntry::DelegatedResourceIndex {
            index: Arc::clone(&index),
            from_key: from_key.clone(),
            from_prior: None,
            to_key: to_key.clone(),
            to_prior: None,
        });
        index
            .put_raw(
                &from_key,
                &DelegatedResourceAccountIndex { account: to.as_bytes().to_vec(), timestamp: 7, ..Default::default() },
            )
            .unwrap();
        index
            .put_raw(
                &to_key,
                &DelegatedResourceAccountIndex { account: from.as_bytes().to_vec(), timestamp: 7, ..Default::default() },
            )
            .unwrap();
        assert!(index.get_raw(&from_key).unwrap().is_some());
        assert!(index.get_raw(&to_key).unwrap().is_some());

        // Frame revert: unwind to 0 restores the pre-write (absent) state.
        let (accts, dr, dp) = other_stores();
        journal.unwind_to(0, &accts, None, &dr, &dp);
        assert!(index.get_raw(&from_key).unwrap().is_none(), "fresh from-row deleted on revert");
        assert!(index.get_raw(&to_key).unwrap().is_none(), "fresh to-row deleted on revert");
    }

    /// When the index rows EXISTED before (e.g. a re-delegation overwriting the
    /// timestamp), reversal restores the exact prior rows, not a delete.
    #[test]
    fn delegated_resource_index_revert_restores_prior_rows() {
        let index = Arc::new(DelegatedResourceAccountIndexStore::new(mem()));
        let (from, to) = (addr(0x33), addr(0x44));
        let from_key = DelegatedResourceAccountIndexStore::v2_from_key(&from, &to).to_vec();
        let to_key = DelegatedResourceAccountIndexStore::v2_to_key(&from, &to).to_vec();
        let prior_from = DelegatedResourceAccountIndex { account: to.as_bytes().to_vec(), timestamp: 100, ..Default::default() };
        let prior_to = DelegatedResourceAccountIndex { account: from.as_bytes().to_vec(), timestamp: 100, ..Default::default() };
        index.put_raw(&from_key, &prior_from).unwrap();
        index.put_raw(&to_key, &prior_to).unwrap();

        let mut journal = StakingJournal::default();
        journal.push(StakingEntry::DelegatedResourceIndex {
            index: Arc::clone(&index),
            from_key: from_key.clone(),
            from_prior: Some(prior_from.clone()),
            to_key: to_key.clone(),
            to_prior: Some(prior_to.clone()),
        });
        // Bridge overwrites with a newer timestamp.
        index
            .put_raw(&from_key, &DelegatedResourceAccountIndex { account: to.as_bytes().to_vec(), timestamp: 200, ..Default::default() })
            .unwrap();

        let (accts, dr, dp) = other_stores();
        journal.unwind_to(0, &accts, None, &dr, &dp);
        assert_eq!(index.get_raw(&from_key).unwrap().unwrap().timestamp, 100, "prior from-row restored");
        assert_eq!(index.get_raw(&to_key).unwrap().unwrap().timestamp, 100, "prior to-row restored");
    }
}
