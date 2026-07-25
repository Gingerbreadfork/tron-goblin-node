//! `ForkOverlay` — the overlay-stacking core of Chronos.
//!
//! A fork is a set of never-committed [`SessionBackend`] layers, one per
//! store, stacked over a *base* view of chain state:
//!
//! - [`BaseBlock::Height`] — each session wraps an
//!   [`ArchiveAtBackend`], the read-only at-height historical view. Nothing
//!   written to the overlay can ever reach disk: the base refuses writes and
//!   the sessions are never committed.
//! - [`BaseBlock::Latest`] — each session wraps the live backend directly.
//!   Reads see current head state; writes still land only in the overlay.
//!
//! ```text
//!   VM writes ─▶ top SessionBackend ─▶ … ─▶ SessionBackend(layer 0)
//!                                                     │
//!                                        ArchiveAtBackend(height N)  ─▶ live
//!                                             (read-only)                store
//! ```
//!
//! Snapshot / revert is layer stacking: [`ForkOverlay::checkpoint`] pushes a
//! fresh session on top of every store's stack, and
//! [`ForkOverlay::revert_to`] discards that layer and everything above it —
//! anvil's `evm_snapshot` / `evm_revert` semantics, in memory.

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountStore, BlockIndexStore, CodeStore, ContractStateStore, ContractStore,
    DelegatedResourceStore, DelegationStore, DynamicPropertiesStore, KvBackend, SessionBackend,
    StorageRowStore, UndoStoreId, VotesStore, WitnessStore,
};
use tron_index::{ArchiveAtBackend, ArchiveReader};
use tron_tvm::execute::VmStores;

use crate::error::SimError;

/// What a fork is seeded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseBlock {
    /// Fork from current head — sessions wrap the live backends.
    Latest,
    /// Fork from the state *after* block `N` fully applied — sessions
    /// wrap at-height archive views.
    Height(i64),
}

/// Raw backends the fork wraps — mirrors [`tron_rpc::EthCallBackends`]
/// exactly, plus optional `votes` and `abi` so mutating opcodes
/// (VOTEWITNESS, SELFDESTRUCT cleanup) land in the overlay instead of
/// silently no-op'ing. Built by the RPC layer from its `EthCallBackends`
/// and `ArchiveApiState` accessors; kept a plain struct here so `tron-sim`
/// never has to depend on `tron-rpc` (which depends on it).
#[derive(Clone)]
pub struct ForkBackends {
    pub accounts: Arc<dyn KvBackend>,
    pub code: Arc<dyn KvBackend>,
    pub storage: Arc<dyn KvBackend>,
    pub witnesses: Arc<dyn KvBackend>,
    pub contract_state: Arc<dyn KvBackend>,
    pub dyn_props: Arc<dyn KvBackend>,
    pub delegated_resources: Arc<dyn KvBackend>,
    pub delegation: Arc<dyn KvBackend>,
    pub contracts: Arc<dyn KvBackend>,
    /// VOTEWITNESS target store. When `None`, the bridge returns 0 as on
    /// the read-only call path.
    pub votes: Option<Arc<dyn KvBackend>>,
    /// SELFDESTRUCT contract-row cleanup store. When `None`, cleanup is
    /// skipped as on the read-only call path.
    pub abi: Option<Arc<dyn KvBackend>>,
    /// BLOCKHASH source. When `None`, BLOCKHASH returns zero.
    pub block_index: Option<Arc<dyn KvBackend>>,
}

/// One store's stack of overlay layers over a fixed base.
///
/// `layers` is never empty: `layers[0]` wraps `base`, and every later
/// layer wraps the one before it. The top layer (`layers.last()`) is where
/// current writes land and what [`ForkOverlay::vm_stores`] reads.
struct StoreStack {
    base: Arc<dyn KvBackend>,
    layers: Vec<Arc<SessionBackend>>,
}

impl StoreStack {
    fn new(base: Arc<dyn KvBackend>) -> Self {
        let bottom = Arc::new(SessionBackend::new(base.clone()));
        Self { base, layers: vec![bottom] }
    }

    /// The current writable/readable top layer as a trait object.
    fn top_dyn(&self) -> Arc<dyn KvBackend> {
        self.layers.last().expect("stack never empty").clone()
    }

    /// Push a fresh layer over the current top; subsequent writes land in it.
    fn push_layer(&mut self) {
        let parent = self.top_dyn();
        self.layers.push(Arc::new(SessionBackend::new(parent)));
    }

    /// Discard the layer at `idx` (clear its pending writes) and drop every
    /// layer above it. `idx` must be a valid, non-bottom layer index.
    fn revert_to(&mut self, idx: usize) {
        if idx == 0 || idx >= self.layers.len() {
            return;
        }
        self.layers[idx].revert();
        self.layers.truncate(idx + 1);
    }

    /// Total pending keys across every layer (upper bound on distinct
    /// touched keys — a key written in two layers counts twice, which is
    /// the memory-cost measure the cap cares about).
    fn overlay_keys(&self) -> usize {
        self.layers.iter().map(|s| s.pending_len()).sum()
    }

    /// Diff the current top-of-stack state against the view resolved
    /// through `from_below`, considering only keys touched in `from_layer..`.
    ///
    /// For a cumulative diff, `from_below` is the stack's own base and
    /// `from_layer` is 0. For a since-checkpoint diff, `from_below` is the
    /// layer just under the checkpoint and `from_layer` is the checkpoint
    /// layer index.
    fn diff(
        &self,
        from_below: &Arc<dyn KvBackend>,
        from_layer: usize,
    ) -> Result<Vec<DiffEntry>, SimError> {
        use std::collections::BTreeSet;
        let mut keys: BTreeSet<Vec<u8>> = BTreeSet::new();
        for layer in &self.layers[from_layer..] {
            for (k, _) in layer.pending_snapshot() {
                keys.insert(k);
            }
        }
        let top = self.layers.last().expect("stack never empty");
        let mut out = Vec::new();
        for k in keys {
            let before = from_below.get(&k)?;
            let after = top.get(&k)?;
            if before != after {
                out.push((k, before, after));
            }
        }
        Ok(out)
    }
}

/// A single changed key: `(key, before, after)`, each value `None` when
/// the key was absent on that side.
pub type DiffEntry = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);

/// Per-store raw state diff. `before` reads the base (or checkpoint) view;
/// `after` reads the current top-of-stack view. Only keys whose value
/// actually changed appear. Decoding into account/storage/code shapes is
/// the RPC layer's job (`DecodedStateDiff`).
#[derive(Debug, Default, Clone)]
pub struct RawStateDiff {
    pub accounts: Vec<DiffEntry>,
    pub code: Vec<DiffEntry>,
    pub storage: Vec<DiffEntry>,
    pub witnesses: Vec<DiffEntry>,
    pub contract_state: Vec<DiffEntry>,
    pub dyn_props: Vec<DiffEntry>,
    pub delegated_resources: Vec<DiffEntry>,
    pub delegation: Vec<DiffEntry>,
    pub contracts: Vec<DiffEntry>,
    pub votes: Vec<DiffEntry>,
    pub abi: Vec<DiffEntry>,
}

impl RawStateDiff {
    /// Total changed keys across all stores.
    pub fn len(&self) -> usize {
        self.accounts.len()
            + self.code.len()
            + self.storage.len()
            + self.witnesses.len()
            + self.contract_state.len()
            + self.dyn_props.len()
            + self.delegated_resources.len()
            + self.delegation.len()
            + self.contracts.len()
            + self.votes.len()
            + self.abi.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An opaque snapshot handle — the layer index a [`ForkOverlay::checkpoint`]
/// created. Passed back to [`ForkOverlay::revert_to`] /
/// [`ForkOverlay::diff_since`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkCheckpoint(usize);

/// The overlay-stacking core: a never-committed set of session layers per
/// store over an at-height or live base.
pub struct ForkOverlay {
    accounts: StoreStack,
    code: StoreStack,
    storage: StoreStack,
    witnesses: StoreStack,
    contract_state: StoreStack,
    dyn_props: StoreStack,
    delegated_resources: StoreStack,
    delegation: StoreStack,
    contracts: StoreStack,
    votes: Option<StoreStack>,
    abi: Option<StoreStack>,
    block_index: Option<StoreStack>,
    base: BaseBlock,
    /// Base-height head `(number, timestamp_ms)` read once at construction.
    seed_head: (i64, i64),
}

impl ForkOverlay {
    /// Build a fork over `b`.
    ///
    /// With `arch = Some((reader, height))` each store's base is an
    /// [`ArchiveAtBackend`] at `height` and `base` is
    /// [`BaseBlock::Height`]; coverage is validated up front. With
    /// `arch = None` each store's base is the live backend directly and
    /// `base` is [`BaseBlock::Latest`].
    pub fn new(
        b: &ForkBackends,
        arch: Option<(&ArchiveReader, i64)>,
    ) -> Result<Self, SimError> {
        let base = match arch {
            Some((_, h)) => BaseBlock::Height(h),
            None => BaseBlock::Latest,
        };

        // Validate coverage before building any at-height view.
        if let Some((reader, h)) = arch {
            match reader.coverage().map_err(|e| SimError::Backend(e.to_string()))? {
                Some((cb, ch)) if h >= cb && h <= ch => {}
                Some((cb, ch)) => {
                    return Err(SimError::OutOfCoverage { height: h, base: cb, head: ch })
                }
                None => return Err(SimError::NoCoverage),
            }
        }

        // Map one raw backend to its base view (at-height or live).
        let at = |live: &Arc<dyn KvBackend>, id: UndoStoreId| -> Arc<dyn KvBackend> {
            match arch {
                Some((reader, h)) => {
                    Arc::new(ArchiveAtBackend::new(live.clone(), reader.clone(), id, h))
                }
                None => live.clone(),
            }
        };
        let stack = |live: &Arc<dyn KvBackend>, id: UndoStoreId| StoreStack::new(at(live, id));
        let opt_stack = |live: &Option<Arc<dyn KvBackend>>, id: UndoStoreId| {
            live.as_ref().map(|l| StoreStack::new(at(l, id)))
        };

        let dyn_props = stack(&b.dyn_props, UndoStoreId::DynProps);

        // Seed head: for a height base, the fork "is at block N" so the head
        // number is N; the timestamp comes from the at-height dyn-props
        // (which hold block N's head timestamp exactly). For a latest base,
        // read both from the live dyn-props.
        let dp = DynamicPropertiesStore::new(dyn_props.top_dyn());
        let seed_num = match base {
            BaseBlock::Height(h) => h,
            BaseBlock::Latest => dp.latest_block_header_number().unwrap_or(0),
        };
        let seed_ts = dp.latest_block_header_timestamp().unwrap_or(0);

        Ok(Self {
            accounts: stack(&b.accounts, UndoStoreId::Accounts),
            code: stack(&b.code, UndoStoreId::Code),
            storage: stack(&b.storage, UndoStoreId::StorageRow),
            witnesses: stack(&b.witnesses, UndoStoreId::Witnesses),
            contract_state: stack(&b.contract_state, UndoStoreId::ContractState),
            dyn_props,
            delegated_resources: stack(&b.delegated_resources, UndoStoreId::DelegatedResources),
            delegation: stack(&b.delegation, UndoStoreId::Delegation),
            contracts: stack(&b.contracts, UndoStoreId::Contracts),
            votes: opt_stack(&b.votes, UndoStoreId::Votes),
            abi: opt_stack(&b.abi, UndoStoreId::Abi),
            block_index: b.block_index.as_ref().map(|bi| {
                // BLOCKHASH reads heights <= the block env's head; the live
                // block index is append-only by height, so no at-height view
                // is needed (matches the read-path wiring).
                StoreStack::new(bi.clone())
            }),
            base,
            seed_head: (seed_num, seed_ts),
        })
    }

    /// The base this fork was seeded from.
    pub fn base(&self) -> BaseBlock {
        self.base
    }

    /// `(head_number, head_timestamp_ms)` read at construction.
    pub fn seed_head(&self) -> (i64, i64) {
        self.seed_head
    }

    /// Build a fresh [`VmStores`] over the current top of every stack —
    /// the composition `eth_call` uses, but over the fork's sessions, and
    /// with `votes`/`abi` attached so mutating opcodes hit the overlay.
    /// Writes performed by the VM through the returned stores accumulate in
    /// the top layer and are visible to the next call on this overlay.
    pub fn vm_stores(&self) -> VmStores {
        VmStores {
            accounts: Arc::new(AccountStore::new(self.accounts.top_dyn())),
            code: Arc::new(CodeStore::new(self.code.top_dyn())),
            storage: Arc::new(StorageRowStore::new(self.storage.top_dyn())),
            witnesses: Arc::new(WitnessStore::new(self.witnesses.top_dyn())),
            contract_state: Arc::new(ContractStateStore::new(self.contract_state.top_dyn())),
            dynamic_properties: Arc::new(DynamicPropertiesStore::new(self.dyn_props.top_dyn())),
            delegated_resources: Arc::new(DelegatedResourceStore::new(
                self.delegated_resources.top_dyn(),
            )),
            // RPC-only bidirectional index; never read into any balance/
            // energy/consensus computation. Left unset (bridges skip it).
            delegated_resource_account_index: None,
            delegation: Arc::new(DelegationStore::new(self.delegation.top_dyn())),
            block_index: self
                .block_index
                .as_ref()
                .map(|s| Arc::new(BlockIndexStore::new(s.top_dyn()))),
            contracts: Some(Arc::new(ContractStore::new(self.contracts.top_dyn()))),
            votes: self
                .votes
                .as_ref()
                .map(|s| Arc::new(VotesStore::new(s.top_dyn()))),
            // reward-vi stays off, matching the read path (only legacy
            // pre-reward-opt voters read it).
            reward_vi: None,
            abi: self.abi.as_ref().map(|s| Arc::new(AbiStore::new(s.top_dyn()))),
        }
    }

    /// Every present stack, for lockstep operations.
    fn stacks_mut(&mut self) -> Vec<&mut StoreStack> {
        let mut v: Vec<&mut StoreStack> = vec![
            &mut self.accounts,
            &mut self.code,
            &mut self.storage,
            &mut self.witnesses,
            &mut self.contract_state,
            &mut self.dyn_props,
            &mut self.delegated_resources,
            &mut self.delegation,
            &mut self.contracts,
        ];
        if let Some(s) = self.votes.as_mut() {
            v.push(s);
        }
        if let Some(s) = self.abi.as_mut() {
            v.push(s);
        }
        if let Some(s) = self.block_index.as_mut() {
            v.push(s);
        }
        v
    }

    /// Push a new layer on every stack and return a handle to it. All
    /// stacks stay at the same depth, so one index identifies the
    /// checkpoint across every store.
    pub fn checkpoint(&mut self) -> ForkCheckpoint {
        // Depth is uniform across stacks; read it before pushing.
        let idx = self.accounts.layers.len();
        for s in self.stacks_mut() {
            s.push_layer();
        }
        ForkCheckpoint(idx)
    }

    /// Discard the checkpoint's layer and everything written above it,
    /// restoring the exact state as of `cp`.
    pub fn revert_to(&mut self, cp: ForkCheckpoint) {
        let idx = cp.0;
        for s in self.stacks_mut() {
            s.revert_to(idx);
        }
    }

    /// Total overlay keys across every layer of every stack — the figure
    /// the per-fork cap is enforced against.
    pub fn overlay_keys(&self) -> usize {
        let mut n = self.accounts.overlay_keys()
            + self.code.overlay_keys()
            + self.storage.overlay_keys()
            + self.witnesses.overlay_keys()
            + self.contract_state.overlay_keys()
            + self.dyn_props.overlay_keys()
            + self.delegated_resources.overlay_keys()
            + self.delegation.overlay_keys()
            + self.contracts.overlay_keys();
        if let Some(s) = &self.votes {
            n += s.overlay_keys();
        }
        if let Some(s) = &self.abi {
            n += s.overlay_keys();
        }
        if let Some(s) = &self.block_index {
            n += s.overlay_keys();
        }
        n
    }

    /// Cumulative diff of the whole fork against its base.
    pub fn cumulative_diff(&self) -> Result<RawStateDiff, SimError> {
        let mut d = RawStateDiff::default();
        d.accounts = self.accounts.diff(&self.accounts.base, 0)?;
        d.code = self.code.diff(&self.code.base, 0)?;
        d.storage = self.storage.diff(&self.storage.base, 0)?;
        d.witnesses = self.witnesses.diff(&self.witnesses.base, 0)?;
        d.contract_state = self.contract_state.diff(&self.contract_state.base, 0)?;
        d.dyn_props = self.dyn_props.diff(&self.dyn_props.base, 0)?;
        d.delegated_resources =
            self.delegated_resources.diff(&self.delegated_resources.base, 0)?;
        d.delegation = self.delegation.diff(&self.delegation.base, 0)?;
        d.contracts = self.contracts.diff(&self.contracts.base, 0)?;
        if let Some(s) = &self.votes {
            d.votes = s.diff(&s.base, 0)?;
        }
        if let Some(s) = &self.abi {
            d.abi = s.diff(&s.base, 0)?;
        }
        Ok(d)
    }

    /// Diff of everything written since checkpoint `cp`.
    pub fn diff_since(&self, cp: ForkCheckpoint) -> Result<RawStateDiff, SimError> {
        let idx = cp.0;
        // "before" for a since-checkpoint diff is the view resolved through
        // the layer just under the checkpoint layer.
        let since = |s: &StoreStack| -> Result<Vec<DiffEntry>, SimError> {
            if idx == 0 || idx >= s.layers.len() {
                return Ok(Vec::new());
            }
            let below = s.layers[idx - 1].clone() as Arc<dyn KvBackend>;
            s.diff(&below, idx)
        };
        let mut d = RawStateDiff::default();
        d.accounts = since(&self.accounts)?;
        d.code = since(&self.code)?;
        d.storage = since(&self.storage)?;
        d.witnesses = since(&self.witnesses)?;
        d.contract_state = since(&self.contract_state)?;
        d.dyn_props = since(&self.dyn_props)?;
        d.delegated_resources = since(&self.delegated_resources)?;
        d.delegation = since(&self.delegation)?;
        d.contracts = since(&self.contracts)?;
        if let Some(s) = &self.votes {
            d.votes = since(s)?;
        }
        if let Some(s) = &self.abi {
            d.abi = since(s)?;
        }
        Ok(d)
    }
}
