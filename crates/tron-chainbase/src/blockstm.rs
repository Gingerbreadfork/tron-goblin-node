//! Block-STM multi-version memory — phase 1: the pure MVCC core.
//!
//! Optimistic parallel block execution (see `working/BLOCKSTM-DESIGN.md`) needs a
//! place to hold the *speculative* writes of in-flight transactions, versioned by
//! transaction index, so that a higher-indexed tx reading a key sees the write of
//! the highest **lower-indexed** tx (or the committed base) — exactly what serial
//! execution would have seen. This module is that store plus the read-set
//! validation used to detect when a speculative read was wrong and the tx must be
//! re-executed.
//!
//! It is deliberately self-contained and integration-free: it knows nothing about
//! the EVM, actuators, or RocksDB. Higher phases wrap a `KvBackend` around it to
//! capture per-tx read/write-sets (phase 2) and drive the parallel scheduler
//! (phase 3). Keeping the conflict-resolution logic pure makes it exhaustively
//! unit-testable, which matters because a bug here is a silent consensus
//! divergence.
//!
//! Concurrency note: a single `RwLock<HashMap>` guards the map for now —
//! correctness first. Phase 3 swaps it for a sharded / lock-free map; the `&self`
//! API is unchanged by that.

use crate::backend::{KvBackend, KvError};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Identifies one of the node's KV stores (accounts, storage_row, dyn_props, …).
/// The conflict-key space is `(StoreId, key-bytes)`; each store gets a stable
/// small index so two different stores never alias on the same key bytes.
pub type StoreId = u16;

/// A transaction's position in the block (0-based serial execution order). The
/// whole point of the version index is "what would tx `i` have read if every tx
/// `< i` had already run".
pub type TxIdx = u32;

/// A value a transaction wrote: `Some` = put, `None` = delete (tombstone). Stored
/// so a reader sees a delete as "absent" rather than falling through to the base.
pub type VersionValue = Option<Vec<u8>>;

/// A (transaction, incarnation) pair. A tx is re-executed (a new *incarnation*)
/// when an earlier read is invalidated; the incarnation lets validation tell a
/// re-run's writes apart from the originals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub idx: TxIdx,
    pub incarnation: u32,
}

/// One slot for a (store,key) at a particular tx index.
#[derive(Clone, Debug)]
enum Entry {
    /// A concrete value from a finished incarnation.
    Written {
        value: VersionValue,
        incarnation: u32,
    },
    /// The writing tx is mid-re-execution; its prior value can't be trusted.
    /// Block-STM's ESTIMATE — a reader must treat the writer as a dependency.
    Estimate,
}

/// Where a read resolved. Recorded in the read-set so validation can re-check that
/// the same source would still serve the read after other txs commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOrigin {
    /// No lower-indexed tx had written the key — the value came from the committed
    /// base state.
    Base,
    /// The value came from a lower tx's speculative write.
    Version(Version),
}

/// Outcome of resolving a read against the multi-version memory.
#[derive(Clone, Debug)]
pub enum ReadOutcome {
    /// Resolved to a lower tx's write (`origin = Version`). `value` is its put/
    /// tombstone.
    Versioned {
        value: VersionValue,
        version: Version,
    },
    /// No lower tx wrote the key — caller should read the base backend and record
    /// [`ReadOrigin::Base`].
    Base,
    /// A lower tx that wrote this key is currently an ESTIMATE (being re-run). The
    /// reader can't proceed deterministically; the scheduler should make it wait
    /// on `blocking` and retry.
    Blocked { blocking: TxIdx },
}

/// One entry of a transaction's read-set: the key it read, where the value came
/// from, and the value itself.
///
/// Validation is **value-based**: a read stays valid as long as re-resolving the
/// key yields the same `value` it returned during execution — even if a
/// *different* (or newly-visible) lower tx now serves it, as long as that tx
/// wrote the identical bytes. This is the standard Block-STM precision
/// improvement over version-based validation: idempotent "write the same value"
/// updates (e.g. revm crediting the zero-address beneficiary `+= 0` on every tx,
/// or any RMW that lands on its prior value) no longer create a false
/// every-tx-depends-on-the-previous chain that would force ~n re-execution
/// rounds. `origin` is retained only to validate reads that resolved to the
/// (block-invariant) committed base.
#[derive(Clone, Debug)]
pub struct ReadDescriptor {
    pub store: StoreId,
    pub key: Vec<u8>,
    pub origin: ReadOrigin,
    pub value: VersionValue,
}

/// Number of independently-locked shards in the multi-version store. Reads and
/// writes hash `(store,key)` to a shard, so concurrent accesses to *different*
/// keys (the common case across a block's txs) rarely contend on the same lock.
/// A single global `RwLock` here was the dominant cost — 32 threads cache-line-
/// bouncing on one lock word swamped the actual work.
const MV_SHARDS: usize = 256;

/// The multi-version store: for each `(store,key)`, the writes keyed by tx index.
/// Sharded into [`MV_SHARDS`] independently-locked maps.
pub struct MvMemory {
    shards: Vec<RwLock<HashMap<(StoreId, Vec<u8>), BTreeMap<TxIdx, Entry>>>>,
}

impl Default for MvMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl MvMemory {
    pub fn new() -> Self {
        Self {
            shards: (0..MV_SHARDS).map(|_| RwLock::new(HashMap::new())).collect(),
        }
    }

    /// Pick the shard for `(store,key)` via FNV-1a. Sharding is a pure
    /// performance concern — it never affects which value a read resolves to, so
    /// the hash need not be cryptographic or stable across versions.
    #[inline]
    fn shard(&self, store: StoreId, key: &[u8]) -> &RwLock<HashMap<(StoreId, Vec<u8>), BTreeMap<TxIdx, Entry>>> {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        h ^= store as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        for &b in key {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        &self.shards[(h as usize) & (MV_SHARDS - 1)]
    }

    /// Resolve what tx `reader` should see for `(store,key)`: the write of the
    /// highest tx strictly below `reader`, or `Base` if none. An ESTIMATE from a
    /// lower tx yields `Blocked`.
    pub fn read(&self, store: StoreId, key: &[u8], reader: TxIdx) -> ReadOutcome {
        let map = self.shard(store, key).read().expect("MvMemory poisoned");
        let Some(versions) = map.get(&(store, key.to_vec())) else {
            return ReadOutcome::Base;
        };
        // Highest tx index strictly below the reader.
        match versions.range(..reader).next_back() {
            None => ReadOutcome::Base,
            Some((&idx, Entry::Estimate)) => ReadOutcome::Blocked { blocking: idx },
            Some((&idx, Entry::Written { value, incarnation })) => ReadOutcome::Versioned {
                value: value.clone(),
                version: Version {
                    idx,
                    incarnation: *incarnation,
                },
            },
        }
    }

    /// Record a finished incarnation's writes (put/tombstone) at tx `version.idx`.
    pub fn record_writes(&self, version: Version, writes: &[(StoreId, Vec<u8>, VersionValue)]) {
        for (store, key, value) in writes {
            let mut map = self.shard(*store, key).write().expect("MvMemory poisoned");
            map.entry((*store, key.clone())).or_default().insert(
                version.idx,
                Entry::Written {
                    value: value.clone(),
                    incarnation: version.incarnation,
                },
            );
        }
    }

    /// Mark a tx's previously-written keys as ESTIMATE before re-executing it, so
    /// concurrent readers below the next incarnation treat them as a dependency
    /// instead of reading a soon-to-be-stale value.
    pub fn mark_estimates(&self, idx: TxIdx, written_keys: &[(StoreId, Vec<u8>)]) {
        for (store, key) in written_keys {
            let mut map = self.shard(*store, key).write().expect("MvMemory poisoned");
            if let Some(versions) = map.get_mut(&(*store, key.clone())) {
                versions.insert(idx, Entry::Estimate);
            }
        }
    }

    /// Remove a tx's entries for keys it no longer writes in its newest
    /// incarnation (a re-run may touch fewer keys). Leaves keys still written by
    /// `record_writes`.
    pub fn remove_writes(&self, idx: TxIdx, stale_keys: &[(StoreId, Vec<u8>)]) {
        for (store, key) in stale_keys {
            let mut map = self.shard(*store, key).write().expect("MvMemory poisoned");
            if let Some(versions) = map.get_mut(&(*store, key.clone())) {
                versions.remove(&idx);
            }
        }
    }

    /// Re-validate a tx's read-set (value-based — see [`ReadDescriptor`]): every
    /// read must still resolve to the same *value* it saw during execution.
    ///
    /// * Resolves to a lower tx's write → valid iff that write's bytes equal the
    ///   recorded value (a different writer that produced identical bytes is
    ///   fine; the tx would have computed the same result).
    /// * Resolves to the committed base → valid iff the read originally came from
    ///   the base too (the base is invariant for the whole block, so its value is
    ///   unchanged; a read that previously saw a lower write but now sees base
    ///   means that writer vanished and is conservatively treated as stale).
    /// * An ESTIMATE (writer mid-re-execution) → fail; the dependency is in flux.
    pub fn validate(&self, reader: TxIdx, read_set: &[ReadDescriptor]) -> bool {
        for rd in read_set {
            match self.read(rd.store, &rd.key, reader) {
                ReadOutcome::Base => {
                    if rd.origin != ReadOrigin::Base {
                        return false;
                    }
                }
                ReadOutcome::Versioned { value, .. } => {
                    if value != rd.value {
                        return false;
                    }
                }
                ReadOutcome::Blocked { .. } => return false,
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Phase 2: per-tx read/write capture + a KvBackend that resolves through MVCC.
// ---------------------------------------------------------------------------

/// A single transaction's captured read-set + write-set during one speculative
/// execution. Shared (behind a `Mutex`) across all of the tx's wrapped stores; a
/// tx executes on one thread, so the lock is uncontended within a tx.
#[derive(Default)]
pub struct TxCapture {
    /// Every cross-tx read, in order, with where it resolved — replayed by
    /// [`MvMemory::validate`] to detect stale speculation.
    pub reads: Vec<ReadDescriptor>,
    /// Last value written per key. Serves read-your-writes during execution AND
    /// is the write-set published to the multi-version memory afterward.
    pub writes: HashMap<(StoreId, Vec<u8>), VersionValue>,
    /// Commutative accumulators (e.g. `TRANSACTION_FEE_POOL`): this tx's NET
    /// integer delta relative to the committed base, per `(store,key)`. These
    /// are RMW'd by nearly every tx on a single shared key; as ordinary conflict
    /// keys they'd serialise the whole block (every tx invalidating every
    /// other). Instead each tx records only its `+= delta`; the scheduler sums
    /// `base + Σ delta` at commit (addition is associative ⇒ order-independent ⇒
    /// byte-identical to the serial loop). They are NOT in the read-set (never
    /// trigger re-execution) and NOT published to the multi-version memory.
    /// See `working/BLOCKSTM-DESIGN.md` hazard #1.
    pub deltas: HashMap<(StoreId, Vec<u8>), i64>,
    /// Lower tx indices whose speculative writes this tx read (the `Version`
    /// origins, with duplicates). Tracked incrementally as reads happen so the
    /// scheduler can compute the dependency set without rescanning the whole
    /// read-set every (re-)execution. Cleared on re-execution.
    pub version_deps: Vec<TxIdx>,
    /// Deferred-sequential accumulator side-channel: the free-net `bytes` this
    /// tx contributed to the chain-global `PUBLIC_NET_USAGE` (None if it didn't
    /// use free net). That counter is updated by a windowed-average `increase()`
    /// that is read-AND-branched and *non-associative* (ceil/floor rounding), so
    /// it can't be delta-ized like the commutative accumulators — instead its
    /// reads/writes are excluded from the MVCC chain (so they don't serialise
    /// the block) and the exact serial fold is replayed at commit from these
    /// captured `bytes`, in tx order, with a per-step limit guard. Lives and
    /// dies with the write-set (cleared on re-exec + on revert) so a reverted tx
    /// contributes nothing, matching serial. See `execute_block_parallel`'s
    /// commit and `working/BLOCKSTM-DESIGN.md`.
    pub public_net_bytes: Option<i64>,
    /// Deferred per-contract dynamic-energy accumulator: `contract address →
    /// this tx's net `energy_usage` delta` for contracts already caught-up this
    /// cycle. Like [`Self::public_net_bytes`], `ContractState.energy_usage` is
    /// RMW'd by every call to a hot contract (USDT) — an N-deep chain. Mid-cycle
    /// it's a pure `+=` (the dynamic factor is fixed for the cycle), so it's
    /// excluded from the MVCC chain and the deltas are summed onto the base at
    /// commit. Cleared on re-exec + revert (the VM-frame session already drops
    /// energy on a VM revert; this covers a later outer-tx revert). See
    /// `VersionedBackend`'s energy-deferred path + `execute_block_parallel`.
    pub contract_energy: std::collections::HashMap<Vec<u8>, i64>,
    /// Defensive backstop: set if a deferred contract's write unexpectedly
    /// changed `update_cycle`/`energy_factor` (a cycle-boundary catch-up should
    /// only ever hit a NON-deferred contract). Forces a serial fallback for the
    /// block so a factor/cycle change can never be silently mis-folded.
    pub contract_energy_boundary: bool,
}

impl TxCapture {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset for a re-execution (new incarnation).
    pub fn clear(&mut self) {
        self.reads.clear();
        self.writes.clear();
        self.deltas.clear();
        self.version_deps.clear();
        self.public_net_bytes = None;
        self.contract_energy.clear();
        self.contract_energy_boundary = false;
    }

    /// This tx's deduplicated dependency set (the distinct lower tx indices it
    /// read speculative writes from).
    pub fn dep_set(&self) -> Vec<TxIdx> {
        let mut d = self.version_deps.clone();
        d.sort_unstable();
        d.dedup();
        d
    }

    /// The write-set flattened for [`MvMemory::record_writes`].
    pub fn write_set(&self) -> Vec<(StoreId, Vec<u8>, VersionValue)> {
        self.writes
            .iter()
            .map(|((s, k), v)| (*s, k.clone(), v.clone()))
            .collect()
    }

    /// The set of keys written (for estimate-marking / stale-write cleanup).
    pub fn written_keys(&self) -> Vec<(StoreId, Vec<u8>)> {
        self.writes.keys().cloned().collect()
    }

    /// Per-key baseline: the value this tx first read for a key, before writing
    /// it. A write back to that same value is a no-op (the tx changed nothing).
    fn read_baseline(&self) -> HashMap<(StoreId, Vec<u8>), &VersionValue> {
        let mut m: HashMap<(StoreId, Vec<u8>), &VersionValue> = HashMap::new();
        for rd in &self.reads {
            m.entry((rd.store, rd.key.clone())).or_insert(&rd.value);
        }
        m
    }

    /// Like [`write_set`], but drops **no-op writes** — a write whose value
    /// equals the value this tx read for that key (a read-modify-write that
    /// lands back on the original). The classic case is revm crediting the
    /// zero-address beneficiary `+= 0` on every tx: as a real write it publishes
    /// a fresh version per tx, so every later reader resolves to the previous tx
    /// and the whole block degenerates into an n-deep dependency chain. Dropping
    /// it is byte-identical (the write changed nothing — the surviving creator's
    /// value is what serial leaves too) and collapses that chain to a star.
    /// Blind writes (no preceding read of the key) are kept — we can't prove
    /// they're no-ops.
    pub fn effective_write_set(&self) -> Vec<(StoreId, Vec<u8>, VersionValue)> {
        let base = self.read_baseline();
        self.writes
            .iter()
            .filter(|((s, k), v)| base.get(&(*s, k.clone())).map_or(true, |rv| *rv != *v))
            .map(|((s, k), v)| (*s, k.clone(), v.clone()))
            .collect()
    }
}

/// Single-owner cell for a [`TxCapture`]. Block-STM touches one tx's capture from
/// exactly one thread at a time (the rayon task running that incarnation; the
/// scheduler only reads it before/after, separated by rayon join barriers that
/// establish happens-before), so the `Mutex` it used to need was a pure
/// atomic-fence tax on *every* state get/put. This wraps a `RefCell` instead — no
/// atomics — and the debug-build borrow check is a tripwire if the single-thread
/// invariant is ever broken.
///
/// SAFETY: `unsafe impl Sync` asserts that invariant, which holds because
/// `execute_block_parallel` never hands one capture to two threads at once —
/// within a round each tx index is processed by a single thread, and across
/// rounds rayon's join orders all accesses.
pub struct TxCaptureCell {
    inner: std::cell::RefCell<TxCapture>,
}

// SAFETY: see the type doc — accesses to a given cell are single-threaded by the
// scheduler's construction; the wrapper exists only to drop the atomic fence.
unsafe impl Sync for TxCaptureCell {}

impl TxCaptureCell {
    pub fn new() -> Self {
        Self {
            inner: std::cell::RefCell::new(TxCapture::new()),
        }
    }
    #[inline]
    pub fn borrow_mut(&self) -> std::cell::RefMut<'_, TxCapture> {
        self.inner.borrow_mut()
    }
    #[inline]
    pub fn borrow(&self) -> std::cell::Ref<'_, TxCapture> {
        self.inner.borrow()
    }
}

impl Default for TxCaptureCell {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`KvBackend`] for ONE store during ONE transaction's speculative execution.
///
/// Reads resolve through the multi-version memory — the highest lower-indexed tx's
/// write, or the committed base — recording each into the shared [`TxCapture`]
/// read-set. Writes buffer into the capture (serving read-your-writes). It is a
/// drop-in `Arc<dyn KvBackend>`, so the existing `execute_one_tx` runs unchanged;
/// the scheduler just hands it versioned stores instead of the real ones.
pub struct VersionedBackend {
    store: StoreId,
    tx_idx: TxIdx,
    base: Arc<dyn KvBackend>,
    mv: Arc<MvMemory>,
    capture: Arc<TxCaptureCell>,
    /// Keys in THIS store that are commutative i64 accumulators (see
    /// [`TxCapture::deltas`]). Empty (a shared empty set) for every store except
    /// the one holding the accumulators (dyn_props), so the membership check
    /// short-circuits with no allocation on the hot path.
    accumulators: Arc<HashSet<Vec<u8>>>,
    /// Keys in THIS store that are deferred-sequential accumulators
    /// (`PUBLIC_NET_USAGE` / `PUBLIC_NET_TIME`): read-and-branched + non-
    /// associative, so they can't chain through MVCC. Reads return the committed
    /// base WITHOUT recording a read-set entry (no dependency ⇒ no re-execution);
    /// writes are dropped (the value is recomputed by the exact serial fold at
    /// commit). Empty shared set for every other store. See
    /// [`TxCapture::public_net_bytes`].
    deferred: Arc<HashSet<Vec<u8>>>,
    /// True only for the `contract_state` store in parallel: enables the
    /// per-contract dynamic-energy deferral. A contract already caught-up THIS
    /// cycle (`update_cycle == now_cycle`) has a fixed factor and only `+=`s
    /// `energy_usage`, so it's excluded from the MVCC chain and its delta is
    /// captured ([`TxCapture::contract_energy`]) for a commit-time sum. A
    /// contract on its first touch this cycle stays on the normal MVCC path (its
    /// catch-up reset/factor write must chain).
    energy_deferred: bool,
    /// Current maintenance cycle (`dyn_props.current_cycle_number()`), block-
    /// constant. Only meaningful when `energy_deferred`.
    now_cycle: i64,
}

impl VersionedBackend {
    pub fn new(
        store: StoreId,
        tx_idx: TxIdx,
        base: Arc<dyn KvBackend>,
        mv: Arc<MvMemory>,
        capture: Arc<TxCaptureCell>,
    ) -> Self {
        Self::with_accumulators(store, tx_idx, base, mv, capture, empty_accumulators())
    }

    /// As [`VersionedBackend::new`], but with the set of accumulator keys for
    /// this store (commutative-delta handling). Use the shared empty set for
    /// non-accumulator stores.
    pub fn with_accumulators(
        store: StoreId,
        tx_idx: TxIdx,
        base: Arc<dyn KvBackend>,
        mv: Arc<MvMemory>,
        capture: Arc<TxCaptureCell>,
        accumulators: Arc<HashSet<Vec<u8>>>,
    ) -> Self {
        Self::with_accumulators_and_deferred(
            store,
            tx_idx,
            base,
            mv,
            capture,
            accumulators,
            empty_accumulators(),
        )
    }

    /// As [`VersionedBackend::with_accumulators`], but also with the set of
    /// deferred-sequential keys for this store (`PUBLIC_NET_USAGE` /
    /// `PUBLIC_NET_TIME` on dyn_props — see the `deferred` field).
    pub fn with_accumulators_and_deferred(
        store: StoreId,
        tx_idx: TxIdx,
        base: Arc<dyn KvBackend>,
        mv: Arc<MvMemory>,
        capture: Arc<TxCaptureCell>,
        accumulators: Arc<HashSet<Vec<u8>>>,
        deferred: Arc<HashSet<Vec<u8>>>,
    ) -> Self {
        Self {
            store,
            tx_idx,
            base,
            mv,
            capture,
            accumulators,
            deferred,
            energy_deferred: false,
            now_cycle: 0,
        }
    }

    /// Enable the per-contract dynamic-energy deferral on this backend (the
    /// `contract_state` store in parallel). `now_cycle` is the block's
    /// maintenance cycle. See the `energy_deferred` field.
    pub fn with_energy_deferral(mut self, now_cycle: i64) -> Self {
        self.energy_deferred = true;
        self.now_cycle = now_cycle;
        self
    }

    #[inline]
    fn is_accumulator(&self, key: &[u8]) -> bool {
        !self.accumulators.is_empty() && self.accumulators.contains(key)
    }

    #[inline]
    fn is_deferred(&self, key: &[u8]) -> bool {
        !self.deferred.is_empty() && self.deferred.contains(key)
    }

    /// Decode a `ContractState` blob; `None`/garbage ⇒ a default record
    /// (`update_cycle = 0`), matching `ContractStateStore::get`'s absent handling.
    #[inline]
    fn decode_contract_state(bytes: Option<&Vec<u8>>) -> tron_proto::ContractState {
        use prost::Message;
        bytes
            .and_then(|b| tron_proto::ContractState::decode(b.as_slice()).ok())
            .unwrap_or_default()
    }
}

/// A shared empty accumulator set (one allocation, cloned cheaply via `Arc`).
pub fn empty_accumulators() -> Arc<HashSet<Vec<u8>>> {
    use std::sync::OnceLock;
    static EMPTY: OnceLock<Arc<HashSet<Vec<u8>>>> = OnceLock::new();
    EMPTY.get_or_init(|| Arc::new(HashSet::new())).clone()
}

/// Decode a dyn_props "long" value (8-byte big-endian, zero-padded) exactly as
/// `DynamicPropertiesStore::get_long`'s `parse_long_permissive` does, so the
/// accumulator delta math is byte-identical to the serial read-modify-write.
pub fn decode_long(bytes: Option<&Vec<u8>>) -> i64 {
    let Some(bytes) = bytes else { return 0 };
    if bytes.is_empty() {
        return 0;
    }
    let len = bytes.len();
    let mut buf = [0u8; 8];
    if len >= 8 {
        buf.copy_from_slice(&bytes[len - 8..]);
    } else {
        buf[8 - len..].copy_from_slice(bytes);
    }
    i64::from_be_bytes(buf)
}

impl KvBackend for VersionedBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        // Commutative accumulator: resolve to `base + this tx's own delta`
        // (read-your-writes within the tx), invisible to other txs and to
        // validation. Encoded as 8-byte BE to mirror `put_long`.
        //
        // Absent-ness is preserved: if the base key is missing AND this tx has
        // not contributed, return `None`. Some callers gate on key *presence*
        // (`support_transaction_fee_pool()` is `get_long(..).is_some()`), so a
        // spurious `Some(0)` would flip a fork decision and diverge from serial.
        // Deferred-sequential key (PUBLIC_NET_USAGE / PUBLIC_NET_TIME): every tx
        // sees the committed base and the read is NOT recorded, so it creates no
        // cross-tx dependency — the chain that would otherwise serialise the
        // whole block is broken. The actuator's branch evaluates against the
        // base (decayed); the exact serial value is replayed at commit from the
        // captured `bytes` (with a per-step limit guard). Read-your-writes isn't
        // needed: `try_use_free_net` reads then writes once, never re-reads.
        if self.is_deferred(key) {
            return self.base.get(key);
        }
        // Energy-deferred contract_state: a contract already caught-up THIS cycle
        // has a fixed dynamic-energy factor and only `+=`s `energy_usage`, so the
        // read carries no cross-tx dependency — return base, no read-set entry,
        // chain broken. A contract on its first touch this cycle
        // (`update_cycle != now_cycle`) must keep its catch-up reset/factor write
        // on the MVCC chain, so it falls through to the normal path below.
        if self.energy_deferred {
            let base_raw = self.base.get(key)?;
            if Self::decode_contract_state(base_raw.as_ref()).update_cycle == self.now_cycle {
                return Ok(base_raw);
            }
        }
        if self.is_accumulator(key) {
            let base_raw = self.base.get(key)?;
            let delta = self
                .capture
                .borrow_mut()
                .deltas
                .get(&(self.store, key.to_vec()))
                .copied();
            return Ok(match (base_raw, delta) {
                (None, None) => None, // absent and untouched by this tx
                (base_opt, d) => {
                    let v = decode_long(base_opt.as_ref()).wrapping_add(d.unwrap_or(0));
                    Some(v.to_be_bytes().to_vec())
                }
            });
        }
        let mut cap = self.capture.borrow_mut();
        // Read-your-writes: the tx's own prior write wins and is NOT a cross-tx
        // dependency, so it isn't recorded in the read-set.
        if let Some(v) = cap.writes.get(&(self.store, key.to_vec())) {
            return Ok(v.clone());
        }
        match self.mv.read(self.store, key, self.tx_idx) {
            ReadOutcome::Versioned { value, version } => {
                cap.reads.push(ReadDescriptor {
                    store: self.store,
                    key: key.to_vec(),
                    origin: ReadOrigin::Version(version),
                    value: value.clone(),
                });
                cap.version_deps.push(version.idx);
                Ok(value)
            }
            // Base is the normal fall-through. Blocked is only reachable if the
            // scheduler marks ESTIMATEs, which this (round-based) scheduler does
            // not — so treat it as a base read; validation would catch any stale
            // result regardless.
            ReadOutcome::Base | ReadOutcome::Blocked { .. } => {
                let value = self.base.get(key)?;
                cap.reads.push(ReadDescriptor {
                    store: self.store,
                    key: key.to_vec(),
                    origin: ReadOrigin::Base,
                    value: value.clone(),
                });
                Ok(value)
            }
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        // Deferred-sequential key: drop the write. The actuator computed this
        // value from the (base) read, which doesn't reflect lower txs' running
        // total; the correct serial value is recomputed at commit by replaying
        // the fold from each tx's captured `bytes`. Publishing it here would
        // chain the block (defeating the whole point) and commit a wrong value.
        if self.is_deferred(key) {
            return Ok(());
        }
        // Energy-deferred contract_state: for a contract caught-up this cycle,
        // the VM-frame session flushes ONE final `ContractState` here (it already
        // aggregated the tx's frames + dropped energy on a VM revert). Capture
        // the `energy_usage` delta vs base (a pure `+=` — `update_cycle`/factor
        // are fixed for a caught-up contract) and drop the write; the sum is
        // folded onto base at commit. If the write somehow changed
        // `update_cycle`/factor (a cycle boundary should only hit a NON-deferred
        // contract), trip the backstop so the block falls back to serial.
        if self.energy_deferred {
            let base_raw = self.base.get(key)?;
            let base_cs = Self::decode_contract_state(base_raw.as_ref());
            if base_cs.update_cycle == self.now_cycle {
                use prost::Message;
                let mut cap = self.capture.borrow_mut();
                match tron_proto::ContractState::decode(value) {
                    Ok(new_cs)
                        if new_cs.update_cycle == base_cs.update_cycle
                            && new_cs.energy_factor == base_cs.energy_factor =>
                    {
                        cap.contract_energy.insert(
                            key.to_vec(),
                            new_cs.energy_usage.wrapping_sub(base_cs.energy_usage),
                        );
                    }
                    _ => cap.contract_energy_boundary = true,
                }
                return Ok(());
            }
        }
        // Accumulator: record only the net delta vs. the committed base. The
        // value written by `add_*` is `cur + amount` where `cur` is what our
        // `get` returned (`base + delta_so_far`), so `value - base` is exactly
        // the tx's cumulative contribution — correct across multiple updates
        // within one tx. Not added to `writes` (not published to MVCC).
        if self.is_accumulator(key) {
            let base_i = decode_long(self.base.get(key)?.as_ref());
            let new_i = decode_long(Some(&value.to_vec()));
            self.capture
                .borrow_mut()
                .deltas
                .insert((self.store, key.to_vec()), new_i.wrapping_sub(base_i));
            return Ok(());
        }
        self.capture
            .borrow_mut()
            .writes
            .insert((self.store, key.to_vec()), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        // Deferred-sequential keys are never deleted by the bandwidth path, but
        // drop defensively so they never enter the MVCC chain.
        if self.is_deferred(key) {
            return Ok(());
        }
        self.capture
            .borrow_mut()
            .writes
            .insert((self.store, key.to_vec()), None);
        Ok(())
    }

    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        // The MVCC layer has no native full-table scan. Build the key set this
        // tx can see — every key in the committed `base` plus any this tx itself
        // wrote — then resolve each through `get()`. Reusing `get()` keeps the
        // scan byte-identical to the per-key path: the same MVCC visibility
        // (read-your-writes > highest lower-index version > base) AND the same
        // read-set recording, so a parallel full-table scan stays
        // conflict-correct — if a lower-index tx writes any scanned key, this tx
        // re-validates. Deletes (`get` => `None`) drop out; ascending byte order
        // is preserved by the `BTreeMap`.
        //
        // Without this override `VersionedBackend` inherited the erroring default
        // `scan_all`, so every full-table scan failed *only under parallel
        // execution*: a full-table scan (e.g. the maintenance round's
        // `WitnessStore::all`) then returned failure — a parallel-vs-serial
        // divergence, since serial runs on a snapshot/session backend that
        // implements `scan_all`.
        //
        // A key *created* by a lower-index tx this block that is neither in base
        // nor written by this tx is not enumerated, but the stores reachable by a
        // VM scan (witnesses / proposals / asset-issues) are never created
        // mid-block by a transaction, so that case does not arise.
        let mut keys: BTreeMap<Vec<u8>, ()> = self
            .base
            .scan_all()?
            .into_iter()
            .map(|(k, _)| (k, ()))
            .collect();
        {
            let cap = self.capture.borrow();
            for (store, key) in cap.writes.keys() {
                if *store == self.store {
                    keys.insert(key.clone(), ());
                }
            }
        }
        let mut out = Vec::with_capacity(keys.len());
        for (k, ()) in keys {
            if let Some(v) = self.get(&k)? {
                out.push((k, v));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    const ACC: StoreId = 0;
    fn v(idx: TxIdx, inc: u32) -> Version {
        Version {
            idx,
            incarnation: inc,
        }
    }
    fn val(b: &[u8]) -> VersionValue {
        Some(b.to_vec())
    }

    #[test]
    fn read_sees_highest_lower_write_else_base() {
        let mv = MvMemory::new();
        // No writers yet → base.
        assert!(matches!(mv.read(ACC, b"a", 5), ReadOutcome::Base));
        // tx2 writes "a"; tx5 sees it, tx1 (below the writer) sees base.
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        match mv.read(ACC, b"a", 5) {
            ReadOutcome::Versioned { value, version } => {
                assert_eq!(value, val(b"x"));
                assert_eq!(version, v(2, 0));
            }
            o => panic!("expected versioned, got {o:?}"),
        }
        assert!(matches!(mv.read(ACC, b"a", 1), ReadOutcome::Base));
        assert!(matches!(mv.read(ACC, b"a", 2), ReadOutcome::Base), "own index excluded");
    }

    #[test]
    fn read_picks_nearest_lower_writer() {
        let mv = MvMemory::new();
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), val(b"from2"))]);
        mv.record_writes(v(4, 0), &[(ACC, b"a".to_vec(), val(b"from4"))]);
        // tx5 sees tx4 (nearest below); tx3 sees tx2.
        match mv.read(ACC, b"a", 5) {
            ReadOutcome::Versioned { version, .. } => assert_eq!(version, v(4, 0)),
            o => panic!("got {o:?}"),
        }
        match mv.read(ACC, b"a", 3) {
            ReadOutcome::Versioned { version, .. } => assert_eq!(version, v(2, 0)),
            o => panic!("got {o:?}"),
        }
    }

    #[test]
    fn tombstone_is_a_versioned_absent_not_base() {
        let mv = MvMemory::new();
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), None)]); // delete
        match mv.read(ACC, b"a", 5) {
            ReadOutcome::Versioned { value, version } => {
                assert_eq!(value, None);
                assert_eq!(version, v(2, 0));
            }
            o => panic!("got {o:?}"),
        }
    }

    #[test]
    fn estimate_blocks_lower_readers() {
        let mv = MvMemory::new();
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        mv.mark_estimates(2, &[(ACC, b"a".to_vec())]);
        assert!(matches!(
            mv.read(ACC, b"a", 5),
            ReadOutcome::Blocked { blocking: 2 }
        ));
    }

    #[test]
    fn validate_detects_a_newly_visible_lower_write() {
        let mv = MvMemory::new();
        // tx5 executed reading "a" from base (no lower writer existed → absent).
        let rs = vec![ReadDescriptor {
            store: ACC,
            key: b"a".to_vec(),
            origin: ReadOrigin::Base,
            value: None,
        }];
        assert!(mv.validate(5, &rs), "still base → valid");
        // Now tx3 writes "a" → tx5's base read is stale.
        mv.record_writes(v(3, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        assert!(!mv.validate(5, &rs), "tx3 now visible → tx5 must re-run");
    }

    #[test]
    fn validate_detects_changed_incarnation_and_disappeared_write() {
        let mv = MvMemory::new();
        mv.record_writes(v(3, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        let rs = vec![ReadDescriptor {
            store: ACC,
            key: b"a".to_vec(),
            origin: ReadOrigin::Version(v(3, 0)),
            value: val(b"x"),
        }];
        assert!(mv.validate(5, &rs));
        // tx3 re-executed and wrote a DIFFERENT value → value-based validation
        // detects the stale read. (A re-run writing the *same* bytes would stay
        // valid — that's the point of value-based validation.)
        mv.record_writes(v(3, 1), &[(ACC, b"a".to_vec(), val(b"y"))]);
        assert!(!mv.validate(5, &rs), "value changed → re-run");
        // tx3's write disappears entirely (its re-run no longer touches "a").
        mv.remove_writes(3, &[(ACC, b"a".to_vec())]);
        assert!(!mv.validate(5, &rs), "now resolves to base → re-run");
    }

    #[test]
    fn validate_is_value_based_idempotent_write_stays_valid() {
        // The beneficiary case: tx5 read "a"=x from tx3. tx3 re-executes (or a
        // different lower tx becomes the highest writer) but writes the SAME
        // bytes. Value-based validation keeps tx5 valid — no false re-run.
        let mv = MvMemory::new();
        mv.record_writes(v(3, 0), &[(ACC, b"a".to_vec(), val(b"same"))]);
        let rs = vec![ReadDescriptor {
            store: ACC,
            key: b"a".to_vec(),
            origin: ReadOrigin::Version(v(3, 0)),
            value: val(b"same"),
        }];
        assert!(mv.validate(5, &rs));
        // tx3 re-runs, same value, new incarnation → still valid (version-based
        // would have failed here on the incarnation change).
        mv.record_writes(v(3, 1), &[(ACC, b"a".to_vec(), val(b"same"))]);
        assert!(mv.validate(5, &rs), "same bytes from a new incarnation → valid");
        // A lower tx4 now also writes the same bytes and becomes the highest
        // writer below 5 → still the same value → still valid.
        mv.record_writes(v(4, 0), &[(ACC, b"a".to_vec(), val(b"same"))]);
        assert!(mv.validate(5, &rs), "different writer, same bytes → valid");
        // But a genuinely different value invalidates.
        mv.record_writes(v(4, 1), &[(ACC, b"a".to_vec(), val(b"different"))]);
        assert!(!mv.validate(5, &rs), "different bytes → re-run");
    }

    // ---- Phase 2: VersionedBackend ----

    fn versioned(
        tx_idx: TxIdx,
        base: Arc<dyn KvBackend>,
        mv: Arc<MvMemory>,
    ) -> (VersionedBackend, Arc<TxCaptureCell>) {
        let cap = Arc::new(TxCaptureCell::new());
        (
            VersionedBackend::new(ACC, tx_idx, base, mv, cap.clone()),
            cap,
        )
    }

    #[test]
    fn versioned_read_falls_to_base_and_records_base_origin() {
        let base = Arc::new(MemBackend::new());
        base.put(b"a", b"base").unwrap();
        let mv = Arc::new(MvMemory::new());
        let (vb, cap) = versioned(5, base, mv);
        assert_eq!(vb.get(b"a").unwrap(), Some(b"base".to_vec()));
        let c = cap.borrow();
        assert_eq!(c.reads.len(), 1);
        assert_eq!(c.reads[0].origin, ReadOrigin::Base);
    }

    #[test]
    fn versioned_read_your_writes_not_recorded_as_a_dependency() {
        let base = Arc::new(MemBackend::new());
        base.put(b"a", b"base").unwrap();
        let mv = Arc::new(MvMemory::new());
        let (vb, cap) = versioned(5, base, mv);
        vb.put(b"a", b"mine").unwrap();
        assert_eq!(vb.get(b"a").unwrap(), Some(b"mine".to_vec()), "read-your-writes");
        vb.delete(b"a").unwrap();
        assert_eq!(vb.get(b"a").unwrap(), None, "read-your-delete");
        let c = cap.borrow();
        assert!(c.reads.is_empty(), "own writes are not cross-tx reads");
        assert_eq!(c.writes.get(&(ACC, b"a".to_vec())), Some(&None)); // last write = delete
    }

    #[test]
    fn versioned_read_resolves_lower_tx_write_via_mvcc() {
        let base = Arc::new(MemBackend::new());
        base.put(b"a", b"base").unwrap();
        let mv = Arc::new(MvMemory::new());
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), val(b"from2"))]);
        let (vb, cap) = versioned(5, base, mv);
        assert_eq!(vb.get(b"a").unwrap(), Some(b"from2".to_vec()), "sees tx2, not base");
        let c = cap.borrow();
        assert_eq!(c.reads[0].origin, ReadOrigin::Version(v(2, 0)));
    }

    #[test]
    fn versioned_write_set_round_trips_to_mvcc() {
        let base = Arc::new(MemBackend::new());
        let mv = Arc::new(MvMemory::new());
        let (vb, cap) = versioned(3, base, mv.clone());
        vb.put(b"a", b"x").unwrap();
        vb.delete(b"b").unwrap();
        let ws = cap.borrow().write_set();
        mv.record_writes(v(3, 0), &ws);
        // A higher tx now sees tx3's put and tombstone.
        assert!(matches!(mv.read(ACC, b"a", 9), ReadOutcome::Versioned { value, .. } if value == val(b"x")));
        assert!(matches!(mv.read(ACC, b"b", 9), ReadOutcome::Versioned { value, .. } if value.is_none()));
    }

    #[test]
    fn versioned_scan_all_merges_base_overlay_mvcc_and_records_reads() {
        // Regression: `VersionedBackend` used to inherit the erroring default
        // `scan_all`, so full-table scans (e.g. the maintenance round's
        // `WitnessStore::all`) failed *only under parallel execution*,
        // diverging from serial (which uses a backend that implements
        // `scan_all`).
        let base = Arc::new(MemBackend::new());
        base.put(b"a", b"1").unwrap();
        base.put(b"b", b"2").unwrap();
        base.put(b"c", b"3").unwrap();
        let mv = Arc::new(MvMemory::new());
        // A lower-index tx updated "b".
        mv.record_writes(v(2, 0), &[(ACC, b"b".to_vec(), val(b"two"))]);
        let (vb, cap) = versioned(5, base, mv);
        // This tx deletes "a" and creates "d".
        vb.delete(b"a").unwrap();
        vb.put(b"d", b"4").unwrap();

        assert_eq!(
            vb.scan_all().unwrap(),
            vec![
                (b"b".to_vec(), b"two".to_vec()), // lower-tx version, not base "2"
                (b"c".to_vec(), b"3".to_vec()),   // base
                (b"d".to_vec(), b"4".to_vec()),   // this tx's own write
                                                  // "a" deleted by this tx => absent
            ],
            "scan merges base + mvcc + own writes, drops deletes, ascending order",
        );

        // The scan must register cross-tx read deps so a concurrent write to a
        // scanned key re-validates: "b" (versioned) and "c" (base) are recorded;
        // "d" is the tx's own write and "a" its own delete (neither a dep).
        let c = cap.borrow();
        let read_keys: HashSet<_> = c.reads.iter().map(|r| r.key.clone()).collect();
        assert!(read_keys.contains(&b"b".to_vec()), "versioned key recorded");
        assert!(read_keys.contains(&b"c".to_vec()), "base key recorded");
        assert!(!read_keys.contains(&b"d".to_vec()), "own write is not a read dep");
        assert!(!read_keys.contains(&b"a".to_vec()), "own delete is not a read dep");
    }
}
