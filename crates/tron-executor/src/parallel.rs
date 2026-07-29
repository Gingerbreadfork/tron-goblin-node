//! Block-STM parallel transaction execution (phase 3).
//!
//! Replaces the serial `for tx { execute_one_tx }` loop with an optimistic
//! parallel one that produces **byte-identical** results (java-tron is serial; no
//! state root ⇒ any divergence is silent corruption). See
//! `working/BLOCKSTM-DESIGN.md`.
//!
//! Strategy (round-based fixpoint — provably serial-equivalent):
//! 1. Execute every tx in parallel against a [`VersionedBackend`] view: reads
//!    resolve to the highest lower-indexed tx's speculative write (or the
//!    committed base) and are recorded; writes buffer into the tx's capture and
//!    are published to the shared [`MvMemory`]. `execute_one_tx` is unchanged —
//!    it just gets versioned stores instead of the real ones, so nothing touches
//!    the real `state` during speculation.
//! 2. Re-validate every tx's read-set against the multi-version memory. A tx whose
//!    reads no longer resolve to the same source read a stale value and is
//!    re-executed (new incarnation). Repeat until no tx is invalid — that
//!    fixpoint is exactly what serial execution would have produced (each tx saw
//!    the writes of all lower txs).
//! 3. Commit every tx's write-set to the real `state` in ascending tx order, so
//!    the on-disk result equals the serial loop's.
//!
//! Dependencies only ever point from higher to lower tx index (a read sees only
//! lower writes), so the fixpoint converges in at most the longest dependency
//! chain's depth — one round for fully independent blocks, more for chained ones.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use rayon::prelude::*;
use tron_chainbase::blockstm::{
    decode_long, empty_accumulators, MvMemory, StoreId, TxCaptureCell, Version, VersionedBackend,
};
use tron_chainbase::dynamic_properties_keys;
use tron_chainbase::KvBackend;
use tron_crypto::address::Address;
use tron_proto::Transaction;
use tron_types::TxWireInfo;

use crate::resource::increase_default;
use crate::{execute_one_tx_versioned, ExecConfig, StateBackends, TxResult};

// Stable store ids for the conflict-key space — one per StateBackends field.
const SID_ACCOUNTS: StoreId = 0;
const SID_WITNESSES: StoreId = 1;
const SID_VOTES: StoreId = 2;
const SID_DELEGATION: StoreId = 3;
const SID_DELEGATED_RESOURCES: StoreId = 4;
const SID_DRAI: StoreId = 5; // delegated_resource_account_index
const SID_DYN_PROPS: StoreId = 6;
const SID_PROPOSALS: StoreId = 7;
const SID_NAME_INDEX: StoreId = 8;
const SID_ID_INDEX: StoreId = 9;
const SID_ASSET_V1: StoreId = 10;
const SID_ASSET_V2: StoreId = 11;
const SID_CONTRACTS: StoreId = 12;
const SID_ABI: StoreId = 13;
const SID_EXCHANGE_V1: StoreId = 14;
const SID_EXCHANGE_V2: StoreId = 15;
const SID_MARKET_ORDERS: StoreId = 16;
const SID_NULLIFIERS: StoreId = 17;
const SID_MERKLE_TREES: StoreId = 18;
const SID_CODE: StoreId = 19;
const SID_STORAGE_ROW: StoreId = 20;
const SID_CONTRACT_STATE: StoreId = 21;
const SID_BLOCK_INDEX: StoreId = 22;
const SID_WITNESS_SCHEDULE: StoreId = 23;
const SID_MARKET_ACCOUNT: StoreId = 24;

/// Commutative-accumulator keys in the dyn_props store: pure additive (`+=`)
/// counters RMW'd by (nearly) every tx on a single shared key. As ordinary
/// conflict keys each one serialises the whole block — every tx invalidating
/// every other, an O(n²) re-execution cascade — so they're handled as summable
/// per-tx deltas instead (`base + Σ delta` at commit; addition is associative ⇒
/// byte-identical to the serial in-order RMW). See
/// [`tron_chainbase::blockstm::TxCapture::deltas`] and
/// `working/BLOCKSTM-DESIGN.md` hazard #1.
///
/// CRITICAL SAFETY RULE: a key may be delta-ized ONLY if no per-tx execution
/// path ever reads its running value to make a decision (a branch or a divisor)
/// — i.e. it is write-only-within-a-tx (`+=` only) plus at most a `.is_some()`
/// presence gate. The delta scheme feeds a tx `base + its own delta`, NOT
/// `base + Σ lower deltas`, so any tx that *consumes* the running value would
/// diverge from serial and validation would NOT catch it (the read is excluded
/// from the read-set). Verified write-only-within-tx (readers, if any, are the
/// post-block reward/adaptive passes on committed state, identical in both
/// paths):
///   - TRANSACTION_FEE_POOL / BURN_TRX_AMOUNT / TOTAL_TRANSACTION_COST — fee
///     path of every tx; only `+=` (+ `.is_some()` fee-pool gate).
///   - TOTAL_CREATE_ACCOUNT_COST — account creation; `+=` only.
///   - BLOCK_ENERGY_USAGE — adaptive-energy `+=` (off on mainnet); the running
///     value is never branched on intra-block.
/// DELIBERATELY EXCLUDED (must stay ordinary MVCC keys): TOTAL_NET_WEIGHT,
/// TOTAL_ENERGY_WEIGHT, TOTAL_TRON_POWER_WEIGHT — these are read AND used as a
/// `== 0` branch / divisor in the per-tx bandwidth/energy/undelegate resource-
/// limit math (bandwidth.rs, energy.rs, delegate.rs), so a freeze + a resource-
/// charged tx in the same block must see the updated weight. Left as conflict
/// keys, value-based validation re-executes the dependent tx correctly.
fn accumulator_keys() -> Arc<HashSet<Vec<u8>>> {
    use std::sync::OnceLock;
    static KEYS: OnceLock<Arc<HashSet<Vec<u8>>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        Arc::new(HashSet::from([
            dynamic_properties_keys::TOTAL_TRANSACTION_COST.to_vec(),
            dynamic_properties_keys::TRANSACTION_FEE_POOL.to_vec(),
            dynamic_properties_keys::BURN_TRX_AMOUNT.to_vec(),
            dynamic_properties_keys::TOTAL_CREATE_ACCOUNT_COST.to_vec(),
            dynamic_properties_keys::BLOCK_ENERGY_USAGE.to_vec(),
        ]))
    })
    .clone()
}

/// Deferred-sequential dyn_props keys: the chain-global free-bandwidth counter
/// (`PUBLIC_NET_USAGE`) and its decay timestamp (`PUBLIC_NET_TIME`). Every tx
/// that spends free net read-modify-writes `PUBLIC_NET_USAGE` via a windowed-
/// average `increase()` that is (a) branched against `PUBLIC_NET_LIMIT` and (b)
/// non-associative (ceil/floor rounding) — so it can be neither an ordinary
/// MVCC key (it would serialise the whole block into one ~N-deep chain — the
/// dominant Block-STM tax on real mainnet blocks) nor a commutative delta. They
/// are instead excluded from the MVCC chain (reads return base, writes dropped)
/// and the EXACT serial fold is replayed once at commit from each tx's captured
/// free-net `bytes`, with a per-step limit guard that falls back to serial if
/// the chain-wide budget is ever actually approached. See the commit code in
/// [`execute_block_parallel`] and `working/BLOCKSTM-DESIGN.md`.
fn deferred_public_net_keys() -> Arc<HashSet<Vec<u8>>> {
    use std::sync::OnceLock;
    static KEYS: OnceLock<Arc<HashSet<Vec<u8>>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        Arc::new(HashSet::from([
            dynamic_properties_keys::PUBLIC_NET_USAGE.to_vec(),
            dynamic_properties_keys::PUBLIC_NET_TIME.to_vec(),
        ]))
    })
    .clone()
}

/// Build a `StateBackends` whose every field reads/writes through a
/// [`VersionedBackend`] sharing `mv` + this tx's `capture`. Drop-in for
/// `execute_one_tx`. `acc` is the dyn_props accumulator-key set.
fn versioned_state(
    base: &StateBackends,
    mv: &Arc<MvMemory>,
    tx_idx: u32,
    cap: &Arc<TxCaptureCell>,
    acc: &Arc<HashSet<Vec<u8>>>,
    now_cycle: i64,
) -> StateBackends {
    let w = |sid: StoreId, b: &Arc<dyn KvBackend>| -> Arc<dyn KvBackend> {
        // Only the dyn_props store carries accumulator + deferred keys;
        // everything else shares the empty sets (membership check short-circuits
        // with no allocation on the hot path).
        let (accs, defs) = if sid == SID_DYN_PROPS {
            (acc.clone(), deferred_public_net_keys())
        } else {
            (empty_accumulators(), empty_accumulators())
        };
        let vb = VersionedBackend::with_accumulators_and_deferred(
            sid,
            tx_idx,
            b.clone(),
            mv.clone(),
            cap.clone(),
            accs,
            defs,
        );
        // The contract_state store gets the per-contract dynamic-energy deferral
        // (caught-up contracts' energy_usage is a pure `+=`, folded at commit).
        let vb = if sid == SID_CONTRACT_STATE {
            vb.with_energy_deferral(now_cycle)
        } else {
            vb
        };
        Arc::new(vb)
    };
    let wo = |sid: StoreId, b: &Option<Arc<dyn KvBackend>>| b.as_ref().map(|x| w(sid, x));
    StateBackends {
        accounts: w(SID_ACCOUNTS, &base.accounts),
        witnesses: w(SID_WITNESSES, &base.witnesses),
        votes: w(SID_VOTES, &base.votes),
        delegation: w(SID_DELEGATION, &base.delegation),
        delegated_resources: w(SID_DELEGATED_RESOURCES, &base.delegated_resources),
        delegated_resource_account_index: wo(SID_DRAI, &base.delegated_resource_account_index),
        dyn_props: w(SID_DYN_PROPS, &base.dyn_props),
        proposals: w(SID_PROPOSALS, &base.proposals),
        name_index: w(SID_NAME_INDEX, &base.name_index),
        id_index: w(SID_ID_INDEX, &base.id_index),
        asset_v1: w(SID_ASSET_V1, &base.asset_v1),
        asset_v2: w(SID_ASSET_V2, &base.asset_v2),
        contracts: w(SID_CONTRACTS, &base.contracts),
        abi: w(SID_ABI, &base.abi),
        exchange_v1: w(SID_EXCHANGE_V1, &base.exchange_v1),
        exchange_v2: w(SID_EXCHANGE_V2, &base.exchange_v2),
        market_orders: w(SID_MARKET_ORDERS, &base.market_orders),
        market_account: w(SID_MARKET_ACCOUNT, &base.market_account),
        nullifiers: w(SID_NULLIFIERS, &base.nullifiers),
        merkle_trees: wo(SID_MERKLE_TREES, &base.merkle_trees),
        code: wo(SID_CODE, &base.code),
        storage_row: wo(SID_STORAGE_ROW, &base.storage_row),
        contract_state: wo(SID_CONTRACT_STATE, &base.contract_state),
        block_index: wo(SID_BLOCK_INDEX, &base.block_index),
        witness_schedule: wo(SID_WITNESS_SCHEDULE, &base.witness_schedule),
        // Read-only pass-through: never written by any tx, so it needs no
        // MVCC versioning (reads go straight to base).
        reward_vi: base.reward_vi.clone(),
    }
}

/// The base backend for a store id (for in-order commit). `None` mirrors an
/// absent optional store (its writes can't have been produced).
fn base_field(state: &StateBackends, sid: StoreId) -> Option<Arc<dyn KvBackend>> {
    Some(match sid {
        SID_ACCOUNTS => state.accounts.clone(),
        SID_WITNESSES => state.witnesses.clone(),
        SID_VOTES => state.votes.clone(),
        SID_DELEGATION => state.delegation.clone(),
        SID_DELEGATED_RESOURCES => state.delegated_resources.clone(),
        SID_DRAI => return state.delegated_resource_account_index.clone(),
        SID_DYN_PROPS => state.dyn_props.clone(),
        SID_PROPOSALS => state.proposals.clone(),
        SID_NAME_INDEX => state.name_index.clone(),
        SID_ID_INDEX => state.id_index.clone(),
        SID_ASSET_V1 => state.asset_v1.clone(),
        SID_ASSET_V2 => state.asset_v2.clone(),
        SID_CONTRACTS => state.contracts.clone(),
        SID_ABI => state.abi.clone(),
        SID_EXCHANGE_V1 => state.exchange_v1.clone(),
        SID_EXCHANGE_V2 => state.exchange_v2.clone(),
        SID_MARKET_ORDERS => state.market_orders.clone(),
        SID_MARKET_ACCOUNT => state.market_account.clone(),
        SID_NULLIFIERS => state.nullifiers.clone(),
        SID_MERKLE_TREES => return state.merkle_trees.clone(),
        SID_CODE => return state.code.clone(),
        SID_STORAGE_ROW => return state.storage_row.clone(),
        SID_CONTRACT_STATE => return state.contract_state.clone(),
        SID_BLOCK_INDEX => return state.block_index.clone(),
        SID_WITNESS_SCHEDULE => return state.witness_schedule.clone(),
        _ => return None,
    })
}

/// Block-STM convergence aggregator, env-gated by `APPLY_TIMING` (shared with the
/// per-block apply profiler in `lib.rs`). Tells us the MECHANISM of the Block-STM
/// tax on real blocks: `reexec%` = total re-executions / total txs. ~0% means txs
/// are independent and parallel is near-ideal (the cost is then per-op MVCC
/// overhead); ~100%+ means the scheduler re-runs most txs (conflict cascade) and
/// the lever is conflict-avoidance, not micro-opt. `nonconv` counts blocks that
/// failed to converge → committed nothing and forced a full SERIAL re-run (pure
/// waste); any nonzero value is a direct, fixable throughput leak.
mod blockstm_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    static TXS: AtomicU64 = AtomicU64::new(0);
    static ROUNDS: AtomicU64 = AtomicU64::new(0);
    static REEXECS: AtomicU64 = AtomicU64::new(0);
    static NONCONV: AtomicU64 = AtomicU64::new(0);
    static BLOCKS: AtomicU64 = AtomicU64::new(0);

    const SAMPLE: u64 = 200;

    fn enabled() -> bool {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| {
            std::env::var("APPLY_TIMING")
                .map(|v| v != "0" && !v.is_empty())
                .unwrap_or(false)
        })
    }

    pub fn is_on() -> bool {
        enabled()
    }

    /// Hottest write key seen in the current sample window: the `(store, key)`
    /// written by the most txs in a single block, with that writer count. A high
    /// count is the chain-former — every higher tx that reads it must re-execute
    /// when a lower writer finalizes. Naming the store + key prefix tells us
    /// exactly which write to break the false dependency on.
    #[allow(clippy::type_complexity)]
    static HOT: std::sync::Mutex<Option<(u16, Vec<u8>, u32, String)>> =
        std::sync::Mutex::new(None);

    /// `detail` = optional field-level note (e.g. which Account fields changed),
    /// so we can tell a genuine balance chain from a deferrable accumulator.
    pub fn record_hotkey(store: u16, key: &[u8], writers: u32, detail: String) {
        if !enabled() {
            return;
        }
        let mut g = HOT.lock().expect("hot poisoned");
        if g.as_ref().map(|(_, _, c, _)| writers > *c).unwrap_or(true) {
            *g = Some((store, key.to_vec(), writers, detail));
        }
    }

    pub fn record(n: usize, rounds: usize, reexecs: usize, converged: bool) {
        if !enabled() {
            return;
        }
        TXS.fetch_add(n as u64, Ordering::Relaxed);
        ROUNDS.fetch_add(rounds as u64, Ordering::Relaxed);
        REEXECS.fetch_add(reexecs as u64, Ordering::Relaxed);
        if !converged {
            NONCONV.fetch_add(1, Ordering::Relaxed);
        }
        let b = BLOCKS.fetch_add(1, Ordering::Relaxed) + 1;
        if b % SAMPLE == 0 {
            let txs = TXS.swap(0, Ordering::Relaxed);
            let rounds = ROUNDS.swap(0, Ordering::Relaxed);
            let reexecs = REEXECS.swap(0, Ordering::Relaxed);
            let nonconv = NONCONV.swap(0, Ordering::Relaxed);
            BLOCKS.store(0, Ordering::Relaxed);
            let txs_per_blk = txs as f64 / b as f64;
            let reexec_pct = if txs > 0 {
                reexecs as f64 / txs as f64 * 100.0
            } else {
                0.0
            };
            let hot = HOT.lock().expect("hot poisoned").take();
            let hot_str = hot
                .map(|(s, k, c, detail)| {
                    // Full key (so a store=0 address can be base58-decoded /
                    // queried to identify the chain-former) + field-diff note.
                    let key_hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
                    format!("  hottest: store={s} writers={c} key={key_hex} [{detail}]")
                })
                .unwrap_or_default();
            eprintln!(
                "[blockstm] /{b} blk: {txs_per_blk:.0} txs/blk  rounds_avg={:.1}  \
                 reexec={reexec_pct:.0}% of txs  nonconverged={nonconv}{hot_str}",
                rounds as f64 / b as f64,
            );
        }
    }
}

/// Diagnostic (APPLY_TIMING): which Account fields changed base→final for the
/// chain-former hot account. `balance` ⇒ a GENUINE sequential chain (balances
/// are sufficiency-checked, can't be deferred). Only `net_usage` / `energy_usage`
/// / `latest_consume_time` ⇒ windowed accumulators that *might* be deferrable
/// like PUBLIC_NET. Decodes both blobs; never panics on the diagnostic path.
fn account_field_diff(base: Option<&[u8]>, fin: Option<&[u8]>) -> String {
    use prost::Message;
    let b = base.and_then(|x| tron_proto::Account::decode(x).ok());
    let f = fin.and_then(|x| tron_proto::Account::decode(x).ok());
    match (b, f) {
        (Some(b), Some(f)) => {
            let mut changed: Vec<&str> = Vec::new();
            if b.balance != f.balance {
                changed.push("balance");
            }
            if b.net_usage != f.net_usage {
                changed.push("net_usage");
            }
            if b.free_net_usage != f.free_net_usage {
                changed.push("free_net_usage");
            }
            let be = b.account_resource.as_ref().map(|r| r.energy_usage).unwrap_or(0);
            let fe = f.account_resource.as_ref().map(|r| r.energy_usage).unwrap_or(0);
            if be != fe {
                changed.push("energy_usage");
            }
            if b.latest_consume_time != f.latest_consume_time {
                changed.push("consume_time");
            }
            if changed.is_empty() {
                "no-change".into()
            } else {
                changed.join(",")
            }
        }
        (None, Some(_)) => "created".into(),
        _ => "?".into(),
    }
}

/// Optimistic-parallel equivalent of the serial tx loop. On success, commits all
/// writes to `state` in tx order and returns the per-tx results in block order.
///
/// Returns `None` (committing nothing) if the fixpoint fails to converge within
/// the bound — a should-never-happen safety hatch (dependencies are acyclic by
/// index) so the caller can fall back to the serial loop rather than risk a wrong
/// state. The serial path is always the source of truth.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_block_parallel(
    state: &StateBackends,
    txs: &[Transaction],
    config: &ExecConfig,
    block_number: i64,
    block_timestamp_ms: i64,
    beneficiary: [u8; 20],
    now_slot: i64,
    head_block_time_ms: i64,
    signers: &[Result<Vec<Address>, String>],
    original_wire: Option<&[TxWireInfo]>,
) -> Option<Vec<TxResult>> {
    let n = txs.len();
    let mv = Arc::new(MvMemory::new());
    let acc = accumulator_keys();
    let captures: Vec<Arc<TxCaptureCell>> =
        (0..n).map(|_| Arc::new(TxCaptureCell::new())).collect();
    let incarnation: Vec<AtomicU32> = (0..n).map(|_| AtomicU32::new(0)).collect();
    let results: Vec<Mutex<Option<TxResult>>> = (0..n).map(|_| Mutex::new(None)).collect();
    // `finalized[i]` = tx i is committed (validated against an mv in which every
    // lower tx is committed and immutable) — set only by the contiguous-prefix
    // commit loop below.
    let finalized: Vec<AtomicBool> = (0..n).map(|_| AtomicBool::new(false)).collect();
    // `deps[i]` = the distinct LOWER tx indices whose speculative writes tx i read
    // in its latest incarnation (its read-set's `Version` origins). Used ONLY to
    // GATE re-execution (re-running a tx whose deps aren't committed just reads the
    // same stale values again — wasted work, and for contract txs that means a
    // wasted EVM run). It does NOT affect finalization, which stays the sound
    // contiguous-prefix commit below — so an incomplete dep set (a hidden dep from
    // a key read as absent) can at worst cost ONE extra re-execution before the new
    // dep is recorded, never a wrong commit.
    let deps: Vec<Mutex<Vec<u32>>> = (0..n).map(|_| Mutex::new(Vec::new())).collect();

    // Build each tx's versioned `StateBackends` ONCE and reuse it across all of
    // that tx's incarnations — nothing in it depends on the incarnation (only on
    // the fixed `tx_idx` + the shared capture, which is cleared in place on
    // re-execution). Saves rebuilding 24 `Arc<VersionedBackend>` per re-execution.
    // Block-constant maintenance cycle, for the per-contract energy deferral.
    let now_cycle =
        tron_chainbase::DynamicPropertiesStore::new(state.dyn_props.clone()).current_cycle_number();
    let vstates: Vec<StateBackends> = (0..n)
        .map(|i| versioned_state(state, &mv, i as u32, &captures[i], &acc, now_cycle))
        .collect();

    // Execute (or re-execute) tx `i` at its current incarnation, publishing its
    // write-set to the multi-version memory and recording its result.
    let run = |i: usize| {
        let inc = incarnation[i].load(Ordering::Relaxed);
        let old_keys = {
            let mut g = captures[i].borrow_mut();
            let k = g.written_keys();
            g.clear();
            k
        };
        // No per-tx TxSession overlay: run directly over the versioned backend,
        // reverting failures by clearing this tx's capture (writes + deltas).
        let r = execute_one_tx_versioned(
            &vstates[i],
            &captures[i],
            &txs[i],
            config,
            block_number,
            block_timestamp_ms,
            beneficiary,
            now_slot,
            head_block_time_ms,
            &signers[i],
            original_wire.and_then(|s| s.get(i).copied()),
        );
        // Publish the EFFECTIVE write-set (no-op read-modify-writes dropped —
        // e.g. the zero-address beneficiary `+= 0`) so idempotent writes don't
        // spawn a fresh version per tx and chain the whole block.
        let write_set = {
            let g = captures[i].borrow();
            g.effective_write_set()
        };
        let new_keys: Vec<(StoreId, Vec<u8>)> =
            write_set.iter().map(|(s, k, _)| (*s, k.clone())).collect();
        // Drop entries for keys this incarnation no longer writes, then publish.
        let stale: Vec<(StoreId, Vec<u8>)> =
            old_keys.into_iter().filter(|k| !new_keys.contains(k)).collect();
        if !stale.is_empty() {
            mv.remove_writes(i as u32, &stale);
        }
        mv.record_writes(
            Version {
                idx: i as u32,
                incarnation: inc,
            },
            &write_set,
        );
        *results[i].lock().expect("result poisoned") = Some(r);
        *deps[i].lock().expect("deps poisoned") = captures[i].borrow().dep_set();
    };

    // Round 0: speculate everything.
    (0..n).into_par_iter().for_each(|i| run(i));

    // Contiguous-prefix commit. A tx may be finalized ONLY once every
    // lower-indexed tx is already finalized AND its own read-set validates
    // against the resulting (stable) multi-version memory. This is the textbook
    // Block-STM commit rule, and it is the SOUND replacement for the earlier
    // dependency-ordered finalization, which finalized any tx whose *tracked*
    // deps were final. That optimization was unsound: a tx's read-set captures
    // only the lower writes it actually OBSERVED, so a tx that read a key as
    // absent (or read a stale lower value) has a hidden dependency on any lower
    // tx that later WRITES that key — e.g. an UnDelegateResource that read its
    // (owner,to) record as absent because the same block's DelegateResource had
    // not published yet. Such a tx has no tracked dep on the writer, gets marked
    // "ready", and validates during the window where the writer is mid-re-
    // execution (its new write not yet in the mv) → it finalizes against a stale
    // read. Committing in strict index order, with re-execution barriered from
    // the commit-advance below, removes that race: each finalized tx is validated
    // against an mv in which every lower tx is final and immutable.
    //
    // Cost: independent txs still finalize in ONE post-speculation round (their
    // round-0 read-sets validate, the whole prefix advances at once). A depth-d
    // dependency chain costs ~d rounds; each round re-executes only the txs whose
    // read-set is currently invalid (a cheap value-based check), so a tx re-runs
    // ~once — when the lower write it depends on first commits — not once-per-round.
    let dbg = std::env::var("BLOCKSTM_DEBUG").is_ok();
    let mut converged = false;
    let mut rounds = 0usize;
    let mut reexecs = 0usize;
    let mut committed = 0usize; // every tx < committed is finalized & immutable
    for _ in 0..=n {
        if committed == n {
            converged = true;
            break;
        }
        rounds += 1;
        // Re-execute, in parallel, every not-yet-committed tx that is BOTH stale
        // (read-set no longer validates) AND dep-ready (every lower tx it read is
        // already committed). The dep-ready gate is the throughput lever: without
        // it a deep dependency chain re-runs its whole tail every round (O(n²) — and
        // for contract txs that is O(n²) wasted EVM runs); gated, each tx re-runs
        // ~once, when the lower write it depends on first commits. The frontier tx
        // (`committed`) reads only committed-or-base state so it is always dep-ready,
        // guaranteeing ≥1 re-run-or-commit per round. The rayon join is a BARRIER:
        // all re-executions publish before the commit-advance reads the mv, so no tx
        // is validated against a value a concurrently re-executing lower tx is about
        // to overwrite.
        let to_run: Vec<usize> = (committed..n)
            .into_par_iter()
            .filter(|&i| {
                let dep_ready = deps[i]
                    .lock()
                    .expect("deps poisoned")
                    .iter()
                    .all(|&j| (j as usize) < committed);
                dep_ready && {
                    let cap = captures[i].borrow();
                    !mv.validate(i as u32, &cap.reads)
                }
            })
            .collect();
        let round_reexecs = to_run.len();
        to_run.par_iter().for_each(|&i| {
            incarnation[i].fetch_add(1, Ordering::Relaxed);
            run(i);
        });
        reexecs += round_reexecs;
        // Re-validate the uncommitted range against the now-stable mv (in
        // parallel — the barrier above means no writer is in flight), then
        // advance the commit frontier over the longest CONTIGUOUS run of valid
        // txs. Each committed tx reads only lower (already-committed) state, so a
        // passing validation means it computed exactly what serial would. The
        // boolean prefix-walk is the only sequential part and is trivially cheap.
        let valid: Vec<bool> = (committed..n)
            .into_par_iter()
            .map(|i| {
                let cap = captures[i].borrow();
                mv.validate(i as u32, &cap.reads)
            })
            .collect();
        let mut advanced = 0usize;
        for &ok in &valid {
            if !ok {
                break;
            }
            finalized[committed + advanced].store(true, Ordering::Relaxed);
            advanced += 1;
        }
        committed += advanced;
        // Progress is guaranteed: the lowest non-committed tx reads only
        // committed lower state, so after its re-execution it must validate. If a
        // round somehow makes no progress with nothing left to re-execute, bail
        // to the serial fallback rather than spin.
        if advanced == 0 && round_reexecs == 0 {
            break;
        }
    }
    if dbg {
        eprintln!("[blockstm] n={n} rounds={rounds} reexecs={reexecs} converged={converged}");
    }
    blockstm_stats::record(n, rounds, reexecs, converged);
    if !converged {
        // Safety hatch: do not commit a non-converged (untrusted) result.
        return None;
    }

    // === Deferred-sequential PUBLIC_NET_USAGE fold (+ limit guard) ===
    //
    // The chain-global free-bandwidth counter was excluded from the MVCC chain
    // (its reads returned base, its writes were dropped — see
    // `deferred_public_net_keys`). Recompute its EXACT serial value here by
    // replaying the windowed-average `increase()` in tx order over each tx's
    // captured free-net `bytes`, with the same per-step branch the serial path
    // takes. Computed BEFORE any base write so a guard trip aborts cleanly.
    //
    // Guard: in serial a tx only spends free net while `bytes <= limit - new`;
    // past that it falls back to a *fee* charge (different state). We speculated
    // every free-net tx through (reading base, far below the limit). If the real
    // running total ever crosses the limit, that speculation diverged → return
    // None so the caller re-runs the whole block serially. At ~30% of the 14.4B
    // limit with ~150KB/block of free-net bytes this is astronomically rare, but
    // it keeps the result provably byte-identical to serial under all loads.
    let public_net_final: Option<(i64, i64)> = {
        let dp = tron_chainbase::DynamicPropertiesStore::new(state.dyn_props.clone());
        let pub_limit = dp.public_net_limit();
        let mut usage = dp.public_net_usage();
        let mut time = dp.public_net_time();
        let mut any = false;
        for i in 0..n {
            let bytes = captures[i].borrow().public_net_bytes;
            if let Some(bytes) = bytes {
                let new_pub = increase_default(usage, 0, time, now_slot);
                if bytes > pub_limit.saturating_sub(new_pub) {
                    // The free budget would actually be exhausted mid-block —
                    // our "all free-net" speculation is unsafe. Abort to serial.
                    return None;
                }
                usage = increase_default(new_pub, bytes, now_slot, now_slot);
                time = now_slot;
                any = true;
            }
        }
        any.then_some((usage, time))
    };

    // === Deferred per-contract dynamic-energy fold (+ boundary guard) ===
    //
    // For contracts caught-up this cycle, `ContractState.energy_usage` was
    // excluded from the MVCC chain and each tx's net delta captured. Sum them per
    // contract in tx order (plain i64 `+=`, associative ⇒ identical to serial)
    // and fold onto base at commit. The boundary backstop (a deferred contract
    // whose write changed cycle/factor — should never happen) forces a serial
    // re-run so a factor change can never be silently mis-applied.
    let contract_energy_totals: std::collections::HashMap<Vec<u8>, i64> = {
        let mut totals: std::collections::HashMap<Vec<u8>, i64> = std::collections::HashMap::new();
        for i in 0..n {
            let cap = captures[i].borrow();
            if cap.contract_energy_boundary {
                return None;
            }
            for (addr, delta) in cap.contract_energy.iter() {
                *totals.entry(addr.clone()).or_insert(0) += *delta;
            }
        }
        totals
    };

    // Commit write-sets to the real state in ascending tx order: the highest tx
    // that wrote a key wins, exactly as serial application would leave it.
    // Accumulate commutative deltas in the same pass.
    let mut delta_totals: std::collections::HashMap<(StoreId, Vec<u8>), i64> =
        std::collections::HashMap::new();
    // Diagnostic only (APPLY_TIMING): a pre-pass finds the chain-former hot key
    // and SNAPSHOTS its base value before the commit overwrites it, so a store=0
    // account can be field-diffed (base→final) to tell a genuine balance chain
    // from a deferrable accumulator. Off the hot path otherwise.
    let stats_on = blockstm_stats::is_on();
    let hot_snapshot: Option<(StoreId, Vec<u8>, u32, Option<Vec<u8>>)> = if stats_on {
        let mut writer_counts: std::collections::HashMap<(StoreId, Vec<u8>), u32> =
            std::collections::HashMap::new();
        for i in 0..n {
            for (sid, key, _) in captures[i].borrow().effective_write_set() {
                *writer_counts.entry((sid, key)).or_insert(0) += 1;
            }
        }
        writer_counts.into_iter().max_by_key(|(_, c)| *c).map(|((sid, key), cnt)| {
            let base_val = base_field(state, sid).and_then(|b| b.get(&key).ok().flatten());
            (sid, key, cnt, base_val)
        })
    } else {
        None
    };
    for i in 0..n {
        let cap = captures[i].borrow();
        // Commit the EFFECTIVE write-set (matching what was published) so the
        // dropped no-op writes are consistently absent — the surviving creator's
        // value is exactly what the serial loop leaves on disk.
        for (sid, key, value) in cap.effective_write_set() {
            if let Some(b) = base_field(state, sid) {
                match value {
                    Some(v) => b.put(&key, &v).expect("commit put"),
                    None => b.delete(&key).expect("commit delete"),
                }
            }
        }
        for ((sid, key), d) in cap.deltas.iter() {
            let e = delta_totals.entry((*sid, key.clone())).or_insert(0);
            *e = e.wrapping_add(*d);
        }
    }
    if let Some((sid, key, cnt, base_val)) = hot_snapshot {
        // Field-diff for store=0 (accounts): which fields changed base→final.
        let detail = if sid == SID_ACCOUNTS {
            let final_val = base_field(state, sid).and_then(|b| b.get(&key).ok().flatten());
            account_field_diff(base_val.as_deref(), final_val.as_deref())
        } else {
            String::new()
        };
        blockstm_stats::record_hotkey(sid, &key, cnt, detail);
    }

    // Accumulators: write `base + Σ delta` once per key (addition is
    // associative ⇒ identical to the serial loop's in-order RMW). Encoded as
    // 8-byte BE, matching `DynamicPropertiesStore::put_long`.
    for ((sid, key), total) in delta_totals.iter() {
        if let Some(b) = base_field(state, *sid) {
            let base_i = decode_long(b.get(key).expect("commit acc get").as_ref());
            let final_i = base_i.wrapping_add(*total);
            b.put(key, &final_i.to_be_bytes()).expect("commit acc put");
        }
    }

    // Write the deferred-sequential PUBLIC_NET fold result (only when ≥1 tx used
    // free net — otherwise serial leaves both keys untouched). Same `put_long`
    // encoding + same store the serial path writes through.
    if let Some((usage, time)) = public_net_final {
        let dp = tron_chainbase::DynamicPropertiesStore::new(state.dyn_props.clone());
        dp.save_public_net_usage(usage);
        dp.save_public_net_time(time);
    }

    // Write the deferred per-contract energy fold: `base.energy_usage + Σ delta`,
    // keeping the caught-up base's `update_cycle` + `energy_factor` (unchanged
    // mid-cycle). Same proto encoding the serial `add_energy_usage` writes. Base
    // is pristine for these contracts (their MVCC writes were dropped).
    if !contract_energy_totals.is_empty() {
        use prost::Message;
        if let Some(b) = base_field(state, SID_CONTRACT_STATE) {
            for (addr, total) in contract_energy_totals.iter() {
                let mut cs = b
                    .get(addr)
                    .expect("commit energy get")
                    .and_then(|bytes| tron_proto::ContractState::decode(bytes.as_slice()).ok())
                    .unwrap_or_default();
                cs.energy_usage = cs.energy_usage.wrapping_add(*total);
                b.put(addr, &cs.encode_to_vec()).expect("commit energy put");
            }
        }
    }

    Some(
        results
            .into_iter()
            .map(|m| m.into_inner().expect("result poisoned").expect("tx not executed"))
            .collect(),
    )
}
