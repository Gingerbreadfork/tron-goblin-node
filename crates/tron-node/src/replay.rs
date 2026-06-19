//! Offline block-apply (`replay-blocks` subcommand).
//!
//! A network-free counterpart to live p2p sync: it reads blocks from a
//! local file and applies each through the **identical** production
//! apply path the live sync uses (`SyncDriver::accept_block` →
//! validate `txTrieRoot`, push into the fork tree, execute every
//! transaction, commit, advance the head). The only difference from a
//! live run is the block *source* — a file instead of a peer — so the
//! timed window is pure apply (no fetch), directly comparable to
//! java-tron's offline `OracleReplay`.
//!
//! ## Block file format
//!
//! The same length-prefixed protobuf stream java-tron's `OracleFetch`
//! writes: a repeating sequence of
//!
//! ```text
//! [ int32 big-endian length ][ length bytes of Block protobuf ]
//! ```
//!
//! in ascending block order, EOF-terminated. The `length` bytes are the
//! canonical `Block` wire encoding (`Block.toByteArray()` from a
//! reference node's `getBlockByNum`), which is exactly what the
//! raw-bytes `txTrieRoot` check validates against.
//!
//! ## Behavior (mirrors `OracleReplay`)
//!
//! * Opens the data-dir (a snapshot that has already been imported).
//! * Reads frames in order; blocks at or below the current head are
//!   **skipped** (so a file that starts before the snapshot head still
//!   works), and replay stops once a block number exceeds `--to`.
//! * Applies each remaining block via the production driver, honoring
//!   the `[vm] parallel_exec` (Block-STM) and `[vm] pipelined_apply`
//!   switches from the config exactly as the daemon does.
//! * Prints a final machine-parseable line:
//!   `replay-blocks: applied=N head=M`.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use bytes::Bytes;
use prost::Message as _;
use tracing::{error, info, warn};
use tron_proto::Block;

use crate::mempool_explore::decode_tx_summary;

use crate::config::NodeConfig;
use crate::storage::OpenedStores;
use crate::sync::{SyncConfig, SyncDriver};

/// Hard cap on a single frame's declared length (matches java-tron's
/// `OracleReplay`): a 64 MiB ceiling rejects a corrupt/desynced stream
/// before it tries to allocate a wild buffer.
const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

/// Result of an offline replay run.
pub struct ReplayReport {
    /// Number of blocks actually applied (extended the head).
    pub applied: u64,
    /// Number of blocks skipped because they were at or below the
    /// starting head.
    pub skipped: u64,
    /// Final head block number after the run.
    pub head: i64,
}

/// Errors a replay run can hit before/around the per-block apply (a
/// per-block apply failure does not error out the run — it stops the
/// loop and reports the head reached, like `OracleReplay`).
#[derive(Debug)]
pub enum ReplayError {
    Storage(crate::storage::StorageError),
    Config(crate::config::ConfigError),
    Io(std::io::Error),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::Storage(e) => write!(f, "open storage: {e}"),
            ReplayError::Config(e) => write!(f, "vm config: {e}"),
            ReplayError::Io(e) => write!(f, "block file: {e}"),
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<crate::storage::StorageError> for ReplayError {
    fn from(e: crate::storage::StorageError) -> Self {
        ReplayError::Storage(e)
    }
}

impl From<std::io::Error> for ReplayError {
    fn from(e: std::io::Error) -> Self {
        ReplayError::Io(e)
    }
}

/// Read a single big-endian `int32` frame length. Returns `Ok(None)` on
/// a clean EOF (the stream terminator).
fn read_frame_len<R: Read>(r: &mut R) -> std::io::Result<Option<usize>> {
    let mut buf = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match r.read(&mut buf[filled..])? {
            0 if filled == 0 => return Ok(None), // clean EOF at a frame boundary
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated frame length",
                ))
            }
            n => filled += n,
        }
    }
    Ok(Some(i32::from_be_bytes(buf) as usize))
}

/// Run an offline block replay.
///
/// Opens `config.data_dir`, builds a `SyncDriver` wired exactly like the
/// daemon's catch-up driver (same executor config, undo store, and
/// cross-store checkpoint), then applies blocks from `blocks_path` up to
/// and including `to` (or EOF). Blocks at or below the opened head are
/// skipped.
pub fn run_replay(
    config: &NodeConfig,
    blocks_path: &Path,
    to: i64,
    verify_contract_ret: bool,
) -> Result<ReplayReport, ReplayError> {
    // === Open the snapshot and replay any orphan checkpoint manifests ===
    // The daemon's startup runs this same BlockSession-checkpoint
    // recovery (runtime.rs); doing it here keeps an offline run's base
    // state identical to a daemon open of the same data-dir.
    let stores = OpenedStores::open(&config.data_dir)?;
    let state = stores.to_state_backends();
    let checkpoint_dir = tron_chainbase::CheckPointV2::new(&config.data_dir);
    match tron_executor::replay_pending_checkpoints(&state, &checkpoint_dir) {
        Ok((0, _)) => {}
        Ok((cp_count, entries)) => info!(
            checkpoints = cp_count,
            entries, "replayed orphan checkpoint manifests into base stores"
        ),
        Err(e) => warn!(error = ?e, "checkpoint recovery failed; continuing"),
    }

    // === Build the executor config, honoring [vm] parallel_exec ===
    // Mirror runtime.rs's `ExecConfig` derivation so the offline apply is
    // byte-identical to a live apply. `with_exec_config` (below) captures
    // the `parallel_exec` master switch; the per-block work gate inside
    // `accept_block` then turns Block-STM on/off per block exactly as the
    // daemon does.
    let vm = config.resolve_vm().map_err(ReplayError::Config)?;
    let exec_config = tron_executor::ExecConfig {
        save_internal_tx: vm.save_internal_tx,
        vm_trace: vm.vm_trace,
        save_featured_internal_tx: vm.save_featured_internal_tx,
        require_signature: true,
        require_fee_limit: true,
        verify_tx_trie: true, // SyncDriver forces this off; it owns the raw-bytes check.
        defer_store_fsync: false,
        parallel_exec: vm.parallel_exec,
        capture_state_deltas: false,
        // Off for a pure throughput benchmark; ON for divergence hunting /
        // narrow fix-verification (the `--verify` flag), so the offline
        // apply runs the same success/failure tripwire the live sync does.
        verify_contract_ret,
    };

    // === Build the apply driver ===
    // No peers, no fetch pool, no leadership — this driver only ever
    // applies blocks handed to it directly. The state-affecting
    // attachments match the daemon's BlockSession (non-snapshot-reorg)
    // catch-up path: undo store + cross-store checkpoint + strict
    // per-tx ref_block validation. P2p/observability attachments
    // (metrics, mempool, pubsub, index hook) are intentionally omitted —
    // they never change committed state.
    let sync_config = SyncConfig {
        peers: Vec::new(),
        max_blocks: None,
        tail_interval: std::time::Duration::from_secs(3),
        initial_backoff: std::time::Duration::from_secs(5),
        blocks_backend: stores.blocks.clone(),
        progress_log_interval: config.p2p.progress_log_interval,
        advertise_port: config.p2p.advertise_port,
        tip_test: false,
        p2p_rate_limits: config.rate_limiter.p2p.clone(),
        fetch_block_timeout: std::time::Duration::from_millis(200),
        peer_is_fast_forward: false,
        follow_tip: false,
    };
    let undo = tron_chainbase::BlockUndoStore::new(stores.block_undo.clone());
    let mut driver = SyncDriver::new(state, sync_config)
        .with_undo_store(undo)
        .with_checkpoint(checkpoint_dir)
        .with_exec_config(exec_config)
        .with_strict_ref_block_check();
    // `vm.pipelined_apply` overlaps a block's commit with the next
    // block's execution (same writes, same order). The daemon gates it
    // on `[witness]` being unset; an offline replay never produces, so
    // honor the config switch directly.
    if config.vm.pipelined_apply {
        driver = driver.with_pipelined_apply();
    }

    let start_head = driver.head_number();
    info!(
        head = start_head,
        blocks = %blocks_path.display(),
        to,
        parallel_exec = vm.parallel_exec,
        "offline replay starting"
    );

    // === Apply loop ===
    let file = File::open(blocks_path)?;
    let mut reader = BufReader::with_capacity(1 << 20, file);

    let mut prev_id = driver.resume_head();
    let mut last_block_ts = 0i64;
    let mut applied = 0u64;
    let mut skipped = 0u64;
    let mut head = start_head;
    let t0 = std::time::Instant::now();

    loop {
        let len = match read_frame_len(&mut reader)? {
            Some(0) => break, // explicit 0-length terminator
            Some(len) => len,
            None => break,    // clean EOF
        };
        if len > MAX_FRAME_LEN {
            warn!(len, "bad frame length; stopping replay");
            break;
        }
        let mut raw = vec![0u8; len];
        reader.read_exact(&mut raw)?;

        let block = match Block::decode(&raw[..]) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "decode Block; stopping replay");
                break;
            }
        };
        let block_num = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.number)
            .unwrap_or(-1);

        // Skip blocks at or below the starting head (the file may begin
        // before the snapshot head — `OracleReplay` does the same).
        if block_num <= head {
            skipped += 1;
            continue;
        }
        // Stop once we'd cross the requested ceiling.
        if block_num > to {
            info!(stop_at = to, next = block_num, "reached --to; stopping replay");
            break;
        }

        // Apply through the production path. `apply_block` consumes the
        // original wire bytes for the raw-bytes txTrieRoot check.
        let before = applied;
        let total_applied =
            driver.replay_apply_block(&block, Bytes::from(raw), block_num, &mut prev_id, &mut last_block_ts);
        // `blocks_applied` only increments on a committed extension; if it
        // didn't move, this block was rejected/side-forked — surface it and
        // stop (a clean linear replay should never hit this).
        if total_applied as u64 == applied {
            error!(
                block = block_num,
                "block not applied (rejected, side-fork, or reorg); stopping replay"
            );
            break;
        }
        applied = total_applied as u64;
        let _ = before;
        head = block_num;

        if block_num >= to {
            info!(stop_at = to, "applied final block; stopping replay");
            break;
        }
    }

    let secs = t0.elapsed().as_secs_f64().max(1e-9);
    info!(
        applied,
        skipped,
        head,
        rate = format!("{:.1} blk/s", applied as f64 / secs),
        elapsed = format!("{:.1}s", secs),
        "offline replay done"
    );

    Ok(ReplayReport {
        applied,
        skipped,
        head,
    })
}

/// Result of a `dump-blocks` archive run.
pub struct DumpReport {
    /// Number of blocks written to the archive.
    pub written: u64,
    /// Lowest block number written (`-1` if none).
    pub first: i64,
    /// Highest block number written (`-1` if none).
    pub last: i64,
}

/// Produce a length-prefixed block archive — the same
/// `[int32 big-endian length][Block bytes]` stream [`run_replay`] consumes —
/// by reading blocks `from..=to` straight out of an already-synced data-dir's
/// `BlockStore`. No network, no peers: run this once after a normal sync to
/// capture the block range, then drive any number of offline replays and
/// narrow fix-verifications from the file at CPU speed (deterministic,
/// repeatable, immune to peer rotation).
///
/// The bytes written are the store's persisted `Block` encoding, which is the
/// canonical wire form the replay's raw-bytes `txTrieRoot`/block-id checks
/// validate against — a non-canonical row would be *rejected* on replay
/// (block-not-applied), not silently mis-applied, so the archive is
/// self-checking the first time it's replayed.
pub fn dump_blocks(
    config: &NodeConfig,
    from: i64,
    to: i64,
    out_path: &Path,
) -> Result<DumpReport, ReplayError> {
    let stores = OpenedStores::open(&config.data_dir)?;
    let block_store = tron_chainbase::BlockStore::new(stores.blocks.clone());

    let file = File::create(out_path)?;
    let mut w = BufWriter::with_capacity(1 << 20, file);

    // Forward num-ordered scan in chunks, the same primitive the chain uses
    // for paginated range walks.
    const CHUNK: usize = 256;
    let mut next = from;
    let mut written = 0u64;
    let mut first = -1i64;
    let mut last = -1i64;
    let t0 = std::time::Instant::now();
    info!(from, to, out = %out_path.display(), "dump-blocks starting");
    'outer: while next <= to {
        let want = (((to - next + 1) as usize).min(CHUNK)).max(1);
        let blocks = block_store.get_limit_number(next, want).map_err(|e| {
            ReplayError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("block store read at {next}: {e}"),
            ))
        })?;
        if blocks.is_empty() {
            break; // gap or end of store
        }
        let mut advanced = false;
        for b in &blocks {
            let n = b
                .block_header
                .as_ref()
                .and_then(|h| h.raw_data.as_ref())
                .map(|r| r.number)
                .unwrap_or(-1);
            // Dedup any fork-height duplicate and stop at the ceiling.
            if n < next {
                continue;
            }
            if n > to {
                break 'outer;
            }
            let bytes = b.encode_to_vec();
            w.write_all(&(bytes.len() as i32).to_be_bytes())?;
            w.write_all(&bytes)?;
            written += 1;
            if first < 0 {
                first = n;
            }
            last = n;
            next = n + 1;
            advanced = true;
            if written % 50_000 == 0 {
                info!(written, at = last, "dump-blocks progress");
            }
        }
        if !advanced {
            break;
        }
    }
    w.flush()?;
    let secs = t0.elapsed().as_secs_f64().max(1e-9);
    info!(
        written,
        first,
        last,
        rate = format!("{:.0} blk/s", written as f64 / secs),
        "dump-blocks done"
    );
    Ok(DumpReport { written, first, last })
}

/// Result of a decode-only microbenchmark run.
pub struct BenchDecodeReport {
    /// Blocks decoded inside the timed loop.
    pub blocks: u64,
    /// Transactions decoded inside the timed loop (summed across blocks).
    pub txs: u64,
    /// Seconds spent in the timed decode loop (corpus already in memory; I/O
    /// excluded).
    pub elapsed_s: f64,
}

/// Run a decode-only microbenchmark over the length-prefixed block corpus.
///
/// This is a sibling of [`run_replay`] that touches **no** state, RocksDB,
/// executor, or consensus accounting — it measures only the CPU cost of
/// deserializing the canonical TRON `Block` protobuf and decoding each
/// transaction's contract parameters, the parse work every node does on the
/// hot path before it can apply anything.
///
/// ## Phases
///
/// 1. **Load (untimed).** Read up to `count` frames from `blocks_path` into an
///    in-memory `Vec<Vec<u8>>` of raw `Block` wire bytes (the same
///    `[int32 big-endian length][Block bytes]` framing [`run_replay`] reads).
///    File I/O and frame splitting happen here so they are excluded from the
///    timed window.
/// 2. **Decode (timed).** In a tight loop over the in-memory corpus, for each
///    frame:
///    * `Block::decode` (prost) the full block;
///    * iterate `block.transactions`;
///    * for each transaction, run the production [`decode_tx_summary`] — the
///      exact decode the `--mempool` / `--explore` dashboards use: it
///      protobuf-decodes the first contract's typed parameter
///      (`TransferContract` / `TransferAssetContract` / `TriggerSmartContract`),
///      reads the 4-byte selector, maps it to a method name, and ABI-decodes
///      the USDT transfer amount. No reimplementation — the same function the
///      node ships.
///
/// The returned report carries `blocks`, `txs`, and `elapsed_s`; the caller
/// derives blocks/sec and txs/sec. `blocks` counts frames the loop actually
/// decoded (so it equals `count` unless the corpus is shorter).
pub fn bench_decode(blocks_path: &Path, count: u64) -> Result<BenchDecodeReport, ReplayError> {
    // === Phase 1: load the corpus into memory (untimed) ===
    let file = File::open(blocks_path)?;
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    while (corpus.len() as u64) < count {
        let len = match read_frame_len(&mut reader)? {
            Some(0) => break, // explicit 0-length terminator
            Some(len) => len,
            None => break,    // clean EOF
        };
        if len > MAX_FRAME_LEN {
            warn!(len, "bad frame length; stopping corpus load");
            break;
        }
        let mut raw = vec![0u8; len];
        reader.read_exact(&mut raw)?;
        corpus.push(raw);
    }
    let loaded = corpus.len();
    info!(
        loaded,
        requested = count,
        blocks = %blocks_path.display(),
        "bench-decode corpus loaded into memory"
    );

    // === Phase 2: decode (timed) ===
    let mut blocks = 0u64;
    let mut txs = 0u64;
    let t0 = std::time::Instant::now();
    for raw in &corpus {
        let block = match Block::decode(&raw[..]) {
            Ok(b) => b,
            Err(e) => {
                // A corpus this benchmark loads is a canonical block stream;
                // a decode failure means the file is corrupt — surface it and
                // stop rather than silently undercounting.
                error!(error = %e, "bench-decode: Block::decode failed; stopping");
                break;
            }
        };
        for tx in &block.transactions {
            // Production decode: protobuf parameter unpack + selector + ABI.
            // The result is consumed by `std::hint::black_box` so the optimizer
            // cannot elide the work being measured.
            let summary = decode_tx_summary(tx);
            std::hint::black_box(&summary);
            txs += 1;
        }
        std::hint::black_box(&block);
        blocks += 1;
    }
    let elapsed_s = t0.elapsed().as_secs_f64();

    let rate = if elapsed_s > 0.0 {
        blocks as f64 / elapsed_s
    } else {
        0.0
    };
    let tx_rate = if elapsed_s > 0.0 {
        txs as f64 / elapsed_s
    } else {
        0.0
    };
    info!(
        blocks,
        txs,
        elapsed = format!("{elapsed_s:.3}s"),
        blocks_per_sec = format!("{rate:.1}"),
        txs_per_sec = format!("{tx_rate:.1}"),
        "bench-decode done"
    );

    Ok(BenchDecodeReport {
        blocks,
        txs,
        elapsed_s,
    })
}
