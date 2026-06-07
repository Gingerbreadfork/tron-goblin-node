//! `tron-node` daemon entry point.
//!
//! ```text
//! tron-node start      [--config FILE] [--data-dir DIR] [--rpc-port N]
//!                      [--rpc-host HOST] [--peer HOST:PORT] [--max-blocks N]
//!                      [--no-rpc] [--no-sync]
//! tron-node init       [--data-dir DIR]
//! tron-node dump-state [--data-dir DIR]
//! ```
//!
//! `start` opens the storage tree, optionally bootstraps from genesis,
//! starts the JSON-RPC server, and runs one sync coordinator per
//! configured peer until Ctrl-C.
//!
//! `init` does the storage open + genesis write and exits — useful
//! for setting up a data directory before starting the daemon proper.
//!
//! `dump-state` emits a JSON snapshot of the consensus-critical chain
//! state (head pointers, chain-wide resource totals, fee accumulators,
//! witness summary) so it can be diffed against a reference java-tron
//! node during first-mainnet-sync triage.

use std::path::PathBuf;
use std::process::ExitCode;

use tron_node::{
    export_to_tarball, import_live, import_snapshot, run, verify_snapshot, Compression,
    ImportMode, NodeConfig,
    OpenedStores, RunError, ShutdownSignal,
};

const USAGE: &str = "\
usage:
  tron-node start            [--config FILE] [--data-dir DIR] [--rpc-port N]
                             [--rpc-host HOST] [--peer HOST:PORT] [--max-blocks N]
                             [--chain-id N] [--no-rpc] [--no-sync]
                             [--progress-log-interval N]
  tron-node init             [--data-dir DIR]
  tron-node dump-state       [--data-dir DIR]
  tron-node import-snapshot  --from PATH [--data-dir DIR]
                             [--mode copy|move|symlink] [--force]
  tron-node import-live      --from PATH [--data-dir DIR]
                             [--secondary-cache DIR] [--force]
  tron-node export-snapshot  --to PATH [--data-dir DIR]
                             [--compression gzip|none]
  tron-node verify-snapshot  [--data-dir DIR]

start:            open the storage tree, bootstrap genesis if needed, then run
                  the JSON-RPC server + one sync coordinator per configured peer
                  until interrupted.

init:             open the storage tree, apply the genesis block, exit. Useful
                  for preparing a data directory ahead of `start`.

dump-state:       open the storage tree read-only and emit a JSON snapshot of
                  head, chain-wide resource totals, fee accumulators, and witness
                  counters. Designed for divergence triage against java-tron.

import-snapshot:  plant a java-tron snapshot into data_dir/db/. --from accepts
                  either a directory of per-store subdirs (account/, witness/,
                  properties/, ...) or a tarball (.tar / .tar.gz / .tgz) —
                  tarballs are auto-extracted to a temp dir, layout-detected,
                  imported, and cleaned up. --mode copy is safest (default);
                  --mode symlink is instant; --mode move is fastest within one
                  FS. --force replaces an existing data_dir/db/. Mainnet
                  snapshots are typically 100+ GiB.

import-live:      copy a java-tron database tree while the source node keeps
                  running. Opens each per-store subdir under --from as a
                  RocksDB secondary (RocksDB lets multiple secondaries coexist
                  with one primary), scans every key, writes into our
                  data_dir/db/<store>. No copy of SST files — strictly
                  key-by-key streaming. --secondary-cache holds the per-store
                  secondary metadata (writable scratch dir, defaults to
                  data_dir/.live-import-cache, cleaned up on success). Consistency
                  is per-store, not chain-wide — different stores end up at
                  slightly different heights (within a few blocks of each
                  other); the daemon catches up on first run.

export-snapshot:  bundle data_dir/db/* into a tarball at --to. --compression
                  gzip (default) writes .tar.gz; --compression none writes
                  plain .tar. Atomic — writes to a .tmp sibling first, renames
                  on success. The node must NOT be running during export (RocksDB
                  WAL writes during a live tar would capture an inconsistent
                  state).

verify-snapshot:  open an existing data_dir/db/ and print the same report as
                  import-snapshot — head pointer, witness count, store list.
                  Use after a manual copy to confirm everything is readable.

Each --peer flag accepts a HOST:PORT and may be repeated to add more
peers. --no-rpc / --no-sync disable the respective subsystem.

If no --peer is given (and --no-sync is not set), the daemon falls
back to the built-in MAINNET_SEEDS list. Pass --mainnet-seeds to mix
them into an explicit peer set. Peer dial order is randomized
per-session.

--progress-log-interval N  during sync, emit a heartbeat every N applied
                           blocks (default 100; set 1 to log every block).
--mainnet-seeds            append the built-in mainnet seed list to --peer.
--metrics-port N           Prometheus /metrics listen port (default 9090).
--metrics-host HOST        Prometheus /metrics bind host (default 127.0.0.1).
--no-metrics               disable the Prometheus metrics endpoint.

Set RUST_LOG to control log verbosity:
  RUST_LOG=info                  (default — startup head, sync progress, warnings)
  RUST_LOG=debug                 verbose per-peer + per-block activity
  RUST_LOG=tron_node=debug,info  module-targeted: tron-node only

At the default `info` level the node prints its startup head (height + UTC
block time + how far behind real time) and a throttled sync-progress line,
e.g. `syncing #83,344,101  2026-06-05 14:23:09Z  (3d 2h behind)  ·  142 blk/s
·  via 8.217.215.241`, then `caught up to chain tip …` once it's following
live blocks.
";

fn main() -> ExitCode {
    init_tracing();

    let args: Vec<String> = std::env::args().collect();
    let Some(cmd) = args.get(1) else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    match cmd.as_str() {
        "start" => run_start(&args[2..]),
        "init" => run_init(&args[2..]),
        "dump-state" => run_dump_state(&args[2..]),
        "import-snapshot" => run_import_snapshot(&args[2..]),
        "import-live" => run_import_live(&args[2..]),
        "export-snapshot" => run_export_snapshot(&args[2..]),
        "verify-snapshot" => run_verify_snapshot(&args[2..]),
        "admin" => run_admin(&args[2..]),
        "--help" | "-h" | "help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_import_snapshot(args: &[String]) -> ExitCode {
    let mut from: Option<PathBuf> = None;
    let mut mode = ImportMode::Copy;
    let mut force = false;
    let mut data_dir = PathBuf::from("./tron-data");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--from" => {
                i += 1;
                from = Some(PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--from needs PATH");
                        return ExitCode::from(2);
                    }
                }));
            }
            "--mode" => {
                i += 1;
                let s = match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--mode needs copy|move|symlink");
                        return ExitCode::from(2);
                    }
                };
                mode = match ImportMode::from_str(s) {
                    Some(m) => m,
                    None => {
                        eprintln!("--mode must be one of: copy, move, symlink");
                        return ExitCode::from(2);
                    }
                };
            }
            "--force" => force = true,
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--data-dir needs PATH");
                        return ExitCode::from(2);
                    }
                });
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("usage: tron-node import-snapshot --from PATH [--data-dir DIR] [--mode copy|move|symlink] [--force]");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(from) = from else {
        eprintln!("--from is required");
        return ExitCode::from(2);
    };
    match import_snapshot(&from, &data_dir, mode, force) {
        Ok(report) => {
            print_import_report(&report, &from, &data_dir, mode);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tron-node: import failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_export_snapshot(args: &[String]) -> ExitCode {
    let mut to: Option<PathBuf> = None;
    let mut compression = Compression::Gzip;
    let mut data_dir = PathBuf::from("./tron-data");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                i += 1;
                to = Some(PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--to needs PATH");
                        return ExitCode::from(2);
                    }
                }));
            }
            "--compression" => {
                i += 1;
                let s = match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--compression needs gzip|none");
                        return ExitCode::from(2);
                    }
                };
                compression = match Compression::from_str(s) {
                    Some(c) => c,
                    None => {
                        eprintln!("--compression must be one of: gzip, none");
                        return ExitCode::from(2);
                    }
                };
            }
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--data-dir needs PATH");
                        return ExitCode::from(2);
                    }
                });
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("usage: tron-node export-snapshot --to PATH [--data-dir DIR] [--compression gzip|none]");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(to) = to else {
        eprintln!("--to is required");
        return ExitCode::from(2);
    };
    match export_to_tarball(&data_dir, &to, compression) {
        Ok(report) => {
            let mib = report.bytes_written as f64 / (1024.0 * 1024.0);
            println!("snapshot exported:");
            println!("  data dir:       {data_dir:?}");
            println!("  output:         {:?}", report.output_path);
            println!("  compression:    {compression:?}");
            println!("  stores:         {}", report.stores_exported);
            println!("  bytes written:  {:.2} MiB", mib);
            println!("  store list:     {}", report.stores.join(", "));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tron-node: export failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_verify_snapshot(args: &[String]) -> ExitCode {
    let config = match parse_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return ExitCode::from(2);
        }
    };
    match verify_snapshot(&config.data_dir) {
        Ok(report) => {
            print_import_report(&report, &config.data_dir, &config.data_dir, ImportMode::Copy);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tron-node: verify failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_import_live(args: &[String]) -> ExitCode {
    let mut from: Option<PathBuf> = None;
    let mut secondary_cache: Option<PathBuf> = None;
    let mut force = false;
    let mut data_dir = PathBuf::from("./tron-data");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--from" => {
                i += 1;
                from = Some(PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--from needs PATH");
                        return ExitCode::from(2);
                    }
                }));
            }
            "--secondary-cache" => {
                i += 1;
                secondary_cache = Some(PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--secondary-cache needs PATH");
                        return ExitCode::from(2);
                    }
                }));
            }
            "--force" => force = true,
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => {
                        eprintln!("--data-dir needs PATH");
                        return ExitCode::from(2);
                    }
                });
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprintln!("usage: tron-node import-live --from PATH [--data-dir DIR] [--secondary-cache DIR] [--force]");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(from) = from else {
        eprintln!("--from is required");
        return ExitCode::from(2);
    };
    match import_live(&from, &data_dir, secondary_cache.as_deref(), force) {
        Ok(report) => {
            println!("live import complete:");
            println!("  source (primary):       {from:?}");
            println!("  destination:            {data_dir:?}");
            println!("  stores imported:        {}", report.stores_imported);
            let mib = report.bytes_copied as f64 / (1024.0 * 1024.0);
            println!("  bytes streamed:         {:.2} MiB", mib);
            println!("  head block number:      {}", report.head_block_number);
            println!("  head block hash:        {}", report.head_block_hash_hex);
            println!("  solidified block:       {}", report.solidified_block_number);
            println!("  witnesses:              {}", report.witness_count);
            println!("  stores:                 {}", report.stores.join(", "));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tron-node: live-import failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_import_report(
    report: &tron_node::ImportReport,
    from: &std::path::Path,
    data_dir: &std::path::Path,
    mode: ImportMode,
) {
    println!("snapshot imported:");
    println!("  source:                 {from:?}");
    println!("  destination:            {data_dir:?}");
    println!("  mode:                   {mode:?}");
    println!("  stores imported:        {}", report.stores_imported);
    if report.bytes_copied > 0 {
        let mib = report.bytes_copied as f64 / (1024.0 * 1024.0);
        println!("  bytes copied:           {:.2} MiB", mib);
    }
    println!("  head block number:      {}", report.head_block_number);
    println!("  head block hash:        {}", report.head_block_hash_hex);
    println!("  solidified block:       {}", report.solidified_block_number);
    println!("  witnesses:              {}", report.witness_count);
    println!(
        "  stores:                 {}",
        report.stores.join(", ")
    );
}

/// `tron-node admin <subcommand>` — DB lifecycle commands.
///
/// Subcommands:
///   * `compact --data-dir DIR` — full RocksDB compaction of every
///     store under `DIR/db/`. The daemon must be stopped (RocksDB
///     holds an exclusive lock).
///   * `prune-before --data-dir DIR --before BLOCK` — drop block
///     bodies + their block_index entries for heights below
///     `BLOCK`. Account state (balances, contract code, storage)
///     is preserved. Idempotent.
///   * `db move --src PATH --dst PATH` — move a database directory
///     (rename in place; cross-filesystem moves return Io error).
///   * `db copy --src PATH --dst PATH` — recursive copy of a database
///     directory. Stop the node first — see also
///     `export-snapshot --checkpoint` for a live-safe alternative.
///   * `db root --data-dir DIR` — recompute the account-state-root over
///     the current AccountStore (+ per-contract storage roots if the
///     `storage-row` store is present). Mirrors java-tron's `DbRoot`.
fn run_admin(args: &[String]) -> ExitCode {
    let Some(sub) = args.first() else {
        eprintln!(
            "admin: missing subcommand. Try one of:\n  \
             admin compact       --data-dir DIR\n  \
             admin prune-before  --data-dir DIR --before BLOCK\n  \
             admin db move       --src PATH --dst PATH\n  \
             admin db copy       --src PATH --dst PATH\n  \
             admin db root       --data-dir DIR"
        );
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    match sub.as_str() {
        "compact" => run_admin_compact(rest),
        "prune-before" => run_admin_prune_before(rest),
        "db" => run_admin_db(rest),
        other => {
            eprintln!("admin: unknown subcommand '{other}'");
            ExitCode::from(2)
        }
    }
}

fn run_admin_db(args: &[String]) -> ExitCode {
    let Some(sub) = args.first() else {
        eprintln!(
            "admin db: missing subcommand. Try:\n  \
             admin db move --src PATH --dst PATH\n  \
             admin db copy --src PATH --dst PATH\n  \
             admin db root --data-dir DIR\n  \
             admin db lite --src DIR --dst DIR [--recent-blocks N]"
        );
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    match sub.as_str() {
        "move" => run_admin_db_move(rest),
        "copy" => run_admin_db_copy(rest),
        "root" => run_admin_db_root(rest),
        "lite" => run_admin_db_lite(rest),
        other => {
            eprintln!("admin db: unknown subcommand '{other}'");
            ExitCode::from(2)
        }
    }
}

fn run_admin_db_lite(args: &[String]) -> ExitCode {
    let mut src: Option<PathBuf> = None;
    let mut dst: Option<PathBuf> = None;
    let mut recent_blocks = tron_node::DEFAULT_LITE_RECENT_BLOCKS;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--src" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("admin db lite: --src needs PATH");
                    return ExitCode::from(2);
                };
                src = Some(PathBuf::from(s));
            }
            "--dst" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("admin db lite: --dst needs PATH");
                    return ExitCode::from(2);
                };
                dst = Some(PathBuf::from(s));
            }
            "--recent-blocks" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("admin db lite: --recent-blocks needs N");
                    return ExitCode::from(2);
                };
                recent_blocks = match s.parse::<i64>() {
                    Ok(n) if n >= 1 => n,
                    _ => {
                        eprintln!("admin db lite: --recent-blocks needs a positive integer");
                        return ExitCode::from(2);
                    }
                };
            }
            other => {
                eprintln!("admin db lite: unknown flag '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let src = match src {
        Some(s) => s,
        None => {
            eprintln!("admin db lite: --src DIR required");
            return ExitCode::from(2);
        }
    };
    let dst = match dst {
        Some(s) => s,
        None => {
            eprintln!("admin db lite: --dst DIR required");
            return ExitCode::from(2);
        }
    };
    match tron_node::db_lite(&src, &dst, recent_blocks) {
        Ok(r) => {
            println!(
                "lite snapshot written to {} (latest={}, kept blocks [{}, {}], dropped {})",
                dst.display(),
                r.latest_block,
                r.prune_below,
                r.latest_block,
                r.blocks_pruned
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("admin db lite: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_admin_db_root(args: &[String]) -> ExitCode {
    let mut data_dir = PathBuf::from("./tron-data");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("--data-dir needs DIR");
                    return ExitCode::from(2);
                };
                data_dir = PathBuf::from(s);
            }
            other => {
                eprintln!("admin db root: unknown flag '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    match tron_node::db_root(&data_dir) {
        Ok(root) => {
            println!("{}", hex::encode(root));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("admin db root: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_src_dst(args: &[String], context: &str) -> Result<(PathBuf, PathBuf), ExitCode> {
    let mut src: Option<PathBuf> = None;
    let mut dst: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--src" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("{context}: --src needs PATH");
                    return Err(ExitCode::from(2));
                };
                src = Some(PathBuf::from(s));
            }
            "--dst" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("{context}: --dst needs PATH");
                    return Err(ExitCode::from(2));
                };
                dst = Some(PathBuf::from(s));
            }
            other => {
                eprintln!("{context}: unknown flag '{other}'");
                return Err(ExitCode::from(2));
            }
        }
        i += 1;
    }
    let src = src.ok_or_else(|| {
        eprintln!("{context}: --src PATH required");
        ExitCode::from(2)
    })?;
    let dst = dst.ok_or_else(|| {
        eprintln!("{context}: --dst PATH required");
        ExitCode::from(2)
    })?;
    Ok((src, dst))
}

fn run_admin_db_move(args: &[String]) -> ExitCode {
    let (src, dst) = match parse_src_dst(args, "admin db move") {
        Ok(p) => p,
        Err(code) => return code,
    };
    match tron_node::db_move(&src, &dst) {
        Ok(()) => {
            println!("moved {} → {}", src.display(), dst.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("admin db move: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_admin_db_copy(args: &[String]) -> ExitCode {
    let (src, dst) = match parse_src_dst(args, "admin db copy") {
        Ok(p) => p,
        Err(code) => return code,
    };
    match tron_node::db_copy(&src, &dst) {
        Ok(bytes) => {
            println!(
                "copied {} → {} ({bytes} bytes)",
                src.display(),
                dst.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("admin db copy: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_admin_compact(args: &[String]) -> ExitCode {
    let mut data_dir = PathBuf::from("./tron-data");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("--data-dir needs DIR");
                    return ExitCode::from(2);
                };
                data_dir = PathBuf::from(s);
            }
            other => {
                eprintln!("admin compact: unknown flag '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    match tron_node::compact_all(&data_dir) {
        Ok(list) => {
            println!(
                "compacted {} store(s): {}",
                list.len(),
                list.join(", ")
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("admin compact: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_admin_prune_before(args: &[String]) -> ExitCode {
    let mut data_dir = PathBuf::from("./tron-data");
    let mut before: Option<i64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("--data-dir needs DIR");
                    return ExitCode::from(2);
                };
                data_dir = PathBuf::from(s);
            }
            "--before" => {
                i += 1;
                let Some(s) = args.get(i) else {
                    eprintln!("--before needs BLOCK");
                    return ExitCode::from(2);
                };
                before = match s.parse() {
                    Ok(n) => Some(n),
                    Err(e) => {
                        eprintln!("--before parse: {e}");
                        return ExitCode::from(2);
                    }
                };
            }
            other => {
                eprintln!("admin prune-before: unknown flag '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(before) = before else {
        eprintln!("admin prune-before: --before BLOCK required");
        return ExitCode::from(2);
    };
    let stores = match OpenedStores::open(&data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("open storage: {e}");
            return ExitCode::FAILURE;
        }
    };
    match tron_node::prune_before(&stores, before) {
        Ok(pruned) => {
            println!("pruned {pruned} block(s) below height {before}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("admin prune-before: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_dump_state(args: &[String]) -> ExitCode {
    let config = match parse_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return ExitCode::from(2);
        }
    };
    let stores = match OpenedStores::open(&config.data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tron-node: open storage: {e}");
            return ExitCode::FAILURE;
        }
    };
    let snap = tron_node::snapshot(stores.dyn_props.clone(), stores.witnesses.clone());
    println!("{}", tron_node::snapshot_to_json(&snap));
    ExitCode::SUCCESS
}

fn run_start(args: &[String]) -> ExitCode {
    let config = match parse_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return ExitCode::from(2);
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let shutdown = ShutdownSignal::new();
    let shutdown_sigint = shutdown.clone();
    rt.spawn(async move {
        let sig = wait_for_shutdown_signal().await;
        eprintln!("\ntron-node: {sig} received, shutting down");
        shutdown_sigint.shutdown();
    });

    let result: Result<(), RunError> = rt.block_on(run(config, shutdown));
    rt.shutdown_timeout(std::time::Duration::from_secs(5));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tron-node: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Block until the process receives a termination signal, returning its
/// name. Handles `SIGINT` (Ctrl-C) **and** `SIGTERM` — the signal
/// systemd / docker / k8s send to stop a service (F-01). Without SIGTERM,
/// those runtimes would kill the process before the graceful
/// `shutdown_timeout` drain + clean RocksDB flush could run.
#[cfg(unix)]
async fn wait_for_shutdown_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        },
        Err(e) => {
            // Couldn't install the SIGTERM handler — fall back to Ctrl-C
            // only rather than failing to start.
            eprintln!("tron-node: failed to install SIGTERM handler ({e}); SIGINT only");
            let _ = tokio::signal::ctrl_c().await;
            "SIGINT"
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "SIGINT"
}

fn run_init(args: &[String]) -> ExitCode {
    let config = match parse_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return ExitCode::from(2);
        }
    };
    // Disable all subsystems so `run()` does the genesis write and
    // exits as soon as shutdown fires. We do NOT pre-open the stores
    // here — that used to hold a RocksDB file lock across the
    // `block_on(run(...))` call, causing run()'s own open to fail
    // silently (the `let _ =` discards the error).
    let mut config = config;
    config.rpc.disabled = true;
    config.p2p.disabled = true;
    config.metrics.disabled = true;

    let shutdown = ShutdownSignal::new();
    let shutdown_clone = shutdown.clone();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tron-node: tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_clone.shutdown();
    });
    match rt.block_on(run(config, shutdown)) {
        Ok(()) => {
            eprintln!("tron-node: init done");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tron-node: init failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Initialize the `tracing` subscriber:
///
/// * `EnvFilter` reads `RUST_LOG` (e.g. `RUST_LOG=info,tron_node=debug`).
///   Defaults to `info` when unset so a flagless invocation emits the
///   key lifecycle lines without being noisy.
/// * `fmt::Layer` writes to stderr (so stdout stays clean for piped
///   subcommands like `dump-state`).
///
/// Called once at the top of `main()`. Safe to call before any
/// subcommand parsing — the subscriber is global.
fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false);
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init();
}

/// CLI flag parser. Returns a config built by:
///
/// 1. Starting from defaults.
/// 2. Overlaying `--config FILE` if supplied (TOML).
/// 3. Applying every other flag on top.
fn parse_args(args: &[String]) -> Result<NodeConfig, String> {
    let mut config = NodeConfig::default();
    let mut i = 0;
    let mut config_file: Option<PathBuf> = None;
    // First pass: find --config so we can layer its contents before
    // applying the rest.
    while i < args.len() {
        if args[i] == "--config" {
            i += 1;
            config_file = Some(PathBuf::from(
                args.get(i).ok_or("--config needs a path")?,
            ));
        }
        i += 1;
    }
    if let Some(path) = &config_file {
        config = NodeConfig::from_file(path).map_err(|e| e.to_string())?;
    } else {
        // No explicit --config: auto-load ./config.toml from the working
        // directory if it exists (the common operator expectation — otherwise
        // a present config silently does nothing and every setting falls back
        // to its default). Logged so it's never a surprise; pass --config to
        // point elsewhere. Later CLI flags (--data-dir, --peer, …) still
        // override whatever the file sets.
        let default_path = PathBuf::from("config.toml");
        if default_path.is_file() {
            config = NodeConfig::from_file(&default_path).map_err(|e| e.to_string())?;
            eprintln!(
                "tron-node: loaded ./config.toml (no --config given); pass --config to override"
            );
        }
    }

    // Second pass: apply every flag.
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1; // already consumed
            }
            "--data-dir" => {
                i += 1;
                config.data_dir =
                    PathBuf::from(args.get(i).ok_or("--data-dir needs a path")?);
            }
            "--rpc-port" => {
                i += 1;
                config.rpc.port = args
                    .get(i)
                    .ok_or("--rpc-port needs N")?
                    .parse()
                    .map_err(|e| format!("rpc-port: {e}"))?;
            }
            "--rpc-host" => {
                i += 1;
                config.rpc.host = args.get(i).ok_or("--rpc-host needs HOST")?.clone();
            }
            "--chain-id" => {
                i += 1;
                config.rpc.chain_id = args
                    .get(i)
                    .ok_or("--chain-id needs N")?
                    .parse()
                    .map_err(|e| format!("chain-id: {e}"))?;
            }
            "--peer" => {
                i += 1;
                config
                    .p2p
                    .peers
                    .push(args.get(i).ok_or("--peer needs HOST:PORT")?.clone());
            }
            "--max-blocks" => {
                i += 1;
                config.p2p.max_blocks = Some(
                    args.get(i)
                        .ok_or("--max-blocks needs N")?
                        .parse()
                        .map_err(|e| format!("max-blocks: {e}"))?,
                );
            }
            "--progress-log-interval" => {
                i += 1;
                config.p2p.progress_log_interval = args
                    .get(i)
                    .ok_or("--progress-log-interval needs N")?
                    .parse()
                    .map_err(|e| format!("progress-log-interval: {e}"))?;
            }
            "--no-rpc" => {
                config.rpc.disabled = true;
            }
            "--no-sync" => {
                config.p2p.disabled = true;
            }
            "--mainnet-seeds" => {
                config.p2p.use_mainnet_seeds = true;
            }
            "--metrics-port" => {
                i += 1;
                config.metrics.port = args
                    .get(i)
                    .ok_or("--metrics-port needs N")?
                    .parse()
                    .map_err(|e| format!("metrics-port: {e}"))?;
            }
            "--metrics-host" => {
                i += 1;
                config.metrics.host = args
                    .get(i)
                    .ok_or("--metrics-host needs HOST")?
                    .clone();
            }
            "--no-metrics" => {
                config.metrics.disabled = true;
            }
            "--tip-test" => {
                i += 1;
                let arg = args
                    .get(i)
                    .ok_or("--tip-test needs BLOCK_NUM:HEX_HASH")?;
                let (num_str, hash_str) = arg.split_once(':').ok_or_else(|| {
                    format!("--tip-test BLOCK_NUM:HEX_HASH (no `:` in {arg})")
                })?;
                let block_num: i64 = num_str
                    .parse()
                    .map_err(|e| format!("--tip-test block num: {e}"))?;
                if hash_str.len() != 64 {
                    return Err(format!(
                        "--tip-test hash must be 64 hex chars (got {})",
                        hash_str.len()
                    ));
                }
                hex::decode(hash_str)
                    .map_err(|e| format!("--tip-test hex hash: {e}"))?;
                config.p2p.tip_test = Some(tron_node::config::TipTestCheckpoint {
                    block_num,
                    block_id_hex: hash_str.to_string(),
                });
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    Ok(config)
}
