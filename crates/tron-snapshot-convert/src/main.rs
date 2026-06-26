//! `tron-snapshot-convert` — CLI front-end.
//!
//! Hand-rolled arg parsing in the same style as `tron-node` (a usage
//! string + a flag loop), no clap dependency.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use tron_snapshot_convert::convert::{
    convert_from_directory, convert_from_stream, ConvertOptions, ConvertReport,
};

const USAGE: &str = "\
tron-snapshot-convert — convert a java-tron LevelDB snapshot to this node's RocksDB format

usage:
  tron-snapshot-convert --from DIR     [--data-dir DIR] [--keep-source] [--resume] [--zstd]
  tron-snapshot-convert --stream [--gzip] [--data-dir DIR] [--zstd]

input (choose one):
  --from DIR        directory of per-store LevelDB sub-dirs (account/, block/,
                    trans/, transactionRetStore/, witness/, properties/,
                    block-index/, ...). Each store is converted into
                    data_dir/database/<store>, fsynced, then the SOURCE store is
                    deleted (unless --keep-source) so peak disk stays near 1x.
  --stream          read a tar of the snapshot from STDIN (add --gzip for a
                    .tar.gz/.tgz). Stores are staged one at a time to a temp dir
                    so the full source never lands on disk — pipe a download
                    straight in:  curl -s URL | tron-snapshot-convert --stream --gzip

options:
  --data-dir DIR    node data dir; stores are written under DIR/database/.
                    Default: ./tron-data
  --keep-source     do NOT delete each source store after converting it
                    (directory input only; doubles peak disk). Default: delete.
  --resume          explicit resume (already the default): stores whose
                    done-marker (engine.properties=ROCKSDB) is present are
                    skipped. A crashed run is safe to re-run as-is.
  --zstd            write destination SSTs with Zstd (~30% smaller) instead of
                    the default Snappy. WARNING: a Zstd-compressed snapshot is
                    NOT readable by the standard tron-node build (Snappy/LZ4
                    only) — and the source is deleted during conversion, so an
                    unreadable result is unrecoverable. Use --zstd only with a
                    tron-node built with Zstd support. Default: Snappy.
  -h, --help        show this help

notes:
  * The conversion is a byte-faithful key-by-key copy — a converted snapshot
    runs identically to the original (java-tron stores the same serialized
    bytes regardless of engine).
  * Each store is verified after writing (key count + byte fingerprint) before
    its source is removed.
  * The LevelDB store written with a custom comparator (market_pair_price_to_order)
    is handled automatically.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let mut from: Option<PathBuf> = None;
    let mut stream = false;
    let mut gzip = false;
    let mut opts = ConvertOptions::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--from" => {
                i += 1;
                from = Some(PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => return arg_err("--from needs DIR"),
                }));
            }
            "--stream" => stream = true,
            "--gzip" | "--gz" => gzip = true,
            "--data-dir" => {
                i += 1;
                opts.data_dir = PathBuf::from(match args.get(i) {
                    Some(s) => s,
                    None => return arg_err("--data-dir needs DIR"),
                });
            }
            "--keep-source" => opts.keep_source = true,
            // Resume is always on (done stores are skipped); accept the flag
            // for explicitness.
            "--resume" => {}
            "--zstd" => opts.compression_zstd = true,
            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown flag: {other}");
                eprint!("{USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    // Exactly one input mode.
    match (from.is_some(), stream) {
        (false, false) => return arg_err("one of --from DIR or --stream is required"),
        (true, true) => return arg_err("--from and --stream are mutually exclusive"),
        _ => {}
    }
    if gzip && !stream {
        return arg_err("--gzip only applies to --stream");
    }
    if opts.keep_source && stream {
        eprintln!("note: --keep-source is ignored with --stream (the source is never on disk)");
    }
    if opts.compression_zstd {
        eprintln!(
            "WARNING: --zstd output is NOT readable by the standard tron-node build \
             (Snappy/LZ4 only). The source is deleted during conversion, so a Zstd \
             snapshot the node cannot open would be unrecoverable — use --zstd only \
             with a tron-node built with Zstd support."
        );
    }

    let mut progress = |line: &str| println!("{line}");

    let started = std::time::Instant::now();
    let result = if stream {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return arg_err("--stream expects a tar on STDIN, but STDIN is a terminal");
        }
        println!(
            "converting from STDIN tar ({}) -> {}/database  [zstd={}]",
            if gzip { "gzip" } else { "plain" },
            opts.data_dir.display(),
            opts.compression_zstd
        );
        convert_from_stream(stdin.lock(), gzip, &opts, &mut progress)
    } else {
        let from = from.unwrap();
        println!(
            "converting {} -> {}/database  [zstd={}, keep_source={}]",
            from.display(),
            opts.data_dir.display(),
            opts.compression_zstd,
            opts.keep_source
        );
        convert_from_directory(&from, &opts, &mut progress)
    };

    match result {
        Ok(report) => {
            print_summary(&report, started.elapsed());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tron-snapshot-convert: conversion failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn arg_err(msg: &str) -> ExitCode {
    eprintln!("{msg}");
    eprint!("{USAGE}");
    ExitCode::from(2)
}

fn print_summary(report: &ConvertReport, elapsed: std::time::Duration) {
    let bytes = report.total_bytes();
    let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    println!();
    println!("conversion complete:");
    println!("  stores converted: {}", report.converted_count());
    if report.skipped_count() > 0 {
        println!("  stores skipped (already done): {}", report.skipped_count());
    }
    println!("  total keys:       {}", report.total_keys());
    println!("  total data:       {gib:.2} GiB ({bytes} bytes)");
    println!("  elapsed:          {:.1}s", elapsed.as_secs_f64());
}
