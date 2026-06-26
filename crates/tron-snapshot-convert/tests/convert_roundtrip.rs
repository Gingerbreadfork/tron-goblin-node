//! End-to-end tests: synthesize a small multi-store java-tron-style
//! LevelDB snapshot, convert it, and verify the result opens as our
//! RocksDB with byte-identical key/value pairs (round-trip). Plus a resume
//! test (a marked store is skipped + its source not re-read) and a
//! `--stream` (tar from a reader) test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusty_leveldb::{Cmp, DefaultCmp, Options, DB};
use tron_chainbase::{KvBackend, RocksDbBackend};
use tron_snapshot_convert::convert::{convert_from_directory, convert_from_stream, ConvertOptions};

fn tmp(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("snapconv-it-{label}-{n}-{}", std::process::id()));
    p
}

/// A comparator reporting java's market name but ordering bytewise — only
/// the NAME matters for writing the test fixture's MANIFEST.
struct NamedBytewise(&'static str);
impl Cmp for NamedBytewise {
    fn cmp(&self, a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        a.cmp(b)
    }
    fn id(&self) -> &'static str {
        self.0
    }
    fn find_shortest_sep(&self, a: &[u8], _b: &[u8]) -> Vec<u8> {
        a.to_vec()
    }
    fn find_short_succ(&self, k: &[u8]) -> Vec<u8> {
        let mut v = k.to_vec();
        v.push(0);
        v
    }
}

/// Write a LevelDB store at `dir` with the given rows. If `cmp_name` is set,
/// the store records that custom comparator name in its MANIFEST (mimicking
/// java-tron's `market_pair_price_to_order`). A small write buffer forces
/// real SSTs so we exercise the on-disk table reader, not just the WAL.
fn write_leveldb_store(dir: &Path, rows: &BTreeMap<Vec<u8>, Vec<u8>>, cmp_name: Option<&'static str>) {
    let mut opt = Options::default();
    opt.create_if_missing = true;
    opt.write_buffer_size = 4 * 1024;
    opt.reuse_logs = false;
    opt.reuse_manifest = false;
    if let Some(name) = cmp_name {
        opt.cmp = Rc::new(Box::new(NamedBytewise(name)));
    } else {
        opt.cmp = Rc::new(Box::new(DefaultCmp));
    }
    let mut db = DB::open(dir, opt).unwrap();
    for (k, v) in rows {
        db.put(k, v).unwrap();
    }
    db.flush().unwrap();
    db.close().unwrap();
}

/// Build a snapshot dir with three stores and return (snapshot_dir, the
/// rows we wrote per store) for later comparison.
fn build_snapshot(label: &str) -> (PathBuf, BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>) {
    let snap = tmp(label);
    std::fs::create_dir_all(&snap).unwrap();
    let mut all: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();

    // account: 1500 rows (multi-SST), default comparator.
    let mut account = BTreeMap::new();
    for i in 0u32..1500 {
        let mut k = vec![0x41u8];
        k.extend_from_slice(&i.to_be_bytes());
        let v = format!("account-capsule-bytes-{i}").into_bytes();
        account.insert(k, v);
    }
    write_leveldb_store(&snap.join("account"), &account, None);
    all.insert("account".to_string(), account);

    // properties: a handful of rows including binary keys/values.
    let mut props = BTreeMap::new();
    props.insert(b"LATEST_BLOCK_HEADER_NUMBER".to_vec(), 12345i64.to_be_bytes().to_vec());
    props.insert(b"TOTAL_NET_WEIGHT".to_vec(), vec![0xde, 0xad, 0xbe, 0xef]);
    props.insert(vec![0x00, 0xff, 0x7f], vec![1, 2, 3, 4, 5]);
    write_leveldb_store(&snap.join("properties"), &props, None);
    all.insert("properties".to_string(), props);

    // market_pair_price_to_order: custom comparator NAME in the MANIFEST.
    let mut market = BTreeMap::new();
    for i in 0u32..300 {
        let mut k = vec![0u8; 54];
        k[..4].copy_from_slice(&i.to_be_bytes());
        market.insert(k, format!("order-{i}").into_bytes());
    }
    write_leveldb_store(
        &snap.join("market_pair_price_to_order"),
        &market,
        Some("MarketOrderPriceComparator"),
    );
    all.insert("market_pair_price_to_order".to_string(), market);

    (snap, all)
}

/// Assert the converted RocksDB store at `data_dir/database/<store>` holds
/// exactly `expected`, byte-for-byte.
fn assert_store_matches(data_dir: &Path, store: &str, expected: &BTreeMap<Vec<u8>, Vec<u8>>) {
    let path = data_dir.join("database").join(store);
    // Open with the right comparator for the market store.
    let db = match tron_chainbase::comparator_for_store(store) {
        Some((name, f)) => RocksDbBackend::open_with_comparator(&path, None, name, f).unwrap(),
        None => RocksDbBackend::open(&path).unwrap(),
    };
    // Every expected row present + equal.
    for (k, v) in expected {
        let got = db.get(k).unwrap();
        assert_eq!(got.as_deref(), Some(v.as_slice()), "store {store} key {k:02x?}");
    }
    // No extra rows.
    let all = db.scan_all().unwrap();
    assert_eq!(all.len(), expected.len(), "store {store} row count");
}

#[test]
fn directory_convert_round_trips_byte_identical_and_deletes_source() {
    let (snap, rows) = build_snapshot("dir");
    let data_dir = tmp("dir-dest");
    let opts = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: true, // exercise the Zstd write path (crate links zstd)
        keep_source: false,
    };
    let mut progress = |_l: &str| {};
    let report = convert_from_directory(&snap, &opts, &mut progress).expect("convert");

    assert_eq!(report.converted_count(), 3, "should convert all 3 stores");
    assert_eq!(report.skipped_count(), 0);

    for (store, expected) in &rows {
        assert_store_matches(&data_dir, store, expected);
    }

    // Source stores were deleted (peak-disk goal); only possibly-empty
    // snapshot dir remains.
    for store in rows.keys() {
        assert!(
            !snap.join(store).exists(),
            "source store {store} should have been deleted"
        );
    }

    let _ = std::fs::remove_dir_all(&snap);
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn keep_source_preserves_originals() {
    let (snap, rows) = build_snapshot("keep");
    let data_dir = tmp("keep-dest");
    let opts = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: false, // Snappy path
        keep_source: true,
    };
    let mut progress = |_l: &str| {};
    convert_from_directory(&snap, &opts, &mut progress).expect("convert");
    for store in rows.keys() {
        assert!(snap.join(store).exists(), "--keep-source kept {store}");
    }
    // And the conversion is still correct.
    for (store, expected) in &rows {
        assert_store_matches(&data_dir, store, expected);
    }
    let _ = std::fs::remove_dir_all(&snap);
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn resume_skips_already_done_stores() {
    let (snap, rows) = build_snapshot("resume");
    let data_dir = tmp("resume-dest");

    // First pass with --keep-source so we can run a second pass over the
    // same source and observe the skip.
    let opts_keep = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: false,
        keep_source: true,
    };
    let mut progress = |_l: &str| {};
    let first = convert_from_directory(&snap, &opts_keep, &mut progress).expect("first");
    assert_eq!(first.converted_count(), 3);

    // Simulate a crash AFTER `account` was converted (its destination is
    // marked done) but with its SOURCE already gone — e.g. a run that
    // deleted `account`'s source then died. On resume the two remaining
    // sources (`properties`, `market_pair_price_to_order`) are visited and
    // SKIPPED via their done-markers (idempotent), and `account` — absent
    // from the source enumeration — is simply not re-touched, yet its
    // destination is intact.
    std::fs::remove_dir_all(snap.join("account")).unwrap();

    let second = convert_from_directory(&snap, &opts_keep, &mut progress).expect("resume");
    assert_eq!(
        second.skipped_count(),
        2,
        "the two remaining marked sources should be skipped on resume"
    );
    assert_eq!(second.converted_count(), 0, "nothing should be re-converted");

    // The destination is still complete + byte-identical despite the
    // source `account` being gone before the resume (its done-marker +
    // already-converted dest protect it).
    for (store, expected) in &rows {
        assert_store_matches(&data_dir, store, expected);
    }

    let _ = std::fs::remove_dir_all(&snap);
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn mid_run_interrupt_skips_only_the_done_store() {
    // Simulate an interrupt: one store (`properties`) finished and was
    // marked done in a prior run; the other two never started. On the next
    // run only the marked store is skipped; the rest convert. All sources
    // are present (so this is the canonical "restart skips done stores").
    let (snap, rows) = build_snapshot("midrun");
    let data_dir = tmp("midrun-dest");

    // Pre-convert ONLY `properties` (writes its dest + done-marker), leaving
    // its source in place. Use a one-store source dir so only it is done.
    {
        let only_props = tmp("midrun-props-only");
        std::fs::create_dir_all(only_props.join("properties")).unwrap();
        // Re-create just the properties LevelDB into the staging source.
        // Easiest: copy the rows directly via a fresh LevelDB write.
        write_leveldb_store(
            &only_props.join("properties"),
            rows.get("properties").unwrap(),
            None,
        );
        let opts = ConvertOptions {
            data_dir: data_dir.clone(),
            compression_zstd: true,
            keep_source: true,
        };
        let mut p = |_l: &str| {};
        let r = convert_from_directory(&only_props, &opts, &mut p).unwrap();
        assert_eq!(r.converted_count(), 1);
        let _ = std::fs::remove_dir_all(&only_props);
    }

    // Now run the full snapshot: properties is already done → skipped;
    // account + market convert.
    let opts = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: true,
        keep_source: false,
    };
    let mut p = |_l: &str| {};
    let report = convert_from_directory(&snap, &opts, &mut p).unwrap();
    assert_eq!(report.skipped_count(), 1, "only `properties` was done");
    assert_eq!(report.converted_count(), 2, "account + market convert");
    // With keep_source=false, ALL sources are reclaimed — the already-done
    // `properties` source too (its dest is durable, so the leftover source
    // is safe to drop, keeping a resumed run idempotent and space-tight).
    assert!(!snap.join("properties").exists(), "done store's leftover source reclaimed");
    assert!(!snap.join("account").exists());
    assert!(!snap.join("market_pair_price_to_order").exists());

    for (store, expected) in &rows {
        assert_store_matches(&data_dir, store, expected);
    }
    let _ = std::fs::remove_dir_all(&snap);
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn partial_destination_without_marker_is_reconverted() {
    let (snap, rows) = build_snapshot("partial");
    let data_dir = tmp("partial-dest");

    // Plant a corrupt/partial destination for `account` with NO done
    // marker — a crashed mid-write. The converter must wipe + redo it.
    let dest_account = data_dir.join("database").join("account");
    std::fs::create_dir_all(&dest_account).unwrap();
    {
        let db = RocksDbBackend::open(&dest_account).unwrap();
        db.put(b"stale-leftover-key", b"garbage").unwrap();
        db.put(b"\x41\x00\x00\x00\x00", b"WRONG-VALUE").unwrap();
    }

    let opts = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: true,
        keep_source: false,
    };
    let mut progress = |_l: &str| {};
    convert_from_directory(&snap, &opts, &mut progress).expect("convert");

    // The stale row is gone and every real row is present + correct.
    for (store, expected) in &rows {
        assert_store_matches(&data_dir, store, expected);
    }

    let _ = std::fs::remove_dir_all(&snap);
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn stream_convert_round_trips_from_tar() {
    let (snap, rows) = build_snapshot("stream");
    // Tar the snapshot to an in-memory buffer (plain tar).
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        // append_dir_all preserves the per-store dir structure under a
        // top-level prefix; use "" so entries are account/CURRENT etc.
        for store in rows.keys() {
            builder
                .append_dir_all(store, snap.join(store))
                .unwrap();
        }
        builder.finish().unwrap();
    }
    // Source snapshot dir can go now — the tar is the input.
    let _ = std::fs::remove_dir_all(&snap);

    let data_dir = tmp("stream-dest");
    let opts = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: true,
        keep_source: false,
    };
    let mut progress = |_l: &str| {};
    let report = convert_from_stream(std::io::Cursor::new(buf), false, &opts, &mut progress)
        .expect("stream convert");
    assert_eq!(report.converted_count(), 3, "all stores from the stream");

    for (store, expected) in &rows {
        assert_store_matches(&data_dir, store, expected);
    }
    // The staging area was cleaned up.
    assert!(!data_dir.join(".snapshot-convert-stage").exists());

    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn stream_convert_handles_database_wrapper_dir() {
    let (snap, rows) = build_snapshot("stream-wrap");
    // Tar with a wrapping `database/` dir: database/account/..., etc.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        for store in rows.keys() {
            builder
                .append_dir_all(format!("database/{store}"), snap.join(store))
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let _ = std::fs::remove_dir_all(&snap);

    let data_dir = tmp("stream-wrap-dest");
    let opts = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: false,
        keep_source: false,
    };
    let mut progress = |_l: &str| {};
    let report = convert_from_stream(std::io::Cursor::new(buf), false, &opts, &mut progress)
        .expect("wrapped stream convert");
    assert_eq!(report.converted_count(), 3, "wrapper dir stripped, all stores converted");

    for (store, expected) in &rows {
        assert_store_matches(&data_dir, store, expected);
    }
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn stream_rejects_non_contiguous_tar() {
    // account (complete) -> market (complete, which flushes account) ->
    // account AGAIN. A real `tar c account/ market/ ...` is contiguous and
    // never does this; the converter must REFUSE the re-appearance rather
    // than silently drop it (the re-appearing store would hit its done-marker
    // and its data would vanish). Regression guard for review finding M2.
    let (snap, _rows) = build_snapshot("noncontig");
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        builder.append_dir_all("account", snap.join("account")).unwrap();
        builder
            .append_dir_all("market_pair_price_to_order", snap.join("market_pair_price_to_order"))
            .unwrap();
        // The non-contiguous re-appearance.
        builder.append_dir_all("account", snap.join("account")).unwrap();
        builder.finish().unwrap();
    }
    let _ = std::fs::remove_dir_all(&snap);

    let data_dir = tmp("noncontig-dest");
    let opts = ConvertOptions {
        data_dir: data_dir.clone(),
        compression_zstd: false,
        keep_source: false,
    };
    let mut progress = |_l: &str| {};
    let err = convert_from_stream(std::io::Cursor::new(buf), false, &opts, &mut progress)
        .expect_err("a non-contiguous tar must be rejected, not silently truncated");
    let msg = format!("{err}");
    assert!(
        msg.contains("non-contiguous") && msg.contains("account"),
        "expected a non-contiguous error for `account`, got: {msg}"
    );
    let _ = std::fs::remove_dir_all(&data_dir);
}
