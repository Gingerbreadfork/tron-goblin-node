//! Read-only consensus / TRC-10 state diagnostics for divergence hunting.
//!
//! Opens a node's data dir READ-ONLY (RocksDB read-only mode), so it runs
//! alongside a live or stalled node, and works on a java-tron data dir too
//! (same protobuf messages + store directory names). Three modes:
//!
//! ```text
//!   vote_audit <data_dir>                   # witness vote-count invariant report
//!   vote_audit <data_dir> --account <hex>   # one account's vote/stake/asset state
//!   vote_audit <data_dir> --voters <hex>    # every account voting for a witness
//! ```
//!
//! The invariant: every witness's stored `vote_count` equals the sum of all
//! accounts' standing votes for it (a genesis SR differs only by the one-time
//! GR-power removal). A mismatch on a non-genesis witness means the maintenance
//! tally drifted from the account store. `--voters` output is sorted, so two
//! runs (e.g. ours vs a java-tron data dir) can be `diff`ed to pinpoint the
//! divergent voter. `<hex>` is a 21-byte address (`41…`).
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use tron_chainbase::{KvBackend, RocksDbBackend, WitnessStore};

fn open_ro(db_root: &std::path::Path, name: &str) -> Arc<dyn KvBackend> {
    Arc::new(RocksDbBackend::open_read_only(db_root.join(name)).unwrap_or_else(|e| {
        panic!("open {name} read-only: {e}");
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(data_dir) = args.get(1) else {
        eprintln!("usage: vote_audit <data_dir> [--account <hex> | --voters <witness-hex>]");
        std::process::exit(2);
    };
    let db_root = std::path::Path::new(data_dir).join("database");
    eprintln!("auditing {}", db_root.display());
    let mode = args.get(2).map(String::as_str);

    // --account <hex>: dump one account's vote / stake / TRC-10 state.
    if mode == Some("--account") {
        let target = hex::decode(args.get(3).expect("--account <hex>")).expect("bad hex");
        let acc = open_ro(&db_root, "account");
        match acc.get(&target).unwrap() {
            Some(v) => {
                let a = tron_proto::Account::decode(v.as_slice()).unwrap();
                let frozen_v1: i64 = a.frozen.iter().map(|f| f.frozen_balance).sum();
                let energy_v1 = a
                    .account_resource
                    .as_ref()
                    .and_then(|r| r.frozen_balance_for_energy.as_ref())
                    .map(|f| f.frozen_balance)
                    .unwrap_or(0);
                let v2: i64 = a.frozen_v2.iter().map(|f| f.amount).sum();
                let deleg_bw = a.delegated_frozen_balance_for_bandwidth;
                println!("account {}", hex::encode(&target));
                println!("  balance={}", a.balance);
                println!(
                    "  frozen entries: {:?}",
                    a.frozen.iter().map(|f| (f.frozen_balance, f.expire_time)).collect::<Vec<_>>()
                );
                println!("  frozen_v1(bw)={frozen_v1} energy_v1={energy_v1} deleg_bw={deleg_bw} v2={v2}");
                println!("  Σ tron_power = {}", frozen_v1 + energy_v1 + deleg_bw + v2);
                println!(
                    "  votes: {:?}",
                    a.votes.iter().map(|v| (hex::encode(&v.vote_address), v.vote_count)).collect::<Vec<_>>()
                );
                println!("  asset(v1): {:?}", a.asset);
                println!("  asset_v2:  {:?}", a.asset_v2);
            }
            None => println!("account {} NOT FOUND", hex::encode(&target)),
        }
        return;
    }

    let voters_target: Option<Vec<u8>> = if mode == Some("--voters") {
        Some(hex::decode(args.get(3).expect("--voters <witness-hex>")).expect("bad hex"))
    } else {
        None
    };

    // Scan every account → Σ standing votes per witness (+ the per-voter list
    // for the requested witness under --voters).
    let acc = open_ro(&db_root, "account");
    let mut sums: HashMap<Vec<u8>, i128> = HashMap::new();
    let mut voters: Vec<(String, i64)> = Vec::new();
    let mut start: Vec<u8> = Vec::new();
    let (mut n, mut voting): (u64, u64) = (0, 0);
    loop {
        let batch = acc.scan_from(&start, 4096).unwrap();
        if batch.is_empty() {
            break;
        }
        for (k, v) in &batch {
            if let Ok(acct) = tron_proto::Account::decode(v.as_slice()) {
                if !acct.votes.is_empty() {
                    voting += 1;
                }
                for vote in &acct.votes {
                    *sums.entry(vote.vote_address.clone()).or_insert(0) += vote.vote_count as i128;
                    if Some(&vote.vote_address) == voters_target.as_ref() {
                        voters.push((hex::encode(k), vote.vote_count));
                    }
                }
            }
            n += 1;
        }
        start = batch.last().unwrap().0.clone();
        start.push(0); // strictly greater than the last key
        if n % 1_000_000 == 0 {
            eprintln!("  scanned {n} accounts...");
        }
    }
    eprintln!(
        "scanned {n} accounts; {voting} with standing votes; {} witnesses voted-for",
        sums.len()
    );

    if let Some(w) = voters_target {
        voters.sort();
        eprintln!("{} voters for {}", voters.len(), hex::encode(&w));
        for (addr, c) in &voters {
            println!("{addr} {c}");
        }
        return;
    }

    // Default: invariant report — stored vote_count vs Σ standing, per witness.
    let wit = WitnessStore::new(open_ro(&db_root, "witness"));
    let witnesses = wit.all().expect("witness scan");
    let mut mism: Vec<(Vec<u8>, i64, i128)> = Vec::new();
    for (addr, w) in &witnesses {
        let sum = *sums.get(&addr.as_bytes().to_vec()).unwrap_or(&0);
        if w.vote_count as i128 != sum {
            mism.push((addr.as_bytes().to_vec(), w.vote_count, sum));
        }
    }
    println!(
        "witnesses where stored vote_count != Σ standing votes: {} of {} (genesis SRs differ by the removed GR power)",
        mism.len(),
        witnesses.len()
    );
    mism.sort_by_key(|x| std::cmp::Reverse((x.1 as i128 - x.2).abs()));
    for (addr, stored, sum) in mism.iter().take(50) {
        println!("  {} stored={stored} Σstanding={sum} diff={}", hex::encode(addr), *stored as i128 - sum);
    }
}
