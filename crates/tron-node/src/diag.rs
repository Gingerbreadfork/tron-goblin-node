//! `tron-node diag <subcommand>` — read-only state inspection for java-tron
//! parity work.
//!
//! Opens a data-dir's stores **read-only** and prints decoded state, so our
//! node's view of an account / delegation / dynamic-property can be diffed
//! directly against java-tron's RPC (`getaccount`, `getdelegatedresourcev2`,
//! `getdelegatedresourceaccountindexv2`). Built for the recurring task of
//! pinning a consensus divergence to a specific store row.
//!
//! Subcommands:
//! ```text
//!   diag account     <hex-addr>              full Account: balance, frozen_v2,
//!                                             energy/net usage+window, and BOTH
//!                                             sides of delegation (acquired_* it
//!                                             RECEIVED, delegated_* it SENT)
//!   diag delegation  <hex-from> <hex-to>     the (from→to) DelegatedResource —
//!                                             BOTH the unlocked (key 0x01) and
//!                                             locked (key 0x02) records, since
//!                                             java's VM undelegate only ever
//!                                             reads the unlocked one
//!   diag dynprop     <key-string>            a DynamicProperties value (i64 + hex)
//! ```
//! Flags: `--data-dir <DIR>` (default `./tron-data`). Addresses are 21-byte
//! mainnet hex (42 chars, `41…`), with or without a leading `0x`.
//!
//! Read-only: the stores are opened without taking the primary RocksDB lock, so
//! this is safe to run against a data-dir while the node is **stopped** without
//! mutating it (no compaction / LOG churn). It will refuse to run against a
//! data-dir held by a live node.

use std::process::ExitCode;
use std::sync::Arc;

use tron_chainbase::{
    AccountStore, DelegatedResourceStore, DynamicPropertiesStore, KvBackend, RocksDbBackend,
};
use tron_crypto::address::{Address, ADDRESS_LENGTH};

const DEFAULT_DATA_DIR: &str = "./tron-data";

/// Open one java-tron store directory (`<data_dir>/database/<name>`) read-only.
/// No primary lock is taken, so this is safe alongside a STOPPED node and never
/// mutates the data-dir (no compaction / LOG churn / schema stamp).
fn open_ro(data_dir: &str, name: &str) -> Result<Arc<dyn KvBackend>, String> {
    let path = std::path::Path::new(data_dir).join("database").join(name);
    let be = RocksDbBackend::open_read_only(&path)
        .map_err(|e| format!("open {} read-only: {e}", path.display()))?;
    Ok(Arc::new(be) as Arc<dyn KvBackend>)
}

pub fn run_diag(args: &[String]) -> ExitCode {
    let Some(sub) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    // Common flag parse: pull `--data-dir DIR` out, leave positionals.
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut pos: Vec<&str> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" | "-d" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("diag: --data-dir needs a value");
                    return ExitCode::from(2);
                };
                data_dir = v.clone();
                i += 2;
            }
            other => {
                pos.push(other);
                i += 1;
            }
        }
    }

    let r = match sub.as_str() {
        "account" => match pos.first().map(|s| parse_addr(s)) {
            Some(Ok(addr)) => diag_account(&data_dir, &addr),
            _ => return arg_err("account <hex-addr>"),
        },
        "delegation" => match (pos.first(), pos.get(1)) {
            (Some(f), Some(t)) => match (parse_addr(f), parse_addr(t)) {
                (Ok(from), Ok(to)) => diag_delegation(&data_dir, &from, &to),
                _ => return arg_err("delegation <hex-from> <hex-to>"),
            },
            _ => return arg_err("delegation <hex-from> <hex-to>"),
        },
        "dynprop" => match pos.first() {
            Some(k) => diag_dynprop(&data_dir, k),
            None => return arg_err("dynprop <key-string>"),
        },
        "--help" | "-h" | "help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("diag: unknown subcommand '{other}'");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("diag: {e}");
            eprintln!("diag: (is a node holding the data-dir lock? stop it first)");
            ExitCode::FAILURE
        }
    }
}

fn diag_account(data_dir: &str, addr: &Address) -> Result<(), String> {
    let accounts = AccountStore::new(open_ro(data_dir, "account")?);
    let account = match accounts.get(addr).map_err(|e| format!("read account: {e}"))? {
        Some(a) => a,
        None => {
            println!("account {}: ABSENT", hex_addr(addr));
            return Ok(());
        }
    };
    let r = account.account_resource.clone().unwrap_or_default();
    println!("account {}", hex_addr(addr));
    println!("  type            {}", account.r#type);
    println!("  balance         {}", account.balance);
    println!("  frozen_v2       {:?}", account.frozen_v2.iter().map(|f| (f.r#type, f.amount)).collect::<Vec<_>>());
    println!("  --- ENERGY ---");
    println!("  energy_usage             {}", r.energy_usage);
    println!("  energy_window_size       {}", r.energy_window_size);
    println!("  latest_consume_time_e    {}", r.latest_consume_time_for_energy);
    println!("  acquired_v2_energy(RECV) {}", r.acquired_delegated_frozen_v2_balance_for_energy);
    println!("  delegated_v2_energy(SENT){}", r.delegated_frozen_v2_balance_for_energy);
    println!("  acquired_v1_energy(RECV) {}", r.acquired_delegated_frozen_balance_for_energy);
    println!("  delegated_v1_energy(SENT){}", r.delegated_frozen_balance_for_energy);
    println!("  --- BANDWIDTH ---");
    println!("  net_usage                {}", account.net_usage);
    println!("  net_window_size          {}", account.net_window_size);
    println!("  latest_consume_time      {}", account.latest_consume_time);
    println!("  acquired_v2_bw(RECV)     {}", account.acquired_delegated_frozen_v2_balance_for_bandwidth);
    println!("  delegated_v2_bw(SENT)    {}", account.delegated_frozen_v2_balance_for_bandwidth);
    Ok(())
}

fn diag_delegation(data_dir: &str, from: &Address, to: &Address) -> Result<(), String> {
    let store = DelegatedResourceStore::new(open_ro(data_dir, "DelegatedResource")?);
    println!("delegation {} -> {}", hex_addr(from), hex_addr(to));
    for (label, key) in [
        ("unlocked(0x01)", DelegatedResourceStore::v2_unlocked_key(from, to)),
        ("locked(0x02)  ", DelegatedResourceStore::v2_locked_key(from, to)),
    ] {
        match store.get_raw(&key).map_err(|e| format!("read delegation: {e}"))? {
            Some(d) => println!(
                "  {label}: energy={} bw={} expire_e={} expire_bw={}",
                d.frozen_balance_for_energy,
                d.frozen_balance_for_bandwidth,
                d.expire_time_for_energy,
                d.expire_time_for_bandwidth,
            ),
            None => println!("  {label}: ABSENT"),
        }
    }
    Ok(())
}

fn diag_dynprop(data_dir: &str, key: &str) -> Result<(), String> {
    let dp = DynamicPropertiesStore::new(open_ro(data_dir, "properties")?);
    match dp.get_long(key.as_bytes()) {
        Some(v) => println!("dynprop {key} = {v} (0x{v:x})"),
        None => println!("dynprop {key}: ABSENT"),
    }
    Ok(())
}

fn arg_err(usage: &str) -> ExitCode {
    eprintln!("diag: usage: tron-node diag {usage} [--data-dir DIR]");
    ExitCode::from(2)
}

/// Parse a 21-byte mainnet hex address (`41…`), optional `0x` prefix.
fn parse_addr(s: &str) -> Result<Address, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("bad hex '{s}': {e}"))?;
    if bytes.len() != ADDRESS_LENGTH {
        return Err(format!(
            "address must be {ADDRESS_LENGTH} bytes ({} hex chars), got {}",
            ADDRESS_LENGTH * 2,
            bytes.len()
        ));
    }
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf.copy_from_slice(&bytes);
    Ok(Address::from_raw(buf))
}

fn hex_addr(a: &Address) -> String {
    hex::encode(a.as_bytes())
}

const USAGE: &str = "\
tron-node diag — read-only state inspection for java-tron parity diffing

USAGE:
  tron-node diag account     <hex-addr>             [--data-dir DIR]
  tron-node diag delegation  <hex-from> <hex-to>    [--data-dir DIR]
  tron-node diag dynprop     <key-string>           [--data-dir DIR]

Addresses are 21-byte mainnet hex (42 chars, '41…'), optional '0x' prefix.
Default --data-dir is ./tron-data. Open is read-only; run with the node stopped.
Diff the output against java-tron's getaccount / getdelegatedresourcev2.
";
