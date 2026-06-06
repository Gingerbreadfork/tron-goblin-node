//! `tron-state-diff` — compare RPC-level state between this node and a
//! reference java-tron node.
//!
//! TRON block headers carry no state root, so byte-identical block hashes do
//! **not** prove the resulting state matches. The only way to verify
//! state-exactness parity is to read the same accounts from both nodes and
//! diff the responses. This tool does that: it settles both nodes onto a
//! common head, queries a probe set (`getaccount`, `getaccountresource`, …)
//! for a list of addresses (supplied or auto-discovered from recent blocks),
//! and reports per-field divergences.
//!
//! Head handling: both nodes advance independently, so a probe taken while
//! the head moves can show a one-block-stale difference that isn't a real
//! divergence. We only trust a *mismatch* observed while both nodes held the
//! same head for the whole probing window; matches are always trustworthy.
//! Mismatches seen only under a moving head are retried, then reported as
//! "unstable / inconclusive" if they never settle.
//!
//! Usage:
//!   tron-state-diff --b http://<java-tron>:8090 \
//!       [--a http://127.0.0.1:8090] \
//!       [--accounts T...,T...] [--accounts-file addrs.txt] \
//!       [--from-recent-blocks N] \
//!       [--probes account,resource,contract] \
//!       [--settle-timeout-secs 30] [--max-rounds 3] [--http-timeout-secs 10] \
//!       [--json]

mod diff;
mod http;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::diff::Mismatch;

const USAGE: &str = "\
tron-state-diff — diff RPC state between this node (A) and a reference java-tron node (B)

REQUIRED:
  --b <url>                 reference node base URL (e.g. http://192.168.0.36:8090)

OPTIONS:
  --a <url>                 node-under-test base URL          [default http://127.0.0.1:8090]
  --accounts <a,b,c>        base58 addresses to probe (comma-separated)
  --accounts-file <path>    file of base58 addresses, one per line ('#' comments ok)
  --from-recent-blocks <N>  also probe every address touched in the last N blocks
  --probes <list>           any of: account,resource,contract  [default account,resource]
  --settle-timeout-secs <n> max wait for both nodes to share a head [default 30]
  --max-rounds <n>          re-check rounds for head-unstable mismatches [default 3]
  --http-timeout-secs <n>   per-request timeout                 [default 10]
  --json                    emit a machine-readable JSON report
  -h, --help                show this help
";

struct Args {
    a: String,
    b: String,
    accounts: Vec<String>,
    accounts_file: Option<String>,
    from_recent_blocks: u64,
    probes: Vec<Probe>,
    settle_timeout: Duration,
    max_rounds: u32,
    http_timeout: Duration,
    json: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Probe {
    Account,
    Resource,
    Contract,
}

impl Probe {
    fn parse(s: &str) -> Option<Probe> {
        match s.trim().to_ascii_lowercase().as_str() {
            "account" | "getaccount" => Some(Probe::Account),
            "resource" | "getaccountresource" => Some(Probe::Resource),
            "contract" | "getcontract" => Some(Probe::Contract),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Probe::Account => "account",
            Probe::Resource => "resource",
            Probe::Contract => "contract",
        }
    }
    fn path(self) -> &'static str {
        match self {
            Probe::Account => "/wallet/getaccount",
            Probe::Resource => "/wallet/getaccountresource",
            Probe::Contract => "/wallet/getcontract",
        }
    }
    fn body(self, address: &str) -> String {
        match self {
            // getcontract takes `value`; the account endpoints take `address`.
            Probe::Contract => format!("{{\"value\":\"{address}\",\"visible\":true}}"),
            _ => format!("{{\"address\":\"{address}\",\"visible\":true}}"),
        }
    }
}

fn main() {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => {
            print!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    std::process::exit(run(args));
}

fn run(args: Args) -> i32 {
    // 1. Assemble the address set.
    let mut addrs: BTreeSet<String> = BTreeSet::new();
    for a in &args.accounts {
        if !a.is_empty() {
            addrs.insert(a.clone());
        }
    }
    if let Some(path) = &args.accounts_file {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                for line in text.lines() {
                    let a = line.split('#').next().unwrap_or("").trim();
                    if !a.is_empty() {
                        addrs.insert(a.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("error: reading {path}: {e}");
                return 2;
            }
        }
    }

    // 2. Initial settle so auto-discovery + probing run against one head.
    let deadline = Instant::now() + args.settle_timeout;
    let (head_num, head_id) = match settle(&args, deadline) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: nodes did not converge on a common head: {e}");
            return 2;
        }
    };
    if !args.json {
        eprintln!("settled at common head {head_num} ({})", short(&head_id));
    }

    // 3. Auto-discover addresses from recent blocks.
    if args.from_recent_blocks > 0 {
        let start = (head_num - args.from_recent_blocks as i64 + 1).max(0);
        for num in start..=head_num {
            match get_block_by_num(&args.a, num, args.http_timeout) {
                Ok(block) => collect_addresses(&block, &mut addrs),
                Err(e) => eprintln!("warn: getblockbynum {num} on A failed: {e}"),
            }
        }
    }

    if addrs.is_empty() {
        eprintln!("error: no addresses to probe (use --accounts, --accounts-file, or --from-recent-blocks)");
        return 2;
    }

    // 4. Probe with head-stability rounds.
    let work: Vec<(String, Probe)> = addrs
        .iter()
        .flat_map(|a| args.probes.iter().map(move |p| (a.clone(), *p)))
        .collect();

    let mut matched: Vec<(String, Probe)> = Vec::new();
    let mut confirmed: Vec<(String, Probe, Vec<Mismatch>)> = Vec::new();
    let mut errors: Vec<(String, Probe, String)> = Vec::new();
    // Items whose mismatch was seen only under a moving head — retried.
    let mut pending: Vec<(String, Probe, Vec<Mismatch>)> = Vec::new();

    let mut queue = work;
    for round in 0..args.max_rounds.max(1) {
        if queue.is_empty() {
            break;
        }
        // Settle before each round.
        let (h_num, h_id) = match settle(&args, Instant::now() + args.settle_timeout) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("error: lost common head before round {}: {e}", round + 1);
                // Whatever is still queued becomes inconclusive.
                pending = queue.into_iter().map(|(a, p)| (a, p, Vec::new())).collect();
                queue = Vec::new();
                break;
            }
        };

        let mut next: Vec<(String, Probe)> = Vec::new();
        let mut round_mismatches: Vec<(String, Probe, Vec<Mismatch>)> = Vec::new();
        for (addr, probe) in &queue {
            match probe_pair(&args, *probe, addr) {
                Ok(ms) if ms.is_empty() => matched.push((addr.clone(), *probe)),
                Ok(ms) => round_mismatches.push((addr.clone(), *probe, ms)),
                Err(e) => errors.push((addr.clone(), *probe, e)),
            }
        }

        // Was the head stable across this whole round?
        let (h_num2, h_id2) = get_now_block(&args.a, args.http_timeout)
            .and_then(|(n, _)| get_now_block(&args.b, args.http_timeout).map(|(_, i)| (n, i)))
            .unwrap_or((-1, String::new()));
        let stable = h_id2 == h_id && h_num2 == h_num;

        if stable {
            // Every mismatch this round is real.
            for m in round_mismatches {
                confirmed.push(m);
            }
        } else {
            // Mismatches may be one-block-stale artifacts — retry them.
            for (a, p, ms) in round_mismatches {
                next.push((a.clone(), p));
                pending.retain(|(pa, pp, _)| !(pa == &a && *pp == p));
                pending.push((a, p, ms));
            }
            if !args.json {
                eprintln!(
                    "round {}: head moved during probing; retrying {} unsettled mismatch(es)",
                    round + 1,
                    next.len()
                );
            }
        }
        queue = next;
    }
    // Anything still pending (never observed under a stable head) stays
    // inconclusive — surface it with its last-seen diff.
    for (a, p) in queue {
        if !pending.iter().any(|(pa, pp, _)| pa == &a && *pp == p) {
            pending.push((a, p, Vec::new()));
        }
    }

    report(&args, head_num, &head_id, &matched, &confirmed, &pending, &errors)
}

/// Probe one (probe, address) pair on both nodes and diff. Treats "account
/// absent on both" (empty/no-address responses) as a match.
fn probe_pair(args: &Args, probe: Probe, address: &str) -> Result<Vec<Mismatch>, String> {
    let body = probe.body(address);
    let ra = http::post_json(&args.a, probe.path(), &body, args.http_timeout)
        .map_err(|e| format!("A: {e}"))?;
    let rb = http::post_json(&args.b, probe.path(), &body, args.http_timeout)
        .map_err(|e| format!("B: {e}"))?;
    let va: Value = serde_json::from_slice(&ra).map_err(|e| format!("A: bad JSON: {e}"))?;
    let vb: Value = serde_json::from_slice(&rb).map_err(|e| format!("B: bad JSON: {e}"))?;
    Ok(diff::diff(&va, &vb))
}

/// Poll both nodes' head until they report the same block id, or the
/// deadline passes.
fn settle(args: &Args, deadline: Instant) -> Result<(i64, String), String> {
    let mut last: String;
    loop {
        let a = get_now_block(&args.a, args.http_timeout);
        let b = get_now_block(&args.b, args.http_timeout);
        match (a, b) {
            (Ok((na, ia)), Ok((nb, ib))) => {
                if ia == ib {
                    return Ok((na, ia));
                }
                last = format!("A={na}/{} B={nb}/{}", short(&ia), short(&ib));
            }
            (Err(e), _) => last = format!("A getnowblock: {e}"),
            (_, Err(e)) => last = format!("B getnowblock: {e}"),
        }
        if Instant::now() >= deadline {
            return Err(last);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn get_now_block(url: &str, timeout: Duration) -> Result<(i64, String), String> {
    let raw = http::post_json(url, "/wallet/getnowblock", "{\"visible\":true}", timeout)?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| format!("getnowblock JSON: {e}"))?;
    let id = v
        .get("blockID")
        .and_then(|x| x.as_str())
        .ok_or("getnowblock: no blockID")?
        .to_string();
    let num = v
        .get("block_header")
        .and_then(|h| h.get("raw_data"))
        .and_then(|r| r.get("number"))
        .and_then(|n| n.as_i64())
        .unwrap_or(0);
    Ok((num, id))
}

fn get_block_by_num(url: &str, num: i64, timeout: Duration) -> Result<Value, String> {
    let body = format!("{{\"num\":{num},\"visible\":true}}");
    let raw = http::post_json(url, "/wallet/getblockbynum", &body, timeout)?;
    serde_json::from_slice(&raw).map_err(|e| format!("getblockbynum {num} JSON: {e}"))
}

/// Recursively collect every base58 TRON address (`T` + 33 base58 chars)
/// appearing as a string value anywhere in `v`. With `visible:true` the
/// block's tx contracts render owner/to/receiver/contract addresses in this
/// form, so this captures exactly the accounts a block touched.
fn collect_addresses(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            if is_base58_address(s) {
                out.insert(s.clone());
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_addresses(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect_addresses(x, out)),
        _ => {}
    }
}

fn is_base58_address(s: &str) -> bool {
    const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    s.len() == 34
        && s.starts_with('T')
        && s.bytes().all(|c| B58.contains(&c))
}

fn report(
    args: &Args,
    head_num: i64,
    head_id: &str,
    matched: &[(String, Probe)],
    confirmed: &[(String, Probe, Vec<Mismatch>)],
    pending: &[(String, Probe, Vec<Mismatch>)],
    errors: &[(String, Probe, String)],
) -> i32 {
    if args.json {
        let report = serde_json::json!({
            "head": { "number": head_num, "id": head_id },
            "summary": {
                "matched": matched.len(),
                "mismatched": confirmed.len(),
                "inconclusive": pending.len(),
                "errors": errors.len(),
            },
            "mismatches": confirmed.iter().map(|(a, p, ms)| serde_json::json!({
                "address": a, "probe": p.name(),
                "fields": ms.iter().map(|m| serde_json::json!({
                    "path": m.path, "a": m.a, "b": m.b,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "inconclusive": pending.iter().map(|(a, p, ms)| serde_json::json!({
                "address": a, "probe": p.name(),
                "fields": ms.iter().map(|m| serde_json::json!({
                    "path": m.path, "a": m.a, "b": m.b,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "errors": errors.iter().map(|(a, p, e)| serde_json::json!({
                "address": a, "probe": p.name(), "error": e,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("\n=== tron-state-diff @ head {head_num} ({}) ===", short(head_id));
        println!(
            "matched: {}   mismatched: {}   inconclusive: {}   errors: {}",
            matched.len(),
            confirmed.len(),
            pending.len(),
            errors.len()
        );
        if !confirmed.is_empty() {
            println!("\n-- MISMATCHES (real; observed under a stable head) --");
            for (addr, probe, ms) in confirmed {
                println!("  {} [{}]", addr, probe.name());
                for m in ms {
                    println!("      {} :  A={}  B={}", m.path, m.a, m.b);
                }
            }
        }
        if !pending.is_empty() {
            println!("\n-- INCONCLUSIVE (head kept moving; account may change every block) --");
            for (addr, probe, ms) in pending {
                println!("  {} [{}]{}", addr, probe.name(), if ms.is_empty() { " (no stable read)" } else { "" });
                for m in ms {
                    println!("      {} :  A={}  B={}", m.path, m.a, m.b);
                }
            }
        }
        if !errors.is_empty() {
            println!("\n-- ERRORS --");
            for (addr, probe, e) in errors {
                println!("  {} [{}]: {}", addr, probe.name(), e);
            }
        }
        if confirmed.is_empty() && errors.is_empty() {
            println!("\nNo real divergences found across {} probe(s).", matched.len());
        }
    }

    // Exit code: 1 if any confirmed mismatch, 2 if errors only, 0 if clean.
    if !confirmed.is_empty() {
        1
    } else if !errors.is_empty() {
        2
    } else {
        0
    }
}

fn short(id: &str) -> String {
    id.chars().take(16).collect()
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut a = "http://127.0.0.1:8090".to_string();
    let mut b: Option<String> = None;
    let mut accounts: Vec<String> = Vec::new();
    let mut accounts_file: Option<String> = None;
    let mut from_recent_blocks: u64 = 0;
    let mut probes_raw = "account,resource".to_string();
    let mut settle = 30u64;
    let mut max_rounds = 3u32;
    let mut http_timeout = 10u64;
    let mut json = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--a" => a = next()?,
            "--b" => b = Some(next()?),
            "--accounts" => {
                accounts.extend(next()?.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
            }
            "--accounts-file" => accounts_file = Some(next()?),
            "--from-recent-blocks" => {
                from_recent_blocks = next()?.parse().map_err(|_| "bad --from-recent-blocks".to_string())?
            }
            "--probes" => probes_raw = next()?,
            "--settle-timeout-secs" => settle = next()?.parse().map_err(|_| "bad --settle-timeout-secs".to_string())?,
            "--max-rounds" => max_rounds = next()?.parse().map_err(|_| "bad --max-rounds".to_string())?,
            "--http-timeout-secs" => http_timeout = next()?.parse().map_err(|_| "bad --http-timeout-secs".to_string())?,
            "--json" => json = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let b = b.ok_or("missing required --b <reference node url>")?;
    let mut probes = Vec::new();
    for p in probes_raw.split(',') {
        if p.trim().is_empty() {
            continue;
        }
        probes.push(Probe::parse(p).ok_or_else(|| format!("unknown probe: {p}"))?);
    }
    if probes.is_empty() {
        return Err("no valid probes selected".into());
    }

    Ok(Some(Args {
        a,
        b,
        accounts,
        accounts_file,
        from_recent_blocks,
        probes,
        settle_timeout: Duration::from_secs(settle),
        max_rounds,
        http_timeout: Duration::from_secs(http_timeout),
        json,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collects_base58_addresses_from_a_block() {
        let block = json!({
            "blockID": "0000000000000001abcd",
            "transactions": [{
                "raw_data": { "contract": [{
                    "parameter": { "value": {
                        "owner_address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                        "to_address": "TWdYxJ3oqHzMa1Hs7e3p9rN5wK2qJ8vC4z",
                        "amount": 100
                    }}
                }]}
            }]
        });
        let mut out = BTreeSet::new();
        collect_addresses(&block, &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.contains("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"));
    }

    #[test]
    fn base58_address_matcher_rejects_non_addresses() {
        assert!(is_base58_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"));
        assert!(!is_base58_address("hello")); // too short
        assert!(!is_base58_address("0000000000000001abcd")); // not T-prefixed
        assert!(!is_base58_address("T0OIl00000000000000000000000000000")); // 0/O/I/l not base58
    }

    #[test]
    fn probe_bodies_use_the_right_field() {
        assert!(Probe::Account.body("TX").contains("\"address\":\"TX\""));
        assert!(Probe::Contract.body("TX").contains("\"value\":\"TX\""));
        assert!(Probe::Account.body("TX").contains("\"visible\":true"));
    }
}
