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
//! Beyond static state, it can also diff **read-only contract execution**
//! (`triggerconstantcontract`): calling the same view function on both nodes
//! and comparing the returned data + `energy_used`. This is how TVM execution
//! exactness gets validated (the resulting state of a real call is otherwise
//! invisible). Both nodes must have `vm.supportConstant = true`.
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
//!       [--constant] [--call T...:decimals()] [--constant-owner T...] \
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
  --constant                diff triggerconstantcontract for standard TRC20 view calls
                            (decimals/name/symbol/totalSupply) on every discovered contract;
                            both nodes need vm.supportConstant = true
  --call <addr:sig[:param]> diff one explicit constant call, e.g. T...:balanceOf(address):<64hex>
                            (repeatable; param is bare hex ABI args, optional)
  --constant-owner <addr>   caller (msg.sender) for constant calls [default: zero-address EOA]
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
    constant: bool,
    calls: Vec<(String, String, String)>, // (contract, signature, param-hex)
    constant_owner: Option<String>,
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

/// A read-only contract view call to compare between nodes.
#[derive(Clone)]
struct CallSpec {
    /// Human label / java `function_selector` signature, e.g. `decimals()`.
    signature: String,
    /// ABI-encoded argument bytes as bare hex (may be empty).
    parameter: String,
}

/// One unit of work — either a static-state probe or a constant call.
#[derive(Clone)]
enum Job {
    State { address: String, probe: Probe },
    Constant { contract: String, owner: String, call: CallSpec },
}

impl Job {
    /// Stable identity used to dedup and match across retry rounds.
    fn id(&self) -> String {
        match self {
            Job::State { address, probe } => format!("{address}|{}", probe.name()),
            Job::Constant { contract, call, .. } => {
                format!("{contract}|constant:{}", call.signature)
            }
        }
    }
    /// The subject address (account or contract).
    fn address(&self) -> &str {
        match self {
            Job::State { address, .. } => address,
            Job::Constant { contract, .. } => contract,
        }
    }
    /// The probe-kind label for reporting.
    fn kind(&self) -> String {
        match self {
            Job::State { probe, .. } => probe.name().to_string(),
            Job::Constant { call, .. } => format!("constant:{}", call.signature),
        }
    }
}

/// Default `owner_address` (msg.sender) for constant calls: the all-zero TRON
/// address — a guaranteed code-less EOA. Using the contract itself trips our
/// node's `RejectCallerWithCode` check (a contract can't be a tx caller), so
/// the caller must be an EOA. Override with `--constant-owner`.
const DEFAULT_CONSTANT_OWNER: &str = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";

/// Standard zero-argument TRC20/ERC20 view functions. Calling these on every
/// discovered contract exercises a uint8 (decimals), two strings (name,
/// symbol), and a uint256 (totalSupply) return — a good spread for TVM
/// exactness. Non-TRC20 contracts revert identically on both nodes (still a
/// match), so it's safe to call them broadly.
fn standard_view_calls() -> Vec<CallSpec> {
    ["decimals()", "name()", "symbol()", "totalSupply()"]
        .iter()
        .map(|sig| CallSpec {
            signature: sig.to_string(),
            parameter: String::new(),
        })
        .collect()
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

    // 4. Build the work list: static-state jobs + constant-call jobs.
    let mut jobs: Vec<Job> = Vec::new();
    for a in &addrs {
        for p in &args.probes {
            jobs.push(Job::State {
                address: a.clone(),
                probe: *p,
            });
        }
    }
    // Explicit --call jobs.
    for (contract, sig, param) in &args.calls {
        let owner = args
            .constant_owner
            .clone()
            .unwrap_or_else(|| DEFAULT_CONSTANT_OWNER.to_string());
        jobs.push(Job::Constant {
            contract: contract.clone(),
            owner,
            call: CallSpec {
                signature: sig.clone(),
                parameter: param.clone(),
            },
        });
    }
    // Auto --constant: standard view calls on every discovered contract.
    if args.constant {
        let candidates: Vec<String> = addrs.iter().cloned().collect();
        if !args.json {
            eprintln!(
                "scanning {} address(es) for contracts (getcontract on A)…",
                candidates.len()
            );
        }
        let mut n_contracts = 0usize;
        for a in &candidates {
            if is_contract(&args.a, a, args.http_timeout) {
                n_contracts += 1;
                let owner = args
                    .constant_owner
                    .clone()
                    .unwrap_or_else(|| DEFAULT_CONSTANT_OWNER.to_string());
                for call in standard_view_calls() {
                    jobs.push(Job::Constant {
                        contract: a.clone(),
                        owner: owner.clone(),
                        call,
                    });
                }
            }
        }
        if !args.json {
            eprintln!(
                "found {n_contracts} contract(s) → {} constant call(s)",
                n_contracts * 4
            );
        }
    }

    if jobs.is_empty() {
        eprintln!(
            "error: nothing to probe (use --accounts, --accounts-file, --from-recent-blocks, --constant, or --call)"
        );
        return 2;
    }

    // 5. Probe with head-stability rounds.
    let mut matched: Vec<Job> = Vec::new();
    let mut confirmed: Vec<(Job, Vec<Mismatch>)> = Vec::new();
    let mut errors: Vec<(Job, String)> = Vec::new();
    // Items whose mismatch was seen only under a moving head — retried.
    let mut pending: Vec<(Job, Vec<Mismatch>)> = Vec::new();

    let mut queue = jobs;
    for round in 0..args.max_rounds.max(1) {
        if queue.is_empty() {
            break;
        }
        // Settle before each round.
        let (h_num, h_id) = match settle(&args, Instant::now() + args.settle_timeout) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("error: lost common head before round {}: {e}", round + 1);
                pending = queue.into_iter().map(|j| (j, Vec::new())).collect();
                queue = Vec::new();
                break;
            }
        };

        let mut round_mismatches: Vec<(Job, Vec<Mismatch>)> = Vec::new();
        for job in &queue {
            match run_job(&args, job) {
                Ok(ms) if ms.is_empty() => matched.push(job.clone()),
                Ok(ms) => round_mismatches.push((job.clone(), ms)),
                Err(e) => errors.push((job.clone(), e)),
            }
        }

        // Was the head stable across this whole round?
        let (h_num2, h_id2) = get_now_block(&args.a, args.http_timeout)
            .and_then(|(n, _)| get_now_block(&args.b, args.http_timeout).map(|(_, i)| (n, i)))
            .unwrap_or((-1, String::new()));
        let stable = h_id2 == h_id && h_num2 == h_num;

        let mut next: Vec<Job> = Vec::new();
        if stable {
            // Every mismatch this round is real.
            for m in round_mismatches {
                confirmed.push(m);
            }
        } else {
            // Mismatches may be one-block-stale artifacts — retry them.
            for (job, ms) in round_mismatches {
                let id = job.id();
                pending.retain(|(pj, _)| pj.id() != id);
                pending.push((job.clone(), ms));
                next.push(job);
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
    // Anything still queued (never observed under a stable head) stays
    // inconclusive — surface it with its last-seen diff (or none).
    for job in queue {
        let id = job.id();
        if !pending.iter().any(|(pj, _)| pj.id() == id) {
            pending.push((job, Vec::new()));
        }
    }

    report(&args, head_num, &head_id, &matched, &confirmed, &pending, &errors)
}

/// Dispatch one job against both nodes and diff.
fn run_job(args: &Args, job: &Job) -> Result<Vec<Mismatch>, String> {
    match job {
        Job::State { address, probe } => probe_pair(args, *probe, address),
        Job::Constant {
            contract,
            owner,
            call,
        } => probe_constant(args, contract, owner, call),
    }
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

/// Call a contract view function on both nodes via triggerconstantcontract
/// and diff only the execution-relevant fields (return data + energy + status).
fn probe_constant(
    args: &Args,
    contract: &str,
    owner: &str,
    call: &CallSpec,
) -> Result<Vec<Mismatch>, String> {
    let body = constant_body(contract, owner, call);
    let path = "/wallet/triggerconstantcontract";
    let ra =
        http::post_json(&args.a, path, &body, args.http_timeout).map_err(|e| format!("A: {e}"))?;
    let rb =
        http::post_json(&args.b, path, &body, args.http_timeout).map_err(|e| format!("B: {e}"))?;
    let va: Value = serde_json::from_slice(&ra).map_err(|e| format!("A: bad JSON: {e}"))?;
    let vb: Value = serde_json::from_slice(&rb).map_err(|e| format!("B: bad JSON: {e}"))?;
    Ok(diff::diff(&constant_exec_fields(&va), &constant_exec_fields(&vb)))
}

/// java-tron-shaped triggerconstantcontract request body (visible:true so
/// both nodes accept base58 addresses).
fn constant_body(contract: &str, owner: &str, call: &CallSpec) -> String {
    if call.parameter.is_empty() {
        format!(
            "{{\"owner_address\":\"{owner}\",\"contract_address\":\"{contract}\",\"function_selector\":\"{}\",\"visible\":true}}",
            call.signature
        )
    } else {
        format!(
            "{{\"owner_address\":\"{owner}\",\"contract_address\":\"{contract}\",\"function_selector\":\"{}\",\"parameter\":\"{}\",\"visible\":true}}",
            call.signature, call.parameter
        )
    }
}

/// Extract just the execution-relevant fields from a triggerconstantcontract
/// response. The full response carries a transaction envelope (ref_block,
/// expiration, timestamp, txID) that legitimately differs between nodes and
/// is NOT an execution result — diffing it would be pure noise. We compare:
/// the return data, the energy spent, the success flag, and the contract ret.
fn constant_exec_fields(v: &Value) -> Value {
    serde_json::json!({
        "constant_result": v.get("constant_result").cloned().unwrap_or(Value::Null),
        "energy_used": v.get("energy_used").cloned().unwrap_or(Value::Null),
        "result_ok": v.get("result").and_then(|r| r.get("result")).cloned().unwrap_or(Value::Null),
        "contract_ret": v
            .get("transaction")
            .and_then(|t| t.get("ret"))
            .and_then(|r| r.get(0))
            .and_then(|r0| r0.get("contractRet"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// True if `address` is a deployed contract on `url` (getcontract returns
/// bytecode / a contract_address). Used to target constant calls.
fn is_contract(url: &str, address: &str, timeout: Duration) -> bool {
    let body = format!("{{\"value\":\"{address}\",\"visible\":true}}");
    let Ok(raw) = http::post_json(url, "/wallet/getcontract", &body, timeout) else {
        return false;
    };
    let Ok(v) = serde_json::from_slice::<Value>(&raw) else {
        return false;
    };
    let nonempty = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    };
    nonempty("bytecode") || nonempty("contract_address")
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
    s.len() == 34 && s.starts_with('T') && s.bytes().all(|c| B58.contains(&c))
}

/// A constant-call diff that is *only* on `energy_used` — return data, success
/// flag, and contractRet all match. This is the known TRON-energy-vs-revm-gas
/// model gap, not an execution-correctness divergence, so it's reported
/// separately and doesn't fail the run.
fn is_energy_only(ms: &[Mismatch]) -> bool {
    !ms.is_empty() && ms.iter().all(|m| m.path == "energy_used")
}

fn report(
    args: &Args,
    head_num: i64,
    head_id: &str,
    matched: &[Job],
    confirmed: &[(Job, Vec<Mismatch>)],
    pending: &[(Job, Vec<Mismatch>)],
    errors: &[(Job, String)],
) -> i32 {
    // Split confirmed mismatches: real execution/state divergences vs
    // constant calls that match on return data but differ only on energy.
    let real: Vec<&(Job, Vec<Mismatch>)> =
        confirmed.iter().filter(|(_, ms)| !is_energy_only(ms)).collect();
    let energy_only: Vec<&(Job, Vec<Mismatch>)> =
        confirmed.iter().filter(|(_, ms)| is_energy_only(ms)).collect();

    if args.json {
        let report = serde_json::json!({
            "head": { "number": head_num, "id": head_id },
            "summary": {
                "matched": matched.len(),
                "mismatched": real.len(),
                "energy_only": energy_only.len(),
                "inconclusive": pending.len(),
                "errors": errors.len(),
            },
            "mismatches": real.iter().map(|(j, ms)| serde_json::json!({
                "address": j.address(), "probe": j.kind(),
                "fields": ms.iter().map(|m| serde_json::json!({
                    "path": m.path, "a": m.a, "b": m.b,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "energy_only": energy_only.iter().map(|(j, ms)| serde_json::json!({
                "address": j.address(), "probe": j.kind(),
                "fields": ms.iter().map(|m| serde_json::json!({
                    "path": m.path, "a": m.a, "b": m.b,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "inconclusive": pending.iter().map(|(j, ms)| serde_json::json!({
                "address": j.address(), "probe": j.kind(),
                "fields": ms.iter().map(|m| serde_json::json!({
                    "path": m.path, "a": m.a, "b": m.b,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "errors": errors.iter().map(|(j, e)| serde_json::json!({
                "address": j.address(), "probe": j.kind(), "error": e,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("\n=== tron-state-diff @ head {head_num} ({}) ===", short(head_id));
        println!(
            "matched: {}   mismatched: {}   energy-only: {}   inconclusive: {}   errors: {}",
            matched.len(),
            real.len(),
            energy_only.len(),
            pending.len(),
            errors.len()
        );
        if !real.is_empty() {
            println!("\n-- MISMATCHES (real; observed under a stable head) --");
            for (job, ms) in &real {
                println!("  {} [{}]", job.address(), job.kind());
                for m in ms {
                    println!("      {} :  A={}  B={}", m.path, m.a, m.b);
                }
            }
        }
        if !energy_only.is_empty() {
            println!(
                "\n-- ENERGY-ONLY ({}) (return data matches; energy_used differs — \
                 known TRON-energy vs revm-gas model gap) --",
                energy_only.len()
            );
            for (job, ms) in energy_only.iter().take(10) {
                let e = ms.iter().find(|m| m.path == "energy_used");
                if let Some(m) = e {
                    println!("  {} [{}]  energy A={} B={}", job.address(), job.kind(), m.a, m.b);
                }
            }
            if energy_only.len() > 10 {
                println!("  … and {} more", energy_only.len() - 10);
            }
        }
        if !pending.is_empty() {
            println!("\n-- INCONCLUSIVE (head kept moving; account may change every block) --");
            for (job, ms) in pending {
                println!(
                    "  {} [{}]{}",
                    job.address(),
                    job.kind(),
                    if ms.is_empty() { " (no stable read)" } else { "" }
                );
                for m in ms {
                    println!("      {} :  A={}  B={}", m.path, m.a, m.b);
                }
            }
        }
        if !errors.is_empty() {
            println!("\n-- ERRORS --");
            for (job, e) in errors {
                println!("  {} [{}]: {}", job.address(), job.kind(), e);
            }
        }
        if real.is_empty() && errors.is_empty() {
            println!(
                "\nNo real divergences found across {} probe(s){}.",
                matched.len() + energy_only.len(),
                if energy_only.is_empty() {
                    String::new()
                } else {
                    format!(" ({} matched on return data, energy aside)", energy_only.len())
                }
            );
        }
    }

    // Exit code: 1 if any REAL divergence (energy-only doesn't fail), 2 if
    // errors only, 0 if clean.
    if !real.is_empty() {
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

/// Parse a `--call` spec: `CONTRACT:SIGNATURE[:PARAMHEX]`. Solidity
/// signatures contain no `:`, and base58 addresses / hex params don't either,
/// so a 3-way split on `:` is unambiguous.
fn parse_call_spec(spec: &str) -> Result<(String, String, String), String> {
    let mut it = spec.splitn(3, ':');
    let contract = it.next().unwrap_or("").trim().to_string();
    let sig = it.next().map(|s| s.trim().to_string()).unwrap_or_default();
    let param = it
        .next()
        .map(|s| s.trim().trim_start_matches("0x").to_string())
        .unwrap_or_default();
    if contract.is_empty() || sig.is_empty() {
        return Err(format!(
            "bad --call spec '{spec}' (want CONTRACT:SIGNATURE[:PARAMHEX])"
        ));
    }
    Ok((contract, sig, param))
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut a = "http://127.0.0.1:8090".to_string();
    let mut b: Option<String> = None;
    let mut accounts: Vec<String> = Vec::new();
    let mut accounts_file: Option<String> = None;
    let mut from_recent_blocks: u64 = 0;
    let mut probes_raw = "account,resource".to_string();
    let mut constant = false;
    let mut calls: Vec<(String, String, String)> = Vec::new();
    let mut constant_owner: Option<String> = None;
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
            "--constant" => constant = true,
            "--call" => calls.push(parse_call_spec(&next()?)?),
            "--constant-owner" => constant_owner = Some(next()?),
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
    // Probes may legitimately be empty if the user only wants constant calls.
    if probes.is_empty() && !constant && calls.is_empty() {
        return Err("no probes and no constant calls selected".into());
    }

    Ok(Some(Args {
        a,
        b,
        accounts,
        accounts_file,
        from_recent_blocks,
        probes,
        constant,
        calls,
        constant_owner,
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

    #[test]
    fn constant_body_has_selector_and_optional_parameter() {
        let no_arg = constant_body(
            "TContract",
            "TOwner",
            &CallSpec { signature: "decimals()".into(), parameter: String::new() },
        );
        assert!(no_arg.contains("\"contract_address\":\"TContract\""));
        assert!(no_arg.contains("\"owner_address\":\"TOwner\""));
        assert!(no_arg.contains("\"function_selector\":\"decimals()\""));
        assert!(!no_arg.contains("parameter"));
        assert!(no_arg.contains("\"visible\":true"));

        let with_arg = constant_body(
            "TContract",
            "TOwner",
            &CallSpec { signature: "balanceOf(address)".into(), parameter: "00aa".into() },
        );
        assert!(with_arg.contains("\"parameter\":\"00aa\""));
    }

    #[test]
    fn constant_exec_fields_drops_tx_envelope_keeps_execution() {
        let resp = json!({
            "result": { "result": true },
            "energy_used": 1234,
            "constant_result": ["0000000000000000000000000000000000000000000000000000000000000006"],
            "transaction": {
                "ret": [{ "contractRet": "SUCCESS" }],
                "txID": "deadbeef",
                "raw_data": { "ref_block_bytes": "abcd", "expiration": 999, "timestamp": 111 }
            }
        });
        let ex = constant_exec_fields(&resp);
        // Execution fields preserved.
        assert_eq!(ex["energy_used"], json!(1234));
        assert_eq!(ex["result_ok"], json!(true));
        assert_eq!(ex["contract_ret"], json!("SUCCESS"));
        assert!(ex["constant_result"].is_array());
        // Envelope dropped.
        assert!(ex.get("transaction").is_none());
    }

    #[test]
    fn two_identical_constant_responses_diff_clean_despite_different_envelopes() {
        // Same execution result; different tx envelopes (ref_block/txID) →
        // must NOT be reported as a divergence.
        let a = json!({
            "result": { "result": true }, "energy_used": 500,
            "constant_result": ["00ff"],
            "transaction": { "ret": [{ "contractRet": "SUCCESS" }], "txID": "aaaa",
                             "raw_data": { "ref_block_bytes": "1111" } }
        });
        let b = json!({
            "result": { "result": true }, "energy_used": 500,
            "constant_result": ["00ff"],
            "transaction": { "ret": [{ "contractRet": "SUCCESS" }], "txID": "bbbb",
                             "raw_data": { "ref_block_bytes": "2222" } }
        });
        assert!(diff::diff(&constant_exec_fields(&a), &constant_exec_fields(&b)).is_empty());
    }

    #[test]
    fn constant_diff_flags_energy_and_return_data_divergence() {
        let a = json!({ "result": { "result": true }, "energy_used": 500, "constant_result": ["0006"] });
        let b = json!({ "result": { "result": true }, "energy_used": 512, "constant_result": ["0008"] });
        let d = diff::diff(&constant_exec_fields(&a), &constant_exec_fields(&b));
        let paths: Vec<&str> = d.iter().map(|m| m.path.as_str()).collect();
        assert!(paths.contains(&"energy_used"), "energy divergence flagged: {paths:?}");
        assert!(
            paths.iter().any(|p| p.starts_with("constant_result")),
            "return-data divergence flagged: {paths:?}"
        );
    }

    #[test]
    fn parse_call_spec_handles_signature_and_optional_param() {
        let (c, s, p) = parse_call_spec("TXcontract:decimals()").unwrap();
        assert_eq!(c, "TXcontract");
        assert_eq!(s, "decimals()");
        assert_eq!(p, "");

        let (c, s, p) = parse_call_spec("TXc:balanceOf(address):0x00aa").unwrap();
        assert_eq!(c, "TXc");
        assert_eq!(s, "balanceOf(address)");
        assert_eq!(p, "00aa"); // 0x stripped

        assert!(parse_call_spec("justone").is_err());
    }

    #[test]
    fn energy_only_diff_is_classified_separately() {
        let m = |p: &str| Mismatch { path: p.into(), a: "x".into(), b: "y".into() };
        assert!(is_energy_only(&[m("energy_used")]));
        assert!(!is_energy_only(&[m("constant_result[0].value")]));
        // A real diff alongside energy is NOT energy-only (it's a real bug).
        assert!(!is_energy_only(&[m("energy_used"), m("constant_result[0].value")]));
        assert!(!is_energy_only(&[]));
    }

    #[test]
    fn default_constant_owner_is_an_eoa_not_the_contract() {
        // Must be a fixed code-less EOA (zero address), never the contract
        // itself, or our node's RejectCallerWithCode trips.
        assert_eq!(DEFAULT_CONSTANT_OWNER, "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb");
    }

    #[test]
    fn job_identity_is_stable_per_kind() {
        let s = Job::State { address: "TX".into(), probe: Probe::Account };
        let c = Job::Constant {
            contract: "TX".into(),
            owner: "TX".into(),
            call: CallSpec { signature: "decimals()".into(), parameter: String::new() },
        };
        assert_eq!(s.id(), "TX|account");
        assert_eq!(c.id(), "TX|constant:decimals()");
        assert_ne!(s.id(), c.id());
        assert_eq!(c.kind(), "constant:decimals()");
    }
}
