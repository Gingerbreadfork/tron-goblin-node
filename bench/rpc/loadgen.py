#!/usr/bin/env python3
"""loadgen.py -- concurrent HTTP query load generator for the RPC benchmark.

Drives a fixed query plan (bench/rpc/queries.json) against ONE engine's
java-tron-compatible HTTP /wallet/* JSON API and reports, per (query type x
concurrency level): p50/p99 latency, requests/sec, and error rate.

It is the SAME generator pointed at both engines (ours.sh and java.sh) so the
load is byte-identical; only the target host:port differs. No installed load
tool (oha/wrk/hey/bombardier) is present on this rig, so this is a small,
dependency-light asyncio + aiohttp client that does the same job and emits a
machine-readable JSON summary the engine runners fold into results/rpc-*.json.

Fairness:
  * Identical query bodies, identical concurrency sweep, identical duration per
    step against both engines.
  * A short warmup precedes each measured step so the first-request JIT/compile
    (java) and lazy RocksDB block-cache fill do not skew the latency window;
    warmup requests are NOT counted.
  * Engines are run in isolation (never concurrently) by the runners, so
    latency is not cross-contaminated.

Usage:
    loadgen.py --base-url http://127.0.0.1:8090 \
               --plan bench/rpc/queries.json \
               --out  bench/results/rpc-ours.queries.json \
               [--connect-timeout 5] [--request-timeout 30] [--warmup-s 1]

Output JSON: {"base_url": ..., "queries": [
    {type, concurrency, p50_ms, p99_ms, req_per_sec, error_rate,
     count, errors, duration_s}, ...]}

Exit status is 0 even if some requests error (error_rate captures that); it is
non-zero only on a usage / connectivity / plan-parse failure so a runner can
distinguish "engine answered, some slow/failed" from "could not benchmark".
"""

import argparse
import asyncio
import json
import sys
import time

try:
    import aiohttp
except ImportError:
    sys.stderr.write(
        "loadgen.py: aiohttp is required (python3 -m pip install aiohttp)\n"
    )
    sys.exit(2)


def percentile(sorted_vals, q):
    """Nearest-rank percentile of an already-sorted list (q in [0,100])."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    # Nearest-rank: rank = ceil(q/100 * N), 1-based, clamped to [1, N].
    import math

    rank = max(1, min(len(sorted_vals), math.ceil(q / 100.0 * len(sorted_vals))))
    return sorted_vals[rank - 1]


async def fire_one(session, method, url, body, timeout):
    """Issue one request; return (latency_seconds, ok_bool).

    A request counts as ok iff it returns HTTP 200 AND a JSON body that does
    not carry an `Error` field (java-tron and our node both report logical
    failures as `{"Error": "..."}` with HTTP 200, so a bare status check would
    miss them). Transport/timeout failures count as errors with the elapsed
    wall time recorded so a stall still shows up in the latency tail.
    """
    t0 = time.perf_counter()
    try:
        if method == "GET":
            async with session.get(url, timeout=timeout) as resp:
                text = await resp.read()
                ok = resp.status == 200 and b'"Error"' not in text
        else:
            async with session.post(url, json=body, timeout=timeout) as resp:
                text = await resp.read()
                ok = resp.status == 200 and b'"Error"' not in text
    except Exception:
        return (time.perf_counter() - t0, False)
    return (time.perf_counter() - t0, ok)


async def worker(session, method, url, body, timeout, deadline, latencies, results):
    """Closed-loop worker: fire back-to-back until the deadline."""
    while time.perf_counter() < deadline:
        lat, ok = await fire_one(session, method, url, body, timeout)
        latencies.append(lat)
        results.append(ok)


async def run_step(session, query, concurrency, duration_s, warmup_s,
                   request_timeout, base_url):
    """Run one (query, concurrency) step and return its summary dict."""
    method = query["method"].upper()
    url = base_url + query["path"]
    body = query.get("body", {})
    timeout = aiohttp.ClientTimeout(total=request_timeout)

    # --- warmup (uncounted) ---
    if warmup_s > 0:
        warm_deadline = time.perf_counter() + warmup_s
        warm_lat, warm_res = [], []
        warm_tasks = [
            asyncio.create_task(
                worker(session, method, url, body, timeout,
                       warm_deadline, warm_lat, warm_res)
            )
            for _ in range(concurrency)
        ]
        await asyncio.gather(*warm_tasks)

    # --- measured window ---
    latencies, results = [], []
    t_start = time.perf_counter()
    deadline = t_start + duration_s
    tasks = [
        asyncio.create_task(
            worker(session, method, url, body, timeout,
                   deadline, latencies, results)
        )
        for _ in range(concurrency)
    ]
    await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - t_start

    count = len(results)
    errors = sum(1 for ok in results if not ok)
    lat_ms = sorted(l * 1000.0 for l in latencies)
    req_per_sec = (count / elapsed) if elapsed > 0 else 0.0
    error_rate = (errors / count) if count else 0.0

    return {
        "type": query["type"],
        "concurrency": concurrency,
        "p50_ms": round(percentile(lat_ms, 50), 3),
        "p99_ms": round(percentile(lat_ms, 99), 3),
        "req_per_sec": round(req_per_sec, 1),
        "error_rate": round(error_rate, 4),
        "count": count,
        "errors": errors,
        "duration_s": round(elapsed, 3),
    }


async def resolve_txid(session, base_url, num, request_timeout):
    """Fetch a real in-snapshot tx id from getblockbynum(num).

    Returns the first transaction's `txID` (hex, no 0x) or None if the block
    has no transactions / the request fails. Keeps the plan robust across
    snapshots without hard-coding a tx id that may not exist.
    """
    url = base_url + "/wallet/getblockbynum"
    timeout = aiohttp.ClientTimeout(total=request_timeout)
    try:
        async with session.post(url, json={"num": num}, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = await resp.json(content_type=None)
    except Exception:
        return None
    txs = (data or {}).get("transactions") or []
    for tx in txs:
        txid = tx.get("txID")
        if txid:
            return txid
    return None


def apply_resolutions(plan, resolved):
    """Substitute resolved dynamic values into the plan's query bodies."""
    for q in plan["queries"]:
        r = q.get("resolve")
        if not r:
            continue
        if r.get("pick") == "first_txid" and resolved.get("txid"):
            q.setdefault("body", {})[r["field"]] = resolved["txid"]


async def main_async(args):
    plan = json.load(open(args.plan))
    connector = aiohttp.TCPConnector(limit=0)  # no client-side connection cap
    async with aiohttp.ClientSession(connector=connector) as session:
        # Resolve any dynamic plan values (e.g. a real tx id) before measuring.
        resolved = {}
        need_txid = any(
            q.get("resolve", {}).get("pick") == "first_txid"
            for q in plan["queries"]
        )
        if need_txid:
            num = next(
                (q["resolve"]["num"] for q in plan["queries"]
                 if q.get("resolve", {}).get("pick") == "first_txid"),
                plan.get("block_for_num"),
            )
            txid = await resolve_txid(session, args.base_url, num,
                                      args.request_timeout)
            if txid:
                resolved["txid"] = txid
                sys.stderr.write(
                    f"loadgen: resolved tx id {txid} from block {num}\n"
                )
            else:
                sys.stderr.write(
                    "loadgen: WARNING could not resolve a tx id from "
                    f"block {num}; using plan fallback value\n"
                )
        apply_resolutions(plan, resolved)

        out = {"base_url": args.base_url, "queries": []}
        for q in plan["queries"]:
            for c in q.get("concurrency", [1]):
                dur = q.get("duration_s", 4)
                step = await run_step(
                    session, q, c, dur, args.warmup_s,
                    args.request_timeout, args.base_url,
                )
                out["queries"].append(step)
                sys.stderr.write(
                    "loadgen: {type:<26} c={concurrency:<3} "
                    "p50={p50_ms:>8}ms p99={p99_ms:>9}ms "
                    "rps={req_per_sec:>9} err={error_rate}\n".format(**step)
                )

    if args.out and args.out != "-":
        with open(args.out, "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
    else:
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return out


def parse_args():
    p = argparse.ArgumentParser(description="RPC query load generator")
    p.add_argument("--base-url", required=True,
                   help="engine HTTP base, e.g. http://127.0.0.1:8090")
    p.add_argument("--plan", required=True, help="path to queries.json")
    p.add_argument("--out", default="-",
                   help="output JSON path (default stdout)")
    p.add_argument("--request-timeout", type=float, default=30.0,
                   help="per-request total timeout seconds (default 30)")
    p.add_argument("--warmup-s", type=float, default=1.0,
                   help="uncounted warmup seconds per step (default 1)")
    return p.parse_args()


def main():
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except FileNotFoundError as e:
        sys.stderr.write(f"loadgen.py: {e}\n")
        sys.exit(2)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"loadgen.py: bad plan JSON: {e}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
