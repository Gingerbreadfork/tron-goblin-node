# RPC / query performance + steady-state RAM — tron-goblin-node vs java-tron

This is the **query-serving** dimension of the public "tron-goblin-node vs
vanilla java-tron" benchmark suite. It measures how each engine behaves as a
**read-only query server** over the same mainnet snapshot (a read-only copy of
the snapshot you supply via `SNAPSHOT_PATH`):

- **Query latency + throughput** — p50/p99 latency, requests/sec, and error
  rate for a fixed set of real, read-only `/wallet/*` queries, at a small
  concurrency sweep.
- **Steady-state RAM** — the engine's resident memory (RSS) just serving the
  static snapshot at rest, with no load (the "idle footprint"), plus peak RSS
  under the query load.

The block-apply throughput dimension lives in the parent `bench/` directory
(`bench/ours.sh`, `bench/java.sh`); this `bench/rpc/` subdirectory owns the
query/RAM dimension only.

## What is measured

Per engine (`ours` = tron-goblin-node, `java` = clean vanilla java-tron), one
run produces `../results/rpc-<engine>.json` with this schema:

| key | meaning |
| --- | --- |
| `dimension` | always `"rpc"` |
| `engine` | `"ours"` or `"java"` |
| `version` | git short SHA (ours) or jar version string (java) |
| `idle_rss_mb` | steady-state resident memory serving the snapshot at rest, no load (MiB) |
| `peak_rss_mb` | peak resident memory under the query load (MiB) |
| `avg_cpu_pct` | mean %CPU under load, across all cores (may exceed 100) |
| `queries` | array of per-query-per-concurrency results (below) |
| `notes` | freeform: protocol, heap/-Xmx, snapshot, anomalies |

Each entry in `queries` is:

| key | meaning |
| --- | --- |
| `type` | query id (`getnowblock`, `getblockbynum`, `getaccount`, `gettransactioninfobyid`, `triggerconstantcontract`) |
| `concurrency` | concurrent in-flight requests for this step |
| `p50_ms`, `p99_ms` | median / 99th-percentile request latency (ms) |
| `req_per_sec` | throughput over the measured window |
| `error_rate` | fraction of requests that failed (non-200 or a logical `{"Error": ...}` body) |
| `count`, `errors`, `duration_s` | raw counts / measured window length (detail) |

## Protocol and query workload

Both engines expose the **identical** java-tron HTTP `/wallet/*` JSON API on
**port 8090** (`HTTP_PORT`) — this is the parity-designed surface, so one
unchanged load generator hits both engines the same way. The five queries (in
`queries.json`), all read-only and deterministic over the snapshot range (the
bundled `queries.json` targets a snapshot at head **83,316,752** — adjust its
`block_for_num` / addresses for a different snapshot):

| type | endpoint | exercises |
| --- | --- | --- |
| `getnowblock` | `POST /wallet/getnowblock` | head read |
| `getblockbynum` | `POST /wallet/getblockbynum` `{num: 83300000}` | block-index + block store read |
| `getaccount` | `POST /wallet/getaccount` `{address: 414294074251…a8ad5a80}` | account store read (SunSwap hub) |
| `gettransactionbyid` | `POST /wallet/gettransactionbyid` `{value: <txid>}` | transaction (`trans` store) read |
| `triggerconstantcontract` | `POST /wallet/triggerconstantcontract` | **VM read path** — USDT `balanceOf(address)` on `41a614f803b6fd780986a42c78ec9c7f77e6ded13c` |

**Snapshot prune note.** The source is a *LiteFullNode* snapshot (head
83,316,752): it prunes historical blocks (anything below ~83,260,000 is gone, so
the in-snapshot block is **83,300,000**, not a deep-history block) and drops the
transaction-info / receipt stores entirely. So the tx-lookup query is
`gettransactionbyid` (reads the populated `trans` store — real data) rather than
`gettransactioninfobyid` (which returns `null` for every tx on this snapshot
because receipts are pruned). Both are read-only `/wallet/*` endpoints both
engines expose identically. On a full-archive snapshot, swap the plan entry back
to `gettransactioninfobyid` for the receipt-read path.

The tx id is **resolved at startup** by the load generator: it fetches block
83,300,000 via `getblockbynum` and uses that block's first `txID`, so a real
in-snapshot tx is always used (the literal in `queries.json` is only a
documented fallback). The `triggerconstantcontract`
query is the high-value one — it stresses the TVM read/eval path, not just a
store lookup, and requires `vm.supportConstant = true` (ours) /
`vm.supportConstant = true` (java), which both runners set.

Each query is run at concurrency **1, 16, 64** for **4 s** each (a short
uncounted warmup precedes every step so JIT/compile and lazy RocksDB
block-cache fill do not skew the latency window).

## Why it is fair

- **Same snapshot, read-only.** Both engines serve the *same* mainnet RocksDB
  snapshot, **copied** into a dedicated per-engine bench data-dir under
  `BENCH_WORK` and served read-only. Neither mutates the source snapshot.
- **Same protocol, same paths, same bodies.** Identical HTTP `/wallet/*`
  endpoints, identical request bodies, identical concurrency sweep and per-step
  duration, driven by the **same load generator** (`loadgen.py`) — only the
  target host:port differs.
- **Same machine, in isolation.** The engines are run **in series, never
  concurrently**, so query latency on one is not contaminated by the other
  contending for CPU, page cache, or disk.
- **Same metric contract.** Both runners sample RSS/CPU through the shared
  `bench/lib.sh` helpers (`bench_sample_proc` / `bench_sampler_summary`) and
  emit the identical RPC JSON schema through the shared `emit_rpc_json.py`.

## Caveats (read this)

- **JVM heap inflates java RSS.** java-tron runs with a fixed, pre-touched heap
  (`-Xms=-Xmx`, default 24 GiB here, `-XX:+AlwaysPreTouch`), so its `idle_rss_mb`
  and `peak_rss_mb` reflect the *configured heap size*, not the working set the
  GC actually needs. Our node has no managed heap; its RSS is the true working
  set. Treat the RSS comparison as "footprint under each engine's normal
  operating configuration," not "minimum memory each could survive on." The
  idle-RSS number is the honest headline for "what does a query node cost to
  keep running"; weigh it with the heap caveat. Lower `XMX` to compare under a
  smaller-heap java configuration.
- **Warm vs cold cache.** Running engines back-to-back over the same snapshot
  means the second engine may see a warmer OS page cache for the shared SSTs.
  The per-step warmup absorbs the engine's own block-cache fill, but the page
  cache of the underlying snapshot is shared. Run each engine first-after-copy,
  or in alternating order across repeated runs, if this matters.
- **Single run, not averaged.** Each number is one run; re-run for a
  distribution (latency tails especially vary with GC and scheduler noise).
- **Closed-loop load.** The generator is closed-loop (each worker fires the next
  request only after the previous completes), so `req_per_sec` is a saturation
  throughput at the given concurrency, not an open-loop arrival rate.
- **RSS sampling granularity.** The sampler polls `/proc/<pid>` ~once per second
  and reads `VmHWM`, so a brief peak between polls is still captured. The idle
  window is short (5 s) by design — RSS at rest is flat — so its peak is the
  idle RSS.

## Inputs

All inputs come from [`../bench.config`](../bench.config) (overridable by
environment); there are no hardcoded machine paths.

| input | config variable | default |
| --- | --- | --- |
| LiteFullNode snapshot | `SNAPSHOT_PATH` | `$BENCH_WORK/snapshot` |
| our node binary | `TRON_NODE` | `target/release/tron-node` |
| vanilla java-tron jar | `JAVA_TRON_JAR` / `JT_BUILT_JAR` | built by `bootstrap.sh` into `$BENCH_WORK/java/FullNode.jar` |
| JDK 8 home | `JDK8_HOME` | `$JAVA_HOME`, else `java`/`javac` on `PATH` |
| HTTP host:port | `HTTP_HOST` / `HTTP_PORT` | `127.0.0.1` / `8090` |
| java heap | `XMX` | `24g` |

Dedicated bench data-dirs live under `BENCH_WORK` and are fully owned by the
suite: ours at `$BENCH_WORK/data/rpc-ours`, java at `$BENCH_WORK/data/rpc-java`.
Each is a **plain copy** of the read-only snapshot (our node:
`bench_copy_snapshot` recursive copy; java: the same) — never a hard-link or
reset of a shared directory, and the source snapshot is never written. The copy
duplicates the snapshot, so point `BENCH_WORK` at a disk with ample free space.

## How to reproduce

> A run **copies** the snapshot into each engine's writable bench data-dir under
> `BENCH_WORK`; it never writes the source snapshot. Do not run while another
> node/sync holds the same bench data-dir or the chosen HTTP port; the runners
> refuse to start if a conflicting node is alive or the port is taken. Run the
> two engines in series, never at the same time (latency isolation). Bootstrap
> first (`bench/bootstrap.sh`).

From the repo root, one engine at a time:

```sh
# tron-goblin-node:
bench/rpc/ours.sh --out bench/results

# vanilla java-tron (after ours has fully stopped):
bench/rpc/java.sh --out bench/results
```

Each runner:

1. Copies its dedicated bench data-dir from the snapshot (timed internally; the
   load measurements exclude this).
2. Starts the engine serving HTTP `/wallet/*` with sync/p2p off and
   `supportConstant` on, and waits until `getnowblock` answers.
3. Measures steady-state idle RSS (5 s, no load).
4. Runs `loadgen.py` over `queries.json` while sampling peak RSS + CPU.
5. Stops the engine cleanly and writes `results/rpc-<engine>.json`.

Drive the load generator directly against an already-running node (e.g. to
iterate on the plan):

```sh
python3 bench/rpc/loadgen.py \
  --base-url http://127.0.0.1:8090 \
  --plan bench/rpc/queries.json \
  --out -
```

## Files

| file | role |
| --- | --- |
| `queries.json` | shared query plan (method + path + body + concurrency sweep) |
| `loadgen.py` | shared concurrent HTTP load generator (asyncio + aiohttp); p50/p99/rps/error-rate per query×concurrency; resolves a real tx id at startup |
| `emit_rpc_json.py` | shared RPC-schema result-JSON writer (both runners) |
| `ours.sh` | tron-goblin-node runner (read-only query server) |
| `java.sh` | clean java-tron runner (read-only query server) |
| `README.md` | this file |

The load generator is a small dependency-light client because no installed HTTP
load tool (`oha`/`wrk`/`hey`/`bombardier`) is present on the rig; it does the
same job (fixed concurrency for a fixed duration → p50/p99 + rps + error rate)
and emits a machine-readable JSON the runners fold into the result.
