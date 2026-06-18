# tron-goblin-node vs java-tron — benchmark suite

A **portable, fully isolated** benchmark suite that measures tron-goblin-node
("ours") head-to-head against a stock, vanilla java-tron FullNode across several
independent dimensions on the same machine: **block-sync throughput**, **decode
throughput**, **read-only query/RPC performance**, and **memory footprint**.

It runs from a **fresh `git clone` on any machine**. You supply one input (a
TRON LiteFullNode snapshot) and run `bootstrap.sh` then `run.sh`; everything
else — building our node, building a vanilla java-tron jar, working data-dirs,
logs — is created inside an isolated working directory the suite owns.

## Isolation guarantee

The suite **only ever reads the snapshot read-only and copies it**; it never
modifies any external or shared data:

- It reads your snapshot at `SNAPSHOT_PATH` **read-only** and **copies** it into
  a per-engine working data-dir under `BENCH_WORK` (our node via
  `import-snapshot --mode copy`; java via a plain `cp`/`rsync`). It never
  hard-links, resets, moves, or writes the snapshot.
- Every artifact it creates — the java-tron jar, the cloned java-tron source,
  per-engine data-dirs, the decode corpus, logs, samples — lives under
  `BENCH_WORK` (default `bench/.work`, overridable to a big disk).
- There are no hardcoded machine paths, no shared "pristine" directory, and no
  private/LAN peer IPs anywhere in the suite.

## What is measured

Per engine (`ours` = tron-goblin-node, `java` = vanilla java-tron), each
dimension writes one JSON file into the results dir, and `report.py` renders
them into `results/REPORT.md` (a headline + a section per dimension with a table
and an ASCII bar chart, plus methodology and caveats).

- **Sync** — block-apply throughput: peer-sync an identical block range, each
  engine starting from the same snapshot pre-state, and time the apply window.
- **Decode** — pure protobuf parse + per-tx parameter-decode throughput over an
  identical in-memory block corpus (no state, no I/O in the timed loop).
- **Query / RPC** — read-only HTTP `/wallet/*` query latency + throughput over
  the same snapshot, plus steady-state idle RAM and peak RAM under load.

See the per-dimension READMEs for the exact scope and fairness contract:
[`decode/README.md`](decode/README.md), [`rpc/README.md`](rpc/README.md).

## Prerequisites

- A **TRON LiteFullNode snapshot** — a java-format RocksDB tree whose stores
  live under `<snapshot>/database/`. Public mainnet LiteFullNode snapshots are
  published by the TRON community (e.g. the snapshot index at
  `http://34.86.86.229/`). Supply it via `SNAPSHOT_PATH`, or have `bootstrap.sh`
  download it via `SNAPSHOT_URL`. The snapshot's head should sit at `(FROM - 1)`
  for the configured sync range; set `FROM` to `(snapshot_head + 1)` otherwise.
- **Disk** — the suite **copies** the snapshot into `BENCH_WORK` (once per
  engine per dimension you run). A mainnet LiteFullNode snapshot is tens of GiB,
  so point `BENCH_WORK` at a disk with several times the snapshot size free.
- **A Rust toolchain** (`rustup`/`cargo`) to build our node.
- **JDK 8 + java-tron build deps** to build the vanilla FullNode jar
  (`bootstrap.sh` clones java-tron at `JAVA_TRON_TAG` and runs its gradle build
  under JDK 8). Alternatively set `JAVA_TRON_JAR` to a prebuilt vanilla jar and
  skip the build.
- **python3** (report + RPC load generator). **grpcurl** is optional — only the
  decode-corpus fetcher uses it; the decode dimension is otherwise optional.

## Configuration

All inputs live in **[`bench.config`](bench.config)**, sourced by every runner.
Each value has a documented default and is overridable from the environment.
The key knobs:

| variable | default | meaning |
| --- | --- | --- |
| `BENCH_WORK` | `bench/.work` | isolated working dir the suite fully owns (jars, data-dirs, corpus, logs). Point at a big disk. |
| `SNAPSHOT_PATH` | `$BENCH_WORK/snapshot` | the LiteFullNode snapshot to read (read-only) and copy. |
| `SNAPSHOT_URL` | _(unset)_ | if `SNAPSHOT_PATH` is absent, an archive `bootstrap.sh` downloads + extracts. |
| `JAVA_TRON_TAG` | `GreatVoyage-v4.8.1.1` | vanilla java-tron release `bootstrap.sh` clones + builds. |
| `JAVA_TRON_JAR` | _(unset)_ | path to a prebuilt vanilla FullNode jar; if set, the build is skipped. |
| `JDK8_HOME` | `$JAVA_HOME` | JDK 8 home; falls back to `java`/`javac` on `PATH`. |
| `XMX` | `24g` | java heap (`-Xms=-Xmx`, pre-touched) — inflates java RSS; see caveats. |
| `SYNC_PEER` | _(empty)_ | sync source: empty = public peer discovery; or `host:port` to pin one mainnet peer for both engines. **Never a private LAN IP.** |
| `FROM` / `TO` | `83316753` / `83386262` | inclusive sync block range. |
| `DECODE_COUNT` | `10000` | leading corpus blocks decoded each pass. |
| `BLOCKS_FILE` | `$BENCH_WORK/corpus/blocks_<FROM>-<TO>.blocks` | decode corpus (fetched by bootstrap, or supplied by you). |
| `HTTP_HOST` / `HTTP_PORT` | `127.0.0.1` / `8090` | HTTP `/wallet/*` host:port for the RPC dimension. |
| `RESULTS_DIR` | `bench/results` | per-engine JSON + generated `REPORT.md`. |

Example (big-disk work dir + a snapshot you already have):

```sh
BENCH_WORK=/data/bench-work SNAPSHOT_PATH=/data/lite-snapshot \
  bench/bootstrap.sh
BENCH_WORK=/data/bench-work SNAPSHOT_PATH=/data/lite-snapshot \
  bench/run.sh
```

## How to run

### 1. Bootstrap (once per machine)

```sh
bench/bootstrap.sh
```

`bootstrap.sh` is idempotent and prepares everything into `BENCH_WORK`:

1. **node** — `cargo build --release -p tron-node`.
2. **java** — uses `JAVA_TRON_JAR` if set; else clones java-tron at
   `JAVA_TRON_TAG` and runs `:framework:buildFullNodeJar` under JDK 8.
3. **snapshot** — verifies `SNAPSHOT_PATH` (or downloads `SNAPSHOT_URL`);
   **fails loudly with instructions** if no snapshot is available.
4. **corpus** _(optional)_ — fetches the decode corpus into `BLOCKS_FILE` via
   `decode/fetch_corpus.py` (needs `grpcurl`); skips with instructions if no
   fetch tool is present, since the decode dimension is optional.

Run a single step with `--only node|java|snapshot|corpus`.

> Bootstrapping is the heavy part: it builds our node, builds (or downloads) a
> ~140 MiB java-tron jar, and may download a tens-of-GiB snapshot. Run it on a
> machine with disk + build deps before benchmarking.

### 2. Run the benchmark

Full run (all dimensions, both engines, default range), from the repo root:

```sh
bench/run.sh
```

Pick a subset / range / output dir:

```sh
bench/run.sh --engines ours                  # ours only
bench/run.sh --dimensions sync               # sync dimension only
bench/run.sh --from 83316753 --to 83327800   # a shorter range
bench/run.sh --out /tmp/bench-results
```

The orchestrator:

1. Pre-flight checks the snapshot and (when java is selected) the java-tron jar,
   and that each engine runner exists. **It fails loudly** if any is missing.
2. Runs each selected `(dimension, engine)` runner **in series** (concurrent
   runs would corrupt throughput/latency/CPU measurements). Each writes its own
   result JSON.
3. Runs `python3 bench/report.py --results <dir>` to produce `REPORT.md`.

A single runner directly (bypassing the orchestrator) is just the runner with
the arguments that dimension expects, e.g.:

```sh
bench/java.sh --from 83316753 --to 83386262 --out bench/results
bench/rpc/ours.sh --out bench/results
bench/decode/java.sh --count 10000 --out bench/results
```

## Sync dimension — fairness

- **Same snapshot pre-state.** Both engines start from a fresh **copy** of the
  same snapshot, so neither is "warmed" by a prior partial sync.
- **Same block range.** Both sync the identical `[FROM, TO]` set of mainnet
  blocks (inclusive of both endpoints).
- **Same block source.** Both obtain blocks the same way: from a single pinned
  `SYNC_PEER` (discovery off), or — when `SYNC_PEER` is empty — via public peer
  discovery (our node walks `main.trondisco.net` + the Kademlia DHT; java uses
  its discovery + the public `JAVA_SEED_NODES`). The network path is the same
  shared cost for both.
- **Same engine path.** Each engine uses its **own production sync path**:
  ours is `tron-node start`, java is a vanilla (un-instrumented) `FullNode`
  doing `PeerConnection → Manager.pushBlock`. No custom replay harness.
- **Same machine, in series.** Engines never run concurrently.
- **Same metric contract.** Both runners emit the identical JSON schema via
  `bench/lib.sh`'s `bench_emit_json`; `blocks` and `blocks_per_sec` are derived
  by the same code path for both.

The timed window is the **sync of `[FROM, TO]`** itself; the snapshot copy is
reported separately as `snapshot_load_s` so throughput isn't polluted by it.
Block-STM (`vm.parallel_exec`) is on for ours — the parallel block-execution
path this benchmark exists to show.

## The vanilla java-tron jar

For credibility the java side is a **vanilla, un-instrumented java-tron** build.
`bootstrap.sh` clones the upstream repo at `JAVA_TRON_TAG` and builds
`:framework:buildFullNodeJar` under JDK 8 into `BENCH_WORK`; no diagnostic edits
are applied. Set `JAVA_TRON_JAR` to a jar you built yourself to skip the build.
The build version under test is stamped into the metric `version` field
(`git describe --tags @ short-sha`, e.g. `GreatVoyage-v4.8.1.1@a79693e45`).

## Caveats

- **JVM heap inflates java RSS.** java-tron runs a fixed, pre-touched heap
  (`-Xms=-Xmx` with `-XX:+AlwaysPreTouch`, default `24g`), so its `peak_rss_mb`
  reflects the configured heap, not the GC working set. Our node has no managed
  heap; its RSS is the true working set. Treat the RSS comparison as "footprint
  under each engine's normal operating configuration." Lower `XMX` to compare
  under a smaller-heap java configuration.
- **Network cancels out.** Both engines fetch blocks the same way, so download
  latency is a shared, identical cost in both `wall_clock_s` values — part of
  the real "sync" work being measured, not a per-engine advantage. Sync speed
  depends on which public peers each engine finds; pin `SYNC_PEER` for a more
  controlled, lower-variance comparison.
- **Single run, not averaged.** Each number is one run; re-run for a
  distribution (variance from compaction, GC, peer timing, scheduler noise).
- **Warm vs cold cache.** Running engines back-to-back over the same snapshot
  copy can leave the second engine with a warmer OS page cache. Run each engine
  first-after-copy, or in alternating order across repeats, if this matters.
- **Block-STM is ON for ours** (`vm.parallel_exec`); the comparison is "Rust +
  parallel execution" vs "JVM serial pushBlock". Disable the flag for an
  apples-to-apples single-thread number.
- **RSS sampling granularity.** The sampler polls `/proc/<pid>` ~once per second
  and also reads `VmHWM` (kernel high-water mark), so a brief peak between polls
  is still captured. CPU% is total CPU jiffies over total wall time.

## Files

| file | role |
| --- | --- |
| `bench.config` | single source of truth for every input (sourced by all runners) |
| `bootstrap.sh` | one-shot prerequisite setup into `BENCH_WORK` (node/java/snapshot/corpus) |
| `run.sh` | orchestrator: pre-flight, run runners in series, build report |
| `lib.sh` | shared helpers: timing, process sampler, snapshot copy, results-JSON writer |
| `ours.sh` / `java.sh` | sync-dimension runners (ours / vanilla java-tron) |
| `decode/` | decode-throughput dimension (see `decode/README.md`) |
| `rpc/` | query/RPC + RAM dimension (see `rpc/README.md`) |
| `report.py` | reads `results/*.json` → `results/REPORT.md` (engine-agnostic) |
| `results/` | per-engine JSON + generated `REPORT.md` |

## Contract for the engine runners

Each sync runner (`ours.sh`, `java.sh`) must:

- Source `bench.config`; take all inputs (paths/peers/range) from it.
- Accept `--from N --to N --out DIR`.
- Obtain the pre-state by **copying** `SNAPSHOT_PATH` into a `BENCH_WORK`
  data-dir, and report that copy cost as `snapshot_load_s` (separate from the
  timed sync window). **Never** touch the snapshot read-write or any shared dir.
- Sync `[from, to]` via `SYNC_PEER` (or discovery) and time **only the sync** as
  `wall_clock_s` (detecting completion at synced head ≥ `to`).
- Sample the engine with `bench_sample_proc` / `bench_sampler_summary`, and emit
  the result via `bench_emit_json` so `blocks` / `blocks_per_sec` are derived
  identically for both engines.
- Refuse to run if a conflicting node/JVM is alive against its bench data-dir.
- Record the mechanism + build flags (Block-STM on/off, release) in `notes`.
