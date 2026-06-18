# tron-goblin-node vs java-tron — decode throughput

This is the **decode** dimension of the `tron-goblin-node vs java-tron`
benchmark suite. Where the top-level suite (`bench/`) measures **block-apply**
throughput (execute every transaction + commit state), this measures pure
**decode** throughput: the CPU cost of deserializing the canonical TRON `Block`
protobuf, iterating its transactions, and decoding each contract call's
parameters — with the corpus pre-loaded in memory so file I/O is excluded from
the timed loop.

Decode is a hot path on every node: every block a node receives over p2p, and
every transaction in it, must be parsed before anything else can happen. It is
also where a zero-copy Rust parser (prost) is expected to beat a JVM
(protobuf-java) most clearly, so it is a high-value, honest thing to measure.

## What is measured (the exact decode scope)

Both engines do **the same logical work over the same bytes**. Per block, per
measured pass:

1. **Parse the block.** `Block` protobuf → in-memory object.
   - ours: `tron_proto::Block::decode(bytes)` (prost).
   - java: `org.tron.protos.Protocol.Block.parseFrom(bytes)` (protobuf-java).
2. **Iterate transactions.** Walk every transaction in the block.
3. **Decode the first contract of each transaction.** Read the contract type
   and unpack the typed `Any` parameter for the three high-volume contract
   kinds, exactly as a node does to classify a transaction:
   - `TransferContract` (native TRX transfer) — decode + read amount + recipient.
   - `TransferAssetContract` (TRC-10 transfer) — decode + read amount + recipient.
   - `TriggerSmartContract` (contract call) — decode + read call value, then:
     - read the **4-byte method selector** and map it to a method name
       (`transfer` / `transferFrom` / `approve` / `mint` / `burn` / `swap` /
       `withdraw` / `deposit` / hex fallback);
     - when the called contract is **USDT**, **ABI-decode the transfer amount**
       (the uint256 amount word at the selector-relative offset).
   - any other contract type: read the type only (no further decode).

That is precisely the production decode the node ships:

- **ours** calls `mempool_explore::decode_tx_summary(tx)` per transaction — the
  same function that powers the `--mempool` and `--explore` live dashboards. No
  decode logic is reimplemented for the benchmark.
- **java** (`bench/decode/java/DecodeBench.java`) mirrors that scope using the
  vanilla java-tron classes on the FullNode classpath
  (`org.tron.protos.Protocol.*`, the generated
  `BalanceContract` / `AssetIssueContractOuterClass` / `SmartContractOuterClass`
  message classes, and the bundled `com.google.protobuf` runtime — including
  `Any.unpack(...)`, the same call java-tron's own `TransactionCapsule` /
  actuators use).

**Not** counted on either side: any chain-state lookup, RocksDB access,
signature recovery, Merkle-root recomputation, fee/resource accounting, or
transaction execution. This dimension isolates parse + parameter-decode CPU.

## Why it is fair

- **Identical bytes.** Both engines decode the **same** length-prefixed corpus
  (below). The `txs=` count both report is identical to the unit — a built-in
  cross-check that they walked the same transactions.
- **Identical scope.** The decode steps above are the same on both sides; the
  READMEs and the source comments pin the scope so neither side does extra work.
  Each side folds its decoded values into a sink (`std::hint::black_box` on the
  Rust side, a live `sink` field on the java side) so the optimizer / JIT cannot
  dead-code-eliminate the work being measured.
- **I/O excluded.** The corpus is read into an in-memory list **before** the
  timer starts; the timed loop only decodes already-resident bytes.
- **JIT warmup excluded (java).** The JVM runs warmup decode passes (default 3)
  that are **not** timed, so HotSpot has JIT-compiled the parse/unpack hot
  methods before the measured passes (default 3, averaged) run. The Rust side
  is AOT-compiled (release build), so it needs no warmup. This is the standard,
  honest way to compare a JIT runtime against an AOT one.
- **Same machine, run separately.** Each runner pins one core; run them in
  series, not concurrently.

## Corpus

The corpus is a stream of `[int32 big-endian length][Block protobuf bytes]` in
ascending block order — the same format the `replay-blocks` apply path reads.
The bytes are canonical `Block` wire encodings (`Block.toByteArray()`), so both
engines decode the **identical bytes**; the `txs=` count both report is the
built-in cross-check that they walked the same transactions.

The corpus path comes from `bench.config`'s `BLOCKS_FILE` (default
`$BENCH_WORK/corpus/blocks_<FROM>-<TO>.blocks`). It is produced **portably**, no
private cache required, in one of two ways:

- **`bootstrap.sh --only corpus`** runs [`fetch_corpus.py`](fetch_corpus.py),
  which fetches blocks `[FROM, TO]` over a **public mainnet gRPC node**
  (`Wallet.GetBlockByNum2`, which returns the full `Block` message) via
  [`grpcurl`](https://github.com/fullstorydev/grpcurl) and writes them
  length-prefixed. Override the endpoint with `--endpoint host:port`.
- **Supply your own** with `--blocks FILE` / `BLOCKS_FILE` — any
  length-prefixed `Block` stream works. The decode dimension is optional, so
  the suite tolerates a missing corpus and prints how to provide one.

Both engines load the **first `--count` blocks** (default `DECODE_COUNT` =
10,000) so a full run is a few minutes at most; the prefix is identical for
both, byte-for-byte.

## Result schema

Each runner writes `bench/results/decode-<engine>.json`:

| key | meaning |
| --- | --- |
| `dimension` | always `"decode"` |
| `engine` | `"ours"` or `"java"` |
| `version` | git short SHA (ours) / java-tron build tag@sha (java) |
| `blocks` | blocks decoded in one pass |
| `txs` | transactions decoded in one pass (must match across engines) |
| `blocks_per_sec` | `blocks / elapsed` (per single decode pass) |
| `txs_per_sec` | `txs / elapsed` (per single decode pass) |
| `peak_rss_mb` | peak resident memory of the decode process (MiB) |
| `notes` | exact decode scope + JIT-warmup note (java) + RSS caveat |

Both runners print a single machine-parseable line the scripts scrape:

```
bench-decode: blocks=N txs=M elapsed_s=S blocks_per_sec=.. txs_per_sec=..
```

## Reproduction

Bootstrap once (builds the node + vanilla java-tron jar, and fetches the corpus
if `grpcurl` is available):

```sh
bench/bootstrap.sh
```

Then run each side (from the repo root):

```sh
bench/decode/ours.sh --count 10000
bench/decode/java.sh --count 10000
```

Each emits `bench/results/decode-<engine>.json`. `java.sh` compiles
`java/DecodeBench.java` against the vanilla jar on first run (and whenever the
source changes) into `java/classes/` (gitignored).

Common flags:

```sh
bench/decode/ours.sh --count 50000                 # bigger sample
bench/decode/java.sh --count 50000 --warmup 5 --measured 5
bench/decode/ours.sh --blocks /path/to/other.blocks --out /tmp/decode
```

The `ours` engine uses the release `tron-node`
(`tron-node bench-decode --blocks FILE --count N`). The `java` engine uses the
**vanilla** java-tron jar `bootstrap.sh` built into `BENCH_WORK` (or whatever
`JAVA_TRON_JAR` points at), under the JDK resolved from `JDK8_HOME`/`JAVA_HOME`.
All paths come from `bench/bench.config` (override `BLOCKS_FILE`, `JAVA_TRON_JAR`,
`JDK8_HOME`, `DECODE_XMX`, ...).

## Caveats

- **Peak RSS is not apples-to-apples.** The JVM runs with a fixed pre-allocated
  heap (`-Xms=-Xmx`, default `4g` for this microbench), so its `peak_rss_mb`
  reflects the configured heap, not the working set the decode actually needs.
  The native process allocates on demand and its RSS is the true working set.
  Treat the RSS figure as "footprint under each engine's normal configuration,"
  not "minimum memory each could survive on." (`XMX` is overridable.)
- **JIT warmup matters for java.** A measured pass with too few warmup passes
  reports a JIT-cold number. The defaults (3 warmup / 3 measured) are enough for
  this hot loop; raise `--warmup` if you suspect a cold compile.
- **Single run, natural variance.** Each number is one process invocation. The
  java side averages several timed passes; the Rust side times one pass over the
  in-memory corpus. Expect run-to-run variance from scheduler noise and (java)
  GC. Re-run for a distribution.
- **First-contract decode only.** Both sides decode the **first** contract of
  each transaction (TRON transactions carry exactly one contract in practice);
  the scope is identical on both sides, so this is fair, but it is a deliberate
  scoping choice, not "decode literally everything in the block."
- **Same prefix, not the whole corpus by default.** `--count` decodes the
  leading N blocks. Both engines use the same N over the same file, so the
  comparison is exact for whatever N you pick.

## Files

| file | role |
| --- | --- |
| `ours.sh` | runs `tron-node bench-decode`, samples RSS, writes `decode-ours.json` |
| `java.sh` | compiles + runs `DecodeBench`, samples RSS, writes `decode-java.json` |
| `java/DecodeBench.java` | vanilla-java-tron decode microbench (source) |
| `java/classes/` | compiled output (gitignored; rebuilt by `java.sh`) |
| `fetch_corpus.py` | portable corpus fetcher (public gRPC node via `grpcurl`) |
| `README.md` | this file |

The shared sampler/JSON-escape helpers come from `bench/lib.sh`; the `ours`
decode-only path is the `tron-node bench-decode` subcommand
(`crates/tron-node/src/replay.rs::bench_decode`, reusing the production
`decode_tx_summary`). The decode-dimension JSON schema differs from the
apply-dimension schema (no block range / `wall_clock_s`), so each runner writes
its JSON directly rather than via `bench_emit_json`.
