# <img src="goblin.svg" width="48" alt="" valign="middle"> Tron Goblin Node

[![Test Suite](https://github.com/Gingerbreadfork/tron-goblin-node/actions/workflows/test-suite.yml/badge.svg)](https://github.com/Gingerbreadfork/tron-goblin-node/actions/workflows/test-suite.yml) [![License](https://img.shields.io/github/license/Gingerbreadfork/tron-goblin-node)](LICENSE) ![Rust](https://img.shields.io/badge/rust-1.80%2B-orange) ![Tests](https://img.shields.io/badge/tests-2711%20passing-brightgreen) [![Stars](https://img.shields.io/github/stars/Gingerbreadfork/tron-goblin-node?style=social)](https://github.com/Gingerbreadfork/tron-goblin-node/stargazers)

A Rust implementation of the [TRON](https://tron.network) full-node
protocol — the same role java-tron plays, written from scratch in
Rust with byte-exact database and wire compatibility as a stated
goal.


## 🧌 What is this?

`tron-goblin-node` is a workspace of small, focused crates that
reproduce java-tron's behaviour piece by piece, alongside some additional tooling.

The goal is to have it stay in lockstep with the
java-tron reference implementation by producing the same hashes, same state, same
RPC responses, just with better performance, lighter hardware requirements, and features the TRON community frequently requests that are not yet supported by java-tron itself.

## ✨ Highlights

- Sync from genesis or a get caught up fast with a RocksDB snapshot
- Convert multi-TB java-tron LevelDB archive snapshots to RocksDB without needing 2× the disk — the node itself is RocksDB-only
- Block-STM parallel execution enables syncing to be several times faster than java-tron (enabled by default)
- Byte-exact RocksDB + bidirectional P2P (pick right up where java-tron left off)
- Built-in TronGrid cross-compatible indexer + historical state archive (both optional to suit your needs)
- ERC-4337 bundler + eth_simulateV1 (full account-abstraction bundler including ERC-7562 validation and reputation throttling)
- Self auditing and diagnostic tools
- Borderline excessive test coverage (2500+ tests)
- Full node functionality - **not a tech demo**


## ⚡ Watch real TRON mainnet live!
Want to just have some fun without diving in head first?

No snapshot, no 100 GB backfill, no hours of syncing. Run one command and
within seconds you're watching the **real** TRON mainnet stream into your
terminal with live blocks every ~3s, every transaction decoded and classified
into a self-updating dashboard:

```sh
./try.sh
```

```text
🧌 TRON GOBLIN  ·  MAINNET LIVE FEED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📅 2026-06-15 10:53:15 UTC      block #83,617,153
  🟢 LIVE    ⚡ 283 TPS · peak 341    📦 0.4 blk/s · 🔗 20 peers
  🔐 46 blocks verified ✓  tx Merkle root recomputed = network's
  🔑 46 producer sigs recovered  33 direct · 13 delegated key (cold/hot SR)
  ⏱ 2m 10s · 📦 46 blocks · 🌐 2,513 peers found (DNS+Kad) · 2 serving
  block sizes ▂▃▃▂▁█▆▁▅▁▂▃▂▂▃▂▅▂▃▃▄▃▂▅▂▄▇▅▄▄  (txs/block, last 30)
  ── THIS SESSION ──────────────────────────────────────────────
   🔄 transactions 26,247          👛 active wallets 10,318
   💵 TRX moved 770K               💚 USDT volume $75.60M
   📜 contract calls 6,101         💸 USDT transfers 5,933
   🪙 token transfers 3,537        🗳 votes+stakes 3,670
   🚀 busiest block 844 txs        🐋 biggest USDT $7.00M
  ── TX MIX ────────────────────────────────────────────────────
   ▪ TRX 33%  ▪ USDT 22%  ▪ tokens 13%  ▪ other 30%   🔧 transfer 96%
  ── PRODUCERS · live SR rotation ─────────────────────────────
   🏛 TQzd66b…SPPZ ×2   TQhuVjZ…PkEX ×2   TSMC4Yz…Bk2E ×2  · 27 of 27 SRs
  ── BLOCK STREAM ──────────────────────────────────────────────
   ▸ #83,617,153  629 tx · 160 USDT $1.90M · 3,136 TRX
   ▸ #83,617,152  615 tx · 161 USDT $1.00M · 11,512 TRX
   ▸ #83,617,151  660 tx · 173 USDT $1.16M · 18,181 TRX
  ── MILESTONES ────────────────────────────────────────────────
   🐋 Whale: $7.00M USDT in a single transfer
   🚀 Heavy block: 844 txs in 3 seconds
```

This is **not** a mock, it's the genuine TRON peer-to-peer protocol. The node
finds peers on its own (the DNS tree + Kademlia DHT — no hardcoded seed list),
learns the current tip straight from them, and follows the live block tail,
decoding every block itself: no chain state, no execution, no database, which
is why it starts in seconds.

And it isn't just *reading* the chain — it's **checking** it. For every block it
independently recomputes the transaction Merkle root and confirms it matches the
one the network committed (proving it hashes transactions byte-for-byte like
java-tron), and it recovers the producer's signature — even spotting the SRs
that sign with a delegated cold/hot key. USDT dollar amounts come straight out
of the real contract calldata.

Pin a peer with `./try.sh --peer HOST:18888`. It runs on a throwaway temp
directory and an isolated RPC port, and cleans up after itself. No API keys, no
external services — just a release build (`cargo build --release`, or drop a
`tron-node` binary next to the script).

If you're just exploring, find this kind of stuff cool, or are simply screwing around a bit, this is for you.

### See the mempool too: pending txs before they're mined

`--explore` shows *confirmed* blocks. Swap in `--mempool` and the same
self-bootstrapping node instead watches the **pending** transaction stream —
the txs peers are broadcasting right now, before any SR has mined them:

```sh
tron-node start --mempool
```

Each pending tx is decoded the instant it arrives (TRX / USDT transfers,
contract calls with method names) and folded into a live dashboard: arrival
rate, pending USDT/TRX volume, the hottest contracts and methods, pending DEX
swaps, time-in-mempool, and whale alerts. That's MEV / ops visibility (front-run
candidates, large transfers landing, contract hotspots) that java-tron does not
expose. Add `--mempool-json <path>` (or `-` for stdout) to also stream one JSON
object per pending tx for tooling. Decode-only, like `--explore` — no execution,
no state, no snapshot.


Concretely, this means:

- **Byte-exact RocksDB compatibility.** A java-tron snapshot can be
  planted under `data_dir/db/` with `tron-node import-snapshot`,
  and the daemon picks up where the java node left off.
- **Wire-compatible P2P, both directions.** The TRON adv-broadcast
  protocol (`HelloMessage`, `BlockInventory`, `Inventory`,
  `FetchInvData`, `Block`, `Trx`) is implemented at the byte level. A
  `tron-goblin-node` instance hand-shakes with java-tron mainnet peers
  and pulls real blocks — and, as a full peer, it also **listens for
  inbound connections** and serves the sync protocol, so other nodes
  (java-tron included) can sync *from* it.
- **java-tron API surface.** JSON-RPC (`eth_*` + `wallet/*`) and
  gRPC (Wallet / WalletSolidity / Database / Monitor / Network) are
  both served. TronWeb, the Java SDK, and TronGrid clients can
  point at this node without modification.

## 👀 See it for yourself

A block hash commits to the full header **and** the transaction Merkle
root — so if a node's block hash matches the network's, every transaction
in that block executed to the same result. Sync this node against mainnet,
then compare its own independently-computed block hashes against the
official `trongrid.io` API for the most recent blocks:

```sh
CT='-H Content-Type:application/json'
H=$(curl -s $CT -X POST http://127.0.0.1:8091/wallet/getnowblock -d '{}' | jq .block_header.raw_data.number)
for N in $(seq $((H-6)) $((H-2))); do
  O=$(curl -s $CT -X POST http://127.0.0.1:8091/wallet/getblockbynum -d "{\"num\":$N}" | jq -r .blockID)
  T=$(curl -s $CT -X POST https://api.trongrid.io/wallet/getblockbynum  -d "{\"num\":$N}" | jq -r .blockID)
  [ "$O" = "$T" ] && echo "✔ #$N  $O" || echo "✘ #$N  MISMATCH"
done
```

```text
✔ #83425584  0000000004f8f930899faeaa52baa520eded6c93d36fb9a384d77f978817664f
✔ #83425585  0000000004f8f93133171bdd150fab96f1fffc78894c4c21d25b1d39d491e158
✔ #83425586  0000000004f8f932d13f30de9fc5856ca13ca21d34ef7080ac5195fdce0c9c5d
✔ #83425587  0000000004f8f9339d1953474fac8c5fb3ce6fd7c9d31dba40ce05eb7830792a
✔ #83425588  0000000004f8f934a8d80f6d0164af2e9c2086e2af088e09a378a4cfa9238ebd
```

Matching the header and tx-merkle root is only half the story, though —
TRON headers commit to no state root, so the resulting *state* is verified
separately (see [Compatibility notes](#compatibility-notes)). That
distinction is the whole reason this project is careful about the word
"parity."

## 💡 Motivation

This project exists because of [**trongoblin.com**](https://trongoblin.com).

Running production infrastructure on TRON means living downstream of
java-tron — its release cadence, its operational quirks, its
resource profile. A second independent implementation in a different
language is the cheapest way to harden the ecosystem: divergences
get surfaced as bugs instead of silently propagating, snapshot and
RPC paths get a second set of eyes, and operators get a node they
can actually profile, debug, and tune without fighting a JVM.

...and it's just kinda fun to make this all work.

## 🚦 Status

> [!WARNING]
> While a lot of effort has gone into making this as functional and bug-free as possible, a project of this scope will inevitably have some rough edges. If you're powering a project with it, you should at minimum keep a java-tron node as a fallback, and not trust it with anything mission-critical. Bug reports from real use are exactly how it gets hardened, so if you do run it, please send them.

`tron-goblin-node` imports, validates, and executes
live mainnet blocks into **byte-exact** RocksDB state, syncs off public
mainnet up to the live tip and tracks head-of-chain, produces blocks as an
SR, and serves java-tron's full API surface — plus developer tooling
java-tron doesn't have.What works today, by area:

### ⚙️ Consensus & execution

- **Block execution** — decode + validate + execute live mainnet blocks
  into per-store RocksDB state, with full actuator coverage of
  java-tron's contract types (Transfer, AssetTransfer, Exchange\*,
  FreezeBalance\*, DelegateResource\*, Witness\*, Proposal\*, Trigger/CreateSmartContract, …).
- **Block-STM parallel execution** (`vm.parallel_exec`) — transactions
  execute optimistically across cores with MVCC conflict tracking,
  re-running only those that conflict, for a result **byte-identical to
  the serial loop** (pinned by equivalence tests — TRON has no state root,
  so a silent divergence would otherwise be invisible). Transaction-heavy
  blocks apply faster on many cores — **1.3×** on a moderate SSTORE-heavy
  block, scaling toward the core count as per-tx VM work grows past the
  MVCC overhead; light blocks stay serial.
- **TVM** — revm-based interpreter with TRON's energy schedule, the TRC-10
  transfer fields, the TRON opcodes (`0xd0..0xd4`), the per-contract
  dynamic-energy model, and Sapling shielded-TRC-20 (Groth16) proving.
  Read-only (`triggerconstantcontract`) results for tested TRC-20s (USDT
  and others) match java-tron **byte-for-byte**, and energy accounting
  tracks java-tron closely enough that every transaction's
  success / out-of-energy / revert outcome held block-for-block across the
  half-million-block replay.
- **Consensus self-audit watchdog** — every transaction's computed
  success/failure is cross-checked against the block's canonical
  `contractRet` (the only divergence signal a stateless-root chain gives
  you) and exported as a Prometheus counter, so an operator can alert the
  instant the node stops agreeing with the chain.
- **SR block production & PBFT** — with `[witness]` configured, runs
  java-tron's `DposTask` loop (slot check → drain mempool →
  produce/sign/apply/broadcast) plus the Prepare → Commit → solidify vote
  runtime that advances the irreversible block.
- **Reorg-driven rollback** — a sibling-fork overtake rolls the losing
  branch's state back per-block, re-applies the winner, and re-pushes
  reverted txs to the mempool, recovering atomically on failure and never
  crossing the irreversible block. Two backends: undo-store (default) and
  a snapshot overlay (`storage.snapshot_reorg`).

### 🌐 Networking & mempool

- **Public-mainnet sync** — java-tron-style block-locator + pipelined
  fetch with rate-limit/keepalive parity. A single **active syncer** is
  elected across a per-peer driver fleet (the rest stand by and fail over),
  and fetch is **cooperative** — many peers fill a shared pool in parallel
  while one driver applies in chain order. Live-validated catching a
  multi-day backlog off public mainnet and holding the tip.
- **Inbound serving** — binds the P2P port and completes the responder
  handshake, serving `SyncBlockChain` → inventory and `FetchInvData` →
  blocks, so other nodes (java-tron included) can sync *from* it.
- **Validating mempool** — signer recovery + dedup + expiration eviction +
  on-disk persistence (pending txs survive restarts, unlike java-tron's
  volatile queue), with **state-aware admission** — the same
  fee/permission/balance/ref-block and contract `Trigger`/`Create`
  precondition checks a peer runs on receive, so we don't relay
  transactions a peer would reject.

### 💾 State, storage & snapshots

- **Byte-exact RocksDB state** — per-store key/value layout identical to
  java-tron; a java-tron data directory *is* a `tron-node` data directory
  after `import-snapshot`.
- **Snapshot tooling** — `import-snapshot`, `import-live`,
  `export-snapshot`, and `verify-snapshot` move state to and from a
  java-tron RocksDB data directory. A separate `tron-snapshot-convert`
  binary converts a java-tron **LevelDB** snapshot (what most full-history
  archive snapshots ship as) into this node's RocksDB format, deleting each
  source store as it converts so peak disk stays near 1× — and it can stream
  straight from a download.
- **Historical-state archive** (`[index.archive]`) — every block's
  committed write-set recorded as per-key versions, so `getaccount` /
  `getaccountresource` / `triggerconstantcontract` resolve **at any
  covered height** in one seek (no replay), constant calls included.
  Rolling-window or full retention; see
  [docs/historical-state-archive.md](docs/historical-state-archive.md).
- **Verifiable state commitment** (`[index.commitment]`) — an opt-in
  Sparse Merkle Tree (keccak256) over committed state, giving the node a
  **cryptographic state root** TRON headers don't provide, offline
  inclusion/exclusion proofs (`/v1/commitment/*`), and a history-independent
  root so two independently-bootstrapped nodes prove they hold byte-identical
  state by comparing one hash. Off by default, off the hot path; see
  [docs/verifiable-state-commitment.md](docs/verifiable-state-commitment.md).

### 🔌 APIs & compatibility

- **Crypto & wire parity** — secp256k1, SM2 (pure-Rust), keccak256,
  ripemd160, sha256, base58check; the proto/types layer produces block and
  transaction hashes identical to java-tron across the live chain.
- **JSON-RPC + REST + gRPC** — the `eth_*` JSON-RPC surface, the
  `/wallet/*` REST endpoints, and the Wallet / WalletSolidity / Database /
  Monitor / Network gRPC services (no `Status::unimplemented` stubs left).
- **Built-in address-history indexer** (`[index] enable`) —
  TronGrid-compatible
  `/v1/accounts/{address}/transactions[/trc20|/trc721|/internal]` plus
  `/v1/contracts/{address}/events`, served from the node's own stores (no
  external indexer, no API keys). Auto-backfills head-first (recent history
  queryable within seconds), reorg-reconciled, restart-resuming, and
  disposable. Same query params as TronGrid — a drop-in for existing
  TronWeb history code.

### 🛠️ Developer & operator tooling

- **Time-travel transaction tracer** — geth-style `debug_traceTransaction`
  (and `debug_traceBlockByNumber` / `ByHash`) re-execute a transaction
  through a per-opcode structured tracer **against the historical state
  as-of the tx's block** when the archive covers it (not "re-run against
  latest"), reporting which height was used. java-tron has no `debug_trace*`
  surface at all.
- **Explainable energy estimates** — `estimateEnergy` returns the total
  *plus* a breakdown: energy by opcode, the CALL/CREATE frame tree with
  per-frame energy, and the exact halting op + reason when a call would run
  out — "why it costs X / why it would OOG", which java-tron's bare number
  omits.
- **Batch transaction simulation** — `eth_simulateV1`, go-ethereum's
  multi-block simulation API and java-tron's single most-requested missing
  method, runs sequences of calls across one or more synthetic blocks with
  optional balance and block (`number` / `time`) overrides, returning each
  call's status / return data / gas / logs. State **accumulates** across
  calls and blocks against an overlay that is never committed — as
  side-effect-free as `eth_call`, never touching canonical state.
  Unsupported override modes are rejected with an explicit error rather
  than silently mis-simulated.
- **ERC-4337 account-abstraction bundler** (`[bundler]`) — the standard
  bundler RPC namespace (`eth_sendUserOperation`,
  `eth_estimateUserOperationGas`, `eth_getUserOperationByHash`,
  `eth_getUserOperationReceipt`, `eth_supportedEntryPoints`), the smart-account
  / gasless-UX infrastructure layer TRON otherwise lacks. Each UserOperation is
  validated against live state through the constant-call VM, accepted into an
  in-memory mempool, and **batched** — many ops per `handleOps` — by a background
  loop (`auto` mode) or on demand (`manual` mode via the `debug_bundler_*`
  control methods); the node signs, submits (auto-relayed by the mempool), and
  tracks each for the by-hash / receipt queries. A bad op is dropped from a
  bundle by its `FailedOp` index so it can't wedge the rest. **ERC-7562
  validation rules** reject ops that use banned (non-deterministic / unsafe)
  opcodes during validation — traced via a non-committing validation simulation
  — and **reputation** throttles then bans accounts / factories / paymasters
  that flood the mempool with ops that never get included. **Off-protocol** — a
  bundled op is an ordinary contract call on the same byte-exact TVM, so it adds
  zero consensus risk (additive, like `eth_simulateV1`). userOpHash, validation,
  and gas estimation are all delegated to the *deployed* EntryPoint via
  simulation, so it stays version-agnostic (v0.6 / v0.7 / v0.8). java-tron has no
  bundler. See
  [docs/apis-indexing-firehose.md](docs/apis-indexing-firehose.md#erc-4337-bundler).
- **Firehose** (`[index.firehose]`) — a durable, append-only stream of
  applied blocks (decoded transfer facts, TRC20 logs, internal txs) with
  explicit `UNWIND` entries for reorgs and crash recovery, tailed over gRPC
  (`tronfirehose.Firehose/Tail`, resume by sequence). Postgres, NATS
  JetStream, and ClickHouse reference consumers ship in-workspace.
- **Prometheus `/metrics`** (`--metrics-port`, default 9091) — chain head,
  sync flow, reorg/fork-tree outcomes, SR/PBFT traffic, mempool (with
  reject-reason labels), peers (incl. inbound peers syncing *from* us),
  per-method RPC counters, the consensus watchdog, and indexer / archive /
  firehose health.

## 🧪 Tests & metrics

Parity work that doesn't have a test pinning it isn't real parity —
java-tron's behaviour is too nuanced to maintain by inspection
alone. So coverage is **dense**: essentially every actuator branch, every RPC
shape, every chainbase encoding has at least one test that fails if
the byte layout drifts.

| Metric | Count |
| --- | --- |
| Workspace tests passing | **3230** |
| Ignored — live-network (6), Sapling Groth16 proving (5), perf/diagnostic (7) | 18 |
| Integration test files (`crates/*/tests/`) | 150 |
| Source modules with `#[cfg(test)]` blocks | 150 |

Per-crate breakdown of the test surface (where coverage lives is
where parity risk lives):

| Crate | Tests | Crate | Tests |
| --- | ---: | --- | ---: |
| `tron-node`      | 419 | `tron-types`     |  74 |
| `tron-actuator`  | 432 | `tron-net`       |  78 |
| `tron-rpc`       | 414 | `tron-index`     | 126 |
| `tron-tvm`       | 682 | `tron-crypto`    |  40 |
| `tron-chainbase` | 303 | `tron-mempool`   |  30 |
| `tron-executor`  | 191 | `tron-wallet`    |  23 |
| `tron-consensus` | 134 | `tron-eventer`   |  16 |
| `tron-grpc`      |  67 | `tron-firehose-*`|  10 |
| `tron-proto`     |  13 | `tron-replay`    |   8 |

These crates account for 3,054 of the 3,224 passing tests. The remaining
170 are the four vendored `revm-*` forks (136) and the `tron-state-diff` /
`tron-snapshot-convert` tooling crates (34).

Notable test categories:

- **Behaviour-pinned against java-tron**: actuator validate/execute
  paths, hash and signing vectors, RocksDB key encodings, RPC
  response shapes, energy / bandwidth accounting.
- **Live mainnet observation**: peer handshake, adv-broadcast
  framing, and block-application tests run against captured live
  fixtures (see `crates/tron-net/tests/live_mainnet.rs`,
  `crates/tron-node/tests/live_tip_observation.rs`).
- **Shielded proving**: `#[ignore]`-gated Groth16 round-trips for
  mint / transfer / burn under
  `crates/tron-grpc/tests/create_shielded_*.rs`. Run just these with
  `cargo test -p tron-grpc --release -- --ignored` (workspace-wide
  `--ignored` also pulls in the live-network tests).
- **Deliberate java-tron deviations**: each of the ~handful of
  intentional behaviour gaps (e.g. `createtransaction`
  permissiveness, `getaccount` unknown-address shape) has a
  test that asserts our shape and references the java-tron site
  it diverges from.

The default suite finishes in under 90 s on a modern laptop:

```sh
cargo test --workspace --release
```

The 18 "ignored" tests are opt-in: 5 Sapling Groth16 round-trips (load the
embedded ~50 MB params and run real proofs), 6 live-network tests (dial
real mainnet peers / DNS / Kad — need outbound connectivity), and 7
perf/diagnostic probes. Add `-- --include-ignored` to run them too.

## 🧩 Layout

The workspace is split into one crate per concern. java-tron's modules
are big, monolithic Java packages; this repo flattens them out so each
crate is something you can hold in your head.

| Crate | Role |
| --- | --- |
| [`tron-crypto`](crates/tron-crypto) | secp256k1 / SM2 / keccak / ripemd / sha256 / base58check. |
| [`tron-proto`](crates/tron-proto) | Protobuf message types. Wire-compatible with java-tron. |
| [`tron-types`](crates/tron-types) | Capsule wrappers over `tron-proto` — hash, id, merkle-root conventions. |
| [`tron-chainbase`](crates/tron-chainbase) | Storage: per-store key/value codecs over a pluggable KV backend. |
| [`tron-net`](crates/tron-net) | Wire framing + message types for the TRON P2P protocol. |
| [`tron-mempool`](crates/tron-mempool) | Validating mempool: decode + signer recovery + dedup + expiration. |
| [`tron-actuator`](crates/tron-actuator) | Per-contract `(validate, execute)` pairs — reproduces java-tron actuator semantics. |
| [`tron-executor`](crates/tron-executor) | Block-level orchestrator. Validates structure, applies txs via the actuator dispatch table — serial or Block-STM parallel. |
| [`tron-consensus`](crates/tron-consensus) | DPoS slot scheduling, witness validation, maintenance period, fork choice. |
| [`tron-tvm`](crates/tron-tvm) | TRON precompiles + energy model + revm-based contract execution. |
| [`tron-rpc`](crates/tron-rpc) | Ethereum-compatible JSON-RPC server backed by chainbase. |
| [`tron-grpc`](crates/tron-grpc) | gRPC (Wallet / WalletSolidity / Database / Monitor / Network). Wraps `tron-rpc`. |
| [`tron-eventer`](crates/tron-eventer) | Event subscribe / logsfilter — per-block, per-tx, per-contract-event/log triggers. |
| [`tron-index`](crates/tron-index) | Built-in address-history indexer: extraction rules, backfill/follow engine, query layer for the `/v1` history + event-search API, the versioned-KV historical-state archive, and the firehose segment log. |
| [`tron-wallet`](crates/tron-wallet) | Key management + transaction signing CLI. Reads java-tron-compatible v3 keystores. |
| [`tron-replay`](crates/tron-replay) | CLI for generating + validating length-delimited TRON block streams. |
| [`tron-node`](crates/tron-node) | Full-node daemon binary — opens stores, runs RPC, syncs blocks. |

Three `tron-firehose-*` crates (`-postgres`, `-nats`, `-clickhouse`)
are standalone reference consumers for the firehose stream — never
linked into the node; each runs its own codegen over the same
`firehose.proto` the node serves, so they build (and can be vendored)
independently.

Four `revm-*` crates are vendored forks needed to plug TRON's
TRC-10 transfer fields and the five TRON-extended opcodes
(`0xd0..0xd4`) into revm's CALL machinery without re-implementing
gas accounting and journal logic. All other revm crates come from
crates.io unchanged.

## 🦀 Build

Prerequisites:

- **Rust 1.80+**. Stable toolchain is fine.
- **Protoc**. Used by `tron-proto`'s build script. `protoc --version`
  should print `3.x` or `5.x`.
- **libclang**. Pulled in transitively by `rocksdb` → `librocksdb-sys`
  → `bindgen`, which loads it *dynamically* at build time (the
  `bindgen-runtime` feature), so the versioned `libclang.so.NN` every
  distro ships is found automatically — no symlink or shim needed. Just
  install your platform's package: `clang-devel`/`llvm-devel` (Fedora /
  RHEL), `libclang-dev` (Debian / Ubuntu), `clang` (Arch), or `brew
  install llvm` (macOS). If it lives somewhere non-standard, point
  `LIBCLANG_PATH` at the directory containing it.

Then:

```sh
cargo build --release
```

The full workspace compiles in ~3–5 minutes on a modern machine, and the full test suite runs in ~5 minutes.
Tests:

```sh
cargo test --workspace            # 3230 tests, all defaults
cargo test --workspace --release -- --include-ignored
                                  # + 18 opt-in: Sapling proving (~50 MB
                                  # Groth16 params), live-network, diagnostics
```

## 🚀 Run

Initialise a data directory:

```sh
./target/release/tron-node init --data-dir ./mainnet-data
```

Start the daemon against the mainnet seed peers:

```sh
./target/release/tron-node start \
    --data-dir ./mainnet-data \
    --rpc-port 8545
```

Or against a specific peer:

```sh
./target/release/tron-node start \
    --data-dir ./mainnet-data \
    --peer 18.221.130.41:18888
```

If you have your own java-tron node on the LAN and want a clean
sync-from-genesis test against just that peer (no public-mainnet
noise), there's a wrapper script that handles fresh-data-dir setup,
TCP reachability pre-flight, log capture, and a post-run summary:

```sh
./scripts/sync-from-peer.sh <your-node-host>:18888 --max-blocks 100000
```

Run with `--help` for all options.

By default the node is a **full peer**: it listens on the P2P port
(`18889` by default — java-tron's `18888` + 1) and serves blocks to nodes that sync *from* it, in addition to
dialing peers to sync itself. For other peers to actually reach you, that
port must be open through your firewall / NAT (port-forward). To run as a
firewalled, outbound-only sync client instead, set `[p2p] listen = false`.

To plant a java-tron snapshot first (skip the genesis-walk and start
from a recent state):

```sh
./target/release/tron-node import-snapshot \
    --from ./path/to/java-tron-snapshot.tar.gz \
    --data-dir ./mainnet-data
```

> **`import-snapshot` expects a RocksDB snapshot.** This node is
> RocksDB-only — there is no LevelDB backend — so a java-tron **LevelDB**
> snapshot (`db.engine = LEVELDB`, the older default) won't open directly:
> RocksDB reads LevelDB SSTs only partially (`Cannot find Properties block
> from file` in the logs) and can crash trying to rewrite them. Either use a
> RocksDB snapshot (`db.engine = ROCKSDB`), or convert a LevelDB one with the
> bundled **`tron-snapshot-convert`**, which rewrites each store into RocksDB
> and deletes the source as it goes (so you don't need 2× the disk) and can
> stream a download straight in:

```sh
# convert a LevelDB snapshot dir in place — each source store is deleted as it
# converts, so peak disk stays near 1x
tron-snapshot-convert --from ./java-tron-leveldb-snapshot --data-dir ./mainnet-data

# or pipe the download straight in — the full (multi-TB) source never lands
curl -s <snapshot-url> | tron-snapshot-convert --stream --gzip --data-dir ./mainnet-data
```

`tron-node --help` lists every subcommand with its flags.

Configuration is **TOML**, not java-tron's HOCON — config files are
intentionally not drop-in. State directories are byte-exact
compatible; runtime config is its own surface. A fully-annotated
starting point ships at [`config.example.toml`](config.example.toml)
(every key set to its built-in default); copy it and pass it with
`--config`.

## 🔍 Indexer, historical state & firehose

The node can be its own TronGrid: a built-in indexer serves address
history, NFT transfers, internal transactions, and contract events from
the node's own stores — self-hosted, no API keys, no external indexing
stack. Enable it in the config:

```toml
[index]
enable = true            # address-history index + /v1 API
scope  = "trc20"         # native | trc20 (default) | all (adds event search)

[index.archive]
enabled = true           # + historical-state archive (/v1/archive); off by default
mode    = "rolling"      # bounded window (default) | "full"

[index.firehose]
enable = true            # + the external-sink stream (gRPC Tail)

[index.commitment]
enabled = true           # + verifiable state root + proofs (/v1/commitment); off by default
```

With a populated block store (e.g. right after `import-snapshot`) the
index **backfills automatically** — no command, head-first by default so
the most recent history is queryable within seconds — then follows the
live head, reconciling reorgs by hash and resuming across restarts. The
HTTP surface (same port as the REST API):

```text
GET /v1/accounts/{address}/transactions             — native + contract calls
GET /v1/accounts/{address}/transactions/trc20       — TRC20 transfers
GET /v1/accounts/{address}/transactions/trc721      — NFT transfers (extension)
GET /v1/accounts/{address}/transactions/internal    — internal txs (extension)
GET /v1/contracts/{address}/events                  — event search (scope = "all")
GET /v1/archive/account?address=…&block=H           — account state at height H
GET /v1/archive/accountresource?address=…&block=H   — bandwidth/energy at height H
GET /v1/archive/storage?address=…&slot=…&block=H    — contract storage slot at height H
GET /v1/archive/coverage                            — archive's covered block range
POST /v1/archive/triggerconstantcontract            — constant call at height H
GET /v1/commitment/root                             — current state root + height
GET /v1/commitment/status                           — committed/head heights, lag
GET|POST /v1/commitment/proof                       — inclusion/exclusion proof
```

Query params mirror TronGrid (`limit`, `fingerprint` pagination,
`only_from`/`only_to`, `only_confirmed`/`only_unconfirmed`,
`min_timestamp`/`max_timestamp`, `order_by`, `contract_address`), so
existing TronWeb / TronGrid client code points here unmodified. Event
search resolves `event_name` through the contract's on-chain ABI and
returns ABI-decoded results when the ABI is stored.

Three properties worth knowing:

- **The index is disposable.** `data_dir/index/` can be deleted at any
  time; the node re-derives it from its own stores. Scope changes and
  format-version bumps rebuild automatically (and loudly).
- **The archive is not.** `[index.archive]` records each block's
  committed write-set as per-key versions (one seek per historical
  read, no replay) — coverage starts when first enabled and cannot be
  back-filled, since deleted history isn't re-derivable. It is
  storage-heavy (rolling-window or full); sizing, curl examples, and
  caveats are in
  [docs/historical-state-archive.md](docs/historical-state-archive.md).
- **TRC20/internal backfill needs transaction-info.** Snapshots without
  `transactionRetStore` index native kinds only for pre-enable history
  (the gap is counted in metrics); once enabled, the node persists
  transaction-info for every newly-applied block.
- **The commitment layer is verifiable, not consensus-critical.**
  `[index.commitment]` maintains a keccak256 Sparse Merkle Tree over
  committed state and serves a root plus offline-verifiable
  inclusion/exclusion proofs (`/v1/commitment/*`). The root is
  history-independent, so two independently-bootstrapped nodes at the same
  committed height compute the same root — an integrity self-check that the
  node is byte-exact with the canonical chain. It runs off the hot path, so
  the committed root trails head past finality; it is independent of the
  archive and stores only the latest tree. Guide and the offline
  proof-verification recipe:
  [docs/verifiable-state-commitment.md](docs/verifiable-state-commitment.md).

The **firehose** is the push-side complement: a durable append-only log
of applied blocks (decoded transfer facts, TRC20 logs, internal txs)
with explicit `UNWIND` entries, so reorgs and crash recovery reach
consumers through one protocol. External processes tail it over gRPC
(`tronfirehose.Firehose/Tail`) resuming by sequence number; three
reference consumers ship in-workspace — `tron-firehose-postgres`
(exactly-once into an explorer schema), `tron-firehose-nats`
(JetStream bridge), and `tron-firehose-clickhouse` (analytics schema).
Format, cursor protocol, and consumer setup:
[docs/apis-indexing-firehose.md](docs/apis-indexing-firehose.md).

Every `[index]` knob is annotated in
[`config.example.toml`](config.example.toml).

## 📚 Documentation

This README is the high-level tour. Deeper, task-oriented guides live in
[`docs/`](docs/):

| Guide | For |
| --- | --- |
| [Architecture](docs/architecture.md) | The workspace layers, core invariants, and how a block flows through them. |
| [Operations](docs/operations.md) | Building, running, importing snapshots, and operating the services day to day. |
| [Configuration](docs/configuration.md) | Choosing safe runtime settings; every knob is also annotated in [`config.example.toml`](config.example.toml). |
| [Security & Production Readiness](docs/security-production.md) | The hardening checklist before exposing a node publicly. |
| [APIs, Indexing & Firehose](docs/apis-indexing-firehose.md) | The RPC / REST / gRPC surface, the `/v1` history API, archive reads, and the firehose. |
| [Historical-State Archive](docs/historical-state-archive.md) | Reading account / contract state — or running constant calls — as-of a past block. |
| [Verifiable State Commitment](docs/verifiable-state-commitment.md) | The opt-in cryptographic state root, offline proofs, and the node-equality self-check. |
| [Development](docs/development.md) | Building, testing, and validating parity when changing code. |
| [Troubleshooting](docs/troubleshooting.md) | Diagnosing common failures. |

A terser, structured set written for AI coding assistants lives under
[`docs/llm/`](docs/llm/).

## 🔄 Compatibility notes

- **Database**: byte-exact, per-store **RocksDB** layout — RocksDB-only,
  no LevelDB backend. A java-tron snapshot is a `tron-node` data directory
  after `import-snapshot`, **provided it was written with `db.engine =
  ROCKSDB`**; a LevelDB snapshot must be converted to RocksDB first with the
  bundled `tron-snapshot-convert` tool.
- **P2P**: byte-exact handshake + adv-broadcast, **inbound and
  outbound** — the node dials peers to sync and also listens on the P2P
  port (`18889` by default — java-tron's `18888` + 1; `[p2p] listen`) to serve peers that sync
  from it. Identifies itself on the wire as `tron-goblin/<version>`.
- **JSON-RPC + gRPC**: response shapes match java-tron's. Deliberate
  deviations (e.g. `createtransaction` permissiveness, `getaccount`
  on unknown addresses) are pinned in tests and documented at the
  call site.
- **Config**: TOML, not HOCON. Pull settings explicitly when porting
  from a java-tron `config.conf`.
- **State parity is verified by reads, not by block hashes.** TRON
  block headers commit to the transaction Merkle root but **not** to an
  enforced state root, so a state-computation bug can hide behind
  block hashes that are byte-for-byte identical to the reference chain.
  Parity of the resulting state is therefore checked by comparing RPC
  reads (`getaccount`, delegated-resource queries, …) against a
  java-tron node — not by hash equality alone. (This is exactly how the
  delegated-resource divergence in [Status](#status) was found.)

## 📐 Reference implementation

The `.proto` definitions needed to build are vendored at
`crates/tron-proto/vendored/java-tron/`, so a fresh clone builds
without needing the full java-tron repo on disk.

Parity work is still grounded in side-by-side reading of the java-tron
source. If you want to run that comparison yourself, clone java-tron
and `tronprotocol/documentation-en` next to this checkout —
they're gitignored on purpose so this repo stays small:

```sh
git clone https://github.com/tronprotocol/java-tron.git
git clone https://github.com/tronprotocol/documentation-en.git tronprotocol/documentation-en
```

If you want the build to consume `.proto` files from a parallel
java-tron clone instead of the vendored copy (useful when chasing a
wire-format change before re-vendoring), point both `build.rs`
scripts at it via:

```sh
export JAVA_TRON_PROTO_ROOT=$PWD/java-tron/protocol/src/main/protos
cargo build --release
```

## 🙏 Acknowledgements

This project stands on a stack of other people's hard work.
Thanks in particular to:

- **[java-tron](https://github.com/tronprotocol/java-tron)** — the
  reference implementation. Every parity decision in this repo was
  grounded by reading the Java source. Without it there is no spec
  to mirror.
- **[revm](https://github.com/bluealloy/revm)** — Dragan Rakita and
  the revm contributors. We use revm as a library and vendored four
  of its crates as forks to slot in TRON's TRC-10 transfer fields
  and the five TRON-extended opcodes (`0xd0..0xd4`) without
  reimplementing CALL's gas + journal logic.
- **[RustCrypto](https://github.com/RustCrypto)** — `k256` (the
  secp256k1 path), `sm2` (the SM2 signature path), `sha2`, `sha3`,
  `ripemd`, `ecdsa`, `elliptic-curve`. The whole crypto stack
  underneath `tron-crypto` is RustCrypto crates plus a thin TRON
  shim.
- **[Zcash / Sapling crates](https://github.com/zcash/librustzcash)**
  — `sapling-crypto`, `bls12_381`, `jubjub`, plus
  [`wagyu-zcash-parameters`](https://crates.io/crates/wagyu-zcash-parameters)
  for the embedded ~50 MB Groth16 MPC parameters. Without these, the
  shielded TRC-20 (mint / transfer / burn) prover would have been a
  multi-month project on its own.
- **[RocksDB](https://github.com/facebook/rocksdb)** and the
  [`rust-rocksdb`](https://github.com/rust-rocksdb/rust-rocksdb)
  bindings — the storage substrate every chainbase store opens
  against. java-tron's on-disk format is RocksDB; reusing the same
  engine is what makes byte-exact DB compatibility tractable.
- **[Tokio](https://tokio.rs)**, **[axum](https://github.com/tokio-rs/axum)**,
  **[tonic](https://github.com/hyperium/tonic)**, and
  **[prost](https://github.com/tokio-rs/prost)** — the async runtime,
  HTTP server, gRPC + Protobuf stack underneath every network
  surface in the node.
- **[eth_trie](https://crates.io/crates/eth_trie)** — Ethereum
  Merkle-Patricia-Trie semantics for the account-state-root path
  TRON inherits from Ethereum.
- **[tracing](https://github.com/tokio-rs/tracing)** — structured
  logging across every crate.

If you maintain a crate we depend on and you're not listed here,
that's an oversight, please open an issue and we'll fix it. Happy to give credit to the many great projects that helped give this one life.

## 🤝 Contributions

Contributions are absolutely welcome, just please take the time to validate your submissions. Using modern AI tools to help yourself contribute is fine, this project simply wouldn't be feasible without them, please just don't submit low quality junk.

## 💚 Support

This project is independent and unfunded, built from scratch to give TRON
something it has never had: a real second client. **It has currently received no funding or support from the TRON Foundation**. It's free, open-source, and
already does things the reference node can't.

If it saved you time, taught you something, or you simply want an independent
TRON client to keep existing, a donation puts that work directly back into more
parity, more features, and keeping all of it free. Even a few TRX makes a
difference.

Send TRX or any TRC-20 token, on TRON mainnet, to:

```
TKbx8NEyu41T69zgmQGbjAt1dF6o49QuNA
```

Can't spare anything but still want to help? Drop a ⭐ on this repo, it helps get more eyes on the project and is **REALLY** appreciated.

Every contribution keeps the goblin fed and the commits coming. Thank you. 🧌


## 📜 License

LGPL-3.0-or-later. See [`LICENSE`](LICENSE).

This matches java-tron's license. If you redistribute a modified
version, the LGPL's source-availability terms apply to the modified
crates.
