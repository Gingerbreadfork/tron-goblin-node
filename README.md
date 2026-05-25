# <img src="goblin.svg" width="48" alt="" valign="middle"> Tron Goblin Node

A Rust implementation of the [TRON](https://tron.network) full-node
protocol — the same role java-tron plays, written from scratch in
Rust with byte-exact database and wire compatibility as a stated
goal.

> **Status: pre-release, experimental.** The protocol stack syncs
> blocks from live mainnet peers and applies them into RocksDB
> chainbase state. Reorg-driven state rollback, long-running mainnet
> soak, and a few smaller polish items still need work. See
> [Status](#status) below for specifics. This is **not** a drop-in
> production replacement for java-tron today — though that is the
> goal.


## What this is

`tron-goblin-node` is a workspace of small, focused crates that
reproduce java-tron's behaviour piece by piece. The goal is one
binary you can point at a peer and have it stay in lockstep with the
java-tron reference implementation — same hashes, same state roots,
same RPC responses.

Concretely, this means:

- **Byte-exact RocksDB compatibility.** A java-tron snapshot can be
  planted under `data_dir/db/` with `tron-node import-snapshot`,
  and the daemon picks up where the java node left off.
- **Wire-compatible P2P.** The TRON adv-broadcast protocol
  (`HelloMessage`, `BlockInventory`, `Inventory`, `FetchInvData`,
  `Block`, `Trx`) is implemented at the byte level. A
  `tron-goblin-node` instance hand-shakes with a java-tron mainnet
  peer and pulls real blocks.
- **java-tron API surface.** JSON-RPC (`eth_*` + `wallet/*`) and
  gRPC (Wallet / WalletSolidity / Database / Monitor / Network) are
  both served. TronWeb, the Java SDK, and TronGrid clients can
  point at this node without modification.

## Motivation

This node exists because of [**trongoblin.com**](https://trongoblin.com).

Running production infrastructure on TRON means living downstream of
java-tron — its release cadence, its operational quirks, its
resource profile. A second independent implementation in a different
language is the cheapest way to harden the ecosystem: divergences
get surfaced as bugs instead of silently propagating, snapshot and
RPC paths get a second set of eyes, and operators get a node they
can actually profile, debug, and tune without fighting a JVM.

## Status

What works today:

- ✅ Crypto vertical slice: secp256k1, SM2 (via pure-Rust
  `sm2` crate), keccak256, ripemd160, sha256, base58check.
- ✅ Proto / wire / types layer — produces hashes identical to
  java-tron for blocks and transactions across the live chain.
- ✅ Block import: decode + validate + execute live mainnet blocks
  into per-store RocksDB state.
- ✅ Actuator dispatch: full coverage of java-tron's contract types
  (Transfer, AssetTransfer, Exchange*, FreezeBalance*, Witness*,
  Proposal*, TriggerSmartContract, CreateSmartContract, …).
- ✅ TVM phase 1: precompile registry + energy model + Sapling
  shielded-TRC-20 (Groth16 proving) wired into the prover service.
  Phase 2 (full EVM-interpreter integration) tracks the revm fork.
- ✅ JSON-RPC + REST: the `eth_*` surface that java-tron exposes
  plus the `/wallet/*` REST endpoints, backed by chainbase reads.
- ✅ gRPC server on the Wallet / WalletSolidity / Database / Monitor
  / Network services — no `Status::unimplemented` stubs left.
- ✅ Mempool with signer recovery + dedup + expiration eviction +
  on-disk persistence (java-tron's pending queue is volatile;
  `tron-goblin-node` reloads pending txs across restarts).
- ✅ Snapshot import / export (`import-snapshot`, `import-live`,
  `export-snapshot`, `verify-snapshot`) for moving state to and
  from a java-tron data directory.
- ✅ Multi-batch peer sync: `SyncBlockChain` → drain queue →
  re-request → transition to live-tip `BlockInventory` advertise
  mode at head. Pipelined with rate-limit + keepalive parity.
- ✅ SR block production: when `[witness]` is configured, the
  daemon runs java-tron's `DposTask` loop — slot ownership check,
  drain mempool, produce + sign + apply + broadcast.
- ✅ PBFT vote runtime: Prepare → Commit → solidify state machine
  driven off the SR runtime; signatures persist to
  `PbftSignDataStore` and `LATEST_SOLIDIFIED_BLOCK_NUM` advances.
- ✅ Snapshot-stack reorg primitives in chainbase
  (`SnapshotManager`-style overlay layers, revoked on reorg) — the
  storage layer is ready for runtime-driven rollback.
- ✅ Prometheus `/metrics` endpoint (`--metrics-port`, default 9090)
  exposes ~29 metrics across chain head, sync flow, reorg / fork-tree
  outcomes, SR block production, PBFT message traffic, mempool
  (size + accepted + evicted + rejected-by-reason labels), active
  peers, and per-method RPC counters.

What doesn't work yet (real, currently-open gaps):

- ❌ **Automatic reorg-driven state rollback in the sync path.**
  When a sibling fork overtakes the canonical head, the node
  detects it and warns loudly but doesn't yet rebuild head — the
  snapshot-stack primitives are wired in chainbase, but the sync
  driver doesn't pull the trigger. See `tron-node/src/sync.rs:1483`.
- ❌ **Long-running mainnet soak / endurance.** Short live sessions
  pass; multi-hour, multi-day stability under realistic peer churn
  hasn't been characterized.
- ❌ **Probably a number of other things.** java-tron is large
  and old; some quirks will only surface when a specific client or
  workload hits them. This list will be updated as new items are
  discovered.

## Tests & metrics

Parity work that doesn't have a test pinning it isn't real parity —
java-tron's behaviour is too nuanced to maintain by inspection
alone. So coverage is **dense**: every actuator branch, every RPC
shape, every chainbase encoding has at least one test that fails if
the byte layout drifts.

| Metric | Count |
| --- | --- |
| Workspace tests passing | **1837** |
| Ignored (gated on Sapling proving, ~50 MB params + 1–2 s each) | 9 |
| Test binaries | 151 |
| Integration test files (`crates/*/tests/`) | 106 |
| Source modules with `#[cfg(test)]` blocks | 62 |

Per-crate breakdown of the test surface (where coverage lives is
where parity risk lives):

| Crate | Tests | Crate | Tests |
| --- | ---: | --- | ---: |
| `tron-actuator`  | 300 | `tron-net`      |  50 |
| `tron-rpc`       | 285 | `tron-types`    |  43 |
| `tron-tvm`       | 278 | `tron-crypto`   |  34 |
| `tron-node`      | 272 | `tron-mempool`  |  22 |
| `tron-chainbase` | 166 | `tron-wallet`   |  22 |
| `tron-executor`  |  86 | `tron-eventer`  |  14 |
| `tron-consensus` |  84 | `tron-replay`   |   6 |
| `tron-grpc`      |  62 | `tron-proto`    |   5 |

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
  `crates/tron-grpc/tests/create_shielded_*.rs`. Run with
  `cargo test --release -- --ignored`.
- **Deliberate java-tron deviations**: each of the ~handful of
  intentional behaviour gaps (e.g. `createtransaction`
  permissiveness, `getaccount` unknown-address shape) has a
  test that asserts our shape and references the java-tron site
  it diverges from.

What coverage **doesn't** include yet:

- End-to-end reorg-driven state rollback under live conditions —
  the snapshot-stack primitives are unit-tested, but the sync-path
  trigger that drives them on a sibling-fork overtake is the open
  gap (see Status above).
- Long-running soak / load tests against mainnet snapshots. Manual
  for now; CI integration is on the observability backlog.

The whole sweep (default + ignored) finishes in under 90 s on a
modern laptop:

```sh
cargo test --workspace --release -- --include-ignored
```

## Layout

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
| [`tron-executor`](crates/tron-executor) | Block-level orchestrator. Validates structure, applies txs via the actuator dispatch table. |
| [`tron-consensus`](crates/tron-consensus) | DPoS slot scheduling, witness validation, maintenance period, fork choice. |
| [`tron-tvm`](crates/tron-tvm) | TRON precompiles + energy model. Phase 1 of the TVM port. |
| [`tron-rpc`](crates/tron-rpc) | Ethereum-compatible JSON-RPC server backed by chainbase. |
| [`tron-grpc`](crates/tron-grpc) | gRPC (Wallet / WalletSolidity / Database / Monitor / Network). Wraps `tron-rpc`. |
| [`tron-eventer`](crates/tron-eventer) | Event subscribe / logsfilter — per-block, per-tx, per-contract-event/log triggers. |
| [`tron-wallet`](crates/tron-wallet) | Key management + transaction signing CLI. Reads java-tron-compatible v3 keystores. |
| [`tron-replay`](crates/tron-replay) | CLI for generating + validating length-delimited TRON block streams. |
| [`tron-node`](crates/tron-node) | Full-node daemon binary — opens stores, runs RPC, syncs blocks. |

Four `revm-*` crates are vendored forks needed to plug TRON's
TRC-10 transfer fields and the five TRON-extended opcodes
(`0xd0..0xd4`) into revm's CALL machinery without re-implementing
gas accounting and journal logic. All other revm crates come from
crates.io unchanged.

## Build

Prerequisites:

- **Rust 1.80+**. Stable toolchain is fine.
- **Protoc**. Used by `tron-proto`'s build script. `protoc --version`
  should print `3.x` or `5.x`.
- **libclang**. Pulled in transitively by `rocksdb` → `librocksdb-sys`
  → `bindgen`. On Fedora / RHEL / Arch without the `clang` meta-package
  you'll need to create a `libclang.so` symlink — run the shim
  script once after cloning:

  ```sh
  ./scripts/setup-libclang.sh
  ```

  The script is idempotent and auto-detects the highest-versioned
  `libclang` on the host (Debian / Ubuntu / macOS paths included).
  `.cargo/config.toml` points `LIBCLANG_PATH` at the shim directory
  it creates.

Then:

```sh
cargo build --release
```

The full workspace compiles in ~3–5 minutes on a modern machine.
Tests:

```sh
cargo test --workspace            # 1800+ tests, all defaults
cargo test --workspace --release -- --ignored
                                  # adds 9 Sapling-proving tests
                                  # (~50 MB Groth16 params + 1-2s each)
```

## Run

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
./scripts/sync-from-peer.sh 192.168.0.36:18888 --max-blocks 100000
```

Run with `--help` for all options.

To plant a java-tron snapshot first (skip the genesis-walk and start
from a recent state):

```sh
./target/release/tron-node import-snapshot \
    --from ./path/to/java-tron-snapshot.tar.gz \
    --data-dir ./mainnet-data
```

`tron-node --help` lists every subcommand with its flags.

Configuration is **TOML**, not java-tron's HOCON — config files are
intentionally not drop-in. State directories are byte-exact
compatible; runtime config is its own surface.

## Compatibility notes

- **Database**: byte-exact, per-store RocksDB layout. A java-tron
  snapshot is a `tron-node` data directory after `import-snapshot`.
- **P2P**: byte-exact handshake + adv-broadcast. The node identifies
  itself on the wire as `tron-goblin/0.0.1`.
- **JSON-RPC + gRPC**: response shapes match java-tron's. Deliberate
  deviations (e.g. `createtransaction` permissiveness, `getaccount`
  on unknown addresses) are pinned in tests and documented at the
  call site.
- **Config**: TOML, not HOCON. Pull settings explicitly when porting
  from a java-tron `config.conf`.

## Reference implementation

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

## Acknowledgements

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
- **[`eth_trie`](https://crates.io/crates/eth_trie)** — Ethereum
  Merkle-Patricia-Trie semantics for the account-state-root path
  TRON inherits from Ethereum.
- **[tracing](https://github.com/tokio-rs/tracing)** — structured
  logging across every crate.

If you maintain a crate we depend on and you're not listed here,
that's an oversight — please open an issue and we'll fix it.

## License

LGPL-3.0-or-later. See [`LICENSE`](LICENSE).

This matches java-tron's license. If you redistribute a modified
version, the LGPL's source-availability terms apply to the modified
crates.
