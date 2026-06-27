# Architecture

`tron-goblin-node` is a Rust workspace implementing a TRON full node with
byte-exact database and wire compatibility as the long-term goal. The node is
not a wrapper around java-tron: it reimplements protocol, storage, execution,
networking, RPC, indexing, and operational tooling in Rust.

## Core Invariants

- Block hashes must match the canonical chain for applied blocks.
- RocksDB state layout must remain compatible with java-tron snapshots.
- Serial and Block-STM execution must commit byte-identical state.
- Reorg handling must restore every mutated store before applying the winning
  branch.
- TRON headers do not include a state root, so state parity must be verified by
  RPC-level diffing, not only block-hash comparison.

## Workspace Layers

| Layer | Crates | Responsibility |
| --- | --- | --- |
| Protocol primitives | `tron-crypto`, `tron-proto`, `tron-types` | Hashing, signatures, generated protobuf types, block IDs, tx IDs, Merkle roots, capsule/domain wrappers. |
| Storage | `tron-chainbase` | Per-store codecs over RocksDB-compatible backends, sessions, snapshots, rollback support. |
| Execution | `tron-actuator`, `tron-executor`, `tron-tvm`, vendored `revm-*` | Contract-type validation/execution, block orchestration, TVM/EVM execution, TRON precompiles, energy/resource logic. |
| Consensus | `tron-consensus` | DPoS scheduling, witness checks, maintenance periods, fork choice helpers. |
| Networking | `tron-net`, `tron-node/src/sync.rs`, `inbound.rs`, `fetch_block.rs` | P2P framing, discovery, peer sync, inbound serving, fetch scheduling. |
| Node runtime | `tron-node` | Daemon, config, store opening, services, sync loop, metrics, snapshots, admin commands. |
| APIs | `tron-rpc`, `tron-grpc` | Ethereum-compatible JSON-RPC, TRON REST wallet endpoints, gRPC Wallet/Database/Monitor/Network surfaces. |
| Mempool and production | `tron-mempool`, `tron-node/src/sr_runtime.rs`, `pbft_runtime.rs` | Admission validation, persistence, relay, SR block production, PBFT vote runtime. |
| Indexing and events | `tron-index`, `tron-eventer`, `tron-eventer-kafka`, firehose consumer crates | Address history, archive deltas, event/log triggers, durable firehose and reference sinks. |
| Tools | `tron-wallet`, `tron-state-diff`, `tron-replay`, `tron-snapshot-convert` | Key/signing CLI, RPC parity diffing, block stream replay/testing, java-tron LevelDB→RocksDB snapshot conversion. |

The vendored `revm-*` crates are patched at the workspace root so all downstream
uses resolve to local forks. Those forks carry TRON-specific interpreter/context
extensions such as TRC-10 transfer fields and extended opcodes.

## Runtime Flow

1. `tron-node start` loads `NodeConfig`, opens `data_dir/db/`, initializes
   genesis if required, and starts configured services.
2. The P2P layer discovers or dials peers, completes TRON handshakes, and elects
   an active sync path while other peers remain available for failover and
   cooperative fetching.
3. Blocks are decoded and validated, then applied through `tron-executor`.
4. Contract actuators mutate chainbase sessions. Smart-contract execution routes
   into `tron-tvm` and the patched revm stack.
5. Commit hooks update mempool state, index rows, firehose entries, metrics,
   event subscribers, head pointers, and reorg undo records.
6. RPC, REST, gRPC, index, archive, and metrics servers serve reads from the
   committed state and secondary indexes.

## Data Layout

The configured `data_dir` defaults to `./tron-data`. The consensus database is
under `data_dir/db/`, where each java-tron chainbase store is represented as its
own RocksDB instance. Secondary data such as the built-in index lives outside
the consensus stores, for example `data_dir/index/`. The firehose log uses its
own retention-managed directory under `data_dir/firehose/`.

The address-history index is disposable because it can be rebuilt from block and
transaction stores. Archive state deltas are not disposable: coverage begins
only when `[index] capture_state_deltas = true` is enabled, and deleting the
archive restarts coverage at the then-current head.

## Reorg Model

The default reorg path uses undo records in `BlockUndoStore`. When a better
sibling branch overtakes the local branch, the node rolls back losing blocks,
restores mutated stores and head pointers, re-pushes reverted transactions into
the mempool, then applies the winning branch. The alternative snapshot overlay
path is available behind `[storage] snapshot_reorg = true` and is best treated
as a testing path until validated at mainnet scale.

## Observability

The runtime emits structured logs through `tracing`, writes rotating logs, and
serves Prometheus metrics on the configured metrics host and port. Metrics cover
head/sync status, peers, mempool, RPC methods, indexer lag, archive coverage,
firehose sequence/unwind counts, SR production, and PBFT activity.
