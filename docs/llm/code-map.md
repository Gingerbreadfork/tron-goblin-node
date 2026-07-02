# LLM Code Map

## Top-Level Files

- `Cargo.toml`: workspace members, dependency versions, local `revm-*` patches.
- `config.example.toml`: annotated runtime defaults and operator-facing config.
- `README.md`: public overview, status, build/run notes.
- `docs/`: task-oriented human docs and AI-focused context.
- `scripts/sync-from-peer.sh`: controlled sync test helper.

## Crates by Task

| Task | Start Here |
| --- | --- |
| Hash/address/signature issue | `crates/tron-crypto/src/` |
| Protobuf/message mismatch | `crates/tron-proto/`, generated types, build script |
| Block or transaction ID/root mismatch | `crates/tron-types/src/` |
| Store codec/session/rollback issue | `crates/tron-chainbase/src/` |
| Contract actuator behavior | `crates/tron-actuator/src/` |
| DPoS consensus: witness schedule, maintenance, reward, proposals, slot timing | `crates/tron-consensus/src/` (`maintenance.rs`, `proposals.rs`, `slot.rs`, `producer.rs`, `sr_epoch.rs`) |
| Block apply or Block-STM | `crates/tron-executor/src/lib.rs` |
| TVM/precompile/energy issue | `crates/tron-tvm/src/` |
| P2P framing/discovery | `crates/tron-net/src/` |
| Sync/reorg/fetch/inbound serving | `crates/tron-node/src/sync.rs`, `fetch_block.rs`, `inbound.rs`; fork-choice + reorg tree in `crates/tron-consensus/src/khaos.rs`, `fork_choice.rs` |
| Config parsing/defaults | `crates/tron-node/src/config.rs` |
| Node command-line behavior | `crates/tron-node/src/main.rs` |
| Snapshot import/export | `crates/tron-node/src/snapshot_import.rs`, `snapshot_export.rs` |
| Convert a java-tron LevelDB snapshot to RocksDB | `crates/tron-snapshot-convert/` (standalone `tron-snapshot-convert` binary; keeps the LevelDB dependency out of `tron-node`) |
| Admin DB tools | `crates/tron-node/src/admin.rs`, `main.rs` admin subcommands |
| JSON-RPC/REST behavior | `crates/tron-rpc/src/` |
| gRPC behavior | `crates/tron-grpc/src/` |
| Mempool admission/relay | `crates/tron-mempool/src/`, `crates/tron-node/src/mempool_validator.rs`, `relay.rs` |
| Address-history index | `crates/tron-index/src/`, `crates/tron-node/src/index_hook.rs` |
| Firehose log/runtime | `crates/tron-index/src/firehose_log.rs`, `crates/tron-node/src/firehose.rs` |
| Event subscription | `crates/tron-eventer/src/`, `crates/tron-node/src/event_loader.rs` |
| Wallet CLI | `crates/tron-wallet/src/bin/tron-wallet.rs` |
| State parity diff | `crates/tron-state-diff/src/main.rs`, `crates/tron-state-diff/README.md` |
| Block-stream fixtures (generate/validate; crypto+proto+types harness) | `crates/tron-replay/src/main.rs` |
| Live mainnet / mempool feed dashboards | `crates/tron-node/src/explore.rs` (`--explore`), `mempool_explore.rs` (`--mempool`) |

## Important `tron-node/src` Files

- `runtime.rs`: starts services, opens stores, wires sync/index/RPC/mempool.
- `sync.rs`: peer sync engine, fork/reorg logic, block application flow.
- `config.rs`: `NodeConfig` and nested config structs/defaults/aliases.
- `storage.rs`: store opening and database wiring.
- `snapshot_import.rs`, `snapshot_export.rs`: import/export/verify logic.
- `diag.rs`: read-only row inspection for parity debugging.
- `sr_runtime.rs`: Super Representative block production loop.
- `pbft_runtime.rs`: PBFT vote state machine.
- `resilience.rs`: runtime resilience/backoff behavior.
- `p2p_rate_limiter.rs`: P2P rate limiting.
- `node_persist.rs`: peer persistence.
- `logfmt.rs`: operational log formatting.

## Test Locations

- Unit tests are commonly colocated in crate source files.
- Integration tests live under `crates/*/tests/`.
- High-risk areas with existing integration coverage include `tron-node`,
  `tron-tvm`, `tron-index`, `tron-rpc`, and `tron-chainbase`.
