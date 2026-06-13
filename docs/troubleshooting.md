# Troubleshooting

## Build Cannot Find `protoc`

Install protobuf compiler and confirm:

```sh
protoc --version
```

Then rerun the Cargo command.

## Build Cannot Find `libclang`

`rocksdb` depends on bindgen through `librocksdb-sys`, which needs libclang.
Run:

```sh
./scripts/setup-libclang.sh
```

The script creates a shim path used by `.cargo/config.toml`.

## RocksDB Reports Too Many Open Files

Each chainbase store is its own RocksDB instance. The effective descriptor
pressure is roughly `[storage].max_open_files` multiplied by the number of
stores. Lower the config value or raise the process file descriptor limit.

## Imported Snapshot Fails With RocksDB/LevelDB Errors

The node supports RocksDB snapshots only. A java-tron LevelDB database can fail
with SST/property errors and must be converted with java-tron tooling before
import.

## Snapshot Import Reports Cross-Store Inconsistency

The source was probably copied while java-tron was running. Re-import from a
consistent stopped snapshot, or use `import-live` if copying from a running
RocksDB primary is required.

## Sync Stalls or Has Poor Peer Quality

Try explicit peers, enable mainnet seeds, and verify outbound TCP connectivity
to port `18888`:

```sh
./target/release/tron-node start \
  --data-dir ./mainnet-data \
  --peer HOST:18888 \
  --mainnet-seeds
```

For controlled LAN testing against one java-tron node:

```sh
./scripts/sync-from-peer.sh HOST:18888 --max-blocks 100000
```

Increase logs while investigating:

```sh
RUST_LOG=tron_node=debug,info ./target/release/tron-node start --data-dir ./mainnet-data
```

## Other Peers Cannot Sync From This Node

Check:

- `[p2p] listen = true`
- `advertise_port` is non-zero and reachable.
- Firewall/NAT forwards TCP `18888`.
- `listen_host` is not restricted to localhost for public serving.

## RPC, REST, gRPC, or Metrics Calls Fail From Another Machine

The default bind host for these services is `127.0.0.1`. Set the relevant
service host to `0.0.0.0` only on a trusted network or behind appropriate
controls:

```toml
[rpc]
host = "0.0.0.0"

[http]
host = "0.0.0.0"

[grpc]
host = "0.0.0.0"

[metrics]
host = "0.0.0.0"
```

## Constant Calls Fail

Set `[vm] support_constant = true`. Both the Rust node and the java-tron
reference node need constant-call support when using
`tron-state-diff --constant`.

If calls run but are cut off, review `[vm] max_energy_limit_for_constant` and
`constant_call_timeout_ms`.

## Index History Is Missing for Older Blocks

TRC20/internal history backfill needs transaction-info in the source stores. If
older snapshots lack that data, native history can still index while richer
history begins from newly applied blocks.

Also check `[index] scope` and any explicit `capture_*` overrides. Event search
requires `scope = "all"` or `capture_logs = true`.

## Archive Reads Are Missing for Old Heights

Archive coverage starts when `[index] capture_state_deltas = true` is first
enabled. It cannot backfill historical state deltas that were not recorded.

## State Diverges But Block Hashes Match

This is possible on TRON because headers do not commit state roots. Use
`tron-state-diff` against java-tron at a common head, and include constant-call
probes for TVM-sensitive changes.
