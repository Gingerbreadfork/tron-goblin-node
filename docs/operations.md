# Operations

This guide covers the practical lifecycle for building and running
`tron-goblin-node`.

For public or production-like deployments, read
[Security and Production Readiness](security-production.md) before exposing
ports or relying on this node for critical workflows.

## Prerequisites

- Rust stable, workspace MSRV 1.80 or newer.
- `protoc`, used by protobuf build scripts.
- `libclang`, required by `rocksdb` through `bindgen` (loaded dynamically at
  build time, so a normal install is discovered automatically).

If `libclang` is installed in a non-standard location, set `LIBCLANG_PATH` to
the directory containing it.

## Build and Test

```sh
cargo build --release
cargo test --workspace
```

Ignored release tests include heavier Sapling proving coverage:

```sh
cargo test --workspace --release -- --ignored
```

## First Run

For a minimal local evaluation, initialize a data directory and start with
built-in defaults:

```sh
./target/release/tron-node init --data-dir ./mainnet-data
./target/release/tron-node start --data-dir ./mainnet-data
```

Start against explicit peers:

```sh
./target/release/tron-node start \
  --data-dir ./mainnet-data \
  --peer 18.221.130.41:18888
```

By default the node listens on the TRON P2P port (`18888`) and can serve blocks
to other peers. If the host is firewalled or should not accept inbound peers,
set `[p2p] listen = false` in the config.

## Configuration File

Copy the example config and adjust only what you need:

```sh
cp config.example.toml config.toml
./target/release/tron-node start --config config.toml
```

CLI flags override config values. The config file is TOML, not java-tron's
HOCON format. Runtime config is not intended to be drop-in compatible with
java-tron, even though the RocksDB state layout is. If `./config.toml` exists
and `--config` is omitted, `tron-node start` loads it automatically.

Common first edits:

- Set `data_dir` to the intended persistent disk.
- Set `[p2p] listen = false` for an outbound-only node.
- Set `[vm] support_constant = true` if serving `eth_call`,
  `triggerconstantcontract`, or `tron-state-diff --constant`.
- Enable `[index]` only when `/v1` history, archive, or firehose output is
  needed.

## Snapshot Import and Export

Import a stopped java-tron RocksDB snapshot or tarball:

```sh
./target/release/tron-node import-snapshot \
  --from ./java-tron-snapshot.tar.gz \
  --data-dir ./mainnet-data
```

Use `--mode copy` by default. `--mode move` is faster on the same filesystem but
consumes the source. `--mode symlink` is instant but ties the destination to the
source path.

Important: `import-snapshot` expects a **RocksDB** snapshot — this node has no
LevelDB backend. To use a java-tron **LevelDB** snapshot (the older
`db.engine = LEVELDB`, and the only engine many full-history archive snapshots
ship in), convert it first with the standalone `tron-snapshot-convert` tool
(below).

### Convert a LevelDB snapshot

`tron-snapshot-convert` is a separate binary (built with the workspace, kept out
of the `tron-node` binary so its LevelDB reader never ships in the node). It
rewrites each java-tron LevelDB store into this node's RocksDB format and
**deletes each source store as it finishes**, so peak disk stays near 1× rather
than needing room for both copies at once.

```sh
# from an on-disk LevelDB snapshot directory (per-store sub-dirs); each source
# store is removed as it converts (pass --keep-source to keep them)
./target/release/tron-snapshot-convert \
  --from ./java-tron-leveldb-snapshot \
  --data-dir ./mainnet-data

# or stream a download straight in — the full (multi-TB) source never lands on disk
curl -s <snapshot-url> | ./target/release/tron-snapshot-convert \
  --stream --gzip --data-dir ./mainnet-data
```

- The conversion is a byte-faithful key-by-key copy, so a converted snapshot
  runs identically to the original. Each store is integrity-checked (key count
  + key/value byte sums) before its source is removed, and the run is crash-safe
  and resumable — a completed store carries a done-marker and is skipped on a
  re-run.
- Output is **Snappy** by default (java-tron's snapshot format — the most
  portable). `--zstd` opts into ~30% smaller output; `tron-node` reads it
  natively (it links the Zstd codec).
- Deletion is per-store (a LevelDB store can't be safely pruned mid-read); the
  `block` store is the single-largest disk high-water mark.

Copy from a running java-tron primary using RocksDB secondary opens:

```sh
./target/release/tron-node import-live \
  --from /path/to/java-tron/output-directory/database \
  --data-dir ./mainnet-data
```

`import-live` is per-store consistent rather than chain-wide consistent, so the
node may need to reconcile a small height spread on first start.

Export the local database while the node is stopped:

```sh
./target/release/tron-node export-snapshot \
  --data-dir ./mainnet-data \
  --to ./mainnet-data.tar.gz
```

Verify a copied database:

```sh
./target/release/tron-node verify-snapshot --data-dir ./mainnet-data
```

## Services and Ports

| Service | Default | Config section |
| --- | --- | --- |
| P2P | `0.0.0.0:18889` when listening | `[p2p]` |
| Ethereum JSON-RPC | `127.0.0.1:8546` | `[rpc]` |
| TRON REST wallet API | `127.0.0.1:8091` | `[http]` |
| TRON gRPC | `127.0.0.1:50052` | `[grpc]` |
| Prometheus metrics | `127.0.0.1:9091` | `[metrics]` |

Keep writer APIs bound to localhost unless the deployment has authentication,
firewalling, or a trusted network boundary. REST and gRPC include transaction
broadcast and other writer methods.

For public P2P serving, expose only the P2P port unless there is a deliberate
reason to expose RPC, REST, or gRPC.

## Storage and Resource Planning

Mainnet operation is disk and file-descriptor heavy:

- Consensus state is split across many RocksDB stores under `data_dir/db/`.
- The address-history index can be large; full mainnet history at richer scopes
  can be comparable to the base archive in size.
- Historical-state archive capture has its own write and disk cost and cannot
  be reconstructed for past heights after the fact.
- Firehose retention is bounded by `[index.firehose] retain_mb`; consumers
  behind retention must resync from a fresh source.

Use a persistent disk with enough free space for compaction headroom, backups,
and any enabled indexes. Avoid storing `data_dir` on ephemeral instance disks
unless data loss is acceptable.

## Logs

Set `RUST_LOG` for verbosity:

```sh
RUST_LOG=info ./target/release/tron-node start --data-dir ./mainnet-data
RUST_LOG=debug ./target/release/tron-node start --data-dir ./mainnet-data
RUST_LOG=tron_node=debug,info ./target/release/tron-node start --data-dir ./mainnet-data
```

At `info`, the node reports startup head, sync progress, and catch-up status.

## Monitoring and Alerting

The node exposes Prometheus metrics on `127.0.0.1:9091` by default (`[metrics]`
section, or `--metrics-port`). Scrape `/metrics` for chain head, sync flow,
reorg/fork outcomes, peer counts, per-method RPC counters, and indexer health.

The single most important alert is the **consensus self-audit watchdog**. As
each block applies, the executor cross-checks every transaction's computed
success/failure outcome against the block's canonical `contractRet`. TRON block
headers commit no state root, so this is the node's only runtime signal that its
state has silently diverged from consensus.

| Metric | Meaning |
| --- | --- |
| `tron_node_consensus_divergences_total` | Count of observed divergences since process start. **Alert on any increase** (`increase(...[5m]) > 0`). A healthy node holds this at `0`. |
| `tron_node_consensus_last_divergence_block` | Block height of the most recent divergence (for triage). |

A non-zero counter means this node disagrees with the chain on at least one
transaction outcome — treat it as a correctness incident: capture the block from
`tron_node_consensus_last_divergence_block`, and re-trace the offending
transaction with `debug_traceTransaction` against the historical archive. This
signal is emitted regardless of whether the executor's `verify_contract_ret`
mode is also set to hard-reject the divergent block, so monitoring catches a
divergence even when the node is configured to keep applying.

## Database Administration

Run admin commands only while the node is stopped unless the command explicitly
documents live-safe behavior.

```sh
./target/release/tron-node admin compact --data-dir ./mainnet-data
./target/release/tron-node admin prune-before --data-dir ./mainnet-data --before 80000000
./target/release/tron-node admin db root --data-dir ./mainnet-data
./target/release/tron-node admin db copy --src ./mainnet-data/db --dst ./copy/db
./target/release/tron-node admin db lite --src ./mainnet-data --dst ./lite-data --recent-blocks 10000
```

`admin db root` recomputes the account-state root over current account state and
contract storage. This is useful for parity investigations, even though TRON
block headers do not commit a state root.

## Parity Check

After syncing alongside a java-tron reference node, use `tron-state-diff` for
state parity checks:

```sh
cargo build --release -p tron-state-diff
./target/release/tron-state-diff \
  --a http://127.0.0.1:8091 \
  --b http://JAVA_TRON_HOST:8090 \
  --from-recent-blocks 200
```

Replace `JAVA_TRON_HOST` with the host or IP of the reference java-tron node.

## Wallet CLI

Builds with the workspace and exposes key management, keystore, signing, and
broadcast helpers:

```sh
read -r -s -p 'Wallet password: ' TRON_WALLET_PASSWORD
echo
export TRON_WALLET_PASSWORD
./target/release/tron-wallet keygen --out wallet.json
./target/release/tron-wallet address --keystore wallet.json
./target/release/tron-wallet sign --keystore wallet.json --tx 0x...
./target/release/tron-wallet send --keystore wallet.json --tx 0x... --rpc http://127.0.0.1:8091
```

Password lookup order is `--password`, `TRON_WALLET_PASSWORD`, then an
interactive prompt when stdin is a TTY. Avoid putting passwords directly in
shell history for real wallets. Replace `0x...` with the unsigned transaction
protobuf hex for the transaction you intend to sign or broadcast.
