# Security and Production Readiness

`tron-goblin-node` is pre-release software. Public or production-like use should
be deliberate: run it behind normal infrastructure controls, compare it against
java-tron, and keep a rollback path.

## Readiness Checklist

Before relying on a node for critical workflows:

- Build from a known commit and record that commit in deployment metadata.
- Import or initialize data on persistent storage with enough free space for
  RocksDB compaction and enabled indexes.
- Keep REST, JSON-RPC, gRPC, and metrics bound to localhost unless access is
  explicitly controlled.
- Expose only TCP P2P port `18888` for public peer service by default.
- Run `cargo test --workspace` for the deployed commit, plus targeted tests for
  any local patches.
- Compare against a java-tron reference using `tron-state-diff` for the accounts
  and contracts relevant to your workload.
- Monitor sync height, peer count, mempool, RPC errors, index lag, archive
  coverage, firehose sequence, disk space, file descriptors, and process
  restarts.
- Keep a java-tron fallback or another known-good data source for rollback.
- Test restore from snapshot or backup before treating backups as usable.

## Network Exposure

Default service binds are intentionally conservative:

| Surface | Public by default? | Notes |
| --- | --- | --- |
| P2P `18888` | Yes, when `[p2p] listen = true` | Needed for serving blocks to peers. |
| JSON-RPC `8545` | No | Includes read APIs and Ethereum-compatible calls. |
| REST `/wallet/*` `8090` | No | Includes transaction broadcast/writer methods. |
| gRPC `50051` | No | Includes wallet service methods. |
| Metrics `9090` | No | Can reveal topology, load, and operational state. |

If RPC, REST, gRPC, or metrics must be reachable off-host, put them behind a
trusted network boundary, reverse proxy, firewall allowlist, VPN, or other
access control. This repository does not provide built-in authentication for
those surfaces.

## Key Management

Witness block production requires signing material. Prefer:

- `key_env` for environment-provided private keys.
- `keystore` plus `keystore_password_env` for encrypted key material.

Avoid committing private keys, `.env` files, keystores, or passwords. Avoid
inline `key_hex` outside throwaway development environments.

## Snapshot and Backup Safety

- The node runs on **RocksDB only** — there is no LevelDB backend.
  `import-snapshot` takes RocksDB snapshots; a java-tron LevelDB snapshot must
  be converted to RocksDB first with `tron-snapshot-convert` (a one-time
  migration, not a runtime backend).
- Stop the source node before ordinary filesystem copies.
- Use `import-live` when copying from a running RocksDB primary.
- Run `verify-snapshot` after manual copies or restored backups.
- Do not tar a live `data_dir/db/` and assume it is consistent.

The built-in address-history index is disposable and can be rebuilt. Historical
archive state deltas are not: coverage starts when enabled, and deleting the
archive restarts coverage at the current head.

## Operational Monitoring

At minimum, alert on:

- Head lag increasing or no new blocks applied.
- Peer count dropping to zero or repeated sync failover.
- Disk free space approaching compaction danger.
- File descriptor exhaustion.
- RPC 5xx/error-rate spikes.
- Index backfill or live cursor lag growing unexpectedly.
- Firehose consumers approaching retention limits.
- Reorg/unwind spikes beyond expected network behavior.

Use `RUST_LOG=info` for normal operation and targeted debug logging during
incident investigation. Avoid leaving broad `debug` logging on indefinitely in
high-volume deployments.

## Upgrade and Rollback

For public deployments, use a staged rollout:

1. Build and test the new commit.
2. Run it on a copied or disposable data directory if the change touches
   storage, execution, sync, or indexing.
3. Compare state and constant-call behavior against java-tron.
4. Snapshot or back up the previous known-good data before switching.
5. Keep the previous binary and config available for rollback.

Changes to consensus storage, execution, config defaults, index format, and
firehose format deserve extra caution because they can affect data
compatibility or downstream consumers.
