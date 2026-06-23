# Configuration

The node uses TOML configuration. [config.example.toml](../config.example.toml)
is the best starting point because every key is annotated and set to its
built-in default.

## Precedence

1. Built-in defaults from `NodeConfig`.
2. Values loaded from `--config FILE`, or from `./config.toml` when that file
   exists and no explicit `--config` was supplied.
3. CLI flags such as `--data-dir`, `--rpc-port`, `--peer`, and `--no-sync`.

Unknown config keys are accepted and ignored so migrated configs can carry
extra values during experimentation. Many java-tron camelCase aliases are also
accepted, but the file format itself is TOML rather than java-tron's HOCON.

## Important Sections

### Root

`data_dir` controls where node state is stored. The consensus database lives
under `<data_dir>/db/`.

### `[storage]`

Controls RocksDB lifecycle and reorg implementation. High-impact keys:

- `write_buffer_size_mb`: per-store memtable size; multiplied across many
  stores.
- `max_open_files`: per-store open-file cap; process-wide pressure is roughly
  this value times the number of stores.
- `compact_on_start`: run a full manual compaction on startup.
- `snapshot_reorg`: switch from undo-log reorg handling to snapshot-overlay
  reorg handling for testing.

`[storage.db_settings]` and `[storage.tx_cache]` parse several java-tron
compatibility knobs. Some are currently accepted for round-tripping but not
applied to the open path; check the comments in `config.example.toml` before
assuming a key is wired.

### `[p2p]`

Controls discovery, outbound sync, inbound serving, and peer persistence.

- `peers`: explicit `HOST:PORT` peers.
- `use_mainnet_seeds`: mix built-in seeds into an explicit peer set.
- `discover_enable`: enable UDP discovery.
- `discover_tree_urls`: DNS discovery trees walked at startup.
- `advertise_port`: port announced in handshakes and used for inbound listener.
- `listen`: accept inbound peers and serve sync protocol.
- `progress_log_interval`: sync progress heartbeat interval.
- `disabled`: run without the P2P sync loop.

#### Live dashboard modes (decode-only)

These run a self-bootstrapping node that discovers the live tip, follows it, and
decodes traffic for a terminal dashboard — without executing, persisting, or
snapshotting. Usually set via the matching CLI flag rather than the config file.

- `explore` (CLI `--explore`): live dashboard of **confirmed** blocks — each
  block's transactions decoded as they arrive.
- `mempool` (CLI `--mempool`): live dashboard of the **pending** transaction
  stream — the txs peers are broadcasting before any SR mines them. Each is
  decoded on arrival (TRX / USDT transfers, contract calls with method names)
  and folded into running stats: arrival rate, pending USDT/TRX volume, hottest
  contracts and methods, pending DEX swaps, time-in-mempool, and whale alerts —
  MEV / ops visibility java-tron does not expose. In this mode the state-aware
  mempool validator is skipped (the node carries no real account state), so the
  raw pending stream is surfaced as-is.
- `mempool_json` (CLI `--mempool-json PATH`): with `mempool`, also write one
  JSON object per pending tx to `PATH` (`-` for stdout) for downstream tooling.
  Each line: `{txid, ts, signer, type, to, amount_sun, usdt_units, contract,
  method, expiration}`.

In a dashboard mode, node logs are routed to the file sink only so they don't
clobber the terminal UI (check `logs/tron-node.log` for errors).

### `[rpc]`, `[http]`, `[grpc]`, `[metrics]`

Configure bind hosts, ports, and disable flags for served interfaces.

Defaults bind RPC, REST, gRPC, and metrics to `127.0.0.1`. Expose them
deliberately: HTTP REST and gRPC include writer/broadcast methods.

### `[vm]`

Controls TVM behavior and java-tron VM compatibility switches. The most
operator-visible keys are:

- `support_constant`: required for `eth_call`, `triggerconstantcontract`, and
  TVM parity probing with `tron-state-diff --constant`.
- `max_energy_limit_for_constant`: per-call energy ceiling for constant calls.
- `constant_call_timeout_ms`: optional wall-clock timeout for constant calls.
- `pipelined_apply`: overlaps commit/fsync work with the next block during bulk
  sync without changing committed write order.

### `[index]`

Enables built-in address history, event search, archive state deltas, and
backfill behavior.

- `enable = true`: create and serve the address-history index.
- `scope`: choose native-only, TRC20, or full event search coverage.
- `stream`: follow canonical head or PBFT-solidified blocks.
- `capture_state_deltas = true`: record per-block write-set versions for
  historical archive reads.
- `[index.backfill] start_height`: bound rebuild/backfill range for capacity.
- `[index.firehose] enable = true`: enable durable firehose stream.
- `[index.firehose] retain_mb`: firehose retention budget.

The index can be rebuilt from node stores. Archive coverage cannot be backfilled
for heights before capture was enabled.

### `[witness]`

Configures Super Representative block production. Without this section the node
is sync-only. Prefer `key_env` or a keystore over inline private keys.

```toml
[witness]
key_env = "TRON_WITNESS_KEY"           # env var holding the raw private-key hex
# keystore = "/path/to/keystore.json"  # alternative: java-tron-compatible v3 keystore
# keystore_password_env = "TRON_KEYSTORE_PASSWORD"
max_txs_per_block = 1000               # mempool txs pulled per produced block
```

Provide the signing key by exactly one method. See
[Security and Production Readiness](security-production.md#key-management) for
key-handling guidance.

### Event Subscription

The event subscription config mirrors java-tron logsfilter concepts and can
emit block, transaction, contract event, and contract log triggers to configured
listeners such as Kafka.

## Safe Defaults for Local Evaluation

For a local node that syncs but does not expose public writer APIs:

```toml
data_dir = "./tron-data"

[p2p]
listen = false

[rpc]
host = "127.0.0.1"

[http]
host = "127.0.0.1"

[grpc]
host = "127.0.0.1"

[metrics]
host = "127.0.0.1"
```

Enable indexing only when you need history APIs or firehose output; it adds disk
and backfill work.
