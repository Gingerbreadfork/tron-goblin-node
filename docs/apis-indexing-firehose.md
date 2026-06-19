# APIs, Indexing, and Firehose

`tron-goblin-node` serves several compatibility surfaces from one process.

## JSON-RPC

The `tron-rpc` crate provides Ethereum-compatible JSON-RPC methods such as
`eth_*` and `net_*`, backed by chainbase state and TVM constant execution.
Default bind: `127.0.0.1:8545`.

Important config:

- `[rpc] chain_id`: returned by `eth_chainId` and `net_version`.
- `[rpc] eth_call_gas_cap`: maximum gas for `eth_call` and estimation paths.
- `[vm] support_constant`: required for read-only smart-contract calls.

### Developer and debug methods

Beyond the standard `eth_*` reads, the JSON-RPC surface exposes two
developer tools java-tron does not provide. Both require
`[vm] support_constant = true` (they re-execute through the TVM).

- **`debug_traceTransaction`** (and `debug_traceBlockByNumber` /
  `debug_traceBlockByHash`, which trace each contained transaction):
  geth-style structured trace of a TVM transaction — per-opcode
  `StructLog` plus the CALL/CREATE frame tree. Standard `tracer` /
  `disableStack` / `disableMemory` / `disableStorage` options are
  honored. When the historical-state archive
  (`[index] capture_state_deltas = true`) covers the transaction's block
  boundary, the trace re-executes against the state **as-of that height**
  rather than current state, so it reflects what the transaction actually
  did. A `tracedAtHeight` field reports the height used, or `null` when
  current state was used (no archive, height not covered, or a
  non-VM transaction). Granularity is the block boundary — it ignores the
  effects of earlier transactions within the same block, which is exact
  for the common single-VM-call-per-target case.
- **`estimateEnergy`**: returns the estimated `energy_required` and, in
  an `energy_breakdown` object, where that energy goes — energy by opcode
  (top 15), the call-frame tree with per-frame energy, and, if the call
  would fail, the halting opcode and reason. The breakdown is best-effort:
  if the tracer cannot run, the total estimate is still returned.

## TRON REST Wallet API

The HTTP REST surface provides java-tron-compatible `/wallet/*` endpoints used
by TronWeb and TronGrid-style clients. Default bind: `127.0.0.1:8090`.

Examples:

```sh
curl -s -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8090/wallet/getnowblock \
  -d '{}'
```

Writer endpoints such as transaction broadcast are available on this surface.
Keep it on localhost or behind explicit access controls.

## gRPC

The `tron-grpc` crate serves Wallet, WalletSolidity, Database, Monitor, and
Network services on the java-tron-compatible gRPC API. Default bind:
`127.0.0.1:50051`.

The implementation wraps the same underlying RPC and chainbase handlers used by
the HTTP surfaces where practical.

## Built-In TronGrid-Compatible Index

Enable:

```toml
[index]
enable = true
scope = "trc20"
```

Served on the HTTP REST port:

```text
GET /v1/accounts/{address}/transactions
GET /v1/accounts/{address}/transactions/trc20
GET /v1/accounts/{address}/transactions/trc721
GET /v1/accounts/{address}/transactions/internal
GET /v1/contracts/{address}/events
```

Common query parameters mirror TronGrid, including `limit`, `fingerprint`,
`only_from`, `only_to`, `only_confirmed`, `only_unconfirmed`,
`min_timestamp`, `max_timestamp`, `order_by`, and `contract_address`.

The index backfills automatically from existing block stores and follows live
head after catching up. It is reorg-aware and can resume after restart. If the
index directory is deleted, the node rebuilds it.

## Historical Archive

Answer "what was account/contract X at block N?" and run read-only contract
calls against state as of block N. Enable:

```toml
[index.archive]
enabled = true              # implies [index] capture_state_deltas
mode    = "rolling"         # bounded window (default) | "full"
```

Archive endpoints (served on the HTTP REST port):

```text
GET  /v1/archive/account?address=...&block=H
GET  /v1/archive/accountresource?address=...&block=H
POST /v1/archive/triggerconstantcontract     (standard body + "block": H)
```

Archive reads use recorded per-key versions rather than replay (one seek per
read). Coverage starts at the current head when capture is first enabled; it
cannot reconstruct earlier state. The feature is storage-heavy and off by
default. Full configuration, disk-cost sizing, curl examples, and caveats:
[Historical-State Archive](historical-state-archive.md).

## Verifiable State Commitment

Give the node a cryptographic state root (which TRON headers do not provide),
serve offline-verifiable inclusion/exclusion proofs, and self-check that the
node is byte-exact with the canonical chain. Enable:

```toml
[index.commitment]
enabled = true              # implies [index] capture_state_deltas; off by default
```

Commitment endpoints (served on the HTTP REST port):

```text
GET      /v1/commitment/root      — current state root + committed height
GET      /v1/commitment/status    — committed/head heights, confirmation lag, bootstrap
GET|POST /v1/commitment/proof     — inclusion/exclusion proof for a store + key
```

The root is history-independent, so two independently-bootstrapped nodes at
the same committed height compute the byte-identical root. It is not
consensus-critical and runs off the apply hot path, so `committed_height`
trails head past finality. Independent of `[index.archive]`. Full
configuration, the offline proof-verification recipe, the integrity
self-check workflow, and the phase-2 roadmap (historical at-height proofs,
on-chain anchoring — not yet shipped):
[Verifiable State Commitment](verifiable-state-commitment.md).

## Firehose

Enable:

```toml
[index]
enable = true

[index.firehose]
enable = true
```

The firehose is a durable append-only stream of applied blocks plus explicit
`UNWIND` entries for reorgs and crash recovery. External consumers tail the
`tronfirehose.Firehose/Tail` gRPC stream and resume by sequence number.

Reference consumers:

- `tron-firehose-postgres`: writes to a Postgres explorer schema.
- `tron-firehose-nats`: republishes entries to NATS JetStream with sequence
  deduplication.
- `tron-firehose-clickhouse`: writes analytics tables in ClickHouse.

Build and run a consumer with Cargo, for example:

```sh
DATABASE_URL=postgres://USER:PASSWORD@HOST/DB \
TRON_FIREHOSE_URL=http://127.0.0.1:50051 \
  cargo run --release -p tron-firehose-postgres

NATS_URL=nats://127.0.0.1:4222 \
TRON_FIREHOSE_URL=http://127.0.0.1:50051 \
  cargo run --release -p tron-firehose-nats

CLICKHOUSE_URL=http://127.0.0.1:8123 \
TRON_FIREHOSE_URL=http://127.0.0.1:50051 \
  cargo run --release -p tron-firehose-clickhouse
```

Replace uppercase placeholders with deployment-specific values. The consumers
are configured by environment variables; check each consumer's `src/main.rs`
module docs for optional variables and idempotence semantics when wiring
production pipelines.
