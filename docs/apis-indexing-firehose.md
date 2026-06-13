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

Enable:

```toml
[index]
enable = true
capture_state_deltas = true
```

Archive endpoints:

```text
GET  /v1/archive/account?address=...&block=H
GET  /v1/archive/accountresource?address=...&block=H
POST /v1/archive/triggerconstantcontract
```

Archive reads use recorded per-key versions rather than replay. Coverage starts
when state-delta capture is enabled; it cannot reconstruct earlier deleted
state.

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
