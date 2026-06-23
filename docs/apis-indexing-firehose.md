# APIs, Indexing, and Firehose

`tron-goblin-node` serves several compatibility surfaces from one process.

## JSON-RPC

The `tron-rpc` crate provides Ethereum-compatible JSON-RPC methods such as
`eth_*` and `net_*`, backed by chainbase state and TVM constant execution.
Default bind: `127.0.0.1:8545`.

Important config:

- `[rpc] chain_id`: returned by `eth_chainId` and `net_version`.
- `[rpc] eth_call_gas_cap`: maximum gas for `eth_call`, `eth_simulateV1`, and
  estimation paths.
- `[vm] support_constant`: required for read-only smart-contract calls.

JSON-RPC is a single `POST /` on the RPC port. A standard read — call a
contract (here USDT's `decimals()`) against the latest state, and fetch the
head number:

```sh
curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
        {"to":"0xa614f803b6fd780986a42c78ec9c7f77e6ded13c","data":"0x313ce567"},
        "latest"]}'
# → {"jsonrpc":"2.0","id":1,"result":"0x0000…0006"}   (6 decimals)

curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
```

Addresses accept eth `0x…` (20-byte), TRON `41…`, or base58 `T…` form.

### Developer and debug methods

Beyond the standard `eth_*` reads, the JSON-RPC surface exposes three
developer tools java-tron does not provide. All three re-execute through the
TVM, so all require `[vm] support_constant = true`; `estimateEnergy`
additionally requires `[vm] estimateEnergy = true`.

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
- **`eth_simulateV1`**: go-ethereum-style batch simulation. The payload is
  one or more synthetic blocks, each `{ calls, blockOverrides,
  stateOverrides }`; every call returns its `status`, `returnData`,
  `gasUsed`, and `logs`. Unlike `eth_call` (single, stateless), all calls
  run against **one** in-memory overlay reused across every call and block,
  so state **accumulates** — a later call sees an earlier call's writes,
  and block N+1 sees block N's. That overlay is never committed, so this is
  exactly as side-effect-free as `eth_call`: it never touches canonical
  state. Supported overrides are `blockOverrides.{number,time}` and
  `stateOverrides.<addr>.balance`; per-call gas is capped by
  `[rpc] eth_call_gas_cap`. Modes that would otherwise be mis-simulated are
  **rejected with an explicit error** rather than silently ignored —
  `validation`, `traceTransfers`, the `code`/`state`/`stateDiff`/`nonce`
  state overrides, contract-creation calls (omitted `to`), and non-`latest`
  base blocks.

#### `debug_traceTransaction` example

The hash must be `0x`-prefixed — the REST API returns txIDs *without* it, so
prepend `0x`. Only contract (`TriggerSmartContract`) transactions can be
traced; anything else returns `-32603 cannot trace non-VM contract type …`.
The optional second param carries the standard tracer options:

```sh
curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"debug_traceTransaction","params":[
        "0x<contract-tx-hash>",
        {"disableMemory":true,"disableStorage":true}]}'
```

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": {
    "gas": 31895, "failed": false, "returnValue": "",
    "structLogs": [
      { "pc": 0, "op": "PUSH1", "gas": 13945000, "gasCost": 3, "depth": 1, "stack": [] }
    ],
    "tracedAtHeight": 64238117
  }
}
```

`tracer: "callTracer"` returns the CALL/CREATE frame tree instead of opcode
logs. `tracedAtHeight` is the archive height the trace ran against, or `null`
when current state was used (no archive, height not covered, or non-VM).

#### `estimateEnergy` example

Requires **both** `[vm] estimateEnergy = true` and `[vm] support_constant =
true`; otherwise it returns `-32600` naming the missing switch. Same call shape
as `eth_call` (eth-style `to`/`from` or TRON-style
`contract_address`/`owner_address` are both accepted):

```sh
curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"estimateEnergy","params":[
        {"to":"0x<contract>","data":"0x<selector+args>"}]}'
```

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": {
    "result": { "result": true },
    "energy_required": 31895,
    "energy_breakdown": {
      "ops_executed": 412,
      "total_unique_opcodes": 23,
      "by_opcode": [ { "op": "SSTORE", "count": 2, "energy": 40000 } ],
      "call_frames": [ { "type": "CALL", "depth": 0, "to": "0x<contract>", "energy_used": 28931, "error": null } ],
      "halt": null
    }
  }
}
```

`by_opcode` is capped at the 15 highest-energy opcodes (`total_unique_opcodes`
flags truncation); `halt` is non-null (`op` + `reason`) when the call would
fail. The breakdown is best-effort — if the tracer cannot run, `energy_required`
is still returned.

#### `eth_simulateV1` example

JSON-RPC is a single `POST /` on the RPC port (`8545` by default). This request
overrides one address's balance and then runs two calls in one synthetic block,
so the second call observes the first's writes — the accumulating behaviour
`eth_call` cannot express. `params` is `[<simulation>, "latest"]`. Addresses may
be eth `0x…` (20-byte), TRON `41…`, or base58 `T…`; `balance` is in **sun**
(no wei scaling).

```sh
curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{
    "jsonrpc": "2.0", "id": 1, "method": "eth_simulateV1",
    "params": [
      { "blockStateCalls": [ {
          "stateOverrides": {
            "0x1111111111111111111111111111111111111111": { "balance": "0x3b9aca00" }
          },
          "calls": [
            { "from": "0x1111111111111111111111111111111111111111",
              "to":   "0x2222222222222222222222222222222222222222", "data": "0x" },
            { "from": "0x1111111111111111111111111111111111111111",
              "to":   "0x2222222222222222222222222222222222222222", "data": "0x" }
          ]
      } ] },
      "latest"
    ]
  }'
```

The result is one object per simulated block — the block env it ran under plus a
`calls` array with one entry per call:

```json
{
  "jsonrpc": "2.0", "id": 1,
  "result": [ {
    "number": "0x...", "timestamp": "0x...", "gasLimit": "0x...",
    "gasUsed": "0x...", "baseFeePerGas": "0x0",
    "calls": [
      { "status": "0x1", "returnData": "0x...", "gasUsed": "0x...", "logs": [] },
      { "status": "0x1", "returnData": "0x...", "gasUsed": "0x...", "logs": [] }
    ]
  } ]
}
```

A reverted call instead reports `"status": "0x0"` with an `error` object
carrying the revert reason.

### ERC-4337 bundler

With `[bundler] enable = true` (plus a signing key and at least one
`entry_points` address — see `config.example.toml`), the node is an ERC-4337
**bundler**: it serves the standard bundler RPC namespace and submits `handleOps`
transactions itself.

- **`eth_supportedEntryPoints`** → the configured EntryPoint addresses.
- **`eth_sendUserOperation(userOp, entryPoint)`** → validate by simulating
  `handleOps` (rejecting, with the decoded `FailedOp` reason, if it reverts),
  then sign + submit; returns the `userOpHash` (computed by the EntryPoint, so it
  matches whatever EntryPoint version is deployed).
- **`eth_estimateUserOperationGas(userOp, entryPoint)`** →
  `{preVerificationGas, verificationGasLimit, callGasLimit,
  paymasterVerificationGasLimit, paymasterPostOpGasLimit}`. Each limit is
  binary-searched against `handleOps` simulations (the least value at which the
  bundle doesn't revert / the op's `UserOperationEvent` reports success), with a
  small safety margin — not a heuristic.
- **`eth_getUserOperationByHash(hash)`** → the op + its on-chain location, or `null`.
- **`eth_getUserOperationReceipt(hash)`** → success + actual gas (from the
  `UserOperationEvent`) + the inner tx receipt, or `null` until mined.

It is **off-protocol** — a bundled op is an ordinary `EntryPoint` contract call
executed by the same TVM, so the bundler has zero consensus effect (the namespace
is additive, like `eth_simulateV1`). TRON has no canonical EntryPoint yet, so the
operator deploys the standard v0.7 EntryPoint (e.g. via CREATE2) and lists it in
`[bundler] entry_points`; the signing account must hold TRX/energy to pay for the
`handleOps` transactions. Validation, gas estimation, and `getUserOpHash` are all
delegated to that deployed EntryPoint via the constant-call VM, so the bundler is
version-agnostic.

Accepted ops enter an in-memory **mempool** and are **batched** — multiple ops
per `handleOps` — by a background loop (`auto` mode, on `bundle_interval_ms`) or
on demand (`manual` mode). If the EntryPoint rejects an op while building a
bundle, that op is dropped by its `FailedOp` opIndex and the rest still submit,
so one bad op can't wedge the queue.

**ERC-7562 validation rules.** On accept, the op's validation phase is re-run
under a validation tracer; if any entity (account / factory / paymaster) uses a
**banned opcode** while inside its validation subtree — non-deterministic block
context (`TIMESTAMP`, `NUMBER`, `COINBASE`, `BLOCKHASH`, `GASLIMIT`, `BASEFEE`,
`PREVRANDAO`, blob ops), cross-account `BALANCE`/`SELFBALANCE`, `ORIGIN`,
`GASPRICE`, raw `CREATE`, or `SELFDESTRUCT` — the op is rejected. This blocks ops
that pass a one-shot simulation but could behave differently (or fail) when
actually mined. Toggle with `[bundler] enforce_validation_rules` (default on);
the tracer only runs the validation phase and is non-committing.

**ERC-7562 reputation / throttling.** Each entity (account / factory /
paymaster) is also tracked by ops *seen* vs ops *included*; one that floods the
mempool with ops that never get included is **throttled** (capped mempool
presence) and then **banned** (`eth_sendUserOperation` rejected) — the standard
`opsSeen / 10` inclusion-rate rule. `debug_bundler_getStakeStatus` reports an
entity's stake in the EntryPoint (`getDepositInfo`).

The `debug_bundler_*` control namespace — `sendBundleNow`, `setBundlingMode`,
`dumpMempool`, `clearMempool`, `clearState`, `dumpReputation`, `setReputation`,
`clearReputation`, `getStakeStatus` — drives manual bundling, inspection, and
reputation control (and the ERC-4337 bundler-spec test suite).

Example — discover the EntryPoint, then submit a UserOperation (the canonical
v0.7 EntryPoint address is shown; long fields are abbreviated with `…`):

```sh
# Which EntryPoints this bundler accepts:
curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_supportedEntryPoints","params":[]}'
# → {"jsonrpc":"2.0","id":1,"result":["0x0000000071727de22e5e9d8baf0edac6f37da032"]}

# Submit a UserOperation (unpacked v0.7 shape); the result is the userOpHash,
# computed by the EntryPoint itself so it matches the deployed version:
curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_sendUserOperation","params":[
        {
          "sender":               "0x1234…",
          "nonce":                "0x0",
          "callData":             "0xb61d27f6…",
          "callGasLimit":         "0x88b8",
          "verificationGasLimit": "0x186a0",
          "preVerificationGas":   "0xc350",
          "maxFeePerGas":         "0x3b9aca00",
          "maxPriorityFeePerGas": "0x3b9aca00",
          "signature":            "0x…"
        },
        "0x0000000071727de22e5e9d8baf0edac6f37da032"
      ]}'
# → {"jsonrpc":"2.0","id":1,"result":"0xefbc1a…"}

# Poll the receipt with that userOpHash once the bundle is mined (null until then):
curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getUserOperationReceipt","params":["0xefbc1a…"]}'
```

A rejected `eth_sendUserOperation` returns the EntryPoint's decoded `FailedOp`
reason (e.g. `op 0: AA24 signature error`) rather than a bare revert, so callers
see *why* validation failed.

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

Any java-tron gRPC client or generated stub works unchanged — the wire contract
is the standard `protocol` package (service `Wallet`, methods like
`GetNowBlock`), vendored at
`crates/tron-proto/vendored/java-tron/api/api.proto`. Server reflection is not
enabled, so an ad-hoc client must supply that proto tree (and its `google/api`
imports) as the import path — e.g. with
[`grpcurl`](https://github.com/fullstorydev/grpcurl):

```sh
grpcurl -plaintext \
  -import-path crates/tron-proto/vendored/java-tron \
  -proto api/api.proto \
  -d '{}' 127.0.0.1:50051 protocol.Wallet/GetNowBlock
```

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

For example, the two most recent confirmed USDT transfers for an account:

```sh
curl -s 'http://127.0.0.1:8090/v1/accounts/<T-address>/transactions/trc20?limit=2&only_confirmed=true&contract_address=TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
```

```json
{
  "data": [ /* TronGrid-shaped TRC-20 transfer records */ ],
  "meta": { "at": 1782191730710, "page_size": 2,
            "backfill": { "complete": true, "indexed_from": 0 } },
  "success": true
}
```

`meta.backfill.complete` is `false` while history is still being indexed
head-first; results stream in within seconds and fill in as backfill catches up.

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
