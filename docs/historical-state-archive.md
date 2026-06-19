# Historical-State Archive

The historical-state archive lets the node answer two questions a normal
TRON node cannot:

- **State at height** — what was an account's or contract's state *as of
  block N*? (`getaccount` / `getaccountresource` at a chosen height.)
- **Constant call at height** — run a read-only contract call against
  state *as of block N*, so `block.number` / `block.timestamp` and every
  storage slot reflect that height rather than the live tip.

It is **disabled by default**. It is storage-heavy, and coverage cannot
be cheaply re-derived after the fact, so turn it on deliberately.

## Why this is not a normal node feature

TRON block headers commit to the transaction Merkle root but **not** to
an enforced state root. There is no canonical hash of "the world at block
N", and the public network exposes no at-height state archive. A stock
node keeps only current state plus a shallow undo log for reorgs; once a
block solidifies, the state it produced is overwritten and gone.

The archive closes that gap by recording every block's committed
write-set as **per-key versions** in a versioned-KV store. A historical
read of a key at height `H` is a single seek to the most recent version
at or before `H` — not a replay, not an anchor-walk, so history depth
adds no read cost. Keys never written since capture began fall through to
the live store, which still holds their correct (unchanged) value.

This is foundational for the time-travel transaction tracer:
`debug_traceTransaction` re-executes against the as-of-block state when
the archive covers the transaction's block (see
[APIs, Indexing, and Firehose](apis-indexing-firehose.md#developer-and-debug-methods)).

## Enabling it

The archive has its own config section:

```toml
[index.archive]
enabled       = true        # master switch (default false)
mode          = "rolling"   # "rolling" (bounded window) | "full" (keep all)
retain_blocks = 2592000     # rolling: keep [head - retain_blocks, head]
```

`enabled = true` implies `[index] capture_state_deltas` — the underlying
per-key version capture — and starts the indexer if it is not already
running. See [config.example.toml](../config.example.toml) for the
per-key comments and defaults.

- `mode = "rolling"` keeps a bounded window of `retain_blocks` behind the
  head and prunes older versions as the head advances. This is the
  default and the right choice for almost everyone.
- `mode = "full"` keeps every version from the moment capture began. Disk
  grows without bound; only sensible with explicit capacity planning.
- `retain_blocks` defaults to `2592000` (≈ 90 days at 3-second blocks)
  and applies only in rolling mode.

> Reconcile note (config name): the underlying capture flag is
> `[index] capture_state_deltas`. The `[index.archive]` section is the
> operator-facing wrapper that owns it; `enabled = true` is the single
> switch you should use.

### Disk-cost guide

Archive size scales with **state writes** — changed keys multiplied by
blocks — not with the number of blocks alone. On mainnet that runs to
roughly **8–15 GB/day** of versioned write history (busy days higher,
quiet days lower). Pick a window for the questions you need to answer:

| Window | `retain_blocks` (3s blocks) | Rough disk |
| --- | ---: | ---: |
| 7 days | `201600` | ~60–100 GB |
| 30 days | `864000` | ~250–450 GB |
| 90 days (default) | `2592000` | ~0.8–1.3 TB |
| 1 year | `10512000` | ~3–5 TB |
| Full (from enable) | `mode = "full"` | tens of TB and growing |

Full-from-genesis is **not** possible by enabling this later — capture
only begins at the current head (see [Operational notes](#operational-notes)).
A "full" archive grows from whenever you first turned it on; a
full-history archive would require capturing from genesis and lands in
the tens-of-TB range.

These figures are order-of-magnitude planning numbers, not guarantees.
Provision headroom and watch the `tron_node_*archive*` metrics.

## The API

All endpoints are served on the HTTP REST port (default
`127.0.0.1:8090`). Each takes a `block` (the height `H` to read at) and
is valid only inside the retained coverage window — see
[Caveats](#caveats). A request for an out-of-window height returns
`success: false` with an error naming the covered `[base, head]` range.

> Reconcile note (endpoint names): the shapes below match the current
> `/v1/archive` surface in `crates/tron-rpc/src/index_api.rs`. If an
> endpoint name shifts during implementation, this is the spot to
> update; the `?address=…&block=H` / `"block": H` parameter convention is
> stable.

### State at height — account

```sh
curl -s 'http://127.0.0.1:8090/v1/archive/account?address=TXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&block=83000000'
```

```json
{
  "success": true,
  "block": 83000000,
  "data": {
    "address": "41...",
    "balance": 123456789,
    "create_time": 1690000000000,
    "frozenV2": [ ... ],
    "account_resource": { ... }
  }
}
```

`data` is the standard `getaccount` body, resolved against state as of
the requested block. Add `&visible=true` to get base58 (`T…`) addresses
in the response instead of hex.

### State at height — account resource

```sh
curl -s 'http://127.0.0.1:8090/v1/archive/accountresource?address=TXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&block=83000000'
```

```json
{
  "success": true,
  "block": 83000000,
  "data": {
    "freeNetUsed": 100,
    "freeNetLimit": 600,
    "NetUsed": 0,
    "NetLimit": 0,
    "EnergyUsed": 4200,
    "EnergyLimit": 50000,
    "TotalNetLimit": 43200000000,
    "TotalEnergyLimit": 180000000000
  }
}
```

The standard `getaccountresource` body, with bandwidth/energy limits and
usage computed against the network-wide weights as of block `H`.

### Constant call at height

`POST` the standard `/wallet/triggerconstantcontract` body with an added
`block` field. The whole VM environment — storage slots, code, and the
`block.number` / `block.timestamp` opcodes — comes from state as of `H`.

```sh
curl -s -X POST 'http://127.0.0.1:8090/v1/archive/triggerconstantcontract' \
  -H 'Content-Type: application/json' \
  -d '{
    "owner_address": "410000000000000000000000000000000000000000",
    "contract_address": "41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
    "function_selector": "balanceOf(address)",
    "parameter": "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c",
    "block": 83000000
  }'
```

```json
{
  "success": true,
  "block": 83000000,
  "data": {
    "result": { "result": true },
    "constant_result": [
      "0000000000000000000000000000000000000000000000000000000000bc614e"
    ],
    "energy_used": 1080
  }
}
```

`constant_result` is the raw ABI-encoded return data, decoded exactly as
the live `triggerconstantcontract` would — but reading the contract's
storage and balances as they were at block `H`. Requires
`[vm] support_constant = true`, the same as live constant calls.

## Caveats

- **Coverage window only.** Reads succeed only for heights inside
  `[base, head]`, where `base` is where capture began (rolling mode
  advances it as it prunes). A height below `base` was never captured and
  cannot be reconstructed; the API rejects it with the covered range.
- **No cryptographic proof.** TRON has no enforced state root, so there
  is no Merkle proof that a returned value is canonical. Correctness is
  **deterministically reproducible and consensus-parity-validated**: the
  archive stores exactly what the executor committed for each block, and
  state parity is verified by comparing reads against a java-tron node
  (see the parity notes in the root [README](../README.md)). Trust model:
  trust the node, as with any RPC — not a self-verifying proof.
- **Rolling-window pruning is irreversible.** Once a height drops below
  `base` it is gone. Size your window for the deepest history you intend
  to query.

## Operational notes

- **Coverage begins at the current head, not genesis.** Turning the
  archive on starts capture from the then-current block. There is no way
  to backfill earlier history — the deltas are not re-derivable from
  current state after the fact (this is why the archive, unlike the
  address-history index, is **not** disposable).
- **It is storage-heavy.** Plan disk against the
  [disk-cost guide](#disk-cost-guide) and monitor it; a rolling window
  bounds growth, `mode = "full"` does not.
- **It cannot be cheaply re-derived.** If capture is toggled off and back
  on, or a crash gap out-lives the undo log, the archive resets and
  coverage restarts at the then-current head — loudly, because that
  discards hours-to-terabytes of history. Small crash tails self-repair
  exactly from the block-undo log.
- **Requires `[storage] snapshot_reorg = false`** (the default reorg
  engine), which the capture path depends on.
- Archive data lives under `<data_dir>/archive/db/` and is separate from
  the disposable address-history index under `<data_dir>/index/`.
