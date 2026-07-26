# Chronos — Deterministic Time-Travel Fork Simulation

Chronos is **anvil-fork / Tenderly for TRON, byte-exact**. It forks the chain
at a historical block (or head), opens a **mutable, never-committed** overlay
seeded from real archived state, and runs arbitrary **mutating** transactions
and bundles — with state, code, balance, and block-environment overrides —
returning per-call status, return data, energy (including the dynamic-energy
penalty), logs, the internal-transaction tree, the opcode trace, and decoded
state diffs.

Everything runs against the same TRON VM the node uses to apply blocks, so a
replay of a real transaction reproduces its on-chain result byte-for-byte, and
overridden state is read back exactly as the VM composed it (v1 / v2 / CREATE2
storage layouts included).

## Enabling it

Chronos is **off by default** — it executes arbitrary code with large energy
budgets and holds per-fork memory, so operators opt in. It also needs the
historical-state archive (it reads at-height state and pulls its raw backends
from the archive's live set).

```toml
[index]
enable  = true
archive = true          # required — Chronos forks read archived state

[sim]
enabled                  = true      # master switch (default false)
max_forks                = 8         # concurrent named fork sessions (LRU-evicted)
fork_ttl_secs            = 3600      # evict a fork this long after last use
max_overlay_keys         = 1000000   # hard per-fork overlay-size cap
max_calls_per_bundle     = 256
max_blocks_per_bundle    = 64
energy_cap               = 50000000  # per-call ceiling (= eth_call gas cap)
max_state_override_slots = 10000     # `state` replace-all enumeration cap
max_struct_logs          = 100000    # per-call opcode-log cap (trace=full); 0 = unlimited
call_timeout_ms          = 0         # per-call wall-clock deadline; 0 = off (see note)
```

Historical forks are limited to the archive's coverage window; a request
outside it is **rejected** with the exact `[base, head]` — no silent clamping.

## Methods

| Method | Shape | Purpose |
| --- | --- | --- |
| `tron_simulateBundle` | native, full-power | run a one-shot bundle |
| `tron_forkCreate` | `[{ base, overrides? }]` | open a named fork session |
| `tron_forkCall` | `[forkId, { blocks\|calls, trace?, returnStateDiff? }]` | run against a fork; advances its head |
| `tron_forkSnapshot` | `[forkId]` → `{ snapshotId }` | anvil `evm_snapshot` |
| `tron_forkRevert` | `[forkId, snapshotId]` | anvil `evm_revert` |
| `tron_forkStateDiff` | `[forkId]` | fork's cumulative diff |
| `tron_forkList` / `tron_forkDelete` | `[]` / `[forkId]` | manage forks |
| `eth_simulateV1` | geth shape | gains historical base + full `stateOverrides` + creation calls when Chronos is on |
| `POST /v1/sim/bundle` | REST | the `tron_simulateBundle` payload as the request body |

Addresses accept base58check (`T…`) or hex; numbers accept a JSON number, a
`0x`-hex string, or a decimal string.

## `tron_simulateBundle`

```json
{
  "jsonrpc": "2.0", "id": 1, "method": "tron_simulateBundle",
  "params": [{
    "base": { "block": 83316700 },
    "trace": "full",
    "returnStateDiff": "perCall",
    "blocks": [{
      "overrides": {
        "accounts": {
          "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {
            "balance": "1000000000",
            "stateDiff": { "0x…02": "0x…deadbeef" },
            "trc10": { "1002000": "5000000" }
          }
        },
        "block": { "number": 83316701, "time": 1750900000 }
      },
      "calls": [
        { "type": "trigger",
          "ownerAddress": "TSzoLaVCdSNDpNxgChcvzBHZasyQXHjgbK",
          "contractAddress": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
          "data": "a9059cbb…", "callValue": 0, "energy": 30000000 },
        { "type": "create",
          "ownerAddress": "TSzoLaVCdSNDpNxgChcvzBHZasyQXHjgbK",
          "initCode": "6080604052…", "energy": 50000000,
          "consumeUserResourcePercent": 100, "name": "Probe" }
      ]
    }]
  }]
}
```

- `base`: `{ "block": N }` for a historical fork, or `{ "tag": "latest" }` /
  omitted for head.
- `trace`: `none` (default) | `callTree` | `full`. `callTree` gives the
  CALL/CREATE frame tree; `full` adds per-opcode struct logs.
- `returnStateDiff`: `none` | `final` (default) | `perCall`.
- Every call may carry TRC-10 `tokenId` / `tokenValue` (top-level CALLTOKEN).

State accumulates: call *N* sees call *N−1*'s writes, and block *N+1* sees
block *N*'s. Nothing is ever committed to disk.

### Response

```json
{
  "basis": {
    "baseBlock": 83316700, "mode": "vm",
    "archiveCoverage": { "base": 83316752, "head": 85908001 },
    "granularity": "block-boundary", "warnings": []
  },
  "blocks": [{
    "number": 83316701, "timestampMs": 1750900000000, "energyUsed": 41873122,
    "calls": [{
      "status": "SUCCESS", "returnData": "0x…01",
      "energyUsed": 29112, "energyPenalty": 0,
      "logs": [ … ], "internalTransactions": [ … ],
      "callFrames": [ … ], "structLogs": [ … ],
      "stateDiff": { "accounts": [ … ], "storage": [ … ], "code": [ … ] }
    }]
  }],
  "stateDiff": { … cumulative … },
  "warnings": []
}
```

`status` ∈ `SUCCESS | REVERT | TRANSFER_FAILED | HALT | ERROR | TIMEOUT`.
Creation calls report the deterministic deployed address as `contractAddress`.

## Fork sessions

```
tron_forkCreate [{ "base": { "block": 83316700 } }]
  → { "forkId": "…", "seedBlock": 83316700, "seedTimestampMs": …, "coverage": {…}, "ttlSecs": 3600 }
tron_forkCall  ["…", { "calls": [ … ] }]        # advances the fork's synthetic head
tron_forkSnapshot ["…"] → { "snapshotId": 1 }
tron_forkCall  ["…", { "calls": [ … ] }]        # more mutations
tron_forkRevert ["…", 1]                        # roll back to the snapshot
tron_forkStateDiff ["…"]                        # cumulative decoded diff
tron_forkDelete ["…"]
```

Distinct forks run concurrently; calls on one fork are serialized. Forks are
node-local, unguessable, and evicted by TTL / LRU.

## What Chronos guarantees — and what it does not

Every response carries a `basis` header stating the truth:

- **`mode: "vm"`** — real VM, real state, real energy metering (including the
  dynamic-energy penalty). It does **not** charge bandwidth, apply
  fee-limit-vs-frozen-energy admission, verify signatures/permissions, or run
  non-VM contract types. Energy numbers are not "the fee this would cost on
  mainnet".
- **`granularity: "block-boundary"`** — a fork "at N" is the state *after*
  block N fully applied; replaying a transaction that sat mid-block does not
  see its intra-block predecessors.
- **`archiveCoverage`** — history is a window, not eternity; out-of-window
  requests are rejected, not clamped.
- **Determinism** — same request + same fork state ⇒ byte-identical response.
  Synthetic transaction ids are derived (`sha256(forkId ‖ blockNumber ‖
  callIndex)`), so created addresses are stable across replays and never
  collide across a session's calls. The per-call energy budget (`energy_cap`)
  is the deterministic compute bound; `call_timeout_ms` is **off by default**
  because a call that trips a wall-clock deadline would resolve differently on
  a slow vs a fast host (an explicit `TIMEOUT` status) — enable it only if you
  prefer a wall-clock guard over byte-exact replay. `trace: "full"` is capped
  at `max_struct_logs` opcode logs per call; a truncated trace sets
  `structLogsTruncated`.
- **selfCheck is contractRet-CLASS parity, not the exact-code tripwire** — it
  re-runs block N+1's index-0 tx and compares the outcome class (Success /
  Revert / TransferFailed / Halt). A mismatch may be a real divergence or a
  VM-mode limitation (a tx needing more than `energy_cap`, one relying on
  frozen energy, or a maintenance-boundary block); the rigorous byte-exact
  check is the rig parity run.
- **Isolation** — nothing Chronos does can reach disk: height-based overlays
  sit on read-only at-height views and no session is ever committed.

`nonce` overrides are accepted and ignored with a warning (TRON has no nonce).
