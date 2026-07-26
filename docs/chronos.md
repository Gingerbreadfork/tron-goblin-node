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
max_struct_logs          = 100000    # per-call opcode-log COUNT cap (trace=full)
max_struct_log_bytes     = 134217728 # per-call opcode-log BYTE budget (real memory bound)
max_call_frames          = 100000    # per-call call-tree frame cap
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

## Recipes

Copy-pasteable flows for the things people actually reach for a fork simulator
to do. `$RPC` is the JSON-RPC endpoint (default `http://127.0.0.1:8545`);
addresses accept base58check (`T…`) or hex.

### 0. What can I fork? (check coverage first)

Historical forks work within the archive's window. Check it, then fork inside it:

```sh
curl -s http://127.0.0.1:8090/v1/archive/coverage
# {"data":{"base":84800506,"head":84900000,"blocks":99495},"success":true}
```

A base outside `[base, head]` is rejected (not clamped) with the exact window.
`{ "base": { "tag": "latest" } }` forks head and needs no historical coverage.

### 1. Read on-chain contract state at a past block

Call a real contract as it existed at block *N* — Chronos reads its code and
storage straight from chain state. This one is runnable as-is (USDT
`decimals()`, selector `0x313ce567`); pick a `block` inside your coverage
window:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 },
    "blocks": [{ "calls": [
      { "type":"trigger",
        "ownerAddress":"0x0000000000000000000000000000000000000001",
        "contractAddress":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "data":"0x313ce567", "energy":10000000 }
    ]}]
  }]
}'
# result.blocks[0].calls[0].returnData = 0x…06  (USDT has 6 decimals)
```

Notes: `data` is `0x`-prefixed hex (bare hex is rejected). The caller
(`ownerAddress`) must be an account WITHOUT code — a contract as caller is
rejected (EIP-3607), like a real signed tx; any plain address works for a view
call. Swap `data` for `0x70a08231` + a 32-byte-padded holder address to read a
`balanceOf` at that height, or any method + ABI-encoded args.

### 2. "What-if": replay a failing call after fixing the missing state

The headline use case — a call reverted on-chain because a balance/allowance
was missing. Fork just before it, **override** the state it needed, and re-run:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 },
    "trace": "callTree",
    "returnStateDiff": "final",
    "blocks": [{
      "overrides": { "accounts": {
        "TSenderAddr...": { "balance": "1000000000", "trc10": { "1002000": "5000000" } },
        "TTokenContract...": { "stateDiff": {
          "0x<allowance_slot_32B>": "0x000000000000000000000000000000000000000000000000ffffffffffffffff"
        }}
      }},
      "calls": [
        { "type":"trigger", "ownerAddress":"TSenderAddr...",
          "contractAddress":"TDexRouter...", "data":"<swap_calldata>", "energy":30000000 }
      ]
    }]
  }]
}'
# now status:"SUCCESS", with callFrames (the internal transfers) and stateDiff
# (who ended up with what). Flip the override off to see it revert again.
```

Override kinds: `balance` (sun), `code` (runtime bytecode), `state`
(replace-all), `stateDiff` (merge slots), `trc10` (token id → amount).

### 3. Deploy and poke a contract in a throwaway fork

Persistent session, anvil-style — deploy something that never existed on-chain,
call it, snapshot, try a risky path, and roll back:

```sh
# create a fork and keep its id
FID=$(curl -s -X POST $RPC -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tron_forkCreate","params":[{"base":{"block":84800600}}]}' \
  | jq -r .result.forkId)

# deploy a probe contract
curl -s -X POST $RPC -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tron_forkCall\",\"params\":[\"$FID\",{
    \"blocks\":[{ \"overrides\":{\"accounts\":{\"TDeployer...\":{\"balance\":\"1000000000\"}}},
      \"calls\":[{\"type\":\"create\",\"ownerAddress\":\"TDeployer...\",
                  \"initCode\":\"<init_bytecode>\",\"energy\":50000000,\"name\":\"Probe\"}] }]
  }]}"    # → result.blocks[0].calls[0].contractAddress

SNAP=$(curl ... tron_forkSnapshot [\"$FID\"] ... | jq -r .result.snapshotId)
# ... run experiments via tron_forkCall ...
curl ... tron_forkRevert [\"$FID\", $SNAP]        # roll back to the snapshot
curl ... tron_forkStateDiff [\"$FID\"]            # cumulative diff so far
curl ... tron_forkDelete [\"$FID\"]               # done
```

### 4. Prove a replay matches on-chain (selfCheck)

Confirm the node reproduces a real block's result byte-for-byte — re-runs block
*N+1*'s index-0 transaction and compares its contractRet class to the recorded
receipt:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle",
  "params":[{ "base": { "block": 84800620 }, "selfCheck": true, "blocks":[{"calls":[]}] }]
}'
# result.selfCheck: { "checked":1, "matched":true, "ourStatus":"SUCCESS",
#                     "recordedContractRet":"SUCCESS" }
```

### 5. Use your existing Ethereum tooling

`eth_simulateV1` keeps the geth request/response shape, so viem/foundry-style
clients work unmodified — and with Chronos on, param 1 accepts a historical hex
height and full `stateOverrides` (code/state/stateDiff) + creation calls:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"eth_simulateV1","params":[
    { "blockStateCalls":[{
        "stateOverrides": { "0x<addr>": { "balance":"0x3b9aca00", "code":"0x6080..." } },
        "calls": [ { "from":"0x<addr>", "to":"0x<contract>", "input":"0x70a08231...", "gas":"0xf4240" } ]
    }]},
    "0x50df458"
  ]
}'
```

`POST /v1/sim/bundle` (body = the `tron_simulateBundle` payload) is the REST
mirror, wrapped as `{ "success": true, "data": … }`.

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
