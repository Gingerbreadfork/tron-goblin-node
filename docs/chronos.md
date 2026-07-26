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
storage layouts included). Nothing Chronos does ever touches disk.

- [60-second quickstart](#60-second-quickstart)
- [Coming from Ethereum tooling](#coming-from-ethereum-tooling)
- [TRON gotchas for Ethereum devs](#tron-gotchas-for-ethereum-devs)
- [Enabling it](#enabling-it)
- [Methods](#methods)
- [`tron_simulateBundle` reference](#tron_simulatebundle-reference)
- [Response reference](#response-reference)
- [Fork sessions](#fork-sessions)
- [Recipes](#recipes)
- [Errors](#errors)
- [Guarantees and limits](#what-chronos-guarantees--and-what-it-does-not)

---

## 60-second quickstart

Enable Chronos (see [Enabling it](#enabling-it)), then find your fork window and
run a call. This example reads USDT's `decimals()` at a past block and is
runnable as-is once you drop in a block inside your coverage window:

```sh
RPC=http://127.0.0.1:8545

# 1. What can I fork? (the archive coverage window)
curl -s http://127.0.0.1:8090/v1/archive/coverage
# {"data":{"base":84800506,"head":84902100,"blocks":101595},"success":true}

# 2. Call a real contract as it existed at a past block
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 },
    "calls": [{
      "type":"trigger",
      "from":"0x0000000000000000000000000000000000000001",
      "to":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
      "data":"0x313ce567", "energy":10000000
    }]
  }]
}' | jq -r '.result.blocks[0].calls[0].returnData'
# 0x0000000000000000000000000000000000000000000000000000000000000006  → 6 decimals
```

That's the whole model: pick a `base`, describe `calls`, read the result. From
here you add overrides (state/code/balance/block), traces, state diffs, and —
for stateful experiments — named [fork sessions](#fork-sessions).

---

## Coming from Ethereum tooling

Chronos maps one-to-one onto the fork/simulate primitives you already know.

| You'd reach for (Ethereum) | In Chronos |
| --- | --- |
| `anvil --fork-url … --fork-block-number N` / foundry `vm.createSelectFork` | `base: { "block": N }` in a bundle, or `tron_forkCreate [{ "base": { "block": N } }]` for a session |
| `evm_snapshot` / `evm_revert` | `tron_forkSnapshot` / `tron_forkRevert` |
| `hardhat_setBalance` | `overrides.accounts[a].balance` (in **sun**) |
| `hardhat_setCode` | `overrides.accounts[a].code` (runtime bytecode) |
| `hardhat_setStorageAt` | `overrides.accounts[a].stateDiff` (merge) or `state` (replace-all) |
| `hardhat_impersonateAccount` + send | just set `from` / `ownerAddress` — **no unlock, no signature** (see gotchas) |
| `eth_call` + geth 3-arg state override | one `tron_simulateBundle` call, or `eth_simulateV1` |
| `eth_simulateV1` (geth bundles) | `eth_simulateV1` — same request/response shape, **plus** a historical base and creation calls |
| `debug_traceCall` `{tracer: callTracer}` | `"trace": "callTree"` → `callFrames` |
| `debug_traceCall` `{tracer: structLogs}` | `"trace": "full"` → `structLogs` |
| Tenderly *Simulate* / *Simulate Bundle* | `tron_simulateBundle` with `blocks[]` / `calls[]` |
| foundry `vm.warp` / `vm.roll` | `overrides.block.time` / `overrides.block.number` |
| several txs in sequence, state carrying forward | one bundle: multiple `calls` (same block) or multiple `blocks` |

Field names accept the Ethereum spelling too: `from`/`to`/`value`/`input`/`gas`
work as aliases for `ownerAddress`/`contractAddress`/`callValue`/`data`/`energy`.

---

## TRON gotchas for Ethereum devs

The VM is EVM-compatible, but the chain around it differs. These are the things
that trip people:

| Concept | Ethereum | TRON / Chronos |
| --- | --- | --- |
| **Address** | `0x` + 20 bytes | base58 `T…` **or** hex `0x41…` (21 bytes, `0x41` prefix). Chronos accepts either for any address field; it returns base58 for created contracts and 20-byte hex inside traces. |
| **Native unit** | wei (1e18 / ETH) | **sun** (1e6 / TRX). `balance` overrides and `callValue` are in sun. |
| **Gas** | `gas` + `gasPrice` | **energy** — no price in simulation. The field is `energy` (alias `gas`); the per-call ceiling is `energy_cap`. `energyPenalty` is TRON's dynamic-energy surcharge. |
| **Tokens** | ERC-20 | TRC-20 (EVM, identical to ERC-20) **and** TRC-10 (native multi-asset). Send TRC-10 with `tokenId` + `tokenValue` on a call; seed balances with the `trc10` override. |
| **Nonce** | matters | none. A `nonce` override is accepted and **ignored** (with a warning). |
| **Caller** | impersonation needs an unlock | set `from` to **any codeless address** — no signature is checked. A caller that *has* code is rejected (EIP-3607). |
| **Storage slot** | `keccak256(key ‖ slot)` | you pass the **same 32-byte Solidity slot** you'd give `hardhat_setStorageAt`; Chronos composes TRON's physical key (v1 / v2 / CREATE2) for you. |
| **Status** | revert / success | `SUCCESS · REVERT · TRANSFER_FAILED · HALT · ERROR · TIMEOUT` (TRON `contractRet` classes). |

---

## Enabling it

Chronos is **off by default** — it executes arbitrary code with large energy
budgets and holds per-fork memory, so operators opt in. It also needs the
historical-state archive, which it reads at-height state from.

```toml
[index]
enable = true          # master index switch (required for the archive)

[index.archive]
enabled = true         # historical-state archive — Chronos reads this

[sim]
enabled                  = true      # Chronos master switch (default false)
max_forks                = 8         # concurrent named fork sessions (LRU-evicted)
fork_ttl_secs            = 3600      # evict a fork this long after last use
max_overlay_keys         = 1000000   # hard per-fork overlay-size cap
max_calls_per_bundle     = 256
max_blocks_per_bundle    = 64
energy_cap               = 50000000  # per-call energy ceiling (≈ eth_call gas cap)
max_state_override_slots = 10000     # `state` replace-all enumeration cap
max_struct_logs          = 100000    # per-call opcode-log COUNT cap (trace=full)
max_struct_log_bytes     = 134217728 # per-call opcode-log BYTE budget (real memory bound)
max_call_frames          = 100000    # per-call call-tree frame cap
call_timeout_ms          = 0         # per-call wall-clock deadline; 0 = off (see Guarantees)
```

> **The archive is forward-only.** It captures state from the moment you enable
> it, so your fork window starts at roughly the block where the archive turned
> on — not genesis. To fork deep history, rebuild the archive from a snapshot
> first. Coverage is always reported by `/v1/archive/coverage`, and a request
> outside `[base, head]` is **rejected** with the exact window (never clamped).

Everything under `[sim]` has a sane default; you can enable Chronos with just the
three `= true` lines.

---

## Methods

All are JSON-RPC on the node's RPC port (default `:8545`).

| Method | Params | Purpose |
| --- | --- | --- |
| `tron_simulateBundle` | `[bundle]` | one-shot bundle — the full-power entry point |
| `tron_forkCreate` | `[{ base?, overrides? }]` | open a persistent named fork session |
| `tron_forkCall` | `[forkId, bundle]` | run against a session; **advances its head** |
| `tron_forkSnapshot` | `[forkId]` → `{ snapshotId }` | anvil `evm_snapshot` |
| `tron_forkRevert` | `[forkId, snapshotId]` | anvil `evm_revert` |
| `tron_forkStateDiff` | `[forkId]` | session's cumulative decoded diff |
| `tron_forkList` / `tron_forkDelete` | `[]` / `[forkId]` | manage sessions |
| `eth_simulateV1` | `[payload, block?]` | geth shape; gains a historical base + full `stateOverrides` + creation calls when Chronos is on |
| `POST /v1/sim/bundle` | body = a bundle | REST mirror of `tron_simulateBundle` |

Addresses accept base58check (`T…`) or hex; numbers accept a JSON number, a
`0x`-hex string, or a decimal string.

---

## `tron_simulateBundle` reference

A **bundle** is one or more synthetic **blocks**, each an optional `overrides`
set plus a list of `calls`. State accumulates: call *N* sees call *N−1*'s
writes, and block *N+1* sees block *N*'s.

```json
{
  "jsonrpc": "2.0", "id": 1, "method": "tron_simulateBundle",
  "params": [{
    "base": { "block": 84800600 },
    "trace": "full",
    "returnStateDiff": "perCall",
    "selfCheck": false,
    "blocks": [{
      "overrides": {
        "accounts": {
          "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {
            "balance": "1000000000",
            "code": "0x6080…",
            "stateDiff": { "0x…02": "0x…deadbeef" },
            "trc10": { "1002000": "5000000" }
          }
        },
        "block": { "number": 84800601, "time": 1750900000 }
      },
      "calls": [
        { "type": "trigger", "from": "TSzoLaVCdSNDpNxgChcvzBHZasyQXHjgbK",
          "to": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
          "data": "0xa9059cbb…", "callValue": 0, "energy": 30000000 },
        { "type": "create", "from": "TSzoLaVCdSNDpNxgChcvzBHZasyQXHjgbK",
          "initCode": "0x6080…", "energy": 50000000, "name": "Probe" }
      ]
    }]
  }]
}
```

**Single-block shorthand:** put `calls` (and optional `overrides`) directly on
`params[0]` and drop the `blocks` wrapper — `params[0]` becomes the one block.

### Bundle fields

| Field | Values | Default |
| --- | --- | --- |
| `base` | `{ "block": N }` · `{ "tag": "latest" }` · `"latest"` · `N` · `"0x…"` | `latest` |
| `trace` | `none` · `callTree` (frame tree) · `full` (adds per-opcode `structLogs`) | `none` |
| `returnStateDiff` | `none` · `final` (one cumulative diff) · `perCall` (a diff on every call) | `final` |
| `selfCheck` | `true` runs the [replay-parity check](#4-prove-a-replay-matches-on-chain-selfcheck) | `false` |
| `energyCap` | per-call energy override (≤ configured `energy_cap`) | config |
| `blocks` | array of `{ overrides?, calls }` | — |

### Call fields

| Field (aliases) | Meaning |
| --- | --- |
| `type` | `trigger` (call, alias `call`) or `create` (deploy, alias `deploy`) |
| `from` (`ownerAddress`) | caller; any codeless address, no signature |
| `to` (`contractAddress`) | *trigger only* — target contract |
| `data` (`input`) | *trigger only* — `0x`-prefixed calldata |
| `initCode` (`data`) | *create only* — `0x`-prefixed deploy bytecode |
| `callValue` (`value`) | TRX to send, in **sun** |
| `energy` (`gas`) | energy budget for this call |
| `tokenId` / `tokenValue` (`callTokenValue`) | TRC-10 token id + amount (native CALLTOKEN) |
| `name`, `consumeUserResourcePercent` | *create only* — contract name, user-resource split (default 100) |

### Override fields (`overrides.accounts[address]`)

| Field | Meaning |
| --- | --- |
| `balance` | set TRX balance, in **sun** |
| `code` | replace runtime bytecode (creates the account/contract row if absent) |
| `state` | **replace-all** storage (clears existing slots first; bounded by `max_state_override_slots`) |
| `stateDiff` | **merge** individual slots — `{ "0x<32B slot>": "0x<32B value>" }` |
| `trc10` (`tokenBalances`) | `{ "<tokenId>": <amount> }` TRC-10 balances |
| `nonce` | accepted and **ignored** (TRON has no nonce) |

`overrides.block` sets `number`, `time` (alias `timestamp`, seconds), and
`coinbase` for that synthetic block.

---

## Response reference

```json
{
  "basis": {
    "baseBlock": 84800600, "mode": "vm",
    "archiveCoverage": { "base": 84800506, "head": 84902100 },
    "granularity": "block-boundary", "warnings": []
  },
  "blocks": [{
    "number": 84800601, "timestampMs": 1750900000000, "energyUsed": 41873,
    "calls": [{
      "status": "SUCCESS", "returnData": "0x…06",
      "energyUsed": 29112, "energyPenalty": 0,
      "logs": [ … ], "internalTransactions": [ … ],
      "callFrames": [ … ], "structLogs": [ … ],
      "stateDiff": { … }, "contractAddress": "T… (creates only)"
    }]
  }],
  "stateDiff": { … cumulative, when returnStateDiff=final … },
  "selfCheck": { … when selfCheck=true … },
  "warnings": []
}
```

**Per-call fields**

| Field | When | Meaning |
| --- | --- | --- |
| `status` | always | `SUCCESS · REVERT · TRANSFER_FAILED · HALT · ERROR · TIMEOUT` |
| `returnData` | always | `0x`-hex return / revert data |
| `energyUsed`, `energyPenalty` | always | energy consumed; dynamic-energy surcharge |
| `logs` | always | `{ address, topics, data }` events |
| `internalTransactions` | always | TRON internal-tx records (transfers, calls, `rejected` flags) |
| `contractAddress` | creates | deterministic deployed address (base58) |
| `callFrames` | `trace ≥ callTree` | recursive CALL/CREATE frame tree |
| `structLogs` | `trace = full` | per-opcode `{ pc, op, gas, gasCost, depth, stack, error }` |
| `structLogsTruncated` / `callFramesTruncated` | if capped | trace hit `max_struct_logs` / `max_call_frames` |
| `stateDiff` | `returnStateDiff = perCall` | this call's diff |
| `error`, `haltReason` | on failure | message; VM halt code |

**State-diff shape** (per-call or the cumulative bundle-level `stateDiff`):

```json
{
  "accounts": [{ "address": "T…", "balanceBefore": 0, "balanceAfter": 500, "created": true }],
  "storage":  [{ "slotKey": "0x…", "before": null, "after": "0x…2a" }],
  "code":     [{ "address": "T…", "beforeLen": null, "afterLen": 10 }],
  "totalChangedKeys": 4
}
```

`slotKey` is TRON's **physical** key (`addr_hash[..16] ‖ slot[16..]` for v2), so
you see exactly what the VM wrote.

---

## Fork sessions

For stateful, multi-step experiments — anvil with `evm_snapshot`/`evm_revert`.
Each `tron_forkCall` advances the session's synthetic head; overrides and writes
persist until you revert or delete.

```
tron_forkCreate  [{ "base": { "block": 84800600 } }]
  → { "forkId":"…", "seedBlock":84800600, "seedTimestampMs":…, "coverage":{…}, "ttlSecs":3600, "warnings":[] }
tron_forkCall    ["…", { "calls":[ … ] }]      # advances the head; state persists
tron_forkSnapshot["…"]            → { "snapshotId": 1 }
tron_forkCall    ["…", { "calls":[ … ] }]      # more mutations
tron_forkRevert  ["…", 1]         → { "reverted": true }   # back to the snapshot
tron_forkStateDiff ["…"]                        # cumulative decoded diff
tron_forkList    []                             # live sessions + overlayKeys/age
tron_forkDelete  ["…"]            → { "deleted": true }
```

Distinct forks run concurrently; calls on a single fork are serialized. Forks
are node-local, have unguessable ids, and are evicted by TTL / LRU. A
`latest`-base fork reads live head state for un-overridden keys (it drifts as the
node syncs) — use a `{ "block": N }` base for a reproducible fork; Chronos warns
you when you don't.

---

## Recipes

`$RPC` is the JSON-RPC endpoint (default `http://127.0.0.1:8545`). Examples
marked **runnable** work as-is against any covered block; others need your own
addresses/calldata. The tiny bytecode snippets are intentionally minimal so you
can see exactly what each proves.

### 0. What can I fork? (check coverage first)

```sh
curl -s http://127.0.0.1:8090/v1/archive/coverage
# {"data":{"base":84800506,"head":84902100,"blocks":101595},"success":true}
```

Fork inside `[base, head]`. `{ "base": { "tag": "latest" } }` forks head and
needs no historical coverage.

### 1. Read on-chain state at a past block — **runnable**

USDT `decimals()` at block *N* (Chronos reads its real code and storage):

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 },
    "calls": [{ "type":"trigger",
      "from":"0x0000000000000000000000000000000000000001",
      "to":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
      "data":"0x313ce567", "energy":10000000 }]
  }]
}'
# result.blocks[0].calls[0].returnData = 0x…06
```

`data` must be `0x`-prefixed. The `from` account must be **codeless** (EIP-3607);
any plain address works for a read. Swap `data` for `0x70a08231` + a 32-byte
padded address to read `balanceOf` at that height.

### 2. Patch-and-test: override a contract's code — **runnable**

`hardhat_setCode`. Swap USDT's bytecode for `0x602a60005260206000f3` (*PUSH1
0x2a; PUSH1 0; MSTORE; PUSH1 0x20; PUSH1 0; RETURN* — always returns 42) and
watch `decimals()` change:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 },
    "overrides": { "accounts": { "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {
      "code": "0x602a60005260206000f3" } } },
    "calls": [{ "type":"trigger",
      "from":"0x0000000000000000000000000000000000000001",
      "to":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
      "data":"0x313ce567", "energy":10000000 }]
  }]
}'
# returnData = 0x…2a  (42 — the patched code ran instead of USDT's)
```

### 3. Impersonate + fix missing state, then replay a failing call

The headline what-if: a call reverted on-chain because a balance/allowance was
missing. Fork just before it, **impersonate** the sender (just name them in
`from` — no key needed), **override** the state they lacked, and re-run. Ask for
the call tree and the diff so you can see what moved:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 },
    "trace": "callTree",
    "returnStateDiff": "final",
    "overrides": { "accounts": {
      "TSenderAddr...": { "balance": "1000000000", "trc10": { "1002000": "5000000" } },
      "TTokenContract...": { "stateDiff": {
        "0x<allowance_slot_32B>": "0x00000000000000000000000000000000000000000000000000ffffffffffffffff"
      } }
    } },
    "calls": [{ "type":"trigger", "from":"TSenderAddr...",
      "to":"TDexRouter...", "data":"0x<swap_calldata>", "energy":30000000 }]
  }]
}'
# status:"SUCCESS", callFrames = the internal transfers, stateDiff = who ended up with what.
# Remove the overrides to watch it revert again.
```

The `<allowance_slot_32B>` is the same slot you'd compute for
`hardhat_setStorageAt` (`keccak256(owner ‖ mapSlot)` etc.); Chronos handles
TRON's physical key composition.

### 4. Inspect a storage write with a per-call diff — **runnable**

Install `0x602a60005500` (*PUSH1 0x2a; PUSH1 0; SSTORE; STOP* — writes 42 to
slot 0) and read the exact slot from the per-call diff:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 }, "returnStateDiff": "perCall",
    "overrides": { "accounts": { "0x0000000000000000000000000000000000000dad": {
      "code": "0x602a60005500" } } },
    "calls": [{ "type":"trigger",
      "from":"0x0000000000000000000000000000000000000001",
      "to":"0x0000000000000000000000000000000000000dad", "data":"0x", "energy":10000000 }]
  }]
}' | jq '.result.blocks[0].calls[0].stateDiff.storage'
# [ { "slotKey":"0x0d3cf01b…", "before":null, "after":"0x…2a" } ]
```

### 5. Time-travel the block environment — **runnable**

`vm.warp`. Install `0x4260005260206000f3` (returns `TIMESTAMP`) and override the
block time — a time-locked contract behaves as if it's the future:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 },
    "overrides": {
      "accounts": { "0x00000000000000000000000000000000000000e5": { "code":"0x4260005260206000f3" } },
      "block": { "time": 1893456000 }
    },
    "calls": [{ "type":"trigger",
      "from":"0x0000000000000000000000000000000000000001",
      "to":"0x00000000000000000000000000000000000000e5", "data":"0x", "energy":10000000 }]
  }]
}'
# returnData decodes to 1893456000 (2030-01-01) — the overridden timestamp
```

### 6. Trace internal transactions and opcodes

`debug_traceCall`. `trace:"callTree"` gives the CALL/CREATE frame tree (like the
`callTracer`); `trace:"full"` adds per-opcode `structLogs` (like `structLog`):

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle","params":[{
    "base": { "block": 84800600 }, "trace": "full",
    "calls": [{ "type":"trigger",
      "from":"0x0000000000000000000000000000000000000001",
      "to":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
      "data":"0x313ce567", "energy":10000000 }]
  }]
}' | jq '{steps:(.result.blocks[0].calls[0].structLogs|length),
          frames:.result.blocks[0].calls[0].callFrames}'
```

Large traces are capped (`max_struct_logs`, `max_call_frames`) and flag
`structLogsTruncated` / `callFramesTruncated` when they are.

### 7. Deploy, snapshot, experiment, revert (fork session)

Persistent anvil-style session — deploy something that never existed, snapshot,
try a risky path, roll back:

```sh
# open a fork, keep its id
FID=$(curl -s -X POST $RPC -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tron_forkCreate","params":[{"base":{"block":84800600}}]}' \
  | jq -r .result.forkId)

# deploy a probe (initCode 0x600a600c600039600a6000f3602a60005260206000f3 deploys the "return 42" runtime)
ADDR=$(curl -s -X POST $RPC -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tron_forkCall\",\"params\":[\"$FID\",{
    \"calls\":[{\"type\":\"create\",\"from\":\"0x0000000000000000000000000000000000000001\",
      \"initCode\":\"0x600a600c600039600a6000f3602a60005260206000f3\",\"energy\":30000000,\"name\":\"Probe\"}]
  }]}" | jq -r .result.blocks[0].calls[0].contractAddress)

SNAP=$(curl -s -X POST $RPC -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tron_forkSnapshot\",\"params\":[\"$FID\"]}" \
  | jq -r .result.snapshotId)
# ... run experiments via tron_forkCall (they persist) ...
curl -s -X POST $RPC -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tron_forkRevert\",\"params\":[\"$FID\",$SNAP]}"
curl -s -X POST $RPC -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tron_forkStateDiff\",\"params\":[\"$FID\"]}"
curl -s -X POST $RPC -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tron_forkDelete\",\"params\":[\"$FID\"]}"
```

Deployed addresses are deterministic (`sha256(forkId ‖ blockNumber ‖ callIndex)`),
so replays are stable and never collide within a session.

### 8. Prove a replay matches on-chain (selfCheck) — **runnable**

Confirm the node reproduces a real block's result. `selfCheck` re-runs block
*N+1*'s index-0 transaction against a fresh fork at *N* and compares its
`contractRet` class to the recorded receipt:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tron_simulateBundle",
  "params":[{ "base": { "block": 84801150 }, "selfCheck": true, "blocks":[{"calls":[]}] }]
}' | jq '.result.selfCheck'
# { "checked":1, "comparedBlock":84801151, "matched":true, "ourStatus":"SUCCESS",
#   "recordedContractRet":"SUCCESS", "txId":"9a2135c5…" }
```

If *N+1*'s index-0 tx isn't a VM contract call, `checked` is 0 with a `note` —
pick another height. This is **class parity**, not the byte-exact tripwire (see
[Guarantees](#what-chronos-guarantees--and-what-it-does-not)).

### 9. Use your existing Ethereum tooling (`eth_simulateV1`)

`eth_simulateV1` keeps the geth request/response shape, so viem/foundry-style
clients work unmodified — and with Chronos on, param 1 accepts a historical hex
height and full `stateOverrides` (balance/code/state/stateDiff) + creation calls:

```sh
curl -s -X POST $RPC -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"eth_simulateV1","params":[
    { "blockStateCalls":[{
        "stateOverrides": { "0x00000000000000000000000000000000000000ef": { "code":"0x602a60005260206000f3" } },
        "calls": [ { "from":"0x0000000000000000000000000000000000000001",
                     "to":"0x00000000000000000000000000000000000000ef", "gas":"0x989680" } ]
    }]},
    "0x50df458"
  ]
}'
# result[0].calls[0]: { "status":"0x1", "returnData":"0x…2a" }
```

`POST /v1/sim/bundle` (body = a `tron_simulateBundle` bundle) is the REST mirror,
wrapped as `{ "success": true, "data": … }`.

---

## Errors

Errors come back as JSON-RPC `error` objects. Common ones:

| Message contains | Cause | Fix |
| --- | --- | --- |
| `Chronos fork simulation is disabled` | `[sim] enabled = false` | set `[sim] enabled = true` |
| `not available on this node` | archive missing | enable `[index]` + `[index.archive]` |
| `outside archive coverage [base, head]` | `base` before the archive window | fork inside coverage, or rebuild the archive from a snapshot |
| `hex string must start with 0x` | bare-hex `data` / `code` | prefix with `0x` |
| `RejectCallerWithCode` (status) | `from` has code (EIP-3607) | use a codeless caller address |
| `state replace-all … > cap` | too many `state` slots | use `stateDiff` to set individual slots |
| `unknown or expired forkId` | session evicted (TTL/LRU) or bad id | recreate the fork |

---

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
  at `max_struct_logs` / `max_struct_log_bytes` per call; a truncated trace sets
  `structLogsTruncated`.
- **selfCheck is contractRet-CLASS parity, not the exact-code tripwire** — it
  re-runs block N+1's index-0 tx and compares the outcome class (Success /
  Revert / TransferFailed / Halt). A mismatch may be a real divergence or a
  VM-mode limitation (a tx needing more than `energy_cap`, one relying on
  frozen energy, or a maintenance-boundary block); the rigorous byte-exact
  check is the rig parity run.
- **Isolation** — nothing Chronos does can reach disk: height-based overlays
  sit on read-only at-height views and no session is ever committed.
