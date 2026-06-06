# tron-state-diff

Diff **RPC-level state** between a `tron-goblin-node` (node A) and a reference
**java-tron** node (node B).

## Why this exists

TRON block headers carry no state root (only `txTrieRoot`). So byte-identical
block hashes — which this node produces — do **not** prove the resulting
*state* matches java-tron. A consensus-state bug (wrong balance, usage,
delegated resource, …) is invisible to block-hash comparison. The only way to
verify state-exactness parity is to read the same accounts from both nodes and
diff the responses. That's what this tool does.

It's the verification companion to the consensus-state work (delegated-resource
usage-transfer, the V2 window machinery, reorg rollback): those are implemented
to java-tron's spec and unit-tested against its formulas, but only an
RPC-level diff against a live java-tron node confirms byte-equality.

## How it works

1. **Settle** — polls `/wallet/getnowblock` on both nodes until they report the
   same head block id (state queries return *current head* state, so the two
   nodes must be compared at the same head).
2. **Probe** — for each address, calls each probe endpoint on both nodes and
   diffs the JSON.
3. **Head-stability** — a mismatch seen while the head moved mid-probe could be
   a one-block-stale artifact, not a real divergence. Matches are always
   trusted; mismatches are only reported as real when both nodes held the same
   head for the whole probing window. Unsettled mismatches are retried, then
   reported as *inconclusive*.

### Probes (REST, both nodes expose them)

| probe      | endpoint                      | covers                                                                 |
|------------|-------------------------------|-----------------------------------------------------------------------|
| `account`  | `/wallet/getaccount`          | balance, `frozenV2`, delegated/acquired V2, **net_usage / energy_usage, window sizes, latest_consume_time** |
| `resource` | `/wallet/getaccountresource`  | bandwidth / energy limits + usage (depends on chain-wide weights)     |
| `contract` | `/wallet/getcontract`         | contract bytecode / ABI / settings                                    |

`account` alone validates the bulk of the delegated-resource + usage-transfer +
window-machinery work. (The `DelegatedResource` records and the account index
aren't REST-exposed by this node yet, so they're out of v1 scope.)

### Diff normalization

TRON renders protobuf to JSON with **default-valued fields omitted**, and two
faithful nodes can legitimately omit different defaults (one emits
`"net_usage": 0`, the other drops it). The differ treats a missing key as the
default of the other side's type, so only genuinely non-default divergences are
reported. Object key order is ignored.

## Usage

```sh
# Build
cargo build --release -p tron-state-diff

# Diff the accounts touched in the last 200 blocks, against your java-tron node
./target/release/tron-state-diff \
    --a http://127.0.0.1:8090 \
    --b http://192.168.0.36:8090 \
    --from-recent-blocks 200

# Diff a specific set of accounts
tron-state-diff --b http://192.168.0.36:8090 \
    --accounts TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t,TWdYx... \
    --probes account,resource

# Accounts from a file, machine-readable output
tron-state-diff --b http://192.168.0.36:8090 --accounts-file addrs.txt --json
```

### Flags

| flag | default | meaning |
|------|---------|---------|
| `--b <url>` | *(required)* | reference java-tron base URL |
| `--a <url>` | `http://127.0.0.1:8090` | node-under-test base URL |
| `--accounts <a,b,c>` | — | base58 addresses to probe |
| `--accounts-file <path>` | — | one base58 address per line (`#` comments ok) |
| `--from-recent-blocks <N>` | `0` | also probe every address touched in the last N blocks |
| `--probes <list>` | `account,resource` | any of `account,resource,contract` |
| `--settle-timeout-secs <n>` | `30` | max wait for a common head |
| `--max-rounds <n>` | `3` | re-check rounds for head-unstable mismatches |
| `--http-timeout-secs <n>` | `10` | per-request timeout |
| `--json` | off | machine-readable report |

### Exit codes

- `0` — no real divergences found
- `1` — at least one confirmed mismatch (observed under a stable head)
- `2` — usage error, or the nodes never converged on a common head

## Notes / limits

- Plain HTTP only (LAN full node); no TLS.
- Addresses are exchanged base58 (`visible: true`).
- An address absent on both nodes counts as a match.
- A frequently-updated account whose head never holds still is reported
  *inconclusive*, not a mismatch.
