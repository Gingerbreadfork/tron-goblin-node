# Verifiable State-Commitment Layer

The state-commitment layer gives the node something TRON itself does not
provide: a **cryptographic commitment over the node's committed state**.
When enabled, the node maintains a Sparse Merkle Tree (keccak256) over its
state and exposes:

- **A state root** — a single 32-byte hash that commits to the node's
  current key/value state at a final height.
- **Inclusion / exclusion proofs** — a client can prove offline that a
  given account or storage key had a given value (or was absent) at the
  committed height, checking the proof against the root without trusting
  the operator.
- **An integrity self-check** — two nodes that bootstrap independently
  (from different snapshots, or one `tron-node` and one java-tron) and
  converge to the same committed state must compute the **byte-identical**
  root. An operator can therefore prove their node is byte-exact with the
  canonical chain by comparing roots.

It is **disabled by default** and is **not consensus-critical**: it runs
off the block-apply hot path and never blocks sync. Turn it on
deliberately.

## Why this is not a normal node feature

TRON block headers commit to the transaction Merkle root but **not** to an
enforced state root (unlike Ethereum). There is no canonical hash of "the
world at block N", and the public network exposes none. A stock node keeps
only current state plus a shallow undo log for reorgs, so there is no way
to hand a third party a compact, verifiable answer to "did account A hold
balance B?" — they have to trust an RPC.

This layer manufactures the missing root. The root is a **pure function of
the current key/value set** — history-independent: it depends only on which
keys hold which values, never on the path or order of per-block changes
taken to reach that state. Two nodes that reach the same committed state
compute the same root regardless of how they got there (insertion order,
snapshot origin, or implementation). That is exactly the property that
makes it a useful integrity check across independent nodes.

Because the root is reproducible from state alone, an operator who suspects
state drift can compare their node's root against another node (or a
java-tron node running the same commitment scheme) at the same committed
height: a mismatch is a precise, early signal that one node's state has
diverged.

## What the root covers

The root commits to the **executor-written state surface**: exactly the
stores the executor's per-block write-set can touch — the same surface the
[historical-state archive](historical-state-archive.md) versions. It is
**not** a commitment to every RocksDB store on disk.

In particular, `account_asset` is **not** part of the root, mirroring the
archive: the executor never writes that store (TRC-10 balances live inline
in `Account.asset_v2`), so it can never appear in the per-block write-set
and cannot be kept current off that stream. The executor-written surface is
the only surface that can be maintained deterministically, which is why it
is the definition. The `/root`, `/status`, and `/proof` responses all
describe the root as covering the executor-written state surface, not "all
on-disk state".

## Committed height trails the head (by design)

The committed root deliberately **trails the live head** by a fixed
confirmation lag (`confirmation_lag_blocks`, default 20). A root is folded
into the tree only once its height is final — past TRON's ~19-block PBFT
finality — so a committed root never names a reorg-able tip height. A proof
against an orphaned height would be worthless, so the layer never produces
one.

`committed_height` is therefore ~`confirmation_lag_blocks` blocks behind
head, and the RPC always reports the exact committed height the root
corresponds to. This lag is intended and acceptable precisely because the
commitment is not consensus-critical:

- **Reorgs shallower than the lag** are absorbed before the affected height
  is ever committed — they change buffered, not-yet-folded state, so there
  is nothing to undo and the committed root is unaffected.
- **Committed roots are final.** Anything the layer has rooted is past
  finality, so a client verifying a proof against a committed root can rely
  on it.

## Enabling it

The commitment layer has its own config section:

```toml
[index.commitment]
enabled                  = true   # master switch (default false)
confirmation_lag_blocks  = 20     # commit depth behind head (default 20)
max_lag_blocks           = 256    # builder-lag warn threshold (default 256)
```

`enabled = true` implies `[index] capture_state_deltas` (the underlying
per-block write-set capture) and requires `[storage] snapshot_reorg =
false` (the default reorg engine, which the capture path depends on). See
[config.example.toml](../config.example.toml) for the per-key comments and
defaults.

The layer is **independent of `[index.archive]`** — neither requires the
other. You can run the commitment layer with no archive (for the integrity
self-check and current-state proofs), the archive with no commitment, or
both. If you only want the integrity self-check, the layer keeps just the
latest tree, which is the cheap mode.

When the layer is first enabled on a node that already has state, it
performs a one-time full Merkleization of the executor-written surface at
the current head (minutes to low tens of minutes on mainnet, on the
background builder, never on the apply path). The current root is available
once that bootstrap completes; `/v1/commitment/status` reports progress
while it runs.

### Config reference

| Key | Type | Default | Meaning |
| --- | --- | ---: | --- |
| `enabled` | bool | `false` | Master switch. Implies `[index] capture_state_deltas`. |
| `confirmation_lag_blocks` | u64 | `20` | Blocks behind head at which roots are committed. Roots are folded only at this depth, so they sit past PBFT finality and never commit reorg-able tip state. `committed_height` trails head by ~this many blocks. Camel-case alias: `confirmationLagBlocks`. |
| `max_lag_blocks` | u64 | `256` | Warn threshold for how far the async builder may trail head before logging a warning. Tunes the warning only. Camel-case alias: `maxLagBlocks`. |

Lowering `confirmation_lag_blocks` below ~19 risks committing a root that a
tip reorg later orphans (the height is no longer past finality when it is
folded). The default of 20 leaves a one-block margin past TRON's ~19-block
PBFT finality. Raising it widens the lag.

## Storage and cost

The v1 layer stores **only the latest tree**: one leaf per live key plus
the internal nodes on the populated paths, all overwritten in place as the
state changes (no per-height versioning). This is **roughly a few percent
of state size** — far smaller than a full archive, which keeps every
historical version of every touched key.

Commitment data lives under `<data_dir>/commitment/db`, separate from the
archive (`<data_dir>/archive/db`) and the disposable address-history index
(`<data_dir>/index/`). It is its own RocksDB instance with independent
compactions, bounded by the process-wide shared block cache and
write-buffer manager.

Per changed key per block, the builder rewrites only the nodes on that
key's path (comparable to a single Merkle-Patricia update), so steady-state
write volume is a small fraction of full chain-state write volume. Watch
the `tron_node_*commitment*` metrics for builder lag and folded-block
counters.

## The API

All endpoints are served on the HTTP REST port (default
`127.0.0.1:8091`). When the layer is not enabled, every route returns
`501 Not Implemented` with a message pointing at
`[index.commitment] enabled = true`.

### Current root

```sh
curl -s 'http://127.0.0.1:8091/v1/commitment/root'
```

```json
{
  "success": true,
  "data": {
    "height": 83447108,
    "root": "0x9b3f0c1d8a4e6f2b5c7d9e0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e"
  }
}
```

`height` is the **committed** height the root commits to — it trails the
node's live head by ~`confirmation_lag_blocks` (see
[Committed height trails the head](#committed-height-trails-the-head-by-design)).
While the layer is still performing its one-time bootstrap, `height` is
`null` and `root` is the empty-tree root:

```json
{
  "success": true,
  "data": { "height": null, "root": "0x…", "note": "commitment bootstrapping" }
}
```

### Status

```sh
curl -s 'http://127.0.0.1:8091/v1/commitment/status'
```

```json
{
  "success": true,
  "data": {
    "committed_height": 83447108,
    "head_height": 83447128,
    "confirmation_lag_blocks": 20,
    "root": "0x9b3f0c1d8a4e6f2b5c7d9e0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e",
    "bootstrapping": false,
    "bootstrap_keys_done": 0,
    "empty_root": "0x5d0c1b…"
  }
}
```

- `committed_height` — the height the current `root` commits to.
- `head_height` — the max height the builder has seen (≈ live head);
  `committed_height` trails this by ~`confirmation_lag_blocks`.
- `confirmation_lag_blocks` — the configured commit depth, echoed so a
  client can see exactly how far behind head the committed root sits.
- `bootstrapping` / `bootstrap_keys_done` — true and a rising key count
  during the one-time full Merkleization.
- `empty_root` — the root of an empty tree, a fixed constant useful when
  verifying exclusion proofs by hand.

### Proof

`GET` or `POST` (body wins for `POST`). A proof identifies a state entry by
its store and raw key, and the same convenience sugar as
`/v1/archive/storage` is accepted:

- `store` — required. Either the store name (e.g. `accounts`,
  `storagerow`, `code`) or its numeric discriminant.
- `key` — required. Hex (`0x`-optional) of the raw store key.
- `account=<T-addr|41-hex>` — sugar for `store=accounts` with the
  account's raw 21-byte key.
- `address=<contract>` + `slot=<hex slot>` — sugar that composes the
  `StorageRow` key exactly as a contract-storage read does, so the proof
  key matches the live read key byte-for-byte.

Account inclusion proof:

```sh
curl -s 'http://127.0.0.1:8091/v1/commitment/proof?account=TXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
```

```json
{
  "success": true,
  "data": {
    "height": 83447108,
    "root": "0x9b3f0c1d8a4e6f2b5c7d9e0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e",
    "included": true,
    "store": "accounts",
    "key": "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
    "leaf_path": "0x7c1e9a02b4d6f8103a5c7e9b0d2f4a6c8e012345679abcdef02468ace13579bdf",
    "value_hash": "0x3a5c7e9b0d2f4a6c8e0123456789abcdef0123456789abcdef0123456789abcd",
    "proof": {
      "sibling_mask": "0x0000000000000000000000000000000000000000000000000000000000003fa1",
      "siblings": [
        "0x6f2b5c7d9e0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829300",
        "0x1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9011"
      ]
    }
  }
}
```

An **exclusion** proof has the same shape with `"included": false`;
`value_hash` is omitted, and the proof reconstructs to the default (empty)
leaf at that path.

The response carries `value_hash` (the leaf commitment), not the raw value:
the SMT leaf stores `keccak256(value)`, and the committed root reflects state
at `committed_height` (which trails the head — see above), so the raw bytes
must be read at that exact height. Obtain them from the archive
(`/v1/archive/...` at `block = committed_height`, when `[index.archive]` is
enabled) or any source pinned to that height, then bind them with
`keccak256(value) == value_hash`.

Errors:

- `400` — bad or missing `store` / `key`, malformed hex or address,
  unknown store name.
- `501` — the commitment layer is not enabled on this node.
- `500` — store read failure.

### Verifying a proof offline

The proof is self-contained: a zero-trust client checks it against the root
without contacting the node again. The recipe:

1. **Recompute the leaf path.** `leaf_path = keccak256(store_byte ‖ key)`,
   where `store_byte` is the single-byte store discriminant and `key` is the
   raw store key (both as returned in the response, with `‖` plain byte
   concatenation). Confirm it equals the response's `leaf_path`.
2. **Walk the proof to a root.** Starting from the leaf, fold up the
   256-level path. At each level, the bit of `leaf_path` (read MSB-first)
   chooses whether the recomputed hash is the left or right child; the
   sibling is taken from `siblings` when `sibling_mask` marks that level as
   non-default, otherwise it is the precomputed empty-subtree default for
   that level. Internal nodes hash as `keccak256(0x01 ‖ left ‖ right)`; the
   occupied leaf contributes `keccak256(0x00 ‖ leaf_path ‖ value_hash)`. For
   an exclusion proof the leaf slot is the empty default.
3. **Compare to the root.** The reconstructed level-0 hash must equal the
   `root` in the response (and a root you obtained from a trusted source).
4. **For inclusion, bind the value.** Fetch the raw value as of
   `committed_height` (e.g. from `/v1/archive` at that block, or any
   height-pinned source), then check `keccak256(value) == value_hash`. The
   commitment endpoint serves only `value_hash`, so the value comes from a
   source the client already trusts to hold the bytes — the proof binds it to
   the root.

The `0x00` / `0x01` domain-separation prefixes distinguish leaf nodes from
internal nodes (preventing a value from being replayed at a different key),
and including the full `leaf_path` in the leaf hash binds the value to its
exact key. Verification depends only on keccak256 and these public
constants — no node state.

## Integrity self-check between two nodes

The headline use of the layer: prove that a node's state is byte-exact with
the canonical chain by comparing roots with an independently-bootstrapped
node.

1. Enable `[index.commitment]` on both nodes and let each finish its
   one-time bootstrap (`/v1/commitment/status` → `bootstrapping: false`).
2. Read `/v1/commitment/root` on each. Pick a height both have committed —
   because the root is history-independent, the two nodes need only agree on
   the **committed height**, not on how they reached it.
3. Compare the roots **at the same `committed_height`**:
   - **Identical** → the two nodes hold byte-identical state across the
     entire executor-written surface at that height. That is strong evidence
     the node under test is byte-exact with the canonical chain.
   - **Different** → the two nodes' state has diverged. Use
     `/v1/commitment/proof` on each for suspect accounts/slots and compare
     `value_hash` to localize the divergent key.

Because the comparison is a single 32-byte hash, it scales to full mainnet
state and works against any node implementing the same scheme — including a
java-tron node running an equivalent commitment.

## Operational notes

- **Off the hot path.** The builder runs as a background task. It never
  blocks block apply or sync; the committed root simply trails head by the
  confirmation lag.
- **Bootstrap begins at the current head.** Enabling on an existing node
  Merkleizes the live state at the then-current head. There is no
  per-height history in v1 — the layer keeps the latest tree only.
- **Not cheaply re-derived.** Disabling and re-enabling, or a crash gap that
  out-lives the recovery sources, triggers a full re-Merkleization at the
  then-current head (loudly). The current-tree storage cost makes this far
  cheaper than rebuilding an archive, but it is still a full state pass.
- **Requires `[storage] snapshot_reorg = false`** (the default reorg
  engine), which the write-set capture depends on — the same requirement as
  the archive.
- **Independent of the archive.** Storage, RocksDB instance, and enablement
  are all separate from `[index.archive]`.

## Roadmap — phase 2 (not yet shipped)

The v1 layer delivers the current-state root, inclusion/exclusion proofs
against that root, and the integrity self-check. The following are
**planned, not yet implemented** — do not rely on them today:

- **Historical at-height proofs.** Proofs and roots for a past height N
  (`N < head`), so a client could verify "key K held value V at height N",
  not only at the current committed height. v1 commits and proves against
  the latest committed root only.
- **On-chain anchoring.** Publishing roots on-chain together with an
  on-chain (e.g. Solidity) proof verifier. The keccak256 hashing and
  domain-separation scheme were chosen to keep this open, but no anchoring
  or on-chain verifier ships in v1.

These would build on the same tree and proof format, so proofs you verify
today against a committed root will keep verifying.
