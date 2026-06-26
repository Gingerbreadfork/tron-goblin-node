# Development

This workspace is built around protocol parity. Favor small, well-tested changes
that preserve byte-level compatibility with java-tron.

## Local Workflow

```sh
cargo fmt --all
cargo check --workspace
cargo test --workspace
```

For documentation-only changes, a Markdown/source-link review is usually enough
unless command examples or generated API docs changed.

For release-only or heavy coverage:

```sh
cargo test --workspace --release -- --ignored
```

Use narrower package tests while iterating:

```sh
cargo test -p tron-types
cargo test -p tron-tvm
cargo test -p tron-node sync
```

## Crate Map for Contributors

- `tron-crypto`: base58check, hashes, secp256k1, SM2, RLP, Merkle helpers.
- `tron-proto`: generated TRON protobuf messages.
- `tron-types`: block/tx wrappers, ID and root conventions.
- `tron-chainbase`: store codecs, RocksDB backend, sessions, snapshots,
  rollback primitives.
- `tron-actuator`: per-contract validation and execution.
- `tron-executor`: block validation/application and serial vs parallel
  execution orchestration.
- `tron-tvm`: TRON VM host, energy model, precompiles, TRC-10 behavior,
  shielded support.
- `tron-consensus`: DPoS and fork-choice helpers.
- `tron-net`: wire framing, TRON P2P messages, discovery helpers.
- `tron-node`: daemon runtime, config, sync, inbound serving, snapshots, admin,
  index hooks, SR/PBFT runtimes.
- `tron-rpc` and `tron-grpc`: client-facing APIs.
- `tron-index`: address history, archive rows, query engine, firehose log.
- `tron-mempool`: transaction admission, deduplication, persistence, relay feed.
- `tron-eventer`: java-tron logsfilter-compatible event emission.
- `tron-wallet`: key, keystore, mnemonic, signing, broadcast CLI.
- `tron-state-diff`: RPC-level state parity verifier against java-tron.

## Parity Testing Strategy

Block hashes prove transaction ordering and transaction Merkle root parity, but
not full state parity because TRON headers lack a state root. Use layered
verification:

1. Unit tests for deterministic codecs, hashes, actuators, and store behavior.
2. Integration tests for sync, reorgs, RPC, index, and archive paths.
3. Serial-vs-parallel executor equivalence tests for Block-STM changes.
4. `tron-state-diff` against a java-tron reference node for account/resource,
   contract, and constant-call state checks.
5. Mainnet soak tests for peer churn, long catch-up, API behavior, and resource
   usage.

## State Diff Tool

Build:

```sh
cargo build --release -p tron-state-diff
```

Compare recent touched accounts against a java-tron node:

```sh
./target/release/tron-state-diff \
  --a http://127.0.0.1:8090 \
  --b http://<java-tron-host>:8090 \
  --from-recent-blocks 200
```

Validate TVM constant-call behavior:

```sh
./target/release/tron-state-diff \
  --b http://<java-tron-host>:8090 \
  --from-recent-blocks 200 \
  --constant
```

Both nodes need constant-call support enabled for constant-call probes.

## Implementation Guidance

- Preserve store key/value encodings. Compatibility with java-tron snapshots is
  a core feature.
- Keep state mutation paths session-oriented so rollback and reorg logic can
  remain atomic.
- When touching execution, add tests that compare serial and parallel behavior
  if the code can affect committed state.
- When adding RPC fields, check protobuf JSON default omission behavior.
  Missing default-valued fields may be compatibility-correct.
- Treat config parsing as a compatibility surface. Maintain snake_case and
  existing accepted aliases when adding fields.
- Avoid adding sink dependencies to `tron-node` for optional external pipelines;
  firehose consumers are intentionally out-of-process.
- Keep docs close to the code: when changing a command, config field, endpoint,
  or crate responsibility, update `docs/` and `config.example.toml` as needed.

## Files to Treat Carefully

- Vendored `crates/revm-*` are intentional forks. Avoid broad mechanical
  changes there unless the task is specifically about VM interpreter/context
  behavior.
- Generated protobuf output should be changed through the proto/build path, not
  by editing generated code.
- Consensus stores and key encodings are compatibility boundaries; changing them
  can make existing java-tron snapshots unreadable.

## Useful Files

- Node CLI: [crates/tron-node/src/main.rs](../crates/tron-node/src/main.rs)
- Node config: [crates/tron-node/src/config.rs](../crates/tron-node/src/config.rs)
- Runtime orchestration: [crates/tron-node/src/runtime.rs](../crates/tron-node/src/runtime.rs)
- Sync: [crates/tron-node/src/sync.rs](../crates/tron-node/src/sync.rs)
- Storage API: [crates/tron-chainbase/src/lib.rs](../crates/tron-chainbase/src/lib.rs)
- Executor: [crates/tron-executor/src/lib.rs](../crates/tron-executor/src/lib.rs)
- TVM execution: [crates/tron-tvm/src/execute.rs](../crates/tron-tvm/src/execute.rs)
- RPC methods: [crates/tron-rpc/src/methods.rs](../crates/tron-rpc/src/methods.rs)
- Index engine: [crates/tron-index/src/engine.rs](../crates/tron-index/src/engine.rs)
