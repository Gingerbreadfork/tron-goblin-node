# LLM Project Context

## Mission

Rust implementation of a TRON full node with java-tron-compatible wire protocol,
RocksDB state layout, block execution, RPC/gRPC/REST APIs, indexing, firehose,
mempool, and operational tooling.

## Status Snapshot

- Pre-release and experimental.
- Can sync public mainnet from java-tron RocksDB snapshots, apply blocks, hold
  live tip in tested sessions, and compute canonical block hashes.
- Block-STM parallel execution is optional and must remain byte-identical to the
  serial path.
- Major remaining risks include long-running mainnet soak and residual
  java-tron edge-case parity.

## Non-Negotiable Invariants

- Do not break java-tron RocksDB store compatibility.
- Do not treat matching block hashes as proof of state parity; TRON block
  headers do not include state roots.
- State-changing execution changes need tests and, when possible,
  `tron-state-diff` validation.
- Reorg code must restore all mutated stores and head pointers atomically.
- Vendored `revm-*` crates are intentional workspace patches.

## Main Runtime Command

```sh
cargo build --release
./target/release/tron-node start --config config.toml
```

## Primary Docs

- Human docs index: `docs/README.md`
- Architecture: `docs/architecture.md`
- Development workflow: `docs/development.md`
- Operator guide: `docs/operations.md`
- Config reference source: `config.example.toml`

## Good AI Behavior in This Repo

- Read the crate and tests before changing behavior.
- Prefer existing store/session/config patterns.
- Keep changes narrow and parity-oriented.
- Run package-specific tests first, then broader tests when risk warrants.
- Do not modify generated or vendored revm code unless the task explicitly
  concerns interpreter/context behavior.
- Preserve unrelated local changes in the worktree.
- Update docs and `config.example.toml` when changing operator-facing behavior.
