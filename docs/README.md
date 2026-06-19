# Tron Goblin Node Documentation

This directory contains focused project documentation for operators,
contributors, and AI coding agents. The root [README](../README.md) remains the
high-level project narrative and status page; these docs are organized by task.

## Status

`tron-goblin-node` is pre-release software. It is suitable for evaluation,
parity testing, development, and controlled infrastructure experiments. Treat it
as not yet a drop-in production replacement for java-tron unless your deployment
has its own soak testing, monitoring, rollback plan, and java-tron comparison
path.

## Start Here

| Goal | Read |
| --- | --- |
| Understand the system shape | [Architecture](architecture.md) |
| Build, run, import snapshots, operate services | [Operations](operations.md) |
| Choose safe runtime settings | [Configuration](configuration.md) |
| Prepare a public or production-like deployment | [Security and Production Readiness](security-production.md) |
| Use RPC, history APIs, archive reads, or firehose | [APIs, Indexing, and Firehose](apis-indexing-firehose.md) |
| Read account/contract state (or run calls) at a past block | [Historical-State Archive](historical-state-archive.md) |
| Get a verifiable state root + offline proofs, or self-check a node is byte-exact | [Verifiable State Commitment](verifiable-state-commitment.md) |
| Change code or validate parity | [Development](development.md) |
| Diagnose common failures | [Troubleshooting](troubleshooting.md) |

## AI-Optimized Docs

The [llm](llm/) folder is intentionally terse and structured for AI assistants:

- [llm/README.md](llm/README.md) explains how to use the AI docs.
- [llm/project-context.md](llm/project-context.md) gives mission, invariants,
  current status, and risk boundaries.
- [llm/code-map.md](llm/code-map.md) maps crates and important files to likely
  tasks.
- [llm/change-playbook.md](llm/change-playbook.md) gives safe modification and
  verification guidance for common work.

## Source of Truth

- Workspace membership and dependencies: [Cargo.toml](../Cargo.toml)
- Runtime defaults and config comments: [config.example.toml](../config.example.toml)
- `tron-node` CLI behavior: [crates/tron-node/src/main.rs](../crates/tron-node/src/main.rs)
- Node configuration structs: [crates/tron-node/src/config.rs](../crates/tron-node/src/config.rs)
- State diff tool details: [crates/tron-state-diff/README.md](../crates/tron-state-diff/README.md)

When documentation and code disagree, treat code and tests as authoritative and
update the docs in the same change.

## Maintenance Rules

- Keep operator commands copy-pasteable from the repository root.
- Prefer linking to source files over restating every flag or field.
- If a CLI, config key, endpoint, or crate responsibility changes, update the
  relevant docs in the same commit.
