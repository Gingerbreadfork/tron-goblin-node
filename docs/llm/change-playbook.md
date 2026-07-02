# LLM Change Playbook

Use this when making code changes in `tron-goblin-node`.

## Before Editing

1. Identify the narrow crate and file set from `docs/llm/code-map.md`.
2. Read nearby tests before choosing an implementation.
3. Check whether the change affects consensus state, RPC compatibility,
   storage compatibility, or external config.
4. Inspect `git status` and preserve unrelated user changes.
5. If behavior is operator-facing, inspect `config.example.toml` and `docs/`.

## Verification by Change Type

| Change Type | Minimum Verification |
| --- | --- |
| Formatting/docs only | Markdown review; no Cargo test required unless examples changed. |
| Config parsing/default | `cargo test -p tron-node config` or relevant config tests. |
| Crypto/types/proto | Package tests plus affected downstream package tests. |
| Store codecs/session/rollback | `cargo test -p tron-chainbase`; add integration coverage for rollback. |
| Actuator/executor/TVM state mutation | Affected crate tests; serial-vs-parallel equivalence if applicable; consider `tron-state-diff`. |
| Sync/reorg | Targeted `tron-node` sync/reorg tests; avoid relying only on unit tests. |
| RPC/REST/gRPC output | Relevant API tests; check default-field JSON behavior. |
| Index/archive/firehose | `tron-index` tests plus `tron-node` wiring tests if runtime hooks changed. |
| CLI behavior | Run the binary help or targeted command where feasible; update docs if flags changed. |
| Documentation | Check links, command accuracy, and whether the doc tells the reader what to do next. |

## Consensus-Sensitive Checklist

- Are all state writes routed through the expected session/store API?
- Is rollback/reorg behavior preserved?
- Does Block-STM parallel execution still match serial output?
- Are java-tron default omissions and protobuf encoding quirks respected?
- Is there any change to block ID, tx ID, Merkle root, or account-state root
  computation?
- Does it affect DPoS scheduling — witness ranking/tie-break, vote tally, reward,
  or maintenance accounting? These paths are era/proposal-gated; match java-tron's
  gate exactly (behavior differs before/after specific proposals).

## Config Change Checklist

- Add field to the appropriate struct in `crates/tron-node/src/config.rs`.
- Set an explicit default.
- Preserve existing aliases and naming conventions.
- Update `config.example.toml`.
- Update `docs/configuration.md` if operator-facing.

## API Change Checklist

- Confirm which surface is affected: JSON-RPC, REST wallet, gRPC, `/v1` index,
  archive, or firehose.
- Add tests around request shape, response shape, and error behavior.
- For REST/protobuf JSON, be careful with absent default-valued fields.
- Update docs when endpoints, params, ports, or compatibility behavior changes.

## Avoid

- Broad refactors while fixing a parity bug.
- Replacing structured protobuf/store parsing with string manipulation.
- Adding dependencies to `tron-node` for optional external sinks.
- Editing vendored `revm-*` crates unless required by VM/interpreter work.
- Assuming live-mainnet behavior without tests or a reproducible diagnostic.
