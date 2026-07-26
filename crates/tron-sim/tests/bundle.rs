//! End-to-end bundle execution over `MemBackend`: a mutating call actually
//! runs through the TVM against the overlay, state accumulates and diffs,
//! creates deploy, trace levels behave, and status mapping is correct.

use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend};
use tron_crypto::address::Address;

use tron_sim::{
    AccountOverride, BlockSpec, CallSpec, CallStatus, DiffLevel, ForkBackends, ForkOverlay,
    OverrideSet, SimConfig, SimRequest, TraceLevel,
};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fork() -> ForkOverlay {
    let fb = ForkBackends {
        accounts: mem(),
        code: mem(),
        storage: mem(),
        witnesses: mem(),
        contract_state: mem(),
        dyn_props: mem(),
        delegated_resources: mem(),
        delegation: mem(),
        contracts: mem(),
        votes: Some(mem()),
        abi: Some(mem()),
        block_index: Some(mem()),
    };
    ForkOverlay::new(&fb, None).unwrap()
}

fn addr(n: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[20] = n;
    Address::from_raw(a)
}

fn word(n: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = n;
    w
}

fn fund(set: &mut OverrideSet, a: Address) {
    set.accounts
        .insert(a, AccountOverride { balance: Some(1_000_000_000), ..Default::default() });
}

fn code(set: &mut OverrideSet, a: Address, bytecode: Vec<u8>) {
    set.accounts
        .insert(a, AccountOverride { code: Some(bytecode), ..Default::default() });
}

// PUSH1 0x2a PUSH1 0x00 SSTORE STOP  — store 0x2a at slot 0.
const SSTORE_2A: [u8; 6] = [0x60, 0x2a, 0x60, 0x00, 0x55, 0x00];
// PUSH1 0x00 PUSH1 0x00 REVERT — revert immediately.
const REVERT_NOW: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];
// init code returning a 1-byte 0x00 runtime.
const INIT_RETURNS_STOP: [u8; 10] =
    [0x60, 0x00, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3];

fn trigger(from: Address, to: Address, energy: u64) -> CallSpec {
    CallSpec::Trigger {
        from,
        to,
        value: 0,
        data: Vec::new(),
        energy: Some(energy),
        token_id: 0,
        token_value: 0,
    }
}

fn run(ov: &mut ForkOverlay, req: SimRequest) -> tron_sim::SimResult {
    tron_sim::run_bundle(ov, &req, &SimConfig::default(), [0u8; 16], None).unwrap()
}

#[test]
fn mutating_trigger_runs_and_diffs() {
    let mut ov = fork();
    let (c, caller) = (addr(0x10), addr(0x11));
    let mut ovr = OverrideSet::default();
    code(&mut ovr, c, SSTORE_2A.to_vec());
    fund(&mut ovr, caller);

    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
        return_state_diff: DiffLevel::Final,
        ..Default::default()
    };
    let res = run(&mut ov, req);

    let call = &res.blocks[0].calls[0];
    assert_eq!(call.status, CallStatus::Success, "err={:?}", call.error);
    assert!(call.energy_used > 0);
    let diff = res.state_diff.expect("final diff requested");
    assert!(
        diff.storage.iter().any(|s| s.after == Some(word(0x2a))),
        "expected SSTORE 0x2a in storage diff, got {:?}",
        diff.storage
    );
}

#[test]
fn reverting_call_reports_revert() {
    let mut ov = fork();
    let (c, caller) = (addr(0x12), addr(0x13));
    let mut ovr = OverrideSet::default();
    code(&mut ovr, c, REVERT_NOW.to_vec());
    fund(&mut ovr, caller);

    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
        ..Default::default()
    };
    let res = run(&mut ov, req);
    assert_eq!(res.blocks[0].calls[0].status, CallStatus::Revert);
}

#[test]
fn create_deploys_and_reports_address() {
    let mut ov = fork();
    let deployer = addr(0x20);
    let mut ovr = OverrideSet::default();
    fund(&mut ovr, deployer);

    let req = SimRequest {
        blocks: vec![BlockSpec {
            overrides: ovr,
            calls: vec![CallSpec::Create {
                from: deployer,
                init_code: INIT_RETURNS_STOP.to_vec(),
                value: 0,
                energy: Some(2_000_000),
                consume_user_resource_percent: 100,
                name: "Probe".to_string(),
                token_id: 0,
                token_value: 0,
            }],
        }],
        ..Default::default()
    };
    let res = run(&mut ov, req);
    let call = &res.blocks[0].calls[0];
    assert_eq!(call.status, CallStatus::Success, "err={:?}", call.error);
    assert!(call.contract_address.is_some(), "create must report the deployed address");
    // Create return data is blanked; the address is on `contract_address`.
    assert!(call.return_data.is_empty());
}

#[test]
fn trace_levels_control_capture() {
    let (c, caller) = (addr(0x14), addr(0x15));
    let build = |lvl: TraceLevel| {
        let mut ov = fork();
        let mut ovr = OverrideSet::default();
        code(&mut ovr, c, SSTORE_2A.to_vec());
        fund(&mut ovr, caller);
        let req = SimRequest {
            blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
            trace: lvl,
            return_state_diff: DiffLevel::None,
            ..Default::default()
        };
        let res = run(&mut ov, req);
        res.blocks[0].calls[0].clone()
    };

    let none = build(TraceLevel::None);
    assert!(none.struct_logs.is_empty() && none.call_frames.is_empty());

    let tree = build(TraceLevel::CallTree);
    assert!(tree.struct_logs.is_empty(), "callTree must not carry struct logs");
    assert!(!tree.call_frames.is_empty(), "callTree must carry the call frame");

    let full = build(TraceLevel::Full);
    assert!(!full.struct_logs.is_empty(), "full must carry opcode struct logs");
    assert!(!full.call_frames.is_empty());
}

#[test]
fn per_call_diff_is_attached() {
    let mut ov = fork();
    let (c, caller) = (addr(0x16), addr(0x17));
    let mut ovr = OverrideSet::default();
    code(&mut ovr, c, SSTORE_2A.to_vec());
    fund(&mut ovr, caller);

    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
        return_state_diff: DiffLevel::PerCall,
        ..Default::default()
    };
    let res = run(&mut ov, req);
    let call = &res.blocks[0].calls[0];
    let d = call.state_diff.as_ref().expect("per-call diff");
    assert!(d.storage.iter().any(|s| s.after == Some(word(0x2a))));
}

#[test]
fn multi_block_numbers_increment_and_state_accumulates() {
    let mut ov = fork();
    let (c, caller) = (addr(0x18), addr(0x19));
    let mut b1 = OverrideSet::default();
    code(&mut b1, c, SSTORE_2A.to_vec());
    fund(&mut b1, caller);

    let req = SimRequest {
        blocks: vec![
            BlockSpec { overrides: b1, calls: vec![trigger(caller, c, 1_000_000)] },
            // Second block: no overrides; the contract code from block 1
            // persists in the overlay, so this call runs the same SSTORE.
            BlockSpec { overrides: OverrideSet::default(), calls: vec![trigger(caller, c, 1_000_000)] },
        ],
        ..Default::default()
    };
    let res = run(&mut ov, req);
    assert_eq!(res.blocks.len(), 2);
    assert!(res.blocks[1].number > res.blocks[0].number);
    assert_eq!(res.blocks[0].calls[0].status, CallStatus::Success);
    assert_eq!(
        res.blocks[1].calls[0].status,
        CallStatus::Success,
        "block-1 code must persist into block 2: {:?}",
        res.blocks[1].calls[0].error
    );
}

#[test]
fn deterministic_replay_is_identical() {
    let run_once = || {
        let mut ov = fork();
        let (c, caller) = (addr(0x1a), addr(0x1b));
        let mut ovr = OverrideSet::default();
        code(&mut ovr, c, SSTORE_2A.to_vec());
        fund(&mut ovr, caller);
        let req = SimRequest {
            blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
            return_state_diff: DiffLevel::Final,
            ..Default::default()
        };
        let res = run(&mut ov, req);
        let call = &res.blocks[0].calls[0];
        (call.energy_used, call.status.clone(), res.state_diff.unwrap().storage.len())
    };
    assert_eq!(run_once(), run_once());
}

#[test]
fn full_trace_struct_logs_are_capped() {
    let mut ov = fork();
    let (c, caller) = (addr(0x24), addr(0x25));
    let mut ovr = OverrideSet::default();
    code(&mut ovr, c, SSTORE_2A.to_vec()); // 4 opcodes
    fund(&mut ovr, caller);
    // Cap struct-logs at 2; the contract runs more than 2 opcodes.
    let cfg = SimConfig { max_struct_logs: 2, ..Default::default() };
    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
        trace: TraceLevel::Full,
        return_state_diff: DiffLevel::None,
        ..Default::default()
    };
    let res = tron_sim::run_bundle(&mut ov, &req, &cfg, [0u8; 16], None).unwrap();
    let call = &res.blocks[0].calls[0];
    assert_eq!(call.status, CallStatus::Success, "err={:?}", call.error);
    assert!(call.struct_logs.len() <= 2, "struct logs must be capped: {}", call.struct_logs.len());
    assert!(call.struct_logs_truncated, "truncation must be flagged");
}

#[test]
fn full_trace_struct_logs_capped_by_bytes() {
    let mut ov = fork();
    let (c, caller) = (addr(0x26), addr(0x27));
    let mut ovr = OverrideSet::default();
    code(&mut ovr, c, SSTORE_2A.to_vec());
    fund(&mut ovr, caller);
    // Unlimited count, but a 1-byte budget → drops every log (each is ≥96 B).
    let cfg = SimConfig { max_struct_logs: 0, max_struct_log_bytes: 1, ..Default::default() };
    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
        trace: TraceLevel::Full,
        return_state_diff: DiffLevel::None,
        ..Default::default()
    };
    let res = tron_sim::run_bundle(&mut ov, &req, &cfg, [0u8; 16], None).unwrap();
    let call = &res.blocks[0].calls[0];
    assert_eq!(call.status, CallStatus::Success, "err={:?}", call.error);
    assert!(call.struct_logs.is_empty(), "a 1-byte budget must drop all logs");
    assert!(call.struct_logs_truncated, "byte-budget truncation must be flagged");
}

// PUSH1 0 ×7 (CALL's 7 stack args), CALL (0xf1), STOP — makes one inner CALL
// to the zero address, so the trace has a root frame + one nested frame.
const CALL_ZERO: [u8; 16] = [
    0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf1, 0x00,
];

#[test]
fn call_frames_are_capped() {
    let mut ov = fork();
    let (c, caller) = (addr(0x28), addr(0x29));
    let mut ovr = OverrideSet::default();
    code(&mut ovr, c, CALL_ZERO.to_vec());
    fund(&mut ovr, caller);
    // Two frames (root + inner CALL); cap of 1 drops one and flags it.
    let cfg = SimConfig { max_call_frames: 1, ..Default::default() };
    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
        trace: TraceLevel::CallTree,
        return_state_diff: DiffLevel::None,
        ..Default::default()
    };
    let res = tron_sim::run_bundle(&mut ov, &req, &cfg, [0u8; 16], None).unwrap();
    let call = &res.blocks[0].calls[0];
    assert!(call.call_frames_truncated, "frame cap must be flagged; frames={:?}", call.call_frames.len());
}

#[test]
fn callless_block_overrides_hit_overlay_cap() {
    // A block with overrides but NO calls must still be bounded by the
    // overlay-key cap (checked after applying overrides).
    let mut ov = fork();
    let a = addr(0x22);
    let mut diff = std::collections::BTreeMap::new();
    diff.insert(word(1), word(0xaa));
    diff.insert(word(2), word(0xbb));
    let mut oset = OverrideSet::default();
    oset.accounts
        .insert(a, AccountOverride { state_diff: Some(diff), ..Default::default() });
    let cfg = SimConfig { max_overlay_keys: 1, ..Default::default() };
    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: oset, calls: Vec::new() }],
        ..Default::default()
    };
    let err = tron_sim::run_bundle(&mut ov, &req, &cfg, [0u8; 16], None).unwrap_err();
    assert!(matches!(err, tron_sim::SimError::OverlayCapExceeded { .. }), "got {err:?}");
}

#[test]
fn state_diff_over_cap_errors() {
    let mut ov = fork();
    let a = addr(0x23);
    let mut diff = std::collections::BTreeMap::new();
    diff.insert(word(1), word(0xaa));
    diff.insert(word(2), word(0xbb));
    diff.insert(word(3), word(0xcc));
    let mut oset = OverrideSet::default();
    oset.accounts
        .insert(a, AccountOverride { state_diff: Some(diff), ..Default::default() });
    let cfg = SimConfig { max_state_override_slots: 2, ..Default::default() };
    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: oset, calls: Vec::new() }],
        ..Default::default()
    };
    let err = tron_sim::run_bundle(&mut ov, &req, &cfg, [0u8; 16], None).unwrap_err();
    assert!(matches!(err, tron_sim::SimError::Backend(_)), "got {err:?}");
}

#[test]
fn overlay_key_cap_is_enforced() {
    let mut ov = fork();
    let (c, caller) = (addr(0x1c), addr(0x1d));
    let mut ovr = OverrideSet::default();
    code(&mut ovr, c, SSTORE_2A.to_vec());
    fund(&mut ovr, caller);

    // Cap of 1 key: the override already writes several, so the call is refused.
    let cfg = SimConfig { max_overlay_keys: 1, ..Default::default() };
    let req = SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: vec![trigger(caller, c, 1_000_000)] }],
        ..Default::default()
    };
    let err = tron_sim::run_bundle(&mut ov, &req, &cfg, [0u8; 16], None).unwrap_err();
    assert!(
        matches!(err, tron_sim::SimError::OverlayCapExceeded { .. }),
        "got {err:?}"
    );
}
