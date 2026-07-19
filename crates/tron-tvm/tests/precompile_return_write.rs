//! Precompile return-data memory write, across the
//! `ALLOW_TVM_SELFDESTRUCT_RESTRICTION` (proposal #94) boundary.
//!
//! java-tron's `Program.callToPrecompiledAddress` picks its memory-write
//! overload on that proposal (`Program.java:1771-1775`):
//!
//! * before #94 — `memorySave(int addr, byte[] value)`, i.e.
//!   `memory.write(addr, value, value.length, false)`. The write length is the
//!   precompile OUTPUT's own length; `outDataSize` is never consulted. With
//!   `limited = false` the write routes through `Memory.extend`, which grows
//!   memory with no energy accounting at all, so both MSIZE and the
//!   memory-charging baseline move for free.
//! * from #94 — `memorySave(int addr, int allocSize, byte[] value)`, which
//!   truncates to `min(outDataSize, value.length)` inside the return window the
//!   caller already paid to expand.
//!
//! The regular-call path (`Program.callToAddress:1191`) uses `memorySaveLimited`
//! in BOTH eras, so none of this applies to a call to an ordinary contract.
//!
//! These tests drive the behaviour through deployed bytecode so the real
//! frame-return path runs; the precompile implementations themselves are
//! covered directly in `precompiles.rs`.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores() -> VmStores {
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties: Arc::new(DynamicPropertiesStore::new(mem())),
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: None,
        reward_vi: None,
        abi: None,
    }
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn install_caller(stores: &VmStores) -> [u8; 21] {
    let caller = tron_addr(0xa0);
    stores
        .accounts
        .put(
            &Address::from_raw(caller),
            &Account {
                address: caller.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    caller
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance: 0,
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
}

fn run(stores: &VmStores, caller: [u8; 21], contract: [u8; 21]) -> VmOutcome {
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        &trigger,
        5_000_000,
    )
}

fn slot(stores: &VmStores, contract: [u8; 21], index: u8) -> Vec<u8> {
    let mut key = [0u8; 32];
    key[31] = index;
    let composed = StorageRowStore::compose_key(&Address::from_raw(contract), &key);
    stores.storage.get(&composed).unwrap().unwrap_or_default()
}

fn energy_used(o: &VmOutcome) -> u64 {
    match o {
        VmOutcome::Success { energy_used, .. }
        | VmOutcome::Revert { energy_used, .. }
        | VmOutcome::Halt { energy_used, .. }
        | VmOutcome::TransferFailed { energy_used } => *energy_used,
        other => panic!("unexpected outcome: {other:?}"),
    }
}

/// A 32-byte word used as the sha256 preimage, distinctive enough that a
/// zero-filled slot cannot be mistaken for a real digest.
const PREIMAGE: [u8; 32] = [0xab; 32];

/// sha256 precompile — java's `PrecompiledContracts` address 0x02, ungated.
const SHA256: u8 = 0x02;
/// identity precompile — address 0x04, ungated. Returns its input verbatim, so
/// an empty input produces an EMPTY output.
const IDENTITY: u8 = 0x04;

/// `PUSH32 PREIMAGE PUSH1 0x00 MSTORE` — parks the sha256 input at memory
/// 0x00..0x20, leaving memory exactly one word long.
fn store_preimage(bc: &mut Vec<u8>) {
    bc.push(0x7f); // PUSH32
    bc.extend_from_slice(&PREIMAGE);
    bc.extend_from_slice(&[0x60, 0x00, 0x52]); // PUSH1 0x00 MSTORE
}

/// `STATICCALL(0xFFFF, to, in_off, in_len, out_off, out_len)`, then POP the
/// success flag. Operands are pushed in reverse stack order.
fn staticcall(bc: &mut Vec<u8>, to: u8, in_off: u8, in_len: u8, out_off: u16, out_len: u8) {
    bc.extend_from_slice(&[0x60, out_len]); // PUSH1 retSize
    if out_off <= 0xff {
        bc.extend_from_slice(&[0x60, out_off as u8]); // PUSH1 retOffset
    } else {
        bc.push(0x61); // PUSH2 retOffset
        bc.extend_from_slice(&out_off.to_be_bytes());
    }
    bc.extend_from_slice(&[0x60, in_len]); // PUSH1 argSize
    bc.extend_from_slice(&[0x60, in_off]); // PUSH1 argOffset
    bc.extend_from_slice(&[0x60, to]); // PUSH1 address
    bc.extend_from_slice(&[0x61, 0xff, 0xff]); // PUSH2 gas
    bc.push(0xfa); // STATICCALL
    bc.push(0x50); // POP
}

/// `MSIZE PUSH1 <slot> SSTORE`.
fn sstore_msize(bc: &mut Vec<u8>, index: u8) {
    bc.extend_from_slice(&[0x59, 0x60, index, 0x55]);
}

/// `PUSH1 <addr> MLOAD PUSH1 <slot> SSTORE`.
fn sstore_mload(bc: &mut Vec<u8>, addr: u8, index: u8) {
    bc.extend_from_slice(&[0x60, addr, 0x51, 0x60, index, 0x55]);
}

/// Bytecode for the headline case: a `retSize == 0` sha256 STATICCALL whose
/// return offset is 0x80.
///
/// MSIZE is recorded BEFORE the MLOAD probes, because MLOAD itself expands
/// memory and would otherwise mask the difference between the two eras.
fn zero_retsize_bytecode() -> Vec<u8> {
    let mut bc = Vec::new();
    store_preimage(&mut bc);
    staticcall(&mut bc, SHA256, 0x00, 0x20, 0x80, 0x00);
    sstore_msize(&mut bc, 1);
    sstore_mload(&mut bc, 0x80, 0);
    bc.push(0x00); // STOP
    bc
}

fn u256_bytes(v: u64) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Pre-#94: a precompile's return data is written in FULL at the raw return
/// offset even though the caller asked for ZERO bytes back, and the memory that
/// write needs is created for free.
///
/// java `Program.java:1774` — `memorySave(msg.getOutDataOffs().intValue(),
/// out.getRight())`, whose length argument is `value.length`. Nothing consults
/// `outDataSize`, and `EnergyCost.memNeeded` returns zero for a zero-size
/// region, so the caller never paid for the memory the write lands in.
#[test]
fn pre_94_precompile_writes_full_output_ignoring_zero_retsize() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc1);
    install_contract(&stores, c, zero_retsize_bytecode());

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    let digest = tron_crypto::hash::sha256(&PREIMAGE);
    assert_eq!(
        slot(&stores, c, 0),
        digest.to_vec(),
        "memory at the raw return offset must hold the full sha256 digest"
    );
    // The preimage MSTORE left memory one word long; the free extension must
    // carry it to 0x80 + 32 = 0xA0.
    assert_eq!(
        slot(&stores, c, 1),
        u256_bytes(0xa0),
        "the free extension must be visible to MSIZE"
    );
}

/// Post-#94 the same bytecode leaves memory completely untouched: the write
/// truncates to `min(outDataSize, out.length)`, and `outDataSize` is zero.
#[test]
fn post_94_precompile_respects_zero_retsize() {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION", 1);
    let caller = install_caller(&stores);
    let c = tron_addr(0xc2);
    install_contract(&stores, c, zero_retsize_bytecode());

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    assert_eq!(
        slot(&stores, c, 0),
        Vec::<u8>::new(),
        "nothing may be written when the caller asked for zero bytes"
    );
    assert_eq!(
        slot(&stores, c, 1),
        u256_bytes(0x20),
        "memory must still be just the preimage word"
    );
}

/// Bytecode for the partial-window case: retOffset 0x80, retSize 0x10, against
/// a precompile that returns 32 bytes.
fn partial_retsize_bytecode() -> Vec<u8> {
    let mut bc = Vec::new();
    store_preimage(&mut bc);
    staticcall(&mut bc, SHA256, 0x00, 0x20, 0x80, 0x10);
    sstore_msize(&mut bc, 2);
    sstore_mload(&mut bc, 0x80, 0);
    sstore_mload(&mut bc, 0x90, 1);
    bc.push(0x00); // STOP
    bc
}

/// Pre-#94 the write IGNORES the return size rather than merely writing
/// something: all 32 output bytes land, overrunning the 16-byte window the
/// caller paid for.
#[test]
fn pre_94_precompile_overruns_the_requested_window() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc3);
    install_contract(&stores, c, partial_retsize_bytecode());

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    let digest = tron_crypto::hash::sha256(&PREIMAGE);
    assert_eq!(slot(&stores, c, 0), digest.to_vec());
    // MLOAD(0x90) reads 0x90..0xB0: the digest's second half followed by the
    // zeroes MLOAD's own expansion created.
    let mut expected_high = digest[16..].to_vec();
    expected_high.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        slot(&stores, c, 1),
        expected_high,
        "bytes past the requested window must carry the rest of the digest"
    );
    // The 0x10-byte window already paid to expand memory to 0xA0, so the full
    // write needs no further growth.
    assert_eq!(slot(&stores, c, 2), u256_bytes(0xa0));
}

/// Post-#94 the write truncates: only the first 16 digest bytes land and the
/// rest of the word stays zero.
#[test]
fn post_94_precompile_truncates_to_the_requested_window() {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION", 1);
    let caller = install_caller(&stores);
    let c = tron_addr(0xc4);
    install_contract(&stores, c, partial_retsize_bytecode());

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    let digest = tron_crypto::hash::sha256(&PREIMAGE);
    let mut expected_low = digest[..16].to_vec();
    expected_low.extend_from_slice(&[0u8; 16]);
    assert_eq!(slot(&stores, c, 0), expected_low);
    assert_eq!(
        slot(&stores, c, 1),
        Vec::<u8>::new(),
        "nothing may be written past the requested window"
    );
    assert_eq!(slot(&stores, c, 2), u256_bytes(0xa0));
}

/// Free growth must advance the memory-CHARGING baseline, not just the buffer.
///
/// java's `calcMemEnergy` is always called with `oldMemSize =
/// program.getMemSize()`, which is `Memory.softSize` — the very field
/// `Memory.extend` raised. So the expansion is given away permanently and is
/// never re-billed by a later memory operation.
///
/// The probe is an `MSTORE` inside the freely-grown region. Its energy is
/// compared against the identical program whose final `MSTORE` targets memory
/// that was already paid for. If the implementation grows the buffer but leaves
/// `words_num` behind, the first `MSTORE` re-charges for the expansion java gave
/// away and the two diverge — while the MSIZE assertions above still pass.
#[test]
fn pre_94_free_growth_advances_the_charging_baseline() {
    fn probe(mstore_at: u8) -> Vec<u8> {
        let mut bc = Vec::new();
        store_preimage(&mut bc);
        staticcall(&mut bc, SHA256, 0x00, 0x20, 0x80, 0x00);
        // PUSH1 1 PUSH1 <addr> MSTORE
        bc.extend_from_slice(&[0x60, 0x01, 0x60, mstore_at, 0x52]);
        bc.push(0x00); // STOP
        bc
    }

    // Inside the region the precompile write grew for free.
    let grown = fresh_stores();
    let gc = tron_addr(0xc5);
    install_contract(&grown, gc, probe(0x80));
    let grown_caller = install_caller(&grown);
    let grown_out = run(&grown, grown_caller, gc);
    assert!(matches!(grown_out, VmOutcome::Success { .. }), "{grown_out:?}");

    // Inside the region the preimage MSTORE already paid for.
    let paid = fresh_stores();
    let pc = tron_addr(0xc5);
    install_contract(&paid, pc, probe(0x00));
    let paid_caller = install_caller(&paid);
    let paid_out = run(&paid, paid_caller, pc);
    assert!(matches!(paid_out, VmOutcome::Success { .. }), "{paid_out:?}");

    assert_eq!(
        energy_used(&grown_out),
        energy_used(&paid_out),
        "an MSTORE inside the freely-grown region must cost no memory-expansion \
         energy: java never re-charges for growth `Memory.extend` gave away"
    );
}

/// An EMPTY precompile output is a total no-op, whatever the return offset.
///
/// java `Memory.extend` returns immediately on `size <= 0`, so there is neither
/// growth nor a write — even at an offset far past the end of memory.
#[test]
fn pre_94_empty_precompile_output_does_not_grow_memory() {
    fn probe(out_off: u16) -> Vec<u8> {
        let mut bc = Vec::new();
        store_preimage(&mut bc);
        // Identity with a ZERO-length input returns zero bytes.
        staticcall(&mut bc, IDENTITY, 0x00, 0x00, out_off, 0x00);
        sstore_msize(&mut bc, 0);
        bc.push(0x00); // STOP
        bc
    }

    let far = fresh_stores();
    let fc = tron_addr(0xc6);
    install_contract(&far, fc, probe(0x1000));
    let far_caller = install_caller(&far);
    let far_out = run(&far, far_caller, fc);
    assert!(matches!(far_out, VmOutcome::Success { .. }), "{far_out:?}");
    assert_eq!(
        slot(&far, fc, 0),
        u256_bytes(0x20),
        "an empty output must leave memory at the preimage word"
    );

    let near = fresh_stores();
    let nc = tron_addr(0xc6);
    install_contract(&near, nc, probe(0x0000));
    let near_caller = install_caller(&near);
    let near_out = run(&near, near_caller, nc);
    assert!(matches!(near_out, VmOutcome::Success { .. }), "{near_out:?}");

    assert_eq!(
        energy_used(&far_out),
        energy_used(&near_out),
        "a far return offset must cost nothing extra when the output is empty"
    );
}

/// A call to an ORDINARY contract must keep truncating in both eras.
///
/// java routes it to `Program.callToAddress`, which ends in
/// `memorySaveLimited(offset, buffer, size)` — `memory.write(..., limited =
/// true)` — which skips `extend` entirely and clamps the copy to `softSize`.
/// This is the guard against the pre-#94 precompile write leaking into the
/// frame-return path both call kinds share.
#[test]
fn regular_call_return_data_truncates_in_both_eras() {
    /// Returns 32 bytes of 0xEE.
    fn callee_bytecode() -> Vec<u8> {
        let mut bc = Vec::new();
        bc.push(0x7f); // PUSH32
        bc.extend_from_slice(&[0xee; 32]);
        bc.extend_from_slice(&[0x60, 0x00, 0x52]); // PUSH1 0 MSTORE
        bc.extend_from_slice(&[0x60, 0x20, 0x60, 0x00, 0xf3]); // PUSH1 32 PUSH1 0 RETURN
        bc
    }

    /// `CALL(0xFFFF, callee, value=0, in 0x00/0x00, out 0x80/0x10)`.
    fn caller_bytecode(callee: [u8; 21]) -> Vec<u8> {
        let mut bc = Vec::new();
        bc.extend_from_slice(&[0x60, 0x10]); // PUSH1 retSize
        bc.extend_from_slice(&[0x60, 0x80]); // PUSH1 retOffset
        bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 argSize
        bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 argOffset
        bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 value
        bc.push(0x73); // PUSH20 callee (EVM form drops the 0x41 prefix byte)
        bc.extend_from_slice(&callee[1..]);
        bc.extend_from_slice(&[0x61, 0xff, 0xff]); // PUSH2 gas
        bc.push(0xf1); // CALL
        bc.push(0x50); // POP
        sstore_msize(&mut bc, 2);
        sstore_mload(&mut bc, 0x80, 0);
        sstore_mload(&mut bc, 0x90, 1);
        bc.push(0x00); // STOP
        bc
    }

    for restriction_on in [false, true] {
        let stores = fresh_stores();
        if restriction_on {
            stores
                .dynamic_properties
                .put_long(b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION", 1);
        }
        let caller = install_caller(&stores);
        let callee = tron_addr(0xd1);
        let c = tron_addr(0xd2);
        install_contract(&stores, callee, callee_bytecode());
        install_contract(&stores, c, caller_bytecode(callee));

        let out = run(&stores, caller, c);
        assert!(
            matches!(out, VmOutcome::Success { .. }),
            "restriction_on={restriction_on}: {out:?}"
        );

        let mut expected_low = vec![0xeeu8; 16];
        expected_low.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            slot(&stores, c, 0),
            expected_low,
            "restriction_on={restriction_on}: only the requested 16 bytes may land"
        );
        assert_eq!(
            slot(&stores, c, 1),
            Vec::<u8>::new(),
            "restriction_on={restriction_on}: nothing may be written past the window"
        );
        assert_eq!(
            slot(&stores, c, 2),
            u256_bytes(0xa0),
            "restriction_on={restriction_on}: memory must not grow past the paid window"
        );
    }
}

/// Pre-#94, a return offset whose low 32 bits are negative kills the frame.
///
/// java resolves the offset with `DataWord.intValue()` (DataWord.java:209-216),
/// which folds all 32 bytes into an `int` — the low 32 bits, signed. A negative
/// result reaches `chunks.get(negative)` and throws
/// `IndexOutOfBoundsException`; that throw is uncaught inside
/// `callToPrecompiledAddress`, so `VM.java:97-105` runs `program
/// .spendAllEnergy(); program.stop();` and `VM.java:117` records a runtime
/// failure. Nothing is written to memory.
#[test]
fn pre_94_negative_wrapped_return_offset_halts_and_spends_all_energy() {
    let mut bc = Vec::new();
    store_preimage(&mut bc);
    // Operands in reverse stack order, with a PUSH4 return offset of
    // 0x80000000 — as an i32 that is `i32::MIN`.
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 retSize
    bc.extend_from_slice(&[0x63, 0x80, 0x00, 0x00, 0x00]); // PUSH4 retOffset
    bc.extend_from_slice(&[0x60, 0x20]); // PUSH1 argSize
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 argOffset
    bc.extend_from_slice(&[0x60, SHA256]); // PUSH1 address
    bc.extend_from_slice(&[0x61, 0xff, 0xff]); // PUSH2 gas
    bc.push(0xfa); // STATICCALL
    bc.push(0x50); // POP
    sstore_msize(&mut bc, 0);
    bc.push(0x00); // STOP

    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc7);
    install_contract(&stores, c, bc);

    let out = run(&stores, caller, c);
    assert!(
        matches!(out, VmOutcome::Halt { .. }),
        "a negative wrapped return offset must halt the frame: {out:?}"
    );
    assert_eq!(
        energy_used(&out),
        5_000_000,
        "java's spendAllEnergy() consumes the whole limit"
    );
    assert_eq!(
        slot(&stores, c, 0),
        Vec::<u8>::new(),
        "the halt must land before any state is committed"
    );
}
