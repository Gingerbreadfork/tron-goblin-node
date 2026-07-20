//! Value-bearing CALL / CALLTOKEN to a PRECOMPILE address.
//!
//! java-tron dispatches such a call to `Program.callToPrecompiledAddress`
//! (`OperationActions.exeCall:1033-1041` picks it whenever
//! `PrecompiledContracts.getContractForAddress` is non-null). Unlike
//! `Program.callToAddress`, that method NEVER calls `createAccountIfNotExist`,
//! so its transfer block (`Program.java:1716-1732`) reaches `MUtil.transfer` /
//! `VMUtils.validateForSmartContract` with no `toAccount` and takes the throw at
//! `VMUtils.java:155-159` (TRC-10 twin at `:239-243`). Both catches rethrow
//! `BytecodeExecutionException` (`Program.java:1723`, `:1730`).
//!
//! Consequences, all pinned below:
//!
//! * UNGATED — `createAccountIfNotExist` is behind ALLOW_TVM_SOLIDITY_059 (#32)
//!   but is unreachable from this method in any era, and the method has no
//!   ALLOW_TVM_CONSTANTINOPLE branch, so the failure never softens into a
//!   `TransferException`.
//! * `VM.java:97-105` spends the CALLING frame's whole remaining energy — java
//!   runs a precompile inline in that frame — and stops it.
//! * `RuntimeImpl.setResultCode` has no arm for a bare
//!   `BytecodeExecutionException`, so it records `contractResult UNKNOWN`.
//! * Frame-fatal, not transaction-fatal: a parent frame pushes zero and carries
//!   on.
//! * CALLCODE and DELEGATECALL are exempt — `Program.java:1687-1688` sets
//!   `contextAddress = senderAddress` (the same array object), so the guard
//!   `senderAddress != contextAddress` at line 1717 is a reference compare that
//!   is false and the entire transfer block is skipped.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::transaction::result::ContractResult;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

const ENERGY_LIMIT: u64 = 1_000_000;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// ALLOW_TVM_SOLIDITY_059 (#32) is ON in every fixture here.
///
/// With #32 OFF, `Program.callToAddress` also refuses to create a value
/// recipient, so a plain contract target produces a superficially similar
/// failure and these tests would not isolate the precompile path. Turning #32
/// on is both the mainnet-realistic configuration (active since 2019) and what
/// makes the assertions specific: `callToAddress` would now happily create the
/// recipient, so any remaining refusal must come from
/// `callToPrecompiledAddress`, which never calls `createAccountIfNotExist` at
/// any height.
fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    VmStores {
        dynamic_properties,
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
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

/// The TRON form of a single-low-byte EVM address, e.g. `0x41…04` for the
/// identity precompile — the shape a `PUSH1 <low>` address operand produces.
fn low_byte_tron_addr(low: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[20] = low;
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

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, balance: i64) {
    let mut acct = Account {
        address: addr.to_vec(),
        balance,
        ..Default::default()
    };
    if !bytecode.is_empty() {
        let hash = code_hash(&bytecode);
        stores.code.put(hash.as_slice(), &bytecode).unwrap();
        acct.code = bytecode;
        acct.code_hash = hash.as_slice().to_vec();
    }
    stores.accounts.put(&Address::from_raw(addr), &acct).unwrap();
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
        ENERGY_LIMIT,
    )
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

fn slot(stores: &VmStores, contract: [u8; 21], index: u8) -> Vec<u8> {
    let mut key = [0u8; 32];
    key[31] = index;
    let composed = StorageRowStore::compose_key(&Address::from_raw(contract), &key);
    stores.storage.get(&composed).unwrap().unwrap_or_default()
}

fn account(stores: &VmStores, addr: [u8; 21]) -> Option<Account> {
    stores.accounts.get(&Address::from_raw(addr)).unwrap()
}

fn balance_of(stores: &VmStores, addr: [u8; 21]) -> i64 {
    account(stores, addr).map(|a| a.balance).unwrap_or(0)
}

/// `CALL(gas, to, value, 0, 0, 0, 0)` followed by STOP. Operands are pushed in
/// reverse stack order.
fn call_precompile_bytecode(to_low: u8, value: u8) -> Vec<u8> {
    vec![
        0x60, 0x00, // PUSH1 0    retSize
        0x60, 0x00, // PUSH1 0    retOffset
        0x60, 0x00, // PUSH1 0    argSize
        0x60, 0x00, // PUSH1 0    argOffset
        0x60, value, // PUSH1 value
        0x60, to_low, // PUSH1 to
        0x61, 0xff, 0xff, // PUSH2 gas
        0xf1, // CALL
        0x00, // STOP
    ]
}

/// As above, but SSTOREs the CALL's success flag into slot 0 and a marker into
/// slot 1, so a surviving frame is observable.
fn call_precompile_then_record(to_low: u8, value: u8) -> Vec<u8> {
    let mut bc = call_precompile_bytecode(to_low, value);
    bc.pop(); // drop STOP
    bc.extend_from_slice(&[0x60, 0x00, 0x55]); // PUSH1 0 SSTORE  (success flag)
    bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x01, 0x55]); // PUSH1 1 PUSH1 1 SSTORE
    bc.push(0x00); // STOP
    bc
}

/// A value-bearing CALL to a precompile with no account row kills the frame:
/// `contractResult UNKNOWN`, the whole energy limit consumed, no account
/// created, and the caller's balance untouched.
#[test]
fn value_call_to_precompile_without_account_row_halts_with_unknown() {
    // Swept across ALLOW_TVM_SOLIDITY_059 (#32) to pin that the behaviour is
    // UNGATED: `createAccountIfNotExist` is behind #32 but is never reached
    // from `callToPrecompiledAddress` in either era.
    for solidity_059 in [false, true] {
        let stores = fresh_stores();
        stores
            .dynamic_properties
            .put_long(b"ALLOW_TVM_SOLIDITY_059", i64::from(solidity_059));
        let caller = install_caller(&stores);
        let c = tron_addr(0xc1);
        install_contract(&stores, c, call_precompile_bytecode(0x04, 1), 1000);

        // Precondition: java's `deposit.getAccount(41…04)` is null on mainnet at
        // every height — no precompile address has ever had an account row.
        assert!(account(&stores, low_byte_tron_addr(0x04)).is_none());

        let out = run(&stores, caller, c);
        match &out {
            VmOutcome::Halt { result, .. } => assert_eq!(
                *result,
                ContractResult::Unknown,
                "#32={solidity_059}: a bare BytecodeExecutionException has no \
                 RuntimeImpl.setResultCode arm"
            ),
            other => panic!("#32={solidity_059}: expected a halt, got {other:?}"),
        }
        assert_eq!(
            energy_used(&out),
            ENERGY_LIMIT,
            "#32={solidity_059}: VM.java:97-105 spends all energy for a non-TransferException"
        );
        assert!(
            account(&stores, low_byte_tron_addr(0x04)).is_none(),
            "#32={solidity_059}: the precompile address must not gain an account row"
        );
        assert_eq!(
            balance_of(&stores, c),
            1000,
            "#32={solidity_059}: the endowment must not move"
        );
    }
}

/// The contrast that makes the test above specific: with #32 active, the very
/// same value CALL to an ORDINARY dead address succeeds and creates the
/// recipient, because `Program.callToAddress:1083` calls
/// `createAccountIfNotExist`. Only the precompile arm refuses.
#[test]
fn value_call_to_plain_dead_address_creates_it_post_32() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc2);
    install_contract(&stores, c, call_precompile_then_record(0xad, 1), 1000);

    let target = low_byte_tron_addr(0xad);
    assert!(account(&stores, target).is_none());

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");
    assert_eq!(
        slot(&stores, c, 0),
        {
            let mut v = vec![0u8; 32];
            v[31] = 1;
            v
        },
        "a plain target must succeed"
    );
    assert_eq!(
        balance_of(&stores, target),
        1,
        "post-#32 `createAccountIfNotExist` creates the recipient"
    );
}

/// The halt is FRAME-fatal, not transaction-fatal.
///
/// `Program.callToAddress:1156-1169` contains a child frame's exception —
/// `callResult.getException() != null` leads to `internalTx.reject();
/// stackPushZero(); return;` — so the parent carries on and the transaction
/// succeeds. Only a depth-0 occurrence fails the transaction.
///
/// The child is given a bounded, explicit energy budget so the assertion that
/// its WHOLE forwarded budget is burned can be made against a benign control
/// child, rather than being satisfied accidentally by an out-of-energy child
/// that never reached the transfer at all.
#[test]
fn precompile_transfer_failure_is_contained_at_depth_one() {
    /// Forwarded to the child. Comfortably above the ~34,000 the value CALL
    /// itself costs (NEW_ACCT_CALL 25000 + VT_CALL 9000), so the child really
    /// does reach java's transfer validation.
    const FORWARDED: u64 = 200_000;

    /// Root: CALL the child with `FORWARDED` energy, record the child's success
    /// flag in slot 0, then a survival marker in slot 1.
    fn root_bytecode(child: [u8; 21]) -> Vec<u8> {
        let mut bc = Vec::new();
        bc.extend_from_slice(&[0x60, 0x00]); // retSize
        bc.extend_from_slice(&[0x60, 0x00]); // retOffset
        bc.extend_from_slice(&[0x60, 0x00]); // argSize
        bc.extend_from_slice(&[0x60, 0x00]); // argOffset
        bc.extend_from_slice(&[0x60, 0x00]); // value
        bc.push(0x73); // PUSH20 child
        bc.extend_from_slice(&child[1..]);
        bc.push(0x62); // PUSH3 forwarded energy
        bc.extend_from_slice(&(FORWARDED as u32).to_be_bytes()[1..]);
        bc.push(0xf1); // CALL
        bc.extend_from_slice(&[0x60, 0x00, 0x55]); // SSTORE slot 0 = success flag
        bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x01, 0x55]); // SSTORE slot 1 = 1
        bc.push(0x00); // STOP
        bc
    }

    let marker = {
        let mut v = vec![0u8; 32];
        v[31] = 1;
        v
    };

    // Offending child: makes the value-bearing precompile CALL.
    let bad = fresh_stores();
    let bad_caller = install_caller(&bad);
    let bad_child = tron_addr(0xb1);
    let bad_root = tron_addr(0xb2);
    install_contract(&bad, bad_child, call_precompile_bytecode(0x04, 1), 1000);
    install_contract(&bad, bad_root, root_bytecode(bad_child), 0);
    let bad_out = run(&bad, bad_caller, bad_root);

    assert!(
        matches!(bad_out, VmOutcome::Success { .. }),
        "the root frame must survive its child's halt: {bad_out:?}"
    );
    assert_eq!(
        slot(&bad, bad_root, 0),
        Vec::<u8>::new(),
        "the failed child must push zero"
    );
    assert_eq!(
        slot(&bad, bad_root, 1),
        marker,
        "the root must keep executing past the failed CALL"
    );
    assert!(
        account(&bad, low_byte_tron_addr(0x04)).is_none(),
        "the precompile address must not gain an account row"
    );
    assert_eq!(balance_of(&bad, bad_child), 1000, "the endowment must not move");

    // Control: an identical shape whose child fails IMMEDIATELY and cheaply.
    // A plain REVERT has the same stack effect on the root (the CALL pushes
    // zero, so the root's SSTOREs cost the same in both runs) but refunds its
    // unspent energy — so the difference between the two totals is exactly the
    // budget `spendAllEnergy()` burned.
    let good = fresh_stores();
    let good_caller = install_caller(&good);
    let good_child = tron_addr(0xb1);
    let good_root = tron_addr(0xb2);
    install_contract(&good, good_child, vec![0x60, 0x00, 0x60, 0x00, 0xfd], 1000);
    install_contract(&good, good_root, root_bytecode(good_child), 0);
    let good_out = run(&good, good_caller, good_root);

    assert!(matches!(good_out, VmOutcome::Success { .. }), "{good_out:?}");
    assert_eq!(
        slot(&good, good_root, 0),
        Vec::<u8>::new(),
        "the control child must also push zero, so the roots cost the same"
    );
    assert_eq!(slot(&good, good_root, 1), marker);

    let burned = energy_used(&bad_out) - energy_used(&good_out);
    assert!(
        burned + 1_000 >= FORWARDED,
        "the child's whole forwarded budget must be consumed by spendAllEnergy \
         (burned {burned}, forwarded {FORWARDED})"
    );
}

/// A ZERO-value CALL to a precompile — the overwhelmingly common real-world
/// shape, e.g. Solidity's `staticcall(gas, 4, …)` memory copy — is untouched.
///
/// java's transfer block is gated on `endowment > 0` (`Program.java:1717`), so
/// nothing is validated and nothing is created.
#[test]
fn zero_value_call_to_precompile_is_unaffected() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc3);
    install_contract(&stores, c, call_precompile_then_record(0x04, 0), 1000);

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");
    assert_eq!(
        slot(&stores, c, 0),
        {
            let mut v = vec![0u8; 32];
            v[31] = 1;
            v
        },
        "a zero-value precompile CALL must push 1"
    );
    assert!(
        account(&stores, low_byte_tron_addr(0x04)).is_none(),
        "a zero-endowment touch must not create the account"
    );
}

/// When the precompile address DOES have an account row, the transfer is legal
/// and the call proceeds — java's `validateForSmartContract` passes whenever
/// `toAccount != null` (`VMUtils.java:155-159`).
#[test]
fn value_call_to_precompile_with_existing_row_succeeds() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let target = low_byte_tron_addr(0x04);
    install_contract(&stores, target, Vec::new(), 500);

    let c = tron_addr(0xc4);
    install_contract(&stores, c, call_precompile_then_record(0x04, 1), 1000);

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");
    assert_eq!(
        slot(&stores, c, 0),
        {
            let mut v = vec![0u8; 32];
            v[31] = 1;
            v
        },
        "the call must succeed and push 1"
    );
    assert_eq!(balance_of(&stores, target), 501, "the endowment must land");
    assert_eq!(balance_of(&stores, c), 999);
}

/// `senderBalance < endowment` (`Program.java:1707`) is answered with a
/// push-zero and a full energy refund, and takes PRECEDENCE over the throw.
///
/// This is the case a naive fix gets wrong by checking recipient existence
/// before affordability.
#[test]
fn insufficient_balance_pushes_zero_rather_than_halting() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc5);
    // Balance 0, endowment 1 — the sender cannot fund the transfer.
    install_contract(&stores, c, call_precompile_then_record(0x04, 1), 0);

    let out = run(&stores, caller, c);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "an under-funded call must push zero and let the caller continue: {out:?}"
    );
    assert_eq!(
        slot(&stores, c, 0),
        Vec::<u8>::new(),
        "the call must push zero"
    );
    assert_eq!(
        slot(&stores, c, 1),
        {
            let mut v = vec![0u8; 32];
            v[31] = 1;
            v
        },
        "execution must continue past the failed call"
    );
    assert!(account(&stores, low_byte_tron_addr(0x04)).is_none());
}

/// CALLCODE is exempt: `Program.java:1687-1688` assigns `contextAddress =
/// senderAddress`, so the reference compare `senderAddress != contextAddress`
/// at line 1717 is FALSE and the whole transfer block is skipped.
#[test]
fn callcode_to_precompile_with_value_is_exempt() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc6);
    // Identical operand layout to CALL, opcode 0xf2.
    let mut bc = call_precompile_then_record(0x04, 1);
    let call_pos = bc.iter().position(|&b| b == 0xf1).unwrap();
    bc[call_pos] = 0xf2; // CALLCODE
    install_contract(&stores, c, bc, 1000);

    let out = run(&stores, caller, c);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "CALLCODE must not take the precompile transfer path: {out:?}"
    );
    assert!(
        account(&stores, low_byte_tron_addr(0x04)).is_none(),
        "CALLCODE keeps the caller's own context — no row for the code address"
    );
    assert_eq!(
        balance_of(&stores, c),
        1000,
        "CALLCODE's transfer is caller-to-caller, so the balance is unchanged"
    );
}

/// The TRC-10 arm. Post-ALLOW_MULTI_SIGN a CALLTOKEN takes java's
/// `isTokenTransfer` branch (`Program.java:1726-1731`), where
/// `VMUtils.validateForSmartContract(..., tokenId, ...)` throws the same
/// "no ToAccount" `ContractValidateException` (`VMUtils.java:239-243`) and the
/// catch rethrows `BytecodeExecutionException`.
#[test]
fn value_calltoken_to_precompile_without_account_row_halts_with_unknown() {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    let caller = install_caller(&stores);

    const TOKEN_ID: i64 = 1_000_042;
    const TOKEN_VALUE: i64 = 7;

    // CALLTOKEN stack (top first): gas, to, value, tokenId, inOff, inSize,
    // outOff, outSize — pushed in reverse.
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00]); // outSize
    bc.extend_from_slice(&[0x60, 0x00]); // outOffset
    bc.extend_from_slice(&[0x60, 0x00]); // inSize
    bc.extend_from_slice(&[0x60, 0x00]); // inOffset
    bc.push(0x62); // PUSH3 tokenId
    bc.extend_from_slice(&(TOKEN_ID as u32).to_be_bytes()[1..]);
    bc.extend_from_slice(&[0x60, TOKEN_VALUE as u8]); // value = token amount
    bc.extend_from_slice(&[0x60, 0x04]); // to = identity precompile
    bc.extend_from_slice(&[0x61, 0xff, 0xff]); // gas
    bc.push(0xd0); // CALLTOKEN
    bc.push(0x00); // STOP

    let c = tron_addr(0xc7);
    let mut acct = Account {
        address: c.to_vec(),
        balance: 0,
        ..Default::default()
    };
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    acct.code = bc;
    acct.code_hash = hash.as_slice().to_vec();
    acct.asset_v2.insert(TOKEN_ID.to_string(), 1000);
    stores.accounts.put(&Address::from_raw(c), &acct).unwrap();

    let out = run(&stores, caller, c);
    match &out {
        VmOutcome::Halt { result, .. } => assert_eq!(*result, ContractResult::Unknown),
        other => panic!("expected a halt, got {other:?}"),
    }
    assert_eq!(energy_used(&out), ENERGY_LIMIT);

    let target = low_byte_tron_addr(0x04);
    assert!(
        account(&stores, target).is_none(),
        "the TRC-10 path must not create the precompile's account row"
    );
    assert_eq!(
        account(&stores, c)
            .unwrap()
            .asset_v2
            .get(&TOKEN_ID.to_string())
            .copied()
            .unwrap_or(0),
        1000,
        "the asset must not move"
    );
}

/// The endowment-range split between java's two call arms.
///
/// `callToPrecompiledAddress:1693` reads `msg.getEndowment().value()
/// .longValueExact()` with NO try/catch, so a value above `i64::MAX` raises a
/// bare `ArithmeticException` — spend-all, UNKNOWN. `callToAddress:1033-1042`
/// wraps the same read and, from ALLOW_TVM_CONSTANTINOPLE (#26), converts it
/// into a `TransferException` — consumed-only energy, TRANSFER_FAILED.
#[test]
fn endowment_out_of_range_splits_between_precompile_and_regular_targets() {
    /// `CALL(gas, to, 2^64, 0, 0, 0, 0)` — a value word well past `i64::MAX`.
    fn bytecode(to_low: u8) -> Vec<u8> {
        let mut bc = Vec::new();
        bc.extend_from_slice(&[0x60, 0x00]); // retSize
        bc.extend_from_slice(&[0x60, 0x00]); // retOffset
        bc.extend_from_slice(&[0x60, 0x00]); // argSize
        bc.extend_from_slice(&[0x60, 0x00]); // argOffset
        bc.push(0x68); // PUSH9 2^64
        bc.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
        bc.extend_from_slice(&[0x60, to_low]); // to
        bc.extend_from_slice(&[0x61, 0xff, 0xff]); // gas
        bc.push(0xf1); // CALL
        bc.push(0x00); // STOP
        bc
    }

    // Precompile target → java's unwrapped read → spend-all + UNKNOWN.
    let pre = fresh_stores();
    pre.dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    let pre_caller = install_caller(&pre);
    let pc = tron_addr(0xc8);
    install_contract(&pre, pc, bytecode(0x04), 1000);
    let pre_out = run(&pre, pre_caller, pc);
    match &pre_out {
        VmOutcome::Halt { result, .. } => assert_eq!(
            *result,
            ContractResult::Unknown,
            "the precompile arm has no try/catch, so #26 cannot soften it"
        ),
        other => panic!("expected a halt for the precompile target, got {other:?}"),
    }
    assert_eq!(energy_used(&pre_out), ENERGY_LIMIT);

    // Plain target → `callToAddress`'s catch → TransferException.
    let reg = fresh_stores();
    reg.dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    let reg_caller = install_caller(&reg);
    let rc = tron_addr(0xc9);
    install_contract(&reg, rc, bytecode(0xad), 1000);
    let reg_out = run(&reg, reg_caller, rc);
    assert!(
        matches!(reg_out, VmOutcome::TransferFailed { .. }),
        "a regular target must produce a TransferException from #26 on: {reg_out:?}"
    );
    assert!(
        energy_used(&reg_out) < ENERGY_LIMIT,
        "a TransferException is exempt from spendAllEnergy"
    );
}

/// The oracle must be java's PROPOSAL-GATED dispatch set, not our (wider) warm
/// address set.
///
/// Blake2F sits at `0x00020009` behind ALLOW_TVM_COMPATIBLE_EVM
/// (`PrecompiledContracts.java:212-302`). With the proposal off,
/// `getContractForAddress` returns null and the call takes ordinary
/// `callToAddress` semantics — post-#32 that means `createAccountIfNotExist`
/// creates the recipient and the call succeeds. With it on, the call takes the
/// precompile arm and dies.
#[test]
fn precompile_set_follows_the_active_proposals() {
    /// `CALL(gas, 0x00020009, 1, 0, 0, 0, 0)`.
    fn bytecode() -> Vec<u8> {
        let mut bc = Vec::new();
        bc.extend_from_slice(&[0x60, 0x00]); // retSize
        bc.extend_from_slice(&[0x60, 0x00]); // retOffset
        bc.extend_from_slice(&[0x60, 0x00]); // argSize
        bc.extend_from_slice(&[0x60, 0x00]); // argOffset
        bc.extend_from_slice(&[0x60, 0x01]); // value
        bc.push(0x63); // PUSH4 blake2F address
        bc.extend_from_slice(&[0x00, 0x02, 0x00, 0x09]);
        bc.extend_from_slice(&[0x61, 0xff, 0xff]); // gas
        bc.push(0xf1); // CALL
        bc.push(0x00); // STOP
        bc
    }

    // `make_addr(0x0002_0009)` lays the id into EVM bytes 16..20, which are
    // bytes 17..21 of the 0x41-prefixed TRON form.
    let blake2f = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[18] = 0x02;
        a[20] = 0x09;
        a
    };

    // Proposal OFF → not a precompile → `callToAddress` → post-#32 the
    // recipient is created and the transfer lands.
    let off = fresh_stores();
    off.dynamic_properties
        .put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    let off_caller = install_caller(&off);
    let oc = tron_addr(0xca);
    install_contract(&off, oc, bytecode(), 1000);
    let off_out = run(&off, off_caller, oc);
    assert!(
        matches!(off_out, VmOutcome::Success { .. }),
        "a gated-off address is an ordinary account: {off_out:?}"
    );
    assert_eq!(
        balance_of(&off, blake2f),
        1,
        "post-#32 `createAccountIfNotExist` creates the recipient"
    );

    // Proposal ON → a real precompile → the transfer validation throws.
    let on = fresh_stores();
    on.dynamic_properties
        .put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    on.dynamic_properties
        .put_long(b"ALLOW_TVM_COMPATIBLE_EVM", 1);
    let on_caller = install_caller(&on);
    let nc = tron_addr(0xcb);
    install_contract(&on, nc, bytecode(), 1000);
    let on_out = run(&on, on_caller, nc);
    match &on_out {
        VmOutcome::Halt { result, .. } => assert_eq!(*result, ContractResult::Unknown),
        other => panic!("expected a halt once blake2F is a precompile, got {other:?}"),
    }
    assert_eq!(energy_used(&on_out), ENERGY_LIMIT);
    assert!(
        account(&on, blake2f).is_none(),
        "the precompile arm never creates the recipient"
    );
}

// ---------------------------------------------------------------------------
// Endowment range and depth on the precompile arm.
//
// `callToPrecompiledAddress` runs three things in a fixed order before it
// touches a balance or a token id (`Program.java:1673-1698`):
//
//   1. `:1677` — `getCallDeep() == MAX_DEPTH` → `stackPushZero();
//      refundEnergy(...); return;`
//   2. `:1693` — `long endowment = msg.getEndowment().value().longValueExact()`,
//      with NO try/catch, unlike `callToAddress:1033-1042`
//   3. `:1697` — `checkTokenId(msg)`
//
// `DataWord.value()` is `new BigInteger(1, data)` (DataWord.java:197-199), so
// the accepted range is `[0, 2^63)` and any word from 2^63 up throws a bare
// `ArithmeticException`. `VM.java:97-101` exempts only a `TransferException`
// from `spendAllEnergy()`, and `RuntimeImpl.setResultCode`
// (RuntimeImpl.java:129-138) has no `ArithmeticException` arm, so the root
// frame records `contractResult UNKNOWN` with the whole budget consumed.
//
// `OperationActions.exeCall:1033-1041` dispatches on the target address alone,
// so CALL, CALLCODE and CALLTOKEN all reach `:1693` identically. CALLCODE's
// `contextAddress = senderAddress` (`:1687-1688`) only neutralises the transfer
// block at `:1717`, five statements after the throw.
// ---------------------------------------------------------------------------

const BIG_ENERGY_LIMIT: u64 = 50_000_000;

/// `fresh_stores` plus the proposals CALLTOKEN needs: ALLOW_TVM_TRANSFER_TRC10
/// enables the opcode, ALLOW_MULTI_SIGN makes `Program.isTokenTransfer`
/// unconditionally true for it (`OperationActions.callTokenAction:987`).
fn trc10_stores() -> VmStores {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    stores
}

fn push32(word: [u8; 32]) -> Vec<u8> {
    let mut v = vec![0x7f];
    v.extend_from_slice(&word);
    v
}

/// A 32-byte big-endian word holding `n` in its low 8 bytes.
fn word_u64(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

/// `2^64 + extra` — above `i64::MAX`, and its low 64 bits are `extra`, so a
/// truncating read sees `extra` where java sees a throw.
fn word_two_pow_64_plus(extra: u64) -> [u8; 32] {
    let mut w = word_u64(extra);
    w[23] = 0x01;
    w
}

/// `CALLTOKEN(gas, to, value, tokenId, 0, 0, 0, 0)` then STOP. Operands are
/// pushed in reverse stack order.
fn calltoken_bytecode(to_low: u8, value: [u8; 32], token_id: i64) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00]); // outSize
    bc.extend_from_slice(&[0x60, 0x00]); // outOffset
    bc.extend_from_slice(&[0x60, 0x00]); // inSize
    bc.extend_from_slice(&[0x60, 0x00]); // inOffset
    bc.extend(push32(word_u64(token_id as u64)));
    bc.extend(push32(value));
    bc.extend_from_slice(&[0x60, to_low]); // to
    bc.extend_from_slice(&[0x61, 0xff, 0xff]); // gas
    bc.push(0xd0); // CALLTOKEN
    bc.push(0x00); // STOP
    bc
}

/// `CALLCODE(gas, to, value, 0, 0, 0, 0)` then STOP.
fn callcode_bytecode(to_low: u8, value: [u8; 32]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00]); // retSize
    bc.extend_from_slice(&[0x60, 0x00]); // retOffset
    bc.extend_from_slice(&[0x60, 0x00]); // argSize
    bc.extend_from_slice(&[0x60, 0x00]); // argOffset
    bc.extend(push32(value));
    bc.extend_from_slice(&[0x60, to_low]); // to
    bc.extend_from_slice(&[0x61, 0xff, 0xff]); // gas
    bc.push(0xf2); // CALLCODE
    bc.push(0x00); // STOP
    bc
}

/// Replace the trailing STOP with "SSTORE the call's success flag into slot 0,
/// SSTORE 1 into slot 1, STOP", so both the pushed value and the fact that the
/// frame survived are observable.
fn then_record(mut bc: Vec<u8>) -> Vec<u8> {
    bc.pop(); // drop STOP
    bc.extend_from_slice(&[0x60, 0x00, 0x55]); // PUSH1 0 SSTORE  (success flag)
    bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x01, 0x55]); // PUSH1 1 PUSH1 1 SSTORE
    bc.push(0x00); // STOP
    bc
}

fn set_token_balance(stores: &VmStores, addr: [u8; 21], token_id: i64, amount: i64) {
    let mut acct = account(stores, addr).unwrap_or(Account {
        address: addr.to_vec(),
        ..Default::default()
    });
    acct.asset_v2.insert(token_id.to_string(), amount);
    stores.accounts.put(&Address::from_raw(addr), &acct).unwrap();
}

fn token_balance(stores: &VmStores, addr: [u8; 21], token_id: i64) -> Option<i64> {
    account(stores, addr).and_then(|a| a.asset_v2.get(&token_id.to_string()).copied())
}

fn run_with_limit(
    stores: &VmStores,
    caller: [u8; 21],
    contract: [u8; 21],
    limit: u64,
) -> VmOutcome {
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
        limit,
    )
}

fn chain_addr(i: usize) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1] = 0xcc;
    a[2..4].copy_from_slice(&(i as u16).to_be_bytes());
    a
}

/// Install a chain of `depth + 1` contracts where link `i` zero-value CALLs
/// link `i + 1` and the last link runs `leaf_code`. Triggering link 0 puts the
/// leaf at frame depth `depth`, so `depth == 64` is java's
/// `getCallDeep() == MAX_DEPTH`. Every link records a survival marker in slot 0
/// after its CALL returns. Returns link 0's address.
fn install_call_chain(stores: &VmStores, depth: usize, leaf_code: Vec<u8>) -> [u8; 21] {
    install_contract(stores, chain_addr(depth), leaf_code, 0);
    for i in (0..depth).rev() {
        let next = chain_addr(i + 1);
        let mut bc = Vec::new();
        bc.extend_from_slice(&[0x60, 0x00]); // outSize
        bc.extend_from_slice(&[0x60, 0x00]); // outOffset
        bc.extend_from_slice(&[0x60, 0x00]); // inSize
        bc.extend_from_slice(&[0x60, 0x00]); // inOffset
        bc.extend_from_slice(&[0x60, 0x00]); // value = 0
        bc.push(0x73); // PUSH20 next
        bc.extend_from_slice(&next[1..]);
        bc.extend(push32(word_u64(30_000_000))); // gas, capped by the 63/64 rule
        bc.push(0xf1); // CALL
        bc.push(0x50); // POP
        bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55]); // SSTORE slot0 := 1
        bc.push(0x00); // STOP
        install_contract(stores, chain_addr(i), bc, 0);
    }
    chain_addr(0)
}

fn one_word() -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[31] = 1;
    v
}

const TOKEN_ID: i64 = 1_000_042;

/// (a1) A CALLTOKEN endowment word of exactly 2^64 to a precompile.
///
/// Its low 64 bits are ZERO, so a truncating read classifies the call as
/// carrying no token at all and lets the identity precompile run and push 1.
/// java never gets that far: `Program.java:1693` reads the whole unsigned word
/// and `longValueExact()` throws. Needs no account row at the precompile
/// address, which is what makes this the reachable shape.
#[test]
fn calltoken_endowment_2_pow_64_to_precompile_halts_with_unknown() {
    let stores = trc10_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xd1);
    install_contract(
        &stores,
        c,
        then_record(calltoken_bytecode(0x04, word_two_pow_64_plus(0), TOKEN_ID)),
        0,
    );
    set_token_balance(&stores, c, TOKEN_ID, 1000);
    assert!(account(&stores, low_byte_tron_addr(0x04)).is_none());

    let out = run(&stores, caller, c);
    match &out {
        VmOutcome::Halt { result, .. } => assert_eq!(
            *result,
            ContractResult::Unknown,
            "an ArithmeticException matches no RuntimeImpl.setResultCode arm"
        ),
        other => panic!("expected a halt, got {other:?}"),
    }
    assert_eq!(
        energy_used(&out),
        ENERGY_LIMIT,
        "VM.java:99 spends all energy for a non-TransferException"
    );
    assert_eq!(
        token_balance(&stores, c, TOKEN_ID),
        Some(1000),
        "the endowment must not move"
    );
    assert!(
        account(&stores, low_byte_tron_addr(0x04)).is_none(),
        "the precompile address must not gain an account row"
    );
}

/// (a2) The throw at `:1693` precedes the sender-balance check at `:1707`, so a
/// truncated amount the caller cannot afford is still a throw, not the
/// push-zero an ordinary short balance produces.
#[test]
fn calltoken_endowment_over_i64_max_to_precompile_ignores_token_balance() {
    let stores = trc10_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xd2);
    install_contract(
        &stores,
        c,
        then_record(calltoken_bytecode(0x04, word_two_pow_64_plus(5), TOKEN_ID)),
        0,
    );
    // Below the truncated amount (5): a short balance would otherwise push zero.
    set_token_balance(&stores, c, TOKEN_ID, 1);

    let out = run(&stores, caller, c);
    match &out {
        VmOutcome::Halt { result, .. } => assert_eq!(*result, ContractResult::Unknown),
        other => panic!("expected a halt, got {other:?}"),
    }
    assert_eq!(energy_used(&out), ENERGY_LIMIT);
    assert_eq!(token_balance(&stores, c, TOKEN_ID), Some(1));
}

/// (a3) With an account row already at the precompile address the truncating
/// read is not merely wrong about the outcome, it moves tokens: a word of
/// `2^64 - 1` truncates to `-1`, so a naive debit CREDITS the caller and leaves
/// the counterparty row negative — a balance java can never produce. Both rows
/// must be untouched.
#[test]
fn calltoken_endowment_over_i64_max_to_precompile_with_existing_row_moves_nothing() {
    let stores = trc10_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xd3);
    install_contract(
        &stores,
        c,
        then_record(calltoken_bytecode(0x04, word_two_pow_64_plus(u64::MAX), TOKEN_ID)),
        0,
    );
    set_token_balance(&stores, c, TOKEN_ID, 1000);
    let target = low_byte_tron_addr(0x04);
    install_contract(&stores, target, Vec::new(), 0);
    set_token_balance(&stores, target, TOKEN_ID, 0);

    let out = run(&stores, caller, c);
    match &out {
        VmOutcome::Halt { result, .. } => assert_eq!(*result, ContractResult::Unknown),
        other => panic!("expected a halt, got {other:?}"),
    }
    assert_eq!(energy_used(&out), ENERGY_LIMIT);
    assert_eq!(
        token_balance(&stores, c, TOKEN_ID),
        Some(1000),
        "the caller must not be credited"
    );
    assert_eq!(
        token_balance(&stores, target, TOKEN_ID),
        Some(0),
        "the precompile row must not go negative"
    );
}

/// (a3, sibling) A word of exactly 2^63 truncates to `i64::MIN`, which makes
/// the naive `caller_balance - transferred` overflow. The guard must halt
/// before any arithmetic, in a debug build as much as a release one.
#[test]
fn calltoken_endowment_2_pow_63_to_precompile_does_not_overflow() {
    let stores = trc10_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xd4);
    let mut value = [0u8; 32];
    value[24] = 0x80; // 2^63 — the smallest word `longValueExact` rejects
    install_contract(
        &stores,
        c,
        then_record(calltoken_bytecode(0x04, value, TOKEN_ID)),
        0,
    );
    set_token_balance(&stores, c, TOKEN_ID, 0);
    let target = low_byte_tron_addr(0x04);
    install_contract(&stores, target, Vec::new(), 0);
    set_token_balance(&stores, target, TOKEN_ID, 0);

    let out = run(&stores, caller, c);
    match &out {
        VmOutcome::Halt { result, .. } => assert_eq!(*result, ContractResult::Unknown),
        other => panic!("expected a halt, got {other:?}"),
    }
    assert_eq!(token_balance(&stores, c, TOKEN_ID), Some(0));
    assert_eq!(token_balance(&stores, target, TOKEN_ID), Some(0));
}

/// (a4) Ordering: `:1693` runs BEFORE `checkTokenId` at `:1697`, so an
/// out-of-range endowment on a CALLTOKEN whose token id would also fail
/// `checkTokenId` (id <= MIN_TOKEN_ID) produces the endowment's spend-all
/// UNKNOWN, not `checkTokenId`'s TransferException.
#[test]
fn calltoken_endowment_over_i64_max_to_precompile_precedes_check_token_id() {
    let stores = trc10_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xd5);
    install_contract(
        &stores,
        c,
        // tokenId 5 is <= MIN_TOKEN_ID (1_000_000), so `checkTokenId` would
        // throw if it were reached first.
        then_record(calltoken_bytecode(0x04, word_two_pow_64_plus(0), 5)),
        0,
    );

    let out = run(&stores, caller, c);
    match &out {
        VmOutcome::Halt { result, .. } => assert_eq!(
            *result,
            ContractResult::Unknown,
            "the endowment read precedes checkTokenId, so this is not TRANSFER_FAILED"
        ),
        other => panic!("expected a halt, got {other:?}"),
    }
    assert_eq!(energy_used(&out), ENERGY_LIMIT);
}

/// (b1) CALLCODE reaches `:1693` exactly like CALL.
/// `OperationActions.callCodeAction:988-995` passes the popped `codeAddress`
/// and a real `value` to the opcode-blind `exeCall`, and CALLCODE's
/// `contextAddress = senderAddress` (`:1687-1688`) only disarms the transfer
/// block at `:1717`, which the throw never reaches. Swept across
/// ALLOW_TVM_CONSTANTINOPLE to pin that the precompile arm is UNGATED — the
/// method has no proposal branch between `:1673` and `:1698`.
#[test]
fn callcode_endowment_over_i64_max_to_precompile_halts_with_unknown() {
    for constantinople in [false, true] {
        let stores = fresh_stores();
        stores
            .dynamic_properties
            .put_long(b"ALLOW_TVM_CONSTANTINOPLE", i64::from(constantinople));
        let caller = install_caller(&stores);
        let c = tron_addr(0xd6);
        install_contract(
            &stores,
            c,
            then_record(callcode_bytecode(0x04, word_two_pow_64_plus(0))),
            1000,
        );

        let out = run(&stores, caller, c);
        match &out {
            VmOutcome::Halt { result, .. } => assert_eq!(
                *result,
                ContractResult::Unknown,
                "#26={constantinople}: the precompile arm has no try/catch to soften"
            ),
            other => panic!("#26={constantinople}: expected a halt, got {other:?}"),
        }
        assert_eq!(energy_used(&out), ENERGY_LIMIT, "#26={constantinople}");
        assert_eq!(
            balance_of(&stores, c),
            1000,
            "#26={constantinople}: nothing moves"
        );
    }
}

/// (b2) The depth return at `:1677` precedes the endowment read at `:1693`, so
/// at `getCallDeep() == MAX_DEPTH` the same CALLCODE pushes zero and refunds
/// instead of throwing, and the frame carries on.
#[test]
fn callcode_endowment_over_i64_max_at_max_depth_pushes_zero() {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    let caller = install_caller(&stores);
    let head = install_call_chain(
        &stores,
        64,
        then_record(callcode_bytecode(0x04, word_two_pow_64_plus(0))),
    );

    let out = run_with_limit(&stores, caller, head, BIG_ENERGY_LIMIT);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "at MAX_DEPTH java pushes zero before the endowment read, got {out:?}"
    );
    assert_eq!(
        slot(&stores, chain_addr(64), 0),
        Vec::<u8>::new(),
        "the call must push zero"
    );
    assert_eq!(
        slot(&stores, chain_addr(64), 1),
        one_word(),
        "the leaf must continue past the refused call"
    );
    assert_eq!(slot(&stores, chain_addr(0), 0), one_word());
}

/// (c1) The depth return at `:1677` is the FIRST statement in
/// `callToPrecompiledAddress`, ahead of the transfer block whose "no ToAccount"
/// failure otherwise kills the calling frame. At MAX_DEPTH a value CALLTOKEN to
/// a precompile with no account row must therefore push zero, refund the whole
/// forwarded budget, and let the caller carry on.
#[test]
fn calltoken_to_precompile_at_max_depth_pushes_zero() {
    let stores = trc10_stores();
    let caller = install_caller(&stores);
    let head = install_call_chain(
        &stores,
        64,
        then_record(calltoken_bytecode(0x04, word_u64(7), TOKEN_ID)),
    );
    // Fund the leaf so a short token balance is not what produces the push-zero.
    set_token_balance(&stores, chain_addr(64), TOKEN_ID, 1000);

    let out = run_with_limit(&stores, caller, head, BIG_ENERGY_LIMIT);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "the depth push-zero precedes the transfer block, got {out:?}"
    );
    assert_eq!(
        slot(&stores, chain_addr(64), 0),
        Vec::<u8>::new(),
        "the call must push zero"
    );
    assert_eq!(
        slot(&stores, chain_addr(64), 1),
        one_word(),
        "the leaf must continue past the refused call"
    );
    assert_eq!(slot(&stores, chain_addr(0), 0), one_word());
    assert_eq!(
        token_balance(&stores, chain_addr(64), TOKEN_ID),
        Some(1000),
        "nothing is transferred at the depth limit"
    );
    assert!(account(&stores, low_byte_tron_addr(0x04)).is_none());
}

/// (c2) The same depth return in `callToAddress` (`Program.java:1003-1007`)
/// precedes `createAccountIfNotExist`, so a CALLTOKEN to an ordinary dead
/// address at MAX_DEPTH must not create the recipient either.
#[test]
fn calltoken_at_max_depth_creates_no_account_row() {
    let stores = trc10_stores();
    let caller = install_caller(&stores);
    let head = install_call_chain(
        &stores,
        64,
        then_record(calltoken_bytecode(0xad, word_u64(7), TOKEN_ID)),
    );
    set_token_balance(&stores, chain_addr(64), TOKEN_ID, 1000);
    let target = low_byte_tron_addr(0xad);
    assert!(account(&stores, target).is_none());

    let out = run_with_limit(&stores, caller, head, BIG_ENERGY_LIMIT);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");
    assert_eq!(
        slot(&stores, chain_addr(64), 0),
        Vec::<u8>::new(),
        "the call must push zero"
    );
    assert!(
        account(&stores, target).is_none(),
        "the depth return precedes createAccountIfNotExist"
    );
    assert_eq!(
        token_balance(&stores, chain_addr(64), TOKEN_ID),
        Some(1000),
        "nothing is transferred at the depth limit"
    );
}
