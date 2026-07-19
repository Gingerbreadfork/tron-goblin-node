//! End-to-end test for the CALLTOKEN opcode (0xd0).
//!
//! Deploys a contract whose bytecode invokes CALLTOKEN to send TRC-10
//! tokens to another address, then verifies:
//! 1. The caller's `Account.asset_v2[tokenId]` got debited.
//! 2. The target's `Account.asset_v2[tokenId]` got credited.
//! 3. The callee's bytecode read the right token id / value via
//!    CALLTOKENID / CALLTOKENVALUE.
//!
//! Also exercises the revert path: a CALLTOKEN whose callee REVERTs
//! must roll back the asset_v2 transfer.

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
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    // CALLTOKEN / TOKENBALANCE / CALLTOKENVALUE / CALLTOKENID are gated
    // on ALLOW_TVM_TRANSFER_TRC10 — every test in this file exercises
    // the family, so enable it once at fixture construction.
    dynamic_properties.put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
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

fn install_contract_with_balance(
    stores: &VmStores,
    addr: [u8; 21],
    bytecode: &[u8],
    asset_id: i64,
    asset_balance: i64,
) {
    let mut acct = Account {
        address: addr.to_vec(),
        balance: 0,
        ..Default::default()
    };
    if !bytecode.is_empty() {
        let hash = code_hash(bytecode);
        stores.code.put(hash.as_slice(), bytecode).unwrap();
        acct.code = bytecode.to_vec();
        acct.code_hash = hash.as_slice().to_vec();
    }
    if asset_id != 0 {
        acct.asset_v2.insert(asset_id.to_string(), asset_balance);
    }
    stores.accounts.put(&Address::from_raw(addr), &acct).unwrap();
}

/// Push a U256 onto the EVM stack: PUSH32 followed by 32 bytes.
fn push_u256_bytecode(value: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(0x7f); // PUSH32
    let mut buf = [0u8; 32];
    let be = value.to_be_bytes();
    buf[16..].copy_from_slice(&be);
    out.extend_from_slice(&buf);
    out
}

fn push1(value: u8) -> Vec<u8> {
    vec![0x60, value]
}

/// Build a contract that issues CALLTOKEN to `target` with `token_id`/
/// `token_value`. Stack order (top first) per java-tron's `callTokenAction`
/// + `exeCall` — 8 items, where `value` IS the TRC-10 token amount. There is
/// NO separate native call-value operand: CALLTOKEN's native `msg.value` is
/// always 0 (`ProgramInvokeFactory` native side = `ZERO`, token side = value):
///   [gas, to, value, tokenId, inOffset, inSize, outOffset, outSize]
///
/// Bytecode strategy:
///   * Push outSize=0, outOffset=0, inSize=0, inOffset=0
///   * Push tokenId, tokenValue (= value), target_address, gas=large
///   * Emit CALLTOKEN (0xd0)
///   * STOP
fn build_calltoken_caller(target: [u8; 21], token_id: i64, token_value: i64) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0));       // outSize = 0
    bc.extend(push1(0));       // outOffset = 0
    bc.extend(push1(0));       // inSize = 0
    bc.extend(push1(0));       // inOffset = 0
    bc.extend(push_u256_bytecode(token_id as u128)); // tokenId
    bc.extend(push_u256_bytecode(token_value as u128)); // value = TRC-10 token amount
    // Push target address (20 bytes of the 21 — strip 0x41 prefix).
    bc.push(0x73); // PUSH20
    bc.extend_from_slice(&target[1..]);
    bc.extend(push_u256_bytecode(100_000)); // gas
    bc.push(0xd0); // CALLTOKEN
    bc.push(0x00); // STOP
    bc
}

/// Build a "receiver" contract that:
///   * Reads CALLTOKENVALUE via opcode 0xd2 and stores at slot 0
///   * Reads CALLTOKENID via opcode 0xd3 and stores at slot 1
///   * STOP
fn build_calltoken_receiver() -> Vec<u8> {
    vec![
        0xd2, 0x60, 0x00, 0x55, // CALLTOKENVALUE PUSH1 0 SSTORE
        0xd3, 0x60, 0x01, 0x55, // CALLTOKENID    PUSH1 1 SSTORE
        0x00,                    // STOP
    ]
}

#[test]
fn calltoken_transfers_trc10_and_callee_reads_token_data() {
    let stores = fresh_stores();
    let token_id = 1_000_001i64;
    let transfer_amount = 250i64;
    let initial_balance = 10_000i64;

    let caller_user = tron_addr(0xa0);
    let caller_contract = tron_addr(0xc0);
    let receiver_contract = tron_addr(0xc1);

    // Caller-user has 1B TRX + initial asset balance.
    let mut acct = Account {
        address: caller_user.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    acct.asset_v2.insert(token_id.to_string(), initial_balance);
    stores
        .accounts
        .put(&Address::from_raw(caller_user), &acct).unwrap();

    install_contract_with_balance(
        &stores,
        caller_contract,
        &build_calltoken_caller(receiver_contract, token_id, transfer_amount),
        token_id,
        initial_balance,
    );
    install_contract_with_balance(
        &stores,
        receiver_contract,
        &build_calltoken_receiver(),
        0,
        0,
    );

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0, // tx-level (we want to use CALLTOKEN from bytecode, not tx)
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
        },
        &trigger,
        500_000,
    );
    match outcome {
        VmOutcome::Success { .. } => {}
        other => panic!("expected Success, got {other:?}"),
    }

    // Assert asset_v2 balances: caller_contract debited, receiver_contract credited.
    let caller_acct = stores
        .accounts
        .get(&Address::from_raw(caller_contract))
        .unwrap()
        .unwrap();
    let receiver_acct = stores
        .accounts
        .get(&Address::from_raw(receiver_contract))
        .unwrap()
        .unwrap();
    assert_eq!(
        caller_acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(initial_balance - transfer_amount),
        "caller's TRC-10 balance must be debited"
    );
    assert_eq!(
        receiver_acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(transfer_amount),
        "receiver's TRC-10 balance must be credited"
    );

    // Assert receiver's storage: slot 0 = transfer_amount (from CALLTOKENVALUE),
    // slot 1 = token_id (from CALLTOKENID).
    let slot0_key = StorageRowStore::compose_key(&Address::from_raw(receiver_contract), &[0u8; 32]);
    let slot1_bytes = {
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    };
    let slot1_key = StorageRowStore::compose_key(&Address::from_raw(receiver_contract), &slot1_bytes);

    let slot0 = stores.storage.get(&slot0_key).unwrap().expect("slot 0 missing");
    let slot1 = stores.storage.get(&slot1_key).unwrap().expect("slot 1 missing");

    let mut expected_value = [0u8; 32];
    expected_value[24..].copy_from_slice(&(transfer_amount as u64).to_be_bytes());
    assert_eq!(
        slot0.as_slice(),
        expected_value.as_slice(),
        "CALLTOKENVALUE inside callee should equal transferred amount"
    );

    let mut expected_id = [0u8; 32];
    expected_id[24..].copy_from_slice(&(token_id as u64).to_be_bytes());
    assert_eq!(
        slot1.as_slice(),
        expected_id.as_slice(),
        "CALLTOKENID inside callee should equal token id"
    );
}

/// CALL-F7b: a CALLTOKEN whose caller lacks the TRC-10 balance must SKIP the
/// callee and push 0 (java `Program.callToAddress`: stackPushZero +
/// refundEnergy + return) — NOT run the callee with no transfer. We assert the
/// callee never executed (its storage writes are absent) and no token moved.
#[test]
fn calltoken_insufficient_token_balance_skips_callee() {
    let stores = fresh_stores();
    let token_id = 1_000_001i64;
    let transfer_amount = 250i64;
    let caller_balance = transfer_amount - 1; // one short

    let caller_user = tron_addr(0xa0);
    let caller_contract = tron_addr(0xc0);
    let receiver_contract = tron_addr(0xc1);

    let acct = Account {
        address: caller_user.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    stores.accounts.put(&Address::from_raw(caller_user), &acct).unwrap();

    install_contract_with_balance(
        &stores,
        caller_contract,
        &build_calltoken_caller(receiver_contract, token_id, transfer_amount),
        token_id,
        caller_balance,
    );
    install_contract_with_balance(&stores, receiver_contract, &build_calltoken_receiver(), 0, 0);

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        500_000,
    );
    // The caller STOPs after CALLTOKEN (ignoring its 0 return), so the tx
    // itself succeeds; the point is the callee was skipped.
    match outcome {
        VmOutcome::Success { .. } => {}
        other => panic!("expected Success, got {other:?}"),
    }

    // Callee never ran → its storage slots were never written.
    let slot0_key = StorageRowStore::compose_key(&Address::from_raw(receiver_contract), &[0u8; 32]);
    assert!(
        stores.storage.get(&slot0_key).unwrap().is_none(),
        "callee must NOT have executed (no CALLTOKENVALUE SSTORE)"
    );
    // No token moved: caller still holds its (insufficient) balance, receiver none.
    let caller_acct =
        stores.accounts.get(&Address::from_raw(caller_contract)).unwrap().unwrap();
    assert_eq!(
        caller_acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(caller_balance),
        "caller's TRC-10 balance must be unchanged"
    );
    let receiver_acct =
        stores.accounts.get(&Address::from_raw(receiver_contract)).unwrap().unwrap();
    assert_eq!(
        receiver_acct.asset_v2.get(&token_id.to_string()).copied(),
        None,
        "receiver must not have been credited"
    );
}

/// A CALLTOKEN to a fresh address creates the recipient EOA with the default
/// owner(id=0) + active(id=2) permission pair. java `Program.callToAddress`
/// (endowment > 0) -> `createAccountIfNotExist` -> `RepositoryImpl
/// .createNormalAccount`, which builds the account
/// `withDefaultPermission = getAllowMultiSign() == 1` (mainnet). Without it a
/// later multisig tx from this account would diverge ("permission_id 2 not
/// found").
#[test]
fn calltoken_to_fresh_address_applies_default_permissions() {
    let stores = fresh_stores();
    // ALLOW_MULTI_SIGN drives `withDefaultPermission`; head-block timestamp is
    // stamped as the new account's create_time.
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    // `createAccountIfNotExist` only creates the recipient once
    // ALLOW_TVM_SOLIDITY_059 (#32) is active; the mainnet shape this models
    // (default permissions, i.e. post-ALLOW_MULTI_SIGN #20) is well past it.
    stores.dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    stores.dynamic_properties.save_latest_block_header_timestamp(1_700_000_000_000);

    let token_id = 1_000_001i64;
    let transfer_amount = 250i64;
    let initial_balance = 10_000i64;

    let caller_user = tron_addr(0xa0);
    let caller_contract = tron_addr(0xc0);
    // A brand-new recipient EOA — deliberately NOT pre-installed.
    let fresh_target = tron_addr(0xee);

    let acct = Account { address: caller_user.to_vec(), balance: 1_000_000_000, ..Default::default() };
    stores.accounts.put(&Address::from_raw(caller_user), &acct).unwrap();

    install_contract_with_balance(
        &stores,
        caller_contract,
        &build_calltoken_caller(fresh_target, token_id, transfer_amount),
        token_id,
        initial_balance,
    );

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        500_000,
    );
    match outcome {
        VmOutcome::Success { .. } => {}
        other => panic!("expected Success, got {other:?}"),
    }

    let target_acct = stores
        .accounts
        .get(&Address::from_raw(fresh_target))
        .unwrap()
        .expect("fresh CALLTOKEN recipient must exist after the transfer");
    // Token was credited.
    assert_eq!(
        target_acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(transfer_amount),
        "fresh recipient must be credited the transferred TRC-10 amount"
    );
    // create_time stamped from the head-block timestamp.
    assert_eq!(target_acct.create_time, 1_700_000_000_000);
    // Default owner(id=0) + active(id=2) permission pair attached.
    let owner = target_acct.owner_permission.expect("default owner permission missing");
    assert_eq!(owner.id, 0, "owner permission id");
    assert_eq!(owner.threshold, 1);
    assert_eq!(target_acct.active_permission.len(), 1, "exactly one active permission");
    assert_eq!(
        target_acct.active_permission[0].id, 2,
        "default active permission must carry id=2 (java createDefaultActivePermission)"
    );
}

/// CALL-F8: a CALLTOKEN to the executing contract's OWN address is rejected
/// (java throws TransferException, halting the frame) and must NOT net-mint
/// tokens to the caller. Before the fix the inspector wrote caller-then-target
/// as two clones of the same account, minting `value` to the caller.
#[test]
fn calltoken_self_transfer_rejected_and_does_not_mint() {
    let stores = fresh_stores();
    let token_id = 1_000_001i64;
    let value = 250i64;
    let initial = 10_000i64;

    let caller_user = tron_addr(0xa0);
    let self_contract = tron_addr(0xc0);
    let acct = Account {
        address: caller_user.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    stores.accounts.put(&Address::from_raw(caller_user), &acct).unwrap();

    // The contract CALLTOKENs ITS OWN address (target == self_contract).
    install_contract_with_balance(
        &stores,
        self_contract,
        &build_calltoken_caller(self_contract, token_id, value),
        token_id,
        initial,
    );

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: self_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        500_000,
    );
    // The self-CALLTOKEN halts the (top-level) frame → the tx fails.
    assert!(
        !matches!(outcome, VmOutcome::Success { .. }),
        "self-CALLTOKEN must fail, got {outcome:?}"
    );
    // No mint: the contract's TRC-10 balance is exactly its pre-tx balance.
    let acct = stores.accounts.get(&Address::from_raw(self_contract)).unwrap().unwrap();
    assert_eq!(
        acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(initial),
        "self-CALLTOKEN must not mint; balance must be unchanged"
    );
}

/// Regression: a CALLTOKEN callee must see native CALLVALUE (`msg.value`) == 0.
/// The old code popped a phantom `callValue` operand and passed the TRC-10
/// token amount as the native call-value, so a callee guarded by
/// `require(msg.value == 0)` reverted ("trx is not allowed") — the live
/// SunSwap/USDD-PSM divergence (block 83323740, tx 51eef569). With the fix the
/// native value is 0 and the asset travels only as the TRC-10 token.
#[test]
fn calltoken_callee_sees_zero_native_callvalue() {
    let stores = fresh_stores();
    let token_id = 1_000_009i64;
    let transfer_amount = 221_026_891i64; // a real, non-zero token amount
    let initial_balance = 1_000_000_000i64;

    let caller_user = tron_addr(0xa2);
    let caller_contract = tron_addr(0xc2);
    let receiver_contract = tron_addr(0xc3);

    let mut acct = Account {
        address: caller_user.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    acct.asset_v2.insert(token_id.to_string(), initial_balance);
    stores.accounts.put(&Address::from_raw(caller_user), &acct).unwrap();

    install_contract_with_balance(
        &stores,
        caller_contract,
        &build_calltoken_caller(receiver_contract, token_id, transfer_amount),
        token_id,
        initial_balance,
    );
    // Receiver: SSTORE(slot 0, CALLVALUE + 1) ; STOP. The `+1` makes the row
    // exist even when CALLVALUE is 0 (a bare `SSTORE 0` to an empty slot writes
    // no row), so we can distinguish "msg.value == 0" from "callee never ran".
    // Bytecode: CALLVALUE PUSH1 1 ADD PUSH1 0 SSTORE STOP.
    install_contract_with_balance(
        &stores,
        receiver_contract,
        &[0x34, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x00],
        0,
        0,
    );

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
        },
        &trigger,
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");

    let slot0_key =
        StorageRowStore::compose_key(&Address::from_raw(receiver_contract), &[0u8; 32]);
    let slot0 = stores.storage.get(&slot0_key).unwrap().expect("slot 0 missing");
    let mut expected = [0u8; 32];
    expected[31] = 1; // CALLVALUE (must be 0) + 1
    assert_eq!(
        slot0.as_slice(),
        expected.as_slice(),
        "CALLTOKEN callee's native CALLVALUE (msg.value) must be 0 (stored here as 0+1), \
         not the token amount",
    );

    // The TRC-10 token must still have been transferred to the receiver.
    let recv = stores
        .accounts
        .get(&Address::from_raw(receiver_contract))
        .unwrap()
        .unwrap();
    assert_eq!(
        recv.asset_v2.get(&token_id.to_string()).copied(),
        Some(transfer_amount),
        "TRC-10 token must still be credited to the receiver",
    );
}

/// Build a receiver that always REVERTs. Stack: PUSH1 0 PUSH1 0 REVERT.
fn build_reverter() -> Vec<u8> {
    vec![0x60, 0x00, 0x60, 0x00, 0xfd]
}

#[test]
fn calltoken_unwinds_trc10_transfer_when_callee_reverts() {
    let stores = fresh_stores();
    let token_id = 7777i64;
    let transfer_amount = 100i64;
    let initial_balance = 1_000i64;

    let caller_user = tron_addr(0xa1);
    let caller_contract = tron_addr(0xb1);
    let receiver_contract = tron_addr(0xb2);

    let mut acct = Account {
        address: caller_user.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    acct.asset_v2.insert(token_id.to_string(), initial_balance);
    stores.accounts.put(&Address::from_raw(caller_user), &acct).unwrap();

    install_contract_with_balance(
        &stores,
        caller_contract,
        &build_calltoken_caller(receiver_contract, token_id, transfer_amount),
        token_id,
        initial_balance,
    );
    install_contract_with_balance(&stores, receiver_contract, &build_reverter(), 0, 0);

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
        },
        &trigger,
        500_000,
    );
    // Outer contract's STOP runs even though callee reverted (CALL/CALLTOKEN
    // doesn't propagate the inner revert; it just returns 0 on the stack).
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");

    // The inspector's call_end on the inner revert should have restored
    // the asset_v2 balances.
    let caller_acct = stores
        .accounts
        .get(&Address::from_raw(caller_contract))
        .unwrap()
        .unwrap();
    let receiver_acct = stores
        .accounts
        .get(&Address::from_raw(receiver_contract))
        .unwrap();

    assert_eq!(
        caller_acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(initial_balance),
        "caller's TRC-10 balance must be restored after inner revert"
    );
    if let Some(r) = receiver_acct {
        assert!(
            !r.asset_v2.contains_key(&token_id.to_string()),
            "receiver must not retain the credit after inner revert"
        );
    }
}

/// `build_calltoken_caller` but the trailing STOP becomes REVERT — the CALLTOKEN
/// callee still succeeds, but this frame reverts afterwards.
fn build_calltoken_then_revert(target: [u8; 21], token_id: i64, token_value: i64) -> Vec<u8> {
    let mut bc = build_calltoken_caller(target, token_id, token_value);
    bc.pop(); // drop trailing STOP (0x00)
    bc.extend([0x60, 0x00, 0x60, 0x00, 0xfd]); // PUSH1 0 PUSH1 0 REVERT
    bc
}

/// Outer contract: CALL `inner` (ignoring its revert via POP) then STOP, so the
/// overall tx SUCCEEDS while `inner`'s frame reverted.
fn build_outer_caller(inner: [u8; 21]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0)); // retLen
    bc.extend(push1(0)); // retOff
    bc.extend(push1(0)); // argsLen
    bc.extend(push1(0)); // argsOff
    bc.extend(push1(0)); // value
    bc.push(0x73); // PUSH20 inner
    bc.extend_from_slice(&inner[1..]);
    bc.extend(push_u256_bytecode(300_000)); // gas
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP success flag
    bc.push(0x00); // STOP
    bc
}

#[test]
fn calltoken_transfer_rolls_back_when_an_ancestor_frame_reverts() {
    // Regression: a CALLTOKEN whose immediate callee SUCCEEDS, but inside a
    // frame that an ANCESTOR later reverts, must roll back the TRC-10 transfer
    // (java rolls back the whole deposit on the ancestor revert). The old
    // inspector finalized the transfer on the callee's success and never
    // unwound it when an ancestor reverted, so the *sender* lost tokens it
    // should have kept — the live USDD/GasFree cascade from block 83327784.
    let stores = fresh_stores();
    let token_id = 1_000_021i64;
    let transfer_amount = 500i64;
    let initial_balance = 10_000i64;

    let user = tron_addr(0xa3);
    let outer = tron_addr(0xc4); // CALLs inner, ignores its revert, STOPs
    let inner = tron_addr(0xc5); // CALLTOKEN to receiver (ok) then REVERT
    let receiver = tron_addr(0xc6); // STOP

    let acct = Account {
        address: user.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    stores.accounts.put(&Address::from_raw(user), &acct).unwrap();

    install_contract_with_balance(&stores, outer, &build_outer_caller(inner), 0, 0);
    install_contract_with_balance(
        &stores,
        inner,
        &build_calltoken_then_revert(receiver, token_id, transfer_amount),
        token_id,
        initial_balance,
    );
    install_contract_with_balance(&stores, receiver, &[0x00], 0, 0); // STOP

    let trigger = TriggerSmartContract {
        owner_address: user.to_vec(),
        contract_address: outer.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
        },
        &trigger,
        1_000_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "outer tx should succeed, got {outcome:?}",
    );

    let inner_acct = stores
        .accounts
        .get(&Address::from_raw(inner))
        .unwrap()
        .unwrap();
    assert_eq!(
        inner_acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(initial_balance),
        "sender's TRC-10 balance must be fully restored after the ancestor frame reverted",
    );
    let recv_acct = stores.accounts.get(&Address::from_raw(receiver)).unwrap();
    if let Some(r) = recv_acct {
        assert!(
            !r.asset_v2.contains_key(&token_id.to_string()),
            "receiver must not retain the rolled-back credit",
        );
    }
}

// ---------------------------------------------------------------------------
// ALLOW_TVM_SOLIDITY_059 (#32): a contract may not create the recipient of a
// TRC-10 transfer before the proposal activates.
//
// java `Program.callToAddress` calls `createAccountIfNotExist`, whose body is
// wrapped in `if (VMConfig.allowTvmSolidity059())`. With the proposal inactive
// the recipient stays absent and the TRC-10 overload of
// `VMUtils.validateForSmartContract` throws "Validate InternalTransfer error,
// no ToAccount. And not allowed to create account in smart contract."
// `callToAddress`'s catch then picks the flavour on
// ALLOW_TVM_CONSTANTINOPLE (#26): a `TransferException` (energy-refunding,
// `spendAllEnergy`-exempt, `contractResult TRANSFER_FAILED`) with it active, a
// plain `BytecodeExecutionException` (all energy spent, `UNKNOWN`) before it.
// ---------------------------------------------------------------------------

/// Fund `caller_user` with TRX and `asset_balance` of `token_id`, install the
/// CALLTOKEN-issuing contract with the same asset balance, and run it. The
/// target is deliberately never installed.
fn run_calltoken_to_absent_target(
    stores: &VmStores,
    token_id: i64,
    caller_asset_balance: i64,
    transfer_amount: i64,
) -> VmOutcome {
    let caller_user = tron_addr(0xa0);
    let caller_contract = tron_addr(0xc0);
    let absent_target = tron_addr(0xd7); // never installed → no account row

    let mut acct = Account {
        address: caller_user.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    acct.asset_v2.insert(token_id.to_string(), caller_asset_balance);
    stores
        .accounts
        .put(&Address::from_raw(caller_user), &acct)
        .unwrap();

    install_contract_with_balance(
        stores,
        caller_contract,
        &build_calltoken_caller(absent_target, token_id, transfer_amount),
        token_id,
        caller_asset_balance,
    );

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
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
        500_000,
    )
}

/// #32 OFF, #26 ON: java throws a `TransferException`. The whole transaction
/// fails as TRANSFER_FAILED with consumed-only energy (`VMActuator` exempts a
/// `TransferException` from `spendAllEnergy`), the target is never created and
/// the caller's asset map is untouched.
#[test]
fn calltoken_to_absent_target_pre_059_transfer_failed() {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    // ALLOW_TVM_SOLIDITY_059 deliberately left unset.
    let token_id = 1_000_001i64;
    let initial_balance = 10_000i64;
    let transfer_amount = 250i64;

    let outcome =
        run_calltoken_to_absent_target(&stores, token_id, initial_balance, transfer_amount);
    let VmOutcome::TransferFailed { energy_used } = outcome else {
        panic!("expected TransferFailed, got {outcome:?}");
    };
    assert!(
        energy_used < 500_000,
        "a TransferException is spend-all-exempt, so energy must be \
         consumed-only; got {energy_used} of a 500000 limit"
    );

    assert!(
        stores
            .accounts
            .get(&Address::from_raw(tron_addr(0xd7)))
            .unwrap()
            .is_none(),
        "the target must NOT have been created before ALLOW_TVM_SOLIDITY_059"
    );
    let caller_acct = stores
        .accounts
        .get(&Address::from_raw(tron_addr(0xc0)))
        .unwrap()
        .unwrap();
    assert_eq!(
        caller_acct.asset_v2.get(&token_id.to_string()).copied(),
        Some(initial_balance),
        "no asset may move when the transfer is refused"
    );
}

/// #32 OFF and #26 OFF: java's catch falls through to a plain
/// `BytecodeExecutionException`, which is NOT a `TransferException`, so
/// `VMActuator` calls `spendAllEnergy()` and `RuntimeImpl.setResultCode`
/// records `contractResult UNKNOWN`.
#[test]
fn calltoken_to_absent_target_pre_constantinople_spends_all_energy() {
    let stores = fresh_stores();
    // Neither ALLOW_TVM_SOLIDITY_059 nor ALLOW_TVM_CONSTANTINOPLE set.
    let token_id = 1_000_001i64;

    let outcome = run_calltoken_to_absent_target(&stores, token_id, 10_000, 250);
    let VmOutcome::Halt { result, energy_used, .. } = outcome else {
        panic!("expected Halt, got {outcome:?}");
    };
    assert_eq!(
        result,
        tron_proto::transaction::result::ContractResult::Unknown,
        "a BytecodeExecutionException records UNKNOWN"
    );
    assert_eq!(
        energy_used, 500_000,
        "a non-TransferException spends ALL energy"
    );
}

/// #32 ON — today's mainnet. `createAccountIfNotExist` creates the recipient
/// and the transfer proceeds. Pins the existing behaviour against regression.
#[test]
fn calltoken_to_absent_target_post_059_creates_account() {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    let token_id = 1_000_001i64;
    let initial_balance = 10_000i64;
    let transfer_amount = 250i64;

    let outcome =
        run_calltoken_to_absent_target(&stores, token_id, initial_balance, transfer_amount);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got {outcome:?}"
    );

    let target = stores
        .accounts
        .get(&Address::from_raw(tron_addr(0xd7)))
        .unwrap()
        .expect("target must be created once ALLOW_TVM_SOLIDITY_059 is active");
    assert_eq!(
        target.asset_v2.get(&token_id.to_string()).copied(),
        Some(transfer_amount),
        "the created target must be credited"
    );
}

/// Ordering trap: java checks the sender's TOKEN balance
/// (`if (senderBalance < endowment) { stackPushZero(); refundEnergy(...);
/// return; }`) BEFORE `createAccountIfNotExist`. An under-funded CALLTOKEN must
/// therefore push 0 and let the caller continue — the transaction SUCCEEDS —
/// even though the target is absent and #32 is off. It must never be turned
/// into a TransferException.
#[test]
fn calltoken_insufficient_balance_pre_059_still_pushes_zero() {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    // ALLOW_TVM_SOLIDITY_059 deliberately left unset.
    let token_id = 1_000_001i64;

    // Caller holds 100 but tries to send 250.
    let outcome = run_calltoken_to_absent_target(&stores, token_id, 100, 250);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "an under-funded CALLTOKEN pushes 0 and continues; expected Success, \
         got {outcome:?}"
    );
    assert!(
        stores
            .accounts
            .get(&Address::from_raw(tron_addr(0xd7)))
            .unwrap()
            .is_none(),
        "the target must still not be created"
    );
}

// =============================================================================
// Shared fixtures and builders for the era / static-context CALLTOKEN tests
// =============================================================================

/// `fresh_stores` leaves ALLOW_MULTI_SIGN (#20) unset, so it is already a
/// pre-#20 fixture: `Program.isTokenTransfer` falls to
/// `msg.getTokenId().longValue() != 0` and a CALLTOKEN with a zero low-64
/// tokenId is a NATIVE TRX call. This adds ALLOW_TVM_CONSTANTINOPLE (#26) so the
/// failure flavour is the modern `TransferException`.
fn pre_multisign_stores() -> VmStores {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    stores
}

/// The modern mainnet era: ALLOW_MULTI_SIGN (#20) and
/// ALLOW_TVM_CONSTANTINOPLE (#26) both active — what the 83M snapshot rig runs.
fn modern_stores() -> VmStores {
    let stores = pre_multisign_stores();
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    stores
}

/// Like [`build_calltoken_caller`] but taking the tokenId and the value as RAW
/// 32-byte stack words, so a test can place a word outside `i64` range or with
/// high bytes set below the low-64 the asset key uses.
fn build_calltoken_caller_raw(target: [u8; 21], token_id: [u8; 32], value: [u8; 32]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0)); // outSize
    bc.extend(push1(0)); // outOffset
    bc.extend(push1(0)); // inSize
    bc.extend(push1(0)); // inOffset
    bc.push(0x7f); // PUSH32 tokenId
    bc.extend_from_slice(&token_id);
    bc.push(0x7f); // PUSH32 value
    bc.extend_from_slice(&value);
    bc.push(0x73); // PUSH20 target
    bc.extend_from_slice(&target[1..]);
    bc.extend(push_u256_bytecode(100_000)); // gas
    bc.push(0xd0); // CALLTOKEN
    // A trailing SSTORE makes "the opcode pushed 0 and the frame carried on"
    // observable and distinguishable from "the opcode killed the frame".
    bc.push(0x50); // POP the success flag
    bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x02, 0x55]); // SSTORE slot2 := 1
    bc.push(0x00); // STOP
    bc
}

/// OUTER: `STATICCALL(gas, inner, 0, 0, 0, 0); POP; STOP` — puts `inner` in a
/// static context.
fn outer_staticcalls(inner: [u8; 21]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00]); // outLen
    bc.extend_from_slice(&[0x60, 0x00]); // outOff
    bc.extend_from_slice(&[0x60, 0x00]); // inLen
    bc.extend_from_slice(&[0x60, 0x00]); // inOff
    bc.push(0x73); // PUSH20 to
    bc.extend_from_slice(&inner[1..]);
    bc.extend_from_slice(&[0x62, 0x0f, 0x42, 0x40]); // PUSH3 1_000_000 gas
    bc.push(0xfa); // STATICCALL
    bc.push(0x50); // POP
    bc.push(0x00); // STOP
    bc
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn trigger_for(owner: [u8; 21], contract: [u8; 21]) -> TriggerSmartContract {
    TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    }
}

fn run(stores: &VmStores, trigger: &TriggerSmartContract, limit: u64) -> VmOutcome {
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        trigger,
        limit,
    )
}

fn slot(stores: &VmStores, contract: [u8; 21], index: u8) -> Vec<u8> {
    let mut key = [0u8; 32];
    key[31] = index;
    let composed = StorageRowStore::compose_key(&Address::from_raw(contract), &key);
    stores.storage.get(&composed).unwrap().unwrap_or_default()
}

fn asset_of(stores: &VmStores, addr: [u8; 21], key: &str) -> Option<i64> {
    stores
        .accounts
        .get(&Address::from_raw(addr))
        .unwrap()
        .and_then(|a| a.asset_v2.get(key).copied())
}

fn set_trx_balance(stores: &VmStores, addr: [u8; 21], balance: i64) {
    let key = Address::from_raw(addr);
    let acct = stores.accounts.get(&key).unwrap().unwrap();
    stores
        .accounts
        .put(&key, &Account { balance, ..acct })
        .unwrap();
}

// =============================================================================
// Static context: java throws only for a VALUE-BEARING CALLTOKEN
// =============================================================================
//
// `OperationActions.callTokenAction` (OperationActions.java:973-987) guards with
// `if (program.isStaticCall() && !value.isZero())` — the same predicate
// `callAction` uses for CALL, not the unconditional form `create2Action` and
// `suicideAction` use. A zero-value CALLTOKEN moves nothing (the transfer block
// in `Program.callToAddress` is gated on `endowment > 0`), so it is permitted
// inside a static context.

/// A zero-value CALLTOKEN inside a STATICCALL must proceed, not halt.
#[test]
fn calltoken_zero_value_permitted_inside_staticcall() {
    let stores = modern_stores();
    let owner = tron_addr(0xa0);
    let outer = tron_addr(0xc0);
    let inner = tron_addr(0xc1);
    let receiver = tron_addr(0xc2);
    let token_id = 1_000_001i64;

    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(&stores, outer, &outer_staticcalls(inner), 0, 0);
    install_contract_with_balance(
        &stores,
        inner,
        &build_calltoken_caller(receiver, token_id, 0),
        token_id,
        10_000,
    );
    install_contract_with_balance(&stores, receiver, &build_calltoken_receiver(), 0, 0);

    let limit = 500_000u64;
    match run(&stores, &trigger_for(owner, outer), limit) {
        VmOutcome::Success { energy_used, .. } => {
            assert!(
                energy_used < limit,
                "a permitted CALLTOKEN must not burn the whole limit"
            );
        }
        other => panic!("a zero-value CALLTOKEN is legal inside a static call, got {other:?}"),
    }
    assert_eq!(
        asset_of(&stores, receiver, &token_id.to_string()),
        None,
        "a zero-value CALLTOKEN moves no asset (java gates the transfer on endowment > 0)"
    );
    assert_eq!(
        asset_of(&stores, inner, &token_id.to_string()),
        Some(10_000),
        "the caller's asset balance is untouched"
    );
}

/// The preserved half of the guard: a CALLTOKEN that DOES carry value inside a
/// static context throws `StaticCallModificationException`, a
/// `BytecodeExecutionException` subclass — spend-all, `contractResult UNKNOWN`.
/// Guards against over-relaxing the guard to an unconditional allow.
#[test]
fn calltoken_nonzero_value_rejected_inside_staticcall() {
    let stores = modern_stores();
    let owner = tron_addr(0xa1);
    let outer = tron_addr(0xc3);
    let inner = tron_addr(0xc4);
    let receiver = tron_addr(0xc5);
    let token_id = 1_000_001i64;

    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(&stores, outer, &outer_staticcalls(inner), 0, 0);
    install_contract_with_balance(
        &stores,
        inner,
        &build_calltoken_caller(receiver, token_id, 5),
        token_id,
        10_000,
    );
    install_contract_with_balance(&stores, receiver, &build_calltoken_receiver(), 0, 0);

    // The throw is contained to `inner`'s frame; `outer` pushes 0 and STOPs.
    // What must hold is that no asset moved and `inner` died at the opcode.
    let _ = run(&stores, &trigger_for(owner, outer), 500_000);
    assert_eq!(
        asset_of(&stores, inner, &token_id.to_string()),
        Some(10_000),
        "a rejected static CALLTOKEN must move nothing"
    );
    assert_eq!(asset_of(&stores, receiver, &token_id.to_string()), None);
}

/// The callee of a CALLTOKEN inherits the caller's static context. java builds
/// the child invoke with `msg.getOpCode() == Op.STATICCALL || isStaticCall()`
/// (Program.java:1138), and CALLTOKEN is never STATICCALL — so the child is
/// static exactly when the parent is. Without this the relaxed zero-value path
/// above would be a static ESCAPE: the callee could SSTORE where java forbids
/// it.
#[test]
fn calltoken_callee_inherits_static_context() {
    let stores = modern_stores();
    let owner = tron_addr(0xa2);
    let outer = tron_addr(0xc6);
    let inner = tron_addr(0xc7);
    let writer = tron_addr(0xc8);
    let token_id = 1_000_001i64;

    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(&stores, outer, &outer_staticcalls(inner), 0, 0);
    install_contract_with_balance(
        &stores,
        inner,
        &build_calltoken_caller(writer, token_id, 0),
        token_id,
        10_000,
    );
    // PUSH1 1 PUSH1 0 SSTORE STOP — a state mutation the static context forbids.
    install_contract_with_balance(
        &stores,
        writer,
        &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00],
        0,
        0,
    );

    let _ = run(&stores, &trigger_for(owner, outer), 500_000);
    assert!(
        slot(&stores, writer, 0).iter().all(|&b| b == 0),
        "the CALLTOKEN callee must run STATIC, so its SSTORE cannot commit"
    );
}

/// ORDERING: java throws the static-call exception in `callTokenAction`, before
/// `exeCall` ever reaches `callToAddress`/`checkTokenId`. So a static,
/// value-bearing CALLTOKEN with a tokenId that would ALSO trip `checkTokenId`
/// must record the spend-all static halt, not the consumed-only
/// TRANSFER_FAILED. Energy distinguishes the two, so this genuinely detects a
/// mis-ordered guard.
#[test]
fn calltoken_static_guard_precedes_token_id_check() {
    let stores = modern_stores();
    let owner = tron_addr(0xa3);
    // Run the value-bearing static CALLTOKEN at the ROOT frame so the outcome
    // is the transaction's own, not a contained nested halt.
    let caller = tron_addr(0xc9);
    let receiver = tron_addr(0xca);

    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    // tokenId = 5 (<= MIN_TOKEN_ID) would trip `checkTokenId` -> TransferFailed.
    install_contract_with_balance(
        &stores,
        caller,
        &build_calltoken_caller(receiver, 5, 5),
        5,
        10_000,
    );
    install_contract_with_balance(&stores, receiver, &build_calltoken_receiver(), 0, 0);

    // Not static: `checkTokenId` owns the failure, consumed-only.
    let limit = 500_000u64;
    match run(&stores, &trigger_for(owner, caller), limit) {
        VmOutcome::TransferFailed { energy_used } => {
            assert!(
                energy_used < limit,
                "checkTokenId raises a TransferException, which is spend-all-exempt"
            );
        }
        other => panic!("expected TransferFailed from checkTokenId, got {other:?}"),
    }

    // Static: the static guard fires FIRST, so it is a spend-all halt instead.
    let stores = modern_stores();
    let outer = tron_addr(0xcb);
    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(&stores, outer, &outer_staticcalls(caller), 0, 0);
    install_contract_with_balance(
        &stores,
        caller,
        &build_calltoken_caller(receiver, 5, 5),
        5,
        10_000,
    );
    install_contract_with_balance(&stores, receiver, &build_calltoken_receiver(), 0, 0);
    let outcome = run(&stores, &trigger_for(owner, outer), limit);
    assert!(
        !matches!(outcome, VmOutcome::TransferFailed { .. }),
        "the static guard must pre-empt checkTokenId's TransferException, got {outcome:?}"
    );
    assert_eq!(
        asset_of(&stores, caller, "5"),
        Some(10_000),
        "nothing moves either way"
    );
}

/// Pre-ALLOW_MULTI_SIGN, tokenId 0 makes `value` a NATIVE call-value rather
/// than a token amount. With value 0 there is still nothing to move, so a
/// static context permits it. Covers the `is_token_transfer == false` branch of
/// the relaxed guard.
#[test]
fn calltoken_zero_value_zero_token_id_permitted_inside_staticcall() {
    let stores = pre_multisign_stores(); // ALLOW_MULTI_SIGN deliberately off
    let owner = tron_addr(0xa4);
    let outer = tron_addr(0xcc);
    let inner = tron_addr(0xcd);
    let receiver = tron_addr(0xce);

    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(&stores, outer, &outer_staticcalls(inner), 0, 0);
    install_contract_with_balance(&stores, inner, &build_calltoken_caller(receiver, 0, 0), 0, 0);
    install_contract_with_balance(&stores, receiver, &build_calltoken_receiver(), 0, 0);

    let limit = 500_000u64;
    match run(&stores, &trigger_for(owner, outer), limit) {
        VmOutcome::Success { energy_used, .. } => assert!(energy_used < limit),
        other => panic!("a zero-value native CALLTOKEN is legal inside static, got {other:?}"),
    }
}

// =============================================================================
// CALLTOKEN endowment range
// =============================================================================
//
// `callTokenAction` (OperationActions.java:973-987) pops the value word and
// `exeCall` (:1019-1043) hands it to `MessageCall` as the 4th constructor
// argument — the ENDOWMENT. So CALLTOKEN reaches the same
// `msg.getEndowment().value().longValueExact()` at Program.java:1034 that CALL
// does, and `value()` is unsigned: every word from 2^63 up throws.

/// A callee that records the three call-shape words the caller handed it.
fn build_call_shape_recorder() -> Vec<u8> {
    vec![
        0x34, 0x60, 0x00, 0x55, // CALLVALUE      -> slot 0
        0xd2, 0x60, 0x01, 0x55, // CALLTOKENVALUE -> slot 1
        0xd3, 0x60, 0x02, 0x55, // CALLTOKENID    -> slot 2
        0x00, // STOP
    ]
}

/// Set up owner + a CALLTOKEN caller with raw words + a recorder callee.
/// Returns `(owner, caller, receiver)`.
fn raw_calltoken_rig(
    stores: &VmStores,
    token_id: [u8; 32],
    value: [u8; 32],
    caller_asset_id: i64,
    caller_asset_balance: i64,
) -> ([u8; 21], [u8; 21], [u8; 21]) {
    let owner = tron_addr(0xa9);
    let caller = tron_addr(0xd0);
    let receiver = tron_addr(0xd1);
    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(
        stores,
        caller,
        &build_calltoken_caller_raw(receiver, token_id, value),
        caller_asset_id,
        caller_asset_balance,
    );
    install_contract_with_balance(stores, receiver, &build_call_shape_recorder(), 0, 0);
    (owner, caller, receiver)
}

/// value = 2^63, one above `i64::MAX`. Today this truncates to `i64::MIN` and
/// drives a `0 - i64::MIN` overflow in the asset transfer.
#[test]
fn calltoken_value_over_i64_max_is_transfer_failed() {
    let stores = modern_stores();
    let mut value = [0u8; 32];
    value[24] = 0x80;
    let (owner, caller, _) =
        raw_calltoken_rig(&stores, word_u64(1_000_001), value, 1_000_001, 10_000);

    let limit = 500_000u64;
    match run(&stores, &trigger_for(owner, caller), limit) {
        VmOutcome::TransferFailed { energy_used } => {
            assert!(energy_used > 0 && energy_used < limit);
        }
        other => panic!("expected TransferFailed, got {other:?}"),
    }
    assert_eq!(asset_of(&stores, caller, "1000001"), Some(10_000));
}

/// value = 2^64 exactly: its LOW 64 BITS ARE ZERO, so before the guard it
/// truncated to 0, performed no transfer at all, and the transaction reported
/// SUCCESS. The highest-signal regression in this family.
#[test]
fn calltoken_value_2_pow_64_is_transfer_failed_not_success() {
    let stores = modern_stores();
    let mut value = [0u8; 32];
    value[23] = 0x01; // 2^64
    let (owner, caller, receiver) =
        raw_calltoken_rig(&stores, word_u64(1_000_001), value, 1_000_001, 10_000);

    let outcome = run(&stores, &trigger_for(owner, caller), 500_000);
    assert!(
        matches!(outcome, VmOutcome::TransferFailed { .. }),
        "a 2^64 endowment must not truncate to a silent no-op, got {outcome:?}"
    );
    assert_eq!(asset_of(&stores, caller, "1000001"), Some(10_000));
    assert_eq!(asset_of(&stores, receiver, "1000001"), None);
}

/// The all-ones word pins the UNSIGNED (`value()`) reading: the signed
/// `sValue()` helper would accept it as -1.
#[test]
fn calltoken_value_all_ones_is_transfer_failed() {
    let stores = modern_stores();
    let (owner, caller, _) =
        raw_calltoken_rig(&stores, word_u64(1_000_001), [0xFF; 32], 1_000_001, 10_000);
    assert!(matches!(
        run(&stores, &trigger_for(owner, caller), 500_000),
        VmOutcome::TransferFailed { .. }
    ));
}

/// Boundary: `i64::MAX` is in range. The caller holds far fewer tokens, so java
/// takes its insufficient-balance push-0 (Program.java:1060-1063) and the frame
/// carries on. Guards against the guard over-firing by one.
#[test]
fn calltoken_value_at_i64_max_is_not_transfer_failed() {
    let stores = modern_stores();
    let mut value = [0u8; 32];
    value[24] = 0x7F;
    value[25..].fill(0xFF);
    let (owner, caller, _) =
        raw_calltoken_rig(&stores, word_u64(1_000_001), value, 1_000_001, 10_000);

    let outcome = run(&stores, &trigger_for(owner, caller), 500_000);
    assert!(
        !matches!(outcome, VmOutcome::TransferFailed { .. }),
        "i64::MAX is in range; the shortfall is an ordinary push-0, got {outcome:?}"
    );
    assert_eq!(
        slot(&stores, caller, 2).last(),
        Some(&1u8),
        "the caller must run on past the CALLTOKEN"
    );
}

/// Pre-#26 half: without ALLOW_TVM_CONSTANTINOPLE the raw `ArithmeticException`
/// propagates, so it spends all energy and records UNKNOWN — explicitly neither
/// TRANSFER_FAILED nor OUT_OF_MEMORY.
#[test]
fn calltoken_value_over_i64_max_pre_constantinople_is_spend_all_unknown() {
    let stores = fresh_stores(); // ALLOW_TVM_CONSTANTINOPLE deliberately unset
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    let mut value = [0u8; 32];
    value[24] = 0x80;
    let (owner, caller, _) =
        raw_calltoken_rig(&stores, word_u64(1_000_001), value, 1_000_001, 10_000);

    let limit = 500_000u64;
    match run(&stores, &trigger_for(owner, caller), limit) {
        VmOutcome::Halt {
            result,
            energy_used,
            ..
        } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::Unknown
            );
            assert_eq!(energy_used, limit, "spendAllEnergy consumes the whole limit");
        }
        other => panic!("expected a spend-all Halt/UNKNOWN, got {other:?}"),
    }
}

/// The endowment read precedes `checkTokenId` and is independent of the
/// `isTokenTransfer` branch, so it applies to a pre-#20 CALLTOKEN with
/// tokenId 0 (native-value semantics) exactly as to a token transfer.
#[test]
fn calltoken_value_over_i64_max_with_zero_token_id_pre_multisign() {
    let stores = pre_multisign_stores(); // ALLOW_MULTI_SIGN off
    let mut value = [0u8; 32];
    value[23] = 0x01; // 2^64
    let (owner, caller, _) = raw_calltoken_rig(&stores, [0u8; 32], value, 0, 0);
    assert!(matches!(
        run(&stores, &trigger_for(owner, caller), 500_000),
        VmOutcome::TransferFailed { .. }
    ));
}

// =============================================================================
// Pre-ALLOW_MULTI_SIGN (#20): tokenId keying, the native branch, and the
// full-word CALLTOKENID
// =============================================================================
//
// `Program.isTokenTransfer` (Program.java:1827-1833) falls back to
// `msg.getTokenId().longValue() != 0` before #20, and `DataWord.longValue()`
// (DataWord.java:237-245) is a LOW-64-BIT truncation. On the native branch java
// zeroes BOTH the token id and the token value it hands the callee
// (Program.java:1135-1136) and moves TRX instead.

/// The shape java calls a plain "TRX call via CALLTOKEN": pre-#20, tokenId 0,
/// value > 0. The callee must RUN with `msg.value == value`, TRX must move, and
/// no `asset_v2["0"]` row may be invented. Before the fix the token id/value
/// reached the child unzeroed, the asset machinery tried to move asset "0",
/// found no balance and short-circuited the child with a revert + stack 0.
#[test]
fn calltoken_pre_multisign_zero_token_id_is_native_trx_call() {
    let stores = pre_multisign_stores();
    let (owner, caller, receiver) = raw_calltoken_rig(&stores, [0u8; 32], word_u64(100), 0, 0);
    set_trx_balance(&stores, caller, 5_000);

    let outcome = run(&stores, &trigger_for(owner, caller), 500_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "a pre-#20 zero-tokenId CALLTOKEN is an ordinary TRX call, got {outcome:?}"
    );

    let caller_acct = stores
        .accounts
        .get(&Address::from_raw(caller))
        .unwrap()
        .unwrap();
    let recv_acct = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    assert_eq!(caller_acct.balance, 4_900, "caller debited the TRX value");
    assert_eq!(recv_acct.balance, 100, "receiver credited the TRX value");
    assert!(
        caller_acct.asset_v2.is_empty() && recv_acct.asset_v2.is_empty(),
        "the native branch must not touch asset_v2 at all"
    );

    // The callee ran, and saw a NATIVE value with both token words zeroed.
    assert_eq!(slot(&stores, receiver, 0).last(), Some(&100u8), "CALLVALUE");
    assert!(
        slot(&stores, receiver, 1).iter().all(|&b| b == 0),
        "CALLTOKENVALUE must be 0 on the native branch"
    );
    assert!(
        slot(&stores, receiver, 2).iter().all(|&b| b == 0),
        "CALLTOKENID must be 0 on the native branch"
    );
}

/// The native branch is self-transfer-banned too: `validateForSmartContract`'s
/// TRX overload throws "Cannot transfer TRX to yourself" (VMUtils.java:146-148),
/// so this is NOT a permitted no-op self-call.
#[test]
fn calltoken_pre_multisign_native_self_transfer_rejected() {
    let stores = pre_multisign_stores();
    let owner = tron_addr(0xaa);
    let own = tron_addr(0xd2);
    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(
        &stores,
        own,
        &build_calltoken_caller_raw(own, [0u8; 32], word_u64(100)),
        0,
        0,
    );
    set_trx_balance(&stores, own, 5_000);

    let outcome = run(&stores, &trigger_for(owner, own), 500_000);
    assert!(
        matches!(outcome, VmOutcome::TransferFailed { .. }),
        "a funded native self-CALLTOKEN must be TRANSFER_FAILED, got {outcome:?}"
    );
    let acct = stores
        .accounts
        .get(&Address::from_raw(own))
        .unwrap()
        .unwrap();
    assert_eq!(acct.balance, 5_000, "no TRX may move");
}

/// java's ban is gated on `endowment > 0`, so a ZERO-value native self-CALLTOKEN
/// is permitted and the callee runs. Locks the `has_transfer` half of the guard.
#[test]
fn calltoken_pre_multisign_native_self_transfer_zero_value_allowed() {
    let stores = pre_multisign_stores();
    let owner = tron_addr(0xab);
    let own = tron_addr(0xd3);
    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    install_contract_with_balance(
        &stores,
        own,
        &build_calltoken_caller_raw(own, [0u8; 32], [0u8; 32]),
        0,
        0,
    );

    let outcome = run(&stores, &trigger_for(owner, own), 500_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "a zero-value self-CALLTOKEN is permitted, got {outcome:?}"
    );
    assert_eq!(
        slot(&stores, own, 2).last(),
        Some(&1u8),
        "the caller must run on past the CALLTOKEN"
    );
}

/// `DataWord.longValue()` truncates to the LOW 64 bits, so a tokenId word of
/// `1 << 64` — low 8 bytes zero, bit 64 set — is a NATIVE call, not a token
/// transfer. A whole-word `is_zero()` test would wrongly take the token path.
#[test]
fn calltoken_pre_multisign_high_word_token_id_is_native() {
    let stores = pre_multisign_stores();
    let mut token_id = [0u8; 32];
    token_id[23] = 0x01; // 1 << 64
    let (owner, caller, receiver) = raw_calltoken_rig(&stores, token_id, word_u64(50), 0, 0);
    set_trx_balance(&stores, caller, 5_000);

    let outcome = run(&stores, &trigger_for(owner, caller), 500_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "low-64 keying makes this the native branch, got {outcome:?}"
    );
    let recv = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    assert_eq!(recv.balance, 50, "TRX moved, not a token");
    assert!(recv.asset_v2.is_empty(), "no asset_v2 row may be created");
    assert!(
        slot(&stores, receiver, 2).iter().all(|&b| b == 0),
        "CALLTOKENID is zeroed on the native branch"
    );
}

/// Key-vs-CALLTOKENID divergence. The asset STORE KEY is the low-64 signed
/// decimal (`String.valueOf(tokenId.longValue())`, Program.java:1059) while the
/// callee's CALLTOKENID sees the FULL 32-byte word (Program.java:1136). Before
/// #20 nothing constrains the word, so the two legitimately differ.
#[test]
fn calltoken_pre_multisign_full_word_token_id_reaches_callee() {
    let stores = pre_multisign_stores();
    // (1 << 64) + 1_000_001 — low-64 is 1_000_001, high bytes set.
    let mut token_id = word_u64(1_000_001);
    token_id[23] = 0x01;
    let (owner, caller, receiver) =
        raw_calltoken_rig(&stores, token_id, word_u64(250), 1_000_001, 10_000);

    let outcome = run(&stores, &trigger_for(owner, caller), 500_000);
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");

    // The asset moved under the LOW-64 key.
    assert_eq!(asset_of(&stores, caller, "1000001"), Some(9_750));
    assert_eq!(asset_of(&stores, receiver, "1000001"), Some(250));
    // But CALLTOKENID pushed the WHOLE word.
    assert_eq!(
        slot(&stores, receiver, 2),
        token_id.to_vec(),
        "CALLTOKENID must push the full 32-byte word, not the low-64 key"
    );
}

/// A tokenId word of `U256::MAX` has low-64 == -1, so java's key is `"-1"` and
/// CALLTOKENID pushes `2^256-1`. The old `v.max(0) as u64` clamp pushed 0 for
/// any negative low-64 — a second, independent error in the same expression.
#[test]
fn calltoken_pre_multisign_negative_low_word_token_id() {
    let stores = pre_multisign_stores();
    let (owner, caller, receiver) =
        raw_calltoken_rig(&stores, [0xFF; 32], word_u64(250), -1, 10_000);

    let outcome = run(&stores, &trigger_for(owner, caller), 500_000);
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");
    assert_eq!(
        asset_of(&stores, caller, "-1"),
        Some(9_750),
        "the asset key is String.valueOf(-1L)"
    );
    assert_eq!(asset_of(&stores, receiver, "-1"), Some(250));
    assert_eq!(
        slot(&stores, receiver, 2),
        [0xFFu8; 32].to_vec(),
        "CALLTOKENID must push the full word, not a clamped 0"
    );
}

/// The whole pre-#20 change set must be INERT once ALLOW_MULTI_SIGN is active —
/// `checkTokenId` then forces the tokenId into `(1_000_000, i64::MAX]` with all
/// high bytes zero, so word == low-64 == the i64. This is the guard that the
/// change set does not move the 83M snapshot rig.
#[test]
fn calltoken_post_multisign_unchanged() {
    let stores = modern_stores();
    let (owner, caller, receiver) =
        raw_calltoken_rig(&stores, word_u64(1_000_001), word_u64(250), 1_000_001, 10_000);

    let outcome = run(&stores, &trigger_for(owner, caller), 500_000);
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");
    assert_eq!(asset_of(&stores, caller, "1000001"), Some(9_750));
    assert_eq!(asset_of(&stores, receiver, "1000001"), Some(250));
    // Native value 0, token value 250, token id 1_000_001 — the modern shape.
    assert!(slot(&stores, receiver, 0).iter().all(|&b| b == 0), "CALLVALUE");
    assert_eq!(slot(&stores, receiver, 1).last(), Some(&250u8));
    assert_eq!(slot(&stores, receiver, 2), word_u64(1_000_001).to_vec());
}

/// ORDERING: java's TOKEN-balance check (Program.java:1058-1063) precedes the
/// transfer block, so a self-CALLTOKEN the caller cannot fund pushes 0 and the
/// frame carries on — it never reaches the self-transfer ban. Also guards the
/// inspector's self-transfer no-op against regressing into a mint.
#[test]
fn self_calltoken_with_insufficient_token_balance_pushes_zero() {
    let stores = modern_stores();
    let owner = tron_addr(0xac);
    let own = tron_addr(0xd4);
    stores
        .accounts
        .put(
            &Address::from_raw(owner),
            &Account {
                address: owner.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    // Holds 0 of token 1_000_001 but CALLTOKENs itself for 250.
    install_contract_with_balance(
        &stores,
        own,
        &build_calltoken_caller_raw(own, word_u64(1_000_001), word_u64(250)),
        1_000_001,
        0,
    );

    let outcome = run(&stores, &trigger_for(owner, own), 500_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "an under-funded self-CALLTOKEN takes java's balance push-0, got {outcome:?}"
    );
    assert_eq!(
        slot(&stores, own, 2).last(),
        Some(&1u8),
        "the frame must run on past the CALLTOKEN"
    );
    assert_eq!(
        asset_of(&stores, own, "1000001"),
        Some(0),
        "and must not net-mint itself the amount"
    );
}
