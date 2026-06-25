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
