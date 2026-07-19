//! ALLOW_TVM_SOLIDITY_059 (#32) parity for the NATIVE value CALL.
//!
//! java `Program.callToAddress` calls `createAccountIfNotExist(deposit,
//! contextAddress)`, whose entire body is wrapped in
//! `if (VMConfig.allowTvmSolidity059())`. Before the proposal activates the
//! recipient of a value-bearing CALL is left absent and
//! `VMUtils.validateForSmartContract` throws `ContractValidateException`
//! ("Validate InternalTransfer error, no ToAccount. And not allowed to create
//! an account in a smartContract."). `callToAddress`'s catch selects the
//! flavour on ALLOW_TVM_CONSTANTINOPLE (#26):
//!
//!   #26 on  → `refundEnergy(msg.getEnergy())` then `TransferException`:
//!             `VMActuator` exempts it from `spendAllEnergy`, so energy is
//!             consumed-only and `RuntimeImpl` records TRANSFER_FAILED.
//!   #26 off → plain `BytecodeExecutionException`: not a `TransferException`,
//!             so `VMActuator` spends all energy and the result falls through
//!             `RuntimeImpl.setResultCode` to UNKNOWN.
//!
//! Also pinned here: the java orderings that must NOT be turned into failures —
//! an under-funded sender still pushes 0 and continues, CALLCODE never enters
//! the transfer block at all, and CREATE creates its address before validating.

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// `solidity_059` / `constantinople` set the two proposals under test; every
/// other key is left unset, which is what a from-genesis sync starts from.
fn stores(solidity_059: bool, constantinople: bool) -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    if solidity_059 {
        dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    }
    if constantinople {
        dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    }
    dynamic_properties.save_latest_block_header_timestamp(1_700_000_000_000);
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
        contracts: Some(Arc::new(ContractStore::new(mem()))),
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
        abi: Some(Arc::new(AbiStore::new(mem()))),
    }
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn install_caller(stores: &VmStores, addr: [u8; 21], balance: i64) {
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance,
                ..Default::default()
            },
        )
        .unwrap();
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, balance: i64) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.code.put(&addr, &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance,
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
}

fn push1(v: u8) -> Vec<u8> {
    vec![0x60, v]
}

/// `PUSH1 outSize PUSH1 outOff PUSH1 inSize PUSH1 inOff PUSH<value>
///  PUSH20 target PUSH2 gas <op> PUSH1 0 SSTORE STOP`
///
/// The CALL's success flag is stored at slot 0 so a test can tell "pushed 0 and
/// continued" from "the transaction died".
fn call_bytecode(op: u8, target: [u8; 21], value: u8, gas: u16) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0)); // outSize
    bc.extend(push1(0)); // outOffset
    bc.extend(push1(0)); // inSize
    bc.extend(push1(0)); // inOffset
    bc.extend(push1(value)); // call value
    bc.push(0x73); // PUSH20
    bc.extend_from_slice(&target[1..]);
    bc.push(0x61); // PUSH2
    bc.extend_from_slice(&gas.to_be_bytes());
    bc.push(op);
    bc.extend(push1(0)); // slot 0
    bc.push(0x55); // SSTORE
    bc.push(0x00); // STOP
    bc
}

fn run(stores: &VmStores, caller: [u8; 21], contract: [u8; 21], energy: u64) -> VmOutcome {
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
        energy,
    )
}

const CALLER: [u8; 21] = {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    let mut i = 1;
    while i < 21 {
        a[i] = 0xa0;
        i += 1;
    }
    a
};

/// #32 OFF, #26 ON: the whole transaction dies as TRANSFER_FAILED with
/// consumed-only energy, and the target is never created.
#[test]
fn value_call_to_absent_target_pre_059_transfer_failed() {
    let stores = stores(false, true);
    let contract = tron_addr(0xc0);
    let absent = tron_addr(0xd7); // never installed
    install_caller(&stores, CALLER, 1_000_000_000);
    install_contract(&stores, contract, call_bytecode(0xf1, absent, 5, 0xffff), 1_000);

    let out = run(&stores, CALLER, contract, 500_000);
    let VmOutcome::TransferFailed { energy_used } = out else {
        panic!("expected TransferFailed, got {out:?}");
    };
    assert!(
        energy_used < 500_000,
        "a TransferException is spend-all-exempt; got {energy_used}"
    );
    assert!(
        stores
            .accounts
            .get(&Address::from_raw(absent))
            .unwrap()
            .is_none(),
        "the target must not be created before ALLOW_TVM_SOLIDITY_059"
    );
}

/// #32 OFF, #26 OFF: a plain `BytecodeExecutionException` — all energy spent
/// and `contractResult UNKNOWN`.
#[test]
fn value_call_to_absent_target_pre_constantinople_spends_all() {
    let stores = stores(false, false);
    let contract = tron_addr(0xc0);
    let absent = tron_addr(0xd7);
    install_caller(&stores, CALLER, 1_000_000_000);
    install_contract(&stores, contract, call_bytecode(0xf1, absent, 5, 0xffff), 1_000);

    let out = run(&stores, CALLER, contract, 500_000);
    let VmOutcome::Halt { result, energy_used, .. } = out else {
        panic!("expected Halt, got {out:?}");
    };
    assert_eq!(
        result,
        tron_proto::transaction::result::ContractResult::Unknown,
        "a BytecodeExecutionException records UNKNOWN, not the halt reason's \
         own mapping"
    );
    assert_eq!(energy_used, 500_000, "all energy is spent");
    assert!(
        stores
            .accounts
            .get(&Address::from_raw(absent))
            .unwrap()
            .is_none()
    );
}

/// #32 ON — today's mainnet: `createAccountIfNotExist` creates the recipient
/// and the value lands. Pins the existing behaviour against regression.
#[test]
fn value_call_to_absent_target_post_059_creates_account() {
    let stores = stores(true, true);
    let contract = tron_addr(0xc0);
    let absent = tron_addr(0xd7);
    install_caller(&stores, CALLER, 1_000_000_000);
    install_contract(&stores, contract, call_bytecode(0xf1, absent, 5, 0xffff), 1_000);

    let out = run(&stores, CALLER, contract, 500_000);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "expected Success, got {out:?}"
    );
    let created = stores
        .accounts
        .get(&Address::from_raw(absent))
        .unwrap()
        .expect("target must be created once ALLOW_TVM_SOLIDITY_059 is active");
    assert_eq!(created.balance, 5, "the created target must be credited");
}

/// Ordering trap: java's sender-balance check
/// (`if (senderBalance < endowment) { stackPushZero(); refundEnergy(...);
/// return; }`) runs BEFORE `createAccountIfNotExist`, so an under-funded CALL
/// pushes 0 and lets the caller CONTINUE — it must never become tx-fatal, even
/// with the target absent and #32 off.
#[test]
fn value_call_to_absent_target_pre_059_insufficient_balance_pushes_zero() {
    let stores = stores(false, true);
    let contract = tron_addr(0xc0);
    let absent = tron_addr(0xd7);
    install_caller(&stores, CALLER, 1_000_000_000);
    // The contract holds 1 sun but tries to send 5.
    install_contract(&stores, contract, call_bytecode(0xf1, absent, 5, 0xffff), 1);

    let out = run(&stores, CALLER, contract, 500_000);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "an under-funded CALL pushes 0 and continues; expected Success, got \
         {out:?}"
    );
    assert!(
        stores
            .accounts
            .get(&Address::from_raw(absent))
            .unwrap()
            .is_none(),
        "the target must still not be created"
    );
}

/// CALLCODE keeps the caller's own context: java sets
/// `contextAddress = senderAddress`, so the outer
/// `senderAddress != contextAddress` reference compare is false and the whole
/// transfer block — `createAccountIfNotExist` included — is skipped. A
/// value-bearing CALLCODE to a code-address with no account row must therefore
/// be unaffected by the gate.
#[test]
fn callcode_with_value_pre_059_unaffected() {
    let stores = stores(false, true);
    let contract = tron_addr(0xc0);
    let absent = tron_addr(0xd7);
    install_caller(&stores, CALLER, 1_000_000_000);
    install_contract(&stores, contract, call_bytecode(0xf2, absent, 5, 0xffff), 1_000);

    let out = run(&stores, CALLER, contract, 500_000);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "CALLCODE must not be gated; expected Success, got {out:?}"
    );
}

/// DELEGATECALL carries no value at all, so it can never reach java's transfer
/// block either.
#[test]
fn delegatecall_pre_059_unaffected() {
    let stores = stores(false, true);
    let contract = tron_addr(0xc0);
    let absent = tron_addr(0xd7);
    install_caller(&stores, CALLER, 1_000_000_000);
    // DELEGATECALL pops no value operand; the extra PUSH is harmless dead
    // stack, and slot 0 still records the success flag.
    install_contract(&stores, contract, call_bytecode(0xf4, absent, 0, 0xffff), 1_000);

    let out = run(&stores, CALLER, contract, 500_000);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "DELEGATECALL must not be gated; expected Success, got {out:?}"
    );
}

/// CREATE must NOT be gated: `Program.createContractImpl` runs
/// `deposit.createAccount(newAddress, ...)` BEFORE
/// `validateForSmartContract(deposit, senderAddress, newAddress, endowment)`,
/// which is why java's own source calls that throw
/// "TODO: unreachable exception". A nested CREATE with a non-zero endowment
/// must still succeed pre-#32.
#[test]
fn create_with_endowment_pre_059_unaffected() {
    let stores = stores(false, true);
    let contract = tron_addr(0xc0);
    install_caller(&stores, CALLER, 1_000_000_000);

    // Store a 1-byte STOP as the child's init code, then
    // `CREATE(value=5, offset=0, size=1)` and SSTORE the resulting address.
    let mut bc = Vec::new();
    bc.push(0x60); // PUSH1 0x00 — init code: STOP
    bc.push(0x00);
    bc.extend(push1(0)); // memory offset 0
    bc.push(0x53); // MSTORE8 -> memory[0] = 0x00
    bc.extend(push1(1)); // size = 1
    bc.extend(push1(0)); // offset = 0
    bc.extend(push1(5)); // value = 5
    bc.push(0xf0); // CREATE
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE
    bc.push(0x00); // STOP
    install_contract(&stores, contract, bc, 1_000);

    let out = run(&stores, CALLER, contract, 500_000);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "CREATE creates its address before validating; expected Success, got \
         {out:?}"
    );
}

/// Zero-value CALL is outside the gate entirely: java only calls
/// `createAccountIfNotExist` when `endowment > 0`.
#[test]
fn zero_value_call_to_absent_target_pre_059_unaffected() {
    let stores = stores(false, true);
    let contract = tron_addr(0xc0);
    let absent = tron_addr(0xd7);
    install_caller(&stores, CALLER, 1_000_000_000);
    install_contract(&stores, contract, call_bytecode(0xf1, absent, 0, 0xffff), 1_000);

    let out = run(&stores, CALLER, contract, 500_000);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "a zero-value CALL is never gated; expected Success, got {out:?}"
    );
}
