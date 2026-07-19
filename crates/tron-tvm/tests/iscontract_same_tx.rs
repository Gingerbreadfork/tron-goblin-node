//! ISCONTRACT (0xd4) must answer from the IN-FLIGHT state, the way java's
//! `Program.isContract` reads the live `Repository`.
//!
//! `Program.isContract` is `getContractState().getContract(addr) != null` with
//! no version branch — one behaviour in every era in which the opcode is
//! dispatchable (the only gate is opcode availability under
//! ALLOW_TVM_SOLIDITY_059). The row it reads is written before the init code
//! runs, by `Program.createContractImpl` for a nested CREATE/CREATE2
//! (`deposit.createContract(newAddress, ...)`) and by `VMActuator.create` for a
//! top-level `CreateSmartContract` (`rootRepository.createContract(...)`).
//!
//! But it is only PUBLISHED to the parent `Repository` by `deposit.commit()`,
//! which `createContractImpl` skips when the create reverts or throws
//! (`if (createResult.getException() != null || createResult.isRevert())`).
//! So a reverted create must still report 0 — which is why the in-flight signal
//! has to be the revert-aware journal `Account::is_created()` and never the
//! frame-entry `pending_created_contracts` map (deliberately never pruned on
//! revert).

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{smart_contract::Abi, Account, CreateSmartContract, SmartContract,
    TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_create, execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// ISCONTRACT is registered under ALLOW_TVM_SOLIDITY_059, and a deploy needs
/// ALLOW_TVM_CONSTANTINOPLE for the init code's RETURN to become the stored
/// runtime code, so both are on for every test here.
fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
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

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.code.put(&addr, &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance: 0,
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
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
        1_000_000,
    )
}

fn slot0(stores: &VmStores, addr: [u8; 21]) -> [u8; 32] {
    read_slot(stores, addr, [0u8; 32])
}

fn read_slot(stores: &VmStores, addr: [u8; 21], key: [u8; 32]) -> [u8; 32] {
    let composed = StorageRowStore::compose_key(&Address::from_raw(addr), &key);
    let raw = stores.storage.get(&composed).unwrap().unwrap_or_default();
    let mut out = [0u8; 32];
    if raw.len() == 32 {
        out.copy_from_slice(&raw);
    }
    out
}

fn is_one(word: [u8; 32]) -> bool {
    word[31] == 1 && word[..31].iter().all(|b| *b == 0)
}

fn is_zero(word: [u8; 32]) -> bool {
    word.iter().all(|b| *b == 0)
}

fn push1(v: u8) -> Vec<u8> {
    vec![0x60, v]
}

/// Init code that writes `ADDRESS ISCONTRACT` to the new contract's slot 0 and
/// then returns a 1-byte STOP as its runtime code.
fn probe_self_init_code() -> Vec<u8> {
    let mut bc = Vec::new();
    bc.push(0x30); // ADDRESS
    bc.push(0xd4); // ISCONTRACT
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE slot 0
    // return a 1-byte STOP (0x00) as the runtime code: mem[0] is already 0.
    bc.extend(push1(1)); // length 1
    bc.extend(push1(0)); // offset 0
    bc.push(0xf3); // RETURN
    bc
}

/// Init code that just returns empty runtime code.
fn empty_init_code() -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0)); // length 0
    bc.extend(push1(0)); // offset 0
    bc.push(0xf3); // RETURN
    bc
}

/// Init code that reverts.
fn reverting_init_code() -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0));
    bc.extend(push1(0));
    bc.push(0xfd); // REVERT
    bc
}

/// Store `init` into memory at offset 0 (via MSTORE of a right-aligned word)
/// and leave `[size, offset]` ready for CREATE/CREATE2. `init` must be <= 32
/// bytes.
fn mstore_init(init: &[u8]) -> Vec<u8> {
    assert!(init.len() <= 32);
    let mut padded = [0u8; 32];
    padded[32 - init.len()..].copy_from_slice(init);
    let mut bc = vec![0x7f]; // PUSH32
    bc.extend_from_slice(&padded);
    bc.extend(push1(0));
    bc.push(0x52); // MSTORE  -> mem[0..32]
    bc
}

/// `ALLOW_TVM_SOLIDITY_059` is on, so ISCONTRACT is dispatchable.
///
/// java `VMActuator.create` calls `rootRepository.createContract(...)` before
/// the constructor runs, so `address(this).isContract` is 1 inside a top-level
/// constructor.
#[test]
fn iscontract_true_inside_top_level_constructor() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa0);
    install_caller(&stores, owner, 1_000_000_000);

    let create = CreateSmartContract {
        owner_address: owner.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: owner.to_vec(),
            contract_address: vec![],
            abi: Some(Abi::default()),
            bytecode: probe_self_init_code(),
            call_value: 0,
            consume_user_resource_percent: 100,
            name: "SelfProbe".into(),
            origin_energy_limit: 1_000_000,
            code_hash: vec![],
            trx_hash: vec![],
            version: 1,
        }),
        call_token_value: 0,
        token_id: 0,
    };
    let tx_id = [0xab; 32];
    let outcome = execute_create(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        &create,
        &tx_id,
        1_000_000,
    );
    let VmOutcome::Success { return_data, .. } = outcome else {
        panic!("expected Success, got {outcome:?}");
    };
    let mut deployed = [0u8; 21];
    deployed.copy_from_slice(&return_data);

    assert!(
        is_one(slot0(&stores, deployed)),
        "address(this).isContract must be 1 inside a top-level constructor \
         (java VMActuator.create writes the contract row before the init code)"
    );
}

/// A nested CREATE writes the contract row before the child's init code runs
/// (`Program.createContractImpl`), so the CHILD sees itself as a contract.
#[test]
fn iscontract_true_inside_nested_constructor() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa0);
    let factory = tron_addr(0xc0);
    install_caller(&stores, owner, 1_000_000_000);

    // Factory: MSTORE the probe init code, CREATE it, SSTORE the child address
    // at slot 1 so the test can find it.
    let init = probe_self_init_code();
    let mut bc = mstore_init(&init);
    bc.extend(push1(init.len() as u8)); // size
    bc.extend(push1((32 - init.len()) as u8)); // offset (right-aligned in the word)
    bc.extend(push1(0)); // value
    bc.push(0xf0); // CREATE
    bc.extend(push1(1));
    bc.push(0x55); // SSTORE slot 1 = child address
    bc.push(0x00); // STOP
    install_contract(&stores, factory, bc);

    let out = run(&stores, owner, factory);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "expected Success, got {out:?}"
    );

    let mut child_key = [0u8; 32];
    child_key[31] = 1;
    let child_word = read_slot(&stores, factory, child_key);
    let mut child = [0u8; 21];
    child[0] = 0x41;
    child[1..].copy_from_slice(&child_word[12..]);
    assert_ne!(child_word, [0u8; 32], "CREATE must have succeeded");

    assert!(
        is_one(slot0(&stores, child)),
        "address(this).isContract must be 1 inside a nested constructor"
    );
}

/// After a SUCCESSFUL nested CREATE the parent's `Repository` holds the child's
/// contract row (`deposit.commit()`), so probing the returned address in the
/// same transaction returns 1.
#[test]
fn iscontract_true_for_nested_create_after_success() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa0);
    let factory = tron_addr(0xc0);
    install_caller(&stores, owner, 1_000_000_000);

    let init = empty_init_code();
    let mut bc = mstore_init(&init);
    bc.extend(push1(init.len() as u8));
    bc.extend(push1((32 - init.len()) as u8));
    bc.extend(push1(0));
    bc.push(0xf0); // CREATE -> pushes the child address
    bc.push(0xd4); // ISCONTRACT on the returned address
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE slot 0
    bc.push(0x00);
    install_contract(&stores, factory, bc);

    let out = run(&stores, owner, factory);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "expected Success, got {out:?}"
    );
    assert!(
        is_one(slot0(&stores, factory)),
        "a successfully created child must report isContract == 1 in the same tx"
    );
}

/// The regression that blocks the naive fix: after a CREATE whose init code
/// REVERTED, java never runs `deposit.commit()`, so the parent `Repository`
/// has no contract row and `isContract` on the would-be address is 0. Using
/// the frame-entry `pending_created_contracts` map (never pruned on revert)
/// instead of the journal's revert-aware `is_created()` would return 1 here.
#[test]
fn iscontract_false_after_reverted_nested_create() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa0);
    let factory = tron_addr(0xc0);
    install_caller(&stores, owner, 1_000_000_000);

    // CREATE2's address is deterministic (EIP-1014:
    // keccak(0xff || caller || salt || keccak(init))[12..]), so the factory can
    // probe the exact address the failed deploy WOULD have occupied — the
    // "CREATE2 factory catches a failed deploy and re-checks the slot" pattern.
    let init = reverting_init_code();
    let salt_byte = 0x77u8;
    let predicted = create2_address(factory, salt_byte, &init);

    let mut bc = mstore_init(&init);
    bc.extend(push1(salt_byte)); // salt
    bc.extend(push1(init.len() as u8)); // size
    bc.extend(push1((32 - init.len()) as u8)); // offset
    bc.extend(push1(0)); // value
    bc.push(0xf5); // CREATE2 -> pushes 0 because the init code REVERTed
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE slot 0 = the CREATE2 result (expected 0)
    // Now probe the deterministic address the deploy would have taken.
    bc.push(0x73); // PUSH20
    bc.extend_from_slice(&predicted[1..]);
    bc.push(0xd4); // ISCONTRACT
    bc.extend(push1(1));
    bc.push(0x55); // SSTORE slot 1
    bc.push(0x00);
    install_contract(&stores, factory, bc);

    let out = run(&stores, owner, factory);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "the factory itself must survive a failed CREATE2; got {out:?}"
    );
    assert!(
        is_zero(slot0(&stores, factory)),
        "a reverted CREATE2 must push 0"
    );
    let mut key1 = [0u8; 32];
    key1[31] = 1;
    assert!(
        is_zero(read_slot(&stores, factory, key1)),
        "the address of a REVERTED CREATE2 must report isContract == 0 — java          never runs `deposit.commit()` for a failed create, so the contract row          is never published. Reading `pending_created_contracts` (a frame-entry          record that is never pruned on revert) instead of the journal's          revert-aware `is_created()` would wrongly return 1 here."
    );
}

/// EIP-1014 address for a CREATE2 by `caller` with a single-byte `salt` and the
/// given init code — the derivation `CreateInputs::created_address` uses.
fn create2_address(caller: [u8; 21], salt_byte: u8, init: &[u8]) -> [u8; 21] {
    let mut salt = [0u8; 32];
    salt[31] = salt_byte;
    let init_hash = tron_crypto::hash::keccak256(init);
    let mut buf = Vec::with_capacity(85);
    buf.push(0xff);
    buf.extend_from_slice(&caller[1..]);
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(init_hash.as_slice());
    let h = tron_crypto::hash::keccak256(&buf);
    let mut out = [0u8; 21];
    out[0] = 0x41;
    out[1..].copy_from_slice(&h[12..]);
    out
}

/// Same rule one level up: an address created inside a frame that LATER reverts
/// must report 0 afterwards. The `AccountCreated` journal entry unmarks
/// `is_created` when the enclosing checkpoint reverts, matching java discarding
/// the whole child `Repository`.
#[test]
fn iscontract_false_when_ancestor_frame_reverts() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa0);
    let factory = tron_addr(0xc0);
    let inner = tron_addr(0xc1);
    install_caller(&stores, owner, 1_000_000_000);

    // `inner`: CREATE a child, then REVERT — so the child's creation is undone.
    let init = empty_init_code();
    let mut inner_bc = mstore_init(&init);
    inner_bc.extend(push1(init.len() as u8));
    inner_bc.extend(push1((32 - init.len()) as u8));
    inner_bc.extend(push1(0));
    inner_bc.push(0xf0); // CREATE
    // Return the child address to the caller: MSTORE it then RETURN 32 bytes.
    inner_bc.extend(push1(0));
    inner_bc.push(0x52); // MSTORE mem[0..32] = child address
    inner_bc.extend(push1(32));
    inner_bc.extend(push1(0));
    inner_bc.push(0xfd); // REVERT (returns the 32-byte child address as revert data)
    install_contract(&stores, inner, inner_bc);

    // `factory`: CALL inner (which reverts), copy the returned address out of
    // the return-data buffer, then ISCONTRACT it.
    let mut bc = Vec::new();
    bc.extend(push1(32)); // outSize
    bc.extend(push1(0)); // outOffset
    bc.extend(push1(0)); // inSize
    bc.extend(push1(0)); // inOffset
    bc.extend(push1(0)); // value
    bc.push(0x73); // PUSH20 inner
    bc.extend_from_slice(&inner[1..]);
    bc.push(0x61); // PUSH2 gas
    bc.extend_from_slice(&0xffffu16.to_be_bytes());
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP the (zero) success flag
    bc.extend(push1(0));
    bc.push(0x51); // MLOAD mem[0..32] = the child address the inner frame wrote
    bc.push(0xd4); // ISCONTRACT
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE slot 0
    bc.push(0x00);
    install_contract(&stores, factory, bc);

    let out = run(&stores, owner, factory);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "expected Success, got {out:?}"
    );
    assert!(
        is_zero(slot0(&stores, factory)),
        "an address created in a frame that later reverted must report \
         isContract == 0"
    );
}

/// Committed contracts and plain EOAs are unaffected by the in-flight check.
#[test]
fn iscontract_unchanged_for_committed_contract_and_eoa() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    let deployed = tron_addr(0xc9);
    install_caller(&stores, owner, 1_000_000_000);
    install_contract(&stores, deployed, vec![0x00]); // committed contract
    install_caller(&stores, tron_addr(0xe0), 42); // committed EOA

    // ISCONTRACT(deployed) -> slot 0, ISCONTRACT(eoa) -> slot 1.
    let mut bc = Vec::new();
    bc.push(0x73);
    bc.extend_from_slice(&deployed[1..]);
    bc.push(0xd4);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x73);
    bc.extend_from_slice(&tron_addr(0xe0)[1..]);
    bc.push(0xd4);
    bc.extend(push1(1));
    bc.push(0x55);
    bc.push(0x00);
    install_contract(&stores, probe, bc);

    let out = run(&stores, owner, probe);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "expected Success, got {out:?}"
    );
    assert!(
        is_one(slot0(&stores, probe)),
        "a committed contract must still report 1"
    );
    let mut key1 = [0u8; 32];
    key1[31] = 1;
    assert!(
        is_zero(read_slot(&stores, probe, key1)),
        "a committed EOA must still report 0"
    );
}
