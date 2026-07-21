//! EXTCODESIZE / EXTCODEHASH / EXTCODECOPY of `address(this)` inside a
//! top-level `CreateSmartContract` constructor must observe EMPTY code, the way
//! java-tron's `Program.getCodeAt` / `getCodeHashAt` do during construction.
//!
//! java `VMActuator.create` writes the account + `SmartContract` rows BEFORE the
//! constructor runs, but deposits the runtime code (`rootRepository.saveCode`)
//! only AFTER it returns. So during construction `invoke.getDeposit().getCode(
//! self)` is null → `getCodeAt(self)` is empty:
//!   * EXTCODESIZE(self) == 0
//!   * EXTCODECOPY(self, …) copies from empty (zero-fill)
//!   * EXTCODEHASH(self) == sha3("") — the contract row exists but carries no
//!     code hash yet, so `getCodeHashAt` hashes the empty code.
//!
//! Our deploy path runs the init code as a CALL to an account pre-installed with
//! that init code as its `code`, so without the `tron_under_construction`
//! override these opcodes would report the ~init-code bytes. This is the exact
//! shape of OpenZeppelin's `initializer` guard
//! (`!AddressUpgradeable.isContract(address(this))`, i.e. EXTCODESIZE==0), which
//! a `TransparentUpgradeableProxy` deploy runs from its constructor
//! (mainnet block 83,931,960): a non-zero size flips the guard and reverts with
//! "Initializable: contract is already initialized".
//!
//! ISCONTRACT(self) legitimately stays 1 during construction (java writes the
//! contract row first) — only the code VIEW is empty — so the two disagree here.

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    smart_contract::Abi, Account, CreateSmartContract, SmartContract, TriggerSmartContract,
};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_create, execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// ISCONTRACT is registered under ALLOW_TVM_SOLIDITY_059, and a deploy needs
/// ALLOW_TVM_CONSTANTINOPLE for the init code's RETURN to become the stored
/// runtime code (and for the empty-code-during-construction view), so both are
/// on for every test here.
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

fn deploy(stores: &VmStores, owner: [u8; 21], init_code: Vec<u8>, tx_id: [u8; 32]) -> VmOutcome {
    let create = CreateSmartContract {
        owner_address: owner.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: owner.to_vec(),
            contract_address: vec![],
            abi: Some(Abi::default()),
            bytecode: init_code,
            call_value: 0,
            consume_user_resource_percent: 100,
            name: "UnderConstruction".into(),
            origin_energy_limit: 1_000_000,
            code_hash: vec![],
            trx_hash: vec![],
            version: 1,
        }),
        call_token_value: 0,
        token_id: 0,
    };
    execute_create(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        &create,
        &tx_id,
        1_000_000,
    )
}

fn run_trigger(stores: &VmStores, caller: [u8; 21], contract: [u8; 21]) -> VmOutcome {
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
            block_number: 2,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        &trigger,
        1_000_000,
    )
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

fn slot(n: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = n;
    k
}

fn is_one(word: [u8; 32]) -> bool {
    word[31] == 1 && word[..31].iter().all(|b| *b == 0)
}

fn is_zero(word: [u8; 32]) -> bool {
    word.iter().all(|b| *b == 0)
}

fn addr_from_return(out: &VmOutcome) -> [u8; 21] {
    let VmOutcome::Success { return_data, .. } = out else {
        panic!("expected Success, got {out:?}");
    };
    let mut deployed = [0u8; 21];
    deployed.copy_from_slice(return_data);
    deployed
}

/// EXTCODESIZE(address(this)) inside a top-level constructor must be 0. The
/// constructor mirrors OpenZeppelin's `isContract` guard: it REVERTs when the
/// self code size is non-zero. Without the `tron_under_construction` fix the
/// pre-installed init code makes the size non-zero and the deploy reverts.
#[test]
fn extcodesize_self_is_zero_inside_top_level_constructor() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa0);
    install_caller(&stores, owner, 1_000_000_000);

    // ADDRESS EXTCODESIZE ; if != 0 -> REVERT ; else RETURN empty runtime.
    let init = vec![
        0x30, // ADDRESS
        0x3b, // EXTCODESIZE
        0x60, 0x0a, // PUSH1 10  (revert JUMPDEST)
        0x57, // JUMPI  (jump to revert when size != 0)
        0x60, 0x00, // PUSH1 0  (return len)
        0x60, 0x00, // PUSH1 0  (return off)
        0xf3, // RETURN  (empty runtime)
        0x5b, // JUMPDEST @10
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xfd, // REVERT
    ];
    let out = deploy(&stores, owner, init, [0x11; 32]);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "deploy must SUCCEED: EXTCODESIZE(address(this)) is 0 during construction \
         (java has not deposited the runtime code yet), so the isContract-style \
         guard does not trip; got {out:?}"
    );
}

/// EXTCODEHASH(address(this)) inside a top-level constructor must be
/// keccak256("") — the contract row exists but its code hash is unset, so java
/// `getCodeHashAt` hashes the empty code. The constructor REVERTs unless the
/// hash equals keccak256(""). Without the fix EXTCODEHASH leaks the init-code
/// hash and the deploy reverts.
#[test]
fn extcodehash_self_is_keccak_empty_inside_top_level_constructor() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa1);
    install_caller(&stores, owner, 1_000_000_000);

    let empty_hash = tron_crypto::hash::keccak256(&[]);
    let mut init = vec![
        0x30, // ADDRESS
        0x3f, // EXTCODEHASH
        0x7f, // PUSH32 keccak256("")
    ];
    init.extend_from_slice(empty_hash.as_slice());
    init.extend_from_slice(&[
        0x14, // EQ  (hash == keccak256(""))
        0x60, 0x2c, // PUSH1 44  (success JUMPDEST)
        0x57, // JUMPI  (jump to success when equal)
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xfd, // REVERT  (mismatch)
        0x5b, // JUMPDEST @44
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN  (empty runtime)
    ]);
    let out = deploy(&stores, owner, init, [0x22; 32]);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "deploy must SUCCEED: EXTCODEHASH(address(this)) is keccak256(\"\") during \
         construction, not the init-code hash; got {out:?}"
    );
}

/// EXTCODECOPY(address(this), …) inside a top-level constructor copies from
/// empty code — the destination is zero-filled. The constructor copies 32 bytes
/// of self code into memory and REVERTs if the word is non-zero. Without the fix
/// it copies the (non-zero) init code and the deploy reverts.
#[test]
fn extcodecopy_self_reads_empty_inside_top_level_constructor() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa2);
    install_caller(&stores, owner, 1_000_000_000);

    let init = vec![
        0x60, 0x20, // PUSH1 32  (length)
        0x60, 0x00, // PUSH1 0   (code offset)
        0x60, 0x00, // PUSH1 0   (dest offset)
        0x30, // ADDRESS         (address, on top)
        0x3c, // EXTCODECOPY     -> mem[0..32] = self code (zero-fill if empty)
        0x60, 0x00, // PUSH1 0
        0x51, // MLOAD           (word = mem[0..32])
        0x60, 0x13, // PUSH1 19  (revert JUMPDEST)
        0x57, // JUMPI           (jump to revert when word != 0)
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN          (empty runtime)
        0x5b, // JUMPDEST @19
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xfd, // REVERT
    ];
    let out = deploy(&stores, owner, init, [0x33; 32]);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "deploy must SUCCEED: EXTCODECOPY(address(this)) copies from empty code \
         during construction; got {out:?}"
    );
}

/// Non-regression: ISCONTRACT(self) stays 1 while EXTCODESIZE(self) is 0 during
/// construction (they legitimately disagree — java writes the contract row
/// before the code). The constructor stores both, then returns runtime code.
#[test]
fn iscontract_stays_one_while_extcodesize_is_zero() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa3);
    install_caller(&stores, owner, 1_000_000_000);

    let init = vec![
        0x30, // ADDRESS
        0xd4, // ISCONTRACT
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE  slot0 = isContract(self)
        0x30, // ADDRESS
        0x3b, // EXTCODESIZE
        0x60, 0x01, // PUSH1 1
        0x55, // SSTORE  slot1 = extcodesize(self)
        0x60, 0x01, // PUSH1 1  (return a 1-byte STOP runtime)
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN
    ];
    let out = deploy(&stores, owner, init, [0x44; 32]);
    let deployed = addr_from_return(&out);

    assert!(
        is_one(read_slot(&stores, deployed, slot(0))),
        "ISCONTRACT(address(this)) must stay 1 during construction"
    );
    assert!(
        is_zero(read_slot(&stores, deployed, slot(1))),
        "EXTCODESIZE(address(this)) must be 0 during construction"
    );
}

/// Scoping: the construction override is per-transaction. After the deploy
/// commits, a LATER transaction must see the real runtime code size — proving
/// `top_level_deploy_version` does not leak past the construction window.
#[test]
fn later_tx_sees_real_runtime_code_size() {
    let stores = fresh_stores();
    let owner = tron_addr(0xa4);
    install_caller(&stores, owner, 1_000_000_000);

    // Constructor returns a 5-byte runtime (five STOPs from zero memory).
    let init = vec![
        0x60, 0x05, // PUSH1 5   (return len)
        0x60, 0x00, // PUSH1 0   (return off)
        0xf3, // RETURN
    ];
    let out = deploy(&stores, owner, init, [0x55; 32]);
    let deployed = addr_from_return(&out);

    // A separate probe contract, run in its own trigger tx, reads
    // EXTCODESIZE(deployed) into slot 0.
    let probe = tron_addr(0xc0);
    let mut bc = vec![0x73]; // PUSH20 deployed
    bc.extend_from_slice(&deployed[1..]);
    bc.extend_from_slice(&[
        0x3b, // EXTCODESIZE
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE slot0
        0x00, // STOP
    ]);
    install_contract(&stores, probe, bc);

    let out = run_trigger(&stores, owner, probe);
    assert!(
        matches!(out, VmOutcome::Success { .. }),
        "probe trigger must succeed; got {out:?}"
    );
    let size = read_slot(&stores, probe, slot(0));
    assert_eq!(
        size[31], 5,
        "a later tx must observe the real 5-byte runtime code size, not the \
         construction-time empty view"
    );
    assert!(
        size[..31].iter().all(|b| *b == 0),
        "runtime code size must be exactly 5"
    );
}
