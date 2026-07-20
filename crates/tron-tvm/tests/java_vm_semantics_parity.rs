//! Opcode-semantics parity against java-tron's own VM test suite.
//!
//! Companion to `java_energy_parity.rs`, which pins java's exact energy
//! numbers. This file pins the *values* java's tests assert for opcodes whose
//! TRON behaviour differs from stock EVM or whose account-classification rules
//! are easy to get subtly wrong:
//!
//! * `ExtCodeHashTest` — what EXTCODEHASH returns for missing accounts,
//!   code-less accounts, and addresses carrying dirty bits above 160.
//! * `IsContractTest` — what ISCONTRACT returns for missing accounts,
//!   code-less accounts, precompile addresses, and real contracts.
//! * `AllowTvmLondonTest.testBaseFee` — BASEFEE pushes the chain's energy
//!   price, not an EIP-1559 base fee.
//!
//! Each probe stores the opcode's result into slot 0 of the executing contract
//! and the test reads that slot back, so the assertion is on committed state
//! rather than on a return value the harness could reshape.

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

/// EXTCODEHASH needs `ALLOW_TVM_CONSTANTINOPLE`, ISCONTRACT needs
/// `ALLOW_TVM_SOLIDITY_059` and BASEFEE needs `ALLOW_TVM_LONDON`; java's
/// `ExtCodeHashTest` / `IsContractTest` / `AllowTvmLondonTest` each switch on
/// exactly the gates their opcode requires, so turn on all three here.
fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_ISTANBUL", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_LONDON", 1);
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

/// A plain account: present in the account store, no code.
fn install_eoa(stores: &VmStores, addr: [u8; 21], balance: i64) {
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
    let composed = StorageRowStore::compose_key(&Address::from_raw(addr), &[0u8; 32]);
    let raw = stores.storage.get(&composed).unwrap().unwrap_or_default();
    let mut out = [0u8; 32];
    if raw.len() == 32 {
        out.copy_from_slice(&raw);
    }
    out
}

/// Pre-fill slot 0 with a sentinel. Tests whose expected answer is zero use
/// this so that "the probe never ran" cannot masquerade as "the probe wrote
/// zero" — the SSTORE has to actually overwrite the sentinel.
fn seed_slot0(stores: &VmStores, addr: [u8; 21]) {
    let composed = StorageRowStore::compose_key(&Address::from_raw(addr), &[0u8; 32]);
    stores.storage.put(&composed, &[0xffu8; 32]).unwrap();
}

/// `PUSH32 <word> ; <opcode> ; PUSH1 0 ; SSTORE ; STOP` — apply a one-argument
/// address opcode to an arbitrary full 256-bit word and commit the result.
fn probe_word(word: [u8; 32], opcode: u8) -> Vec<u8> {
    let mut bc = vec![0x7f];
    bc.extend_from_slice(&word);
    bc.extend_from_slice(&[opcode, 0x60, 0x00, 0x55, 0x00]);
    bc
}

/// The same probe fed a 20-byte EVM address zero-extended into a word, which
/// is how solc passes an `address` argument.
fn probe_addr(addr: [u8; 21], opcode: u8) -> Vec<u8> {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&addr[1..]);
    probe_word(word, opcode)
}

fn assert_success(outcome: &VmOutcome) {
    assert!(matches!(outcome, VmOutcome::Success { .. }), "expected Success, got {outcome:?}");
}

const EXTCODEHASH: u8 = 0x3f;
const ISCONTRACT: u8 = 0xd4;
const BASEFEE: u8 = 0x48;

/// keccak256 of the empty byte string — java's `Hash.EMPTY_TRIE_HASH`
/// equivalent for code, asserted verbatim in `ExtCodeHashTest`.
const KECCAK_EMPTY: &str = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

fn hex32(word: [u8; 32]) -> String {
    word.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// ExtCodeHashTest
// ---------------------------------------------------------------------------

/// java `ExtCodeHashTest.testExtCodeHash` asserts `getCodeHashByAddr` on an
/// account that does not exist returns all zeroes — EXTCODEHASH distinguishes
/// "no such account" from "account with no code".
#[test]
fn extcodehash_of_nonexistent_account_is_zero() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    install_eoa(&stores, caller, 1_000_000_000);
    // 0xbb is never written to any store.
    install_contract(&stores, probe, probe_addr(tron_addr(0xbb), EXTCODEHASH));

    seed_slot0(&stores, probe);
    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    assert_eq!(
        hex32(slot0(&stores, probe)),
        "0".repeat(64),
        "EXTCODEHASH of a nonexistent account must be zero"
    );
}

/// java `ExtCodeHashTest.testExtCodeHash` asserts `getCodeHashByAddr` on an
/// existing account with no code returns `keccak256("")`, not zero.
#[test]
fn extcodehash_of_codeless_account_is_keccak_empty() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    let eoa = tron_addr(0xbb);
    install_eoa(&stores, caller, 1_000_000_000);
    install_eoa(&stores, eoa, 12_345);
    install_contract(&stores, probe, probe_addr(eoa, EXTCODEHASH));

    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    assert_eq!(
        hex32(slot0(&stores, probe)),
        KECCAK_EMPTY,
        "EXTCODEHASH of an existing code-less account must be keccak256(\"\")"
    );
}

/// java `ExtCodeHashTest.testExtCodeHash` asserts `getCodeHashByUint` on a
/// deployed contract returns that contract's code hash.
#[test]
fn extcodehash_of_contract_is_its_code_hash() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    let target = tron_addr(0xdd);
    let target_code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
    install_eoa(&stores, caller, 1_000_000_000);
    install_contract(&stores, target, target_code.clone());
    install_contract(&stores, probe, probe_addr(target, EXTCODEHASH));

    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    assert_eq!(
        hex32(slot0(&stores, probe)),
        hex32(<[u8; 32]>::try_from(code_hash(&target_code).as_slice()).unwrap()),
        "EXTCODEHASH must return the target's code hash"
    );
}

/// java `ExtCodeHashTest.testExtCodeHash` feeds `getCodeHashByUint` the same
/// contract address with `2^160` added and asserts the answer is unchanged:
/// EXTCODEHASH masks its argument down to the low 160 bits, so dirty high bits
/// are ignored rather than producing a miss.
#[test]
fn extcodehash_masks_bits_above_160() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    let target = tron_addr(0xdd);
    let target_code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
    install_eoa(&stores, caller, 1_000_000_000);
    install_contract(&stores, target, target_code.clone());

    // The target address plus 2^160: byte 11 (the one just above the 20-byte
    // body) set to 1, exactly java's `BigInteger.valueOf(2).pow(160).add(...)`.
    let mut dirty = [0u8; 32];
    dirty[12..].copy_from_slice(&target[1..]);
    dirty[11] = 0x01;
    install_contract(&stores, probe, probe_word(dirty, EXTCODEHASH));

    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    assert_eq!(
        hex32(slot0(&stores, probe)),
        hex32(<[u8; 32]>::try_from(code_hash(&target_code).as_slice()).unwrap()),
        "EXTCODEHASH must mask its argument to 160 bits"
    );
}

// ---------------------------------------------------------------------------
// IsContractTest
// ---------------------------------------------------------------------------

/// java `IsContractTest.testIsContract` asserts `isTest(address)` returns 0
/// for an account that does not exist.
#[test]
fn iscontract_of_nonexistent_account_is_zero() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    install_eoa(&stores, caller, 1_000_000_000);
    install_contract(&stores, probe, probe_addr(tron_addr(0xbb), ISCONTRACT));

    seed_slot0(&stores, probe);
    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    assert_eq!(hex32(slot0(&stores, probe)), "0".repeat(64));
}

/// java `IsContractTest.testIsContract` asserts `isTest(address)` returns 0
/// for an existing plain account.
#[test]
fn iscontract_of_codeless_account_is_zero() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    let eoa = tron_addr(0xbb);
    install_eoa(&stores, caller, 1_000_000_000);
    install_eoa(&stores, eoa, 12_345);
    install_contract(&stores, probe, probe_addr(eoa, ISCONTRACT));

    seed_slot0(&stores, probe);
    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    assert_eq!(hex32(slot0(&stores, probe)), "0".repeat(64));
}

/// java `IsContractTest.testIsContract` passes the raw word `0x…010001` — a
/// TRON precompile address — and asserts 0. Precompiles are not contracts as
/// far as ISCONTRACT is concerned, because they have no stored code.
#[test]
fn iscontract_of_precompile_address_is_zero() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    install_eoa(&stores, caller, 1_000_000_000);

    let mut word = [0u8; 32];
    word[30] = 0x01;
    word[31] = 0x01;
    install_contract(&stores, probe, probe_word(word, ISCONTRACT));

    seed_slot0(&stores, probe);
    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    assert_eq!(
        hex32(slot0(&stores, probe)),
        "0".repeat(64),
        "a precompile address must not report as a contract"
    );
}

/// java `IsContractTest.testIsContract` asserts `isTest(address)` returns 1
/// for a deployed contract, and `isContrct()` — which probes `address(this)` —
/// likewise returns 1.
#[test]
fn iscontract_of_deployed_contract_is_one() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    let target = tron_addr(0xdd);
    install_eoa(&stores, caller, 1_000_000_000);
    install_contract(&stores, target, vec![0x60, 0x00, 0x60, 0x00, 0xf3]);
    install_contract(&stores, probe, probe_addr(target, ISCONTRACT));

    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert_eq!(hex32(slot0(&stores, probe)), hex32(expected));
}

/// The `isContrct()` half of java `IsContractTest.testIsContract`:
/// `ADDRESS ISCONTRACT` inside a running contract is 1.
#[test]
fn iscontract_of_self_is_one() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    install_eoa(&stores, caller, 1_000_000_000);
    // ADDRESS ; ISCONTRACT ; PUSH1 0 ; SSTORE ; STOP
    install_contract(&stores, probe, vec![0x30, ISCONTRACT, 0x60, 0x00, 0x55, 0x00]);

    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert_eq!(hex32(slot0(&stores, probe)), hex32(expected));
}

// ---------------------------------------------------------------------------
// AllowTvmLondonTest
// ---------------------------------------------------------------------------

/// java `AllowTvmLondonTest.testBaseFee` asserts `block.basefee` equals
/// `dynamicPropertiesStore.getEnergyFee()`. TRON reuses the EIP-3198 opcode to
/// surface the energy price in sun, so a stock-EVM implementation pushing an
/// EIP-1559 base fee (typically 0) would diverge.
#[test]
fn basefee_pushes_energy_fee() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    stores.dynamic_properties.put_long(b"ENERGY_FEE", 420);
    install_eoa(&stores, caller, 1_000_000_000);
    // BASEFEE ; PUSH1 0 ; SSTORE ; STOP
    install_contract(&stores, probe, vec![BASEFEE, 0x60, 0x00, 0x55, 0x00]);

    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    let mut expected = [0u8; 32];
    expected[30] = 0x01;
    expected[31] = 0xa4; // 420
    assert_eq!(
        hex32(slot0(&stores, probe)),
        hex32(expected),
        "BASEFEE must push getEnergyFee(), not an EIP-1559 base fee"
    );
}

/// The same opcode at the mainnet default energy price of 140 sun, so the test
/// pins the wiring rather than one arbitrary configured value.
#[test]
fn basefee_tracks_configured_energy_fee() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let probe = tron_addr(0xc0);
    stores.dynamic_properties.put_long(b"ENERGY_FEE", 140);
    install_eoa(&stores, caller, 1_000_000_000);
    install_contract(&stores, probe, vec![BASEFEE, 0x60, 0x00, 0x55, 0x00]);

    let outcome = run(&stores, caller, probe);
    assert_success(&outcome);
    let mut expected = [0u8; 32];
    expected[31] = 140;
    assert_eq!(hex32(slot0(&stores, probe)), hex32(expected));
}
