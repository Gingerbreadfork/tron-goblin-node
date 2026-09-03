//! CREATE2 onto an address that already holds a contract, from mainnet block
//! 84,861,074 tx 5debd583… (and 84,861,092 tx 78bd7184…, the same calldata at
//! a 5,000,000 budget).
//!
//! `TokenFactory` (41ca542a…) passes the CALLDATA offset of its `bytes
//! initcode` argument to `CREATE2` as a MEMORY offset, so the child is built
//! from zeroed memory and its address is fixed per salt. An earlier identical
//! call had already deployed that empty contract. java's `createContractImpl`
//! finds the account and its `SmartContract` row (`contractAlreadyExists`),
//! throws, and the factory forfeits the whole forwarded budget: OUT_OF_ENERGY
//! on the very next opcode (`SWAP1`) with `usedEnergy == curInvokeEnergyLimit`.
//! Without the row (a fresh store) the zero init code simply runs, STOPs and
//! deploys empty code again, exactly as java would.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, SmartContract, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

const FACTORY: [u8; 21] = [
    0x41, 0xca, 0x54, 0x2a, 0x98, 0x8b, 0xa8, 0x86, 0x04, 0xd4, 0x7d, 0x20, 0x2f, 0x4b, 0x6a,
    0xdd, 0x56, 0x1e, 0x14, 0x5d, 0xdc,
];
const CALLER: [u8; 21] = [
    0x41, 0xc5, 0x87, 0xea, 0x9a, 0xde, 0xe6, 0xdf, 0xd6, 0x92, 0x80, 0x95, 0xe4, 0x32, 0xcd,
    0x89, 0xae, 0x37, 0x9f, 0xf7, 0xf9,
];

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn hex_fixture(name: &str) -> Vec<u8> {
    let s = include_str!(concat!("fixtures/create2_collision_84861074/", "runtime.hex"));
    let c = match name {
        "runtime" => s,
        "calldata" => include_str!("fixtures/create2_collision_84861074/calldata_5debd583.hex"),
        _ => unreachable!(),
    };
    let c = c.trim();
    (0..c.len() / 2)
        .map(|i| u8::from_str_radix(&c[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// Mainnet proposal state on 2026-07-29 (block 84,861,074): everything up to
/// Cancun, no compatible-EVM, no Prague/Osaka.
fn mainnet_stores() -> VmStores {
    let dp = Arc::new(DynamicPropertiesStore::new(mem()));
    for k in [
        "ALLOW_TVM_TRANSFER_TRC10",
        "ALLOW_TVM_CONSTANTINOPLE",
        "ALLOW_TVM_SOLIDITY_059",
        "ALLOW_TVM_ISTANBUL",
        "ALLOW_TVM_FREEZE_V2",
        "ALLOW_TVM_VOTE",
        "ALLOW_TVM_LONDON",
        "ALLOW_TVM_SHANGHAI",
        "ALLOW_TVM_CANCUN",
        "ALLOW_DYNAMIC_ENERGY",
        "ALLOW_ENERGY_ADJUSTMENT",
        "ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
        "ALLOW_TVM_SELFDESTRUCT_RESTRICTION",
        "ALLOW_MULTI_SIGN",
        "ALLOW_STRICT_MATH",
        "ALLOW_DELEGATE_RESOURCE",
        "ALLOW_NEW_RESOURCE_MODEL",
        "ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID",
        "ALLOW_ACCOUNT_ASSET_OPTIMIZATION",
        "ALLOW_ASSET_OPTIMIZATION",
    ] {
        dp.put_long(k.as_bytes(), 1);
    }
    dp.put_long(b"ALLOW_TVM_COMPATIBLE_EVM", 0);
    dp.put_long(b"ENERGY_FEE", 100);
    dp.put_long(b"DYNAMIC_ENERGY_THRESHOLD", 5_000_000_000);
    dp.put_long(b"DYNAMIC_ENERGY_INCREASE_FACTOR", 2_000);
    dp.put_long(b"DYNAMIC_ENERGY_MAX_FACTOR", 34_000);
    dp.save_latest_block_header_timestamp(1_785_253_899_000);
    let contracts = Arc::new(ContractStore::new(mem()));
    contracts
        .put(
            &Address::from_raw(FACTORY),
            &SmartContract {
                contract_address: FACTORY.to_vec(),
                origin_address: FACTORY.to_vec(),
                consume_user_resource_percent: 0,
                origin_energy_limit: 100_000,
                version: 0,
                ..Default::default()
            },
        )
        .unwrap();
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties: dp,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: Some(contracts),
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
        abi: None,
    }
}

fn install(stores: &VmStores) {
    let code = hex_fixture("runtime");
    let hash = code_hash(&code);
    stores.code.put(hash.as_slice(), &code).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(FACTORY),
            &Account {
                address: FACTORY.to_vec(),
                balance: 0,
                code: code.clone(),
                code_hash: hash.as_slice().to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(CALLER),
            &Account { address: CALLER.to_vec(), balance: 10_000_000_000, ..Default::default() },
        )
        .unwrap();
}

fn assert_java_out_of_energy(out: VmOutcome, limit: u64) {
    match out {
        VmOutcome::Halt { result, energy_used, ref reason } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::OutOfEnergy,
                "java: OUT_OF_ENERGY at SWAP1 right after CREATE2 (halt reason {reason})"
            );
            assert_eq!(energy_used, limit, "java: usedEnergy == curInvokeEnergyLimit");
        }
        other => panic!("java recorded OUT_OF_ENERGY with the whole {limit} spent; ours: {other:?}"),
    }
}

/// The zero init code runs, STOPs at pc 0 and deploys empty code: the create
/// succeeds, the factory returns the address, and almost all of the budget
/// comes back.
fn assert_cheap_deploy(out: VmOutcome) {
    match out {
        VmOutcome::Success { return_data, energy_used, .. } => {
            assert_eq!(&return_data[12..], &ZERO_INIT_TARGET[1..], "the factory returns the created address");
            assert!(energy_used < 200_000, "empty code costs no deposit (used={energy_used})");
        }
        other => panic!("expected a cheap successful deploy, got {other:?}"),
    }
}

const ZERO_INIT_TARGET: [u8; 21] = [
    0x41, 0x4a, 0xf0, 0xf2, 0x35, 0x1c, 0xd3, 0x97, 0x12, 0xa3, 0x33, 0xbc, 0xd6, 0x78, 0x43,
    0xb2, 0x78, 0xb9, 0xe9, 0x64, 0xe5,
];

/// What already sits at the CREATE2 target when the factory runs.
enum Target {
    Nothing,
    /// A plain account that once received funds: no `SmartContract` row.
    FundedAccount,
    /// The mainnet state: the empty contract an earlier call deployed there.
    EmptyContract,
}

fn install_target(stores: &VmStores, target: Target) {
    let addr = Address::from_raw(ZERO_INIT_TARGET);
    match target {
        Target::Nothing => {}
        Target::FundedAccount => {
            stores
                .accounts
                .put(&addr, &Account { address: ZERO_INIT_TARGET.to_vec(), balance: 1_000_000, ..Default::default() })
                .unwrap();
        }
        Target::EmptyContract => {
            stores
                .accounts
                .put(
                    &addr,
                    &Account {
                        address: ZERO_INIT_TARGET.to_vec(),
                        account_name: b"CreatedByContract".to_vec(),
                        r#type: tron_proto::AccountType::Contract as i32,
                        ..Default::default()
                    },
                )
                .unwrap();
            stores
                .contracts
                .as_ref()
                .unwrap()
                .put(
                    &addr,
                    &SmartContract {
                        contract_address: ZERO_INIT_TARGET.to_vec(),
                        origin_address: FACTORY.to_vec(),
                        consume_user_resource_percent: 100,
                        version: 0,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
    }
}

fn run_against(target: Target, limit: u64) -> VmOutcome {
    let stores = mainnet_stores();
    install(&stores);
    install_target(&stores, target);
    let trigger = TriggerSmartContract {
        owner_address: CALLER.to_vec(),
        contract_address: FACTORY.to_vec(),
        call_value: 0,
        data: hex_fixture("calldata"),
        call_token_value: 0,
        token_id: 0,
    };
    execute_trigger(
        &stores,
        VmBlockEnv { block_number: 84_861_074, block_timestamp_ms: 1_785_253_902_000, ..Default::default() },
        &trigger,
        limit,
    )
}

#[test]
fn existing_empty_contract_collides_and_forfeits_the_budget_at_1m() {
    assert_java_out_of_energy(run_against(Target::EmptyContract, 1_000_000), 1_000_000);
}

#[test]
fn existing_empty_contract_collides_and_forfeits_the_budget_at_5m() {
    assert_java_out_of_energy(run_against(Target::EmptyContract, 5_000_000), 5_000_000);
}

#[test]
fn a_fresh_address_takes_the_zero_init_deploy_cheaply() {
    assert_cheap_deploy(run_against(Target::Nothing, 1_000_000));
}

/// java post-Constantinople: an account without a `SmartContract` row is not
/// a collision — it is retyped to Contract and the init code runs.
#[test]
fn a_funded_plain_account_does_not_collide_post_constantinople() {
    assert_cheap_deploy(run_against(Target::FundedAccount, 1_000_000));
}
