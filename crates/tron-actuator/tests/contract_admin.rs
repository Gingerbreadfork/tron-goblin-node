//! Error-path tests for the three smart-contract admin actuators:
//!   * `ClearABIContract`              — wipe a contract's ABI metadata
//!   * `UpdateEnergyLimitContract`     — change a contract's `originEnergyLimit`
//!   * `UpdateSettingContract`         — change `consume_user_resource_percent`
//!
//! Java reference: `ClearABIContractActuatorTest` (~6),
//! `UpdateEnergyLimitContractActuatorTest` (~7),
//! `UpdateSettingContractActuatorTest` (~9). Our `full_layer.rs` had
//! one or two smokes per actuator; these tests cover the per-rule
//! validation (Constantinople gating, ownership, percent / energy
//! bounds, missing-contract) end-to-end.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{contract_admin, ActuatorError};
use tron_chainbase::{
    AbiStore, AccountStore, ContractStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::{
    Account, AccountType, ClearAbiContract, SmartContract, UpdateEnergyLimitContract,
    UpdateSettingContract,
};

const OWNER: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const OTHER: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const CONTRACT: [u8; 21] = hex!("41cccccccccccccccccccccccccccccccccccccccc");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

struct Ctx {
    accounts: AccountStore,
    contracts: ContractStore,
    abi: AbiStore,
    dp: DynamicPropertiesStore,
}

fn ctx() -> Ctx {
    Ctx {
        accounts: AccountStore::new(mem()),
        contracts: ContractStore::new(mem()),
        abi: AbiStore::new(mem()),
        dp: DynamicPropertiesStore::new(mem()),
    }
}

fn put_account(ctx: &Ctx, who: [u8; 21]) {
    ctx.accounts.put(
        &addr(who),
        &Account {
            address: who.to_vec(),
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    );
}

fn put_contract(ctx: &Ctx, contract_addr: [u8; 21], owner: [u8; 21]) {
    ctx.contracts.put(
        &addr(contract_addr),
        &SmartContract {
            origin_address: owner.to_vec(),
            contract_address: contract_addr.to_vec(),
            origin_energy_limit: 10_000_000,
            consume_user_resource_percent: 30,
            ..Default::default()
        },
    );
}

fn enable_constantinople(ctx: &Ctx) {
    ctx.dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
}

// ============================================================
// ClearABIContract
// ============================================================

#[test]
fn clear_abi_rejects_when_constantinople_disabled() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_contract(&ctx, CONTRACT, OWNER);
    let c = ClearAbiContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
    };
    let err =
        contract_admin::validate_clear_abi(&ctx.accounts, &ctx.contracts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ConstantinopleDisabled));
}

#[test]
fn clear_abi_rejects_invalid_contract_address() {
    let ctx = ctx();
    enable_constantinople(&ctx);
    put_account(&ctx, OWNER);
    let c = ClearAbiContract {
        owner_address: OWNER.to_vec(),
        contract_address: vec![0u8; 10], // wrong length
    };
    let err =
        contract_admin::validate_clear_abi(&ctx.accounts, &ctx.contracts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidAddress));
}

#[test]
fn clear_abi_rejects_missing_owner_account() {
    let ctx = ctx();
    enable_constantinople(&ctx);
    put_contract(&ctx, CONTRACT, OWNER);
    // Don't seed owner account.
    let c = ClearAbiContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
    };
    let err =
        contract_admin::validate_clear_abi(&ctx.accounts, &ctx.contracts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn clear_abi_rejects_missing_contract() {
    let ctx = ctx();
    enable_constantinople(&ctx);
    put_account(&ctx, OWNER);
    let c = ClearAbiContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
    };
    let err =
        contract_admin::validate_clear_abi(&ctx.accounts, &ctx.contracts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ContractMissing));
}

#[test]
fn clear_abi_rejects_non_origin_owner() {
    let ctx = ctx();
    enable_constantinople(&ctx);
    put_account(&ctx, OWNER);
    put_account(&ctx, OTHER);
    put_contract(&ctx, CONTRACT, OTHER); // owned by OTHER, not OWNER
    let c = ClearAbiContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
    };
    let err =
        contract_admin::validate_clear_abi(&ctx.accounts, &ctx.contracts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NotContractOwner));
}

#[test]
fn clear_abi_writes_empty_abi() {
    let ctx = ctx();
    enable_constantinople(&ctx);
    put_account(&ctx, OWNER);
    put_contract(&ctx, CONTRACT, OWNER);
    // Seed a non-empty ABI so we can verify it gets cleared.
    use tron_proto::smart_contract::Abi;
    use tron_proto::smart_contract::abi::Entry;
    ctx.abi.put(
        &addr(CONTRACT),
        &Abi {
            entrys: vec![Entry {
                anonymous: false,
                constant: false,
                name: "myFunc".to_string(),
                ..Default::default()
            }],
        },
    );
    let c = ClearAbiContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
    };
    contract_admin::validate_clear_abi(&ctx.accounts, &ctx.contracts, &ctx.dp, &c).unwrap();
    contract_admin::execute_clear_abi(&ctx.abi, &c).unwrap();
    let cleared = ctx.abi.get(&addr(CONTRACT)).unwrap().unwrap();
    assert!(cleared.entrys.is_empty());
}

// ============================================================
// UpdateEnergyLimitContract
// ============================================================

#[test]
fn update_energy_limit_rejects_missing_owner() {
    let ctx = ctx();
    put_contract(&ctx, CONTRACT, OWNER);
    let c = UpdateEnergyLimitContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        origin_energy_limit: 20_000_000,
    };
    let err =
        contract_admin::validate_update_energy_limit(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn update_energy_limit_rejects_invalid_address() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    let c = UpdateEnergyLimitContract {
        owner_address: OWNER.to_vec(),
        contract_address: vec![0u8; 10],
        origin_energy_limit: 1_000,
    };
    let err =
        contract_admin::validate_update_energy_limit(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidAddress));
}

#[test]
fn update_energy_limit_rejects_non_positive_limit() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_contract(&ctx, CONTRACT, OWNER);
    for lim in [0i64, -1, i64::MIN] {
        let c = UpdateEnergyLimitContract {
            owner_address: OWNER.to_vec(),
            contract_address: CONTRACT.to_vec(),
            origin_energy_limit: lim,
        };
        let err =
            contract_admin::validate_update_energy_limit(&ctx.accounts, &ctx.contracts, &c)
                .unwrap_err();
        assert!(
            matches!(err, ActuatorError::NonPositiveEnergyLimit),
            "lim={lim} got: {err:?}"
        );
    }
}

#[test]
fn update_energy_limit_rejects_missing_contract() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    let c = UpdateEnergyLimitContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        origin_energy_limit: 1_000,
    };
    let err =
        contract_admin::validate_update_energy_limit(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ContractMissing));
}

#[test]
fn update_energy_limit_rejects_non_owner() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_account(&ctx, OTHER);
    put_contract(&ctx, CONTRACT, OTHER);
    let c = UpdateEnergyLimitContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        origin_energy_limit: 1_000,
    };
    let err =
        contract_admin::validate_update_energy_limit(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NotContractOwner));
}

#[test]
fn update_energy_limit_writes_new_value() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_contract(&ctx, CONTRACT, OWNER);
    let c = UpdateEnergyLimitContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        origin_energy_limit: 42_000_000,
    };
    contract_admin::validate_update_energy_limit(&ctx.accounts, &ctx.contracts, &c).unwrap();
    contract_admin::execute_update_energy_limit(&ctx.contracts, &c).unwrap();
    let post = ctx.contracts.get(&addr(CONTRACT)).unwrap().unwrap();
    assert_eq!(post.origin_energy_limit, 42_000_000);
    // Other fields unchanged.
    assert_eq!(post.consume_user_resource_percent, 30);
}

// ============================================================
// UpdateSettingContract
// ============================================================

#[test]
fn update_setting_rejects_missing_owner() {
    let ctx = ctx();
    put_contract(&ctx, CONTRACT, OWNER);
    let c = UpdateSettingContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        consume_user_resource_percent: 50,
    };
    let err =
        contract_admin::validate_update_setting(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn update_setting_rejects_invalid_address() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    let c = UpdateSettingContract {
        owner_address: OWNER.to_vec(),
        contract_address: vec![0u8; 10],
        consume_user_resource_percent: 50,
    };
    let err =
        contract_admin::validate_update_setting(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidAddress));
}

#[test]
fn update_setting_rejects_percent_out_of_range() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_contract(&ctx, CONTRACT, OWNER);
    for p in [-1i64, 101, 200, i64::MAX] {
        let c = UpdateSettingContract {
            owner_address: OWNER.to_vec(),
            contract_address: CONTRACT.to_vec(),
            consume_user_resource_percent: p,
        };
        let err =
            contract_admin::validate_update_setting(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::PercentOutOfRange),
            "p={p} got: {err:?}"
        );
    }
}

#[test]
fn update_setting_accepts_boundary_percents() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_contract(&ctx, CONTRACT, OWNER);
    for p in [0i64, 100] {
        let c = UpdateSettingContract {
            owner_address: OWNER.to_vec(),
            contract_address: CONTRACT.to_vec(),
            consume_user_resource_percent: p,
        };
        contract_admin::validate_update_setting(&ctx.accounts, &ctx.contracts, &c).unwrap();
        contract_admin::execute_update_setting(&ctx.contracts, &c).unwrap();
        let sc = ctx.contracts.get(&addr(CONTRACT)).unwrap().unwrap();
        assert_eq!(sc.consume_user_resource_percent, p);
    }
}

#[test]
fn update_setting_rejects_missing_contract() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    let c = UpdateSettingContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        consume_user_resource_percent: 50,
    };
    let err =
        contract_admin::validate_update_setting(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ContractMissing));
}

#[test]
fn update_setting_rejects_non_owner() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_account(&ctx, OTHER);
    put_contract(&ctx, CONTRACT, OTHER);
    let c = UpdateSettingContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        consume_user_resource_percent: 50,
    };
    let err =
        contract_admin::validate_update_setting(&ctx.accounts, &ctx.contracts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NotContractOwner));
}

#[test]
fn update_setting_preserves_origin_energy_limit() {
    let ctx = ctx();
    put_account(&ctx, OWNER);
    put_contract(&ctx, CONTRACT, OWNER);
    let c = UpdateSettingContract {
        owner_address: OWNER.to_vec(),
        contract_address: CONTRACT.to_vec(),
        consume_user_resource_percent: 75,
    };
    contract_admin::execute_update_setting(&ctx.contracts, &c).unwrap();
    let post = ctx.contracts.get(&addr(CONTRACT)).unwrap().unwrap();
    assert_eq!(post.consume_user_resource_percent, 75);
    assert_eq!(post.origin_energy_limit, 10_000_000); // unchanged
}
