//! Validation-order parity with java-tron's actuators.
//!
//! java's `validate()` methods check preconditions in a fixed sequence and
//! the *first* failing check decides the rejection. Every case below feeds a
//! contract that violates **two** preconditions at once, so the test can only
//! pass if the checks run in java's order. The corresponding java tests
//! exercise the checks one at a time and therefore never pin the sequence —
//! that is the gap these fill.
//!
//! References: `CreateAccountActuatorTest`, `UpdateSettingContractActuatorTest`,
//! `UpdateEnergyLimitContractActuatorTest`, `WitnessUpdateActuatorTest`,
//! `UpdateBrokerageActuatorTest`, `ProposalDeleteActuatorTest`,
//! `TransferActuatorTest`, `TransferAssetActuatorTest`.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{
    account, asset, contract_admin, proposal, transfer, witness, ActuatorError,
};
use tron_chainbase::{
    AccountStore, ContractStore, DynamicPropertiesStore, KvBackend, MemBackend, ProposalStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    Account, AccountCreateContract, AccountType, Proposal, ProposalDeleteContract, SmartContract,
    TransferAssetContract, TransferContract, UpdateBrokerageContract, UpdateEnergyLimitContract,
    UpdateSettingContract, Witness, WitnessUpdateContract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const CONTRACT: [u8; 21] = hex!("41dddddddddddddddddddddddddddddddddddddddd");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

fn put_account(accounts: &AccountStore, who: [u8; 21], balance: i64) {
    accounts
        .put(
            &addr(who),
            &Account {
                address: who.to_vec(),
                balance,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
}

fn put_contract(contracts: &ContractStore, at: [u8; 21], origin: [u8; 21]) {
    contracts
        .put(
            &addr(at),
            &SmartContract {
                origin_address: origin.to_vec(),
                contract_address: at.to_vec(),
                consume_user_resource_percent: 50,
                origin_energy_limit: 10_000_000,
                ..Default::default()
            },
        )
        .unwrap();
}

// =============================================================================
// CreateAccountActuator
// =============================================================================

/// java `CreateAccountActuator.validate` resolves the owner account and its
/// fee balance *before* it validates `account_address`. An owner that does not
/// exist is reported as the missing account even when the address being
/// created is malformed.
#[test]
fn create_account_checks_owner_before_new_address() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: vec![0u8; 10], // malformed
        r#type: AccountType::Normal as i32,
    };
    assert_eq!(
        account::validate_create_account(&accounts, &dp, &c),
        Err(ActuatorError::OwnerAccountMissing)
    );
}

/// The fee check ("Validate CreateAccountActuator error, insufficient fee.")
/// also precedes the new-address validity check.
#[test]
fn create_account_checks_fee_before_new_address() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 100_000);
    put_account(&accounts, ALICE, 1); // below the fee
    let c = AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: vec![0u8; 10], // malformed
        r#type: AccountType::Normal as i32,
    };
    assert!(matches!(
        account::validate_create_account(&accounts, &dp, &c),
        Err(ActuatorError::InsufficientBalance { .. })
    ));
}

// =============================================================================
// UpdateSettingContractActuator
// =============================================================================

/// java `UpdateSettingContractActuator.validate` order is
/// address → owner account → percent → contract → contract owner. An unknown
/// owner combined with an out-of-range percent reports the missing account.
#[test]
fn update_setting_checks_owner_before_percent() {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    put_contract(&contracts, CONTRACT, ALICE);
    let c = UpdateSettingContract {
        owner_address: ALICE.to_vec(),
        contract_address: CONTRACT.to_vec(),
        consume_user_resource_percent: 200,
    };
    assert_eq!(
        contract_admin::validate_update_setting(&accounts, &contracts, &c),
        Err(ActuatorError::OwnerAccountMissing)
    );
}

/// …and the percent bound precedes the contract-existence check.
#[test]
fn update_setting_checks_percent_before_contract() {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let c = UpdateSettingContract {
        owner_address: ALICE.to_vec(),
        contract_address: CONTRACT.to_vec(), // no such contract
        consume_user_resource_percent: 101,
    };
    assert_eq!(
        contract_admin::validate_update_setting(&accounts, &contracts, &c),
        Err(ActuatorError::PercentOutOfRange)
    );
}

// =============================================================================
// UpdateEnergyLimitContractActuator
// =============================================================================

/// java `UpdateEnergyLimitContractActuator.validate` order is
/// activation → address → owner account → energy limit → contract → owner.
#[test]
fn update_energy_limit_checks_owner_before_limit() {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_number(10_000_000); // past the activation gate
    put_contract(&contracts, CONTRACT, ALICE);
    let c = UpdateEnergyLimitContract {
        owner_address: ALICE.to_vec(),
        contract_address: CONTRACT.to_vec(),
        origin_energy_limit: 0, // also invalid
    };
    assert_eq!(
        contract_admin::validate_update_energy_limit(&accounts, &contracts, &dp, &c),
        Err(ActuatorError::OwnerAccountMissing)
    );
}

/// …and the limit bound precedes the contract-existence check.
#[test]
fn update_energy_limit_checks_limit_before_contract() {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_number(10_000_000);
    put_account(&accounts, ALICE, 0);
    let c = UpdateEnergyLimitContract {
        owner_address: ALICE.to_vec(),
        contract_address: CONTRACT.to_vec(), // no such contract
        origin_energy_limit: -1,
    };
    assert_eq!(
        contract_admin::validate_update_energy_limit(&accounts, &contracts, &dp, &c),
        Err(ActuatorError::NonPositiveEnergyLimit)
    );
}

// =============================================================================
// WitnessUpdateActuator
// =============================================================================

/// java `WitnessUpdateActuator.validate` order is address → account → url →
/// witness, the reverse of `WitnessCreateActuator`, which validates the url
/// before it reads the account. An unknown account with an empty url reports
/// the missing account.
#[test]
fn witness_update_checks_account_before_url() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let c = WitnessUpdateContract {
        owner_address: ALICE.to_vec(),
        update_url: Vec::new(), // also invalid
    };
    assert_eq!(
        witness::validate_witness_update(&accounts, &witnesses, &c),
        Err(ActuatorError::OwnerAccountMissing)
    );
}

/// `WitnessCreateActuator` keeps the opposite order: the url is rejected
/// before the account lookup runs.
#[test]
fn witness_create_checks_url_before_account() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = tron_proto::WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: Vec::new(), // invalid, and ALICE has no account either
    };
    assert_eq!(
        witness::validate_witness_create(&accounts, &witnesses, &dp, &c),
        Err(ActuatorError::InvalidUrl)
    );
}

// =============================================================================
// UpdateBrokerageActuator
// =============================================================================

/// java `UpdateBrokerageActuator.validate` reads the witness row before the
/// account row, so an address that is neither reports the missing witness.
#[test]
fn update_brokerage_checks_witness_before_account() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_allow_change_delegation(1);
    let c = UpdateBrokerageContract {
        owner_address: ALICE.to_vec(),
        brokerage: 30,
    };
    assert_eq!(
        witness::validate_update_brokerage(&accounts, &witnesses, &dp, &c),
        Err(ActuatorError::WitnessMissing)
    );
}

/// The brokerage bound still precedes both store lookups.
#[test]
fn update_brokerage_checks_range_before_stores() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_allow_change_delegation(1);
    for brokerage in [-1i32, 101] {
        let c = UpdateBrokerageContract {
            owner_address: ALICE.to_vec(),
            brokerage,
        };
        assert_eq!(
            witness::validate_update_brokerage(&accounts, &witnesses, &dp, &c),
            Err(ActuatorError::BrokerageOutOfRange),
            "brokerage={brokerage}"
        );
    }
}

// =============================================================================
// ProposalDeleteActuator
// =============================================================================

/// java `ProposalDeleteActuator.validate` rejects a non-proposer *before* it
/// examines expiry or cancellation. Deleting somebody else's expired proposal
/// is an ownership failure, not an expiry failure.
#[test]
fn proposal_delete_checks_proposer_before_expiry() {
    let accounts = AccountStore::new(mem());
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 0);
    dp.put_long(b"LATEST_PROPOSAL_NUM", 1);
    dp.save_latest_block_header_timestamp(5_000);
    proposals
        .put(
            1,
            &Proposal {
                proposal_id: 1,
                proposer_address: BOB.to_vec(), // not ALICE
                expiration_time: 1_000,         // already expired at now=5_000
                state: tron_proto::proposal::State::Pending as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = ProposalDeleteContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
    };
    assert_eq!(
        proposal::validate_proposal_delete(&accounts, &proposals, &dp, &c),
        Err(ActuatorError::NotProposalOwner)
    );
}

/// …and before the cancellation check, for the same reason.
#[test]
fn proposal_delete_checks_proposer_before_cancelled() {
    let accounts = AccountStore::new(mem());
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 0);
    dp.put_long(b"LATEST_PROPOSAL_NUM", 1);
    dp.save_latest_block_header_timestamp(500);
    proposals
        .put(
            1,
            &Proposal {
                proposal_id: 1,
                proposer_address: BOB.to_vec(),
                expiration_time: 1_000, // still live
                state: tron_proto::proposal::State::Canceled as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = ProposalDeleteContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
    };
    assert_eq!(
        proposal::validate_proposal_delete(&accounts, &proposals, &dp, &c),
        Err(ActuatorError::NotProposalOwner)
    );
}

// =============================================================================
// TransferActuator / TransferAssetActuator
// =============================================================================

/// java `TransferActuator.validate` reads the owner account *before* it bounds
/// the amount: `noExitOwnerAccount` fails as "no OwnerAccount" regardless of
/// the amount carried.
#[test]
fn transfer_checks_owner_account_before_amount() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 0, // also invalid
    };
    assert_eq!(
        transfer::validate_transfer(&accounts, &dp, &c),
        Err(ActuatorError::OwnerAccountMissing)
    );
}

/// Self-transfer still precedes the owner lookup ("Cannot transfer TRX to
/// yourself." is reached without touching the account store).
#[test]
fn transfer_checks_self_transfer_before_owner_account() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: ALICE.to_vec(),
        amount: 0,
    };
    assert_eq!(
        transfer::validate_transfer(&accounts, &dp, &c),
        Err(ActuatorError::SelfTransfer)
    );
}

/// `TransferAssetActuator.validate` inverts the pair: it bounds the amount
/// *before* the self-transfer check, so an owner sending 0 to itself is an
/// amount failure, not a self-transfer failure. This is the opposite of
/// `TransferActuator` above and is easy to normalise away by mistake.
#[test]
fn transfer_asset_checks_amount_before_self_transfer() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = TransferAssetContract {
        owner_address: ALICE.to_vec(),
        to_address: ALICE.to_vec(),
        asset_name: b"1000001".to_vec(),
        amount: 0,
    };
    assert_eq!(
        asset::validate_transfer_asset(&accounts, &dp, &c),
        Err(ActuatorError::NonPositiveAmount)
    );
}

/// Witness rows are irrelevant to the brokerage path once both exist — a
/// sanity anchor so the ordering tests above cannot pass vacuously.
#[test]
fn update_brokerage_accepts_registered_witness_with_account() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_allow_change_delegation(1);
    put_account(&accounts, ALICE, 0);
    witnesses
        .put(
            &addr(ALICE),
            &Witness {
                address: ALICE.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    let c = UpdateBrokerageContract {
        owner_address: ALICE.to_vec(),
        brokerage: 30,
    };
    assert_eq!(
        witness::validate_update_brokerage(&accounts, &witnesses, &dp, &c),
        Ok(())
    );
}
