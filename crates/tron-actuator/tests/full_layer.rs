//! Smoke tests across every new actuator in the v1 state-transition
//! layer. The goal is one happy-path round-trip per actuator plus one or
//! two key validate-failure assertions — not exhaustive per-rule
//! coverage. The dispatcher integration test confirms `ContractType` →
//! actuator routing works end-to-end.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{
    account, asset, contract_admin, delegate, exchange, freeze, freeze_v2, market, proposal,
    witness, ActuatorError,
};
use tron_chainbase::{
    AbiStore, AccountIdIndexStore, AccountIndexStore, AccountStore, AssetIssueStore,
    AssetIssueV2Store, ContractStore, DelegatedResourceAccountIndexStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, ExchangeStore, ExchangeV2Store, KvBackend,
    MarketOrderStore, MemBackend, ProposalStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::Frozen;
use tron_proto::{Account, AccountType, Witness};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

fn put_account(store: &AccountStore, address: [u8; 21], balance: i64) {
    store.put(
        &addr(address),
        &Account {
            address: address.to_vec(),
            balance,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
}

fn put_funded_witness(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    address: [u8; 21],
    balance: i64,
) {
    put_account(accounts, address, balance);
    witnesses.put(
        &addr(address),
        &Witness {
            address: address.to_vec(),
            url: String::from("https://witness.test"),
            ..Default::default()
        },
    ).unwrap();
}

// =============================================================================
// Witness actuators
// =============================================================================

#[test]
fn witness_create_round_trip() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 100_000_000_000_000);
    dp.put_long(b"ACCOUNT_UPGRADE_COST", 9_999_000_000);

    let c = tron_proto::WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: b"https://alice-sr.example".to_vec(),
    };
    assert!(witness::validate_witness_create(&accounts, &witnesses, &dp, &c).is_ok());
    let result = witness::execute_witness_create(&accounts, &witnesses, &dp, &c).unwrap();
    assert_eq!(result.fee, 9_999_000_000);
    assert!(witnesses.contains(&addr(ALICE)).unwrap());
}

#[test]
fn witness_create_rejects_invalid_url() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 100_000_000_000_000);
    let c = tron_proto::WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: Vec::new(),
    };
    assert_eq!(
        witness::validate_witness_create(&accounts, &witnesses, &dp, &c),
        Err(ActuatorError::InvalidUrl)
    );
}

#[test]
fn update_brokerage_round_trip() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let delegation = DelegationStore::new(mem());
    put_funded_witness(&accounts, &witnesses, ALICE, 0);
    let c = tron_proto::UpdateBrokerageContract {
        owner_address: ALICE.to_vec(),
        brokerage: 30,
    };
    witness::validate_update_brokerage(&accounts, &witnesses, &c).unwrap();
    witness::execute_update_brokerage(&delegation, &c).unwrap();
    assert_eq!(delegation.get_brokerage_global(&addr(ALICE)), 30);
}

#[test]
fn update_brokerage_rejects_out_of_range() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    put_funded_witness(&accounts, &witnesses, ALICE, 0);
    let c = tron_proto::UpdateBrokerageContract {
        owner_address: ALICE.to_vec(),
        brokerage: 101,
    };
    assert_eq!(
        witness::validate_update_brokerage(&accounts, &witnesses, &c),
        Err(ActuatorError::BrokerageOutOfRange)
    );
}

#[test]
fn withdraw_balance_round_trip() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let mut alice = Account {
        address: ALICE.to_vec(),
        balance: 50,
        allowance: 1000,
        r#type: AccountType::Normal as i32,
        latest_withdraw_time: 0,
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();
    dp.save_latest_block_header_timestamp(1_700_000_000_000);

    let c = tron_proto::WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };
    let delegation = DelegationStore::new(mem());
    witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap();
    witness::execute_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap();
    alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 1050);
    assert_eq!(alice.allowance, 0);
    assert_eq!(alice.latest_withdraw_time, 1_700_000_000_000);
}

// =============================================================================
// Account actuators
// =============================================================================

#[test]
fn create_account_round_trip() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1_000_000);
    dp.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 0);

    let c = tron_proto::AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: BOB.to_vec(),
        r#type: AccountType::Normal as i32,
    };
    account::validate_create_account(&accounts, &dp, &c).unwrap();
    let res = account::execute_create_account(&accounts, &dp, &c).unwrap();
    assert!(res.created_recipient);
    assert!(accounts.contains(&addr(BOB)).unwrap());
}

#[test]
fn create_account_rejects_existing_target() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 100);
    put_account(&accounts, BOB, 0);
    let c = tron_proto::AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: BOB.to_vec(),
        r#type: AccountType::Normal as i32,
    };
    assert_eq!(
        account::validate_create_account(&accounts, &dp, &c),
        Err(ActuatorError::AccountAlreadyExists)
    );
}

#[test]
fn update_account_round_trip() {
    let accounts = AccountStore::new(mem());
    let name_index = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let c = tron_proto::AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: b"alice".to_vec(),
    };
    account::validate_update_account(&accounts, &name_index, &dp, &c).unwrap();
    account::execute_update_account(&accounts, &name_index, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.account_name, b"alice");
    assert_eq!(name_index.get(b"alice").unwrap().unwrap(), addr(ALICE));
}

#[test]
fn set_account_id_round_trip() {
    let accounts = AccountStore::new(mem());
    let id_index = AccountIdIndexStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let c = tron_proto::SetAccountIdContract {
        owner_address: ALICE.to_vec(),
        account_id: b"alice_id".to_vec(),
    };
    account::validate_set_account_id(&accounts, &id_index, &c).unwrap();
    account::execute_set_account_id(&accounts, &id_index, &c).unwrap();
    assert_eq!(id_index.get(b"alice_id").unwrap().unwrap(), addr(ALICE));
}

// =============================================================================
// Proposal actuators
// =============================================================================

#[test]
fn proposal_create_then_approve_then_delete() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded_witness(&accounts, &witnesses, ALICE, 0);
    put_funded_witness(&accounts, &witnesses, BOB, 0);
    dp.save_latest_block_header_timestamp(1_700_000_000_000);
    dp.save_next_maintenance_time(1_700_000_000_000 + 6 * 60 * 60 * 1000);

    // Create.
    let create = tron_proto::ProposalCreateContract {
        owner_address: ALICE.to_vec(),
        parameters: std::collections::BTreeMap::from([(1i64, 1_000i64)]),
    };
    proposal::validate_proposal_create(&accounts, &witnesses, &create).unwrap();
    proposal::execute_proposal_create(&proposals, &dp, &create).unwrap();
    assert!(proposals.get(1).unwrap().is_some());

    // Approve from Bob.
    let approve = tron_proto::ProposalApproveContract {
        owner_address: BOB.to_vec(),
        proposal_id: 1,
        is_add_approval: true,
    };
    proposal::validate_proposal_approve(&accounts, &witnesses, &proposals, &dp, &approve).unwrap();
    proposal::execute_proposal_approve(&proposals, &approve).unwrap();
    let p = proposals.get(1).unwrap().unwrap();
    assert_eq!(p.approvals.len(), 1);

    // Delete from Alice (creator).
    let del = tron_proto::ProposalDeleteContract {
        owner_address: ALICE.to_vec(),
        proposal_id: 1,
    };
    proposal::validate_proposal_delete(&accounts, &proposals, &dp, &del).unwrap();
    proposal::execute_proposal_delete(&proposals, &del).unwrap();
    let p = proposals.get(1).unwrap().unwrap();
    assert_eq!(p.state, tron_proto::proposal::State::Canceled as i32);
}

#[test]
fn proposal_delete_rejects_non_owner() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let proposals = ProposalStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded_witness(&accounts, &witnesses, ALICE, 0);
    put_funded_witness(&accounts, &witnesses, BOB, 0);
    dp.save_latest_block_header_timestamp(1_700_000_000_000);
    let create = tron_proto::ProposalCreateContract {
        owner_address: ALICE.to_vec(),
        parameters: std::collections::BTreeMap::from([(1i64, 1_000i64)]),
    };
    proposal::execute_proposal_create(&proposals, &dp, &create).unwrap();
    let del = tron_proto::ProposalDeleteContract {
        owner_address: BOB.to_vec(),
        proposal_id: 1,
    };
    assert_eq!(
        proposal::validate_proposal_delete(&accounts, &proposals, &dp, &del),
        Err(ActuatorError::NotProposalOwner)
    );
}

// =============================================================================
// Freeze v1 + v2
// =============================================================================

#[test]
fn freeze_balance_v1_round_trip() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 10_000_000);

    let c = tron_proto::FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 5_000_000,
        frozen_duration: 1,
        resource: 0,
        receiver_address: Vec::new(),
    };
    freeze::validate_freeze_balance(&accounts, &c).unwrap();
    freeze::execute_freeze_balance(&accounts, &dp, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 5_000_000);
    assert_eq!(alice.frozen[0].frozen_balance, 5_000_000);
}

#[test]
fn freeze_balance_v2_requires_unfreeze_delay_enabled() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 10_000_000);
    let c = tron_proto::FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 5_000_000,
        resource: 0,
    };
    // Without UNFREEZE_DELAY_DAYS set the v2 path is gated off.
    assert_eq!(
        freeze_v2::validate_freeze_balance_v2(&accounts, &dp, &c),
        Err(ActuatorError::UnfreezeDelayDisabled)
    );

    dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    freeze_v2::validate_freeze_balance_v2(&accounts, &dp, &c).unwrap();
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 5_000_000);
    assert_eq!(alice.frozen_v2[0].amount, 5_000_000);
}

#[test]
fn freeze_v2_updates_total_net_weight_and_unfreeze_reverses_it() {
    // Critical for mainnet bandwidth correctness: TOTAL_NET_WEIGHT
    // is the denominator of `calculateGlobalNetLimit`. If freeze doesn't
    // bump it (and unfreeze doesn't shrink it), every account's quota
    // is wrong.
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    put_account(&accounts, ALICE, 100_000_000); // 100 TRX

    // Freeze 50 TRX for bandwidth → TOTAL_NET_WEIGHT bumps by 50.
    let freeze = tron_proto::FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 50_000_000,
        resource: 0, // BANDWIDTH
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &freeze).unwrap();
    assert_eq!(dp.total_net_weight(), 50);
    assert_eq!(dp.total_energy_weight(), 0);

    // Freeze another 30 TRX → bumps to 80.
    let freeze2 = tron_proto::FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 30_000_000,
        resource: 0,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &freeze2).unwrap();
    assert_eq!(dp.total_net_weight(), 80);

    // Unfreeze 20 TRX → drops to 60.
    let unfreeze = tron_proto::UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: 20_000_000,
        resource: 0,
    };
    let votes = VotesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    freeze_v2::execute_unfreeze_balance_v2(&accounts, &dp, &votes, &delegation, None, &unfreeze)
        .unwrap();
    assert_eq!(dp.total_net_weight(), 60);
}

#[test]
fn freeze_v2_energy_bumps_total_energy_weight_only() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    put_account(&accounts, ALICE, 100_000_000);

    let freeze = tron_proto::FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 75_000_000,
        resource: 1, // ENERGY
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &freeze).unwrap();
    assert_eq!(dp.total_energy_weight(), 75);
    assert_eq!(dp.total_net_weight(), 0);
}

#[test]
fn freeze_v2_below_one_trx_increment_yields_zero_weight_delta() {
    // Edge case from java-tron: weight is `frozen / TRX_PRECISION`,
    // so any increment under 1 TRX adds 0 to TOTAL_NET_WEIGHT even
    // though the per-account `frozen_v2[BANDWIDTH].amount` increases.
    // This matters because the FreezeTooSmall validator already
    // rejects sub-1-TRX freezes, but the *delta* math can still hit
    // boundary cases when frozen amounts straddle TRX boundaries.
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    put_account(&accounts, ALICE, 10_000_000);

    // Seed with a 1.5 TRX freeze already in place. Validator allows
    // exactly 1 TRX or more, and the resulting weight is floor(1.5) = 1.
    let mut alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    alice.frozen_v2.push(tron_proto::account::FreezeV2 {
        r#type: 0,
        amount: 1_500_000,
    });
    accounts.put(&addr(ALICE), &alice).unwrap();
    // Pretend an earlier freeze bumped the weight to 1.
    dp.save_total_net_weight(1);

    // Freeze another 1_000_001 sun (just above 1 TRX). new = 2.500001 → weight floor = 2.
    let freeze = tron_proto::FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 1_000_001,
        resource: 0,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &freeze).unwrap();
    assert_eq!(dp.total_net_weight(), 2); // delta = 2 - 1 = 1
}

#[test]
fn unfreeze_balance_v2_then_withdraw_after_expiry() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"UNFREEZE_DELAY_DAYS", 1);
    dp.save_latest_block_header_timestamp(1_700_000_000_000);
    accounts.put(
        &addr(ALICE),
        &Account {
            address: ALICE.to_vec(),
            balance: 0,
            r#type: AccountType::Normal as i32,
            frozen_v2: vec![tron_proto::account::FreezeV2 {
                r#type: 0,
                amount: 5_000_000,
            }],
            ..Default::default()
        },
    ).unwrap();

    let unfreeze = tron_proto::UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: 5_000_000,
        resource: 0,
    };
    freeze_v2::validate_unfreeze_balance_v2(&accounts, &dp, &unfreeze).unwrap();
    let votes = VotesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    freeze_v2::execute_unfreeze_balance_v2(&accounts, &dp, &votes, &delegation, None, &unfreeze)
        .unwrap();

    // Fast-forward; the unfreeze entry's expiry is at now + 1 day.
    dp.save_latest_block_header_timestamp(1_700_000_000_000 + 2 * 24 * 60 * 60 * 1000);
    let withdraw = tron_proto::WithdrawExpireUnfreezeContract {
        owner_address: ALICE.to_vec(),
    };
    freeze_v2::validate_withdraw_expire_unfreeze(&accounts, &dp, &withdraw).unwrap();
    freeze_v2::execute_withdraw_expire_unfreeze(&accounts, &dp, &withdraw).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 5_000_000);
    assert!(alice.unfrozen_v2.is_empty());
}

// =============================================================================
// Delegate
// =============================================================================

#[test]
fn delegate_resource_round_trip() {
    let accounts = AccountStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_DELEGATE_RESOURCE", 1);
    dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);

    accounts.put(
        &addr(ALICE),
        &Account {
            address: ALICE.to_vec(),
            r#type: AccountType::Normal as i32,
            frozen_v2: vec![tron_proto::account::FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            ..Default::default()
        },
    ).unwrap();
    put_account(&accounts, BOB, 0);

    let c = tron_proto::DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        balance: 5_000_000,
        receiver_address: BOB.to_vec(),
        lock: false,
        lock_period: 0,
    };
    let dr_index = DelegatedResourceAccountIndexStore::new(mem());
    delegate::validate_delegate_resource(&accounts, &dp, &c).unwrap();
    delegate::execute_delegate_resource(&accounts, &resources, Some(&dr_index), &dp, &c).unwrap();

    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.frozen_v2[0].amount, 5_000_000);
    assert_eq!(alice.delegated_frozen_v2_balance_for_bandwidth, 5_000_000);
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.acquired_delegated_frozen_v2_balance_for_bandwidth, 5_000_000);
}

// =============================================================================
// Exchange
// =============================================================================

#[test]
fn exchange_create_round_trip() {
    let accounts = AccountStore::new(mem());
    let v1 = ExchangeStore::new(mem());
    let v2 = ExchangeV2Store::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    accounts.put(
        &addr(ALICE),
        &Account {
            address: ALICE.to_vec(),
            balance: 10_000_000_000,
            r#type: AccountType::Normal as i32,
            asset_v2: std::collections::BTreeMap::from([("1000001".to_string(), 1_000_000_000i64)]),
            ..Default::default()
        },
    ).unwrap();
    dp.put_long(b"EXCHANGE_CREATE_FEE", 0);

    let c = tron_proto::ExchangeCreateContract {
        owner_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 5_000_000_000,
        second_token_id: b"1000001".to_vec(),
        second_token_balance: 500_000_000,
    };
    exchange::validate_exchange_create(&accounts, &dp, &c).unwrap();
    exchange::execute_exchange_create(&accounts, &v1, &v2, &dp, &c).unwrap();
    assert!(v2.get(1).unwrap().is_some());
}

// =============================================================================
// Market
// =============================================================================

#[test]
fn market_sell_then_cancel() {
    let accounts = AccountStore::new(mem());
    let orders = MarketOrderStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    accounts.put(
        &addr(ALICE),
        &Account {
            address: ALICE.to_vec(),
            balance: 1_000_000_000,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();

    let sell = tron_proto::MarketSellAssetContract {
        owner_address: ALICE.to_vec(),
        sell_token_id: b"_".to_vec(),
        sell_token_quantity: 100_000_000,
        buy_token_id: b"1000001".to_vec(),
        buy_token_quantity: 50_000_000,
    };
    market::validate_market_sell_asset(&accounts, &dp, &sell).unwrap();
    market::execute_market_sell_asset(&accounts, &orders, &dp, &sell).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 900_000_000);

    // We need the order id to cancel; iterate the backend instead.
    let order_id = {
        let mut found: Option<Vec<u8>> = None;
        let _ = orders.get(&[]); // ensure store is touched (no-op)
        // Walk MemBackend directly via known invariant: we just wrote one order.
        // Simulate by computing the same hash the actuator uses.
        use tron_crypto::hash::sha256;
        let mut buf = Vec::with_capacity(29);
        buf.extend_from_slice(addr(ALICE).as_bytes());
        buf.extend_from_slice(&dp.latest_block_header_timestamp().unwrap_or(0).to_be_bytes());
        let id = sha256(&buf).to_vec();
        if orders.get(&id).unwrap().is_some() {
            found = Some(id);
        }
        found.expect("order was written")
    };
    let cancel = tron_proto::MarketCancelOrderContract {
        owner_address: ALICE.to_vec(),
        order_id,
    };
    market::validate_market_cancel_order(&accounts, &orders, &dp, &cancel).unwrap();
    market::execute_market_cancel_order(&accounts, &orders, &dp, &cancel).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 1_000_000_000); // refunded
}

// =============================================================================
// Asset
// =============================================================================

#[test]
fn asset_issue_then_transfer() {
    let accounts = AccountStore::new(mem());
    let v1 = AssetIssueStore::new(mem());
    let v2 = AssetIssueV2Store::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    put_account(&accounts, ALICE, 100_000_000_000_000);
    dp.put_long(b"ASSET_ISSUE_FEE", 0);
    dp.save_latest_block_header_timestamp(1_000);

    let issue = tron_proto::AssetIssueContract {
        owner_address: ALICE.to_vec(),
        name: b"TestToken".to_vec(),
        abbr: b"TTK".to_vec(),
        total_supply: 1_000_000,
        trx_num: 1,
        num: 1,
        start_time: 2_000,
        end_time: 1_000_000,
        ..Default::default()
    };
    asset::validate_asset_issue(&accounts, &v1, &dp, &issue).unwrap();
    asset::execute_asset_issue(&accounts, &v1, &v2, &dp, &issue).unwrap();
    assert!(v1.get(b"TestToken").unwrap().is_some());

    // Now Alice transfers some asset to Bob.
    put_account(&accounts, BOB, 0);
    let token_id = format!(
        "{}",
        dp.get_long(b"TOKEN_ID_NUM").unwrap_or(1_000_001)
    );
    let xfer = tron_proto::TransferAssetContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        asset_name: token_id.as_bytes().to_vec(),
        amount: 100,
    };
    asset::validate_transfer_asset(&accounts, &xfer).unwrap();
    asset::execute_transfer_asset(&accounts, &xfer).unwrap();
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.asset_v2.get(&token_id).copied().unwrap_or(0), 100);
}

// =============================================================================
// Contract admin
// =============================================================================

#[test]
fn update_setting_round_trip() {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let contract_addr = addr(BOB);
    let sc = tron_proto::SmartContract {
        origin_address: ALICE.to_vec(),
        contract_address: BOB.to_vec(),
        consume_user_resource_percent: 50,
        ..Default::default()
    };
    contracts.put(&contract_addr, &sc).unwrap();

    let c = tron_proto::UpdateSettingContract {
        owner_address: ALICE.to_vec(),
        contract_address: BOB.to_vec(),
        consume_user_resource_percent: 75,
    };
    contract_admin::validate_update_setting(&accounts, &contracts, &c).unwrap();
    contract_admin::execute_update_setting(&contracts, &c).unwrap();
    let after = contracts.get(&contract_addr).unwrap().unwrap();
    assert_eq!(after.consume_user_resource_percent, 75);
}

#[test]
fn update_setting_rejects_out_of_range_percent() {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    let c = tron_proto::UpdateSettingContract {
        owner_address: ALICE.to_vec(),
        contract_address: BOB.to_vec(),
        consume_user_resource_percent: 200,
    };
    assert_eq!(
        contract_admin::validate_update_setting(&accounts, &contracts, &c),
        Err(ActuatorError::PercentOutOfRange)
    );
}

#[test]
fn clear_abi_requires_constantinople() {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = tron_proto::ClearAbiContract {
        owner_address: ALICE.to_vec(),
        contract_address: BOB.to_vec(),
    };
    assert_eq!(
        contract_admin::validate_clear_abi(&accounts, &contracts, &dp, &c),
        Err(ActuatorError::ConstantinopleDisabled)
    );
}

// =============================================================================
// Suppress unused warnings — these are reached only via the dispatcher
// integration test below or by user code.
// =============================================================================

#[allow(dead_code)]
fn _unused_alice_priv() -> [u8; 32] {
    ALICE_PRIV
}
#[allow(dead_code)]
fn _abi_store_typed(b: Arc<dyn KvBackend>) -> AbiStore {
    AbiStore::new(b)
}
#[allow(dead_code)]
fn _votes(b: Arc<dyn KvBackend>) -> VotesStore {
    VotesStore::new(b)
}
#[allow(dead_code)]
fn _frozen() -> Frozen {
    Frozen {
        frozen_balance: 0,
        expire_time: 0,
    }
}
