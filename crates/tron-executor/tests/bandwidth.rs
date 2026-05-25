//! Tests for `bandwidth::consume_bandwidth`.
//!
//! Covers the full priority cascade:
//!
//! 1. `useAssetAccountNet` (TRC-10 transfers w/ issuer-funded quota)
//! 2. `useAccountNet` (frozen quota, global-ratio scaled)
//! 3. `useFreeNet` (daily free quota, with chain-wide PUBLIC_NET cap)
//! 4. `useTransactionFee` (TRX fallback)
//!
//! Plus: insufficient-balance error, missing-account error, decay/window
//! math edge cases, adaptive scaling, public-net accumulator.

use std::sync::Arc;

use hex_literal::hex;
use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AccountStore, AssetIssueStore, AssetIssueV2Store, DynamicPropertiesStore, KvBackend,
    MemBackend,
};
use tron_crypto::address::Address;
use tron_executor::bandwidth::{
    consume_bandwidth, increase, BandwidthCharge, BandwidthError, BandwidthStores,
    DEFAULT_FREE_NET_LIMIT, DEFAULT_TRANSACTION_FEE, WINDOW_SIZE_BLOCKS,
};
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract as TxContract, Raw as TxRaw};
use tron_proto::{
    account::FreezeV2, Account, AssetIssueContract, Transaction, TransferAssetContract,
    TransferContract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const ISSUER: [u8; 21] = hex!("4193df56b9d51e84e90c4d61c4ce80a6fb3e57f5dd");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn put(accounts: &AccountStore, addr: [u8; 21], a: Account) {
    accounts.put(&Address::from_raw(addr), &a);
}

struct Env {
    accounts: AccountStore,
    dyn_props: DynamicPropertiesStore,
    asset_v1: AssetIssueStore,
    asset_v2: AssetIssueV2Store,
}

impl Env {
    fn new() -> Self {
        Self {
            accounts: AccountStore::new(mem()),
            dyn_props: DynamicPropertiesStore::new(mem()),
            asset_v1: AssetIssueStore::new(mem()),
            asset_v2: AssetIssueV2Store::new(mem()),
        }
    }
    fn stores(&self) -> BandwidthStores<'_> {
        BandwidthStores {
            accounts: &self.accounts,
            dyn_props: &self.dyn_props,
            asset_v1: &self.asset_v1,
            asset_v2: &self.asset_v2,
        }
    }
}

fn make_transfer_tx() -> (Transaction, TxContract) {
    let tc = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 100,
    };
    let contract = TxContract {
        r#type: ContractType::TransferContract as i32,
        parameter: Some(Any {
            type_url: "type.googleapis.com/protocol.TransferContract".into(),
            value: tc.encode_to_vec(),
        }),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id: 0,
    };
    let tx = Transaction {
        raw_data: Some(TxRaw {
            ref_block_bytes: vec![0, 1],
            ref_block_num: 0,
            ref_block_hash: vec![0u8; 8],
            expiration: 1_700_000_000_000,
            auths: Vec::new(),
            data: Vec::new(),
            contract: vec![contract.clone()],
            scripts: Vec::new(),
            timestamp: 1_700_000_000_000,
            fee_limit: 0,
        }),
        signature: vec![vec![0xaau8; 65]],
        ret: Vec::new(),
    };
    (tx, contract)
}

fn make_transfer_asset_tx(asset_name: &[u8]) -> (Transaction, TxContract) {
    let tc = TransferAssetContract {
        asset_name: asset_name.to_vec(),
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 50,
    };
    let contract = TxContract {
        r#type: ContractType::TransferAssetContract as i32,
        parameter: Some(Any {
            type_url: "type.googleapis.com/protocol.TransferAssetContract".into(),
            value: tc.encode_to_vec(),
        }),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id: 0,
    };
    let tx = Transaction {
        raw_data: Some(TxRaw {
            ref_block_bytes: vec![0, 1],
            ref_block_num: 0,
            ref_block_hash: vec![0u8; 8],
            expiration: 1_700_000_000_000,
            auths: Vec::new(),
            data: Vec::new(),
            contract: vec![contract.clone()],
            scripts: Vec::new(),
            timestamp: 1_700_000_000_000,
            fee_limit: 0,
        }),
        signature: vec![vec![0xaau8; 65]],
        ret: Vec::new(),
    };
    (tx, contract)
}

// ---------------------------------------------------------------------
// 1. useAccountNet / useFreeNet / useTransactionFee — basic priority
// ---------------------------------------------------------------------

#[test]
fn small_tx_charges_against_free_quota() {
    let env = Env::new();
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 1_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0).expect("ok");
    match outcome {
        BandwidthCharge::Free { bytes, .. } => {
            assert!(bytes > 0 && bytes < DEFAULT_FREE_NET_LIMIT);
        }
        other => panic!("expected Free, got {other:?}"),
    }
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert!(after.free_net_usage > 0);
    assert_eq!(after.balance, 1_000);
    // PUBLIC_NET_USAGE also bumped (chain-wide accumulator).
    assert!(env.dyn_props.public_net_usage() > 0);
}

#[test]
fn account_with_frozen_bandwidth_consumes_frozen_first() {
    let env = Env::new();
    // Frozen bandwidth: 1000 TRX (1_000_000_000 sun) — enough that the
    // global-ratio scaling will produce a non-zero net_limit.
    // We also seed TOTAL_NET_WEIGHT so the V2 formula produces a real cap.
    env.dyn_props.save_total_net_weight(1_000); // 1000 TRX weight
    let mut acct = Account {
        address: ALICE.to_vec(),
        balance: 1_000,
        ..Default::default()
    };
    acct.frozen_v2.push(FreezeV2 {
        r#type: 0,
        amount: 1_000_000_000,
    });
    put(&env.accounts, ALICE, acct);
    // Activate unfreeze-delay so the V2 limit formula kicks in.
    env.dyn_props.save_unfreeze_delay_days(1);
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0).expect("ok");
    assert!(matches!(outcome, BandwidthCharge::Frozen { .. }));
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert!(after.net_usage > 0);
    // Free quota untouched.
    assert_eq!(after.free_net_usage, 0);
}

#[test]
fn free_quota_exhaustion_falls_back_to_trx_fee() {
    let env = Env::new();
    env.dyn_props.put_long(b"FREE_NET_LIMIT", 1);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 10_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0).expect("ok");
    let (charged_bytes, fee) = match outcome {
        BandwidthCharge::Fee { bytes, fee_sun } => (bytes, fee_sun),
        other => panic!("expected Fee, got {other:?}"),
    };
    assert!(charged_bytes > 0);
    assert_eq!(fee, charged_bytes * DEFAULT_TRANSACTION_FEE);
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 10_000_000 - fee);
    assert_eq!(env.dyn_props.get_long(b"BURN_TRX_AMOUNT").unwrap(), fee);
    assert_eq!(env.dyn_props.get_long(b"TOTAL_TRANSACTION_COST").unwrap(), fee);
}

#[test]
fn insufficient_balance_for_fee_returns_error() {
    let env = Env::new();
    env.dyn_props.put_long(b"FREE_NET_LIMIT", 1);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 5, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let err = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0)
        .unwrap_err();
    assert!(matches!(err, BandwidthError::Insufficient { .. }));
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 5);
}

#[test]
fn missing_account_yields_error() {
    let env = Env::new();
    let (tx, contract) = make_transfer_tx();
    let err = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0)
        .unwrap_err();
    assert!(matches!(err, BandwidthError::AccountMissing));
}

// ---------------------------------------------------------------------
// 2. useAssetAccountNet — TRC-10 issuer-funded path
// ---------------------------------------------------------------------

const TOKEN_ID: i64 = 1_000_001;
const TOKEN_NAME: &[u8] = b"TestTok";

fn seed_asset(env: &Env, public_limit: i64, free_limit: i64) {
    let asset = AssetIssueContract {
        id: TOKEN_ID.to_string(),
        owner_address: ISSUER.to_vec(),
        name: TOKEN_NAME.to_vec(),
        free_asset_net_limit: free_limit,
        public_free_asset_net_limit: public_limit,
        public_free_asset_net_usage: 0,
        public_latest_free_net_time: 0,
        ..Default::default()
    };
    env.asset_v2.put(TOKEN_ID, &asset);
    env.asset_v1.put(TOKEN_NAME, &asset);

    // Issuer needs frozen bandwidth so the global-net check can pass.
    env.dyn_props.save_total_net_weight(10_000);
    env.dyn_props.save_unfreeze_delay_days(1);
    let mut issuer_acct = Account {
        address: ISSUER.to_vec(),
        balance: 0,
        ..Default::default()
    };
    issuer_acct.frozen_v2.push(FreezeV2 {
        r#type: 0,
        amount: 10_000_000_000, // 10_000 TRX
    });
    put(&env.accounts, ISSUER, issuer_acct);
}

#[test]
fn transfer_asset_uses_issuer_quota_when_funded() {
    let env = Env::new();
    // V1 mode (allow_same_token_name == 0): asset_name is the token name bytes.
    seed_asset(&env, /*public_limit=*/ 1_000_000, /*free_limit=*/ 1_000_000);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 0, ..Default::default() },
    );
    let (tx, contract) = make_transfer_asset_tx(TOKEN_NAME);
    let outcome = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0)
        .expect("ok");
    let charged = match outcome {
        BandwidthCharge::AssetIssuer { bytes, token_id, .. } => {
            assert_eq!(token_id, TOKEN_ID);
            bytes
        }
        other => panic!("expected AssetIssuer, got {other:?}"),
    };
    assert!(charged > 0);

    // Asset row got its public_free_asset_net_usage bumped.
    let asset_v2 = env.asset_v2.get(TOKEN_ID).unwrap().unwrap();
    assert!(asset_v2.public_free_asset_net_usage > 0);
    assert_eq!(asset_v2.public_latest_free_net_time, 0);

    // Issuer's net_usage bumped.
    let issuer = env.accounts.get(&Address::from_raw(ISSUER)).unwrap().unwrap();
    assert!(issuer.net_usage > 0);

    // Sender's per-asset map populated.
    let alice = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert!(alice
        .free_asset_net_usage_v2
        .get(&TOKEN_ID.to_string())
        .copied()
        .unwrap_or(0)
        > 0);
}

#[test]
fn transfer_asset_falls_through_when_public_quota_exhausted() {
    let env = Env::new();
    // public_free_asset_net_limit=1 ⇒ even a tiny tx busts it.
    seed_asset(&env, /*public_limit=*/ 1, /*free_limit=*/ 1_000_000);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 100_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_asset_tx(TOKEN_NAME);
    let outcome = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0)
        .expect("ok");
    // The issuer path fell through; the tx ended up on either the free
    // quota (Alice has none used) or the TRX fee (if free is full).
    assert!(
        matches!(outcome, BandwidthCharge::Free { .. }) || matches!(outcome, BandwidthCharge::Fee { .. }),
        "expected Free or Fee, got {outcome:?}"
    );
}

#[test]
fn transfer_asset_falls_through_when_issuer_net_insufficient() {
    let env = Env::new();
    seed_asset(&env, /*public_limit=*/ 1_000_000, /*free_limit=*/ 1_000_000);
    // Zero out the issuer's frozen bandwidth.
    let mut issuer_acct = env.accounts.get(&Address::from_raw(ISSUER)).unwrap().unwrap();
    issuer_acct.frozen_v2.clear();
    env.accounts.put(&Address::from_raw(ISSUER), &issuer_acct);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 100_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_asset_tx(TOKEN_NAME);
    let outcome = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0)
        .expect("ok");
    assert!(
        matches!(outcome, BandwidthCharge::Free { .. }) || matches!(outcome, BandwidthCharge::Fee { .. }),
        "expected fallthrough, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------
// 3. Public-net accumulator + adaptive global-limit
// ---------------------------------------------------------------------

#[test]
fn public_net_accumulator_blocks_free_quota_when_exhausted() {
    let env = Env::new();
    // Pre-set PUBLIC_NET_USAGE near the limit so the next tx is rejected
    // from the free path → falls to TRX fee.
    env.dyn_props.save_public_net_limit(100);
    env.dyn_props.save_public_net_usage(100); // already at cap
    env.dyn_props.save_public_net_time(0);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 10_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0).expect("ok");
    assert!(
        matches!(outcome, BandwidthCharge::Fee { .. }),
        "expected fee, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------
// 4. Windowed-average math (kept from the old test file, updated to
//    match the hardened-arithmetic semantics).
// ---------------------------------------------------------------------

#[test]
fn increase_decays_to_zero_after_a_full_window() {
    let v = increase(1_000_000, 0, 0, WINDOW_SIZE_BLOCKS);
    assert_eq!(v, 0);
    let v2 = increase(1_000_000, 0, 0, WINDOW_SIZE_BLOCKS + 1);
    assert_eq!(v2, 0);
}

#[test]
fn increase_partial_window_keeps_some_usage() {
    let half = WINDOW_SIZE_BLOCKS / 2;
    let v = increase(1_000_000, 0, 0, half);
    assert!(v > 0 && v < 1_000_000, "got {v}");
}

#[test]
fn increase_adds_new_usage_immediately() {
    // Same slot — no decay, just adds. java-tron's hardened math
    // truncates the final result: 500 * 1M / 28_800 then * 28_800 / 1M
    // collapses to roughly 499.
    let v = increase(0, 500, 0, 0);
    assert!((499..=500).contains(&v), "got {v}");
}
