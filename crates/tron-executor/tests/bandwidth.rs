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
    accounts.put(&Address::from_raw(addr), &a).unwrap();
}

struct Env {
    accounts: AccountStore,
    dyn_props: DynamicPropertiesStore,
    asset_v1: AssetIssueStore,
    asset_v2: AssetIssueV2Store,
}

/// Seed the destination account: a transfer to a MISSING account takes
/// java's `contractCreateNewAccount` branch (tested separately below),
/// so every test of the ordinary cascade needs the recipient to exist.
fn seed_recipient(env: &Env) {
    put(
        &env.accounts,
        BOB,
        Account { address: BOB.to_vec(), balance: 1, ..Default::default() },
    );
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
        unparsed_field10: None,
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
        unparsed_field10: None,
    };
    (tx, contract)
}

// ---------------------------------------------------------------------
// 1. useAccountNet / useFreeNet / useTransactionFee — basic priority
// ---------------------------------------------------------------------

#[test]
fn small_tx_charges_against_free_quota() {
    let env = Env::new();
    seed_recipient(&env);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 1_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None).expect("ok");
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
fn original_wire_size_adds_dropped_bytes_to_the_charge() {
    use prost::Message;
    let (tx, contract) = make_transfer_tx();
    let owner = Address::from_raw(ALICE);
    // 2 non-canonical Transaction-level bytes prost drops but java counts (#9).
    let original = tx.encoded_len() as i64 + 2;

    let env_a = Env::new();
    seed_recipient(&env_a);
    put(
        &env_a.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 1_000, ..Default::default() },
    );
    let baseline = match consume_bandwidth(env_a.stores(), &tx, &contract, &owner, 0, None).expect("ok") {
        BandwidthCharge::Free { bytes, .. } => bytes,
        other => panic!("expected Free, got {other:?}"),
    };

    let env_b = Env::new();
    seed_recipient(&env_b);
    put(
        &env_b.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 1_000, ..Default::default() },
    );
    let bumped =
        match consume_bandwidth(env_b.stores(), &tx, &contract, &owner, 0, Some(original)).expect("ok") {
            BandwidthCharge::Free { bytes, .. } => bytes,
            other => panic!("expected Free, got {other:?}"),
        };

    // The 2 dropped wire bytes are added back: java's getSerializedSize, not
    // prost's canonical encoded_len. A `None` original size keeps prost's size.
    assert_eq!(bumped, baseline + 2);
}

#[test]
fn account_with_frozen_bandwidth_consumes_frozen_first() {
    let env = Env::new();
    seed_recipient(&env);
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
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None).expect("ok");
    assert!(matches!(outcome, BandwidthCharge::Frozen { .. }));
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert!(after.net_usage > 0);
    // Free quota untouched.
    assert_eq!(after.free_net_usage, 0);
}

#[test]
fn free_quota_exhaustion_falls_back_to_trx_fee() {
    let env = Env::new();
    seed_recipient(&env);
    env.dyn_props.put_long(b"FREE_NET_LIMIT", 1);
    // Post-#49 mainnet era: the bandwidth fee is burned (pre-#49 blackhole-
    // account credit is covered by chainbase's fee unit tests).
    env.dyn_props.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 10_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None).expect("ok");
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
    seed_recipient(&env);
    env.dyn_props.put_long(b"FREE_NET_LIMIT", 1);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 5, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let err = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None)
        .unwrap_err();
    assert!(matches!(err, BandwidthError::Insufficient { .. }));
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 5);
}

#[test]
fn missing_account_yields_error() {
    let env = Env::new();
    let (tx, contract) = make_transfer_tx();
    let err = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None)
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
    env.asset_v2.put(TOKEN_ID, &asset).unwrap();
    env.asset_v1.put(TOKEN_NAME, &asset).unwrap();

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
    seed_recipient(&env);
    // V1 mode (allow_same_token_name == 0): asset_name is the token name bytes.
    seed_asset(&env, /*public_limit=*/ 1_000_000, /*free_limit=*/ 1_000_000);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 0, ..Default::default() },
    );
    let (tx, contract) = make_transfer_asset_tx(TOKEN_NAME);
    let outcome = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None)
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
    seed_recipient(&env);
    // public_free_asset_net_limit=1 ⇒ even a tiny tx busts it.
    seed_asset(&env, /*public_limit=*/ 1, /*free_limit=*/ 1_000_000);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 100_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_asset_tx(TOKEN_NAME);
    let outcome = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None)
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
    seed_recipient(&env);
    seed_asset(&env, /*public_limit=*/ 1_000_000, /*free_limit=*/ 1_000_000);
    // Zero out the issuer's frozen bandwidth.
    let mut issuer_acct = env.accounts.get(&Address::from_raw(ISSUER)).unwrap().unwrap();
    issuer_acct.frozen_v2.clear();
    env.accounts.put(&Address::from_raw(ISSUER), &issuer_acct).unwrap();
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 100_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_asset_tx(TOKEN_NAME);
    let outcome = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None)
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
    seed_recipient(&env);
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
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None).expect("ok");
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

// ---------------------------------------------------------------------
// 5. contractCreateNewAccount — the special new-account charge
// ---------------------------------------------------------------------

#[test]
fn transfer_to_missing_account_burns_the_flat_create_fee() {
    let env = Env::new();
    // Post-#49 mainnet era: the flat create fee is burned (pre-#49 blackhole-
    // account credit is covered by chainbase's fee unit tests).
    env.dyn_props.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
    // BOB deliberately absent; ALICE has balance but no frozen net.
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 10_000_000, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None).expect("ok");
    let fee = match outcome {
        BandwidthCharge::CreateNewAccountFee { fee_sun } => fee_sun,
        other => panic!("expected CreateNewAccountFee, got {other:?}"),
    };
    assert_eq!(fee, 100_000, "DEFAULT_CREATE_ACCOUNT_FEE = 0.1 TRX");
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 10_000_000 - fee);
    // Free quota untouched — the create branch never falls through to it.
    assert_eq!(after.free_net_usage, 0);
    assert_eq!(env.dyn_props.get_long(b"BURN_TRX_AMOUNT").unwrap(), fee);
    assert_eq!(env.dyn_props.get_long(b"TOTAL_CREATE_ACCOUNT_COST").unwrap(), fee);
}

#[test]
fn transfer_to_missing_account_uses_frozen_net_at_the_new_account_rate() {
    let env = Env::new();
    env.dyn_props.save_total_net_weight(1_000);
    env.dyn_props.save_unfreeze_delay_days(1);
    let mut acct = Account { address: ALICE.to_vec(), balance: 1_000, ..Default::default() };
    acct.frozen_v2.push(FreezeV2 { r#type: 0, amount: 1_000_000_000 });
    put(&env.accounts, ALICE, acct);
    let (tx, contract) = make_transfer_tx();
    let outcome =
        consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None).expect("ok");
    match outcome {
        BandwidthCharge::CreateNewAccountFrozen { net_cost, new_net_usage } => {
            // Default createNewAccountBandwidthRate = 1 → cost == bytes.
            assert!(net_cost > 0);
            assert!(new_net_usage > 0);
        }
        other => panic!("expected CreateNewAccountFrozen, got {other:?}"),
    }
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert!(after.net_usage > 0);
    assert_eq!(after.balance, 1_000, "no TRX debit when frozen covers it");
}

#[test]
fn create_branch_with_nothing_to_pay_is_a_hard_error() {
    let env = Env::new();
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 5, ..Default::default() },
    );
    let (tx, contract) = make_transfer_tx();
    let err = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None)
        .unwrap_err();
    assert!(matches!(err, BandwidthError::InsufficientForNewAccount { .. }), "got {err:?}");
}

// ---------------------------------------------------------------------
// 6. supportVM byte accounting — the MAX_RESULT_SIZE_IN_TX padding
// ---------------------------------------------------------------------

#[test]
fn support_vm_pads_the_charged_bytes_by_max_result_size() {
    let bytes_with_flag = |vm: bool| -> i64 {
        let env = Env::new();
        seed_recipient(&env);
        if vm {
            env.dyn_props.put_long(b"ALLOW_CREATION_OF_CONTRACTS", 1);
        }
        put(
            &env.accounts,
            ALICE,
            Account { address: ALICE.to_vec(), balance: 10_000_000, ..Default::default() },
        );
        let (tx, contract) = make_transfer_tx();
        match consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), 0, None)
            .expect("ok")
        {
            BandwidthCharge::Free { bytes, .. } => bytes,
            other => panic!("expected Free, got {other:?}"),
        }
    };
    let plain = bytes_with_flag(false);
    let padded = bytes_with_flag(true);
    assert_eq!(
        padded,
        plain + tron_executor::bandwidth::MAX_RESULT_SIZE_IN_TX,
        "supportVM adds the 64-byte per-contract result padding"
    );
}

// ---------------------------------------------------------------------
// 7. useFreeNet growth mirrors java's two-step increase (not a one-shot)
// ---------------------------------------------------------------------

/// java `BandwidthProcessor.useFreeNet` grows the free-net usage in two
/// steps: decay the stored usage to `now`
/// (`newFreeNetUsage = increase(freeNetUsage, 0, latestConsumeFreeTime, now)`),
/// then grow from THAT decayed value at `now`
/// (`increase(newFreeNetUsage, bytes, now, now)`). A single
/// `increase(freeNetUsage, bytes, latestConsumeFreeTime, now)` is NOT
/// equivalent — the intermediate `getUsage` requantization shifts the
/// recorded usage by up to 1 byte on ~2.4% of charges, always upward.
/// Since free-net usage is persisted and burns no TRX (invisible to fee
/// diffs), that drift silently accumulates until a free-net-only account
/// near its daily cap is wrongly rejected for insufficient bandwidth
/// (live-observed on mainnet acct 413cadd745… at block 83317517, where
/// java covered net_usage=345 from the free quota but our node rejected
/// the tx). This guards the two-step growth.
#[test]
fn free_net_growth_matches_java_two_step_not_one_shot() {
    // Seed usage chosen (with the loop below) to land on a divergent
    // (usage, delta, bytes) point for this tx's charged byte count.
    let free0: i64 = 200;
    let l: i64 = 1_000_000; // latest_consume_free_time

    let seed_free_acct = |env: &Env, usage: i64, last: i64| {
        put(
            &env.accounts,
            ALICE,
            Account {
                address: ALICE.to_vec(),
                // No frozen bandwidth and zero balance: forces the free path
                // (useAccountNet is skipped, and there's nothing to pay a fee).
                free_net_usage: usage,
                latest_consume_free_time: last,
                balance: 0,
                ..Default::default()
            },
        );
    };

    // Discover this tx's charged byte count via one throwaway free-net charge.
    let bytes = {
        let env = Env::new();
        seed_recipient(&env);
        seed_free_acct(&env, free0, l);
        let (tx, contract) = make_transfer_tx();
        match consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), l + 1, None)
            .expect("ok")
        {
            BandwidthCharge::Free { bytes, .. } => bytes,
            other => panic!("expected Free, got {other:?}"),
        }
    };

    // `increase` here is the default-window `increase_default` the production
    // path uses. java's two-step vs the buggy one-shot:
    let two_step = |delta: i64| {
        let decayed = increase(free0, 0, l, l + delta);
        increase(decayed, bytes, l + delta, l + delta)
    };
    let one_shot = |delta: i64| increase(free0, bytes, l, l + delta);

    // Pick the first delta where the two genuinely diverge for THIS byte
    // count, so the assertion below actually guards the regression.
    let delta = (1..WINDOW_SIZE_BLOCKS)
        .find(|&d| two_step(d) != one_shot(d))
        .expect("no divergent delta for these inputs — adjust free0");
    assert_ne!(
        two_step(delta),
        one_shot(delta),
        "test must exercise the one-shot/two-step divergence"
    );

    // Real run: the persisted free_net_usage must equal java's two-step value
    // (the old one-shot code produced `one_shot(delta)` here and would fail).
    let env = Env::new();
    seed_recipient(&env);
    seed_free_acct(&env, free0, l);
    let (tx, contract) = make_transfer_tx();
    let now = l + delta;
    let charge = consume_bandwidth(env.stores(), &tx, &contract, &Address::from_raw(ALICE), now, None)
        .expect("ok");
    let new_free = match charge {
        BandwidthCharge::Free { new_free_usage, .. } => new_free_usage,
        other => panic!("expected Free, got {other:?}"),
    };
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();

    assert_eq!(new_free, two_step(delta), "free-net growth must match java useFreeNet");
    assert_eq!(after.free_net_usage, two_step(delta));
    assert_ne!(new_free, one_shot(delta), "must not use the one-shot growth");
}
