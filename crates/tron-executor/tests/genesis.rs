//! Tests for `apply_genesis_allocations` and `mainnet_witnesses`.

use std::sync::Arc;

use tron_chainbase::{AccountIndexStore, AccountStore, KvBackend, MemBackend, WitnessStore};
use tron_crypto::address::Address;
use tron_executor::{apply_genesis_allocations, StateBackends};
use tron_types::{mainnet_inputs, mainnet_witnesses};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> StateBackends {
    StateBackends {
        accounts: mem(),
        witnesses: mem(),
        votes: mem(),
        delegation: mem(),
        delegated_resources: mem(),
        dyn_props: mem(),
        proposals: mem(),
        name_index: mem(),
        id_index: mem(),
        asset_v1: mem(),
        asset_v2: mem(),
        contracts: mem(),
        abi: mem(),
        exchange_v1: mem(),
        exchange_v2: mem(),
        market_orders: mem(),
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
    }
}

#[test]
fn mainnet_witnesses_decodes_27_entries() {
    let ws = mainnet_witnesses();
    assert_eq!(ws.len(), 27);
    // First witness has the largest vote count; last has 100_000_000.
    assert_eq!(ws[0].vote_count, 100_000_026);
    assert_eq!(ws[26].vote_count, 100_000_000);
    // All addresses are 21-byte TRON addresses with the mainnet prefix.
    for w in ws {
        assert_eq!(w.address[0], 0x41, "witness {} prefix", w.url);
    }
}

#[test]
fn apply_genesis_allocations_writes_assets() {
    let state = fresh_state();
    let inputs = mainnet_inputs();
    apply_genesis_allocations(&state, inputs.assets, &[]).unwrap();
    let accounts = AccountStore::new(state.accounts.clone());
    for asset in inputs.assets {
        let acct = accounts
            .get(&Address::from_raw(asset.address))
            .expect("read")
            .expect("asset exists");
        assert_eq!(acct.balance, asset.balance);
    }
}

#[test]
fn apply_genesis_allocations_populates_account_name_and_name_index() {
    // Mirrors java-tron's `Manager.initAccount`: the asset name from
    // `genesis.block.assets[].accountName` lands on both the Account
    // proto's `account_name` field AND `AccountIndexStore[name]`.
    let state = fresh_state();
    let inputs = mainnet_inputs();
    apply_genesis_allocations(&state, inputs.assets, &[]).unwrap();

    let accounts = AccountStore::new(state.accounts.clone());
    let name_index = AccountIndexStore::new(state.name_index.clone());

    for asset in inputs.assets {
        let addr = Address::from_raw(asset.address);
        let acct = accounts.get(&addr).expect("read").expect("asset exists");
        assert_eq!(
            acct.account_name,
            asset.name.as_bytes(),
            "Account.account_name for {}",
            asset.name
        );

        let resolved = name_index
            .get(asset.name.as_bytes())
            .expect("name-index read")
            .expect("name should resolve");
        assert_eq!(
            resolved.as_bytes(),
            &asset.address,
            "name-index should map name → address for {}",
            asset.name
        );
    }
}

#[test]
fn apply_genesis_allocations_writes_witnesses_and_flags_accounts() {
    let state = fresh_state();
    apply_genesis_allocations(&state, &[], mainnet_witnesses()).unwrap();

    let accounts = AccountStore::new(state.accounts.clone());
    let witnesses = WitnessStore::new(state.witnesses.clone());

    for w in mainnet_witnesses() {
        let addr = Address::from_raw(w.address);
        let acct = accounts.get(&addr).expect("read").expect("witness account");
        assert!(acct.is_witness, "address {:02x?} should be flagged", w.address);
        let entry = witnesses
            .get(&addr)
            .expect("read")
            .expect("witness entry");
        assert_eq!(entry.vote_count, w.vote_count);
        assert_eq!(entry.url, w.url);
        assert!(entry.is_jobs);
    }
}

#[test]
fn apply_genesis_allocations_is_idempotent() {
    let state = fresh_state();
    let inputs = mainnet_inputs();
    apply_genesis_allocations(&state, inputs.assets, mainnet_witnesses()).unwrap();
    apply_genesis_allocations(&state, inputs.assets, mainnet_witnesses()).unwrap();

    let accounts = AccountStore::new(state.accounts.clone());
    let witnesses = WitnessStore::new(state.witnesses.clone());

    // Asset balances are still the seed values, not doubled.
    for asset in inputs.assets {
        let acct = accounts
            .get(&Address::from_raw(asset.address))
            .unwrap()
            .unwrap();
        assert_eq!(acct.balance, asset.balance);
    }
    // Witness rows are unchanged.
    for w in mainnet_witnesses() {
        let entry = witnesses
            .get(&Address::from_raw(w.address))
            .unwrap()
            .unwrap();
        assert_eq!(entry.vote_count, w.vote_count);
    }
}

#[test]
fn mainnet_witnesses_addresses_round_trip_to_config_base58() {
    use tron_crypto::base58check::encode_address;
    let expected: &[&str] = &[
        "THKJYuUmMKKARNf7s2VT51g5uPY6KEqnat",
        "TVDmPWGYxgi5DNeW8hXrzrhY8Y6zgxPNg4",
        "TWKZN1JJPFydd5rMgMCV5aZTSiwmoksSZv",
        "TDarXEG2rAD57oa7JTK785Yb2Et32UzY32",
        "TAmFfS4Tmm8yKeoqZN8x51ASwdQBdnVizt",
        "TK6V5Pw2UWQWpySnZyCDZaAvu1y48oRgXN",
        "TGqFJPFiEqdZx52ZR4QcKHz4Zr3QXA24VL",
        "TC1ZCj9Ne3j5v3TLx5ZCDLD55MU9g3XqQW",
        "TWm3id3mrQ42guf7c4oVpYExyTYnEGy3JL",
        "TCvwc3FV3ssq2rD82rMmjhT4PVXYTsFcKV",
        "TFuC2Qge4GxA2U9abKxk1pw3YZvGM5XRir",
        "TNGoca1VHC6Y5Jd2B1VFpFEhizVk92Rz85",
        "TLCjmH6SqGK8twZ9XrBDWpBbfyvEXihhNS",
        "TEEzguTtCihbRPfjf1CvW8Euxz1kKuvtR9",
        "TZHvwiw9cehbMxrtTbmAexm9oPo4eFFvLS",
        "TGK6iAKgBmHeQyp5hn3imB71EDnFPkXiPR",
        "TLaqfGrxZ3dykAFps7M2B4gETTX1yixPgN",
        "TX3ZceVew6yLC5hWTXnjrUFtiFfUDGKGty",
        "TYednHaV9zXpnPchSywVpnseQxY9Pxw4do",
        "TCf5cqLffPccEY7hcsabiFnMfdipfyryvr",
        "TAa14iLEKPAetX49mzaxZmH6saRxcX7dT5",
        "TBYsHxDmFaRmfCF3jZNmgeJE8sDnTNKHbz",
        "TEVAq8dmSQyTYK7uP1ZnZpa6MBVR83GsV6",
        "TRKJzrZxN34YyB8aBqqPDt7g4fv6sieemz",
        "TRMP6SKeFUt5NtMLzJv8kdpYuHRnEGjGfe",
        "TDbNE1VajxjpgM5p7FyGNDASt3UVoFbiD3",
        "TLTDZBcPoJ8tZ6TTEeEqEvwYFk2wgotSfD",
    ];
    let actual = mainnet_witnesses();
    assert_eq!(actual.len(), expected.len());
    for (got, want) in actual.iter().zip(expected.iter()) {
        let encoded = encode_address(&Address::from_raw(got.address));
        assert_eq!(&encoded, want, "for witness {}", got.url);
    }
}
