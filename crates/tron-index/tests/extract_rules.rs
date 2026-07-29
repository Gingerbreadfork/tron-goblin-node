//! Golden tests for the §6.3 extraction table: one fixture per
//! contract-type rule, plus the negative cases (co-signers not
//! indexed, the TRC20/TRC721 `Transfer` split by topic count,
//! reverted-tx logs absent, calldata addresses not indexed).

use prost::Message as _;
use tron_index::{extract_block, keys, CaptureSet, InternalRow, NativeRow, Trc20Row, Trc721Row, DIR_FROM, DIR_TO, TRANSFER_TOPIC};
use tron_proto::transaction::contract::ContractType;

fn addr(b: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(b);
    a
}

fn caps_all() -> CaptureSet {
    CaptureSet { native: true, trc20: true, trc721: true, internal: true, logs: true, callee_contract: false }
}

fn tx_with(ctype: ContractType, param: Vec<u8>) -> tron_proto::Transaction {
    tron_proto::Transaction {
        raw_data: Some(tron_proto::transaction::Raw {
            contract: vec![tron_proto::transaction::Contract {
                r#type: ctype as i32,
                parameter: Some(prost_types::Any { type_url: String::new(), value: param }),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ret: vec![tron_proto::transaction::Result {
            contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn block_of(txs: Vec<tron_proto::Transaction>) -> tron_proto::Block {
    tron_proto::Block {
        transactions: txs,
        block_header: Some(tron_proto::BlockHeader {
            raw_data: Some(tron_proto::block_header::Raw {
                number: 100,
                timestamp: 1_700_000_000_000,
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

/// Addresses (with directions) keyed in idx_native for a single-tx
/// block.
fn native_addrs(tx: tron_proto::Transaction, caps: &CaptureSet) -> Vec<([u8; 21], u32)> {
    let block = block_of(vec![tx]);
    let entries = extract_block(100, &block, None, caps);
    entries
        .puts
        .iter()
        .filter(|(k, _)| k[0] == keys::NS_NATIVE)
        .map(|(k, v)| {
            let mut a = [0u8; 21];
            a.copy_from_slice(&k[1..22]);
            let row = NativeRow::decode(v.as_slice()).unwrap();
            (a, row.direction)
        })
        .collect()
}

#[test]
fn transfer_indexes_both_parties() {
    let c = tron_proto::TransferContract {
        owner_address: addr(1).to_vec(),
        to_address: addr(2).to_vec(),
        amount: 777,
    };
    let got = native_addrs(tx_with(ContractType::TransferContract, c.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM), (addr(2), DIR_TO)]);
}

#[test]
fn self_transfer_gets_one_row_with_both_bits() {
    let c = tron_proto::TransferContract {
        owner_address: addr(1).to_vec(),
        to_address: addr(1).to_vec(),
        amount: 1,
    };
    let got = native_addrs(tx_with(ContractType::TransferContract, c.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM | DIR_TO)]);
}

#[test]
fn trc10_transfer_records_asset() {
    let c = tron_proto::TransferAssetContract {
        asset_name: b"1002000".to_vec(),
        owner_address: addr(1).to_vec(),
        to_address: addr(2).to_vec(),
        amount: 5,
    };
    let block = block_of(vec![tx_with(ContractType::TransferAssetContract, c.encode_to_vec())]);
    let entries = extract_block(100, &block, None, &caps_all());
    let (_, v) = entries.puts.iter().find(|(k, _)| k[0] == keys::NS_NATIVE).unwrap();
    let row = NativeRow::decode(v.as_slice()).unwrap();
    assert_eq!(row.asset.as_deref(), Some("1002000"));
    assert_eq!(row.amount, 5);
}

#[test]
fn trigger_indexes_caller_only_by_default_and_callee_when_enabled() {
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(1).to_vec(),
        contract_address: addr(9).to_vec(),
        call_value: 3,
        ..Default::default()
    };
    let tx = tx_with(ContractType::TriggerSmartContract, c.encode_to_vec());
    let got = native_addrs(tx.clone(), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM)], "callee NOT indexed by default");

    let caps = CaptureSet { callee_contract: true, ..caps_all() };
    let got = native_addrs(tx, &caps);
    assert_eq!(got, vec![(addr(1), DIR_FROM), (addr(9), DIR_TO)]);
}

#[test]
fn create_contract_indexes_deployer_and_derived_address() {
    let c = tron_proto::CreateSmartContract {
        owner_address: addr(1).to_vec(),
        new_contract: Some(tron_proto::SmartContract { call_value: 11, ..Default::default() }),
        ..Default::default()
    };
    let tx = tx_with(ContractType::CreateSmartContract, c.encode_to_vec());
    // The expected created address: 0x41 ‖ keccak(owner ‖ tx_id)[12..].
    let tx_id = tron_crypto::hash::sha256(&tx.raw_data.as_ref().unwrap().encode_to_vec());
    let mut input = addr(1).to_vec();
    input.extend_from_slice(&tx_id);
    let h = tron_crypto::hash::keccak256(&input);
    let mut created = [0u8; 21];
    created[0] = 0x41;
    created[1..].copy_from_slice(&h[12..]);

    let got = native_addrs(tx, &caps_all());
    assert!(got.contains(&(addr(1), DIR_FROM)));
    assert!(got.contains(&(created, DIR_TO)), "created contract is a participant");
}

#[test]
fn delegate_and_freeze_index_receiver_when_present() {
    let d = tron_proto::DelegateResourceContract {
        owner_address: addr(1).to_vec(),
        receiver_address: addr(2).to_vec(),
        balance: 4,
        ..Default::default()
    };
    let got = native_addrs(tx_with(ContractType::DelegateResourceContract, d.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM), (addr(2), DIR_TO)]);

    // v1 freeze with no receiver → owner only.
    let f = tron_proto::FreezeBalanceContract {
        owner_address: addr(1).to_vec(),
        frozen_balance: 100,
        ..Default::default()
    };
    let got = native_addrs(tx_with(ContractType::FreezeBalanceContract, f.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM)]);

    // v2 freeze has no receiver at all.
    let f2 = tron_proto::FreezeBalanceV2Contract {
        owner_address: addr(1).to_vec(),
        frozen_balance: 100,
        ..Default::default()
    };
    let got = native_addrs(tx_with(ContractType::FreezeBalanceV2Contract, f2.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM)]);
}

#[test]
fn vote_targets_are_indexed_under_each_witness() {
    let vote = |to: u8, count: i64| tron_proto::vote_witness_contract::Vote {
        vote_address: addr(to).to_vec(),
        vote_count: count,
    };
    // Two distinct targets, one repeated — repeats collapse into the
    // same key (BTreeMap participant dedup), amount = total votes.
    let c = tron_proto::VoteWitnessContract {
        owner_address: addr(1).to_vec(),
        votes: vec![vote(7, 1000), vote(8, 500), vote(7, 250)],
        ..Default::default()
    };
    let block = block_of(vec![tx_with(ContractType::VoteWitnessContract, c.encode_to_vec())]);
    let entries = extract_block(100, &block, None, &caps_all());
    let got: Vec<([u8; 21], u32, i64)> = entries
        .puts
        .iter()
        .filter(|(k, _)| k[0] == keys::NS_NATIVE)
        .map(|(k, v)| {
            let mut a = [0u8; 21];
            a.copy_from_slice(&k[1..22]);
            let row = NativeRow::decode(v.as_slice()).unwrap();
            (a, row.direction, row.amount)
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (addr(1), DIR_FROM, 1750),
            (addr(7), DIR_TO, 1750),
            (addr(8), DIR_TO, 1750),
        ],
        "owner + each distinct voted-for SR, amount = total vote count"
    );
}

#[test]
fn account_create_indexes_created_account() {
    let c = tron_proto::AccountCreateContract {
        owner_address: addr(1).to_vec(),
        account_address: addr(3).to_vec(),
        ..Default::default()
    };
    let got = native_addrs(tx_with(ContractType::AccountCreateContract, c.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM), (addr(3), DIR_TO)]);
}

#[test]
fn shielded_transfer_indexes_only_transparent_endpoints() {
    let c = tron_proto::ShieldedTransferContract {
        transparent_from_address: addr(1).to_vec(),
        from_amount: 50,
        ..Default::default()
    };
    let got = native_addrs(tx_with(ContractType::ShieldedTransferContract, c.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(1), DIR_FROM)]);

    // Fully shielded: no transparent endpoints → no native rows at all.
    let c = tron_proto::ShieldedTransferContract::default();
    let got = native_addrs(tx_with(ContractType::ShieldedTransferContract, c.encode_to_vec()), &caps_all());
    assert!(got.is_empty());
}

#[test]
fn catch_all_types_index_owner_via_field_walk() {
    // WithdrawBalanceContract — owner is field 1.
    let w = tron_proto::WithdrawBalanceContract { owner_address: addr(4).to_vec() };
    let got = native_addrs(tx_with(ContractType::WithdrawBalanceContract, w.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(4), DIR_FROM)]);

    // AccountUpdateContract — owner is field 2 behind a name blob that
    // must not be mistaken for an address.
    let u = tron_proto::AccountUpdateContract {
        account_name: vec![0x41; 21], // 21 bytes starting 0x41 — a decoy!
        owner_address: addr(5).to_vec(),
    };
    let got = native_addrs(tx_with(ContractType::AccountUpdateContract, u.encode_to_vec()), &caps_all());
    assert_eq!(got, vec![(addr(5), DIR_FROM)], "typed decoder must pick owner, not the name decoy");
}

#[test]
fn multisig_cosigners_are_not_indexed() {
    // Signatures live outside raw_data; only the owner is a participant.
    let c = tron_proto::TransferContract {
        owner_address: addr(1).to_vec(),
        to_address: addr(2).to_vec(),
        amount: 1,
    };
    let mut tx = tx_with(ContractType::TransferContract, c.encode_to_vec());
    tx.signature = vec![vec![0xab; 65], vec![0xcd; 65], vec![0xef; 65]];
    let got = native_addrs(tx, &caps_all());
    assert_eq!(got.len(), 2);
}

// ---------------------------------------------------------------------------
// TRC20 / log rules
// ---------------------------------------------------------------------------

fn topic_addr(a: &[u8; 21]) -> Vec<u8> {
    let mut t = vec![0u8; 12];
    t.extend_from_slice(&a[1..]);
    t
}

fn info_with_logs(logs: Vec<tron_proto::transaction_info::Log>) -> tron_proto::TransactionRet {
    tron_proto::TransactionRet {
        transactioninfo: vec![tron_proto::TransactionInfo { log: logs, ..Default::default() }],
        ..Default::default()
    }
}

fn trc20_rows_of(block: &tron_proto::Block, ret: &tron_proto::TransactionRet) -> Vec<(Vec<u8>, Trc20Row)> {
    // Positional fallback applies (infos carry no id in these fixtures).
    let entries = extract_block(100, block, Some(ret), &caps_all());
    entries
        .puts
        .iter()
        .filter(|(k, _)| k[0] == keys::NS_TRC20)
        .map(|(k, v)| (k.clone(), Trc20Row::decode(v.as_slice()).unwrap()))
        .collect()
}

fn trc721_rows_of(
    block: &tron_proto::Block,
    ret: &tron_proto::TransactionRet,
    caps: &CaptureSet,
) -> Vec<(Vec<u8>, Trc721Row)> {
    let entries = extract_block(100, block, Some(ret), caps);
    entries
        .puts
        .iter()
        .filter(|(k, _)| k[0] == keys::NS_TRC721)
        .map(|(k, v)| (k.clone(), Trc721Row::decode(v.as_slice()).unwrap()))
        .collect()
}

#[test]
fn trc20_transfer_log_indexes_both_parties_with_amount() {
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(1).to_vec(),
        contract_address: addr(9).to_vec(),
        ..Default::default()
    };
    let block = block_of(vec![tx_with(ContractType::TriggerSmartContract, c.encode_to_vec())]);
    let mut amount = vec![0u8; 32];
    amount[31] = 42;
    let ret = info_with_logs(vec![tron_proto::transaction_info::Log {
        address: addr(9)[1..].to_vec(),
        topics: vec![TRANSFER_TOPIC.to_vec(), topic_addr(&addr(1)), topic_addr(&addr(2))],
        data: amount.clone(),
    }]);
    let rows = trc20_rows_of(&block, &ret);
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|(_, r)| r.amount == amount && r.token == addr(9).to_vec()));
    let dirs: Vec<u32> = rows.iter().map(|(_, r)| r.direction).collect();
    assert_eq!(dirs, vec![DIR_FROM, DIR_TO]);
}

#[test]
fn four_topic_transfer_is_trc721_not_trc20() {
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(1).to_vec(),
        contract_address: addr(9).to_vec(),
        ..Default::default()
    };
    let block = block_of(vec![tx_with(ContractType::TriggerSmartContract, c.encode_to_vec())]);
    let mut token_id = vec![0u8; 32];
    token_id[30] = 0x01;
    token_id[31] = 0x41; // tokenId 321
    let ret = info_with_logs(vec![tron_proto::transaction_info::Log {
        address: addr(9)[1..].to_vec(),
        topics: vec![
            TRANSFER_TOPIC.to_vec(),
            topic_addr(&addr(1)),
            topic_addr(&addr(2)),
            token_id.clone(),
        ],
        data: vec![],
    }]);
    // Never a TRC20 row…
    assert!(trc20_rows_of(&block, &ret).is_empty());
    // …but both parties get a TRC721 row carrying the tokenId.
    let rows = trc721_rows_of(&block, &ret, &caps_all());
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|(_, r)| r.token_id == token_id && r.token == addr(9).to_vec()));
    let dirs: Vec<u32> = rows.iter().map(|(_, r)| r.direction).collect();
    assert_eq!(dirs, vec![DIR_FROM, DIR_TO]);

    // With trc721 capture off the log produces nothing at all.
    let caps = CaptureSet { trc721: false, ..caps_all() };
    assert!(trc721_rows_of(&block, &ret, &caps).is_empty());
    assert!(extract_block(100, &block, Some(&ret), &caps)
        .puts
        .iter()
        .all(|(k, _)| k[0] != keys::NS_TRC721));
}

#[test]
fn wrong_topic0_or_data_len_is_excluded() {
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(1).to_vec(),
        contract_address: addr(9).to_vec(),
        ..Default::default()
    };
    let block = block_of(vec![tx_with(ContractType::TriggerSmartContract, c.encode_to_vec())]);
    // Approval(owner,spender,value) — right shape, wrong signature.
    let ret = info_with_logs(vec![tron_proto::transaction_info::Log {
        address: addr(9)[1..].to_vec(),
        topics: vec![vec![0x8c; 32], topic_addr(&addr(1)), topic_addr(&addr(2))],
        data: vec![0u8; 32],
    }]);
    assert!(trc20_rows_of(&block, &ret).is_empty());
    // Transfer with non-32-byte data.
    let ret = info_with_logs(vec![tron_proto::transaction_info::Log {
        address: addr(9)[1..].to_vec(),
        topics: vec![TRANSFER_TOPIC.to_vec(), topic_addr(&addr(1)), topic_addr(&addr(2))],
        data: vec![0u8; 31],
    }]);
    assert!(trc20_rows_of(&block, &ret).is_empty());
}

#[test]
fn reverted_tx_surfaces_no_trc20_rows() {
    // java-tron semantics: a reverted tx's TransactionInfo carries no
    // logs; mirror that committed truth — empty log list ⇒ no rows.
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(1).to_vec(),
        contract_address: addr(9).to_vec(),
        ..Default::default()
    };
    let mut tx = tx_with(ContractType::TriggerSmartContract, c.encode_to_vec());
    tx.ret[0].contract_ret = tron_proto::transaction::result::ContractResult::Revert as i32;
    let block = block_of(vec![tx]);
    let ret = info_with_logs(vec![]);
    assert!(trc20_rows_of(&block, &ret).is_empty());
    // The native caller row still exists, marked unsuccessful.
    let entries = extract_block(100, &block, Some(&ret), &caps_all());
    let (_, v) = entries.puts.iter().find(|(k, _)| k[0] == keys::NS_NATIVE).unwrap();
    assert!(!NativeRow::decode(v.as_slice()).unwrap().success);
}

#[test]
fn transfer_topic_constant_matches_known_value() {
    assert_eq!(
        hex::encode(TRANSFER_TOPIC),
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    );
}

// ---------------------------------------------------------------------------
// Internal transactions
// ---------------------------------------------------------------------------

fn internal_rows_of(
    block: &tron_proto::Block,
    ret: &tron_proto::TransactionRet,
) -> Vec<(Vec<u8>, InternalRow)> {
    let entries = extract_block(100, block, Some(ret), &caps_all());
    entries
        .puts
        .iter()
        .filter(|(k, _)| k[0] == keys::NS_INTERNAL)
        .map(|(k, v)| (k.clone(), InternalRow::decode(v.as_slice()).unwrap()))
        .collect()
}

/// The root frame of every smart-contract call carries a spurious
/// `{tokenId: "0", call_value: 0}` leg (java's
/// `InternalTransaction` unconditionally maps `String.valueOf(getTokenId())`
/// for the root frame, so a non-token call yields tokenId "0"). It must
/// NOT surface as a token transfer on the row.
#[test]
fn internal_non_token_call_does_not_report_token_zero() {
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(1).to_vec(),
        contract_address: addr(9).to_vec(),
        ..Default::default()
    };
    let block = block_of(vec![tx_with(ContractType::TriggerSmartContract, c.encode_to_vec())]);
    let itx = tron_proto::InternalTransaction {
        caller_address: addr(1).to_vec(),
        transfer_to_address: addr(9).to_vec(),
        call_value_info: vec![
            // native leg (always first, empty tokenId)
            tron_proto::internal_transaction::CallValueInfo {
                call_value: 500,
                token_id: String::new(),
            },
            // root-frame no-token sentinel leg
            tron_proto::internal_transaction::CallValueInfo {
                call_value: 0,
                token_id: "0".to_string(),
            },
        ],
        ..Default::default()
    };
    let ret = tron_proto::TransactionRet {
        transactioninfo: vec![tron_proto::TransactionInfo {
            internal_transactions: vec![itx],
            ..Default::default()
        }],
        ..Default::default()
    };
    let rows = internal_rows_of(&block, &ret);
    assert_eq!(rows.len(), 2, "caller + target each get a row");
    for (_, r) in &rows {
        assert_eq!(r.call_value, 500, "native value from the empty-tokenId leg");
        assert_eq!(r.token_id, None, "tokenId \"0\" is the no-token sentinel, never a token");
    }
}

/// A genuine TRC10 leg (positive id, leading zeros stripped) surfaces as
/// the row's token, with the native value taken from leg 0.
#[test]
fn internal_token_call_reports_real_token_id() {
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(1).to_vec(),
        contract_address: addr(9).to_vec(),
        ..Default::default()
    };
    let block = block_of(vec![tx_with(ContractType::TriggerSmartContract, c.encode_to_vec())]);
    let itx = tron_proto::InternalTransaction {
        caller_address: addr(1).to_vec(),
        transfer_to_address: addr(9).to_vec(),
        call_value_info: vec![
            tron_proto::internal_transaction::CallValueInfo {
                call_value: 0,
                token_id: String::new(),
            },
            tron_proto::internal_transaction::CallValueInfo {
                call_value: 4242,
                token_id: "1002000".to_string(),
            },
        ],
        ..Default::default()
    };
    let ret = tron_proto::TransactionRet {
        transactioninfo: vec![tron_proto::TransactionInfo {
            internal_transactions: vec![itx],
            ..Default::default()
        }],
        ..Default::default()
    };
    let rows = internal_rows_of(&block, &ret);
    assert_eq!(rows.len(), 2);
    for (_, r) in &rows {
        assert_eq!(r.call_value, 0, "no native value moved");
        assert_eq!(r.token_id.as_deref(), Some("1002000"));
    }
}

#[test]
fn count_block_txs_raw_matches_decoded() {
    let block = block_of(vec![
        tx_with(ContractType::TransferContract, vec![]),
        tx_with(ContractType::TransferContract, vec![1]),
        tx_with(ContractType::TransferContract, vec![2]),
    ]);
    let bytes = block.encode_to_vec();
    assert_eq!(tron_index::extract::count_block_txs_raw(&bytes), 3);
    assert_eq!(tron_index::extract::count_block_txs_raw(&[]), 0);
}

#[test]
fn stored_info_id_overrides_the_reencode_hash_for_row_keys() {
    // A tx whose raw_data carried an unknown field on the wire is indexed
    // under its STORED info id (the executor's wire-derived id), not the
    // re-encode hash of the decoded tx — otherwise every row for it would
    // be keyed under an id nobody looks up.
    let c = tron_proto::TransferContract {
        owner_address: addr(1).to_vec(),
        to_address: addr(2).to_vec(),
        amount: 7,
    };
    let tx = tx_with(ContractType::TransferContract, c.encode_to_vec());
    let block = block_of(vec![tx.clone()]);

    let wire_id = [0xEEu8; 32]; // the executor's authoritative id
    let ret = tron_proto::TransactionRet {
        transactioninfo: vec![tron_proto::TransactionInfo {
            id: wire_id.to_vec(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let entries = extract_block(100, &block, Some(&ret), &caps_all());
    let native_txids: Vec<Vec<u8>> = entries
        .puts
        .iter()
        .filter(|(k, _)| k[0] == keys::NS_NATIVE)
        .map(|(_, v)| NativeRow::decode(v.as_slice()).unwrap().txid)
        .collect();
    assert!(!native_txids.is_empty());
    for txid in &native_txids {
        assert_eq!(txid.as_slice(), wire_id.as_slice());
    }

    // Without a stored info the extractor still falls back to the
    // re-encode hash (identical for canonical txs).
    let reencode_id = tron_crypto::hash::sha256(
        &tx.raw_data.as_ref().unwrap().encode_to_vec(),
    );
    let entries = extract_block(100, &block, None, &caps_all());
    let native_txids: Vec<Vec<u8>> = entries
        .puts
        .iter()
        .filter(|(k, _)| k[0] == keys::NS_NATIVE)
        .map(|(_, v)| NativeRow::decode(v.as_slice()).unwrap().txid)
        .collect();
    for txid in &native_txids {
        assert_eq!(txid.as_slice(), reencode_id.as_slice());
    }
}
