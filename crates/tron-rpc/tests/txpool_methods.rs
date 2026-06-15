//! Tests for the geth-compatible `txpool_status` / `txpool_content` /
//! `txpool_inspect` JSON-RPC methods.
//!
//! The shape we produce mirrors geth (per-sender map, per-tx_id inner
//! key) with TRON-natural values substituted for the eth-only fields
//! (no nonces, gas, gas_price — TRON's `fee_limit` model is different
//! enough that fabricating eth-style values would be misleading).

use std::sync::Arc;

use hex_literal::hex;
use prost::Message as _;
use tron_chainbase::{KvBackend, MemBackend};
use tron_mempool::{MempoolConfig, TxMempool};
use tron_rpc::{methods, RpcState};
use tron_proto::transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw};
use tron_proto::{Transaction, TransferContract, TriggerSmartContract};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state(mempool: Arc<TxMempool>) -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111).with_mempool(mempool)
}

fn signed_transfer(seed: u8) -> (Vec<u8>, [u8; 21]) {
    let mut owner = [0u8; 21];
    owner[0] = 0x41;
    owner[1..].fill(seed);
    let mut to = [0u8; 21];
    to[0] = 0x41;
    to[1..].fill(seed.wrapping_add(1));
    let tc = TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount: 123,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                ..Default::default()
            }],
            expiration: now_ms + 600_000,
            timestamp: now_ms,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    };
    let priv_key = {
        let mut k = [0u8; 32];
        k[0] = 0x10;
        k[31] = seed;
        k
    };
    tron_types::sign_transaction(&mut tx, &priv_key).unwrap();
    // Derive the signer address so tests can verify the per-sender bucket.
    let signers = tron_types::recover_all_signers(&tx).unwrap();
    let signer: [u8; 21] = (*signers[0].as_bytes()).into();
    (tx.encode_to_vec(), signer)
}

fn signed_trigger_smart(seed: u8) -> (Vec<u8>, [u8; 21]) {
    let mut owner = [0u8; 21];
    owner[0] = 0x41;
    owner[1..].fill(seed);
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(seed.wrapping_add(2));
    let trigger = TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 999,
        data: b"\xaa\xbb\xcc".to_vec(),
        call_token_value: 0,
        token_id: 0,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
                    value: trigger.encode_to_vec(),
                }),
                ..Default::default()
            }],
            expiration: now_ms + 600_000,
            timestamp: now_ms,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    };
    let priv_key = {
        let mut k = [0u8; 32];
        k[0] = 0x20;
        k[31] = seed;
        k
    };
    tron_types::sign_transaction(&mut tx, &priv_key).unwrap();
    let signers = tron_types::recover_all_signers(&tx).unwrap();
    let signer: [u8; 21] = (*signers[0].as_bytes()).into();
    (tx.encode_to_vec(), signer)
}

#[test]
fn status_returns_hex_pending_and_zero_queued_when_empty() {
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let state = fresh_state(mempool);
    let result = methods::txpool_status(&serde_json::Value::Null, &state).unwrap();
    assert_eq!(result["pending"], "0x0");
    assert_eq!(result["queued"], "0x0");
}

#[test]
fn status_reflects_pending_count_in_hex() {
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    for seed in [1u8, 2, 3, 4, 5] {
        let (raw, _) = signed_transfer(seed);
        mempool.submit(&raw).unwrap();
    }
    let state = fresh_state(mempool);
    let result = methods::txpool_status(&serde_json::Value::Null, &state).unwrap();
    assert_eq!(result["pending"], "0x5", "5 txs ⇒ 0x5");
    assert_eq!(result["queued"], "0x0", "queued always empty for TRON");
}

#[test]
fn status_with_no_mempool_returns_zero_zero() {
    // RpcState without a mempool — should not panic, return 0s.
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let result = methods::txpool_status(&serde_json::Value::Null, &state).unwrap();
    assert_eq!(result["pending"], "0x0");
    assert_eq!(result["queued"], "0x0");
}

#[test]
fn content_groups_txs_by_sender_with_tx_id_as_inner_key() {
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let (raw1, signer1) = signed_transfer(0xa1);
    let (raw2, signer2) = signed_transfer(0xa2);
    let (raw3, signer3) = signed_trigger_smart(0xb1);
    let id1 = mempool.submit(&raw1).unwrap();
    let id2 = mempool.submit(&raw2).unwrap();
    let id3 = mempool.submit(&raw3).unwrap();

    let state = fresh_state(mempool);
    let result = methods::txpool_content(&serde_json::Value::Null, &state).unwrap();
    let pending = result["pending"].as_object().expect("pending object");
    assert_eq!(pending.len(), 3, "3 distinct signers → 3 buckets");

    let key1 = format!("0x{}", hex::encode(signer1));
    let key2 = format!("0x{}", hex::encode(signer2));
    let key3 = format!("0x{}", hex::encode(signer3));
    let bucket1 = pending.get(&key1).and_then(|v| v.as_object()).unwrap();
    let bucket2 = pending.get(&key2).and_then(|v| v.as_object()).unwrap();
    let bucket3 = pending.get(&key3).and_then(|v| v.as_object()).unwrap();
    assert_eq!(bucket1.len(), 1);
    assert_eq!(bucket2.len(), 1);
    assert_eq!(bucket3.len(), 1);

    let txid_key1 = format!("0x{}", hex::encode(id1));
    let txid_key2 = format!("0x{}", hex::encode(id2));
    let txid_key3 = format!("0x{}", hex::encode(id3));
    assert!(bucket1.contains_key(&txid_key1));
    assert!(bucket2.contains_key(&txid_key2));
    assert!(bucket3.contains_key(&txid_key3));

    // The tx object inside bucket1 should reflect the TransferContract's
    // amount (123) and target. We don't need exact equality on every
    // field; check the eth-shape ones plus the TRON additions.
    let tx_obj = bucket1.get(&txid_key1).unwrap();
    assert_eq!(tx_obj["hash"], txid_key1);
    assert_eq!(tx_obj["from"], key1);
    assert_eq!(tx_obj["value"], format!("0x{:x}", 123));
    // contractType matches ContractType::TransferContract = 1.
    assert_eq!(tx_obj["contractType"].as_i64().unwrap(), 1);
    // input is the raw protobuf hex.
    assert!(tx_obj["input"].as_str().unwrap().starts_with("0x"));

    // For the trigger-smart-contract bucket, value should be 999.
    let tx_obj3 = bucket3.get(&txid_key3).unwrap();
    assert_eq!(tx_obj3["value"], format!("0x{:x}", 999));
    assert_eq!(tx_obj3["contractType"].as_i64().unwrap(), 31);
}

#[test]
fn content_returns_empty_objects_when_mempool_empty() {
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let state = fresh_state(mempool);
    let result = methods::txpool_content(&serde_json::Value::Null, &state).unwrap();
    assert!(result["pending"].as_object().unwrap().is_empty());
    assert!(result["queued"].as_object().unwrap().is_empty());
}

#[test]
fn content_returns_empty_objects_when_no_mempool_attached() {
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let result = methods::txpool_content(&serde_json::Value::Null, &state).unwrap();
    assert!(result["pending"].as_object().unwrap().is_empty());
    assert!(result["queued"].as_object().unwrap().is_empty());
}

#[test]
fn multiple_txs_from_same_signer_all_appear_in_one_bucket() {
    // Different amounts → distinct tx_ids → both should land under
    // the same signer key.
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    // Same seed → same private key → same signer.
    let (raw_a, signer_a) = signed_transfer(0xc1);
    mempool.submit(&raw_a).unwrap();
    // Build a second tx from the same key, varied amount.
    let priv_key = {
        let mut k = [0u8; 32];
        k[0] = 0x10;
        k[31] = 0xc1;
        k
    };
    let mut owner = [0u8; 21];
    owner[0] = 0x41;
    owner[1..].fill(0xc1);
    let mut to = [0u8; 21];
    to[0] = 0x41;
    to[1..].fill(0xc2);
    let tc = TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount: 99999,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                ..Default::default()
            }],
            expiration: now_ms + 600_000,
            timestamp: now_ms,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    };
    tron_types::sign_transaction(&mut tx, &priv_key).unwrap();
    let raw_b = tx.encode_to_vec();
    mempool.submit(&raw_b).unwrap();

    let state = fresh_state(mempool);
    let result = methods::txpool_content(&serde_json::Value::Null, &state).unwrap();
    let pending = result["pending"].as_object().unwrap();
    assert_eq!(pending.len(), 1, "1 signer ⇒ 1 bucket");
    let key = format!("0x{}", hex::encode(signer_a));
    let bucket = pending.get(&key).and_then(|v| v.as_object()).unwrap();
    assert_eq!(bucket.len(), 2, "both txs land under the same signer");
}

#[test]
fn inspect_returns_summary_strings_per_tx() {
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let (raw, _signer) = signed_transfer(0xd1);
    let id = mempool.submit(&raw).unwrap();

    let state = fresh_state(mempool);
    let result = methods::txpool_inspect(&serde_json::Value::Null, &state).unwrap();
    let pending = result["pending"].as_object().unwrap();
    assert_eq!(pending.len(), 1);
    // Bucket holds one entry, value is a string summary.
    let bucket = pending.values().next().unwrap().as_object().unwrap();
    assert_eq!(bucket.len(), 1);
    let txid_key = format!("0x{}", hex::encode(id));
    let summary = bucket.get(&txid_key).unwrap().as_str().unwrap();
    assert!(summary.contains("0x41"), "summary should embed the target address");
    assert!(summary.contains("123 sun"), "summary should mention the transfer amount in sun");
}

#[test]
fn inspect_skips_malformed_txs() {
    // A backend that contains a malformed entry (won't decode) should
    // not crash inspect — geth silently skips garbage in the same case.
    // We can't easily inject malformed bytes via TxMempool.submit
    // (validation rejects them), but we CAN test the decode-error path
    // by going through InMemoryMempool which accepts any bytes.
    use tron_rpc::mempool::InMemoryMempool;
    let mp = InMemoryMempool::new();
    mp.submit_tron_arc(b"garbage-not-protobuf");
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111).with_mempool(mp.clone());
    let result = methods::txpool_inspect(&serde_json::Value::Null, &state).unwrap();
    // The malformed tx was silently skipped — bucket empty.
    let pending = result["pending"].as_object().unwrap();
    assert!(pending.is_empty(), "malformed txs must not appear in inspect");
}

trait InMemoryMempoolExt {
    fn submit_tron_arc(&self, raw: &[u8]);
}
impl InMemoryMempoolExt for Arc<tron_rpc::mempool::InMemoryMempool> {
    fn submit_tron_arc(&self, raw: &[u8]) {
        use tron_rpc::mempool::Mempool;
        let _ = self.submit_tron(raw);
    }
}

#[test]
fn content_handles_malformed_tx_with_decode_error_marker() {
    // Same as inspect_skips_malformed_txs but for content — content
    // surfaces malformed txs with a `decodeError` marker rather than
    // skipping them, so callers can observe pool corruption.
    use tron_rpc::mempool::InMemoryMempool;
    let mp = InMemoryMempool::new();
    mp.submit_tron_arc(b"garbage-not-protobuf");
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111).with_mempool(mp.clone());
    let result = methods::txpool_content(&serde_json::Value::Null, &state).unwrap();
    let pending = result["pending"].as_object().unwrap();
    // The malformed tx lands under the anonymous-bucket signer key
    // (45-char 0x prefix derived from a 22-zero-byte string), with
    // its decodeError field set.
    assert_eq!(pending.len(), 1);
    let bucket = pending.values().next().unwrap().as_object().unwrap();
    let entry = bucket.values().next().unwrap();
    assert_eq!(entry["decodeError"], "malformed protobuf");
}

const _ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");
