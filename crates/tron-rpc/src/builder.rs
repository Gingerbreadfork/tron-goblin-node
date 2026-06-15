//! Server-side unsigned-transaction builders.
//!
//! Wallets that don't carry the full TRON proto encoder rely on the
//! node to build the `Transaction` envelope: pulling the latest block
//! for `ref_block_*`, setting `expiration = now + 60s`, computing
//! `txID = sha256(raw_data.encode())`. The client then signs the
//! txID locally and submits via `broadcastTransaction`.
//!
//! Each builder follows the same shape:
//!   1. Decode the JSON params into the typed contract proto.
//!   2. Wrap in a `Contract` (with the appropriate `ContractType`).
//!   3. Call [`build_unsigned_tx`] to fill the envelope.
//!   4. Hand back the standard JSON response via [`tx_to_envelope`].
//!
//! The contract-type-specific JSON shape mirrors what java-tron's HTTP
//! API accepts so existing wallet code (TronWeb, TronLink) cross-uses.
//!
//! References:
//!   * `TransactionCapsule.setReference` —
//!     `refBlockNum.subArray(6,8)` + `blockHash.subArray(8,16)`.
//!   * `Constant.TRANSACTION_DEFAULT_EXPIRATION_TIME = 60_000` ms.

use prost::Message as _;
use serde_json::{json, Value};
use tron_chainbase::{BlockIndexStore, BlockStore, DynamicPropertiesStore};
use tron_proto::transaction::{
    contract::ContractType, Contract as TxContract, Raw as TxRaw,
};
use tron_proto::Transaction;

use crate::methods::{hex_bytes, RpcError};
use crate::state::RpcState;

/// java-tron's `Constant.TRANSACTION_DEFAULT_EXPIRATION_TIME`.
pub const DEFAULT_EXPIRATION_MS: i64 = 60 * 1_000;

/// Build an unsigned [`Transaction`] envelope for `contract`.
///
/// Fills in:
///   * `raw_data.contract = [contract]`
///   * `raw_data.ref_block_bytes` = lower 2 bytes (BE) of the latest
///     block number
///   * `raw_data.ref_block_hash` = bytes `[8..16]` of the latest
///     block id
///   * `raw_data.timestamp` = current wall-clock ms (or
///     `latest_block_header_timestamp` if the wall clock isn't trusted —
///     we use wall-clock here, matching java-tron's `Wallet.fillTransaction`)
///   * `raw_data.expiration` = `timestamp + DEFAULT_EXPIRATION_MS`
///   * `raw_data.fee_limit` = `fee_limit` (passed through; 0 for non-VM)
///
/// Leaves `signature: []` empty. The client signs after fetching this.
pub fn build_unsigned_tx(
    state: &RpcState,
    contract: TxContract,
    fee_limit: i64,
) -> Result<Transaction, RpcError> {
    let head_num = state.dyn_props.latest_block_header_number().unwrap_or(0);
    // Look up the head block hash. On a freshly-bootstrapped node
    // (no head yet) we fall back to a zero hash + zero refs so the tx
    // is at least structurally valid for tests.
    let (ref_bytes, ref_hash) = match state.block_index.get(head_num) {
        Ok(id) => {
            let num_be = head_num.to_be_bytes(); // 8 bytes BE
            let mut rb = vec![0u8; 2];
            rb.copy_from_slice(&num_be[6..8]);
            let mut rh = vec![0u8; 8];
            rh.copy_from_slice(&id.as_bytes()[8..16]);
            (rb, rh)
        }
        Err(_) => (vec![0u8; 2], vec![0u8; 8]),
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let raw = TxRaw {
        contract: vec![contract],
        ref_block_bytes: ref_bytes,
        ref_block_hash: ref_hash,
        ref_block_num: head_num,
        expiration: now_ms + DEFAULT_EXPIRATION_MS,
        timestamp: now_ms,
        fee_limit,
        ..Default::default()
    };
    Ok(Transaction {
        raw_data: Some(raw),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    })
}

/// Hand back the JSON shape wallets expect after a builder call:
/// txID + the inline raw_data fields + a hex blob of the raw_data
/// (which is what they actually sign with `sha256` then ECDSA).
pub fn tx_to_envelope(tx: &Transaction) -> Result<Value, RpcError> {
    let raw = tx
        .raw_data
        .as_ref()
        .ok_or_else(|| RpcError::internal("builder produced tx with no raw_data"))?;
    let raw_data_bytes = raw.encode_to_vec();
    let tx_id = tron_crypto::hash::sha256(&raw_data_bytes);
    let contracts: Vec<Value> = raw
        .contract
        .iter()
        .map(|c| {
            json!({
                "type": c.r#type,
                "permission_id": c.permission_id,
                "parameter_type_url": c
                    .parameter
                    .as_ref()
                    .map(|p| p.type_url.clone())
                    .unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({
        "visible": false,
        "txID": hex_bytes(&tx_id),
        "raw_data": {
            "contract": contracts,
            "ref_block_bytes": hex_bytes(&raw.ref_block_bytes),
            "ref_block_hash": hex_bytes(&raw.ref_block_hash),
            "expiration": raw.expiration,
            "timestamp": raw.timestamp,
            "fee_limit": raw.fee_limit,
        },
        "raw_data_hex": hex_bytes(&raw_data_bytes),
        "signature": Vec::<Value>::new(),
    }))
}

/// Convenience: build a `TxContract` of the given `ContractType` wrapping
/// the protobuf-encoded `param` proto.
pub fn wrap_contract<T: prost::Message>(
    contract_type: ContractType,
    param: &T,
    permission_id: i32,
) -> TxContract {
    TxContract {
        r#type: contract_type as i32,
        parameter: Some(prost_types::Any {
            type_url: format!("type.googleapis.com/protocol.{}", proto_name(contract_type)),
            value: param.encode_to_vec(),
        }),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id,
    }
}

/// Map a [`ContractType`] enum variant to the proto message name. Used
/// for the `type_url` field of the wrapping `Any`. java-tron writes
/// these as `type.googleapis.com/protocol.<MessageName>` — wallets
/// inspect the `type_url` to know what to deserialize.
fn proto_name(t: ContractType) -> &'static str {
    use ContractType::*;
    match t {
        TransferContract => "TransferContract",
        TransferAssetContract => "TransferAssetContract",
        TriggerSmartContract => "TriggerSmartContract",
        CreateSmartContract => "CreateSmartContract",
        FreezeBalanceContract => "FreezeBalanceContract",
        UnfreezeBalanceContract => "UnfreezeBalanceContract",
        FreezeBalanceV2Contract => "FreezeBalanceV2Contract",
        UnfreezeBalanceV2Contract => "UnfreezeBalanceV2Contract",
        WithdrawExpireUnfreezeContract => "WithdrawExpireUnfreezeContract",
        CancelAllUnfreezeV2Contract => "CancelAllUnfreezeV2Contract",
        DelegateResourceContract => "DelegateResourceContract",
        UnDelegateResourceContract => "UnDelegateResourceContract",
        VoteWitnessContract => "VoteWitnessContract",
        WithdrawBalanceContract => "WithdrawBalanceContract",
        AccountPermissionUpdateContract => "AccountPermissionUpdateContract",
        AccountCreateContract => "AccountCreateContract",
        AccountUpdateContract => "AccountUpdateContract",
        SetAccountIdContract => "SetAccountIdContract",
        UpdateBrokerageContract => "UpdateBrokerageContract",
        AssetIssueContract => "AssetIssueContract",
        UpdateAssetContract => "UpdateAssetContract",
        ParticipateAssetIssueContract => "ParticipateAssetIssueContract",
        UnfreezeAssetContract => "UnfreezeAssetContract",
        WitnessCreateContract => "WitnessCreateContract",
        WitnessUpdateContract => "WitnessUpdateContract",
        ProposalCreateContract => "ProposalCreateContract",
        ProposalApproveContract => "ProposalApproveContract",
        ProposalDeleteContract => "ProposalDeleteContract",
        ExchangeCreateContract => "ExchangeCreateContract",
        ExchangeInjectContract => "ExchangeInjectContract",
        ExchangeWithdrawContract => "ExchangeWithdrawContract",
        ExchangeTransactionContract => "ExchangeTransactionContract",
        MarketSellAssetContract => "MarketSellAssetContract",
        MarketCancelOrderContract => "MarketCancelOrderContract",
        UpdateSettingContract => "UpdateSettingContract",
        UpdateEnergyLimitContract => "UpdateEnergyLimitContract",
        ClearAbiContract => "ClearABIContract",
        ShieldedTransferContract => "ShieldedTransferContract",
        _ => "Unknown",
    }
}

/// Compile-time check: silence unused-import warnings if the
/// reachable BlockIndexStore / BlockStore / DynamicPropertiesStore
/// aren't directly named (we go through `RpcState` field accesses
/// which keep them live transitively).
#[allow(dead_code)]
fn _keep_types_live() {
    let _ = std::any::type_name::<BlockIndexStore>();
    let _ = std::any::type_name::<BlockStore>();
    let _ = std::any::type_name::<DynamicPropertiesStore>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tron_chainbase::{KvBackend, MemBackend};

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn fresh_state() -> RpcState {
        RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
    }

    #[test]
    fn build_unsigned_tx_emits_envelope_for_fresh_chain() {
        let state = fresh_state();
        let tc = tron_proto::TransferContract {
            owner_address: vec![0x41; 21],
            to_address: vec![0x41; 21],
            amount: 1,
        };
        let contract = wrap_contract(ContractType::TransferContract, &tc, 0);
        let tx = build_unsigned_tx(&state, contract, 0).expect("build");
        assert!(tx.signature.is_empty());
        let raw = tx.raw_data.as_ref().unwrap();
        assert_eq!(raw.ref_block_bytes.len(), 2);
        assert_eq!(raw.ref_block_hash.len(), 8);
        assert!(raw.expiration >= raw.timestamp);
        assert_eq!(raw.expiration - raw.timestamp, DEFAULT_EXPIRATION_MS);
    }

    #[test]
    fn envelope_includes_tx_id_and_hex_blob() {
        let state = fresh_state();
        let tc = tron_proto::TransferContract {
            owner_address: vec![0x41; 21],
            to_address: vec![0x41; 21],
            amount: 1,
        };
        let contract = wrap_contract(ContractType::TransferContract, &tc, 0);
        let tx = build_unsigned_tx(&state, contract, 0).unwrap();
        let env = tx_to_envelope(&tx).unwrap();
        assert!(env["txID"].as_str().unwrap().starts_with("0x"));
        assert_eq!(env["txID"].as_str().unwrap().len(), 66); // 32-byte hex
        assert!(env["raw_data_hex"].as_str().unwrap().starts_with("0x"));
        assert_eq!(env["signature"], Value::Array(vec![]));
    }
}
