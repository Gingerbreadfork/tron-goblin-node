//! JSON-RPC method implementations.
//!
//! Each method is a free function taking `(params: &Value, state:
//! &RpcState) -> Result<Value, RpcError>`. They're registered into a
//! single dispatch table in [`crate::server`].

use prost::Message as _;
use serde_json::{json, Value};
use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_crypto::hash::keccak256;

use crate::state::RpcState;

/// JSON-RPC 2.0 error per the spec.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self { code: -32700, message: msg.into() }
    }
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self { code: -32602, message: msg.into() }
    }
    pub fn method_not_found(name: &str) -> Self {
        Self { code: -32601, message: format!("Method not found: {name}") }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self { code: -32603, message: msg.into() }
    }
    /// JSON-RPC "invalid request" (`-32600`). Used by gated methods
    /// when the surrounding config disables the operation.
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self { code: -32600, message: msg.into() }
    }
}

impl From<tron_chainbase::StoreError> for RpcError {
    fn from(e: tron_chainbase::StoreError) -> Self {
        Self::internal(format!("store error: {e}"))
    }
}

impl From<tron_chainbase::KvError> for RpcError {
    fn from(e: tron_chainbase::KvError) -> Self {
        Self::internal(format!("kv backend error: {e}"))
    }
}

// =============================================================================
// Helpers — hex encoding the Ethereum way (lowercase, `0x`-prefixed, minimal).
// =============================================================================

/// `0x...` with no leading zeros (`0x` for zero). Eth wallets are strict
/// about this — `0x00` is invalid where `0x0` is valid.
pub fn hex_u64(n: u64) -> String {
    format!("0x{n:x}")
}

pub fn hex_i64(n: i64) -> String {
    if n < 0 {
        format!("-0x{:x}", -(n + 1) as u64 + 1)
    } else {
        hex_u64(n as u64)
    }
}

/// `0x` + bytes. Always fixed-width (no leading-zero trim) — for
/// addresses, block hashes, transaction hashes.
pub fn hex_bytes(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Parse a quantity (`"0x1a"` etc.). Reject if it doesn't start with `0x`.
pub fn parse_hex_quantity(s: &str) -> Result<u64, RpcError> {
    let stripped = s
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::invalid_params("quantity must start with 0x"))?;
    u64::from_str_radix(stripped, 16)
        .map_err(|e| RpcError::invalid_params(format!("invalid hex quantity: {e}")))
}

/// Parse a `0x…` quantity into the `i64` the block stores use, rejecting
/// values that don't fit `i64`. The old `parse_hex_quantity(..) as i64`
/// silently turned e.g. `0x8000000000000000` into a negative number —
/// see [`resolve_log_block_range`] for why that was a DoS (C2).
fn parse_block_number(s: &str) -> Result<i64, RpcError> {
    i64::try_from(parse_hex_quantity(s)?)
        .map_err(|_| RpcError::invalid_params("block number out of range"))
}

/// Resolve and validate the `[from, to]` block window for the log-query
/// methods. `Ok(None)` means an empty window (`to < from`); `Ok(Some(..))`
/// a valid in-cap window.
///
/// `from`/`to` are parsed as `u64` then *checked* into `i64`. The old
/// `as i64` cast let `fromBlock=0x8000000000000000` become `i64::MIN`;
/// with a positive `toBlock` the span check `to - from` overflowed (debug
/// panic / release wrap), slipped past the 10k cap, and drove a
/// ~9.2e18-iteration scan loop. The span is also computed in `i128` so it
/// can't overflow regardless of inputs. (C2)
fn resolve_log_block_range(
    obj: &serde_json::Map<String, Value>,
    head: i64,
) -> Result<Option<(i64, i64)>, RpcError> {
    fn tag(v: Option<&str>, head: i64) -> Result<i64, RpcError> {
        match v {
            Some("latest") | Some("pending") | Some("safe") | Some("finalized") | None => Ok(head),
            Some("earliest") => Ok(0),
            Some(hex) => parse_block_number(hex),
        }
    }
    let from_block = tag(obj.get("fromBlock").and_then(|v| v.as_str()), head)?;
    let to_block = tag(obj.get("toBlock").and_then(|v| v.as_str()), head)?;
    if to_block < from_block {
        return Ok(None);
    }
    if (to_block as i128 - from_block as i128) > 10_000 {
        return Err(RpcError::invalid_params(
            "block range too large (max 10000)",
        ));
    }
    Ok(Some((from_block, to_block)))
}

/// Parse hex bytes. Accepts `"0xabcd"` and produces `[0xab, 0xcd]`.
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, RpcError> {
    let stripped = s
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::invalid_params("hex string must start with 0x"))?;
    hex::decode(stripped).map_err(|e| RpcError::invalid_params(format!("bad hex: {e}")))
}

/// Parse an Ethereum-style 0x-prefixed 20-byte address. **TRON address
/// note**: TRON addresses are 21 bytes (0x41 prefix + 20-byte hash).
/// The Ethereum-compat layer accepts the 20-byte form (post-prefix
/// bytes) and prepends `0x41` automatically.
pub fn parse_eth_address(s: &str) -> Result<Address, RpcError> {
    let bytes = parse_hex_bytes(s)?;
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf[0] = 0x41;
    match bytes.len() {
        20 => buf[1..].copy_from_slice(&bytes),
        21 if bytes[0] == 0x41 => buf.copy_from_slice(&bytes),
        n => {
            return Err(RpcError::invalid_params(format!(
                "expected 20- or 21-byte address (got {n} bytes)"
            )))
        }
    }
    Ok(Address::from_raw(buf))
}

// =============================================================================
// web3_*
// =============================================================================

pub fn web3_client_version(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!("tron-goblin/0.0.1"))
}

pub fn web3_sha3(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let s = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("expected one hex-bytes string"))?;
    let bytes = parse_hex_bytes(s)?;
    Ok(json!(hex_bytes(&keccak256(&bytes))))
}

// =============================================================================
// net_*
// =============================================================================

pub fn net_version(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // Per the eth JSON-RPC convention, `net_version` returns the chain
    // id as a *decimal string* (not a hex quantity). Pinned by test.
    Ok(json!(s.chain_id.to_string()))
}

pub fn net_listening(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    // We're a pure RPC server with no P2P listening exposed; report false
    // unless the caller wires a flag through `RpcState` later.
    Ok(json!(false))
}

// =============================================================================
// eth_*
// =============================================================================

pub fn eth_chain_id(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!(hex_u64(s.chain_id)))
}

pub fn eth_protocol_version(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    // Ethereum JSON-RPC's protocolVersion is a magic number that's
    // mostly ignored; java-tron returns "0x41" (TRON's address prefix
    // doubling as a version sentinel). Match that.
    Ok(json!("0x41"))
}

pub fn eth_block_number(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let n = s.dyn_props.latest_block_header_number().unwrap_or(0);
    Ok(json!(hex_i64(n)))
}

pub fn eth_gas_price(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // ENERGY_FEE — sun per energy unit. Defaults to mainnet's current
    // ~210 sun if unset.
    let fee = s.dyn_props.get_long(b"ENERGY_FEE").unwrap_or(210);
    Ok(json!(hex_i64(fee)))
}

pub fn eth_get_balance(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let balance = s
        .accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?
        .map(|a| a.balance)
        .unwrap_or(0);
    Ok(json!(hex_i64(balance)))
}

pub fn eth_get_block_by_number(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let num_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block number"))?;
    let full_txs = p.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    let num: i64 = match num_str {
        "latest" | "pending" => s.dyn_props.latest_block_header_number().unwrap_or(0),
        "earliest" => 0,
        hex => parse_hex_quantity(hex)? as i64,
    };

    let id = match s.block_index.get(num) {
        Ok(id) => id,
        Err(_) => return Ok(Value::Null),
    };
    let block = match s.blocks.get(&id) {
        Ok(b) => b,
        Err(_) => return Ok(Value::Null),
    };
    Ok(encode_block_for_rpc(&id, &block, full_txs))
}

pub fn eth_get_block_by_hash(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block hash"))?;
    let full_txs = p.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    let hash_bytes = parse_hex_bytes(hash_str)?;
    if hash_bytes.len() != 32 {
        return Err(RpcError::invalid_params("block hash must be 32 bytes"));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&hash_bytes);
    let id = tron_types::BlockId::from_raw(buf);
    match s.blocks.get(&id) {
        Ok(block) => Ok(encode_block_for_rpc(&id, &block, full_txs)),
        Err(_) => Ok(Value::Null),
    }
}

/// `eth_getTransactionCount(addr, [block])` — TRON has no transaction
/// nonce, so always return 0. Matches the behaviour of every
/// Ethereum-compatibility shim on TRON-derived chains.
pub fn eth_get_transaction_count(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::String("0x0".to_string()))
}

/// `eth_getCode(addr, [block])` — returns the deployed bytecode for a
/// contract address. The 21-byte TRON address is mapped to its
/// `code_hash` via `AccountStore`, then the bytes are fetched from
/// `CodeStore`. Returns `"0x"` for EOAs and missing contracts.
pub fn eth_get_code(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let Some(code_store) = &s.code else {
        return Ok(Value::String("0x".to_string()));
    };
    let Ok(Some(account)) = s.accounts.get(&addr) else {
        return Ok(Value::String("0x".to_string()));
    };
    if account.code_hash.is_empty() {
        return Ok(Value::String("0x".to_string()));
    }
    match code_store.get(&account.code_hash)? {
        Some(bytecode) => Ok(Value::String(hex_bytes(&bytecode))),
        None => Ok(Value::String("0x".to_string())),
    }
}

/// `eth_getStorageAt(addr, slot, [block])` — read a single 32-byte
/// storage slot for a contract. Falls back to zero on missing entries.
pub fn eth_get_storage_at(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let slot_str = p
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing slot"))?;
    let addr = parse_eth_address(addr_str)?;
    // Slot may be a JSON-RPC "QUANTITY" (`0x0`, odd-length) or a full
    // 32-byte hex value. Normalise by stripping `0x`, left-padding to
    // 64 hex chars, then decoding.
    let stripped = slot_str
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::invalid_params("slot must start with 0x"))?;
    if stripped.len() > 64 {
        return Err(RpcError::invalid_params("slot exceeds 32 bytes"));
    }
    let padded_hex = format!("{:0>64}", stripped);
    let slot_bytes = hex::decode(&padded_hex)
        .map_err(|e| RpcError::invalid_params(format!("bad slot hex: {e}")))?;
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&slot_bytes);

    let Some(storage) = &s.storage else {
        return Ok(Value::String(hex_bytes(&[0u8; 32])));
    };
    // Default to v2 layout — RPC doesn't know about v1 contracts. A
    // sync-aware caller would consult ContractStore to switch, but for
    // a read-only RPC the v2 default matches what new contracts emit.
    let key = tron_chainbase::StorageRowStore::compose_key(&addr, &slot);
    let value = storage.get(&key)?.unwrap_or_else(|| vec![0u8; 32]);
    let mut padded = [0u8; 32];
    let n = value.len().min(32);
    padded[32 - n..].copy_from_slice(&value[value.len() - n..]);
    Ok(Value::String(hex_bytes(&padded)))
}

/// `eth_getBlockTransactionCountByNumber(num)` — number of transactions
/// in a given block by block number.
pub fn eth_get_block_transaction_count_by_number(
    p: &Value,
    s: &RpcState,
) -> Result<Value, RpcError> {
    let num = parse_block_tag_number(p, 0, s)?;
    let Ok(id) = s.block_index.get(num as i64) else {
        return Ok(Value::Null);
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(Value::String(hex_u64(block.transactions.len() as u64)))
}

/// `eth_getBlockTransactionCountByHash(hash)` — number of transactions
/// in a given block by hash.
pub fn eth_get_block_transaction_count_by_hash(
    p: &Value,
    s: &RpcState,
) -> Result<Value, RpcError> {
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block hash"))?;
    let bytes = parse_hex_bytes(hash_str)?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("block hash must be 32 bytes"));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    let id = tron_types::BlockId::from_raw(raw);
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(Value::String(hex_u64(block.transactions.len() as u64)))
}

/// `eth_syncing` — false unless a sync state is wired (we don't track
/// one yet, so always false matches what a fully-synced node would
/// report).
pub fn eth_syncing(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::Bool(false))
}

/// `eth_mining` — TRON is DPoS, no mining. Always false.
pub fn eth_mining(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::Bool(false))
}

/// `eth_hashrate` — likewise zero (DPoS).
pub fn eth_hashrate(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::String("0x0".to_string()))
}

/// `eth_accounts` — the JSON-RPC node doesn't manage private keys.
pub fn eth_accounts(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::Array(vec![]))
}

/// `eth_coinbase` — TRON doesn't surface a coinbase. Return the zero address.
pub fn eth_coinbase(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::String(format!("0x{}", "00".repeat(20))))
}

/// `eth_maxPriorityFeePerGas` — TRON energy isn't EIP-1559; return 0.
pub fn eth_max_priority_fee_per_gas(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::String("0x0".to_string()))
}

/// `eth_feeHistory(blockCount, newestBlock, rewardPercentiles)` —
/// minimal stub that satisfies wallets requesting fee history. Returns
/// zeroed entries for the requested range.
pub fn eth_fee_history(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let count = p
        .get(0)
        .and_then(|v| v.as_str())
        .map(parse_hex_quantity)
        .transpose()?
        .unwrap_or(1)
        .min(1024); // EIP-1559 caps at 1024
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let oldest = head.saturating_sub(count as i64);
    let base_fee: Vec<Value> = (0..=count)
        .map(|_| Value::String("0x0".to_string()))
        .collect();
    let gas_used: Vec<Value> = (0..count).map(|_| Value::String("0x0".to_string())).collect();
    Ok(json!({
        "oldestBlock": hex_i64(oldest),
        "baseFeePerGas": base_fee,
        "gasUsedRatio": gas_used,
        "reward": Value::Null,
    }))
}

/// Resolve a parameter that's either a block-tag string (`"latest"`,
/// `"earliest"`, `"pending"`, `"safe"`, `"finalized"`) or a hex
/// quantity, into an absolute block number.
fn parse_block_tag_number(p: &Value, idx: usize, s: &RpcState) -> Result<u64, RpcError> {
    let raw = p
        .get(idx)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block tag"))?;
    match raw {
        "latest" | "pending" | "safe" | "finalized" => {
            Ok(s.dyn_props.latest_block_header_number().unwrap_or(0) as u64)
        }
        "earliest" => Ok(0),
        other => parse_hex_quantity(other),
    }
}

pub fn eth_get_transaction_by_hash(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx hash"))?;
    let hash_bytes = parse_hex_bytes(hash_str)?;
    if hash_bytes.len() != 32 {
        return Err(RpcError::invalid_params("tx hash must be 32 bytes"));
    }
    let mut tx_id = [0u8; 32];
    tx_id.copy_from_slice(&hash_bytes);

    match s.transactions.get(&tx_id) {
        Ok(Some(tron_chainbase::StoredTransaction::Full(tx))) => Ok(encode_tx_for_rpc(&tx_id, &tx)),
        Ok(Some(tron_chainbase::StoredTransaction::BlockRef(block_num))) => {
            // The full body lives in the BlockStore. Look it up.
            if let Ok(id) = s.block_index.get(block_num) {
                if let Ok(block) = s.blocks.get(&id) {
                    for tx in &block.transactions {
                        if let Some(raw) = &tx.raw_data {
                            let id_bytes = tron_crypto::hash::sha256(&raw.encode_to_vec());
                            if id_bytes == tx_id {
                                return Ok(encode_tx_for_rpc(&tx_id, tx));
                            }
                        }
                    }
                }
            }
            Ok(Value::Null)
        }
        _ => Ok(Value::Null),
    }
}

// =============================================================================
// Encoding helpers
// =============================================================================

fn encode_block_for_rpc(id: &tron_types::BlockId, block: &tron_proto::Block, full_txs: bool) -> Value {
    let header = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref());
    let (number, timestamp, parent_hash, tx_trie_root, witness_address) = match header {
        Some(r) => (
            r.number,
            r.timestamp,
            r.parent_hash.clone(),
            r.tx_trie_root.clone(),
            r.witness_address.clone(),
        ),
        None => (0, 0, Vec::new(), Vec::new(), Vec::new()),
    };
    let transactions = if full_txs {
        Value::Array(
            block
                .transactions
                .iter()
                .map(|tx| {
                    let raw = tx.raw_data.as_ref();
                    let tx_id = raw
                        .map(|r| tron_crypto::hash::sha256(&r.encode_to_vec()))
                        .unwrap_or([0u8; 32]);
                    encode_tx_for_rpc(&tx_id, tx)
                })
                .collect(),
        )
    } else {
        Value::Array(
            block
                .transactions
                .iter()
                .map(|tx| {
                    let raw = tx.raw_data.as_ref();
                    let tx_id = raw
                        .map(|r| tron_crypto::hash::sha256(&r.encode_to_vec()))
                        .unwrap_or([0u8; 32]);
                    json!(hex_bytes(&tx_id))
                })
                .collect(),
        )
    };
    json!({
        "number": hex_i64(number),
        "hash": hex_bytes(id.as_bytes()),
        "parentHash": hex_bytes(&parent_hash),
        "timestamp": hex_i64(timestamp),
        "transactionsRoot": hex_bytes(&tx_trie_root),
        "miner": hex_bytes(&witness_address),
        "transactions": transactions,
        "size": hex_u64(block.encoded_len() as u64),
    })
}

fn encode_tx_for_rpc(tx_id: &[u8; 32], tx: &tron_proto::Transaction) -> Value {
    let raw = tx.raw_data.as_ref();
    let (sender, receiver, value) = if let Some(raw) = raw {
        // Pull the owner_address / to_address / amount from the first contract,
        // if it's a TransferContract. Otherwise leave defaults.
        let first = raw.contract.first();
        if let Some(c) = first {
            if c.r#type == tron_proto::transaction::contract::ContractType::TransferContract as i32
            {
                if let Some(any) = &c.parameter {
                    if let Ok(tc) = tron_proto::TransferContract::decode(any.value.as_slice()) {
                        let mut s = vec![0u8; 21];
                        if tc.owner_address.len() == 21 {
                            s.copy_from_slice(&tc.owner_address);
                        }
                        let mut r = vec![0u8; 21];
                        if tc.to_address.len() == 21 {
                            r.copy_from_slice(&tc.to_address);
                        }
                        (s, r, tc.amount)
                    } else {
                        (Vec::new(), Vec::new(), 0)
                    }
                } else {
                    (Vec::new(), Vec::new(), 0)
                }
            } else {
                (Vec::new(), Vec::new(), 0)
            }
        } else {
            (Vec::new(), Vec::new(), 0)
        }
    } else {
        (Vec::new(), Vec::new(), 0)
    };
    json!({
        "hash": hex_bytes(tx_id),
        "from": hex_bytes(&sender),
        "to": hex_bytes(&receiver),
        "value": hex_i64(value),
        "input": "0x",
    })
}

// =============================================================================
// Additional eth_* read methods
// =============================================================================

/// `net_peerCount` — number of connected peers. We don't track peers
/// at this layer; return 0.
pub fn net_peer_count(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::String("0x0".to_string()))
}

/// `eth_blobBaseFee` — pre-cancun blob fee (EIP-4844); TRON has no
/// concept. Return 0.
pub fn eth_blob_base_fee(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(Value::String("0x0".to_string()))
}

/// `eth_getTransactionByBlockNumberAndIndex` — index-based tx lookup.
pub fn eth_get_transaction_by_block_number_and_index(
    p: &Value,
    s: &RpcState,
) -> Result<Value, RpcError> {
    let num = parse_block_tag_number(p, 0, s)?;
    let idx = p
        .get(1)
        .and_then(|v| v.as_str())
        .map(parse_hex_quantity)
        .transpose()?
        .ok_or_else(|| RpcError::invalid_params("missing index"))?;
    let Ok(id) = s.block_index.get(num as i64) else {
        return Ok(Value::Null);
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    let Some(tx) = block.transactions.get(idx as usize) else {
        return Ok(Value::Null);
    };
    let tx_id_bytes = tx
        .raw_data
        .as_ref()
        .map(|raw| tron_crypto::hash::sha256(&raw.encode_to_vec()))
        .unwrap_or([0u8; 32]);
    Ok(encode_tx_for_rpc(&tx_id_bytes, tx))
}

/// `eth_getTransactionByBlockHashAndIndex` — same as above, but
/// addressed by block hash.
pub fn eth_get_transaction_by_block_hash_and_index(
    p: &Value,
    s: &RpcState,
) -> Result<Value, RpcError> {
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block hash"))?;
    let bytes = parse_hex_bytes(hash_str)?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("block hash must be 32 bytes"));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    let id = tron_types::BlockId::from_raw(raw);
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    let idx = p
        .get(1)
        .and_then(|v| v.as_str())
        .map(parse_hex_quantity)
        .transpose()?
        .ok_or_else(|| RpcError::invalid_params("missing index"))?;
    let Some(tx) = block.transactions.get(idx as usize) else {
        return Ok(Value::Null);
    };
    let tx_id_bytes = tx
        .raw_data
        .as_ref()
        .map(|raw| tron_crypto::hash::sha256(&raw.encode_to_vec()))
        .unwrap_or([0u8; 32]);
    Ok(encode_tx_for_rpc(&tx_id_bytes, tx))
}

// =============================================================================
// TRON wallet/walletsolidity-style methods
// =============================================================================

/// `getAccount(address)` — full Account proto serialized as JSON.
/// Mirrors java-tron's `wallet.getAccount`.
pub fn get_account(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let account = s
        .accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?;
    let genesis_ms = s.dyn_props.genesis_block_timestamp().unwrap_or(0);
    match account {
        Some(mut a) => {
            // java order: importAllAsset (merge asset_v2) THEN updateUsage (decay).
            if let Some(store) = &s.account_assets {
                merge_account_assets(&mut a, store);
            }
            apply_read_usage_recovery(&mut a, &s.dyn_props);
            Ok(encode_account_for_rpc(&a, genesis_ms))
        }
        None => Ok(Value::Null),
    }
}

/// `getNowBlock` — most recent block, full transactions inlined.
pub fn get_now_block(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let Ok(id) = s.block_index.get(head) else {
        return Ok(Value::Null);
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(encode_block_for_rpc(&id, &block, true))
}

/// `getBlockByNum(num)` — TRON-style block fetch (always full txs).
pub fn get_block_by_num(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let num = p
        .get(0)
        .and_then(|v| v.as_i64())
        .or_else(|| {
            p.get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
        })
        .ok_or_else(|| RpcError::invalid_params("missing block number"))?;
    let Ok(id) = s.block_index.get(num) else {
        return Ok(Value::Null);
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(encode_block_for_rpc(&id, &block, true))
}

/// `getChainParameters` — every entry in `DynamicPropertiesStore` that
/// has a long value, returned as a `{key, value}` pair list. Mirrors
/// java-tron's `wallet.getChainParameters`.
pub fn get_chain_parameters(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // Mirrors java-tron's `Wallet.getChainParameters` EXACTLY: the same
    // 75 entries, in the same order, under java's `get…` camelCase names
    // (what TronWeb/TronGrid clients key on). Every entry is emitted even
    // when its value is 0 — but, matching java's proto3 JSON, a zero
    // value omits the `value` field. The third tuple element is java's
    // getter default, used when the key is absent from the DB (a
    // java-imported mainnet DB has virtually all of them).
    const PARAMS: &[(&str, &[u8], i64)] = &[
        ("getMaintenanceTimeInterval", b"MAINTENANCE_TIME_INTERVAL", 0),
        ("getAccountUpgradeCost", b"ACCOUNT_UPGRADE_COST", 0),
        ("getCreateAccountFee", b"CREATE_ACCOUNT_FEE", 0),
        ("getTransactionFee", b"TRANSACTION_FEE", 0),
        ("getAssetIssueFee", b"ASSET_ISSUE_FEE", 0),
        ("getWitnessPayPerBlock", b"WITNESS_PAY_PER_BLOCK", 0),
        ("getWitnessStandbyAllowance", b"WITNESS_STANDBY_ALLOWANCE", 0),
        (
            "getCreateNewAccountFeeInSystemContract",
            b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT",
            0,
        ),
        ("getCreateNewAccountBandwidthRate", b"CREATE_NEW_ACCOUNT_BANDWIDTH_RATE", 0),
        ("getAllowCreationOfContracts", b"ALLOW_CREATION_OF_CONTRACTS", 0),
        ("getRemoveThePowerOfTheGr", b"REMOVE_THE_POWER_OF_THE_GR", 0),
        ("getEnergyFee", b"ENERGY_FEE", 0),
        ("getExchangeCreateFee", b"EXCHANGE_CREATE_FEE", 0),
        ("getMaxCpuTimeOfOneTx", b"MAX_CPU_TIME_OF_ONE_TX", 0),
        ("getAllowUpdateAccountName", b"ALLOW_UPDATE_ACCOUNT_NAME", 0),
        // Leading space: java's canonical key typo.
        ("getAllowSameTokenName", b" ALLOW_SAME_TOKEN_NAME", 0),
        ("getAllowDelegateResource", b"ALLOW_DELEGATE_RESOURCE", 0),
        ("getTotalEnergyLimit", b"TOTAL_ENERGY_LIMIT", 0),
        ("getAllowTvmTransferTrc10", b"ALLOW_TVM_TRANSFER_TRC10", 0),
        ("getTotalEnergyCurrentLimit", b"TOTAL_ENERGY_CURRENT_LIMIT", 0),
        ("getAllowMultiSign", b"ALLOW_MULTI_SIGN", 0),
        ("getAllowAdaptiveEnergy", b"ALLOW_ADAPTIVE_ENERGY", 0),
        ("getTotalEnergyTargetLimit", b"TOTAL_ENERGY_TARGET_LIMIT", 0),
        ("getTotalEnergyAverageUsage", b"TOTAL_ENERGY_AVERAGE_USAGE", 0),
        ("getUpdateAccountPermissionFee", b"UPDATE_ACCOUNT_PERMISSION_FEE", 0),
        ("getMultiSignFee", b"MULTI_SIGN_FEE", 0),
        ("getAllowAccountStateRoot", b"ALLOW_ACCOUNT_STATE_ROOT", 0),
        ("getAllowProtoFilterNum", b"ALLOW_PROTO_FILTER_NUM", 0),
        ("getAllowTvmConstantinople", b"ALLOW_TVM_CONSTANTINOPLE", 0),
        ("getAllowTvmSolidity059", b"ALLOW_TVM_SOLIDITY_059", 0),
        ("getAllowTvmIstanbul", b"ALLOW_TVM_ISTANBUL", 0),
        ("getAllowShieldedTRC20Transaction", b"ALLOW_SHIELDED_TRC20_TRANSACTION", 0),
        ("getForbidTransferToContract", b"FORBID_TRANSFER_TO_CONTRACT", 0),
        // Stored SCALED (`24 * 60 * ratio`, java ProposalService); the
        // getter-facing value divides back out — handled below.
        (
            "getAdaptiveResourceLimitTargetRatio",
            b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO",
            14_400,
        ),
        (
            "getAdaptiveResourceLimitMultiplier",
            b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER",
            1000,
        ),
        ("getChangeDelegation", b"CHANGE_DELEGATION", 0),
        ("getWitness127PayPerBlock", b"WITNESS_127_PAY_PER_BLOCK", 0),
        ("getAllowMarketTransaction", b"ALLOW_MARKET_TRANSACTION", 0),
        ("getMarketSellFee", b"MARKET_SELL_FEE", 0),
        ("getMarketCancelFee", b"MARKET_CANCEL_FEE", 0),
        ("getAllowPBFT", b"ALLOW_PBFT", 0),
        ("getAllowTransactionFeePool", b"ALLOW_TRANSACTION_FEE_POOL", 0),
        ("getMaxFeeLimit", b"MAX_FEE_LIMIT", 0),
        ("getAllowOptimizeBlackHole", b"ALLOW_BLACKHOLE_OPTIMIZATION", 0),
        ("getAllowNewResourceModel", b"ALLOW_NEW_RESOURCE_MODEL", 0),
        ("getAllowTvmFreeze", b"ALLOW_TVM_FREEZE", 0),
        ("getAllowTvmVote", b"ALLOW_TVM_VOTE", 0),
        ("getAllowTvmLondon", b"ALLOW_TVM_LONDON", 0),
        ("getAllowTvmCompatibleEvm", b"ALLOW_TVM_COMPATIBLE_EVM", 0),
        ("getAllowAccountAssetOptimization", b"ALLOW_ACCOUNT_ASSET_OPTIMIZATION", 0),
        ("getFreeNetLimit", b"FREE_NET_LIMIT", 0),
        ("getTotalNetLimit", b"TOTAL_NET_LIMIT", 0),
        (
            "getAllowHigherLimitForMaxCpuTimeOfOneTx",
            b"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
            0,
        ),
        ("getAllowAssetOptimization", b"ALLOW_ASSET_OPTIMIZATION", 0),
        ("getAllowNewReward", b"ALLOW_NEW_REWARD", 0),
        ("getMemoFee", b"MEMO_FEE", 0),
        ("getAllowDelegateOptimization", b"ALLOW_DELEGATE_OPTIMIZATION", 0),
        ("getUnfreezeDelayDays", b"UNFREEZE_DELAY_DAYS", 0),
        (
            "getAllowOptimizedReturnValueOfChainId",
            b"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID",
            0,
        ),
        ("getAllowDynamicEnergy", b"ALLOW_DYNAMIC_ENERGY", 0),
        ("getDynamicEnergyThreshold", b"DYNAMIC_ENERGY_THRESHOLD", 0),
        ("getDynamicEnergyIncreaseFactor", b"DYNAMIC_ENERGY_INCREASE_FACTOR", 0),
        ("getDynamicEnergyMaxFactor", b"DYNAMIC_ENERGY_MAX_FACTOR", 0),
        ("getAllowTvmShangHai", b"ALLOW_TVM_SHANGHAI", 0),
        ("getAllowCancelAllUnfreezeV2", b"ALLOW_CANCEL_ALL_UNFREEZE_V2", 0),
        ("getMaxDelegateLockPeriod", b"MAX_DELEGATE_LOCK_PERIOD", 0),
        ("getAllowOldRewardOpt", b"ALLOW_OLD_REWARD_OPT", 0),
        ("getAllowEnergyAdjustment", b"ALLOW_ENERGY_ADJUSTMENT", 0),
        // java getter default (`CommonParameter.maxCreateAccountTxSize`).
        ("getMaxCreateAccountTxSize", b"MAX_CREATE_ACCOUNT_TX_SIZE", 1000),
        ("getAllowStrictMath", b"ALLOW_STRICT_MATH", 0),
        ("getConsensusLogicOptimization", b"CONSENSUS_LOGIC_OPTIMIZATION", 0),
        ("getAllowTvmCancun", b"ALLOW_TVM_CANCUN", 0),
        ("getAllowTvmBlob", b"ALLOW_TVM_BLOB", 0),
        (
            "getAllowTvmSelfdestructRestriction",
            b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION",
            0,
        ),
        ("getProposalExpireTime", b"PROPOSAL_EXPIRE_TIME", 259_200_000),
    ];
    let entries: Vec<Value> = PARAMS
        .iter()
        .map(|(name, key, default)| {
            let mut v = s.dyn_props.get_long(key).unwrap_or(*default);
            // java's Wallet divides the stored scaled ratio back to the
            // proposal-facing value (10), `24 * 60` periods per day.
            if *name == "getAdaptiveResourceLimitTargetRatio" {
                v /= 24 * 60;
            }
            if v == 0 {
                json!({ "key": name })
            } else {
                json!({ "key": name, "value": v })
            }
        })
        .collect();
    Ok(json!({ "chainParameter": entries }))
}

/// `listWitnesses` — every entry in `WitnessStore`.
pub fn list_witnesses(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(ws) = &s.witnesses else {
        return Ok(json!({ "witnesses": [] }));
    };
    let all = ws
        .all()
        .map_err(|e| RpcError::internal(format!("witness scan: {e}")))?;
    let witnesses: Vec<Value> = all
        .into_iter()
        .map(|(addr, w)| {
            json!({
                "address": hex_bytes(addr.as_bytes()),
                "voteCount": w.vote_count,
                "url": w.url,
                "totalProduced": w.total_produced,
                "totalMissed": w.total_missed,
                "latestBlockNum": w.latest_block_num,
                "latestSlotNum": w.latest_slot_num,
                "isJobs": w.is_jobs,
            })
        })
        .collect();
    Ok(json!({ "witnesses": witnesses }))
}

/// `getDelegatedResource(from, to)` — v1 delegation snapshot.
pub fn get_delegated_resource(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(dr) = &s.delegated_resources else {
        return Ok(Value::Null);
    };
    let from_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing from address"))?;
    let to_str = p
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing to address"))?;
    let from = parse_eth_address(from_str)?;
    let to = parse_eth_address(to_str)?;
    let key = tron_chainbase::DelegatedResourceStore::v1_key(&from, &to);
    match dr.get_raw(&key) {
        Ok(Some(r)) => Ok(json!({
            "from": hex_bytes(&r.from),
            "to": hex_bytes(&r.to),
            "frozenBalanceForBandwidth": r.frozen_balance_for_bandwidth,
            "frozenBalanceForEnergy": r.frozen_balance_for_energy,
            "expireTimeForBandwidth": r.expire_time_for_bandwidth,
            "expireTimeForEnergy": r.expire_time_for_energy,
        })),
        _ => Ok(Value::Null),
    }
}

/// `getBrokerage(witness_address)` — witness's brokerage percentage
/// (0..=100). Default 20% when unset.
pub fn get_brokerage(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing witness address"))?;
    let addr = parse_eth_address(addr_str)?;
    let Some(d) = &s.delegation else {
        return Ok(json!(20));
    };
    let brokerage = d.get_brokerage_global(&addr);
    Ok(json!(brokerage))
}

/// `getReward(address)` — `MortgageService.queryReward` over the live
/// stores. Returns the total claimable reward (allowance + un-claimed
/// vote-based earnings).
pub fn get_reward(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let Some(d) = &s.delegation else {
        return Ok(json!(0));
    };
    let reward =
        tron_tvm::reward::query_reward_actuator(&addr, &s.accounts, d, &s.dyn_props, s.reward_vi.as_deref())
        .map_err(|e| RpcError::internal(format!("reward read: {e}")))?;
    Ok(json!(reward))
}

/// `getBurnTrx` — total amount of TRX burned by the chain, as tracked
/// in `DynamicPropertiesStore` under `BURN_TRX_AMOUNT`. java wraps the
/// value in `{"burnTrxAmount": n}` (`NumberMessage` JSON), not a bare
/// number.
pub fn get_burn_trx(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({
        "burnTrxAmount": s.dyn_props.get_long(b"BURN_TRX_AMOUNT").unwrap_or(0)
    }))
}

/// `listProposals` — every entry in `ProposalStore`, sorted by id.
pub fn list_proposals(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(ps) = &s.proposals else {
        return Ok(json!({ "proposals": [] }));
    };
    let mut all = ps
        .all()
        .map_err(|e| RpcError::internal(format!("proposal scan: {e}")))?;
    all.sort_by_key(|(id, _)| *id);
    let proposals: Vec<Value> = all
        .into_iter()
        .map(|(id, p)| {
            json!({
                "proposalId": id,
                "proposerAddress": hex_bytes(&p.proposer_address),
                "parameters": p.parameters.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
                "expirationTime": p.expiration_time,
                "createTime": p.create_time,
                "approvalsCount": p.approvals.len(),
                "state": p.state,
            })
        })
        .collect();
    Ok(json!({ "proposals": proposals }))
}

/// `getAssetIssueById(id)` — fetch a TRC-10 asset by its 64-bit id.
pub fn get_asset_issue_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(assets) = &s.assets_v2 else {
        return Ok(Value::Null);
    };
    let id = p
        .get(0)
        .and_then(|v| v.as_i64())
        .or_else(|| {
            p.get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
        })
        .ok_or_else(|| RpcError::invalid_params("missing asset id"))?;
    match assets.get(id) {
        Ok(Some(a)) => Ok(json!({
            "id": a.id,
            "ownerAddress": hex_bytes(&a.owner_address),
            "name": String::from_utf8_lossy(&a.name).to_string(),
            "abbr": String::from_utf8_lossy(&a.abbr).to_string(),
            "totalSupply": a.total_supply,
            "trxNum": a.trx_num,
            "num": a.num,
            "startTime": a.start_time,
            "endTime": a.end_time,
            "precision": a.precision,
        })),
        _ => Ok(Value::Null),
    }
}

/// `getExchangeById(id)` — DEX exchange snapshot.
pub fn get_exchange_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(ex) = &s.exchanges_v2 else {
        return Ok(Value::Null);
    };
    let id = p
        .get(0)
        .and_then(|v| v.as_i64())
        .or_else(|| {
            p.get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
        })
        .ok_or_else(|| RpcError::invalid_params("missing exchange id"))?;
    match ex.get(id) {
        Ok(Some(e)) => Ok(json!({
            "exchangeId": e.exchange_id,
            "creatorAddress": hex_bytes(&e.creator_address),
            "createTime": e.create_time,
            "firstTokenId": String::from_utf8_lossy(&e.first_token_id).to_string(),
            "firstTokenBalance": e.first_token_balance,
            "secondTokenId": String::from_utf8_lossy(&e.second_token_id).to_string(),
            "secondTokenBalance": e.second_token_balance,
        })),
        _ => Ok(Value::Null),
    }
}

/// `getNodeInfo` — minimal node identity. Java-tron returns a large
/// blob; we return chain id, head block number, and the client
/// version so wallets that probe it get a reasonable response.
pub fn get_node_info(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({
        "configNodeInfo": {
            "p2pVersion": "0",
            "versionCode": "tron-goblin/0.0.1",
        },
        "block": {
            "number": s.dyn_props.latest_block_header_number().unwrap_or(0),
            "timestamp": s.dyn_props.latest_block_header_timestamp().unwrap_or(0),
        },
        "machineInfo": {},
        "activeConnectCount": 0,
        "currentConnectCount": 0,
        "passiveConnectCount": 0,
        "totalFlow": 0,
    }))
}

/// `/monitor/getstatsinfo` — operational snapshot for dashboards.
/// Mirrors java-tron's `MetricsInfo` top-level shape (interval, node,
/// blockchain, net). Returns whatever we can populate from
/// `RpcState.metrics` + `dyn_props`; absent fields default to zero
/// rather than being omitted so the schema is stable.
pub fn get_stats_info(_p: &Value, s: &RpcState) -> Value {
    let interval = s
        .metrics
        .as_ref()
        .map(|m| m.uptime_secs() as i64)
        .unwrap_or(0);
    let head_num = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let head_ts = s.dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let solid = s
        .dyn_props
        .latest_solidified_block_num()
        .unwrap_or(0);
    let (blocks_applied, blocks_rejected_validation, blocks_rejected_execution, peer_failures, rpc_total, rate_limited) =
        match s.metrics.as_ref() {
            Some(m) => (
                m.sync_blocks_applied(),
                m.sync_blocks_rejected_validation(),
                m.sync_blocks_rejected_execution(),
                m.sync_peer_failures(),
                m.rpc_requests_total(),
                m.p2p_rate_limited(),
            ),
            None => (0, 0, 0, 0, 0, 0),
        };
    json!({
        "interval": interval,
        "node": {
            "ip": "",
            "nodeType": 0,
            "version": "tron-goblin/0.0.1",
            "hostname": "",
        },
        "blockchain": {
            "headBlockNum": head_num,
            "headBlockTimestamp": head_ts,
            "solidifiedBlockNum": solid,
            "blocksApplied": blocks_applied,
            "blocksRejectedValidation": blocks_rejected_validation,
            "blocksRejectedExecution": blocks_rejected_execution,
        },
        "net": {
            "peerFailures": peer_failures,
            "rpcRequestsTotal": rpc_total,
            "p2pRateLimited": rate_limited,
        },
    })
}

/// `getBandwidthPrices` / `getEnergyPrices` — TRON's historic price
/// schedule, served verbatim from the persisted `*_PRICE_HISTORY`
/// strings (`unix_ms:price` pairs, comma-joined; appended by every
/// price-change proposal since genesis). Fabricating `0:current`
/// (the previous behaviour) hid the whole schedule from clients that
/// compute historic fees from it.
pub fn get_bandwidth_prices(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({ "prices": s.dyn_props.bandwidth_price_history() }))
}

pub fn get_energy_prices(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({ "prices": s.dyn_props.energy_price_history() }))
}

// =============================================================================
// Account-encoding helper
// =============================================================================

/// Render an [`Account`] in java-tron's `wallet/getaccount` JSON shape.
///
/// Matches java-tron's protobuf `JsonFormat`: the **proto field names**
/// verbatim (snake_case for most, camelCase for the proto's `frozenV2` /
/// `assetV2` / `…frozenV2…` / `codeHash` fields), default-valued fields
/// **omitted**, nested messages (`account_resource`, permissions) rendered
/// recursively, and map fields rendered as `[{key, value}]` arrays. Bytes are
/// hex; address-bearing fields (`address`, `vote_address`, permission key
/// `address`) are rewritten to base58 by `http_rest::rewrite_addresses` when
/// `visible=true`. `account_name` / `asset_issued_name` / `asset_issued_ID`
/// render as text, as java-tron does.
///
/// (The previous encoder emitted an ETH-style camelCase/`0x`-hex subset,
/// which diverged from java-tron on ~every field — caught by `tron-state-diff`.)
/// Convert a stored resource-consume *slot* to the wall-clock millisecond
/// timestamp java-tron's `Wallet.getAccount` emits: `genesis + 3000 * slot`
/// (java-tron `Wallet.java`). We store `latest_consume_time(_for_energy)` /
/// `latest_consume_free_time` as slots (`(blockTs - genesis)/3000`, matching
/// java's internal `getHeadSlot()`), but java rewrites them to ms on RPC
/// output — so we must too, or the field reads ~3000x too small.
fn consume_slot_to_ms(slot: i64, genesis_ms: i64) -> i64 {
    const BLOCK_PRODUCED_INTERVAL_MS: i64 = 3_000;
    genesis_ms + BLOCK_PRODUCED_INTERVAL_MS * slot
}

/// java-tron's `Wallet.getAccount` decays the stored usage counters at read
/// time — `BandwidthProcessor.updateUsage` / `EnergyProcessor.updateUsage`
/// recover `net_usage` / `free_net_usage` / `energy_usage` toward 0 over the
/// elapsed window BEFORE returning the account. We store the raw
/// post-last-consume value, so without this the RPC reports stale usage where
/// java reports the decayed value (usually 0). Mirrors java exactly: net +
/// energy use the account-windowed recovery, free-net the default window;
/// `latest_consume_time*` is left untouched (its ms conversion happens later
/// in the serializer). Per-asset free-net usage maps are part of the deferred
/// asset-optimization work and are not decayed here.
fn apply_read_usage_recovery(
    account: &mut tron_proto::Account,
    dp: &tron_chainbase::DynamicPropertiesStore,
) {
    use tron_executor::resource::{increase_default, recovery_account, ResourceKind};
    let now_slot = dp.head_slot();
    let net = recovery_account(
        account,
        ResourceKind::Bandwidth,
        account.net_usage,
        account.latest_consume_time,
        now_slot,
        dp.allow_harden_resource_calculation(),
    );
    let free_net =
        increase_default(account.free_net_usage, 0, account.latest_consume_free_time, now_slot);
    // Read energy fields out first so the recovery borrow doesn't overlap the
    // later mutable write-back.
    let energy_in = account
        .account_resource
        .as_ref()
        .map(|r| (r.energy_usage, r.latest_consume_time_for_energy));
    let energy = energy_in
        .map(|(eu, lt)| recovery_account(account, ResourceKind::Energy, eu, lt, now_slot, dp.allow_harden_resource_calculation()));
    account.net_usage = net;
    account.free_net_usage = free_net;
    if let (Some(e), Some(r)) = (energy, account.account_resource.as_mut()) {
        r.energy_usage = e;
    }

    // Per-asset free-net usage (java updateUsage's V2 asset loop): materialize
    // one decayed `free_asset_net_usageV2` entry per asset (run AFTER the
    // asset_v2 merge so the merged balances drive the key set).
    let asset_usage = materialized_asset_net_usage(account, now_slot);
    if !asset_usage.is_empty() {
        account.free_asset_net_usage_v2 = asset_usage;
    }
}

/// Materialize the per-asset `free_asset_net_usageV2` map java's `updateUsage`
/// produces: one decayed entry for every asset the account holds (its merged
/// `asset_v2` keys) ∪ any existing usage key, recovered (default window) via
/// that asset's `latest_asset_operation_timeV2`. Assets never used for free
/// bandwidth still get a (zero) entry, matching java.
fn materialized_asset_net_usage(
    account: &tron_proto::Account,
    now_slot: i64,
) -> std::collections::BTreeMap<String, i64> {
    use tron_executor::resource::increase_default;
    let mut keys: std::collections::BTreeSet<String> = account.asset_v2.keys().cloned().collect();
    keys.extend(account.free_asset_net_usage_v2.keys().cloned());
    let mut out = std::collections::BTreeMap::new();
    for k in keys {
        let old = account.free_asset_net_usage_v2.get(&k).copied().unwrap_or(0);
        let last = account.latest_asset_operation_time_v2.get(&k).copied().unwrap_or(0);
        out.insert(k, increase_default(old, 0, last, now_slot));
    }
    out
}

/// java-tron's `AssetUtil.importAllAsset`: when an account is asset-optimized,
/// merge its TRC10 balances out of the `account-asset` store back into the
/// `asset_v2` map (store rows first, then inline entries override — matching
/// java's `getAllAssets` then `getAssetV2Map().forEach(put)`). No-op for
/// non-optimized accounts (their balances are already inline) and when the
/// store isn't attached.
fn merge_account_assets(
    account: &mut tron_proto::Account,
    store: &tron_chainbase::AccountAssetStore,
) {
    // Single source of truth lives on the store (shared with the consensus
    // actuator path via tron_chainbase::import_all_asset).
    store.import_all_asset(account);
}

fn encode_account_for_rpc(a: &tron_proto::Account, genesis_ms: i64) -> Value {
    use serde_json::Map;
    let mut m = Map::new();

    // address is always present (rewritten to base58 by the http layer).
    m.insert("address".into(), json!(hex_bytes(&a.address)));
    let put = |m: &mut Map<String, Value>, k: &str, present: bool, v: Value| {
        if present {
            m.insert(k.to_string(), v);
        }
    };
    let consume_ms_a = consume_slot_to_ms(a.latest_consume_time, genesis_ms);
    let consume_free_ms = consume_slot_to_ms(a.latest_consume_free_time, genesis_ms);

    if !a.account_name.is_empty() {
        // java's proto3 JsonFormat renders bytes as bare hex (no 0x) with
        // the default `visible=false` (e.g. the Blackhole account's name
        // reads `426c61636b686f6c65`); the readable-text form only appears
        // under `visible=true`, which the HTTP layer's rewrite pass
        // produces.
        m.insert("account_name".into(), json!(hex::encode(&a.account_name)));
    }
    put(&mut m, "type", a.r#type != 0, json!(account_type_name(a.r#type)));
    put(&mut m, "balance", a.balance != 0, json!(a.balance));
    put(&mut m, "create_time", a.create_time != 0, json!(a.create_time));
    put(&mut m, "latest_opration_time", a.latest_opration_time != 0, json!(a.latest_opration_time));
    put(&mut m, "allowance", a.allowance != 0, json!(a.allowance));
    put(&mut m, "latest_withdraw_time", a.latest_withdraw_time != 0, json!(a.latest_withdraw_time));
    put(&mut m, "is_witness", a.is_witness, json!(true));
    put(&mut m, "is_committee", a.is_committee, json!(true));
    put(&mut m, "net_usage", a.net_usage != 0, json!(a.net_usage));
    put(&mut m, "free_net_usage", a.free_net_usage != 0, json!(a.free_net_usage));
    put(&mut m, "latest_consume_time", consume_ms_a != 0, json!(consume_ms_a));
    put(&mut m, "latest_consume_free_time", consume_free_ms != 0, json!(consume_free_ms));
    put(&mut m, "net_window_size", a.net_window_size != 0, json!(a.net_window_size));
    put(&mut m, "net_window_optimized", a.net_window_optimized, json!(true));
    put(&mut m, "asset_optimized", a.asset_optimized, json!(true));
    put(&mut m, "old_tron_power", a.old_tron_power != 0, json!(a.old_tron_power));
    if !a.code_hash.is_empty() {
        m.insert("codeHash".into(), json!(hex::encode(&a.code_hash)));
    }
    if !a.account_id.is_empty() {
        m.insert("account_id".into(), json!(hex::encode(&a.account_id)));
    }
    if !a.asset_issued_name.is_empty() {
        m.insert("asset_issued_name".into(), json!(String::from_utf8_lossy(&a.asset_issued_name)));
    }
    if !a.asset_issued_id.is_empty() {
        m.insert("asset_issued_ID".into(), json!(String::from_utf8_lossy(&a.asset_issued_id)));
    }

    // Delegated / acquired bandwidth balances (v1 + v2).
    put(&mut m, "acquired_delegated_frozen_balance_for_bandwidth",
        a.acquired_delegated_frozen_balance_for_bandwidth != 0,
        json!(a.acquired_delegated_frozen_balance_for_bandwidth));
    put(&mut m, "delegated_frozen_balance_for_bandwidth",
        a.delegated_frozen_balance_for_bandwidth != 0,
        json!(a.delegated_frozen_balance_for_bandwidth));
    put(&mut m, "acquired_delegated_frozenV2_balance_for_bandwidth",
        a.acquired_delegated_frozen_v2_balance_for_bandwidth != 0,
        json!(a.acquired_delegated_frozen_v2_balance_for_bandwidth));
    put(&mut m, "delegated_frozenV2_balance_for_bandwidth",
        a.delegated_frozen_v2_balance_for_bandwidth != 0,
        json!(a.delegated_frozen_v2_balance_for_bandwidth));

    // Frozen / vote arrays.
    if !a.frozen.is_empty() {
        m.insert("frozen".into(), json!(a.frozen.iter().map(frozen_json).collect::<Vec<_>>()));
    }
    // java-tron's `Wallet.sortFrozenV2List`: getAccount ALWAYS returns one
    // FreezeV2 entry per ResourceCode (BANDWIDTH, ENERGY, TRON_POWER) in that
    // order, padding absent resources with amount 0 — an unconditional RPC
    // presentation step (the stored list only carries actually-frozen
    // resources). Emit it the same way so the field matches byte-for-byte.
    m.insert("frozenV2".into(), json!(normalized_frozen_v2_json(a)));
    if !a.frozen_supply.is_empty() {
        m.insert("frozen_supply".into(), json!(a.frozen_supply.iter().map(frozen_json).collect::<Vec<_>>()));
    }
    if let Some(tp) = &a.tron_power {
        if tp.frozen_balance != 0 || tp.expire_time != 0 {
            m.insert("tron_power".into(), frozen_json(tp));
        }
    }
    if !a.votes.is_empty() {
        m.insert("votes".into(), json!(a.votes.iter().map(vote_json).collect::<Vec<_>>()));
    }

    // Map fields → [{key, value}] arrays (java-tron's rendering).
    if !a.asset_v2.is_empty() {
        m.insert("assetV2".into(), kv_array(&a.asset_v2));
    }
    if !a.free_asset_net_usage_v2.is_empty() {
        m.insert("free_asset_net_usageV2".into(), kv_array(&a.free_asset_net_usage_v2));
    }
    if !a.latest_asset_operation_time_v2.is_empty() {
        m.insert("latest_asset_operation_timeV2".into(), kv_array(&a.latest_asset_operation_time_v2));
    }

    // Permissions.
    if let Some(p) = &a.owner_permission {
        m.insert("owner_permission".into(), permission_json(p));
    }
    if let Some(p) = &a.witness_permission {
        m.insert("witness_permission".into(), permission_json(p));
    }
    if !a.active_permission.is_empty() {
        m.insert("active_permission".into(), json!(a.active_permission.iter().map(permission_json).collect::<Vec<_>>()));
    }

    // Nested energy/storage block.
    if let Some(r) = &a.account_resource {
        let ar = account_resource_json(r, genesis_ms);
        if ar.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
            m.insert("account_resource".into(), ar);
        }
    }

    Value::Object(m)
}

fn account_type_name(t: i32) -> &'static str {
    match t {
        1 => "AssetIssue",
        2 => "Contract",
        _ => "Normal",
    }
}

fn resource_code_name(t: i32) -> &'static str {
    match t {
        1 => "ENERGY",
        2 => "TRON_POWER",
        _ => "BANDWIDTH",
    }
}

fn permission_type_name(t: i32) -> &'static str {
    match t {
        1 => "Witness",
        2 => "Active",
        _ => "Owner",
    }
}

fn frozen_json(f: &tron_proto::account::Frozen) -> Value {
    let mut m = serde_json::Map::new();
    if f.frozen_balance != 0 {
        m.insert("frozen_balance".into(), json!(f.frozen_balance));
    }
    if f.expire_time != 0 {
        m.insert("expire_time".into(), json!(f.expire_time));
    }
    Value::Object(m)
}

fn freeze_v2_json(f: &tron_proto::account::FreezeV2) -> Value {
    let mut m = serde_json::Map::new();
    if f.r#type != 0 {
        m.insert("type".into(), json!(resource_code_name(f.r#type)));
    }
    if f.amount != 0 {
        m.insert("amount".into(), json!(f.amount));
    }
    Value::Object(m)
}

/// java-tron's `Wallet.sortFrozenV2List`: one `FreezeV2` per ResourceCode in
/// canonical order (BANDWIDTH=0, ENERGY=1, TRON_POWER=2; UNRECOGNIZED skipped),
/// carrying the stored amount for that resource or 0 if absent. Always three
/// entries, regardless of what's actually frozen. (Proto form — the single
/// source of truth; the JSON serializer maps it through `freeze_v2_json`.)
fn padded_frozen_v2(a: &tron_proto::Account) -> Vec<tron_proto::account::FreezeV2> {
    [0_i32, 1, 2]
        .iter()
        .map(|&code| {
            let amount = a
                .frozen_v2
                .iter()
                .find(|f| f.r#type == code)
                .map(|f| f.amount)
                .unwrap_or(0);
            tron_proto::account::FreezeV2 { r#type: code, amount }
        })
        .collect()
}

fn normalized_frozen_v2_json(a: &tron_proto::Account) -> Vec<Value> {
    padded_frozen_v2(a).iter().map(freeze_v2_json).collect()
}

/// Apply java-tron's `Wallet.getAccount` read-time transforms to `account`
/// IN PLACE, on the proto: `importAllAsset` (merge optimized TRC10 balances),
/// `updateUsage` (decay net/free/energy usage + materialize per-asset free-net
/// usage), the slot→ms rewrite of the consume-time fields, and
/// `sortFrozenV2List` (pad `frozenV2` to all three ResourceCodes).
///
/// Used by the **gRPC** getAccount path, which returns the proto directly. The
/// HTTP serializer produces the identical values via its JSON encoder using the
/// same shared helpers, so the two surfaces stay in lock-step.
pub fn apply_get_account_transforms(
    account: &mut tron_proto::Account,
    dyn_props: &tron_chainbase::DynamicPropertiesStore,
    account_assets: Option<&tron_chainbase::AccountAssetStore>,
    genesis_ms: i64,
) {
    if let Some(store) = account_assets {
        store.import_all_asset(account);
    }
    apply_read_usage_recovery(account, dyn_props);
    account.latest_consume_time = consume_slot_to_ms(account.latest_consume_time, genesis_ms);
    account.latest_consume_free_time =
        consume_slot_to_ms(account.latest_consume_free_time, genesis_ms);
    if let Some(r) = account.account_resource.as_mut() {
        r.latest_consume_time_for_energy =
            consume_slot_to_ms(r.latest_consume_time_for_energy, genesis_ms);
    }
    account.frozen_v2 = padded_frozen_v2(account);
}

fn vote_json(v: &tron_proto::Vote) -> Value {
    json!({ "vote_address": hex_bytes(&v.vote_address), "vote_count": v.vote_count })
}

/// Render a `map<string,int64>` proto field as java-tron does: a
/// `[{key, value}]` array. The proto maps decode to `BTreeMap`, so iteration
/// is already key-sorted (deterministic output).
fn kv_array(map: &std::collections::BTreeMap<String, i64>) -> Value {
    json!(map
        .iter()
        .map(|(k, v)| json!({ "key": k, "value": v }))
        .collect::<Vec<_>>())
}

fn permission_json(p: &tron_proto::Permission) -> Value {
    let mut m = serde_json::Map::new();
    if p.r#type != 0 {
        m.insert("type".into(), json!(permission_type_name(p.r#type)));
    }
    if p.id != 0 {
        m.insert("id".into(), json!(p.id));
    }
    if !p.permission_name.is_empty() {
        m.insert("permission_name".into(), json!(p.permission_name));
    }
    if p.threshold != 0 {
        m.insert("threshold".into(), json!(p.threshold));
    }
    if p.parent_id != 0 {
        m.insert("parent_id".into(), json!(p.parent_id));
    }
    if !p.operations.is_empty() {
        m.insert("operations".into(), json!(hex::encode(&p.operations)));
    }
    if !p.keys.is_empty() {
        m.insert(
            "keys".into(),
            json!(p
                .keys
                .iter()
                .map(|k| json!({ "address": hex_bytes(&k.address), "weight": k.weight }))
                .collect::<Vec<_>>()),
        );
    }
    Value::Object(m)
}

fn account_resource_json(r: &tron_proto::account::AccountResource, genesis_ms: i64) -> Value {
    let mut m = serde_json::Map::new();
    let put = |m: &mut serde_json::Map<String, Value>, k: &str, present: bool, v: Value| {
        if present {
            m.insert(k.to_string(), v);
        }
    };
    put(&mut m, "energy_usage", r.energy_usage != 0, json!(r.energy_usage));
    if let Some(f) = &r.frozen_balance_for_energy {
        if f.frozen_balance != 0 || f.expire_time != 0 {
            m.insert("frozen_balance_for_energy".into(), frozen_json(f));
        }
    }
    let consume_energy_ms = consume_slot_to_ms(r.latest_consume_time_for_energy, genesis_ms);
    put(&mut m, "latest_consume_time_for_energy", consume_energy_ms != 0, json!(consume_energy_ms));
    put(&mut m, "acquired_delegated_frozen_balance_for_energy", r.acquired_delegated_frozen_balance_for_energy != 0, json!(r.acquired_delegated_frozen_balance_for_energy));
    put(&mut m, "delegated_frozen_balance_for_energy", r.delegated_frozen_balance_for_energy != 0, json!(r.delegated_frozen_balance_for_energy));
    put(&mut m, "storage_limit", r.storage_limit != 0, json!(r.storage_limit));
    put(&mut m, "storage_usage", r.storage_usage != 0, json!(r.storage_usage));
    put(&mut m, "latest_exchange_storage_time", r.latest_exchange_storage_time != 0, json!(r.latest_exchange_storage_time));
    put(&mut m, "energy_window_size", r.energy_window_size != 0, json!(r.energy_window_size));
    put(&mut m, "delegated_frozenV2_balance_for_energy", r.delegated_frozen_v2_balance_for_energy != 0, json!(r.delegated_frozen_v2_balance_for_energy));
    put(&mut m, "acquired_delegated_frozenV2_balance_for_energy", r.acquired_delegated_frozen_v2_balance_for_energy != 0, json!(r.acquired_delegated_frozen_v2_balance_for_energy));
    put(&mut m, "energy_window_optimized", r.energy_window_optimized, json!(true));
    Value::Object(m)
}

// =============================================================================
// eth_call + eth_estimateGas — read-only TVM execution
// =============================================================================

/// Build a fresh `VmStores` whose every backend is a `SessionBackend`
/// wrapping the live backends. The caller runs the EVM against it and
/// then drops the session — all writes are discarded. Public so other
/// crates (e.g. `tron-grpc`) can stand up the same read-only EVM
/// environment used by `eth_call`.
pub fn build_call_vm_stores(b: &crate::state::EthCallBackends) -> tron_tvm::execute::VmStores {
    use std::sync::Arc;
    use tron_chainbase::{
        AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
        DelegationStore, DynamicPropertiesStore, SessionBackend, StorageRowStore, WitnessStore,
    };
    let session = |be: &Arc<dyn tron_chainbase::KvBackend>| {
        Arc::new(SessionBackend::new(be.clone())) as Arc<dyn tron_chainbase::KvBackend>
    };
    tron_tvm::execute::VmStores {
        accounts: Arc::new(AccountStore::new(session(&b.accounts))),
        code: Arc::new(CodeStore::new(session(&b.code))),
        storage: Arc::new(StorageRowStore::new(session(&b.storage))),
        witnesses: Arc::new(WitnessStore::new(session(&b.witnesses))),
        contract_state: Arc::new(ContractStateStore::new(session(&b.contract_state))),
        dynamic_properties: Arc::new(DynamicPropertiesStore::new(session(&b.dyn_props))),
        delegated_resources: Arc::new(DelegatedResourceStore::new(session(&b.delegated_resources))),
        delegation: Arc::new(DelegationStore::new(session(&b.delegation))),
        block_index: b
            .block_index
            .as_ref()
            .map(|bi| Arc::new(tron_chainbase::BlockIndexStore::new(session(bi)))),
        contracts: Some(Arc::new(ContractStore::new(session(&b.contracts)))),
        // Read-only call paths (`eth_call`, `debug_traceCall`,
        // `triggerConstantContract`) don't exercise VOTEWITNESS —
        // leave `votes` unset so the bridge returns 0 if hit.
        votes: None,
        // Constant calls CAN hit the RewardBalance precompile; the
        // eth-call backends don't carry reward-vi today — acceptable
        // for read-only paths (no consensus impact).
        reward_vi: None,
        // Read-only path: deletions never persist (session discarded).
        abi: None,
    }
}

/// Dispatch a read-only `TriggerSmartContract` through `tron-tvm`. When
/// `state.constant_call_timeout_ms > 0`, routes through
/// `execute_trigger_with_deadline` so the inspector preempts the VM
/// mid-execution if the wall-clock budget elapses. Otherwise routes
/// through `execute_trigger_with_gas_cap` (no deadline overhead).
/// java-tron's `vm.constantCallTimeoutMs` plumbing terminates here.
pub(crate) fn dispatch_constant_trigger(
    s: &RpcState,
    vm_stores: &tron_tvm::execute::VmStores,
    block_env: tron_tvm::execute::VmBlockEnv,
    trigger: &tron_proto::TriggerSmartContract,
    energy_limit: u64,
) -> (tron_tvm::execute::VmOutcome, u64) {
    if s.constant_call_timeout_ms > 0 {
        let timeout_ms = s.constant_call_timeout_ms as u64;
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(timeout_ms);
        let (outcome, _traces, energy_penalty) = tron_tvm::execute::execute_trigger_with_deadline(
            vm_stores,
            block_env,
            trigger,
            energy_limit,
            s.eth_call_gas_cap,
            deadline,
            timeout_ms,
        );
        return (outcome, energy_penalty);
    }
    let (outcome, _traces, energy_penalty) = tron_tvm::execute::execute_trigger_with_gas_cap(
        vm_stores,
        block_env,
        trigger,
        energy_limit,
        s.eth_call_gas_cap,
    );
    (outcome, energy_penalty)
}

/// Decode an `eth_call` "TransactionRequest" JSON-RPC object.
struct EthCallRequest {
    from: [u8; 21],
    to: [u8; 21],
    data: Vec<u8>,
    value: i64,
    gas: u64,
}

fn parse_eth_call_request(p: &Value, gas_cap: u64) -> Result<EthCallRequest, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("missing call object"))?;
    let to_str = obj
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing `to`"))?;
    let to = parse_eth_address(to_str)?.as_bytes().to_owned();
    let mut to_arr = [0u8; 21];
    to_arr.copy_from_slice(&to);

    // `from` is optional; default to a zero-prefix TRON address.
    let from_arr = match obj.get("from").and_then(|v| v.as_str()) {
        Some(s) => {
            let a = parse_eth_address(s)?.as_bytes().to_owned();
            let mut buf = [0u8; 21];
            buf.copy_from_slice(&a);
            buf
        }
        None => {
            let mut buf = [0u8; 21];
            buf[0] = 0x41;
            buf
        }
    };
    let data = match obj.get("data").or_else(|| obj.get("input")).and_then(|v| v.as_str()) {
        Some(s) => parse_hex_bytes(s)?,
        None => Vec::new(),
    };
    let value = obj
        .get("value")
        .and_then(|v| v.as_str())
        .map(parse_hex_quantity)
        .transpose()?
        .unwrap_or(0) as i64;
    // Clamp the caller-supplied gas to the operator-configured
    // `eth_call_gas_cap`. revm's default cap is
    // `eip7825::TX_GAS_LIMIT_CAP` (16_777_216); we override to
    // `gas_cap` per-call so heavy DEX-simulation reads can succeed
    // (java-tron's HTTP `triggerConstantContract` accepts arbitrary
    // fee_limit). Producers / write-path executors keep the default
    // — only this read-only path lifts the cap.
    let default_gas = (gas_cap.saturating_sub(1_000_000)).min(15_000_000);
    let gas = obj
        .get("gas")
        .and_then(|v| v.as_str())
        .map(parse_hex_quantity)
        .transpose()?
        .map(|g| g as u64)
        .unwrap_or(default_gas)
        .min(gas_cap);
    Ok(EthCallRequest {
        from: from_arr,
        to: to_arr,
        data,
        value,
        gas,
    })
}

/// `eth_call(callObject, [blockTag])` — read-only TVM execution.
pub fn eth_call(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal(
            "eth_call not available: server built without EVM call backends",
        ));
    };
    let req = parse_eth_call_request(p, s.eth_call_gas_cap)?;
    let vm_stores = build_call_vm_stores(b);
    let block_number = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let block_timestamp_ms = s.dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number,
        block_timestamp_ms,
    };
    let trigger = tron_proto::TriggerSmartContract {
        owner_address: req.from.to_vec(),
        contract_address: req.to.to_vec(),
        call_value: req.value,
        data: req.data,
        call_token_value: 0,
        token_id: 0,
    };
    let (outcome, _energy_penalty) = dispatch_constant_trigger(s, &vm_stores, block_env, &trigger, req.gas);
    match outcome {
        tron_tvm::execute::VmOutcome::Success { return_data, .. } => {
            Ok(Value::String(hex_bytes(&return_data)))
        }
        tron_tvm::execute::VmOutcome::Revert { return_data, .. } => {
            // Per eth_call convention, revert returns an error object
            // with the revert data so wallets can decode `Error(string)`.
            Err(RpcError {
                code: 3,
                message: format!("execution reverted: 0x{}", hex::encode(&return_data)),
            })
        }
        tron_tvm::execute::VmOutcome::Halt { reason, .. } => Err(RpcError::internal(format!(
            "execution halted: {reason}"
        ))),
        tron_tvm::execute::VmOutcome::CallTokenIgnored { .. } => Err(RpcError::internal(
            "CALLTOKEN at top-level in eth_call is not supported",
        )),
        tron_tvm::execute::VmOutcome::PreflightError(msg) => {
            Err(RpcError::invalid_params(msg))
        }
        tron_tvm::execute::VmOutcome::Timeout { deadline_ms, .. } => Err(RpcError::internal(
            format!("constant call timed out after {deadline_ms}ms"),
        )),
    }
}

/// `eth_estimateGas(callObject, [blockTag])` — run the EVM
/// read-only and return the actual gas consumed (rounded up to the
/// next 1000 for slack). Matches go-ethereum's behaviour closely
/// enough for wallets that use it to size feeLimit.
pub fn eth_estimate_gas(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal(
            "eth_estimateGas not available: server built without EVM call backends",
        ));
    };
    let req = parse_eth_call_request(p, s.eth_call_gas_cap)?;
    let vm_stores = build_call_vm_stores(b);
    let block_number = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let block_timestamp_ms = s.dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number,
        block_timestamp_ms,
    };
    let trigger = tron_proto::TriggerSmartContract {
        owner_address: req.from.to_vec(),
        contract_address: req.to.to_vec(),
        call_value: req.value,
        data: req.data,
        call_token_value: 0,
        token_id: 0,
    };
    let (outcome, _energy_penalty) = dispatch_constant_trigger(s, &vm_stores, block_env, &trigger, req.gas);
    let used = match outcome {
        tron_tvm::execute::VmOutcome::Success { energy_used, .. } => energy_used,
        tron_tvm::execute::VmOutcome::Revert { energy_used, .. }
        | tron_tvm::execute::VmOutcome::Halt { energy_used, .. } => {
            return Err(RpcError::internal(format!(
                "estimate failed (consumed {energy_used} energy)"
            )));
        }
        tron_tvm::execute::VmOutcome::Timeout { deadline_ms, .. } => {
            return Err(RpcError::internal(format!(
                "estimate failed: constant call timed out after {deadline_ms}ms"
            )));
        }
        _ => return Err(RpcError::internal("estimate failed")),
    };
    let padded = used.saturating_add(used / 10); // 10% padding.
    Ok(Value::String(hex_u64(padded.max(21_000))))
}

// =============================================================================
// debug_* / trace_* — EVM-level trace surface
// =============================================================================
//
// Geth's `debug_trace*` family + parity's `trace_*` family. Both
// re-execute a tx/call against the *current* state and surface either
// per-opcode struct logs (default) or a call tree (`callTracer`).
//
// **State-at-block semantics**: a strict implementation traces
// against the chain state *just before* the tx was originally applied.
// We don't have per-tx state snapshots, so we run against current
// state. For pure read-only contracts and contracts that don't
// depend on historical state (the common case for explorers), the
// result is identical. For contracts whose behaviour depends on
// state that changed between the original apply and now, the trace
// will diverge — documented as a known limitation, matches the
// behaviour of every other "lite" EVM tracer.

fn parse_trace_options(p: &Value, idx: usize) -> tron_tvm::tracer::TracerOptions {
    let mut opts = tron_tvm::tracer::TracerOptions::default();
    let Some(Value::Object(obj)) = p.get(idx) else {
        return opts;
    };
    if let Some(Value::String(name)) = obj.get("tracer") {
        if name == "callTracer" {
            opts.call_tracer_only = true;
        }
    }
    if let Some(Value::Bool(b)) = obj.get("disableStack") {
        opts.disable_stack = *b;
    }
    if let Some(Value::Bool(b)) = obj.get("disableMemory") {
        opts.disable_memory = *b;
    }
    if let Some(Value::Bool(b)) = obj.get("disableStorage") {
        opts.disable_storage = *b;
    }
    opts
}

fn render_struct_logs(logs: &[tron_tvm::tracer::StructLog]) -> Value {
    Value::Array(
        logs.iter()
            .map(|l| {
                let stack: Vec<Value> = l
                    .stack
                    .iter()
                    .map(|w| Value::String(format!("0x{:064x}", w)))
                    .collect();
                json!({
                    "pc": l.pc,
                    "op": l.op_name,
                    "gas": l.gas,
                    "gasCost": l.gas_cost,
                    "depth": l.depth,
                    "stack": stack,
                    "error": l.error,
                })
            })
            .collect(),
    )
}

fn render_call_frame(frame: &tron_tvm::tracer::CallFrame) -> Value {
    json!({
        "type": frame.call_type,
        "from": format!("0x{}", hex::encode(frame.from)),
        "to": frame.to.map(|a| format!("0x{}", hex::encode(a))),
        "value": format!("0x{:x}", frame.value),
        "gas": format!("0x{:x}", frame.gas),
        "gasUsed": format!("0x{:x}", frame.gas_used),
        "input": format!("0x{}", hex::encode(&frame.input)),
        "output": format!("0x{}", hex::encode(&frame.output)),
        "error": frame.error,
        "calls": Value::Array(frame.calls.iter().map(render_call_frame).collect()),
    })
}

fn build_trace_for_call(
    s: &RpcState,
    req: &EthCallRequest,
    options: tron_tvm::tracer::TracerOptions,
) -> Result<Value, RpcError> {
    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal(
            "tracer not available: server built without EVM call backends",
        ));
    };
    let vm_stores = build_call_vm_stores(b);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number: s.dyn_props.latest_block_header_number().unwrap_or(0),
        block_timestamp_ms: s.dyn_props.latest_block_header_timestamp().unwrap_or(0),
    };
    let trigger = tron_proto::TriggerSmartContract {
        owner_address: req.from.to_vec(),
        contract_address: req.to.to_vec(),
        call_value: req.value,
        data: req.data.clone(),
        call_token_value: 0,
        token_id: 0,
    };
    let call_tracer_only = options.call_tracer_only;
    let tracer = tron_tvm::tracer::StructLogTracer::new(options);
    let (outcome, _internal, tracer) = tron_tvm::execute::execute_trigger_with_tracer(
        &vm_stores,
        block_env,
        &trigger,
        req.gas,
        s.eth_call_gas_cap,
        tracer,
    );
    let (struct_logs, call_frames) = tracer.into_outputs();
    let gas_used = match &outcome {
        tron_tvm::execute::VmOutcome::Success { energy_used, .. }
        | tron_tvm::execute::VmOutcome::Revert { energy_used, .. }
        | tron_tvm::execute::VmOutcome::Halt { energy_used, .. } => *energy_used,
        _ => 0,
    };
    let (failed, return_value) = match &outcome {
        tron_tvm::execute::VmOutcome::Success { return_data, .. } => {
            (false, hex::encode(return_data))
        }
        tron_tvm::execute::VmOutcome::Revert { return_data, .. } => (true, hex::encode(return_data)),
        _ => (true, String::new()),
    };
    if call_tracer_only {
        // Top-level frame: the tx is itself a CALL. The tracer's
        // call hook DIDN'T fire for the top-level (revm only calls
        // it on nested), so synthesise the outer frame here.
        let outer = json!({
            "type": "CALL",
            "from": format!("0x{}", hex::encode(req.from)),
            "to": format!("0x{}", hex::encode(req.to)),
            "value": format!("0x{:x}", req.value.max(0) as u64),
            "gas": format!("0x{:x}", req.gas),
            "gasUsed": format!("0x{:x}", gas_used),
            "input": format!("0x{}", hex::encode(&req.data)),
            "output": format!("0x{}", return_value),
            "error": if failed { Some("execution failed") } else { None },
            "calls": Value::Array(call_frames.iter().map(render_call_frame).collect()),
        });
        return Ok(outer);
    }
    Ok(json!({
        "gas": gas_used,
        "failed": failed,
        "returnValue": return_value,
        "structLogs": render_struct_logs(&struct_logs),
    }))
}

/// `debug_traceCall(callObj, blockTag, options)` — geth's tracer
/// applied to an arbitrary call. Default tracer = structLogger;
/// pass `{"tracer": "callTracer"}` for the call tree.
pub fn debug_trace_call(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let req = parse_eth_call_request(p, s.eth_call_gas_cap)?;
    // blockTag at index 1 is ignored — we always trace against
    // current state. options at index 2 (or 1 if only 2 args).
    let options_idx = if p.get(2).is_some() { 2 } else { 1 };
    let options = parse_trace_options(p, options_idx);
    build_trace_for_call(s, &req, options)
}

/// `debug_traceTransaction(hash, options)` — fetch the tx by hash,
/// re-execute its first contract through the tracer.
pub fn debug_trace_transaction(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx hash"))?;
    let bytes = parse_hex_bytes(hash_str)?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("tx hash must be 32 bytes"));
    }
    let mut tx_id = [0u8; 32];
    tx_id.copy_from_slice(&bytes);
    let stored = match s.transactions.get(&tx_id) {
        Ok(Some(t)) => t,
        _ => {
            return Err(RpcError::internal(format!(
                "transaction not found in store: 0x{}",
                hex::encode(tx_id)
            )));
        }
    };
    // Resolve the full Transaction: BlockRef ⇒ look the block up and
    // find the tx by id; Full ⇒ we already have it.
    let mut tx_block_num: Option<i64> = None;
    let tx_obj: tron_proto::Transaction = match stored {
        tron_chainbase::StoredTransaction::Full(t) => t,
        tron_chainbase::StoredTransaction::BlockRef(block_num) => {
            tx_block_num = Some(block_num);
            let block_id = s.block_index.get(block_num).map_err(|e| {
                RpcError::internal(format!("block_index lookup failed: {e:?}"))
            })?;
            let block = s.blocks.get(&block_id).map_err(|e| {
                RpcError::internal(format!("block lookup failed: {e:?}"))
            })?;
            block
                .transactions
                .into_iter()
                .find(|tx| {
                    tx.raw_data
                        .as_ref()
                        .map(|raw| {
                            use prost::Message as _;
                            tron_crypto::hash::sha256(&raw.encode_to_vec()) == tx_id
                        })
                        .unwrap_or(false)
                })
                .ok_or_else(|| {
                    RpcError::internal("tx_id present in store but not in referenced block")
                })?
        }
    };
    let raw = tx_obj.raw_data.as_ref().ok_or_else(|| {
        RpcError::internal("stored tx has no raw_data; cannot trace")
    })?;
    let contract = raw.contract.first().ok_or_else(|| {
        RpcError::internal("stored tx has no contracts; cannot trace")
    })?;
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;
    let ty = ContractType::try_from(contract.r#type).map_err(|_| {
        RpcError::internal(format!("unknown contract type {}", contract.r#type))
    })?;
    let parameter = contract.parameter.as_ref().ok_or_else(|| {
        RpcError::internal("stored tx contract has no parameter; cannot trace")
    })?;
    // Only `TriggerSmartContract` is traceable — other contract
    // types don't go through the VM.
    if ty != ContractType::TriggerSmartContract {
        return Err(RpcError::internal(format!(
            "cannot trace non-VM contract type {:?}",
            ty
        )));
    }
    let trigger = tron_proto::TriggerSmartContract::decode(parameter.value.as_slice())
        .map_err(|e| RpcError::internal(format!("decode TriggerSmartContract: {e}")))?;
    let mut req_from = [0u8; 21];
    if trigger.owner_address.len() == 21 {
        req_from.copy_from_slice(&trigger.owner_address);
    }
    let mut req_to = [0u8; 21];
    if trigger.contract_address.len() == 21 {
        req_to.copy_from_slice(&trigger.contract_address);
    }
    let req = EthCallRequest {
        from: req_from,
        to: req_to,
        data: trigger.data,
        value: trigger.call_value,
        gas: s.eth_call_gas_cap,
    };
    let options = parse_trace_options(p, 1);
    // Time-travel: re-execute against the historical state as-of the tx's block
    // BOUNDARY (block_num - 1) via the archive when available — "what did this
    // tx do when it ran", not "re-run it against latest state". Block-boundary
    // granularity (ignores intra-block preceding-tx effects) is exact for the
    // common single-VM-tx-per-target case and is the granularity the archive
    // captures. Falls back to current state when the archive is absent or
    // doesn't cover the height; `tracedAtHeight` reports which state was used
    // (the height, or null = current).
    let (at_state, traced_at): (Option<RpcState>, Option<i64>) =
        match (tx_block_num, s.archive.as_ref()) {
            (Some(n), Some(arch)) if n >= 1 && arch.covers(n - 1) => (
                Some(crate::index_api::state_at_height(s, arch, n - 1)),
                Some(n - 1),
            ),
            _ => (None, None),
        };
    let mut trace = build_trace_for_call(at_state.as_ref().unwrap_or(s), &req, options)?;
    if let Value::Object(ref mut m) = trace {
        m.insert(
            "tracedAtHeight".to_string(),
            traced_at.map(|h| json!(h)).unwrap_or(Value::Null),
        );
    }
    Ok(trace)
}

fn parse_trace_block_param(p: &Value, s: &RpcState) -> Result<Vec<[u8; 32]>, RpcError> {
    // Resolve the block (by number or hash) to its list of
    // contained tx_ids.
    let arg = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block number or hash"))?;
    let bytes = parse_hex_bytes(arg)?;
    let block = if bytes.len() == 32 {
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        s.blocks
            .get(&tron_types::BlockId::from_raw(id))
            .map_err(|e| RpcError::internal(format!("block lookup failed: {e:?}")))?
    } else {
        let num = parse_hex_quantity(arg)? as i64;
        let block_id = s
            .block_index
            .get(num)
            .map_err(|e| RpcError::internal(format!("block_index lookup failed: {e:?}")))?;
        s.blocks
            .get(&block_id)
            .map_err(|e| RpcError::internal(format!("block lookup failed: {e:?}")))?
    };
    Ok(block
        .transactions
        .iter()
        .filter_map(|tx| {
            tx.raw_data.as_ref().map(|r| {
                use prost::Message as _;
                tron_crypto::hash::sha256(&r.encode_to_vec())
            })
        })
        .collect())
}

/// `debug_traceBlockByNumber(num, options)` — trace every VM tx in
/// the block. Returns an array of `{txHash, result}` entries; the
/// `result` field has the same shape as `debug_traceTransaction`.
pub fn debug_trace_block_by_number(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tx_ids = parse_trace_block_param(p, s)?;
    let options_idx = if p.get(1).is_some() { 1 } else { 0 };
    let mut results: Vec<Value> = Vec::with_capacity(tx_ids.len());
    for tx_id in tx_ids {
        // Per-tx trace re-uses debug_trace_transaction's lookup; we
        // synthesise the JSON param to reuse the impl.
        let params = json!([format!("0x{}", hex::encode(tx_id)), p.get(options_idx).cloned().unwrap_or(Value::Null)]);
        let trace = debug_trace_transaction(&params, s);
        results.push(json!({
            "txHash": format!("0x{}", hex::encode(tx_id)),
            "result": match trace {
                Ok(v) => v,
                Err(e) => Value::String(e.message),
            },
        }));
    }
    Ok(Value::Array(results))
}

/// `debug_traceBlockByHash(hash, options)` — same as
/// `debug_traceBlockByNumber` but resolves by block hash.
pub fn debug_trace_block_by_hash(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    debug_trace_block_by_number(p, s)
}

// =============================================================================
// trace_* (parity namespace)
// =============================================================================
//
// Parity's `trace_*` family is a more compact view: each frame is a
// flat object with `action`, `result`, and `traceAddress` (path
// from root to this frame). We derive it from the same call tree
// the `callTracer` builds.

fn flatten_call_frames<'a>(
    out: &mut Vec<Value>,
    frame: &'a tron_tvm::tracer::CallFrame,
    trace_address: Vec<usize>,
) {
    out.push(json!({
        "action": {
            "callType": frame.call_type.to_lowercase(),
            "from": format!("0x{}", hex::encode(frame.from)),
            "to": frame.to.map(|a| format!("0x{}", hex::encode(a))),
            "gas": format!("0x{:x}", frame.gas),
            "input": format!("0x{}", hex::encode(&frame.input)),
            "value": format!("0x{:x}", frame.value),
        },
        "result": {
            "gasUsed": format!("0x{:x}", frame.gas_used),
            "output": format!("0x{}", hex::encode(&frame.output)),
        },
        "error": frame.error,
        "traceAddress": trace_address,
        "subtraces": frame.calls.len(),
        "type": "call",
    }));
    for (idx, child) in frame.calls.iter().enumerate() {
        let mut next = trace_address.clone();
        next.push(idx);
        flatten_call_frames(out, child, next);
    }
}

/// `trace_call(callObj, traceTypes, blockTag)` — parity-style.
/// `traceTypes` is an array like `["trace"]` (we only support
/// `trace`; `vmTrace` would need full memory capture, `stateDiff`
/// would need a state-diff tracer — both out of scope).
pub fn trace_call(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let req = parse_eth_call_request(p, s.eth_call_gas_cap)?;
    let mut options = tron_tvm::tracer::TracerOptions::default();
    options.call_tracer_only = true;
    let tracer = tron_tvm::tracer::StructLogTracer::new(options);
    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal("trace_call not available"));
    };
    let vm_stores = build_call_vm_stores(b);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number: s.dyn_props.latest_block_header_number().unwrap_or(0),
        block_timestamp_ms: s.dyn_props.latest_block_header_timestamp().unwrap_or(0),
    };
    let trigger = tron_proto::TriggerSmartContract {
        owner_address: req.from.to_vec(),
        contract_address: req.to.to_vec(),
        call_value: req.value,
        data: req.data.clone(),
        call_token_value: 0,
        token_id: 0,
    };
    let (outcome, _internal, tracer) = tron_tvm::execute::execute_trigger_with_tracer(
        &vm_stores, block_env, &trigger, req.gas, s.eth_call_gas_cap, tracer,
    );
    let (_logs, frames) = tracer.into_outputs();
    let gas_used = match &outcome {
        tron_tvm::execute::VmOutcome::Success { energy_used, .. }
        | tron_tvm::execute::VmOutcome::Revert { energy_used, .. }
        | tron_tvm::execute::VmOutcome::Halt { energy_used, .. } => *energy_used,
        _ => 0,
    };
    let failed = !matches!(outcome, tron_tvm::execute::VmOutcome::Success { .. });
    let output = match &outcome {
        tron_tvm::execute::VmOutcome::Success { return_data, .. }
        | tron_tvm::execute::VmOutcome::Revert { return_data, .. } => hex::encode(return_data),
        _ => String::new(),
    };
    // Synthesize the root frame, then walk the children.
    let mut traces: Vec<Value> = Vec::new();
    let root = tron_tvm::tracer::CallFrame {
        call_type: "CALL",
        from: req.from[1..].try_into().unwrap_or([0; 20]),
        to: Some(req.to[1..].try_into().unwrap_or([0; 20])),
        value: alloy_primitives::U256::from(req.value.max(0) as u64),
        input: req.data.clone(),
        output: hex::decode(&output).unwrap_or_default(),
        gas: req.gas,
        gas_used,
        error: if failed { Some("execution failed".into()) } else { None },
        calls: frames,
    };
    flatten_call_frames(&mut traces, &root, Vec::new());
    Ok(json!({
        "output": format!("0x{output}"),
        "stateDiff": Value::Null,
        "trace": Value::Array(traces),
        "vmTrace": Value::Null,
    }))
}

/// `trace_transaction(txHash)` — parity-style trace of a single tx.
pub fn trace_transaction(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // Reuse debug_trace_transaction with call-tracer option and
    // flatten the result.
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx hash"))?;
    let opts = json!({"tracer": "callTracer"});
    let inner_params = json!([hash_str, opts]);
    let frame_json = debug_trace_transaction(&inner_params, s)?;
    // Rehydrate the call frame and flatten. The JSON shape from
    // debug_trace_transaction in callTracer mode IS a `CallFrame`-
    // shaped object; we re-walk it here.
    let mut traces: Vec<Value> = Vec::new();
    walk_json_frame(&mut traces, &frame_json, Vec::new());
    Ok(Value::Array(traces))
}

fn walk_json_frame(out: &mut Vec<Value>, frame: &Value, trace_address: Vec<usize>) {
    let call_type = frame["type"].as_str().unwrap_or("CALL").to_lowercase();
    let subtraces = frame["calls"].as_array().map(|a| a.len()).unwrap_or(0);
    out.push(json!({
        "action": {
            "callType": call_type,
            "from": frame["from"].clone(),
            "to": frame["to"].clone(),
            "gas": frame["gas"].clone(),
            "input": frame["input"].clone(),
            "value": frame["value"].clone(),
        },
        "result": {
            "gasUsed": frame["gasUsed"].clone(),
            "output": frame["output"].clone(),
        },
        "error": frame["error"].clone(),
        "traceAddress": trace_address,
        "subtraces": subtraces,
        "type": "call",
    }));
    if let Some(calls) = frame["calls"].as_array() {
        for (idx, child) in calls.iter().enumerate() {
            let mut next = trace_address.clone();
            next.push(idx);
            walk_json_frame(out, child, next);
        }
    }
}

/// `trace_block(blockTagOrHash)` — parity-style trace of every tx in
/// a block.
pub fn trace_block(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tx_ids = parse_trace_block_param(p, s)?;
    let mut out: Vec<Value> = Vec::new();
    for tx_id in tx_ids {
        let opts = json!({"tracer": "callTracer"});
        let inner_params = json!([format!("0x{}", hex::encode(tx_id)), opts]);
        if let Ok(frame_json) = debug_trace_transaction(&inner_params, s) {
            let mut traces: Vec<Value> = Vec::new();
            walk_json_frame(&mut traces, &frame_json, Vec::new());
            for trace in traces {
                let mut t = trace.as_object().cloned().unwrap_or_default();
                t.insert(
                    "transactionHash".into(),
                    Value::String(format!("0x{}", hex::encode(tx_id))),
                );
                out.push(Value::Object(t));
            }
        }
    }
    Ok(Value::Array(out))
}

// =============================================================================
// eth_getTransactionReceipt + eth_getLogs
// =============================================================================

/// `eth_getTransactionReceipt(hash)` — fetch the TransactionInfo for a
/// tx and shape it as an Ethereum receipt.
pub fn eth_get_transaction_receipt(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(history) = &s.tx_history else {
        return Ok(Value::Null);
    };
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx hash"))?;
    let bytes = parse_hex_bytes(hash_str)?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("tx hash must be 32 bytes"));
    }
    let mut tx_id = [0u8; 32];
    tx_id.copy_from_slice(&bytes);
    let Ok(Some(info)) = history.get(&tx_id) else {
        return Ok(Value::Null);
    };
    Ok(encode_receipt_for_rpc(&tx_id, &info))
}

fn encode_receipt_for_rpc(tx_id: &[u8; 32], info: &tron_proto::TransactionInfo) -> Value {
    let logs: Vec<Value> = info
        .log
        .iter()
        .enumerate()
        .map(|(i, l)| {
            json!({
                "logIndex": hex_u64(i as u64),
                "transactionHash": hex_bytes(tx_id),
                "blockNumber": hex_i64(info.block_number),
                "address": hex_bytes(&l.address),
                "data": hex_bytes(&l.data),
                "topics": l.topics.iter().map(|t| hex_bytes(t)).collect::<Vec<_>>(),
                "removed": false,
            })
        })
        .collect();
    let status = if info.result == 0 { "0x1" } else { "0x0" };
    json!({
        "transactionHash": hex_bytes(tx_id),
        "blockNumber": hex_i64(info.block_number),
        "blockHash": null,
        "transactionIndex": "0x0",
        "from": null,
        "to": null,
        "cumulativeGasUsed": hex_i64(info
            .receipt
            .as_ref()
            .map(|r| r.energy_usage_total)
            .unwrap_or(0)),
        "gasUsed": hex_i64(info
            .receipt
            .as_ref()
            .map(|r| r.energy_usage_total)
            .unwrap_or(0)),
        "contractAddress": if info.contract_address.is_empty() { Value::Null }
                          else { Value::String(hex_bytes(&info.contract_address)) },
        "logs": logs,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "status": status,
        "effectiveGasPrice": "0x0",
        "type": "0x0",
    })
}

/// `eth_getLogs(filter)` — scan the block range, fetch each tx's
/// `TransactionInfo` from history, and filter by address + topics.
pub fn eth_get_logs(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("missing filter object"))?;
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    // Resolve + cap the window (rejects the signed-cast bypass) BEFORE the
    // history-store fallback so misbehaved callers are rejected regardless
    // of whether receipts are wired.
    let (from_block, to_block) = match resolve_log_block_range(obj, head)? {
        Some(window) => window,
        None => return Ok(Value::Array(vec![])),
    };
    let Some(history) = &s.tx_history else {
        return Ok(Value::Array(vec![]));
    };
    let addr_filter: Vec<Vec<u8>> = match obj.get("address") {
        Some(Value::String(s)) => vec![parse_eth_address(s)?.as_bytes().to_vec()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(parse_eth_address)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|a| a.as_bytes().to_vec())
            .collect(),
        _ => Vec::new(),
    };
    // Topic filter: each element is either a single 32-byte hex or a
    // list of alternatives; null = match-any. Position-sensitive.
    let topic_filter: Vec<Vec<Vec<u8>>> = match obj.get("topics") {
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|t| match t {
                Value::String(s) => vec![parse_hex_bytes(s).unwrap_or_default()],
                Value::Array(alts) => alts
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| parse_hex_bytes(s).unwrap_or_default())
                    .collect(),
                _ => Vec::new(), // null / unknown → match any
            })
            .collect(),
        _ => Vec::new(),
    };

    let mut out: Vec<Value> = Vec::new();
    for block_num in from_block..=to_block {
        let Ok(id) = s.block_index.get(block_num) else { continue };
        let Ok(block) = s.blocks.get(&id) else { continue };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            let Ok(Some(info)) = history.get(&tx_id) else { continue };
            for (log_idx, log) in info.log.iter().enumerate() {
                if !addr_filter.is_empty() && !addr_filter.iter().any(|a| a == &log.address) {
                    continue;
                }
                let matches_topics = topic_filter.iter().enumerate().all(|(i, alts)| {
                    if alts.is_empty() {
                        return true; // match-any
                    }
                    log.topics
                        .get(i)
                        .map_or(false, |t| alts.iter().any(|a| a == t))
                });
                if !matches_topics {
                    continue;
                }
                out.push(json!({
                    "logIndex": hex_u64(log_idx as u64),
                    "transactionHash": hex_bytes(&tx_id),
                    "transactionIndex": "0x0",
                    "blockNumber": hex_i64(block_num),
                    "blockHash": hex_bytes(id.as_bytes()),
                    "address": hex_bytes(&log.address),
                    "data": hex_bytes(&log.data),
                    "topics": log.topics.iter().map(|t| hex_bytes(t)).collect::<Vec<_>>(),
                    "removed": false,
                }));
            }
        }
    }
    Ok(Value::Array(out))
}

// =============================================================================
// Remaining TRON wallet methods
// =============================================================================

/// `getTransactionInfoById(hash)` — TRON-style receipt fetch.
pub fn get_transaction_info_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx hash"))?;
    let bytes = parse_hex_bytes(hash_str)?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("tx hash must be 32 bytes"));
    }
    let mut tx_id = [0u8; 32];
    tx_id.copy_from_slice(&bytes);
    // Primary: the tx-id-keyed history store (java-tron's
    // transactionHistoryStore, populated by snapshots).
    if let Some(history) = &s.tx_history {
        if let Ok(Some(info)) = history.get(&tx_id) {
            return Ok(encode_transaction_info(&info));
        }
    }
    // Fallback: the block-keyed transactionRetStore, written at every
    // apply when [index] is enabled. The tx's stored block-ref tells
    // us which block's receipt list to search.
    if let (Some(ret_store), Ok(Some(tron_chainbase::StoredTransaction::BlockRef(num)))) =
        (&s.transaction_ret, s.transactions.get(&tx_id))
    {
        if let Ok(Some(ret)) = ret_store.get(num) {
            if let Some(info) = ret.transactioninfo.iter().find(|i| i.id == tx_id) {
                return Ok(encode_transaction_info(info));
            }
        }
    }
    Ok(Value::Null)
}

/// `getTransactionInfoByBlockNum(num)` — all receipts in the block.
pub fn get_transaction_info_by_block_num(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let num = p
        .get(0)
        .and_then(|v| v.as_i64())
        .or_else(|| {
            p.get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
        })
        .ok_or_else(|| RpcError::invalid_params("missing block number"))?;
    // The block-keyed transactionRetStore IS this query's shape — one
    // get serves the whole block when present (written at apply with
    // [index] enabled, or imported with an archive snapshot).
    if let Some(ret_store) = &s.transaction_ret {
        if let Ok(Some(ret)) = ret_store.get(num) {
            if !ret.transactioninfo.is_empty() {
                return Ok(Value::Array(
                    ret.transactioninfo.iter().map(encode_transaction_info).collect(),
                ));
            }
        }
    }
    // Fallback: per-tx lookups through the tx-id-keyed history store.
    let Some(history) = &s.tx_history else {
        return Ok(Value::Array(vec![]));
    };
    let Ok(id) = s.block_index.get(num) else {
        return Ok(Value::Array(vec![]));
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Array(vec![]));
    };
    let mut infos: Vec<Value> = Vec::new();
    for tx in &block.transactions {
        let Some(raw) = &tx.raw_data else { continue };
        let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
        if let Ok(Some(info)) = history.get(&tx_id) {
            infos.push(encode_transaction_info(&info));
        }
    }
    Ok(Value::Array(infos))
}

fn encode_transaction_info(info: &tron_proto::TransactionInfo) -> Value {
    // java-tron JsonFormat semantics: proto field names verbatim
    // (`blockNumber` but `contract_address` — the .proto mixes styles),
    // default-valued fields omitted, bytes as bare hex, enums as value
    // names (including the `SUCESS` typo java pins forever).
    let mut m = serde_json::Map::new();
    m.insert("id".into(), json!(hex::encode(&info.id)));
    if info.fee != 0 {
        m.insert("fee".into(), json!(info.fee));
    }
    if info.block_number != 0 {
        m.insert("blockNumber".into(), json!(info.block_number));
    }
    if info.block_time_stamp != 0 {
        m.insert("blockTimeStamp".into(), json!(info.block_time_stamp));
    }
    if !info.contract_result.is_empty() {
        m.insert(
            "contractResult".into(),
            json!(info.contract_result.iter().map(hex::encode).collect::<Vec<_>>()),
        );
    }
    if !info.contract_address.is_empty() {
        m.insert("contract_address".into(), json!(hex::encode(&info.contract_address)));
    }
    if let Some(r) = &info.receipt {
        let mut rm = serde_json::Map::new();
        if r.energy_usage != 0 {
            rm.insert("energy_usage".into(), json!(r.energy_usage));
        }
        if r.energy_fee != 0 {
            rm.insert("energy_fee".into(), json!(r.energy_fee));
        }
        if r.origin_energy_usage != 0 {
            rm.insert("origin_energy_usage".into(), json!(r.origin_energy_usage));
        }
        if r.energy_usage_total != 0 {
            rm.insert("energy_usage_total".into(), json!(r.energy_usage_total));
        }
        if r.net_usage != 0 {
            rm.insert("net_usage".into(), json!(r.net_usage));
        }
        if r.net_fee != 0 {
            rm.insert("net_fee".into(), json!(r.net_fee));
        }
        if r.result != 0 {
            let name = tron_proto::transaction::result::ContractResult::try_from(r.result)
                .map(|c| c.as_str_name().to_string())
                .unwrap_or_else(|_| r.result.to_string());
            rm.insert("result".into(), json!(name));
        }
        if r.energy_penalty_total != 0 {
            rm.insert("energy_penalty_total".into(), json!(r.energy_penalty_total));
        }
        m.insert("receipt".into(), Value::Object(rm));
    }
    if !info.log.is_empty() {
        let logs: Vec<Value> = info
            .log
            .iter()
            .map(|l| {
                let mut lm = serde_json::Map::new();
                if !l.address.is_empty() {
                    lm.insert("address".into(), json!(hex::encode(&l.address)));
                }
                if !l.topics.is_empty() {
                    lm.insert(
                        "topics".into(),
                        json!(l.topics.iter().map(hex::encode).collect::<Vec<_>>()),
                    );
                }
                if !l.data.is_empty() {
                    lm.insert("data".into(), json!(hex::encode(&l.data)));
                }
                Value::Object(lm)
            })
            .collect();
        m.insert("log".into(), json!(logs));
    }
    if info.result != 0 {
        let name = tron_proto::transaction_info::Code::try_from(info.result)
            .map(|c| c.as_str_name().to_string())
            .unwrap_or_else(|_| info.result.to_string());
        m.insert("result".into(), json!(name));
    }
    if !info.res_message.is_empty() {
        m.insert("resMessage".into(), json!(hex::encode(&info.res_message)));
    }
    if !info.asset_issue_id.is_empty() {
        m.insert("assetIssueID".into(), json!(info.asset_issue_id));
    }
    if info.withdraw_amount != 0 {
        m.insert("withdraw_amount".into(), json!(info.withdraw_amount));
    }
    if info.unfreeze_amount != 0 {
        m.insert("unfreeze_amount".into(), json!(info.unfreeze_amount));
    }
    if !info.internal_transactions.is_empty() {
        let itxs: Vec<Value> = info
            .internal_transactions
            .iter()
            .map(|t| {
                let mut tm = serde_json::Map::new();
                if !t.hash.is_empty() {
                    tm.insert("hash".into(), json!(hex::encode(&t.hash)));
                }
                if !t.caller_address.is_empty() {
                    tm.insert("caller_address".into(), json!(hex::encode(&t.caller_address)));
                }
                if !t.transfer_to_address.is_empty() {
                    tm.insert(
                        "transferTo_address".into(),
                        json!(hex::encode(&t.transfer_to_address)),
                    );
                }
                if !t.call_value_info.is_empty() {
                    let cvs: Vec<Value> = t
                        .call_value_info
                        .iter()
                        .map(|cv| {
                            let mut cm = serde_json::Map::new();
                            if cv.call_value != 0 {
                                cm.insert("callValue".into(), json!(cv.call_value));
                            }
                            if !cv.token_id.is_empty() {
                                cm.insert("tokenId".into(), json!(cv.token_id));
                            }
                            Value::Object(cm)
                        })
                        .collect();
                    tm.insert("callValueInfo".into(), json!(cvs));
                }
                if !t.note.is_empty() {
                    tm.insert("note".into(), json!(hex::encode(&t.note)));
                }
                if t.rejected {
                    tm.insert("rejected".into(), json!(true));
                }
                if !t.extra.is_empty() {
                    tm.insert("extra".into(), json!(t.extra));
                }
                Value::Object(tm)
            })
            .collect();
        m.insert("internal_transactions".into(), json!(itxs));
    }
    if info.exchange_received_amount != 0 {
        m.insert("exchange_received_amount".into(), json!(info.exchange_received_amount));
    }
    if info.exchange_inject_another_amount != 0 {
        m.insert(
            "exchange_inject_another_amount".into(),
            json!(info.exchange_inject_another_amount),
        );
    }
    if info.exchange_withdraw_another_amount != 0 {
        m.insert(
            "exchange_withdraw_another_amount".into(),
            json!(info.exchange_withdraw_another_amount),
        );
    }
    if info.exchange_id != 0 {
        m.insert("exchange_id".into(), json!(info.exchange_id));
    }
    if info.shielded_transaction_fee != 0 {
        m.insert("shielded_transaction_fee".into(), json!(info.shielded_transaction_fee));
    }
    if !info.order_id.is_empty() {
        m.insert("orderId".into(), json!(hex::encode(&info.order_id)));
    }
    if info.packing_fee != 0 {
        m.insert("packingFee".into(), json!(info.packing_fee));
    }
    if info.withdraw_expire_amount != 0 {
        m.insert("withdraw_expire_amount".into(), json!(info.withdraw_expire_amount));
    }
    if !info.cancel_unfreeze_v2_amount.is_empty() {
        let mut cm = serde_json::Map::new();
        for (k, v) in &info.cancel_unfreeze_v2_amount {
            cm.insert(k.clone(), json!(v));
        }
        m.insert("cancel_unfreezeV2_amount".into(), Value::Object(cm));
    }
    Value::Object(m)
}

/// `listAssets` / `getAssetIssueList` — every TRC-10 asset.
pub fn list_assets(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(assets) = &s.assets_v2 else {
        return Ok(json!({ "assetIssue": [] }));
    };
    let all = assets
        .all()
        .map_err(|e| RpcError::internal(format!("asset scan: {e}")))?;
    let out: Vec<Value> = all
        .into_iter()
        .map(|(_, a)| {
            json!({
                "id": a.id,
                "ownerAddress": hex_bytes(&a.owner_address),
                "name": String::from_utf8_lossy(&a.name).to_string(),
                "abbr": String::from_utf8_lossy(&a.abbr).to_string(),
                "totalSupply": a.total_supply,
                "precision": a.precision,
            })
        })
        .collect();
    Ok(json!({ "assetIssue": out }))
}

/// `listExchanges` — every active DEX exchange.
pub fn list_exchanges(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(ex) = &s.exchanges_v2 else {
        return Ok(json!({ "exchanges": [] }));
    };
    let all = ex
        .all()
        .map_err(|e| RpcError::internal(format!("exchange scan: {e}")))?;
    let out: Vec<Value> = all
        .into_iter()
        .map(|(_, e)| {
            json!({
                "exchangeId": e.exchange_id,
                "creatorAddress": hex_bytes(&e.creator_address),
                "firstTokenId": String::from_utf8_lossy(&e.first_token_id).to_string(),
                "firstTokenBalance": e.first_token_balance,
                "secondTokenId": String::from_utf8_lossy(&e.second_token_id).to_string(),
                "secondTokenBalance": e.second_token_balance,
            })
        })
        .collect();
    Ok(json!({ "exchanges": out }))
}

/// `getNextMaintenanceTime` — next epoch boundary timestamp. java wraps
/// it in `{"num": t}` (`NumberMessage` JSON), not a bare number.
pub fn get_next_maintenance_time(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({
        "num": s.dyn_props.get_long(b"NEXT_MAINTENANCE_TIME").unwrap_or(0)
    }))
}

/// `getNodes` / `listNodes` — peer list. We don't track peers at this
/// layer; return an empty list so explorers don't error out.
pub fn get_nodes(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({ "nodes": [] }))
}

/// `getAccountById(account_id)` — TRON's named-account lookup. We
/// query `AccountIdIndexStore` for the address, then read the account.
pub fn get_account_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(idx) = &s.account_id_index else {
        return Ok(Value::Null);
    };
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing account id"))?;
    let id_bytes = parse_hex_bytes(id_str).unwrap_or_else(|_| id_str.as_bytes().to_vec());
    let Ok(Some(addr)) = idx.get(&id_bytes) else {
        return Ok(Value::Null);
    };
    let genesis_ms = s.dyn_props.genesis_block_timestamp().unwrap_or(0);
    match s.accounts.get(&addr) {
        Ok(Some(mut a)) => {
            if let Some(store) = &s.account_assets {
                merge_account_assets(&mut a, store);
            }
            apply_read_usage_recovery(&mut a, &s.dyn_props);
            Ok(encode_account_for_rpc(&a, genesis_ms))
        }
        _ => Ok(Value::Null),
    }
}

/// `triggerConstantContract(addr, owner_addr, data)` — TRON's name
/// for `eth_call`. Accepts a flat-positional-args form for
/// compatibility with tronweb-style clients.
/// Parse a `triggerConstantContract` request. Accepts BOTH java-tron's
/// native body shape (`contract_address` / `owner_address` /
/// `function_selector` + `parameter`, or raw `data`) AND the eth_call
/// object shape (`to` / `from` / `data`) so existing eth-style callers
/// keep working. Addresses arrive here already translated to hex by the
/// REST layer (or supplied as hex by JSON-RPC callers). `function_selector`
/// is keccak256-hashed (first 4 bytes) and prepended to `parameter`,
/// exactly as java-tron's `Util.getSelector` + parameter concat does.
fn parse_constant_call_request(p: &Value, gas_cap: u64) -> Result<EthCallRequest, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("missing call object"))?;

    let to_str = obj
        .get("to")
        .or_else(|| obj.get("contract_address"))
        .or_else(|| obj.get("contractAddress"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing `contract_address`"))?;
    let to = parse_eth_address(to_str)?.as_bytes().to_owned();
    let mut to_arr = [0u8; 21];
    to_arr.copy_from_slice(&to);

    // `owner_address`/`from` is optional for a read-only call; default to
    // a bare `0x41`-prefixed zero address (msg.sender unused by view fns).
    let from_arr = match obj
        .get("from")
        .or_else(|| obj.get("owner_address"))
        .or_else(|| obj.get("ownerAddress"))
        .and_then(|v| v.as_str())
    {
        Some(s) => {
            let a = parse_eth_address(s)?.as_bytes().to_owned();
            let mut buf = [0u8; 21];
            buf.copy_from_slice(&a);
            buf
        }
        None => {
            let mut buf = [0u8; 21];
            buf[0] = 0x41;
            buf
        }
    };

    // Calldata: prefer `function_selector` (+ optional `parameter`),
    // else fall back to raw `data`/`input` hex. `data`/`parameter` are
    // decoded leniently (with or without a `0x` prefix) because java-tron's
    // HTTP API sends bare hex while eth-style callers send `0x...`.
    fn decode_hex_lenient(s: &str) -> Result<Vec<u8>, RpcError> {
        let s = s.trim();
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        if s.is_empty() {
            return Ok(Vec::new());
        }
        hex::decode(s).map_err(|e| RpcError::invalid_params(format!("invalid hex: {e}")))
    }
    let data = if let Some(sig) = obj.get("function_selector").and_then(|v| v.as_str()) {
        let selector = keccak256(sig.trim().as_bytes());
        let mut d = selector[..4].to_vec();
        if let Some(param) = obj.get("parameter").and_then(|v| v.as_str()) {
            d.extend_from_slice(&decode_hex_lenient(param)?);
        }
        d
    } else {
        match obj.get("data").or_else(|| obj.get("input")).and_then(|v| v.as_str()) {
            Some(sx) => decode_hex_lenient(sx)?,
            None => Vec::new(),
        }
    };

    // `value` may be eth-style hex or java-style `call_value` integer.
    let value = if let Some(s) = obj.get("value").and_then(|v| v.as_str()) {
        parse_hex_quantity(s)? as i64
    } else if let Some(n) = obj.get("call_value").and_then(|v| v.as_i64()) {
        n
    } else {
        0
    };

    let default_gas = (gas_cap.saturating_sub(1_000_000)).min(15_000_000);
    let gas = obj
        .get("gas")
        .and_then(|v| v.as_str())
        .map(parse_hex_quantity)
        .transpose()?
        .map(|g| g as u64)
        .unwrap_or(default_gas)
        .min(gas_cap);

    Ok(EthCallRequest {
        from: from_arr,
        to: to_arr,
        data,
        value,
        gas,
    })
}

/// Render a constant-call `VmOutcome` into java-tron's
/// `triggerConstantContract` response shape: `constant_result` (bare-hex
/// return data), `energy_used`, `result.{result,code,message}`, and a
/// minimal `transaction.ret[].contractRet`. The energy + return-data are
/// what a state-diff harness compares to validate TVM execution exactness.
fn constant_outcome_to_json(outcome: tron_tvm::execute::VmOutcome, energy_penalty: u64) -> Value {
    use tron_tvm::execute::VmOutcome;
    // java-tron: `TransactionExtention.energy_penalty` =
    // `ProgramResult.energyPenaltyTotal` (Wallet.triggerConstantContract).
    // proto3 JsonFormat omits the field when 0.
    let mut v = match outcome {
        VmOutcome::Success {
            return_data,
            energy_used,
            ..
        } => json!({
            "result": { "result": true },
            "energy_used": energy_used,
            "constant_result": [hex::encode(&return_data)],
            "transaction": { "ret": [{ "contractRet": "SUCCESS" }] },
        }),
        VmOutcome::Revert {
            return_data,
            energy_used,
            ..
        } => json!({
            "result": { "result": false, "code": "CONTRACT_EXE_ERROR", "message": "REVERT opcode executed" },
            "energy_used": energy_used,
            "constant_result": [hex::encode(&return_data)],
            "transaction": { "ret": [{ "contractRet": "REVERT" }] },
        }),
        VmOutcome::Halt {
            energy_used,
            reason,
            ..
        } => json!({
            "result": { "result": false, "code": "CONTRACT_EXE_ERROR", "message": format!("halt: {reason}") },
            "energy_used": energy_used,
            "constant_result": [""],
            "transaction": { "ret": [{ "contractRet": "FAILED" }] },
        }),
        VmOutcome::PreflightError(msg) => json!({
            "result": { "result": false, "code": "CONTRACT_VALIDATE_ERROR", "message": msg },
        }),
        VmOutcome::Timeout { deadline_ms, .. } => json!({
            "result": { "result": false, "code": "CONTRACT_EXE_ERROR",
                        "message": format!("constant call timed out after {deadline_ms}ms") },
        }),
        VmOutcome::CallTokenIgnored { .. } => json!({
            "result": { "result": false, "code": "CONTRACT_VALIDATE_ERROR",
                        "message": "CALLTOKEN at top level is not supported in a constant call" },
        }),
    };
    if energy_penalty > 0 {
        if let Value::Object(map) = &mut v {
            map.insert("energy_penalty".to_string(), json!(energy_penalty));
        }
    }
    v
}

pub fn trigger_constant_contract(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // `vm.supportConstant` gate. java-tron rejects the RPC with
    // `CONTRACT_VALIDATE_ERROR` when this is off; the closest analog
    // here is our `invalid_request` error so clients see "unsupported".
    if !s.support_constant {
        return Err(RpcError::invalid_request(
            "triggerConstantContract is disabled on this node \
             (set vm.supportConstant = true to enable)",
        ));
    }
    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal(
            "triggerConstantContract not available: server built without EVM call backends",
        ));
    };
    // Positional `[owner, contract, data]` form → repack into an object
    // so the single parser handles every shape.
    let params_obj;
    let params = if p.get(0).and_then(|v| v.as_object()).is_some() {
        p
    } else {
        let owner = p.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let contract_addr = p
            .get(1)
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::invalid_params("missing contract address"))?;
        let data = p.get(2).and_then(|v| v.as_str()).unwrap_or("0x");
        params_obj = json!([{ "from": owner, "to": contract_addr, "data": data }]);
        &params_obj
    };

    let req = parse_constant_call_request(params, s.eth_call_gas_cap)?;
    let vm_stores = build_call_vm_stores(b);
    let block_number = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let block_timestamp_ms = s.dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number,
        block_timestamp_ms,
    };
    let trigger = tron_proto::TriggerSmartContract {
        owner_address: req.from.to_vec(),
        contract_address: req.to.to_vec(),
        call_value: req.value,
        data: req.data,
        call_token_value: 0,
        token_id: 0,
    };
    let (outcome, energy_penalty) =
        dispatch_constant_trigger(s, &vm_stores, block_env, &trigger, req.gas);
    Ok(constant_outcome_to_json(outcome, energy_penalty))
}

/// `broadcastTransaction(tx)` — accepts a transaction but doesn't
/// broadcast (we have no P2P layer here). Returns `{"result": false,
/// "code": "OTHER_ERROR", "message": "no broadcast layer"}` so clients
/// know to retry against a node that has one.
pub fn broadcast_transaction(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({
        "result": false,
        "code": "OTHER_ERROR",
        "message": "broadcastTransaction not supported on this node (no P2P broadcast layer)",
    }))
}

/// `eth_sendRawTransaction(hex)` — equivalent stub.
pub fn eth_send_raw_transaction(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found(
        "eth_sendRawTransaction (no P2P broadcast layer)",
    ))
}

// =============================================================================
// eth_newFilter family
// =============================================================================

use crate::filters::{decode_filter_id, encode_filter_id, FilterKind, LogFilter};

/// Parse a JSON-RPC log-filter object into a `LogFilter` (same shape
/// as `eth_getLogs`, but stored for repeated polling).
fn parse_log_filter(obj: &serde_json::Map<String, Value>, head: i64) -> Result<LogFilter, RpcError> {
    let from_block = match obj.get("fromBlock").and_then(|v| v.as_str()) {
        Some("latest") | Some("pending") | Some("safe") | Some("finalized") | None => head,
        Some("earliest") => 0,
        Some(hex) => parse_block_number(hex)?,
    };
    let to_block = match obj.get("toBlock").and_then(|v| v.as_str()) {
        Some("latest") | Some("pending") | Some("safe") | Some("finalized") | None => i64::MAX,
        Some("earliest") => 0,
        Some(hex) => parse_block_number(hex)?,
    };
    let addresses: Vec<Vec<u8>> = match obj.get("address") {
        Some(Value::String(s)) => vec![parse_eth_address(s)?.as_bytes().to_vec()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(parse_eth_address)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|a| a.as_bytes().to_vec())
            .collect(),
        _ => Vec::new(),
    };
    let topics: Vec<Vec<Vec<u8>>> = match obj.get("topics") {
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|t| match t {
                Value::String(s) => vec![parse_hex_bytes(s).unwrap_or_default()],
                Value::Array(alts) => alts
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| parse_hex_bytes(s).unwrap_or_default())
                    .collect(),
                _ => Vec::new(),
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(LogFilter {
        from_block,
        to_block,
        addresses,
        topics,
    })
}

/// `eth_newFilter(filterObject)` — register a log filter.
pub fn eth_new_filter(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("missing filter object"))?;
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let filter = parse_log_filter(obj, head)?;
    let id = s
        .filters
        .create(FilterKind::Log(filter), head);
    Ok(encode_filter_id(id))
}

/// `eth_newBlockFilter()` — register a filter that tracks new blocks.
pub fn eth_new_block_filter(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let id = s.filters.create(FilterKind::BlockHeader, head);
    Ok(encode_filter_id(id))
}

/// `eth_newPendingTransactionFilter()` — pending-tx filter. With no
/// mempool wired, this never reports any changes; we still hand out a
/// filter id so wallets that probe support don't error.
pub fn eth_new_pending_transaction_filter(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let id = s.filters.create(FilterKind::PendingTransaction, head);
    Ok(encode_filter_id(id))
}

/// `eth_uninstallFilter(filter_id)` — drop a filter from the
/// registry. Returns `true` if it existed.
pub fn eth_uninstall_filter(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing filter id"))?;
    let id = decode_filter_id(id_str)
        .ok_or_else(|| RpcError::invalid_params("bad filter id"))?;
    Ok(Value::Bool(s.filters.uninstall(id)))
}

/// `eth_getFilterChanges(filter_id)` — incremental delta since last
/// poll. For log filters, returns logs in `[cursor+1, head]`; for
/// block filters, returns block hashes in that range; pending tx
/// filters always return `[]`.
pub fn eth_get_filter_changes(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing filter id"))?;
    let id = decode_filter_id(id_str)
        .ok_or_else(|| RpcError::invalid_params("bad filter id"))?;
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let Some((kind, cursor)) = s.filters.touch(id, head) else {
        return Err(RpcError {
            code: -32000,
            message: "filter not found".into(),
        });
    };
    match kind {
        FilterKind::Log(f) => {
            // Only return logs strictly newer than the cursor and ≤ head,
            // bounded by the filter's declared block range.
            let from = (cursor + 1).max(f.from_block).max(0);
            let to = head.min(f.to_block);
            if to < from {
                return Ok(Value::Array(vec![]));
            }
            collect_logs(s, from, to, &f.addresses, &f.topics)
        }
        FilterKind::BlockHeader => {
            // List block hashes for blocks strictly newer than cursor.
            let from = cursor + 1;
            let mut out: Vec<Value> = Vec::new();
            for n in from..=head {
                if let Ok(id) = s.block_index.get(n) {
                    out.push(Value::String(hex_bytes(id.as_bytes())));
                }
            }
            Ok(Value::Array(out))
        }
        FilterKind::PendingTransaction => Ok(Value::Array(vec![])),
    }
}

/// `eth_getFilterLogs(filter_id)` — return ALL logs matching the
/// filter (not a delta). Only valid for log filters.
pub fn eth_get_filter_logs(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing filter id"))?;
    let id = decode_filter_id(id_str)
        .ok_or_else(|| RpcError::invalid_params("bad filter id"))?;
    let Some(kind) = s.filters.peek(id) else {
        return Err(RpcError {
            code: -32000,
            message: "filter not found".into(),
        });
    };
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    match kind {
        FilterKind::Log(f) => {
            let to = head.min(f.to_block);
            if to < f.from_block {
                return Ok(Value::Array(vec![]));
            }
            collect_logs(s, f.from_block, to, &f.addresses, &f.topics)
        }
        _ => Err(RpcError::invalid_params(
            "eth_getFilterLogs only valid for log filters",
        )),
    }
}

/// Helper: walk block range `[from, to]`, fetch each TransactionInfo,
/// filter by address + topics, encode each log.
fn collect_logs(
    s: &RpcState,
    from: i64,
    to: i64,
    addresses: &[Vec<u8>],
    topics: &[Vec<Vec<u8>>],
) -> Result<Value, RpcError> {
    // Cap to prevent runaway scans on misuse (same cap as eth_getLogs).
    if to - from > 10_000 {
        return Err(RpcError::invalid_params(
            "block range too large (max 10000)",
        ));
    }
    let Some(history) = &s.tx_history else {
        return Ok(Value::Array(vec![]));
    };
    let mut out: Vec<Value> = Vec::new();
    for block_num in from..=to {
        let Ok(id) = s.block_index.get(block_num) else { continue };
        let Ok(block) = s.blocks.get(&id) else { continue };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            let Ok(Some(info)) = history.get(&tx_id) else { continue };
            for (log_idx, log) in info.log.iter().enumerate() {
                if !addresses.is_empty() && !addresses.iter().any(|a| a == &log.address) {
                    continue;
                }
                let matches_topics = topics.iter().enumerate().all(|(i, alts)| {
                    if alts.is_empty() {
                        return true;
                    }
                    log.topics
                        .get(i)
                        .map_or(false, |t| alts.iter().any(|a| a == t))
                });
                if !matches_topics {
                    continue;
                }
                out.push(json!({
                    "logIndex": hex_u64(log_idx as u64),
                    "transactionHash": hex_bytes(&tx_id),
                    "transactionIndex": "0x0",
                    "blockNumber": hex_i64(block_num),
                    "blockHash": hex_bytes(id.as_bytes()),
                    "address": hex_bytes(&log.address),
                    "data": hex_bytes(&log.data),
                    "topics": log.topics.iter().map(|t| hex_bytes(t)).collect::<Vec<_>>(),
                    "removed": false,
                }));
            }
        }
    }
    Ok(Value::Array(out))
}

// =============================================================================
// eth_sendRawTransaction (mempool-backed)
// =============================================================================

/// `eth_sendRawTransaction(hex)` — accepts a raw transaction. Per
/// the TRON protocol the payload is a protobuf-encoded `Transaction`
/// (NOT Ethereum-RLP); wallets that need Ethereum-compat must
/// re-encode before calling.
pub fn eth_send_raw_transaction_v2(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(mempool) = &s.mempool else {
        return Err(RpcError {
            code: -32004,
            message: "eth_sendRawTransaction: no mempool attached on this node".into(),
        });
    };
    let hex_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing raw tx"))?;
    let raw = parse_hex_bytes(hex_str)?;
    match mempool.submit_tron(&raw) {
        crate::mempool::SubmitOutcome::Accepted(tx_id) => Ok(Value::String(hex_bytes(&tx_id))),
        crate::mempool::SubmitOutcome::Rejected(reason) => {
            Err(RpcError::invalid_params(format!("rejected: {reason}")))
        }
        crate::mempool::SubmitOutcome::Unsupported => Err(RpcError {
            code: -32004,
            message: "mempool rejected: unsupported tx type".into(),
        }),
    }
}

/// `broadcastTransaction(txObject)` — TRON-form transaction submission.
/// Returns the TRON-style result envelope `{result, txid, code}`.
pub fn broadcast_transaction_v2(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(mempool) = &s.mempool else {
        return Ok(json!({
            "result": false,
            "code": "OTHER_ERROR",
            "message": "broadcastTransaction not supported on this node (no mempool attached)",
        }));
    };
    // Two accepted forms: a TRON-style transaction object (we
    // round-trip through protobuf), or a hex-encoded raw payload.
    let raw = if let Some(s) = p.get(0).and_then(|v| v.as_str()) {
        parse_hex_bytes(s)?
    } else if let Some(obj) = p.get(0).and_then(|v| v.as_object()) {
        // Accept a {raw_data_hex: "..."} envelope as a convenience.
        let raw_str = obj
            .get("raw_data_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::invalid_params(
                "missing raw_data_hex on transaction object",
            ))?;
        parse_hex_bytes(raw_str)?
    } else {
        return Err(RpcError::invalid_params("missing transaction"));
    };
    match mempool.submit_tron(&raw) {
        crate::mempool::SubmitOutcome::Accepted(tx_id) => Ok(json!({
            "result": true,
            "txid": hex_bytes(&tx_id),
            "code": "SUCCESS",
        })),
        crate::mempool::SubmitOutcome::Rejected(reason) => Ok(json!({
            "result": false,
            "code": "BANDWIDTH_ERROR",
            "message": reason,
        })),
        crate::mempool::SubmitOutcome::Unsupported => Ok(json!({
            "result": false,
            "code": "OTHER_ERROR",
            "message": "mempool does not support this transaction",
        })),
    }
}

// =============================================================================
// eth_getProof
// =============================================================================

/// `eth_getProof(address, storageKeys, blockTag)` — Merkle Patricia
/// state proof.
///
/// **TRON has no global state trie.** Accounts live in individual
/// rows in `AccountStore`; storage slots in `StorageRowStore`;
/// there's no concept of an "account state root" you can produce a
/// proof from. The Ethereum-style proof shape isn't constructible
/// from our storage model.
///
/// We return an EIP-1186-shaped response with **empty** `accountProof`
/// / `storageProof.proof` arrays and the current values inline. This
/// is enough for wallets that want to *display* the account state but
/// callers that depend on the cryptographic proof must not trust it.
pub fn eth_get_proof(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let keys: Vec<Value> = match p.get(1) {
        Some(Value::Array(arr)) => arr.clone(),
        _ => Vec::new(),
    };

    let account = s
        .accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?;
    let balance = account.as_ref().map(|a| a.balance).unwrap_or(0);
    let code_hash = account
        .as_ref()
        .map(|a| a.code_hash.clone())
        .unwrap_or_default();

    let storage_proof: Vec<Value> = keys
        .iter()
        .filter_map(|k| k.as_str())
        .map(|slot_str| {
            let stripped = slot_str.strip_prefix("0x").unwrap_or(slot_str);
            let padded = format!("{:0>64}", stripped);
            let mut slot = [0u8; 32];
            if let Ok(decoded) = hex::decode(&padded) {
                if decoded.len() == 32 {
                    slot.copy_from_slice(&decoded);
                }
            }
            let value = match &s.storage {
                Some(storage) => {
                    let key = tron_chainbase::StorageRowStore::compose_key(&addr, &slot);
                    storage.get(&key).ok().flatten().unwrap_or_else(|| vec![0u8; 32])
                }
                None => vec![0u8; 32],
            };
            let mut padded_val = [0u8; 32];
            let n = value.len().min(32);
            padded_val[32 - n..].copy_from_slice(&value[value.len() - n..]);
            json!({
                "key": slot_str,
                "value": hex_bytes(&padded_val),
                // Empty proof — TRON has no MPT. Documented in the
                // method's rustdoc.
                "proof": Vec::<Value>::new(),
            })
        })
        .collect();

    Ok(json!({
        "address": addr_str,
        "balance": hex_i64(balance),
        "codeHash": hex_bytes(&code_hash),
        "nonce": "0x0",
        "storageHash": format!("0x{}", "00".repeat(32)),
        // Empty proof — TRON has no MPT. Documented in the method's rustdoc.
        "accountProof": Vec::<Value>::new(),
        "storageProof": storage_proof,
    }))
}

// =============================================================================
// Account resource view  —  getAccountResource / getAccountNet
// =============================================================================
//
// These mirror java-tron's HTTP `/wallet/getaccountresource` and
// `/wallet/getaccountnet`. Together they're the single most-called pair
// of read methods from wallets — every transaction-build flow consults
// them to decide whether the sender can afford the bytes / energy.

/// `getAccountResource(address)` — per-account bandwidth + energy quota
/// view. Mirrors java-tron's `wallet.getAccountResource`.
///
/// Returns a flat JSON object with the same field names java-tron
/// emits, so existing clients (TronWeb, TRON-Grid wrappers) cross-decode
/// without translation.
/// Computed `getAccountResource` view for one account — the single source of
/// truth shared by the JSON-RPC/HTTP handler and the gRPC service, so both
/// transports report identical (java-tron-faithful) values. Mirrors
/// `Wallet.getAccountResource`. (Per-asset `assetNet*` maps are not included
/// yet — see the note in `get_account_resource`.)
pub struct AccountResourceView {
    pub free_net_used: i64,
    pub free_net_limit: i64,
    pub net_used: i64,
    pub net_limit: i64,
    pub energy_used: i64,
    pub energy_limit: i64,
    pub total_net_limit: i64,
    pub total_net_weight: i64,
    pub total_energy_limit: i64,
    pub total_energy_weight: i64,
    pub total_tron_power_weight: i64,
    pub tron_power_used: i64,
    pub tron_power_limit: i64,
    pub storage_used: i64,
    pub storage_limit: i64,
}

/// Compute the resource view for `account`. Usage is decayed at read with
/// java's `getHeadSlot()` (timestamp/3000, NOT block height) — account-window
/// recovery for net + energy, default-window for free-net — and per-account
/// limits come from `calculate_global_*_limit` (NOT the chain totals).
pub fn account_resource_view(
    account: &tron_proto::Account,
    dp: &tron_chainbase::DynamicPropertiesStore,
) -> AccountResourceView {
    use tron_executor::resource::{increase_default, recovery_account, ResourceKind};
    let now_slot = dp.head_slot();

    let net_limit = tron_executor::bandwidth::calculate_global_net_limit(account, dp);
    let net_used = recovery_account(
        account,
        ResourceKind::Bandwidth,
        account.net_usage,
        account.latest_consume_time,
        now_slot,
        dp.allow_harden_resource_calculation(),
    );
    let free_net_used =
        increase_default(account.free_net_usage, 0, account.latest_consume_free_time, now_slot);

    let energy_limit = tron_executor::energy::calculate_global_energy_limit(account, dp);
    let (energy_usage, last_energy, storage_limit, storage_used) =
        match account.account_resource.as_ref() {
            Some(r) => (
                r.energy_usage,
                r.latest_consume_time_for_energy,
                r.storage_limit,
                r.storage_usage,
            ),
            None => (0, 0, 0, 0),
        };
    let energy_used =
        recovery_account(account, ResourceKind::Energy, energy_usage, last_energy, now_slot, dp.allow_harden_resource_calculation());

    AccountResourceView {
        free_net_used,
        free_net_limit: dp.free_net_limit(),
        net_used,
        net_limit,
        energy_used,
        energy_limit,
        total_net_limit: dp.total_net_limit(),
        total_net_weight: dp.total_net_weight(),
        total_energy_limit: dp.total_energy_current_limit(),
        total_energy_weight: dp.total_energy_weight(),
        total_tron_power_weight: dp.total_tron_power_weight(),
        tron_power_used: tron_power_usage(account),
        tron_power_limit: all_tron_power(account) / 1_000_000,
        storage_used,
        storage_limit,
    }
}

pub fn get_account_resource(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;

    // Look up account; return an empty quota view for unknown
    // addresses (java-tron does the same — empty body, not an error).
    let mut account = match s
        .accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?
    {
        Some(a) => a,
        None => return Ok(json!({})),
    };

    // java's `getAssetMapV2()` (called from updateUsage) lazily importsAllAsset,
    // so the asset-net maps are keyed by the MERGED asset set. Merge first.
    if let Some(store) = &s.account_assets {
        merge_account_assets(&mut account, store);
    }
    let now_slot = s.dyn_props.head_slot();

    // assetNetUsed = per-asset free-net usage (decayed); assetNetLimit =
    // each asset's AssetIssue `free_asset_net_limit` (java's setAssetNetLimit).
    let asset_net_used = materialized_asset_net_usage(&account, now_slot);
    let mut asset_net_limit: std::collections::BTreeMap<String, i64> =
        std::collections::BTreeMap::new();
    for key in asset_net_used.keys() {
        let limit = key
            .parse::<i64>()
            .ok()
            .and_then(|id| s.assets_v2.as_ref().and_then(|st| st.get(id).ok().flatten()))
            .map(|issue| issue.free_asset_net_limit)
            .unwrap_or(0);
        asset_net_limit.insert(key.clone(), limit);
    }

    let v = account_resource_view(&account, &s.dyn_props);
    Ok(json!({
        "freeNetUsed": v.free_net_used,
        "freeNetLimit": v.free_net_limit,
        "NetUsed": v.net_used,
        "NetLimit": v.net_limit,
        "EnergyUsed": v.energy_used,
        "EnergyLimit": v.energy_limit,
        "TotalNetLimit": v.total_net_limit,
        "TotalNetWeight": v.total_net_weight,
        "TotalEnergyLimit": v.total_energy_limit,
        "TotalEnergyWeight": v.total_energy_weight,
        "TotalTronPowerWeight": v.total_tron_power_weight,
        "tronPowerLimit": v.tron_power_limit,
        "tronPowerUsed": v.tron_power_used,
        "storageLimit": v.storage_limit,
        "storageUsed": v.storage_used,
        "assetNetUsed": kv_array(&asset_net_used),
        "assetNetLimit": kv_array(&asset_net_limit),
    }))
}

/// `getAccountNet(address)` — bandwidth-only subset of
/// `getAccountResource`. Some wallet flows only care about net (e.g.
/// pre-flighting a TRX transfer).
pub fn get_account_net(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let account = match s
        .accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?
    {
        Some(a) => a,
        None => return Ok(json!({})),
    };
    let now_slot = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let net_limit = tron_executor::bandwidth::calculate_global_net_limit(&account, &s.dyn_props);
    let net_usage = tron_executor::resource::increase_default(
        account.net_usage,
        0,
        account.latest_consume_time,
        now_slot,
    );
    let free_net_limit = s.dyn_props.free_net_limit();
    let free_net_usage = tron_executor::resource::increase_default(
        account.free_net_usage,
        0,
        account.latest_consume_free_time,
        now_slot,
    );
    Ok(json!({
        "freeNetUsed": free_net_usage,
        "freeNetLimit": free_net_limit,
        "NetUsed": net_usage,
        "NetLimit": net_limit,
        "TotalNetLimit": s.dyn_props.total_net_limit(),
        "TotalNetWeight": s.dyn_props.total_net_weight(),
        // Assetwise free quotas are an additional dimension — provide
        // an empty map when the account hasn't transferred any TRC-10s.
        // Real clients reach for the per-asset issuer pool via
        // getassetissuebyid; surfacing the full map here would be O(N)
        // and rarely-used.
        "assetNetUsed": Value::Object(Default::default()),
        "assetNetLimit": Value::Object(Default::default()),
    }))
}

/// java-tron `AccountCapsule.getTronPowerUsage` — voting power already cast,
/// i.e. the sum of the account's vote counts.
fn tron_power_usage(account: &tron_proto::Account) -> i64 {
    account.votes.iter().map(|v| v.vote_count).sum()
}

/// java-tron `AccountCapsule.getAllTronPower` (in sun). The `old_tron_power`
/// field selects how legacy power folds in:
///   -1 → V1 + V2 TRON_POWER frozen;
///    0 → legacy `getTronPower()` (all frozen sources) + V1 + V2;
///   >0 → stored old power + V1 + V2.
fn all_tron_power(a: &tron_proto::Account) -> i64 {
    let v1 = a.tron_power.as_ref().map(|f| f.frozen_balance).unwrap_or(0);
    let v2: i64 = a.frozen_v2.iter().filter(|f| f.r#type == 2).map(|f| f.amount).sum();
    match a.old_tron_power {
        -1 => v1 + v2,
        0 => legacy_tron_power(a) + v1 + v2,
        old => old + v1 + v2,
    }
}

/// java-tron `AccountCapsule.getTronPower` — the pre-Stake-2.0 "tron power"
/// sum across every frozen/delegated source except TRON_POWER-typed V2.
fn legacy_tron_power(a: &tron_proto::Account) -> i64 {
    let mut tp: i64 = a.frozen.iter().map(|f| f.frozen_balance).sum();
    if let Some(r) = a.account_resource.as_ref() {
        tp += r.frozen_balance_for_energy.as_ref().map(|f| f.frozen_balance).unwrap_or(0);
        tp += r.delegated_frozen_balance_for_energy;
        tp += r.delegated_frozen_v2_balance_for_energy;
    }
    tp += a.delegated_frozen_balance_for_bandwidth;
    tp += a.frozen_v2.iter().filter(|f| f.r#type != 2).map(|f| f.amount).sum::<i64>();
    tp += a.delegated_frozen_v2_balance_for_bandwidth;
    tp
}

// =============================================================================
// Delegate / unfreeze read methods (v2)
// =============================================================================

/// `getDelegatedResourceV2(from, to)` — V2 delegate entry between two
/// accounts. Distinct from the V1 path because v2 freeze allows
/// per-resource-type delegation with different expirations.
///
/// V2's storage encoding still goes through `DelegatedResourceStore`
/// but with the `v2_key(from, to)` shape (note: java-tron uses the same
/// V1 key encoding under the hood for v2 — the difference is in how the
/// `frozen_balance_for_*` fields are populated, not the key).
pub fn get_delegated_resource_v2(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // Same shape as get_delegated_resource. We expose this as a
    // distinct method because TronWeb's `tronWeb.trx.getDelegatedResourceV2`
    // exists as a separate call even though the on-disk layout overlaps.
    get_delegated_resource(p, s)
}

/// `getDelegatedResourceAccountIndex(address)` — for V1 delegations:
/// the `(fromAccounts, toAccounts)` summary for `address`. Reads the
/// V1 prefix-0x01/0x02 index entries.
pub fn get_delegated_resource_account_index(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(idx) = &s.delegated_resource_account_index else {
        return Ok(Value::Null);
    };
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let key = tron_chainbase::DelegatedResourceAccountIndexStore::legacy_key(&addr);
    encode_delegate_account_index(idx.get_raw(&key))
}

/// `getDelegatedResourceAccountIndexV2(address)` — same shape, v2
/// prefix-0x03/0x04 index entries. Only V2 has the per-resource-type
/// breakdown but the index proto layout is identical.
pub fn get_delegated_resource_account_index_v2(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // The "v2 index" in java-tron is the same proto as v1 — there is
    // no separate per-account-id index store for v2 in current mainnet.
    // The v2 entries are written through the V2 prefixes (0x03/0x04)
    // of the same DelegatedResourceAccountIndexStore. java-tron's
    // `getDelegatedResourceAccountIndexV2` reads from `getV2Index`,
    // which scans the V2-prefix slice and aggregates into the same
    // `DelegatedResourceAccountIndex` shape. Until the store exposes a
    // by-prefix scan, we return the same per-address aggregate as v1.
    get_delegated_resource_account_index(p, s)
}

fn encode_delegate_account_index(
    res: Result<Option<tron_proto::DelegatedResourceAccountIndex>, tron_chainbase::StoreError>,
) -> Result<Value, RpcError> {
    match res {
        Ok(Some(idx)) => Ok(json!({
            "account": hex_bytes(&idx.account),
            "fromAccounts": idx.from_accounts.iter().map(|a| hex_bytes(a)).collect::<Vec<_>>(),
            "toAccounts": idx.to_accounts.iter().map(|a| hex_bytes(a)).collect::<Vec<_>>(),
            "timestamp": idx.timestamp,
        })),
        Ok(None) => Ok(json!({
            "account": "",
            "fromAccounts": Vec::<Value>::new(),
            "toAccounts": Vec::<Value>::new(),
            "timestamp": 0_i64,
        })),
        Err(e) => Err(RpcError::internal(format!("delegate index read: {e}"))),
    }
}

/// `getCanWithdrawUnfreezeAmount(address, timestamp_ms)` — sum of
/// expired `unfrozen_v2[]` entries that would be released by a
/// `WithdrawExpireUnfreeze` at `timestamp`. Used by staking UIs to
/// surface a "claim" CTA.
pub fn get_can_withdraw_unfreeze_amount(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let now_ms = p
        .get(1)
        .and_then(|v| v.as_i64())
        .unwrap_or_else(|| s.dyn_props.latest_block_header_timestamp().unwrap_or(0));
    let account = match s
        .accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?
    {
        Some(a) => a,
        None => return Ok(json!({ "amount": 0_i64 })),
    };
    let amount: i64 = account
        .unfrozen_v2
        .iter()
        .filter(|u| u.unfreeze_expire_time <= now_ms)
        .map(|u| u.unfreeze_amount)
        .sum();
    Ok(json!({ "amount": amount }))
}

/// `getAvailableUnfreezeCount(address)` — number of additional
/// `UnfreezeBalanceV2` slots the account can use before hitting
/// `UNFREEZE_MAX_TIMES` (32, per tron-actuator::freeze_v2). java-tron's
/// "available" view counts active unfreezes only — expired entries
/// that haven't been withdrawn don't count against the cap.
pub fn get_available_unfreeze_count(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let addr = parse_eth_address(addr_str)?;
    let now_ms = s.dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let max_slots = tron_actuator_unfreeze_max_times() as i64;
    let account = match s
        .accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?
    {
        Some(a) => a,
        None => return Ok(json!({ "count": max_slots })),
    };
    let active: i64 = account
        .unfrozen_v2
        .iter()
        .filter(|u| u.unfreeze_expire_time > now_ms)
        .count() as i64;
    Ok(json!({ "count": (max_slots - active).max(0) }))
}

/// Local mirror of `tron_actuator::freeze_v2::UNFREEZE_MAX_TIMES`.
/// Inlined here to avoid an extra crate-edge dependency.
const fn tron_actuator_unfreeze_max_times() -> usize {
    32
}

// =============================================================================
// Block pagination
// =============================================================================

/// `getBlock(id_or_num, detail)` — unified block fetch. java-tron's
/// HTTP `/wallet/getblock` takes a single value that's either:
///
/// * a hex block hash → fetched via `block_index`'s reverse lookup
///   (we look up via `BlockStore::get_by_hash`), OR
/// * an integer / numeric string → block number → `block_index.get(n)`
///
/// `detail` (default true) controls whether transactions are inlined.
pub fn get_block(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let first = p.get(0);
    let detail = p.get(1).and_then(|v| v.as_bool()).unwrap_or(true);
    let id_opt = if let Some(num) = first.and_then(|v| v.as_i64()) {
        s.block_index.get(num).ok()
    } else if let Some(s_str) = first.and_then(|v| v.as_str()) {
        // Numeric string → block number.
        if let Ok(num) = s_str.parse::<i64>() {
            s.block_index.get(num).ok()
        } else {
            // Treat as a 32-byte hash.
            match parse_hex_bytes(s_str) {
                Ok(b) if b.len() == 32 => {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&b);
                    Some(tron_types::BlockId::from_raw(h))
                }
                _ => None,
            }
        }
    } else {
        // No argument → head block.
        let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
        s.block_index.get(head).ok()
    };
    let Some(id) = id_opt else {
        return Ok(Value::Null);
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(encode_block_for_rpc(&id, &block, detail))
}

/// `getBlockById(hash)` — block lookup by 32-byte hash.
pub fn get_block_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let hash_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block hash"))?;
    let bytes = parse_hex_bytes(hash_str)?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("block hash must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    let id = tron_types::BlockId::from_raw(h);
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(encode_block_for_rpc(&id, &block, true))
}

/// `getBlockByLimitNext(start_num, end_num)` — half-open range
/// `[start_num, end_num)`. java-tron caps the request at 100 blocks
/// per call to bound the response size; we mirror that cap.
pub fn get_block_by_limit_next(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let start = p
        .get(0)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RpcError::invalid_params("missing start_num"))?;
    let end = p
        .get(1)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RpcError::invalid_params("missing end_num"))?;
    if end <= start {
        return Ok(json!({ "block": Vec::<Value>::new() }));
    }
    const MAX_PAGE: i64 = 100;
    let effective_end = (start + MAX_PAGE).min(end);
    let mut out = Vec::with_capacity((effective_end - start) as usize);
    for num in start..effective_end {
        let Ok(id) = s.block_index.get(num) else { continue };
        let Ok(block) = s.blocks.get(&id) else { continue };
        out.push(encode_block_for_rpc(&id, &block, true));
    }
    Ok(json!({ "block": out }))
}

/// `getBlockByLatestNum(num)` — the last `num` blocks, oldest first.
/// Caps at 100 blocks per call to match java-tron's
/// `WalletApi.getBlockByLatestNum2` bound.
pub fn get_block_by_latest_num(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let n = p
        .get(0)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RpcError::invalid_params("missing num"))?;
    if n <= 0 {
        return Ok(json!({ "block": Vec::<Value>::new() }));
    }
    let head = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let take = n.min(100).min(head + 1);
    let start = (head + 1 - take).max(0);
    let mut out = Vec::with_capacity(take as usize);
    for num in start..=head {
        let Ok(id) = s.block_index.get(num) else { continue };
        let Ok(block) = s.blocks.get(&id) else { continue };
        out.push(encode_block_for_rpc(&id, &block, true));
    }
    Ok(json!({ "block": out }))
}

// =============================================================================
// Contract / asset / proposal lookups
// =============================================================================

/// Resolve a contract row the way java-tron's `Wallet.getContract` /
/// `getContractInfo` do: the account must exist, the `contract` store
/// must have a row, and the ABI (split into the `abi` column family on
/// post-split chains) is stitched back onto the proto when present.
fn load_contract_with_abi(
    s: &RpcState,
    addr: &tron_crypto::address::Address,
) -> Result<Option<tron_proto::SmartContract>, RpcError> {
    let Some(contracts) = &s.contracts else {
        return Ok(None);
    };
    // java: `accountStore.get(address) == null` → null response.
    let account_exists = s
        .accounts
        .get(addr)
        .map_err(|e| RpcError::internal(format!("account read: {e}")))?
        .is_some();
    if !account_exists {
        return Ok(None);
    }
    let Some(mut contract) = contracts
        .get(addr)
        .map_err(|e| RpcError::internal(format!("contract read: {e}")))?
    else {
        return Ok(None);
    };
    if let Some(abis) = &s.abis {
        if let Ok(Some(abi)) = abis.get(addr) {
            contract.abi = Some(abi);
        }
    }
    Ok(Some(contract))
}

/// `getContract(address)` — the static `SmartContract` metadata
/// (origin, ABI, contract_address, name, settings). Does NOT include
/// runtime code; use `getContractInfo` or `eth_getCode` for that.
pub fn get_contract(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing contract address"))?;
    let addr = parse_eth_address(addr_str)?;
    match load_contract_with_abi(s, &addr)? {
        Some(contract) => Ok(encode_smart_contract(&contract)),
        None => Ok(Value::Null),
    }
}

/// `getContractInfo(address)` — java-tron's `SmartContractDataWrapper`:
/// `{smart_contract, runtimecode, contract_state}`. The runtime code is
/// looked up by ADDRESS (java-tron `CodeStore` keying), and
/// `contract_state` is the caught-up-for-display view of the dynamic-
/// energy record (java runs `catchUpToCycle` on the served capsule
/// without writing it back; a missing record serves
/// `{update_cycle: currentCycleNumber}`).
pub fn get_contract_info(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing contract address"))?;
    let addr = parse_eth_address(addr_str)?;
    let Some(contract) = load_contract_with_abi(s, &addr)? else {
        return Ok(Value::Null);
    };
    // java: a contract row without code yields runtimecode = "".
    let runtime_code = match &s.code {
        Some(code) => code.get(addr.as_bytes()).ok().flatten().unwrap_or_default(),
        None => Vec::new(),
    };

    let current_cycle = s.dyn_props.current_cycle_number();
    let contract_state = match &s.eth_call_backends {
        Some(b) => {
            let cs = tron_chainbase::ContractStateStore::new(b.contract_state.clone());
            let threshold = s.dyn_props.get_long(b"DYNAMIC_ENERGY_THRESHOLD").unwrap_or(0);
            let increase = s
                .dyn_props
                .get_long(b"DYNAMIC_ENERGY_INCREASE_FACTOR")
                .unwrap_or(0);
            let max_factor = s.dyn_props.get_long(b"DYNAMIC_ENERGY_MAX_FACTOR").unwrap_or(0);
            cs.caught_up_view(&addr, current_cycle, threshold, increase, max_factor)
                .map_err(|e| RpcError::internal(format!("contract state read: {e}")))?
        }
        None => tron_proto::ContractState {
            update_cycle: current_cycle,
            ..Default::default()
        },
    };
    let mut csm = serde_json::Map::new();
    if contract_state.energy_usage != 0 {
        csm.insert("energy_usage".into(), json!(contract_state.energy_usage));
    }
    if contract_state.energy_factor != 0 {
        csm.insert("energy_factor".into(), json!(contract_state.energy_factor));
    }
    if contract_state.update_cycle != 0 {
        csm.insert("update_cycle".into(), json!(contract_state.update_cycle));
    }

    let mut m = serde_json::Map::new();
    m.insert("smart_contract".into(), encode_smart_contract(&contract));
    if !runtime_code.is_empty() {
        m.insert("runtimecode".into(), json!(hex::encode(&runtime_code)));
    }
    m.insert("contract_state".into(), Value::Object(csm));
    Ok(Value::Object(m))
}

/// java-tron JsonFormat rendering of a `SmartContract`: proto field
/// names, bare hex for bytes, defaults omitted, ABI enums as value
/// names ("Function", "View", …).
fn encode_smart_contract(c: &tron_proto::SmartContract) -> Value {
    let mut m = serde_json::Map::new();
    if !c.origin_address.is_empty() {
        m.insert("origin_address".into(), json!(hex::encode(&c.origin_address)));
    }
    if !c.contract_address.is_empty() {
        m.insert("contract_address".into(), json!(hex::encode(&c.contract_address)));
    }
    if let Some(a) = &c.abi {
        m.insert("abi".into(), encode_abi(a));
    }
    if !c.bytecode.is_empty() {
        m.insert("bytecode".into(), json!(hex::encode(&c.bytecode)));
    }
    if c.call_value != 0 {
        m.insert("call_value".into(), json!(c.call_value));
    }
    if c.consume_user_resource_percent != 0 {
        m.insert(
            "consume_user_resource_percent".into(),
            json!(c.consume_user_resource_percent),
        );
    }
    if !c.name.is_empty() {
        m.insert("name".into(), json!(c.name));
    }
    if c.origin_energy_limit != 0 {
        m.insert("origin_energy_limit".into(), json!(c.origin_energy_limit));
    }
    if !c.code_hash.is_empty() {
        m.insert("code_hash".into(), json!(hex::encode(&c.code_hash)));
    }
    if !c.trx_hash.is_empty() {
        m.insert("trx_hash".into(), json!(hex::encode(&c.trx_hash)));
    }
    if c.version != 0 {
        m.insert("version".into(), json!(c.version));
    }
    Value::Object(m)
}

/// ABI rendering — java JsonFormat omits unset/default fields per
/// entry, so e.g. `balanceOf` renders as `{"outputs": [...], "constant":
/// true, "name": "balanceOf", "inputs": [...], "type": "Function",
/// "stateMutability": "View"}` with no `anonymous`/`payable` keys.
fn encode_abi(abi: &tron_proto::smart_contract::Abi) -> Value {
    if abi.entrys.is_empty() {
        return json!({});
    }
    let entrys: Vec<Value> = abi
        .entrys
        .iter()
        .map(|e| {
            let mut em = serde_json::Map::new();
            if e.anonymous {
                em.insert("anonymous".into(), json!(true));
            }
            if e.constant {
                em.insert("constant".into(), json!(true));
            }
            if !e.name.is_empty() {
                em.insert("name".into(), json!(e.name));
            }
            if !e.inputs.is_empty() {
                em.insert("inputs".into(), json!(encode_abi_params(&e.inputs)));
            }
            if !e.outputs.is_empty() {
                em.insert("outputs".into(), json!(encode_abi_params(&e.outputs)));
            }
            if e.r#type != 0 {
                let name = tron_proto::smart_contract::abi::entry::EntryType::try_from(e.r#type)
                    .map(|t| t.as_str_name().to_string())
                    .unwrap_or_else(|_| e.r#type.to_string());
                em.insert("type".into(), json!(name));
            }
            if e.payable {
                em.insert("payable".into(), json!(true));
            }
            if e.state_mutability != 0 {
                let name = tron_proto::smart_contract::abi::entry::StateMutabilityType::try_from(
                    e.state_mutability,
                )
                .map(|t| t.as_str_name().to_string())
                .unwrap_or_else(|_| e.state_mutability.to_string());
                em.insert("stateMutability".into(), json!(name));
            }
            Value::Object(em)
        })
        .collect();
    json!({ "entrys": entrys })
}

fn encode_abi_params(params: &[tron_proto::smart_contract::abi::entry::Param]) -> Vec<Value> {
    params
        .iter()
        .map(|p| {
            let mut pm = serde_json::Map::new();
            if p.indexed {
                pm.insert("indexed".into(), json!(true));
            }
            if !p.name.is_empty() {
                pm.insert("name".into(), json!(p.name));
            }
            if !p.r#type.is_empty() {
                pm.insert("type".into(), json!(p.r#type));
            }
            Value::Object(pm)
        })
        .collect()
}

/// `getProposalById(id)` — single proposal lookup. java-tron returns
/// the same shape as the entries in `listProposals`.
pub fn get_proposal_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(ps) = &s.proposals else {
        return Ok(Value::Null);
    };
    let id = p
        .get(0)
        .and_then(|v| v.as_i64())
        .or_else(|| {
            p.get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
        })
        .ok_or_else(|| RpcError::invalid_params("missing proposal id"))?;
    match ps
        .get(id)
        .map_err(|e| RpcError::internal(format!("proposal read: {e}")))?
    {
        Some(p) => Ok(json!({
            "proposalId": id,
            "proposerAddress": hex_bytes(&p.proposer_address),
            "parameters": p.parameters.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
            "expirationTime": p.expiration_time,
            "createTime": p.create_time,
            "approvalsCount": p.approvals.len(),
            "state": p.state,
        })),
        None => Ok(Value::Null),
    }
}

/// `getAssetIssueByAccount(owner_address)` — every asset issued by the
/// given account. Filters the V2 asset list by `owner_address`. Most
/// accounts have 0 or 1 issued asset.
pub fn get_asset_issue_by_account(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(assets) = &s.assets_v2 else {
        return Ok(json!({ "assetIssue": Vec::<Value>::new() }));
    };
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing owner address"))?;
    let addr = parse_eth_address(addr_str)?;
    let all = assets
        .all()
        .map_err(|e| RpcError::internal(format!("asset scan: {e}")))?;
    let filtered: Vec<Value> = all
        .into_iter()
        .filter(|(_, a)| a.owner_address == addr.as_bytes())
        .map(|(id, a)| {
            json!({
                "id": id,
                "owner_address": hex_bytes(&a.owner_address),
                "name": hex_bytes(&a.name),
                "abbr": hex_bytes(&a.abbr),
                "total_supply": a.total_supply,
                "trx_num": a.trx_num,
                "precision": a.precision,
                "num": a.num,
                "start_time": a.start_time,
                "end_time": a.end_time,
                "description": hex_bytes(&a.description),
                "url": hex_bytes(&a.url),
                "free_asset_net_limit": a.free_asset_net_limit,
                "public_free_asset_net_limit": a.public_free_asset_net_limit,
                "public_free_asset_net_usage": a.public_free_asset_net_usage,
                "public_latest_free_net_time": a.public_latest_free_net_time,
            })
        })
        .collect();
    Ok(json!({ "assetIssue": filtered }))
}

/// `validateAddress(address)` — sanity check an address. Accepts:
/// * 21-byte hex (with or without `0x` / `41` prefix)
/// * base58check (e.g. `THKJYuUmMKKAR...`)
///
/// Returns `{ result: bool, message: string }` mirroring java-tron's
/// `wallet.validateAddress`.
pub fn validate_address(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;

    // Try hex first.
    if let Ok(bytes) = parse_hex_bytes(addr_str) {
        let valid = matches!(bytes.len(), 20 | 21)
            && (bytes.len() == 20 || bytes[0] == 0x41);
        return Ok(json!({
            "result": valid,
            "message": if valid { "Valid address" } else { "Invalid address" },
        }));
    }

    // Try base58check.
    let valid = tron_crypto::base58check::decode_address(addr_str).is_ok();
    Ok(json!({
        "result": valid,
        "message": if valid { "Valid address" } else { "Invalid address" },
    }))
}

/// `getPendingSize` — number of transactions in our local mempool.
/// Returns 0 when no mempool is attached (the same shape a quiescent
/// java-tron full node returns).
pub fn get_pending_size(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let n = s.mempool.as_ref().map(|m| m.pending_count() as i64).unwrap_or(0);
    Ok(json!({ "pendingSize": n }))
}

// =============================================================================
// txpool_* (geth-compatible mempool inspection)
// =============================================================================
//
// Ethereum tooling expects three methods to enumerate the local mempool:
//   * `txpool_status`  — counts only.
//   * `txpool_content` — full txs grouped by sender → nonce → tx object.
//   * `txpool_inspect` — like content but with summary strings.
//
// java-tron doesn't ship these (TRON's HTTP API exposes
// `wallet/getpendingsize` instead), but the ecosystem clients
// (Hardhat, ethers, foundry) probe for them. java-tron's lack is one
// of the recurring sources of "this node looks dead" reports from
// people coming over from Ethereum.
//
// TRON-specific shape choices, since TRON txs have no per-account
// nonce:
//   * Group by signer address (the recovered owner from the first
//     contract). For multi-contract txs we use the first contract's
//     owner — matches what every TRON wallet displays as "from".
//   * Use the tx_id hex as the inner "nonce" key. Stable, unique, and
//     clients that just iterate the map don't care about ordering.
//   * `queued` is always empty — TRON has no concept of nonce-gapped
//     pending txs.

/// Format a 21-byte TRON address as the lowercase `0x41` + 20-byte
/// hex string clients expect.
fn fmt_tron_address(addr: &[u8]) -> String {
    if addr.len() == 21 {
        format!("0x{}", hex::encode(addr))
    } else {
        format!("0x{}", hex::encode(addr))
    }
}

/// Recover the signer address from a pending tx. Empty signature ⇒
/// returns `0x` + zero-padded 21 bytes (anonymous bucket). Multiple
/// signatures (multi-sig perm) ⇒ first signer wins.
fn pending_tx_signer(tx: &tron_proto::Transaction) -> String {
    match tron_types::recover_all_signers(tx) {
        Ok(signers) if !signers.is_empty() => fmt_tron_address(signers[0].as_bytes()),
        _ => "0x000000000000000000000000000000000000000000".to_string(),
    }
}

/// Pull a `(to, value)` summary out of the first contract in a tx.
/// Used by `txpool_inspect`. Returns `("0x", 0)` for contracts that
/// don't have an obvious destination.
fn pending_tx_to_and_value(tx: &tron_proto::Transaction) -> (String, i64) {
    let Some(raw) = &tx.raw_data else {
        return ("0x".into(), 0);
    };
    let Some(contract) = raw.contract.first() else {
        return ("0x".into(), 0);
    };
    let Some(param) = &contract.parameter else {
        return ("0x".into(), 0);
    };
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;
    let ty = match ContractType::try_from(contract.r#type) {
        Ok(t) => t,
        Err(_) => return ("0x".into(), 0),
    };
    match ty {
        ContractType::TransferContract => {
            if let Ok(c) = tron_proto::TransferContract::decode(param.value.as_slice()) {
                return (fmt_tron_address(&c.to_address), c.amount);
            }
        }
        ContractType::TriggerSmartContract => {
            if let Ok(c) = tron_proto::TriggerSmartContract::decode(param.value.as_slice()) {
                return (fmt_tron_address(&c.contract_address), c.call_value);
            }
        }
        ContractType::TransferAssetContract => {
            if let Ok(c) = tron_proto::TransferAssetContract::decode(param.value.as_slice()) {
                return (fmt_tron_address(&c.to_address), c.amount);
            }
        }
        _ => {}
    }
    ("0x".into(), 0)
}

/// Render a pending tx as the full JSON object Ethereum clients
/// expect from `txpool_content`. We embed the contract type and the
/// raw protobuf hex so tooling that understands TRON can pick the
/// useful fields out; the eth-shape fields (`to`, `value`, `input`,
/// `gas`, `gasPrice`, `nonce`, `hash`, `from`) are populated with
/// best-effort TRON equivalents so generic dashboards render
/// something coherent.
fn render_pending_tx_object(entry: &crate::mempool::MempoolEntry) -> Value {
    use prost::Message as _;
    let Ok(tx) = tron_proto::Transaction::decode(entry.raw_bytes.as_slice()) else {
        return json!({
            "hash": format!("0x{}", hex::encode(entry.tx_id)),
            "from": "0x0000000000000000000000000000000000000000",
            "to": "0x",
            "value": "0x0",
            "input": "0x",
            "nonce": "0x0",
            "gas": "0x0",
            "gasPrice": "0x0",
            "decodeError": "malformed protobuf",
        });
    };
    let from = pending_tx_signer(&tx);
    let (to, value) = pending_tx_to_and_value(&tx);
    let contract_type = tx
        .raw_data
        .as_ref()
        .and_then(|r| r.contract.first())
        .map(|c| c.r#type)
        .unwrap_or(0);
    json!({
        "hash": format!("0x{}", hex::encode(entry.tx_id)),
        "from": from,
        "to": to,
        "value": format!("0x{:x}", value.max(0) as u64),
        "input": format!("0x{}", hex::encode(&entry.raw_bytes)),
        // TRON has no nonces; we expose the tx_id hex prefix so
        // clients that key by nonce see something stable. eth tooling
        // that requires a hex quantity will accept any 0x string.
        "nonce": "0x0",
        "gas": "0x0",
        "gasPrice": "0x0",
        "contractType": contract_type,
        "receivedAtMs": entry.received_at_ms,
    })
}

/// `txpool_status` — `{pending: hex, queued: hex}`. Queued is always
/// 0 in TRON (no nonce-gapped pending semantics).
pub fn txpool_status(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let pending = s.mempool.as_ref().map(|m| m.pending_count()).unwrap_or(0);
    Ok(json!({
        "pending": format!("0x{:x}", pending),
        "queued": "0x0",
    }))
}

/// `txpool_content` — full pool grouped by sender → `tx_id` → tx
/// object. Queued bucket is always empty. Mirrors geth's shape.
pub fn txpool_content(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(mempool) = s.mempool.as_ref() else {
        return Ok(json!({"pending": {}, "queued": {}}));
    };
    use prost::Message as _;
    let entries = mempool.pending_snapshot();
    let mut pending: serde_json::Map<String, Value> = serde_json::Map::new();
    for entry in &entries {
        // Decode once to get the signer; reuse for the object render.
        let from = tron_proto::Transaction::decode(entry.raw_bytes.as_slice())
            .map(|tx| pending_tx_signer(&tx))
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000000000".into());
        let bucket = pending
            .entry(from)
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Value::Object(map) = bucket {
            map.insert(format!("0x{}", hex::encode(entry.tx_id)), render_pending_tx_object(entry));
        }
    }
    Ok(json!({
        "pending": Value::Object(pending),
        "queued": Value::Object(serde_json::Map::new()),
    }))
}

/// `txpool_inspect` — geth-shape summary: `from → tx_id → "to: VALUE wei + GAS gas × GASPRICE"`.
/// The geth-format summary string keeps existing clients happy; we
/// substitute TRON-natural values for the eth-only fields.
pub fn txpool_inspect(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(mempool) = s.mempool.as_ref() else {
        return Ok(json!({"pending": {}, "queued": {}}));
    };
    use prost::Message as _;
    let entries = mempool.pending_snapshot();
    let mut pending: serde_json::Map<String, Value> = serde_json::Map::new();
    for entry in &entries {
        let Ok(tx) = tron_proto::Transaction::decode(entry.raw_bytes.as_slice()) else {
            continue;
        };
        let from = pending_tx_signer(&tx);
        let (to, value) = pending_tx_to_and_value(&tx);
        let summary = format!("{to}: {value} sun + 0 gas × 0 wei");
        let bucket = pending
            .entry(from)
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Value::Object(map) = bucket {
            map.insert(
                format!("0x{}", hex::encode(entry.tx_id)),
                Value::String(summary),
            );
        }
    }
    Ok(json!({
        "pending": Value::Object(pending),
        "queued": Value::Object(serde_json::Map::new()),
    }))
}

// =============================================================================
// Market (DEX) read methods
// =============================================================================
//
// java-tron's market lets users post limit orders against a TRC-10/TRX
// pair. The on-disk layout is in four stores; we read but don't mutate
// (the actuator path for `MarketSellAssetContract` / `MarketCancelOrderContract`
// is not yet implemented). Read coverage is enough for explorers and
// dashboards that show open orders.

/// Token-id length in the on-disk pair key. Matches java-tron's
/// `MarketUtils.TOKEN_ID_LENGTH` = `Long.toString(Long.MAX_VALUE).length` = 19.
const MARKET_TOKEN_ID_LENGTH: usize = 19;

/// `getMarketOrderById(order_id)` — single order by its 32-byte
/// keccak-hashed id. java-tron uses opaque bytes for the order id;
/// callers typically pass it as hex.
pub fn get_market_order_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(orders) = &s.market_orders else {
        return Ok(Value::Null);
    };
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing order id"))?;
    let id = parse_hex_bytes(id_str)?;
    match orders
        .get(&id)
        .map_err(|e| RpcError::internal(format!("order read: {e}")))?
    {
        Some(o) => Ok(encode_market_order(&o)),
        None => Ok(Value::Null),
    }
}

/// `getMarketOrderByAccount(owner)` — the [`MarketAccountOrder`]
/// summary for an account (active count + total count + order_id list).
pub fn get_market_order_by_account(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(accounts) = &s.market_accounts else {
        return Ok(Value::Null);
    };
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing owner address"))?;
    let addr = parse_eth_address(addr_str)?;
    match accounts
        .get(&addr)
        .map_err(|e| RpcError::internal(format!("market account read: {e}")))?
    {
        Some(mao) => Ok(json!({
            "owner_address": hex_bytes(&mao.owner_address),
            "orders": mao.orders.iter().map(|o| hex_bytes(o)).collect::<Vec<_>>(),
            "count": mao.count,
            "total_count": mao.total_count,
        })),
        None => Ok(Value::Null),
    }
}

/// `getMarketPriceByPair(sell_token_id, buy_token_id)` — number of
/// distinct price levels currently posted for the given pair. The full
/// price-list scan (`MarketPriceList`) would require iterating
/// `market_pair_price_to_order` with the right composite-key prefix,
/// which is not yet plumbed; the count alone is what most explorers
/// surface.
pub fn get_market_price_by_pair(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(prices) = &s.market_pair_to_price else {
        return Ok(Value::Null);
    };
    let (sell, buy) = parse_pair_params(p)?;
    let key = compose_pair_key(&sell, &buy);
    let count = prices
        .get(&key)
        .map_err(|e| RpcError::internal(format!("pair price read: {e}")))?
        .unwrap_or(0);
    Ok(json!({
        "sell_token_id": hex_bytes(&sell),
        "buy_token_id": hex_bytes(&buy),
        "price_level_count": count,
    }))
}

/// `getMarketPairList` — every `(sell, buy)` pair with at least one
/// posted order. Decodes the on-disk pair-key (`sellTokenId(19) ||
/// buyTokenId(19)`) into typed fields per entry.
pub fn get_market_pair_list(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(prices) = &s.market_pair_to_price else {
        return Ok(json!({ "orderPair": Vec::<Value>::new() }));
    };
    let pairs: Vec<Value> = prices
        .all()?
        .into_iter()
        .filter_map(|(k, _count)| {
            if k.len() != 2 * MARKET_TOKEN_ID_LENGTH {
                return None;
            }
            let sell = &k[..MARKET_TOKEN_ID_LENGTH];
            let buy = &k[MARKET_TOKEN_ID_LENGTH..];
            Some(json!({
                "sell_token_id": hex_bytes(sell),
                "buy_token_id": hex_bytes(buy),
            }))
        })
        .collect();
    Ok(json!({ "orderPair": pairs }))
}

/// `getMarketOrderListByPair(sell, buy)` — orders posted against the
/// pair. The full implementation requires scanning the
/// `market_pair_price_to_order` store with the pair-key prefix and
/// chasing the `MarketOrderIdList` for each price level. Our v1 returns
/// an empty list with the pair echoed back — sufficient for clients
/// that only need the empty/non-empty signal pre-real-DEX-activity.
/// Pinned as a follow-up when the actuator-side market ops land.
pub fn get_market_order_list_by_pair(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let (sell, buy) = parse_pair_params(p)?;
    Ok(json!({
        "sell_token_id": hex_bytes(&sell),
        "buy_token_id": hex_bytes(&buy),
        "orders": Vec::<Value>::new(),
    }))
}

fn parse_pair_params(p: &Value) -> Result<(Vec<u8>, Vec<u8>), RpcError> {
    let sell_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing sell_token_id"))?;
    let buy_str = p
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing buy_token_id"))?;
    // Token ids are 19-byte decimal-string blobs on disk. Accept
    // either hex (typical for RPC clients) or a raw decimal id —
    // which we re-encode to the 19-byte form via `pad_token_id`.
    let parse = |s: &str| -> Result<Vec<u8>, RpcError> {
        if let Some(rest) = s.strip_prefix("0x") {
            return Ok(parse_hex_bytes(&format!("0x{rest}"))?);
        }
        if s.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(pad_token_id(s.as_bytes()));
        }
        // Plain ASCII string (e.g., token name) — pad as-is.
        Ok(pad_token_id(s.as_bytes()))
    };
    Ok((parse(sell_str)?, parse(buy_str)?))
}

/// Pad a token-id blob to the canonical 19-byte length used in pair
/// keys. Left-padded with zero bytes if shorter (mirrors java-tron's
/// `Arrays.copyOf` semantics in `createPairKey`).
fn pad_token_id(id: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; MARKET_TOKEN_ID_LENGTH];
    let take = id.len().min(MARKET_TOKEN_ID_LENGTH);
    out[..take].copy_from_slice(&id[..take]);
    out
}

fn compose_pair_key(sell: &[u8], buy: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 * MARKET_TOKEN_ID_LENGTH);
    k.extend_from_slice(sell);
    k.extend_from_slice(buy);
    k
}

fn encode_market_order(o: &tron_proto::MarketOrder) -> Value {
    json!({
        "order_id": hex_bytes(&o.order_id),
        "owner_address": hex_bytes(&o.owner_address),
        "create_time": o.create_time,
        "sell_token_id": hex_bytes(&o.sell_token_id),
        "sell_token_quantity": o.sell_token_quantity,
        "buy_token_id": hex_bytes(&o.buy_token_id),
        "buy_token_quantity": o.buy_token_quantity,
        "sell_token_quantity_remain": o.sell_token_quantity_remain,
        "sell_token_quantity_return": o.sell_token_quantity_return,
        "state": o.state,
        "prev": hex_bytes(&o.prev),
        "next": hex_bytes(&o.next),
    })
}

// =============================================================================
// Asset-by-name + pagination
// =============================================================================

/// `getAssetIssueByName(name)` — fetch the FIRST asset whose `name`
/// field matches. Java-tron uses this for the legacy
/// `ALLOW_SAME_TOKEN_NAME=0` path where names were globally unique;
/// after the fork, multiple assets can share a name and this returns
/// only the first one. Use `getAssetIssueListByName` for the full set.
pub fn get_asset_issue_by_name(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(assets) = &s.assets_v2 else {
        return Ok(Value::Null);
    };
    let name_bytes = parse_name_param(p, "missing asset name")?;
    let all = assets
        .all()
        .map_err(|e| RpcError::internal(format!("asset scan: {e}")))?;
    let found = all
        .into_iter()
        .find(|(_, a)| a.name == name_bytes)
        .map(|(id, a)| encode_asset(id, &a));
    Ok(found.unwrap_or(Value::Null))
}

/// `getAssetIssueListByName(name)` — every asset whose name field
/// matches the parameter. Returns `{ assetIssue: [...] }`.
pub fn get_asset_issue_list_by_name(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(assets) = &s.assets_v2 else {
        return Ok(json!({ "assetIssue": Vec::<Value>::new() }));
    };
    let name_bytes = parse_name_param(p, "missing asset name")?;
    let all = assets
        .all()
        .map_err(|e| RpcError::internal(format!("asset scan: {e}")))?;
    let filtered: Vec<Value> = all
        .into_iter()
        .filter(|(_, a)| a.name == name_bytes)
        .map(|(id, a)| encode_asset(id, &a))
        .collect();
    Ok(json!({ "assetIssue": filtered }))
}

/// `getPaginatedAssetIssueList(offset, limit)` — slice of all V2
/// assets, sorted by id ascending. Caps `limit` at 100 (matches
/// java-tron's `Wallet.getPaginatedAssetIssueList` bound).
pub fn get_paginated_asset_issue_list(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(assets) = &s.assets_v2 else {
        return Ok(json!({ "assetIssue": Vec::<Value>::new() }));
    };
    let (offset, limit) = parse_offset_limit(p, 100)?;
    let mut all = assets
        .all()
        .map_err(|e| RpcError::internal(format!("asset scan: {e}")))?;
    all.sort_by_key(|(id, _)| *id);
    let slice: Vec<Value> = all
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(id, a)| encode_asset(id, &a))
        .collect();
    Ok(json!({ "assetIssue": slice }))
}

/// `getPaginatedProposalList(offset, limit)`. Cap 100.
pub fn get_paginated_proposal_list(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(ps) = &s.proposals else {
        return Ok(json!({ "proposals": Vec::<Value>::new() }));
    };
    let (offset, limit) = parse_offset_limit(p, 100)?;
    let mut all = ps
        .all()
        .map_err(|e| RpcError::internal(format!("proposal scan: {e}")))?;
    all.sort_by_key(|(id, _)| *id);
    let slice: Vec<Value> = all
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(id, p)| {
            json!({
                "proposalId": id,
                "proposerAddress": hex_bytes(&p.proposer_address),
                "parameters": p.parameters.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
                "expirationTime": p.expiration_time,
                "createTime": p.create_time,
                "approvalsCount": p.approvals.len(),
                "state": p.state,
            })
        })
        .collect();
    Ok(json!({ "proposals": slice }))
}

/// `getPaginatedExchangeList(offset, limit)`. Cap 100.
pub fn get_paginated_exchange_list(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(es) = &s.exchanges_v2 else {
        return Ok(json!({ "exchanges": Vec::<Value>::new() }));
    };
    let (offset, limit) = parse_offset_limit(p, 100)?;
    let mut all = es
        .all()
        .map_err(|e| RpcError::internal(format!("exchange scan: {e}")))?;
    all.sort_by_key(|(id, _)| *id);
    let slice: Vec<Value> = all
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|(id, e)| {
            json!({
                "exchange_id": id,
                "creator_address": hex_bytes(&e.creator_address),
                "create_time": e.create_time,
                "first_token_id": hex_bytes(&e.first_token_id),
                "first_token_balance": e.first_token_balance,
                "second_token_id": hex_bytes(&e.second_token_id),
                "second_token_balance": e.second_token_balance,
            })
        })
        .collect();
    Ok(json!({ "exchanges": slice }))
}

fn parse_name_param(p: &Value, missing_msg: &str) -> Result<Vec<u8>, RpcError> {
    let s = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params(missing_msg))?;
    if let Some(rest) = s.strip_prefix("0x") {
        return parse_hex_bytes(&format!("0x{rest}"));
    }
    Ok(s.as_bytes().to_vec())
}

fn parse_offset_limit(p: &Value, max_limit: i64) -> Result<(i64, i64), RpcError> {
    let offset = p
        .get(0)
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0);
    let raw_limit = p
        .get(1)
        .and_then(|v| v.as_i64())
        .unwrap_or(max_limit);
    let limit = raw_limit.max(0).min(max_limit);
    Ok((offset, limit))
}

fn encode_asset(id: i64, a: &tron_proto::AssetIssueContract) -> Value {
    json!({
        "id": id,
        "owner_address": hex_bytes(&a.owner_address),
        "name": hex_bytes(&a.name),
        "abbr": hex_bytes(&a.abbr),
        "total_supply": a.total_supply,
        "trx_num": a.trx_num,
        "precision": a.precision,
        "num": a.num,
        "start_time": a.start_time,
        "end_time": a.end_time,
        "description": hex_bytes(&a.description),
        "url": hex_bytes(&a.url),
        "free_asset_net_limit": a.free_asset_net_limit,
        "public_free_asset_net_limit": a.public_free_asset_net_limit,
        "public_free_asset_net_usage": a.public_free_asset_net_usage,
        "public_latest_free_net_time": a.public_latest_free_net_time,
    })
}

// =============================================================================
// Transaction lookup + misc
// =============================================================================

/// `getTransactionById(tx_id)` — raw `Transaction` proto by sha256
/// transaction id. java-tron's HTTP API returns the protobuf encoded
/// as JSON; we emit a flat object with the key fields wallets need
/// (raw_data hash, contract list, signatures, ret status).
///
/// Distinct from `getTransactionInfoById` which returns the receipt
/// (logs / fee / energy_used). Use this for the *input* shape; use
/// the info variant for the *output* shape.
pub fn get_transaction_by_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx id"))?;
    let id_bytes = parse_hex_bytes(id_str)?;
    if id_bytes.len() != 32 {
        return Err(RpcError::invalid_params("tx id must be 32 bytes"));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_bytes);
    let stored = s
        .transactions
        .get(&id)
        .map_err(|e| RpcError::internal(format!("tx read: {e}")))?;
    let stored = match stored {
        Some(t) => t,
        None => return Ok(Value::Null),
    };
    let tx = match stored {
        tron_chainbase::StoredTransaction::Full(tx) => tx,
        tron_chainbase::StoredTransaction::BlockRef(num) => {
            // Resolve the full body through the canonical block — one
            // block read, exactly java-tron's lite-node lookup path.
            let hydrated = s
                .block_index
                .get(num)
                .ok()
                .and_then(|block_id| s.blocks.get(&block_id).ok())
                .and_then(|block| {
                    block.transactions.into_iter().find(|tx| {
                        tx.raw_data
                            .as_ref()
                            .map(|raw| {
                                tron_crypto::hash::sha256(&raw.encode_to_vec()) == id
                            })
                            .unwrap_or(false)
                    })
                });
            match hydrated {
                Some(tx) => tx,
                None => {
                    // Ref exists but the body is gone (pruned block) —
                    // surface the minimal shape so clients know the tx
                    // exists.
                    return Ok(json!({
                        "txID": hex_bytes(&id),
                        "status": "block_ref_only",
                        "block_num": num,
                    }));
                }
            }
        }
    };

    let raw = tx.raw_data.as_ref();
    let contracts: Vec<Value> = raw
        .map(|r| {
            r.contract
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
                .collect()
        })
        .unwrap_or_default();

    Ok(json!({
        "txID": hex_bytes(&id),
        "raw_data": {
            "expiration": raw.map(|r| r.expiration).unwrap_or(0),
            "timestamp": raw.map(|r| r.timestamp).unwrap_or(0),
            "fee_limit": raw.map(|r| r.fee_limit).unwrap_or(0),
            "contract_count": contracts.len(),
            "contract": contracts,
        },
        "signature": tx.signature.iter().map(|s| hex_bytes(s)).collect::<Vec<_>>(),
        "ret": tx.ret.iter().map(|r| json!({
            "fee": r.fee,
            "contractRet": r.contract_ret,
        })).collect::<Vec<_>>(),
    }))
}

/// `getTotalTransaction` / `totalTransaction` — chain-wide tx counter.
/// java-tron's implementation has been deprecated and returns 0
/// (see `TransactionStore.getTotalTransactions`). We mirror that.
/// `getTransactionCountByBlockNum(num)` — number of transactions in the
/// block at `num`. java-tron `GetTransactionCountByBlockNumServlet`
/// (`{count: -1}` when the block is unknown).
pub fn get_transaction_count_by_block_num(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let num = p
        .get(0)
        .and_then(|v| v.as_i64())
        .or_else(|| p.get(0).and_then(|v| v.as_str()).and_then(|x| x.parse().ok()))
        .ok_or_else(|| RpcError::invalid_params("missing block num"))?;
    let count = s
        .block_index
        .get(num)
        .ok()
        .and_then(|id| s.blocks.get(&id).ok())
        .map(|b| b.transactions.len() as i64)
        .unwrap_or(-1);
    Ok(json!({ "count": count }))
}

/// `getCanDelegatedMaxSize(owner_address, type)` — upper bound on the
/// resource a holder can still delegate. Same conservative shape as
/// the gRPC `GetCanDelegatedMaxSize`: the frozen-v2 amount for the
/// type (java additionally subtracts already-delegated + usage-locked;
/// follow-up once the per-receiver index has a typed helper).
pub fn get_can_delegated_max_size(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let addr_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing owner_address"))?;
    let r#type = p.get(1).and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let addr = parse_eth_address(addr_str)?;
    let acct = s.accounts.get(&addr).ok().flatten().unwrap_or_default();
    let max_size: i64 = acct
        .frozen_v2
        .iter()
        .filter(|f| f.r#type == r#type)
        .map(|f| f.amount)
        .sum();
    Ok(json!({ "max_size": max_size }))
}

pub fn get_total_transaction(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!({ "num": 0_i64 }))
}

/// `getMemoFee` — fee charged for TRX transfers with a non-empty memo
/// field. Set by SR proposal; defaults to 0 (free) when unset.
pub fn get_memo_fee(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let fee = s.dyn_props.get_long(b"MEMO_FEE").unwrap_or(0);
    Ok(json!({ "value": fee }))
}

/// `estimateEnergy` — wallet-side energy budget estimator. Same
/// pre-flight semantics as [`eth_estimate_gas`]: simulate the call in
/// a session, observe the gas (= energy) the VM would consume.
///
/// Returns `{ result: { result: bool, code, message }, energy_required }`
/// matching java-tron's `wallet.estimateEnergy`. Internally we just
/// delegate to `eth_estimate_gas` and reshape.
/// Run a constant call through the structured tracer and return the raw
/// outputs (outcome + per-opcode logs + call-frame tree). Mirrors
/// [`build_trace_for_call`]'s execution setup; shared by the energy breakdown.
fn traced_call_outputs(
    s: &RpcState,
    req: &EthCallRequest,
    options: tron_tvm::tracer::TracerOptions,
) -> Result<
    (
        tron_tvm::execute::VmOutcome,
        Vec<tron_tvm::tracer::StructLog>,
        Vec<tron_tvm::tracer::CallFrame>,
    ),
    RpcError,
> {
    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal(
            "tracer not available: server built without EVM call backends",
        ));
    };
    let vm_stores = build_call_vm_stores(b);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number: s.dyn_props.latest_block_header_number().unwrap_or(0),
        block_timestamp_ms: s.dyn_props.latest_block_header_timestamp().unwrap_or(0),
    };
    let trigger = tron_proto::TriggerSmartContract {
        owner_address: req.from.to_vec(),
        contract_address: req.to.to_vec(),
        call_value: req.value,
        data: req.data.clone(),
        call_token_value: 0,
        token_id: 0,
    };
    let tracer = tron_tvm::tracer::StructLogTracer::new(options);
    let (outcome, _internal, tracer) = tron_tvm::execute::execute_trigger_with_tracer(
        &vm_stores,
        block_env,
        &trigger,
        req.gas,
        s.eth_call_gas_cap,
        tracer,
    );
    let (struct_logs, call_frames) = tracer.into_outputs();
    Ok((outcome, struct_logs, call_frames))
}

/// Aggregate a structured trace into an energy breakdown: per-opcode energy
/// (where the energy went, top 15), the call-frame tree with per-frame energy,
/// and the halting op + reason if it failed. This "why it costs X / why it
/// would OOG" surface is what java-tron's bare estimate omits.
fn energy_breakdown_json(
    struct_logs: &[tron_tvm::tracer::StructLog],
    call_frames: &[tron_tvm::tracer::CallFrame],
) -> Value {
    use std::collections::HashMap;
    let mut by_op: HashMap<&str, (u64, u64)> = HashMap::new(); // (count, energy)
    let mut halt: Option<(&str, String)> = None;
    for log in struct_logs {
        let e = by_op.entry(log.op_name.as_str()).or_insert((0, 0));
        e.0 += 1;
        e.1 = e.1.saturating_add(log.gas_cost);
        if let Some(err) = &log.error {
            halt = Some((log.op_name.as_str(), err.clone()));
        }
    }
    let mut ops: Vec<(&str, u64, u64)> = by_op.into_iter().map(|(op, (c, e))| (op, c, e)).collect();
    // Highest energy first; ties broken by name for determinism.
    ops.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(b.0)));
    let by_opcode: Vec<Value> = ops
        .iter()
        .take(15)
        .map(|(op, count, energy)| json!({ "op": op, "count": count, "energy": energy }))
        .collect();

    fn flatten(frames: &[tron_tvm::tracer::CallFrame], depth: u32, out: &mut Vec<Value>) {
        for f in frames {
            out.push(json!({
                "type": f.call_type,
                "depth": depth,
                "to": f.to.map(|a| format!("0x{}", hex::encode(a))),
                "energy_used": f.gas_used,
                "error": f.error,
            }));
            flatten(&f.calls, depth + 1, out);
        }
    }
    let mut frames_out = Vec::new();
    flatten(call_frames, 1, &mut frames_out);

    json!({
        "ops_executed": struct_logs.len(),
        // `by_opcode` is capped at the 15 highest-energy opcodes; this reports
        // how many distinct opcodes existed so callers can detect truncation.
        "total_unique_opcodes": ops.len(),
        "by_opcode": by_opcode,
        "call_frames": frames_out,
        "halt": halt.map(|(op, reason)| json!({ "op": op, "reason": reason })),
    })
}

pub fn estimate_energy(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let gas_value = eth_estimate_gas(p, s)?;
    // eth_estimateGas returns a hex string; decode back to i64.
    let energy = gas_value
        .as_str()
        .and_then(|hex| u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0) as i64;
    let mut out = json!({
        "result": { "result": true },
        "energy_required": energy,
    });
    // Energy breakdown — where the energy goes (per-opcode), the call-frame
    // tree, and the halting op/reason if it would fail. Best-effort: a missing
    // tracer backend or a parse error just omits the field, leaving the total.
    if let Ok(req) = parse_eth_call_request(p, s.eth_call_gas_cap) {
        if let Ok((_outcome, logs, frames)) =
            traced_call_outputs(s, &req, tron_tvm::tracer::TracerOptions::default())
        {
            out["energy_breakdown"] = energy_breakdown_json(&logs, &frames);
        }
    }
    Ok(out)
}

// =============================================================================
// Multi-sig: getApprovedList / getSignWeight
// =============================================================================
//
// Wallet UIs that build multi-sig transactions need to (a) see who
// has signed so far, and (b) check whether the cumulative weight
// crosses the active permission's threshold. java-tron exposes both
// at HTTP path `/wallet/getapprovedlist` and `/wallet/getsignweight`,
// both taking a raw `Transaction` proto.
//
// For our JSON-RPC the input is the protobuf-encoded Transaction in
// hex — same as `eth_sendRawTransaction` — so wallets can build it
// once and probe with either method.

/// `getApprovedList(rawTxHex)` — list of addresses recovered from the
/// transaction's signatures. Includes every recoverable signature,
/// regardless of whether the signer is in the owner's permission.
pub fn get_approved_list(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let tx = parse_tx_param(p)?;
    let signers = tron_actuator::permission::approved_list(&tx).map_err(|e| {
        RpcError::internal(format!("recover signers: {e}"))
    })?;
    let tx_id = tron_types::tx_id(&tx).map_err(|e| RpcError::internal(format!("tx_id: {e:?}")))?;
    Ok(json!({
        "approved_list": signers.iter().map(|a| hex_bytes(a.as_bytes())).collect::<Vec<_>>(),
        "transaction": {
            "txID": hex_bytes(&tx_id),
            "signature_count": tx.signature.len(),
        },
        "result": { "code": "SUCCESS" },
    }))
}

/// `getSignWeight(rawTxHex)` — `getApprovedList` plus permission
/// resolution and weight summation. Mirrors java-tron's
/// `TransactionSignWeight` proto shape (over JSON).
pub fn get_sign_weight(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tx = parse_tx_param(p)?;
    let info = tron_actuator::permission::compute_sign_weight(&s.accounts, &s.dyn_props, &tx)
        .map_err(|e| RpcError::internal(format!("sign weight: {e}")))?;
    let tx_id = tron_types::tx_id(&tx).map_err(|e| RpcError::internal(format!("tx_id: {e:?}")))?;
    Ok(json!({
        "permission": {
            "type": info.permission.r#type,
            "id": info.permission.id,
            "permission_name": info.permission.permission_name,
            "threshold": info.permission.threshold,
            "parent_id": info.permission.parent_id,
            "operations": hex_bytes(&info.permission.operations),
            "keys": info.permission.keys.iter().map(|k| json!({
                "address": hex_bytes(&k.address),
                "weight": k.weight,
            })).collect::<Vec<_>>(),
        },
        "approved_list": info.approved_list.iter().map(|a| hex_bytes(a.as_bytes())).collect::<Vec<_>>(),
        "current_weight": info.current_weight,
        "result": {
            "code": info.code.as_str(),
            "message": info.message,
        },
        "transaction": {
            "txID": hex_bytes(&tx_id),
            "signature_count": tx.signature.len(),
        },
    }))
}

/// Parse a protobuf-encoded Transaction from a hex string in
/// `params[0]`. Same input shape as `eth_sendRawTransaction`.
fn parse_tx_param(p: &Value) -> Result<tron_proto::Transaction, RpcError> {
    let raw_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx hex"))?;
    let bytes = parse_hex_bytes(raw_str)?;
    tron_proto::Transaction::decode(bytes.as_slice())
        .map_err(|e| RpcError::invalid_params(format!("decode transaction: {e}")))
}

// =============================================================================
// Solidified-state aliases (walletsolidity/* namespace)
// =============================================================================
//
// java-tron splits HTTP endpoints into `wallet/*` (latest state) and
// `walletsolidity/*` (state at `LATEST_SOLIDIFIED_BLOCK_NUM`). For
// block-keyed reads this is a real difference; the solidified variant
// is what wallets use for confirmed-only queries.
//
// **Divergence note**: java-tron maintains a separate solidified-state
// snapshot of the account/asset/etc. stores so non-block reads
// (`getAccount`, `getContract`, etc.) return historical values too.
// We don't maintain that separate snapshot — only block-keyed reads
// are genuinely clamped here. Non-block-keyed solidified methods are
// aliased to the live variant with a `solidified: false` flag in the
// response so clients can detect it.

/// Resolve "head" for the solidified namespace to
/// `LATEST_SOLIDIFIED_BLOCK_NUM`. Falls back to current head if the
/// pointer hasn't been written yet (a single-node chain that never
/// reaches 2/3-threshold solidification — common in tests).
fn solidified_head(s: &RpcState) -> i64 {
    s.dyn_props
        .latest_solidified_block_num()
        .unwrap_or_else(|| s.dyn_props.latest_block_header_number().unwrap_or(0))
}

/// `getNowBlockSolidity` — newest block at or before the solidified
/// head. Equivalent to java-tron's `walletsolidity/getnowblock`.
pub fn get_now_block_solidity(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let head = solidified_head(s);
    let Ok(id) = s.block_index.get(head) else {
        return Ok(Value::Null);
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(encode_block_for_rpc(&id, &block, true))
}

/// `getBlockByNumSolidity(num)` — same as `getBlockByNum` but rejects
/// numbers above the solidified head with `Null`.
pub fn get_block_by_num_solidity(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let num = p
        .get(0)
        .and_then(|v| v.as_i64())
        .or_else(|| {
            p.get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
        })
        .ok_or_else(|| RpcError::invalid_params("missing block number"))?;
    if num > solidified_head(s) {
        return Ok(Value::Null);
    }
    let Ok(id) = s.block_index.get(num) else {
        return Ok(Value::Null);
    };
    let Ok(block) = s.blocks.get(&id) else {
        return Ok(Value::Null);
    };
    Ok(encode_block_for_rpc(&id, &block, true))
}

/// `getTransactionByIdSolidity(tx_id)` — same as `getTransactionById`
/// but rejects with `Null` if the tx hasn't reached the solidified
/// head yet. We check via `tx_history` (if present), otherwise fall
/// back to the live `getTransactionById` (with a flag noting the
/// divergence).
pub fn get_transaction_by_id_solidity(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // For the body lookup we use the live store, but gate on the
    // tx_history's block_num to decide whether it's solidified.
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx id"))?;
    let id_bytes = parse_hex_bytes(id_str)?;
    if id_bytes.len() != 32 {
        return Err(RpcError::invalid_params("tx id must be 32 bytes"));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_bytes);

    // Check the tx's block number against the solidified head.
    let solid_head = solidified_head(s);
    let in_solidified = match &s.tx_history {
        Some(h) => {
            // Read receipt to learn the block_num.
            match h
                .get(&id)
                .map_err(|e| RpcError::internal(format!("tx history: {e}")))?
            {
                Some(info) => info.block_number <= solid_head,
                None => false,
            }
        }
        None => {
            // No history index. Without it we can't know the tx's
            // block; we'd risk returning unconfirmed data. Reject.
            false
        }
    };
    if !in_solidified {
        return Ok(Value::Null);
    }
    // Delegate to the regular lookup for body shape.
    get_transaction_by_id(p, s)
}

/// `getTransactionInfoByIdSolidity(tx_id)` — solidified counterpart
/// of `getTransactionInfoById`. Same gate via `tx_history.block_number`.
pub fn get_transaction_info_by_id_solidity(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let id_str = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing tx id"))?;
    let id_bytes = parse_hex_bytes(id_str)?;
    if id_bytes.len() != 32 {
        return Err(RpcError::invalid_params("tx id must be 32 bytes"));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_bytes);

    let Some(h) = &s.tx_history else {
        return Ok(Value::Null);
    };
    let info = match h
        .get(&id)
        .map_err(|e| RpcError::internal(format!("tx history: {e}")))?
    {
        Some(i) => i,
        None => return Ok(Value::Null),
    };
    if info.block_number > solidified_head(s) {
        return Ok(Value::Null);
    }
    Ok(encode_transaction_info(&info))
}

/// `getAccountSolidity(address)` — live account read aliased to the
/// solidified namespace. java-tron returns the account state at the
/// solidified block, which would require a separate state snapshot
/// we don't maintain. We return the live state with a `solidified:
/// false` flag in the response so callers can detect the divergence.
pub fn get_account_solidity(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let mut result = get_account(p, s)?;
    if let Value::Object(map) = &mut result {
        map.insert("__solidified".to_string(), Value::Bool(false));
    }
    Ok(result)
}

/// `getDelegatedResourceSolidity(from, to)` — same as
/// `getDelegatedResource`. Live read with the same `__solidified:
/// false` flag rationale.
pub fn get_delegated_resource_solidity(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let mut result = get_delegated_resource(p, s)?;
    if let Value::Object(map) = &mut result {
        map.insert("__solidified".to_string(), Value::Bool(false));
    }
    Ok(result)
}

// =============================================================================
// Block balance trace
// =============================================================================

/// `getBlockBalanceTrace(block_id_or_num)` — per-block trace of every
/// balance change. Mirrors java-tron's
/// `wallet.getBlockBalanceTrace`. Returns:
///
/// * `Null` when the BalanceTraceStore isn't attached.
/// * An object with `block_identifier`, `timestamp`, and an empty
///   `transaction_balance_trace` array when the store is attached but
///   the executor hasn't populated this block (the common case until
///   the executor-side trace-recording lands).
/// * A populated object when the executor wrote a trace for this
///   block.
///
/// Accepts either a block number (int / numeric string) or a 32-byte
/// hex hash — same dispatch as `getBlock`.
pub fn get_block_balance_trace(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(trace_store) = &s.balance_trace else {
        return Ok(Value::Null);
    };
    // Resolve the requested block to a (number, hash) pair so the
    // response carries both.
    let first = p.get(0);
    let id_opt = if let Some(num) = first.and_then(|v| v.as_i64()) {
        s.block_index.get(num).ok()
    } else if let Some(s_str) = first.and_then(|v| v.as_str()) {
        if let Ok(num) = s_str.parse::<i64>() {
            s.block_index.get(num).ok()
        } else {
            match parse_hex_bytes(s_str) {
                Ok(b) if b.len() == 32 => {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&b);
                    Some(tron_types::BlockId::from_raw(h))
                }
                _ => None,
            }
        }
    } else {
        return Err(RpcError::invalid_params("missing block id or number"));
    };
    let Some(id) = id_opt else {
        return Ok(Value::Null);
    };
    let block_num = id.num() as i64;
    let block = s.blocks.get(&id).ok();
    let timestamp = block
        .as_ref()
        .and_then(|b| b.block_header.as_ref())
        .and_then(|h| h.raw_data.as_ref())
        .map(|r| r.timestamp)
        .unwrap_or(0);

    let trace = trace_store
        .get(block_num)
        .map_err(|e| RpcError::internal(format!("balance trace read: {e}")))?;

    match trace {
        Some(t) => Ok(encode_block_balance_trace(&t)),
        None => Ok(json!({
            "block_identifier": {
                "hash": hex_bytes(id.as_bytes()),
                "number": block_num,
            },
            "timestamp": timestamp,
            "transaction_balance_trace": Vec::<Value>::new(),
            // Distinguish "no executor writes yet" from "executor wrote
            // an empty trace" so clients can detect the bringup state.
            "__trace_recorded": false,
        })),
    }
}

// =============================================================================
// Shielded TRC-20 key helpers
// =============================================================================
//
// These mirror java-tron's `wallet.getSpendingKey` etc. — stateless
// Sapling crypto utilities that TronWeb's shielded wallet UI calls into
// the node for. They don't touch chain state and could be performed
// client-side; we expose them for compatibility with TronWeb.
//
// All bytes are returned as `0x`-prefixed lowercase hex.

use group::GroupEncoding as _;
use sapling_crypto::constants::{
    CRH_IVK_PERSONALIZATION, PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR,
};
use sapling_crypto::keys::{Diversifier, ExpandedSpendingKey, SaplingIvk};

/// `getSpendingKey` — return a fresh 32-byte spending key from the OS
/// CSPRNG. Wallets that maintain their own keys client-side should
/// prefer that path; this exists for TronWeb's `tronWeb.trx.getSpendingKey`
/// compatibility.
pub fn get_spending_key(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let mut sk = [0u8; 32];
    fill_random(&mut sk)?;
    Ok(json!({ "value": hex_bytes(&sk) }))
}

/// `getExpandedSpendingKey(sk)` — derive `(ask, nsk, ovk)` from a
/// 32-byte spending key per ZIP-32 § 4. Returns the 96-byte
/// `ExpandedSpendingKey` serialization split into three 32-byte fields.
pub fn get_expanded_spending_key(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let sk = parse_hex_with_len(p, 0, 32, "spending key")?;
    let esk = ExpandedSpendingKey::from_spending_key(&sk);
    let bytes = esk.to_bytes();
    Ok(json!({
        "ask": hex_bytes(&bytes[..32]),
        "nsk": hex_bytes(&bytes[32..64]),
        "ovk": hex_bytes(&bytes[64..96]),
    }))
}

/// `getAkFromAsk(ask)` — derive the spend-validating key (ak) from
/// the spend-authorizing scalar (ask) via `ak = ask * SPENDING_KEY_GENERATOR`.
pub fn get_ak_from_ask(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let ask_bytes = parse_hex_with_len(p, 0, 32, "ask")?;
    let ask = parse_jubjub_scalar(&ask_bytes, "ask")?;
    let ak = SPENDING_KEY_GENERATOR * ask;
    Ok(json!({ "value": hex_bytes(&ak.to_bytes()) }))
}

/// `getNkFromNsk(nsk)` — derive the nullifier-deriving key (nk) from
/// the proof-generation scalar (nsk) via
/// `nk = nsk * PROOF_GENERATION_KEY_GENERATOR`.
pub fn get_nk_from_nsk(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let nsk_bytes = parse_hex_with_len(p, 0, 32, "nsk")?;
    let nsk = parse_jubjub_scalar(&nsk_bytes, "nsk")?;
    let nk = PROOF_GENERATION_KEY_GENERATOR * nsk;
    Ok(json!({ "value": hex_bytes(&nk.to_bytes()) }))
}

/// `getIncomingViewingKey(ak, nk)` — `ivk = CRH^ivk(ak, nk)`, the
/// Sapling shielded incoming-viewing key. Uses Blake2s with the
/// `Zcashivk` personalization, then masks the high 5 bits to keep the
/// result in the scalar field.
pub fn get_incoming_viewing_key(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let ak = parse_hex_with_len(p, 0, 32, "ak")?;
    let nk = parse_hex_with_len(p, 1, 32, "nk")?;
    let mut hasher = blake2s_simd::Params::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state();
    hasher.update(&ak);
    hasher.update(&nk);
    let mut ivk = [0u8; 32];
    ivk.copy_from_slice(hasher.finalize().as_bytes());
    // Drop the 5 high bits — required so `ivk` falls inside the
    // little-endian scalar field of Jubjub (matches sapling-crypto's
    // `crh_ivk` impl).
    ivk[31] &= 0x07;
    Ok(json!({ "value": hex_bytes(&ivk) }))
}

/// `getDiversifier` — random 11-byte diversifier that hashes to a
/// valid Jubjub subgroup point. Rejection-samples until a valid one
/// is found (most random 11-byte blobs work, but ~1/2 are rejected
/// per attempt by the group-hash, so this loop runs once or twice on
/// average).
pub fn get_diversifier(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let mut buf = [0u8; 11];
    for _ in 0..32 {
        fill_random(&mut buf)?;
        let d = Diversifier(buf);
        if d.g_d().is_some() {
            return Ok(json!({ "value": hex_bytes(&buf) }));
        }
    }
    Err(RpcError::internal(
        "failed to find a valid diversifier in 32 attempts (statistically impossible)",
    ))
}

/// `getZenPaymentAddress(ivk, d)` — derive the shielded payment
/// address `(d || pk_d)` from an incoming viewing key + diversifier.
/// Returns `{ pkd, payment_address }`; the `payment_address` is the
/// 43-byte concatenation that wallets show as the shielded recipient.
pub fn get_zen_payment_address(p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    let ivk_bytes = parse_hex_with_len(p, 0, 32, "ivk")?;
    let d_bytes = parse_hex_with_len(p, 1, 11, "diversifier")?;
    let mut ivk_arr = [0u8; 32];
    ivk_arr.copy_from_slice(&ivk_bytes);
    let ivk_scalar_bytes = ivk_arr;
    let ivk_scalar = jubjub::Fr::from_bytes(&ivk_scalar_bytes);
    let ivk_scalar: jubjub::Fr = if ivk_scalar.is_some().into() {
        ivk_scalar.unwrap()
    } else {
        return Err(RpcError::invalid_params("ivk not in scalar field"));
    };
    let ivk = SaplingIvk(ivk_scalar);
    let mut d_arr = [0u8; 11];
    d_arr.copy_from_slice(&d_bytes);
    let diversifier = Diversifier(d_arr);
    match ivk.to_payment_address(diversifier) {
        Some(pa) => {
            // `pk_d().to_bytes()` is pub(crate); go through the inner
            // SubgroupPoint and use GroupEncoding for serialization.
            let pkd_bytes = pa.pk_d().inner().to_bytes();
            let mut addr = [0u8; 43];
            addr[..11].copy_from_slice(&d_arr);
            addr[11..].copy_from_slice(&pkd_bytes);
            Ok(json!({
                "pkd": hex_bytes(&pkd_bytes),
                "payment_address": hex_bytes(&addr),
            }))
        }
        None => Err(RpcError::invalid_params(
            "invalid (diversifier, ivk) — produces identity pk_d",
        )),
    }
}

// =============================================================================
// Server-side builders (Tier 1) — return unsigned Transaction envelopes
// =============================================================================
//
// All builders share the same shape:
//   1. Decode the JSON `params[0]` object into a typed contract proto.
//   2. Wrap in a `Contract` of the right `ContractType`.
//   3. Call `builder::build_unsigned_tx` to fill in ref_block, expiration, etc.
//   4. Hand back via `builder::tx_to_envelope`.
//
// The JSON params object keys mirror java-tron's HTTP-API field names so
// existing wallet code cross-uses without renaming.

use crate::builder::{build_unsigned_tx, tx_to_envelope, wrap_contract};
use tron_proto::transaction::contract::ContractType;

/// Pull an `owner_address`/`to_address`/etc. field from `params[0]`
/// and decode as a 21-byte TRON address (hex with the `0x41` prefix
/// OR 20-byte hex which we prefix). Returns the raw 21-byte vec
/// — most contract protos hold `Vec<u8>` rather than the typed
/// `Address`.
fn parse_addr_field(p: &Value, field: &str) -> Result<Vec<u8>, RpcError> {
    let obj = p.get(0).and_then(|v| v.as_object()).ok_or_else(|| {
        RpcError::invalid_params("expected params: [{owner_address: ...}]")
    })?;
    let s = obj
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params(format!("missing {field}")))?;
    let bytes = parse_hex_bytes(s)?;
    match bytes.len() {
        20 => {
            let mut out = vec![0u8; 21];
            out[0] = 0x41;
            out[1..].copy_from_slice(&bytes);
            Ok(out)
        }
        21 if bytes[0] == 0x41 => Ok(bytes),
        n => Err(RpcError::invalid_params(format!(
            "{field} must be a 20- or 21-byte address (got {n} bytes)"
        ))),
    }
}

/// Pull a named field from `params[0]` as an i64. Accepts JSON number
/// or numeric string; defaults to `default` when absent.
fn parse_i64_field(p: &Value, field: &str, default: i64) -> Result<i64, RpcError> {
    let obj = match p.get(0).and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Ok(default),
    };
    match obj.get(field) {
        None => Ok(default),
        Some(v) if v.is_null() => Ok(default),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
            .ok_or_else(|| RpcError::invalid_params(format!("{field}: not a number"))),
    }
}

/// Pull a named field from `params[0]` as i32. Same semantics as
/// `parse_i64_field` but range-checked.
fn parse_i32_field(p: &Value, field: &str, default: i32) -> Result<i32, RpcError> {
    let v = parse_i64_field(p, field, default as i64)?;
    if !(i32::MIN as i64..=i32::MAX as i64).contains(&v) {
        return Err(RpcError::invalid_params(format!("{field}: out of i32 range")));
    }
    Ok(v as i32)
}

/// Pull a named field as hex bytes.
fn parse_bytes_field(p: &Value, field: &str) -> Result<Vec<u8>, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("expected params: [{...}]"))?;
    let s = obj
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params(format!("missing {field}")))?;
    parse_hex_bytes(s)
}

/// Optional bytes field — returns empty vec when absent.
fn parse_bytes_field_opt(p: &Value, field: &str) -> Vec<u8> {
    parse_bytes_field(p, field).unwrap_or_default()
}

/// `createTransaction({owner_address, to_address, amount, ...})` —
/// TRX transfer.
pub fn create_transaction(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::TransferContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        to_address: parse_addr_field(p, "to_address")?,
        amount: parse_i64_field(p, "amount", 0)?,
    };
    let contract = wrap_contract(ContractType::TransferContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `transferAsset({owner_address, to_address, asset_name, amount})` —
/// TRC-10 transfer. `asset_name` is the asset's name bytes (hex) OR
/// id-as-decimal-string-bytes depending on `ALLOW_SAME_TOKEN_NAME`.
pub fn transfer_asset(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::TransferAssetContract {
        asset_name: parse_bytes_field(p, "asset_name")?,
        owner_address: parse_addr_field(p, "owner_address")?,
        to_address: parse_addr_field(p, "to_address")?,
        amount: parse_i64_field(p, "amount", 0)?,
    };
    let contract = wrap_contract(ContractType::TransferAssetContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `triggerSmartContract({owner_address, contract_address, call_value, data, fee_limit, ...})` —
/// build an unsigned VM call. Distinct from `triggerConstantContract`
/// which simulates against a snapshot and returns the call result;
/// this builds a real tx the wallet signs and broadcasts.
pub fn build_trigger_smart_contract(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::TriggerSmartContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        contract_address: parse_addr_field(p, "contract_address")?,
        call_value: parse_i64_field(p, "call_value", 0)?,
        data: parse_bytes_field_opt(p, "data"),
        call_token_value: parse_i64_field(p, "call_token_value", 0)?,
        token_id: parse_i64_field(p, "token_id", 0)?,
    };
    let fee_limit = parse_i64_field(p, "fee_limit", 0)?;
    let contract = wrap_contract(ContractType::TriggerSmartContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, fee_limit)?;
    tx_to_envelope(&tx)
}

/// `freezeBalanceV2({owner_address, frozen_balance, resource})` —
/// freeze TRX for bandwidth/energy/TRON_POWER. `resource` is the
/// `ResourceCode` int (0=BANDWIDTH, 1=ENERGY, 2=TRON_POWER).
pub fn freeze_balance_v2(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::FreezeBalanceV2Contract {
        owner_address: parse_addr_field(p, "owner_address")?,
        frozen_balance: parse_i64_field(p, "frozen_balance", 0)?,
        resource: parse_i32_field(p, "resource", 0)?,
    };
    let contract = wrap_contract(ContractType::FreezeBalanceV2Contract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `unfreezeBalanceV2({owner_address, unfreeze_balance, resource})`.
pub fn unfreeze_balance_v2(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::UnfreezeBalanceV2Contract {
        owner_address: parse_addr_field(p, "owner_address")?,
        unfreeze_balance: parse_i64_field(p, "unfreeze_balance", 0)?,
        resource: parse_i32_field(p, "resource", 0)?,
    };
    let contract = wrap_contract(ContractType::UnfreezeBalanceV2Contract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `withdrawExpireUnfreeze({owner_address})`.
pub fn withdraw_expire_unfreeze(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::WithdrawExpireUnfreezeContract {
        owner_address: parse_addr_field(p, "owner_address")?,
    };
    let contract = wrap_contract(ContractType::WithdrawExpireUnfreezeContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `cancelAllUnfreezeV2({owner_address})`.
pub fn cancel_all_unfreeze_v2(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::CancelAllUnfreezeV2Contract {
        owner_address: parse_addr_field(p, "owner_address")?,
    };
    let contract = wrap_contract(ContractType::CancelAllUnfreezeV2Contract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `delegateResource({owner_address, resource, balance, receiver_address, lock, lock_period})`.
pub fn delegate_resource(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let lock = p
        .get(0)
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("lock"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let tc = tron_proto::DelegateResourceContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        resource: parse_i32_field(p, "resource", 0)?,
        balance: parse_i64_field(p, "balance", 0)?,
        receiver_address: parse_addr_field(p, "receiver_address")?,
        lock,
        lock_period: parse_i64_field(p, "lock_period", 0)?,
    };
    let contract = wrap_contract(ContractType::DelegateResourceContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `unDelegateResource({owner_address, resource, balance, receiver_address})`.
pub fn un_delegate_resource(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::UnDelegateResourceContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        resource: parse_i32_field(p, "resource", 0)?,
        balance: parse_i64_field(p, "balance", 0)?,
        receiver_address: parse_addr_field(p, "receiver_address")?,
    };
    let contract = wrap_contract(ContractType::UnDelegateResourceContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `voteWitnessAccount({owner_address, votes: [{vote_address, vote_count}, ...]})`.
pub fn vote_witness_account(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let obj = p.get(0).and_then(|v| v.as_object()).ok_or_else(|| {
        RpcError::invalid_params("expected params: [{owner_address, votes}]")
    })?;
    let votes_val = obj
        .get("votes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::invalid_params("missing votes array"))?;
    let mut votes = Vec::with_capacity(votes_val.len());
    for v in votes_val {
        let vo = v.as_object().ok_or_else(|| {
            RpcError::invalid_params("each vote must be {vote_address, vote_count}")
        })?;
        let addr_str = vo
            .get("vote_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::invalid_params("vote.vote_address missing"))?;
        let bytes = parse_hex_bytes(addr_str)?;
        let addr = match bytes.len() {
            20 => {
                let mut out = vec![0u8; 21];
                out[0] = 0x41;
                out[1..].copy_from_slice(&bytes);
                out
            }
            21 if bytes[0] == 0x41 => bytes,
            n => {
                return Err(RpcError::invalid_params(format!(
                    "vote.vote_address must be 20- or 21-byte address (got {n})"
                )))
            }
        };
        let count = vo
            .get("vote_count")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| RpcError::invalid_params("vote.vote_count missing"))?;
        votes.push(tron_proto::vote_witness_contract::Vote {
            vote_address: addr,
            vote_count: count,
        });
    }
    let tc = tron_proto::VoteWitnessContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        votes,
        support: true,
    };
    let contract = wrap_contract(ContractType::VoteWitnessContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `withdrawBalance({owner_address})` — claim accumulated SR voter
/// reward to the account balance.
pub fn withdraw_balance(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::WithdrawBalanceContract {
        owner_address: parse_addr_field(p, "owner_address")?,
    };
    let contract = wrap_contract(ContractType::WithdrawBalanceContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `accountPermissionUpdate({owner_address, owner: Permission, witness?, actives?: [Permission]})`.
pub fn account_permission_update(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("expected params: [{...}]"))?;
    let owner_perm = obj
        .get("owner")
        .map(parse_permission_value)
        .transpose()?;
    let witness_perm = obj
        .get("witness")
        .map(parse_permission_value)
        .transpose()?;
    let actives = match obj.get("actives") {
        Some(v) => v
            .as_array()
            .ok_or_else(|| RpcError::invalid_params("actives must be array"))?
            .iter()
            .map(parse_permission_value)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    let tc = tron_proto::AccountPermissionUpdateContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        owner: owner_perm,
        witness: witness_perm,
        actives,
    };
    let contract = wrap_contract(ContractType::AccountPermissionUpdateContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// Decode a `Permission` JSON object: `{type, id, permission_name, threshold,
/// operations (hex), keys: [{address, weight}, ...]}`.
fn parse_permission_value(v: &Value) -> Result<tron_proto::Permission, RpcError> {
    let o = v
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("permission must be object"))?;
    let r#type = o.get("type").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let id = o.get("id").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let permission_name = o
        .get("permission_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let threshold = o.get("threshold").and_then(|v| v.as_i64()).unwrap_or(1);
    let parent_id = o.get("parent_id").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let operations = o
        .get("operations")
        .and_then(|v| v.as_str())
        .map(parse_hex_bytes)
        .transpose()?
        .unwrap_or_default();
    let keys_val = o
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::invalid_params("permission.keys missing"))?;
    let mut keys = Vec::with_capacity(keys_val.len());
    for k in keys_val {
        let ko = k
            .as_object()
            .ok_or_else(|| RpcError::invalid_params("permission.key must be object"))?;
        let addr_str = ko
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::invalid_params("permission.key.address missing"))?;
        let bytes = parse_hex_bytes(addr_str)?;
        let addr = match bytes.len() {
            20 => {
                let mut out = vec![0u8; 21];
                out[0] = 0x41;
                out[1..].copy_from_slice(&bytes);
                out
            }
            21 if bytes[0] == 0x41 => bytes,
            _ => return Err(RpcError::invalid_params("permission.key.address bad len")),
        };
        let weight = ko
            .get("weight")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| RpcError::invalid_params("permission.key.weight missing"))?;
        keys.push(tron_proto::Key {
            address: addr,
            weight,
        });
    }
    Ok(tron_proto::Permission {
        r#type,
        id,
        permission_name,
        threshold,
        parent_id,
        operations,
        keys,
    })
}

/// `updateBrokerage({owner_address, brokerage})` — set the SR's voter
/// brokerage percentage (0..=100, default 20% when never set).
pub fn update_brokerage(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::UpdateBrokerageContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        brokerage: parse_i32_field(p, "brokerage", 20)?,
    };
    let contract = wrap_contract(ContractType::UpdateBrokerageContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

// =============================================================================
// Server-side builders (Tier 2) — account, witness, proposal, asset ops
// =============================================================================

/// `createAccount({owner_address, account_address, type?})` — explicit
/// account creation. Most accounts are auto-created on first receive,
/// but explicit creation lets the owner choose the `AccountType`
/// (0=Normal, 1=AssetIssue, 2=Contract).
pub fn create_account(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::AccountCreateContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        account_address: parse_addr_field(p, "account_address")?,
        r#type: parse_i32_field(p, "type", 0)?,
    };
    let contract = wrap_contract(ContractType::AccountCreateContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `updateAccount({owner_address, account_name})` — set the account's
/// human-readable name. Account names are NOT unique on-chain.
pub fn update_account(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::AccountUpdateContract {
        account_name: parse_bytes_field(p, "account_name")?,
        owner_address: parse_addr_field(p, "owner_address")?,
    };
    let contract = wrap_contract(ContractType::AccountUpdateContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `setAccountId({owner_address, account_id})` — set the account's
/// unique-on-chain id (distinct from `account_name`). Once set,
/// can be queried via `getAccountById`.
pub fn set_account_id(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::SetAccountIdContract {
        account_id: parse_bytes_field(p, "account_id")?,
        owner_address: parse_addr_field(p, "owner_address")?,
    };
    let contract = wrap_contract(ContractType::SetAccountIdContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `createWitness({owner_address, url})` — register the account as a
/// SR candidate. Costs `WITNESS_ISSUE_FEE` (set by SR proposal).
pub fn create_witness(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::WitnessCreateContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        url: parse_bytes_field(p, "url")?,
    };
    let contract = wrap_contract(ContractType::WitnessCreateContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `updateWitness({owner_address, update_url})` — update the SR's
/// metadata URL (tag is `update_url`, not `url`, per proto tag 12).
pub fn update_witness(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::WitnessUpdateContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        update_url: parse_bytes_field(p, "update_url")?,
    };
    let contract = wrap_contract(ContractType::WitnessUpdateContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `proposalCreate({owner_address, parameters: {key:value} | [{key, value}]})` —
/// SR proposes a chain-parameter change. Each entry is a
/// `(parameter_index, new_value)` pair; the set of valid indices is
/// documented in java-tron's `ProposalUtil`.
pub fn proposal_create(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("expected params: [{...}]"))?;
    let mut parameters: std::collections::BTreeMap<i64, i64> =
        std::collections::BTreeMap::new();
    match obj.get("parameters") {
        Some(Value::Array(arr)) => {
            for entry in arr {
                let e = entry.as_object().ok_or_else(|| {
                    RpcError::invalid_params("each parameter entry must be {key, value}")
                })?;
                let k = e.get("key").and_then(|v| v.as_i64()).ok_or_else(|| {
                    RpcError::invalid_params("parameter.key missing")
                })?;
                let v = e.get("value").and_then(|v| v.as_i64()).ok_or_else(|| {
                    RpcError::invalid_params("parameter.value missing")
                })?;
                parameters.insert(k, v);
            }
        }
        Some(Value::Object(map)) => {
            for (k, v) in map {
                let key: i64 = k
                    .parse()
                    .map_err(|_| RpcError::invalid_params(format!("parameter key '{k}' not int")))?;
                let val = v.as_i64().ok_or_else(|| {
                    RpcError::invalid_params(format!("parameter value for '{k}' not int"))
                })?;
                parameters.insert(key, val);
            }
        }
        Some(_) => {
            return Err(RpcError::invalid_params(
                "parameters must be a map or an array of {key, value}",
            ))
        }
        None => {
            return Err(RpcError::invalid_params("missing parameters"));
        }
    }
    let tc = tron_proto::ProposalCreateContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        parameters,
    };
    let contract = wrap_contract(ContractType::ProposalCreateContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `proposalApprove({owner_address, proposal_id, is_add_approval})` —
/// add or remove the SR's approval. `is_add_approval = true` to add.
pub fn proposal_approve(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let is_add = p
        .get(0)
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("is_add_approval"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let tc = tron_proto::ProposalApproveContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        proposal_id: parse_i64_field(p, "proposal_id", 0)?,
        is_add_approval: is_add,
    };
    let contract = wrap_contract(ContractType::ProposalApproveContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `proposalDelete({owner_address, proposal_id})` — proposer cancels
/// a not-yet-activated proposal.
pub fn proposal_delete(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::ProposalDeleteContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        proposal_id: parse_i64_field(p, "proposal_id", 0)?,
    };
    let contract = wrap_contract(ContractType::ProposalDeleteContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `createAssetIssue({owner_address, name, abbr, total_supply, trx_num,
/// num, precision?, start_time, end_time, description?, url?,
/// free_asset_net_limit?, public_free_asset_net_limit?,
/// frozen_supply?: [{frozen_amount, frozen_days}]})` — issue a TRC-10.
pub fn create_asset_issue(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("expected params: [{...}]"))?;
    let frozen_supply: Vec<tron_proto::asset_issue_contract::FrozenSupply> = obj
        .get("frozen_supply")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let o = e.as_object()?;
                    Some(tron_proto::asset_issue_contract::FrozenSupply {
                        frozen_amount: o.get("frozen_amount")?.as_i64()?,
                        frozen_days: o.get("frozen_days")?.as_i64()?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let tc = tron_proto::AssetIssueContract {
        id: String::new(),
        owner_address: parse_addr_field(p, "owner_address")?,
        name: parse_bytes_field(p, "name")?,
        abbr: parse_bytes_field(p, "abbr").unwrap_or_default(),
        total_supply: parse_i64_field(p, "total_supply", 0)?,
        frozen_supply,
        trx_num: parse_i32_field(p, "trx_num", 1)?,
        precision: parse_i32_field(p, "precision", 0)?,
        num: parse_i32_field(p, "num", 1)?,
        start_time: parse_i64_field(p, "start_time", 0)?,
        end_time: parse_i64_field(p, "end_time", 0)?,
        order: 0,
        vote_score: 0,
        description: parse_bytes_field(p, "description").unwrap_or_default(),
        url: parse_bytes_field(p, "url").unwrap_or_default(),
        free_asset_net_limit: parse_i64_field(p, "free_asset_net_limit", 0)?,
        public_free_asset_net_limit: parse_i64_field(
            p,
            "public_free_asset_net_limit",
            0,
        )?,
        public_free_asset_net_usage: 0,
        public_latest_free_net_time: 0,
    };
    let contract = wrap_contract(ContractType::AssetIssueContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `updateAsset({owner_address, description?, url?, new_limit?,
/// new_public_limit?})` — issuer-only metadata update for a TRC-10.
pub fn update_asset(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::UpdateAssetContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        description: parse_bytes_field(p, "description").unwrap_or_default(),
        url: parse_bytes_field(p, "url").unwrap_or_default(),
        new_limit: parse_i64_field(p, "new_limit", 0)?,
        new_public_limit: parse_i64_field(p, "new_public_limit", 0)?,
    };
    let contract = wrap_contract(ContractType::UpdateAssetContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `participateAssetIssue({owner_address, to_address, asset_name, amount})` —
/// buy TRC-10 tokens during the issuance window. Pays in TRX at the
/// issue's `trx_num`/`num` exchange rate.
pub fn participate_asset_issue(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::ParticipateAssetIssueContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        to_address: parse_addr_field(p, "to_address")?,
        asset_name: parse_bytes_field(p, "asset_name")?,
        amount: parse_i64_field(p, "amount", 0)?,
    };
    let contract = wrap_contract(ContractType::ParticipateAssetIssueContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `unfreezeAsset({owner_address})` — issuer reclaims expired
/// `frozen_supply` TRC-10 entries.
pub fn unfreeze_asset(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::UnfreezeAssetContract {
        owner_address: parse_addr_field(p, "owner_address")?,
    };
    let contract = wrap_contract(ContractType::UnfreezeAssetContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

// =============================================================================
// Server-side builders (Tier 3) — contract deploy/admin, exchange, market
// =============================================================================

/// `deployContract({owner_address, bytecode, abi?, name?, call_value?,
/// consume_user_resource_percent?, origin_energy_limit?, fee_limit?,
/// call_token_value?, token_id?, parameter? (constructor args, hex)})` —
/// deploys a new smart contract. Returns the unsigned `CreateSmartContract`
/// envelope. The contract address can be computed client-side from the
/// (owner_address, tx_id) pair.
///
/// `abi` is accepted as a JSON string (the standard ABI JSON) or
/// omitted — we don't yet parse it into the SmartContract.Abi proto
/// (that's a recursive ABI walker; pinned as a follow-up). Most wallets
/// can omit the ABI here and submit it via `setSmartContractAbi` after
/// deployment.
pub fn deploy_contract(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let owner = parse_addr_field(p, "owner_address")?;
    let mut bytecode = parse_bytes_field(p, "bytecode").unwrap_or_default();
    // Append constructor parameters if present — tronweb concatenates
    // them onto the bytecode (the EVM `init` runs `bytecode || params`).
    if let Ok(ctor) = parse_bytes_field(p, "parameter") {
        bytecode.extend_from_slice(&ctor);
    }
    let name = p
        .get(0)
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let smart = tron_proto::SmartContract {
        origin_address: owner.clone(),
        contract_address: Vec::new(), // computed on-chain from tx_id
        abi: None,                    // see note above
        bytecode,
        call_value: parse_i64_field(p, "call_value", 0)?,
        consume_user_resource_percent: parse_i64_field(
            p,
            "consume_user_resource_percent",
            100,
        )?,
        name,
        origin_energy_limit: parse_i64_field(p, "origin_energy_limit", 0)?,
        code_hash: Vec::new(),
        trx_hash: Vec::new(),
        version: 0,
    };
    let tc = tron_proto::CreateSmartContract {
        owner_address: owner,
        new_contract: Some(smart),
        call_token_value: parse_i64_field(p, "call_token_value", 0)?,
        token_id: parse_i64_field(p, "token_id", 0)?,
    };
    let fee_limit = parse_i64_field(p, "fee_limit", 0)?;
    let contract = wrap_contract(ContractType::CreateSmartContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, fee_limit)?;
    tx_to_envelope(&tx)
}

/// `updateSetting({owner_address, contract_address, consume_user_resource_percent})` —
/// contract origin can change the share of energy the caller pays.
pub fn update_setting(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::UpdateSettingContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        contract_address: parse_addr_field(p, "contract_address")?,
        consume_user_resource_percent: parse_i64_field(
            p,
            "consume_user_resource_percent",
            100,
        )?,
    };
    let contract = wrap_contract(ContractType::UpdateSettingContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `updateEnergyLimit({owner_address, contract_address, origin_energy_limit})` —
/// contract origin's per-call energy cap.
pub fn update_energy_limit(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::UpdateEnergyLimitContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        contract_address: parse_addr_field(p, "contract_address")?,
        origin_energy_limit: parse_i64_field(p, "origin_energy_limit", 0)?,
    };
    let contract = wrap_contract(ContractType::UpdateEnergyLimitContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `clearAbi({owner_address, contract_address})` — wipe the contract's
/// on-chain ABI entry.
pub fn clear_abi(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::ClearAbiContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        contract_address: parse_addr_field(p, "contract_address")?,
    };
    let contract = wrap_contract(ContractType::ClearAbiContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `exchangeCreate({owner_address, first_token_id, first_token_balance,
/// second_token_id, second_token_balance})` — create a Bancor exchange
/// between two TRC-10 / TRX pairs. TRX is encoded as token id `_` (0x5f).
pub fn exchange_create(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::ExchangeCreateContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        first_token_id: parse_bytes_field(p, "first_token_id")?,
        first_token_balance: parse_i64_field(p, "first_token_balance", 0)?,
        second_token_id: parse_bytes_field(p, "second_token_id")?,
        second_token_balance: parse_i64_field(p, "second_token_balance", 0)?,
    };
    let contract = wrap_contract(ContractType::ExchangeCreateContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `exchangeInject({owner_address, exchange_id, token_id, quant})` —
/// inject liquidity into an existing exchange.
pub fn exchange_inject(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::ExchangeInjectContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        exchange_id: parse_i64_field(p, "exchange_id", 0)?,
        token_id: parse_bytes_field(p, "token_id")?,
        quant: parse_i64_field(p, "quant", 0)?,
    };
    let contract = wrap_contract(ContractType::ExchangeInjectContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `exchangeWithdraw({owner_address, exchange_id, token_id, quant})` —
/// withdraw liquidity.
pub fn exchange_withdraw(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::ExchangeWithdrawContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        exchange_id: parse_i64_field(p, "exchange_id", 0)?,
        token_id: parse_bytes_field(p, "token_id")?,
        quant: parse_i64_field(p, "quant", 0)?,
    };
    let contract = wrap_contract(ContractType::ExchangeWithdrawContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `exchangeTransaction({owner_address, exchange_id, token_id, quant,
/// expected})` — swap `quant` of `token_id` for the paired token via
/// the Bancor curve. `expected` is the slippage-protection minimum.
pub fn exchange_transaction(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::ExchangeTransactionContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        exchange_id: parse_i64_field(p, "exchange_id", 0)?,
        token_id: parse_bytes_field(p, "token_id")?,
        quant: parse_i64_field(p, "quant", 0)?,
        expected: parse_i64_field(p, "expected", 0)?,
    };
    let contract = wrap_contract(ContractType::ExchangeTransactionContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `marketSellAsset({owner_address, sell_token_id, sell_token_quantity,
/// buy_token_id, buy_token_quantity})` — post a DEX limit order.
/// `buy_token_quantity` is the minimum to receive (slippage cap).
pub fn market_sell_asset(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::MarketSellAssetContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        sell_token_id: parse_bytes_field(p, "sell_token_id")?,
        sell_token_quantity: parse_i64_field(p, "sell_token_quantity", 0)?,
        buy_token_id: parse_bytes_field(p, "buy_token_id")?,
        buy_token_quantity: parse_i64_field(p, "buy_token_quantity", 0)?,
    };
    let contract = wrap_contract(ContractType::MarketSellAssetContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `marketCancelOrder({owner_address, order_id})` — cancel a DEX
/// order by its opaque id bytes.
pub fn market_cancel_order(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let tc = tron_proto::MarketCancelOrderContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        order_id: parse_bytes_field(p, "order_id")?,
    };
    let contract = wrap_contract(ContractType::MarketCancelOrderContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `freezeBalance({owner_address, frozen_balance, frozen_duration,
/// resource?, receiver_address?})` — deprecated v1 freeze; kept for
/// completeness against pre-fork chains.
pub fn freeze_balance(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let receiver = parse_addr_field(p, "receiver_address").unwrap_or_default();
    let tc = tron_proto::FreezeBalanceContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        frozen_balance: parse_i64_field(p, "frozen_balance", 0)?,
        frozen_duration: parse_i64_field(p, "frozen_duration", 3)?,
        resource: parse_i32_field(p, "resource", 0)?,
        receiver_address: receiver,
    };
    let contract = wrap_contract(ContractType::FreezeBalanceContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `unfreezeBalance({owner_address, resource?, receiver_address?})` —
/// deprecated v1 unfreeze.
pub fn unfreeze_balance(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let receiver = parse_addr_field(p, "receiver_address").unwrap_or_default();
    let tc = tron_proto::UnfreezeBalanceContract {
        owner_address: parse_addr_field(p, "owner_address")?,
        resource: parse_i32_field(p, "resource", 0)?,
        receiver_address: receiver,
    };
    let contract = wrap_contract(ContractType::UnfreezeBalanceContract, &tc, 0);
    let tx = build_unsigned_tx(s, contract, 0)?;
    tx_to_envelope(&tx)
}

/// `getRcm` — random 32-byte note-commitment randomness, sampled from
/// the Jubjub scalar field via rejection sampling.
pub fn get_rcm(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    for _ in 0..32 {
        let mut buf = [0u8; 32];
        fill_random(&mut buf)?;
        // Clear the high 5 bits — matches sapling-crypto's
        // `jubjub::Fr::random` rejection-sampling shortcut.
        buf[31] &= 0x07;
        let cand = jubjub::Fr::from_bytes(&buf);
        if cand.is_some().into() {
            return Ok(json!({ "value": hex_bytes(&buf) }));
        }
    }
    Err(RpcError::internal(
        "failed to sample rcm in 32 attempts (statistically impossible)",
    ))
}

// ---- Shielded helper utilities --------------------------------------------

/// Fill `buf` with cryptographically-secure random bytes via the OS
/// entropy source. Maps any failure to an internal RPC error.
fn fill_random(buf: &mut [u8]) -> Result<(), RpcError> {
    getrandom::getrandom(buf).map_err(|e| RpcError::internal(format!("CSPRNG: {e}")))
}

/// Pull `params[idx]` as a hex string and decode to exactly `expected`
/// bytes, raising `invalid_params` on length mismatch.
fn parse_hex_with_len(
    p: &Value,
    idx: usize,
    expected: usize,
    name: &str,
) -> Result<Vec<u8>, RpcError> {
    let s = p
        .get(idx)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params(format!("missing {name}")))?;
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != expected {
        return Err(RpcError::invalid_params(format!(
            "{name} must be {expected} bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Parse a 32-byte little-endian Jubjub scalar, rejecting values
/// outside the scalar field.
fn parse_jubjub_scalar(bytes: &[u8], name: &str) -> Result<jubjub::Fr, RpcError> {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    let candidate = jubjub::Fr::from_bytes(&buf);
    if candidate.is_some().into() {
        Ok(candidate.unwrap())
    } else {
        Err(RpcError::invalid_params(format!(
            "{name} not in Jubjub scalar field"
        )))
    }
}

fn encode_block_balance_trace(t: &tron_proto::BlockBalanceTrace) -> Value {
    let id = t.block_identifier.as_ref().map(|bi| json!({
        "hash": hex_bytes(&bi.hash),
        "number": bi.number,
    })).unwrap_or(json!({}));
    let txs: Vec<Value> = t
        .transaction_balance_trace
        .iter()
        .map(|tx| {
            json!({
                "transaction_identifier": hex_bytes(&tx.transaction_identifier),
                "type": tx.r#type,
                "status": tx.status,
                "operation": tx.operation.iter().map(|op| json!({
                    "operation_identifier": op.operation_identifier,
                    "address": hex_bytes(&op.address),
                    "amount": op.amount,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "block_identifier": id,
        "timestamp": t.timestamp,
        "transaction_balance_trace": txs,
        "__trace_recorded": true,
    })
}

// =============================================================================
// ABI decoding RPCs
// =============================================================================

/// `decodeContractData(contract_address, data)` — decode a call's
/// 4-byte selector + ABI-encoded arguments against the ABI stored at
/// `contract_address`. Returns the function name, selector, and a
/// typed parameter list.
///
/// Useful for tooling that wants to display "what function was called
/// with what arguments" given a raw calldata blob — e.g. a block
/// explorer rendering a `TriggerSmartContract` transaction's
/// `parameter.data` field, or an off-chain indexer enriching its log.
///
/// Returns `null` when the contract has no stored ABI, or
/// `{"error": ...}` when the calldata doesn't match any function in
/// the ABI.
///
/// JSON shape: see [`crate::abi::decoded_call_to_json`].
pub fn decode_contract_data(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(abis) = &s.abis else {
        return Ok(Value::Null);
    };
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("missing decode object"))?;
    let addr_str = obj
        .get("contract_address")
        .or_else(|| obj.get("contractAddress"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing contract_address"))?;
    let addr = parse_eth_address(addr_str)?;
    let data_str = obj
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing data"))?;
    let data = parse_hex_bytes(data_str)?;

    let Ok(Some(abi)) = abis.get(&addr) else {
        return Ok(Value::Null);
    };
    match crate::abi::decode_function_input(&abi, &data) {
        Ok(call) => Ok(crate::abi::decoded_call_to_json(&call)),
        Err(e) => Ok(json!({ "error": format!("{e}") })),
    }
}

/// `decodeEventLog(contract_address, topics, data)` — decode an event
/// log emitted by `contract_address`. `topics` is an array of `0x`-
/// prefixed 32-byte hex strings (first is the event signature hash for
/// non-anonymous events); `data` is the ABI-encoded non-indexed param
/// blob.
///
/// Returns `null` when the contract has no stored ABI, or
/// `{"error": ...}` when no event in the ABI matches `topics[0]`.
pub fn decode_event_log(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(abis) = &s.abis else {
        return Ok(Value::Null);
    };
    let obj = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("missing decode object"))?;
    let addr_str = obj
        .get("contract_address")
        .or_else(|| obj.get("contractAddress"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing contract_address"))?;
    let addr = parse_eth_address(addr_str)?;
    let topics_arr = obj
        .get("topics")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::invalid_params("missing topics array"))?;
    let mut topics: Vec<[u8; 32]> = Vec::with_capacity(topics_arr.len());
    for (i, t) in topics_arr.iter().enumerate() {
        let s = t.as_str().ok_or_else(|| {
            RpcError::invalid_params(format!("topics[{i}] must be a hex string"))
        })?;
        let bytes = parse_hex_bytes(s)?;
        if bytes.len() != 32 {
            return Err(RpcError::invalid_params(format!(
                "topics[{i}] must be 32 bytes (got {})",
                bytes.len()
            )));
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes);
        topics.push(b);
    }
    let data_str = obj.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
    let data = parse_hex_bytes(data_str)?;

    let Ok(Some(abi)) = abis.get(&addr) else {
        return Ok(Value::Null);
    };
    match crate::abi::decode_event_log(&abi, &topics, &data) {
        Ok(ev) => Ok(crate::abi::decoded_event_to_json(&ev)),
        Err(e) => Ok(json!({ "error": format!("{e}") })),
    }
}

// =============================================================================
// eth_* methods that java-tron exposes but tron-goblin-node hadn't filled in.
//
// Categorised by behaviour:
//
// * "real" — does meaningful work backed by chainbase state
// * "no-uncle" / "no-mining" — TRON has none of these concepts; the
//   shape matches what every Ethereum-compatibility shim on a TRON-
//   derived chain returns (empty / zero)
// * "needs node-managed keys" — eth_sendTransaction / eth_sign /
//   eth_signTransaction; java-tron returns MethodNotFound for these
//   because the node doesn't hold private keys. Same approach here.
// * "deprecated" — eth_getCompilers / eth_compile* / eth_submit*; same
//   MethodNotFound shape as java-tron.
// =============================================================================

/// `eth_getBlockReceipts(blockNumOrHashOrTag)` — return every receipt
/// in a block as an array. Block can be specified by tag ("latest" /
/// "earliest" / "pending"), hex number, or 32-byte hash.
pub fn eth_get_block_receipts(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let arg = p
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing block identifier"))?;

    // Resolve to a BlockId — accept tag, number, or hash.
    let block_id = if arg.starts_with("0x") && arg.len() == 66 {
        // 32-byte hash → block hash.
        let bytes = parse_hex_bytes(arg)?;
        if bytes.len() != 32 {
            return Err(RpcError::invalid_params("block hash must be 32 bytes"));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        tron_types::BlockId::from_raw(id)
    } else {
        let num: i64 = match arg {
            "latest" | "pending" => s.dyn_props.latest_block_header_number().unwrap_or(0),
            "earliest" => 0,
            hex => parse_hex_quantity(hex)? as i64,
        };
        match s.block_index.get(num) {
            Ok(id) => id,
            Err(_) => return Ok(json!([])),
        }
    };

    let Ok(block) = s.blocks.get(&block_id) else {
        return Ok(json!([]));
    };
    let Some(history) = &s.tx_history else {
        return Ok(json!([]));
    };

    let mut receipts = Vec::with_capacity(block.transactions.len());
    for tx in &block.transactions {
        let Some(raw) = tx.raw_data.as_ref() else {
            continue;
        };
        let encoded = prost::Message::encode_to_vec(raw);
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(&tron_crypto::hash::sha256(&encoded));
        let Ok(Some(info)) = history.get(&tx_id) else {
            continue;
        };
        receipts.push(encode_receipt_for_rpc(&tx_id, &info));
    }
    Ok(json!(receipts))
}

/// `eth_getUncleByBlockHashAndIndex(hash, index)` — TRON has no
/// uncles. Always `null`. Matches java-tron's `BlockResult` getter
/// (which returns null for any uncle query).
pub fn eth_get_uncle_by_block_hash_and_index(
    _p: &Value,
    _s: &RpcState,
) -> Result<Value, RpcError> {
    Ok(Value::Null)
}

/// `eth_getUncleByBlockNumberAndIndex(num, index)` — TRON has no
/// uncles. Always `null`.
pub fn eth_get_uncle_by_block_number_and_index(
    _p: &Value,
    _s: &RpcState,
) -> Result<Value, RpcError> {
    Ok(Value::Null)
}

/// `eth_getUncleCountByBlockHash(hash)` — TRON has no uncles. `"0x0"`.
pub fn eth_get_uncle_count_by_block_hash(
    _p: &Value,
    _s: &RpcState,
) -> Result<Value, RpcError> {
    Ok(json!("0x0"))
}

/// `eth_getUncleCountByBlockNumber(num)` — TRON has no uncles. `"0x0"`.
pub fn eth_get_uncle_count_by_block_number(
    _p: &Value,
    _s: &RpcState,
) -> Result<Value, RpcError> {
    Ok(json!("0x0"))
}

/// `eth_getWork()` — no mining on TRON. java-tron returns an empty
/// `List<Object>`.
pub fn eth_get_work(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Ok(json!([]))
}

/// `parity_nextNonce(addr)` — TRON has no per-account nonce. Delegate
/// to `eth_getTransactionCount` which returns `"0x0"`.
pub fn parity_next_nonce(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    eth_get_transaction_count(p, s)
}

/// `buildTransaction(args)` — java-tron's unsigned-tx builder. Takes
/// a structured arg with `from`, `to`, `value`, `data`, `gas`, etc.,
/// and emits a Transaction envelope ready for the caller to sign +
/// broadcast.
///
/// Our existing `create_transaction` / `build_trigger_smart_contract`
/// already implement the per-contract-type builders. `buildTransaction`
/// is the routing entrypoint: choose `triggerSmartContract` when
/// `data` is present, `createTransaction` (TransferContract) otherwise.
pub fn build_transaction(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // `p` here is the JSON-RPC `params` array; java-tron passes a
    // single `BuildArguments` object as `params[0]`.
    let args = p.get(0).cloned().unwrap_or_else(|| json!({}));
    let obj = args
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("expected params: [{from, to, data, value}]"))?;

    // Normalise field names — accept either the camelCase eth shape
    // (`from`, `to`, `data`, `value`) or the TRON-native snake_case
    // (`owner_address`, `to_address`, etc.).
    let owner = obj
        .get("from")
        .or_else(|| obj.get("owner_address"))
        .cloned();
    let to = obj.get("to").or_else(|| obj.get("to_address")).cloned();
    let data = obj.get("data").cloned();
    let value = obj.get("value").cloned();

    let mut translated = serde_json::Map::new();
    if let Some(from) = owner {
        translated.insert("owner_address".into(), from);
    }
    if let Some(to) = to {
        translated.insert("to_address".into(), to);
        translated.insert("contract_address".into(), translated["to_address"].clone());
    }
    if let Some(v) = value {
        // Hex-quantity → i64 amount in sun.
        let n = match v.as_str() {
            Some(s) => parse_hex_quantity(s)? as i64,
            None => v.as_i64().unwrap_or(0),
        };
        translated.insert("amount".into(), json!(n));
        translated.insert("call_value".into(), json!(n));
    }
    if let Some(d) = data {
        translated.insert("data".into(), d);
    }
    let inner = Value::Object(translated);

    // Route based on whether data is supplied:
    //   * non-empty data → trigger an existing smart contract
    //   * empty data + to → plain TRX transfer
    let has_data = inner
        .get("data")
        .and_then(|d| d.as_str())
        .map(|s| s.trim_start_matches("0x").len() > 0)
        .unwrap_or(false);

    if has_data {
        build_trigger_smart_contract(&Value::Array(vec![inner]), s)
    } else {
        create_transaction(&Value::Array(vec![inner]), s)
    }
}

/// Three "node-managed keys" methods that java-tron also doesn't
/// support (it explicitly returns MethodNotFound — the node never
/// holds private keys). Same here. Build the unsigned tx via
/// `buildTransaction` / `eth_call`-style builders and sign client-side.
pub fn eth_send_transaction(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_sendTransaction"))
}

pub fn eth_sign(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_sign"))
}

pub fn eth_sign_transaction(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_signTransaction"))
}

/// PoW-mining methods — TRON is DPoS, no mining. Match java-tron's
/// MethodNotFound responses.
pub fn eth_submit_work(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_submitWork"))
}

pub fn eth_submit_hashrate(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_submitHashrate"))
}

/// Compiler family — deprecated on every modern Ethereum client.
/// java-tron returns MethodNotFound; mirror that.
pub fn eth_get_compilers(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_getCompilers"))
}

pub fn eth_compile_solidity(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_compileSolidity"))
}

pub fn eth_compile_lll(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_compileLLL"))
}

pub fn eth_compile_serpent(_p: &Value, _s: &RpcState) -> Result<Value, RpcError> {
    Err(RpcError::method_not_found("eth_compileSerpent"))
}

#[cfg(test)]
mod log_range_tests {
    use super::*;

    fn obj(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn rejects_out_of_range_from_block_instead_of_overflowing() {
        // C2: 0x8000000000000000 (u64 2^63) used to cast to i64::MIN; with
        // a positive toBlock the span check overflowed past the 10k cap.
        let o = obj(json!({"fromBlock": "0x8000000000000000", "toBlock": "0x1"}));
        let err = resolve_log_block_range(&o, 100).unwrap_err();
        assert_eq!(err.code, -32602, "{}", err.message);
    }

    #[test]
    fn rejects_span_over_cap() {
        let o = obj(json!({"fromBlock": "0x0", "toBlock": "0x4e21"})); // 0..=20001
        let err = resolve_log_block_range(&o, 1_000_000).unwrap_err();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn accepts_in_cap_window_and_empty_when_reversed() {
        let o = obj(json!({"fromBlock": "0xa", "toBlock": "0x14"})); // 10..=20
        assert_eq!(resolve_log_block_range(&o, 100).unwrap(), Some((10, 20)));
        let rev = obj(json!({"fromBlock": "0x14", "toBlock": "0xa"}));
        assert_eq!(resolve_log_block_range(&rev, 100).unwrap(), None);
    }

    #[test]
    fn defaults_unspecified_bounds_to_head() {
        assert_eq!(
            resolve_log_block_range(&obj(json!({})), 42).unwrap(),
            Some((42, 42))
        );
    }
}

#[cfg(test)]
mod account_encoding_tests {
    use super::*;
    use tron_proto::account::{AccountResource, FreezeV2};

    #[test]
    fn account_json_matches_java_tron_shape() {
        let a = tron_proto::Account {
            address: vec![0x41; 21],
            balance: 1_000,
            create_time: 1_606_989_672_000_i64,
            net_usage: 250,
            is_witness: true,
            net_window_size: 28_800_000,
            net_window_optimized: true,
            account_name: b"Ant Investment Group".to_vec(),
            frozen_v2: vec![FreezeV2 { r#type: 1, amount: 5_000 }],
            account_resource: Some(AccountResource {
                energy_usage: 999,
                energy_window_size: 28_800_000,
                energy_window_optimized: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let v = encode_account_for_rpc(&a, 0);
        let o = v.as_object().unwrap();

        // java-tron proto field names (snake_case), NOT the old eth camelCase.
        assert_eq!(o.get("create_time"), Some(&json!(1_606_989_672_000_i64)));
        assert_eq!(o.get("net_usage"), Some(&json!(250)));
        assert_eq!(o.get("is_witness"), Some(&json!(true)));
        assert_eq!(o.get("net_window_size"), Some(&json!(28_800_000)));
        assert!(o.get("createTime").is_none(), "no eth-style camelCase keys");
        assert!(o.get("netUsage").is_none());
        assert!(o.get("votesCount").is_none());
        // account_name rendered as HEX bytes (java's proto3 JsonFormat with
        // the default visible=false; the readable-text form is produced by
        // the HTTP layer's visible=true rewrite).
        assert_eq!(
            o.get("account_name"),
            Some(&json!(hex::encode("Ant Investment Group")))
        );
        // frozenV2 is normalized to all 3 ResourceCodes in canonical order
        // (java-tron's Wallet.sortFrozenV2List), padding absent ones with 0:
        // BANDWIDTH:0 → {}, ENERGY:5000, TRON_POWER:0 → {"type":"TRON_POWER"}.
        assert_eq!(
            o["frozenV2"],
            json!([{}, { "type": "ENERGY", "amount": 5_000 }, { "type": "TRON_POWER" }])
        );
        // Nested account_resource block, snake_case fields.
        assert_eq!(o["account_resource"]["energy_usage"], json!(999));
        assert_eq!(o["account_resource"]["energy_window_size"], json!(28_800_000));
        assert_eq!(o["account_resource"]["energy_window_optimized"], json!(true));
        // Default-valued fields omitted (proto3 omission, like java).
        assert!(o.get("allowance").is_none());
        assert!(o.get("frozen").is_none());
    }

    #[test]
    fn frozen_v2_is_padded_to_all_three_resources() {
        // java-tron's Wallet.getAccount always returns all 3 ResourceCodes
        // (zero-padded, canonical order), even for accounts that never froze.
        // Empty stored list → [BANDWIDTH:0, ENERGY:0, TRON_POWER:0].
        let empty = tron_proto::Account { address: vec![0x41; 21], ..Default::default() };
        assert_eq!(
            encode_account_for_rpc(&empty, 0)["frozenV2"],
            json!([{}, { "type": "ENERGY" }, { "type": "TRON_POWER" }])
        );

        // A single non-zero bandwidth freeze keeps its amount and pads the rest.
        let bw = tron_proto::Account {
            address: vec![0x41; 21],
            frozen_v2: vec![FreezeV2 { r#type: 0, amount: 1_000_000 }],
            ..Default::default()
        };
        assert_eq!(
            encode_account_for_rpc(&bw, 0)["frozenV2"],
            json!([{ "amount": 1_000_000 }, { "type": "ENERGY" }, { "type": "TRON_POWER" }])
        );
    }

    #[test]
    fn latest_consume_times_are_converted_from_slot_to_ms() {
        // We store latest_consume_time(_for_energy) / latest_consume_free_time
        // as slots (matching java's internal getHeadSlot()), but java-tron's
        // Wallet.getAccount emits them in ms: genesis + 3000 * slot.
        let a = tron_proto::Account {
            address: vec![0x41; 21],
            latest_consume_time: 591_849_058,
            latest_consume_free_time: 561_158_347,
            account_resource: Some(AccountResource {
                latest_consume_time_for_energy: 592_316_558,
                ..Default::default()
            }),
            ..Default::default()
        };

        // Mainnet genesis = 0 → value is exactly slot * 3000.
        let o = encode_account_for_rpc(&a, 0);
        assert_eq!(o["latest_consume_time"], json!(1_775_547_174_000_i64));
        assert_eq!(o["latest_consume_free_time"], json!(1_683_475_041_000_i64));
        assert_eq!(
            o["account_resource"]["latest_consume_time_for_energy"],
            json!(1_776_949_674_000_i64)
        );

        // Non-zero genesis offsets the result: genesis + 3000 * slot.
        let o2 = encode_account_for_rpc(&a, 1_000);
        assert_eq!(o2["latest_consume_time"], json!(1_775_547_174_000_i64 + 1_000));
    }

    #[test]
    fn merge_account_assets_imports_store_balances_when_optimized() {
        use std::sync::Arc;
        use tron_chainbase::{AccountAssetStore, KvBackend, MemBackend};
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = AccountAssetStore::new(backend);
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0xaa);
        let owner = tron_crypto::address::Address::from_raw(a);
        store.put(&owner, b"1000001", 100).unwrap();
        store.put(&owner, b"1000002", 200).unwrap();

        // Optimized account, empty inline asset_v2 → store balances merge in.
        let mut acct = tron_proto::Account {
            address: a.to_vec(),
            asset_optimized: true,
            ..Default::default()
        };
        merge_account_assets(&mut acct, &store);
        assert_eq!(acct.asset_v2.get("1000001"), Some(&100));
        assert_eq!(acct.asset_v2.get("1000002"), Some(&200));
        assert_eq!(acct.asset_v2.len(), 2);

        // Non-optimized account → no merge (balances already inline).
        let mut plain = tron_proto::Account {
            address: a.to_vec(),
            asset_optimized: false,
            ..Default::default()
        };
        merge_account_assets(&mut plain, &store);
        assert!(plain.asset_v2.is_empty());
    }

    #[test]
    fn materialized_asset_net_usage_pads_one_zero_entry_per_asset() {
        // java materializes a free_asset_net_usageV2 entry per held asset,
        // decayed to 0 when the asset was never used for free bandwidth.
        let mut acct = tron_proto::Account::default();
        acct.asset_v2.insert("1000001".into(), 100);
        acct.asset_v2.insert("1000002".into(), 200);
        let m = materialized_asset_net_usage(&acct, 1_000_000);
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("1000001"), Some(&0));
        assert_eq!(m.get("1000002"), Some(&0));
    }
}

#[cfg(test)]
mod eth_call_tests {
    use super::*;

    fn call_obj() -> Value {
        json!([{
            "to": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
        }])
    }

    #[test]
    fn no_gas_field_defaults_below_cap() {
        let req = parse_eth_call_request(&call_obj(), 50_000_000).unwrap();
        // Default gas = (cap - 1M).min(15M) → 15M here.
        assert_eq!(req.gas, 15_000_000);
    }

    #[test]
    fn caller_gas_within_cap_is_passed_through() {
        let mut o = call_obj();
        o[0]["gas"] = json!("0x1c9c380"); // 30_000_000
        let req = parse_eth_call_request(&o, 50_000_000).unwrap();
        assert_eq!(req.gas, 30_000_000);
    }

    #[test]
    fn caller_gas_above_cap_is_clamped() {
        let mut o = call_obj();
        o[0]["gas"] = json!("0x5f5e1000"); // 1_600_000_000
        let req = parse_eth_call_request(&o, 50_000_000).unwrap();
        assert_eq!(req.gas, 50_000_000, "clamped to cap");
    }

    #[test]
    fn lower_cap_works_for_throttled_public_nodes() {
        let mut o = call_obj();
        o[0]["gas"] = json!("0x989680"); // 10_000_000
        // Operator configured a 5M cap; caller's 10M gets clamped.
        let req = parse_eth_call_request(&o, 5_000_000).unwrap();
        assert_eq!(req.gas, 5_000_000);
    }

    #[test]
    fn energy_breakdown_aggregates_by_opcode_and_flags_halt() {
        use tron_tvm::tracer::StructLog;
        let mk = |op: &str, cost: u64, err: Option<&str>| StructLog {
            pc: 0,
            op: 0,
            op_name: op.to_string(),
            gas: 0,
            gas_cost: cost,
            depth: 0,
            stack: vec![],
            error: err.map(|e| e.to_string()),
        };
        let logs = vec![
            mk("SSTORE", 20000, None),
            mk("SSTORE", 5000, None),
            mk("PUSH1", 3, None),
            mk("EXTCODESIZE", 0, Some("OutOfGas(Basic)")),
        ];
        let v = energy_breakdown_json(&logs, &[]);
        assert_eq!(v["ops_executed"], 4);
        // 4 log entries but 3 distinct opcodes (SSTORE appears twice).
        assert_eq!(v["total_unique_opcodes"], 3);
        // SSTORE (25000 across 2 ops) ranks first; PUSH1 is far down.
        assert_eq!(v["by_opcode"][0]["op"], "SSTORE");
        assert_eq!(v["by_opcode"][0]["energy"], 25000);
        assert_eq!(v["by_opcode"][0]["count"], 2);
        // The halting op + reason are surfaced (the "why it would OOG").
        assert_eq!(v["halt"]["op"], "EXTCODESIZE");
        assert_eq!(v["halt"]["reason"], "OutOfGas(Basic)");
    }
}
