//! ERC-4337 account-abstraction **bundler** (java-tron feature #6647).
//!
//! Exposes the bundler JSON-RPC namespace (`eth_sendUserOperation`,
//! `eth_estimateUserOperationGas`, `eth_getUserOperationByHash`,
//! `eth_getUserOperationReceipt`, `eth_supportedEntryPoints`), validates each
//! UserOperation against live state through our constant-call VM, bundles
//! accepted ops into an `EntryPoint.handleOps` transaction, signs it with a
//! configured key, and broadcasts it via the mempool.
//!
//! **Off-protocol, zero consensus risk.** A bundled UserOp becomes an ordinary
//! `TriggerSmartContract` call to the EntryPoint, executed by the same TVM we
//! hold byte-exact with java-tron — no new tx type, opcode, or consensus rule.
//! The RPC namespace is additive, exactly like `eth_simulateV1`.
//!
//! **Version-agnostic by delegation.** Rather than re-derive the
//! version-specific userOpHash / nonce / packing rules, we delegate to the
//! deployed EntryPoint via VM simulation (`getUserOpHash`, `getNonce`,
//! `handleOps`), so the bundler stays correct against whatever EntryPoint
//! (v0.6/v0.7/v0.8) the operator deployed. The on-chain encoding below targets
//! the v0.7 `PackedUserOperation` ABI.
use std::collections::HashMap;
use std::sync::Mutex;

use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolCall, SolError, SolEvent};
use prost::Message;
use serde_json::{json, Map, Value};
use tron_proto::TriggerSmartContract;
use tron_tvm::execute::{VmBlockEnv, VmOutcome};

use crate::methods::{build_call_vm_stores, dispatch_constant_trigger, RpcError};
use crate::state::RpcState;

sol! {
    /// EntryPoint v0.7 on-chain UserOperation representation.
    #[derive(Debug)]
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    /// EntryPoint methods the bundler encodes/decodes via alloy.
    function handleOps(PackedUserOperation[] ops, address beneficiary) external;
    function getUserOpHash(PackedUserOperation userOp) external view returns (bytes32);
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);

    /// Reverts the EntryPoint raises when a UserOp fails validation — the
    /// `reason` is surfaced to the caller so they can see *why* it was rejected.
    error FailedOp(uint256 opIndex, string reason);
    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

    /// Emitted once per executed UserOperation — drives the receipt.
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
}

/// The **unpacked** v0.7 UserOperation as clients submit it over JSON-RPC.
/// [`Self::pack`] folds it into the on-chain [`PackedUserOperation`].
#[derive(Debug, Clone)]
pub struct UserOperation {
    pub sender: Address,
    pub nonce: U256,
    pub factory: Option<Address>,
    pub factory_data: Bytes,
    pub call_data: Bytes,
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub paymaster: Option<Address>,
    pub paymaster_verification_gas_limit: U256,
    pub paymaster_post_op_gas_limit: U256,
    pub paymaster_data: Bytes,
    pub signature: Bytes,
}

impl UserOperation {
    /// Fold into the EntryPoint's on-chain layout:
    /// * `initCode = factory ++ factoryData` (empty when no factory)
    /// * `accountGasLimits = verificationGasLimit[16] ++ callGasLimit[16]`
    /// * `gasFees = maxPriorityFeePerGas[16] ++ maxFeePerGas[16]`
    /// * `paymasterAndData = paymaster ++ pmVerGas[16] ++ pmPostOpGas[16] ++ data`
    pub fn pack(&self) -> PackedUserOperation {
        let init_code = match self.factory {
            Some(f) => concat_bytes(f.as_slice(), &self.factory_data),
            None => Bytes::new(),
        };
        let paymaster_and_data = match self.paymaster {
            Some(pm) => {
                let mut v = pm.to_vec();
                v.extend_from_slice(&low16(self.paymaster_verification_gas_limit));
                v.extend_from_slice(&low16(self.paymaster_post_op_gas_limit));
                v.extend_from_slice(&self.paymaster_data);
                Bytes::from(v)
            }
            None => Bytes::new(),
        };
        PackedUserOperation {
            sender: self.sender,
            nonce: self.nonce,
            initCode: init_code,
            callData: self.call_data.clone(),
            accountGasLimits: pack_pair(self.verification_gas_limit, self.call_gas_limit),
            preVerificationGas: self.pre_verification_gas,
            gasFees: pack_pair(self.max_priority_fee_per_gas, self.max_fee_per_gas),
            paymasterAndData: paymaster_and_data,
            signature: self.signature.clone(),
        }
    }

    /// The unpacked v0.7 JSON shape `eth_getUserOperationByHash` echoes back —
    /// every field `0x…`, the factory/paymaster groups omitted when unset.
    pub fn to_json(&self) -> Value {
        let addr = |a: Address| format!("0x{}", hex::encode(a.as_slice()));
        let q = |v: U256| format!("0x{v:x}");
        let b = |x: &Bytes| format!("0x{}", hex::encode(x));
        let mut o = Map::new();
        o.insert("sender".into(), json!(addr(self.sender)));
        o.insert("nonce".into(), json!(q(self.nonce)));
        if let Some(f) = self.factory {
            o.insert("factory".into(), json!(addr(f)));
            o.insert("factoryData".into(), json!(b(&self.factory_data)));
        }
        o.insert("callData".into(), json!(b(&self.call_data)));
        o.insert("callGasLimit".into(), json!(q(self.call_gas_limit)));
        o.insert("verificationGasLimit".into(), json!(q(self.verification_gas_limit)));
        o.insert("preVerificationGas".into(), json!(q(self.pre_verification_gas)));
        o.insert("maxFeePerGas".into(), json!(q(self.max_fee_per_gas)));
        o.insert("maxPriorityFeePerGas".into(), json!(q(self.max_priority_fee_per_gas)));
        if let Some(pm) = self.paymaster {
            o.insert("paymaster".into(), json!(addr(pm)));
            o.insert(
                "paymasterVerificationGasLimit".into(),
                json!(q(self.paymaster_verification_gas_limit)),
            );
            o.insert("paymasterPostOpGasLimit".into(), json!(q(self.paymaster_post_op_gas_limit)));
            o.insert("paymasterData".into(), json!(b(&self.paymaster_data)));
        }
        o.insert("signature".into(), json!(b(&self.signature)));
        Value::Object(o)
    }
}

/// Big-endian low 16 bytes of a `U256`. The EntryPoint packs these fields as
/// `uint128`; gas limits / fees are expected to fit, and the high bits are
/// dropped to match the contract's `uint128` truncation.
fn low16(v: U256) -> [u8; 16] {
    let be = v.to_be_bytes::<32>();
    let mut out = [0u8; 16];
    out.copy_from_slice(&be[16..32]);
    out
}

/// `[hi:16][lo:16]` packed into a `bytes32`.
fn pack_pair(hi: U256, lo: U256) -> FixedBytes<32> {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&low16(hi));
    out[16..32].copy_from_slice(&low16(lo));
    FixedBytes::from(out)
}

fn concat_bytes(a: &[u8], b: &[u8]) -> Bytes {
    let mut v = Vec::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    Bytes::from(v)
}

/// Resolved `[bundler]` config plus in-flight UserOp tracking, held in
/// [`RpcState`]. Present only when the node is configured as a bundler.
pub struct BundlerState {
    /// EntryPoint addresses this bundler accepts (20-byte EVM form). The first
    /// is the default for ops whose request omits the entryPoint param.
    pub entry_points: Vec<Address>,
    /// secp256k1 signing key for the `handleOps` transactions the bundler sends.
    pub signing_key: [u8; 32],
    /// Bundler's own TRON address (21-byte, `0x41`-prefixed) derived from the key.
    pub bundler_address: [u8; 21],
    /// `beneficiary` passed to `handleOps` — the gas-fee recipient (20-byte EVM).
    pub beneficiary: Address,
    /// Per-bundle TRX fee cap, in sun.
    pub fee_limit: i64,
    /// Accepted UserOps keyed by userOpHash, for the by-hash / receipt RPCs.
    pub tracked: Mutex<HashMap<B256, TrackedUserOp>>,
}

/// A UserOperation the bundler has accepted, with its on-chain submission.
#[derive(Clone, Debug)]
pub struct TrackedUserOp {
    pub user_op: UserOperation,
    pub entry_point: Address,
    /// The `handleOps` tx id this op was submitted in (`None` until submitted).
    pub tx_id: Option<[u8; 32]>,
}

impl BundlerState {
    pub fn new(
        entry_points: Vec<Address>,
        signing_key: [u8; 32],
        bundler_address: [u8; 21],
        beneficiary: Address,
        fee_limit: i64,
    ) -> Self {
        Self {
            entry_points,
            signing_key,
            bundler_address,
            beneficiary,
            fee_limit,
            tracked: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `addr` (20-byte EVM form) is a configured EntryPoint.
    pub fn supports(&self, addr: &Address) -> bool {
        self.entry_points.iter().any(|e| e == addr)
    }

    /// The `eth_supportedEntryPoints` result — configured EntryPoints as `0x…`.
    pub fn entry_points_json(&self) -> Value {
        json!(self
            .entry_points
            .iter()
            .map(|a| format!("0x{}", hex::encode(a.as_slice())))
            .collect::<Vec<_>>())
    }
}

/// `eth_supportedEntryPoints` — the EntryPoint addresses this bundler accepts.
pub fn eth_supported_entry_points(s: &RpcState) -> Result<Value, RpcError> {
    match &s.bundler {
        Some(b) => Ok(b.entry_points_json()),
        None => Err(RpcError::invalid_request(
            "bundler not enabled on this node (set [bundler] enable = true)",
        )),
    }
}

/// Parse a 20-byte EVM `Address` from any accepted form (`0x…`, TRON `41…`,
/// base58 `T…`) by reusing the node's robust address parser and dropping the
/// `0x41` TRON prefix.
fn parse_addr_evm(s: &str) -> Result<Address, RpcError> {
    let tron = crate::methods::parse_eth_address(s)?;
    Ok(Address::from_slice(&tron.as_bytes()[1..]))
}

fn parse_u256(s: &str) -> Result<U256, RpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(stripped, 16)
        .map_err(|e| RpcError::invalid_params(format!("invalid uint256 `{s}`: {e}")))
}

fn parse_bytes(s: &str) -> Result<Bytes, RpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped)
        .map(Bytes::from)
        .map_err(|e| RpcError::invalid_params(format!("invalid hex bytes `{s}`: {e}")))
}

/// Parse the unpacked v0.7 [`UserOperation`] JSON object an `eth_sendUserOperation`
/// / `eth_estimateUserOperationGas` request carries. Absent optional gas/bytes
/// fields default to `0`/empty; `sender` and `nonce` are required.
fn parse_user_op(obj: &Map<String, Value>) -> Result<UserOperation, RpcError> {
    fn req<'a>(obj: &'a Map<String, Value>, k: &str) -> Result<&'a str, RpcError> {
        obj.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params(format!("UserOperation missing `{k}`")))
    }
    fn u256_or_zero(obj: &Map<String, Value>, k: &str) -> Result<U256, RpcError> {
        match obj.get(k).and_then(Value::as_str) {
            Some(s) => parse_u256(s),
            None => Ok(U256::ZERO),
        }
    }
    fn bytes_or_empty(obj: &Map<String, Value>, k: &str) -> Result<Bytes, RpcError> {
        match obj.get(k).and_then(Value::as_str) {
            Some(s) => parse_bytes(s),
            None => Ok(Bytes::new()),
        }
    }
    let opt_addr = |k: &str| -> Result<Option<Address>, RpcError> {
        match obj.get(k).and_then(Value::as_str) {
            Some(s) => Ok(Some(parse_addr_evm(s)?)),
            None => Ok(None),
        }
    };
    Ok(UserOperation {
        sender: parse_addr_evm(req(obj, "sender")?)?,
        nonce: parse_u256(req(obj, "nonce")?)?,
        factory: opt_addr("factory")?,
        factory_data: bytes_or_empty(obj, "factoryData")?,
        call_data: bytes_or_empty(obj, "callData")?,
        call_gas_limit: u256_or_zero(obj, "callGasLimit")?,
        verification_gas_limit: u256_or_zero(obj, "verificationGasLimit")?,
        pre_verification_gas: u256_or_zero(obj, "preVerificationGas")?,
        max_fee_per_gas: u256_or_zero(obj, "maxFeePerGas")?,
        max_priority_fee_per_gas: u256_or_zero(obj, "maxPriorityFeePerGas")?,
        paymaster: opt_addr("paymaster")?,
        paymaster_verification_gas_limit: u256_or_zero(obj, "paymasterVerificationGasLimit")?,
        paymaster_post_op_gas_limit: u256_or_zero(obj, "paymasterPostOpGasLimit")?,
        paymaster_data: bytes_or_empty(obj, "paymasterData")?,
        signature: bytes_or_empty(obj, "signature")?,
    })
}

/// Decode the EntryPoint's `FailedOp` / `FailedOpWithRevert` revert into a human
/// reason, so a rejected `eth_sendUserOperation` tells the caller *why* (e.g.
/// "AA24 signature error"). Returns `None` for non-FailedOp revert data.
fn decode_failed_op(revert_data: &[u8]) -> Option<String> {
    if let Ok(e) = FailedOp::abi_decode(revert_data) {
        return Some(format!("op {}: {}", e.opIndex, e.reason));
    }
    if let Ok(e) = FailedOpWithRevert::abi_decode(revert_data) {
        return Some(format!(
            "op {}: {} (inner revert 0x{})",
            e.opIndex,
            e.reason,
            hex::encode(&e.inner)
        ));
    }
    None
}

/// `0x41`-prefixed 21-byte TRON address for a 20-byte EVM `Address`.
fn tron_addr_21(evm: Address) -> Vec<u8> {
    let mut v = Vec::with_capacity(21);
    v.push(0x41);
    v.extend_from_slice(evm.as_slice());
    v
}

/// Simulate a call to the EntryPoint from the bundler's address through the
/// constant-call VM (the session is never committed — read-only, like
/// `eth_call`). Returns the call's return data, or an error carrying the decoded
/// `FailedOp` reason on revert.
fn sim_entrypoint(
    s: &RpcState,
    bundler: &BundlerState,
    entry_point: Address,
    calldata: Vec<u8>,
) -> Result<Vec<u8>, RpcError> {
    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal("bundler: server built without EVM call backends"));
    };
    let vm_stores = build_call_vm_stores(b);
    let block_env = VmBlockEnv {
        block_number: s.dyn_props.latest_block_header_number().unwrap_or(0),
        block_timestamp_ms: s.dyn_props.latest_block_header_timestamp().unwrap_or(0),
    };
    let trigger = TriggerSmartContract {
        owner_address: bundler.bundler_address.to_vec(),
        contract_address: tron_addr_21(entry_point),
        call_value: 0,
        data: calldata,
        call_token_value: 0,
        token_id: 0,
    };
    let (outcome, _penalty) =
        dispatch_constant_trigger(s, &vm_stores, block_env, &trigger, s.eth_call_gas_cap);
    match outcome {
        VmOutcome::Success { return_data, .. } => Ok(return_data),
        VmOutcome::Revert { return_data, .. } => {
            let reason = decode_failed_op(&return_data)
                .unwrap_or_else(|| format!("execution reverted: 0x{}", hex::encode(&return_data)));
            Err(RpcError::invalid_request(reason))
        }
        VmOutcome::Halt { reason, .. } => {
            Err(RpcError::server_error(format!("entrypoint call halted: {reason}")))
        }
        _ => Err(RpcError::server_error("entrypoint call did not complete")),
    }
}

/// `eth_sendUserOperation(userOp, entryPoint)` — validate the op by simulating
/// `EntryPoint.handleOps` (reject on revert, surfacing the `FailedOp` reason),
/// then bundle it into a signed `handleOps` transaction and submit it to the
/// mempool (which auto-relays to peers). Returns the userOpHash, computed by the
/// EntryPoint itself so it matches whatever EntryPoint version is deployed.
pub fn eth_send_user_operation(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(bundler) = &s.bundler else {
        return Err(RpcError::invalid_request(
            "bundler not enabled on this node (set [bundler] enable = true)",
        ));
    };
    let obj = p
        .get(0)
        .and_then(Value::as_object)
        .ok_or_else(|| RpcError::invalid_params("missing UserOperation object (params[0])"))?;
    let ep_str = p
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing entryPoint address (params[1])"))?;
    let entry_point = parse_addr_evm(ep_str)?;
    if !bundler.supports(&entry_point) {
        return Err(RpcError::invalid_params(format!(
            "unsupported entryPoint 0x{} (see eth_supportedEntryPoints)",
            hex::encode(entry_point.as_slice())
        )));
    }
    let op = parse_user_op(obj)?;
    let packed = op.pack();

    // userOpHash from the EntryPoint itself — version-agnostic, binds chainId.
    let hash_ret = sim_entrypoint(
        s,
        bundler,
        entry_point,
        getUserOpHashCall { userOp: packed.clone() }.abi_encode(),
    )?;
    if hash_ret.len() < 32 {
        return Err(RpcError::internal("EntryPoint.getUserOpHash returned < 32 bytes"));
    }
    let user_op_hash = B256::from_slice(&hash_ret[..32]);

    // Validate: simulate handleOps; reject (with reason) if it reverts.
    let handle_data =
        handleOpsCall { ops: vec![packed], beneficiary: bundler.beneficiary }.abi_encode();
    sim_entrypoint(s, bundler, entry_point, handle_data.clone())?;

    // Bundle: sign the handleOps tx and submit it (the mempool auto-relays).
    let Some(mempool) = &s.mempool else {
        return Err(RpcError::internal("bundler: no mempool attached to submit the bundle"));
    };
    let trigger = TriggerSmartContract {
        owner_address: bundler.bundler_address.to_vec(),
        contract_address: tron_addr_21(entry_point),
        call_value: 0,
        data: handle_data,
        call_token_value: 0,
        token_id: 0,
    };
    let contract = crate::builder::wrap_contract(
        tron_proto::transaction::contract::ContractType::TriggerSmartContract,
        &trigger,
        0,
    );
    let mut tx = crate::builder::build_unsigned_tx(s, contract, bundler.fee_limit)?;
    tron_types::tx_sign::sign_transaction(&mut tx, &bundler.signing_key)
        .map_err(|e| RpcError::internal(format!("bundler tx sign failed: {e:?}")))?;
    let tx_id = match mempool.submit_tron(&tx.encode_to_vec()) {
        crate::mempool::SubmitOutcome::Accepted(id) => id,
        crate::mempool::SubmitOutcome::Rejected(reason) => {
            return Err(RpcError::server_error(format!("bundle tx rejected: {reason}")))
        }
        crate::mempool::SubmitOutcome::Unsupported => {
            return Err(RpcError::internal("bundle tx submission unsupported by mempool"))
        }
    };

    // Track for eth_getUserOperationByHash / Receipt.
    if let Ok(mut tracked) = bundler.tracked.lock() {
        tracked.insert(
            user_op_hash,
            TrackedUserOp { user_op: op, entry_point, tx_id: Some(tx_id) },
        );
    }
    Ok(Value::String(format!("0x{}", hex::encode(user_op_hash.as_slice()))))
}

/// Parse a 32-byte `0x…` hash into a [`B256`].
fn parse_b256(s: &str) -> Result<B256, RpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped)
        .map_err(|e| RpcError::invalid_params(format!("invalid hash `{s}`: {e}")))?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("userOpHash must be 32 bytes"));
    }
    Ok(B256::from_slice(&bytes))
}

/// Find the `UserOperationEvent` for `hash` in a receipt's logs and decode it
/// into `(success, actualGasCost, actualGasUsed, paymaster)`. The event data is
/// `abi(nonce, success, actualGasCost, actualGasUsed)`; topic[3] is the paymaster.
fn find_user_op_event(logs: &[Value], hash: &B256) -> Option<(bool, String, String, Value)> {
    let sig_hex = format!("0x{}", hex::encode(UserOperationEvent::SIGNATURE_HASH.as_slice()));
    let hash_hex = format!("0x{}", hex::encode(hash.as_slice()));
    for log in logs {
        let Some(topics) = log.get("topics").and_then(Value::as_array) else { continue };
        if topics.len() < 4 {
            continue;
        }
        let t0 = topics[0].as_str().unwrap_or_default();
        let t1 = topics[1].as_str().unwrap_or_default();
        if !t0.eq_ignore_ascii_case(&sig_hex) || !t1.eq_ignore_ascii_case(&hash_hex) {
            continue;
        }
        let paymaster = topics[3]
            .as_str()
            .filter(|s| s.len() >= 40)
            .map(|s| json!(format!("0x{}", &s[s.len() - 40..])))
            .unwrap_or(Value::Null);
        let data_hex = log.get("data").and_then(Value::as_str).unwrap_or("0x");
        let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(data_hex)).unwrap_or_default();
        if data.len() < 128 {
            return Some((false, "0x0".into(), "0x0".into(), paymaster));
        }
        let success = data[63] != 0;
        let cost = U256::from_be_slice(&data[64..96]);
        let used = U256::from_be_slice(&data[96..128]);
        return Some((success, format!("0x{cost:x}"), format!("0x{used:x}"), paymaster));
    }
    None
}

/// `eth_getUserOperationByHash(userOpHash)` — the tracked op + its on-chain
/// location, or `null` if the bundler never saw it.
pub fn eth_get_user_operation_by_hash(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(bundler) = &s.bundler else {
        return Ok(Value::Null);
    };
    let hash = parse_b256(
        p.get(0)
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("missing userOpHash"))?,
    )?;
    let Some(tracked) = bundler.tracked.lock().ok().and_then(|t| t.get(&hash).cloned()) else {
        return Ok(Value::Null);
    };
    let (tx_hash, block_number, block_hash) = match tracked.tx_id {
        Some(id) => {
            let receipt = crate::methods::eth_get_transaction_receipt(
                &json!([format!("0x{}", hex::encode(id))]),
                s,
            )
            .unwrap_or(Value::Null);
            (
                json!(format!("0x{}", hex::encode(id))),
                receipt.get("blockNumber").cloned().unwrap_or(Value::Null),
                receipt.get("blockHash").cloned().unwrap_or(Value::Null),
            )
        }
        None => (Value::Null, Value::Null, Value::Null),
    };
    Ok(json!({
        "userOperation": tracked.user_op.to_json(),
        "entryPoint": format!("0x{}", hex::encode(tracked.entry_point.as_slice())),
        "transactionHash": tx_hash,
        "blockNumber": block_number,
        "blockHash": block_hash,
    }))
}

/// `eth_getUserOperationReceipt(userOpHash)` — the ERC-4337 receipt (success +
/// actual gas from the `UserOperationEvent`, plus the inner tx receipt), or
/// `null` while the op is unknown or not yet mined.
pub fn eth_get_user_operation_receipt(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let Some(bundler) = &s.bundler else {
        return Ok(Value::Null);
    };
    let hash = parse_b256(
        p.get(0)
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("missing userOpHash"))?,
    )?;
    let Some(tracked) = bundler.tracked.lock().ok().and_then(|t| t.get(&hash).cloned()) else {
        return Ok(Value::Null);
    };
    let Some(tx_id) = tracked.tx_id else {
        return Ok(Value::Null);
    };
    let receipt =
        crate::methods::eth_get_transaction_receipt(&json!([format!("0x{}", hex::encode(tx_id))]), s)?;
    if receipt.is_null() {
        return Ok(Value::Null); // submitted but not yet mined
    }
    let logs = receipt.get("logs").and_then(Value::as_array).cloned().unwrap_or_default();
    let (success, actual_gas_cost, actual_gas_used, paymaster) =
        find_user_op_event(&logs, &hash).unwrap_or_else(|| {
            // No UserOperationEvent (bundle reverted) — fall back to tx status.
            let ok = receipt.get("status").and_then(Value::as_str) == Some("0x1");
            (ok, "0x0".to_string(), "0x0".to_string(), Value::Null)
        });
    Ok(json!({
        "userOpHash": format!("0x{}", hex::encode(hash.as_slice())),
        "entryPoint": format!("0x{}", hex::encode(tracked.entry_point.as_slice())),
        "sender": format!("0x{}", hex::encode(tracked.user_op.sender.as_slice())),
        "nonce": format!("0x{:x}", tracked.user_op.nonce),
        "paymaster": paymaster,
        "success": success,
        "actualGasCost": actual_gas_cost,
        "actualGasUsed": actual_gas_used,
        "logs": logs,
        "receipt": receipt,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u64) -> U256 {
        U256::from(n)
    }

    fn sample(factory: Option<Address>, paymaster: Option<Address>) -> UserOperation {
        UserOperation {
            sender: Address::repeat_byte(0x11),
            nonce: u(7),
            factory,
            factory_data: Bytes::from(vec![0xaa, 0xbb]),
            call_data: Bytes::from(vec![0xde, 0xad]),
            call_gas_limit: u(0x1111),
            verification_gas_limit: u(0x2222),
            pre_verification_gas: u(0x3333),
            max_fee_per_gas: u(0x4444),
            max_priority_fee_per_gas: u(0x5555),
            paymaster,
            paymaster_verification_gas_limit: u(0x6666),
            paymaster_post_op_gas_limit: u(0x7777),
            paymaster_data: Bytes::from(vec![0xcc]),
            signature: Bytes::from(vec![0x01, 0x02]),
        }
    }

    #[test]
    fn pack_account_gas_limits_and_fees() {
        let p = sample(None, None).pack();
        // accountGasLimits = verificationGasLimit[high16] ++ callGasLimit[low16]
        assert_eq!(&p.accountGasLimits[0..16], &low16(u(0x2222)), "verificationGasLimit high");
        assert_eq!(&p.accountGasLimits[16..32], &low16(u(0x1111)), "callGasLimit low");
        // gasFees = maxPriorityFeePerGas[high16] ++ maxFeePerGas[low16]
        assert_eq!(&p.gasFees[0..16], &low16(u(0x5555)), "maxPriorityFeePerGas high");
        assert_eq!(&p.gasFees[16..32], &low16(u(0x4444)), "maxFeePerGas low");
        // no factory/paymaster -> empty initCode / paymasterAndData
        assert!(p.initCode.is_empty());
        assert!(p.paymasterAndData.is_empty());
        assert_eq!(p.sender, Address::repeat_byte(0x11));
        assert_eq!(p.nonce, u(7));
    }

    #[test]
    fn pack_init_code_and_paymaster() {
        let factory = Address::repeat_byte(0x22);
        let paymaster = Address::repeat_byte(0x33);
        let p = sample(Some(factory), Some(paymaster)).pack();
        // initCode = factory(20) ++ factoryData
        assert_eq!(&p.initCode[0..20], factory.as_slice());
        assert_eq!(&p.initCode[20..], &[0xaa, 0xbb]);
        // paymasterAndData = paymaster(20) ++ pmVerGas(16) ++ pmPostOp(16) ++ data
        assert_eq!(&p.paymasterAndData[0..20], paymaster.as_slice());
        assert_eq!(&p.paymasterAndData[20..36], &low16(u(0x6666)));
        assert_eq!(&p.paymasterAndData[36..52], &low16(u(0x7777)));
        assert_eq!(&p.paymasterAndData[52..], &[0xcc]);
    }

    #[test]
    fn handle_ops_abi_encodes_with_selector() {
        // The sol! interface ABI-encodes handleOps([op], beneficiary) with the
        // canonical selector — proves the on-chain call encoding is wired.
        let op = sample(None, None).pack();
        let call = handleOpsCall { ops: vec![op], beneficiary: Address::repeat_byte(0x44) };
        let encoded = call.abi_encode();
        assert_eq!(encoded[0..4], handleOpsCall::SELECTOR, "handleOps selector");
        assert!(encoded.len() > 4);
    }

    #[test]
    fn supported_entry_points_and_supports() {
        let ep1 = Address::repeat_byte(0xa1);
        let ep2 = Address::repeat_byte(0xb2);
        let st = BundlerState::new(
            vec![ep1, ep2],
            [0u8; 32],
            [0x41u8; 21],
            Address::repeat_byte(0xcc),
            1_000_000_000,
        );
        assert!(st.supports(&ep1) && st.supports(&ep2));
        assert!(!st.supports(&Address::repeat_byte(0x99)));
        let arr = st.entry_points_json();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], format!("0x{}", hex::encode(ep1.as_slice())));
    }

    #[test]
    fn parse_user_op_round_trips() {
        let obj = json!({
            "sender": "0x1111111111111111111111111111111111111111",
            "nonce": "0x7",
            "callData": "0xdead",
            "callGasLimit": "0x1111",
            "verificationGasLimit": "0x2222",
            "preVerificationGas": "0x3333",
            "maxFeePerGas": "0x4444",
            "maxPriorityFeePerGas": "0x5555",
            "signature": "0x0102"
        });
        let op = parse_user_op(obj.as_object().unwrap()).unwrap();
        assert_eq!(op.sender, Address::repeat_byte(0x11));
        assert_eq!(op.nonce, U256::from(7));
        assert_eq!(op.call_gas_limit, U256::from(0x1111));
        assert!(op.factory.is_none() && op.paymaster.is_none());
        // absent optional fields default to empty/zero
        assert!(op.factory_data.is_empty());
        assert_eq!(op.pre_verification_gas, U256::from(0x3333));
        // packs cleanly: no factory/paymaster -> empty initCode/paymasterAndData
        let p = op.pack();
        assert!(p.initCode.is_empty() && p.paymasterAndData.is_empty());
        assert_eq!(&p.callData[..], &[0xde, 0xad]);
    }

    #[test]
    fn parse_user_op_rejects_missing_sender() {
        let err = parse_user_op(json!({ "nonce": "0x1" }).as_object().unwrap()).unwrap_err();
        assert!(err.message.contains("missing `sender`"), "got: {}", err.message);
    }

    #[test]
    fn decode_failed_op_reason() {
        let enc = FailedOp { opIndex: U256::from(0u64), reason: "AA24 signature error".to_string() }
            .abi_encode();
        assert_eq!(decode_failed_op(&enc).as_deref(), Some("op 0: AA24 signature error"));
        assert!(decode_failed_op(&[0x12, 0x34]).is_none(), "non-FailedOp data must not decode");
    }

    #[test]
    fn send_user_operation_gating() {
        use std::sync::Arc;
        use tron_chainbase::{KvBackend, MemBackend};
        let mem = || Arc::new(MemBackend::new()) as Arc<dyn KvBackend>;
        let base = || RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
        let bundler = || {
            Arc::new(BundlerState::new(
                vec![Address::repeat_byte(0x11)],
                [7u8; 32],
                [0x41u8; 21],
                Address::repeat_byte(0xcc),
                1_000_000_000,
            ))
        };
        let p = json!([
            { "sender": "0x1111111111111111111111111111111111111111", "nonce": "0x0" },
            "0xabababababababababababababababababababab"
        ]);
        // bundler disabled -> error
        assert!(eth_send_user_operation(&p, &base())
            .unwrap_err()
            .message
            .contains("bundler not enabled"));
        // enabled but unsupported entryPoint -> error, before any VM work
        let s = base().with_bundler(bundler());
        assert!(eth_send_user_operation(&p, &s)
            .unwrap_err()
            .message
            .contains("unsupported entryPoint"));
        // supportedEntryPoints reflects the config
        assert_eq!(eth_supported_entry_points(&s).unwrap().as_array().unwrap().len(), 1);
    }

    #[test]
    fn user_op_to_json_echoes() {
        let j = sample(None, None).to_json();
        assert_eq!(j["sender"], format!("0x{}", hex::encode(Address::repeat_byte(0x11).as_slice())));
        assert_eq!(j["nonce"], "0x7");
        assert_eq!(j["callGasLimit"], "0x1111");
        assert_eq!(j["callData"], "0xdead");
        assert!(j.get("factory").is_none() && j.get("paymaster").is_none(), "omitted when unset");
        let jp = sample(None, Some(Address::repeat_byte(0x33))).to_json();
        assert_eq!(jp["paymaster"], format!("0x{}", hex::encode(Address::repeat_byte(0x33).as_slice())));
    }

    #[test]
    fn user_op_event_decode() {
        let hash = B256::repeat_byte(0xab);
        let pm = Address::repeat_byte(0xcd);
        let sig = format!("0x{}", hex::encode(UserOperationEvent::SIGNATURE_HASH.as_slice()));
        let hash_t = format!("0x{}", hex::encode(hash.as_slice()));
        let pm_topic = format!("0x{}{}", "0".repeat(24), hex::encode(pm.as_slice()));
        // data words: nonce=0, success=1, actualGasCost=0x111, actualGasUsed=0x222
        let mut data = vec![0u8; 32];
        let mut succ = vec![0u8; 32];
        succ[31] = 1;
        let mut cost = vec![0u8; 32];
        cost[30] = 0x01;
        cost[31] = 0x11;
        let mut used = vec![0u8; 32];
        used[30] = 0x02;
        used[31] = 0x22;
        data.extend_from_slice(&succ);
        data.extend_from_slice(&cost);
        data.extend_from_slice(&used);
        let log = json!({
            "topics": [sig, hash_t, format!("0x{}", "0".repeat(64)), pm_topic],
            "data": format!("0x{}", hex::encode(&data)),
        });
        let (success, gas_cost, gas_used, paymaster) = find_user_op_event(&[log], &hash).unwrap();
        assert!(success);
        assert_eq!(gas_cost, "0x111");
        assert_eq!(gas_used, "0x222");
        assert_eq!(paymaster, json!(format!("0x{}", hex::encode(pm.as_slice()))));
        // non-matching log -> None
        assert!(find_user_op_event(&[json!({ "topics": [], "data": "0x" })], &hash).is_none());
    }

    #[test]
    fn by_hash_and_receipt_null_when_unknown() {
        use std::sync::Arc;
        use tron_chainbase::{KvBackend, MemBackend};
        let mem = || Arc::new(MemBackend::new()) as Arc<dyn KvBackend>;
        let p = json!([format!("0x{}", "ab".repeat(32))]);
        // bundler disabled -> null
        let s = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
        assert!(eth_get_user_operation_by_hash(&p, &s).unwrap().is_null());
        assert!(eth_get_user_operation_receipt(&p, &s).unwrap().is_null());
        // enabled but hash not tracked -> null
        let s = s.with_bundler(Arc::new(BundlerState::new(
            vec![],
            [0u8; 32],
            [0x41u8; 21],
            Address::repeat_byte(0),
            0,
        )));
        assert!(eth_get_user_operation_by_hash(&p, &s).unwrap().is_null());
        assert!(eth_get_user_operation_receipt(&p, &s).unwrap().is_null());
    }
}
