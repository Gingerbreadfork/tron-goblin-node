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
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolCall, SolError, SolEvent};
use prost::Message;
use serde_json::{json, Map, Value};
use tron_proto::TriggerSmartContract;
use tron_tvm::execute::{VmBlockEnv, VmLog, VmOutcome};

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

    /// EntryPoint StakeManager deposit/stake record for an entity.
    struct DepositInfo {
        uint256 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    /// EntryPoint methods the bundler encodes/decodes via alloy.
    function handleOps(PackedUserOperation[] ops, address beneficiary) external;
    function getUserOpHash(PackedUserOperation userOp) external view returns (bytes32);
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);
    function getDepositInfo(address account) external view returns (DepositInfo info);

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

/// Default cap on UserOps packed into one `handleOps` bundle.
pub const DEFAULT_MAX_BUNDLE_SIZE: usize = 50;
/// Default auto-mode bundling cadence, in milliseconds.
pub const DEFAULT_BUNDLE_INTERVAL_MS: u64 = 2_000;

/// How the bundler decides when to submit pending ops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BundlingMode {
    /// Bundle + submit automatically on the configured interval (default).
    #[default]
    Auto,
    /// Hold ops in the mempool; only bundle on `debug_bundler_sendBundleNow`.
    Manual,
}

impl BundlingMode {
    /// Parse the `auto` / `manual` strings the config and the
    /// `debug_bundler_setBundlingMode` RPC accept.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }
}

/// A validated UserOperation waiting in the mempool to be bundled, in arrival
/// order. Its `user_op_hash` was computed by the EntryPoint at accept time.
#[derive(Clone, Debug)]
pub struct PendingUserOp {
    pub user_op: UserOperation,
    pub entry_point: Address,
    pub user_op_hash: B256,
}

// ── ERC-7562 reputation / throttling (mempool DoS protection) ────────────────
//
// Each entity (account / factory / paymaster) that appears in a UserOp is
// tracked by how many of its ops the bundler has SEEN versus how many reached a
// submitted bundle (INCLUDED). An entity that floods the mempool with ops that
// never get included loses reputation: it is THROTTLED (only a minimal mempool
// presence admitted) and eventually BANNED, by the reference-bundler rule:
//
//   minExpectedIncluded = opsSeen / MIN_INCLUSION_RATE_DENOMINATOR
//   OK        if opsSeen <= THROTTLING_SLACK
//             or minExpectedIncluded <= opsIncluded + THROTTLING_SLACK
//   THROTTLED if minExpectedIncluded <= opsIncluded + BAN_SLACK
//   BANNED    otherwise

/// Below this many seen ops an entity is always OK (warm-up slack).
const THROTTLING_SLACK: u64 = 10;
/// Extra inclusion slack before an entity is banned outright.
const BAN_SLACK: u64 = 50;
/// 1-in-N expected inclusion rate; below it an entity loses reputation.
const MIN_INCLUSION_RATE_DENOMINATOR: u64 = 10;
/// A throttled entity may keep at most this many ops in the mempool at once.
const THROTTLED_ENTITY_MEMPOOL_COUNT: usize = 1;

/// Reputation verdict for an entity, per ERC-7562.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReputationStatus {
    Ok,
    Throttled,
    Banned,
}

impl ReputationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Throttled => "throttled",
            Self::Banned => "banned",
        }
    }
}

/// Per-entity seen/included counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReputationEntry {
    pub ops_seen: u64,
    pub ops_included: u64,
}

impl ReputationEntry {
    fn status(&self) -> ReputationStatus {
        if self.ops_seen <= THROTTLING_SLACK {
            return ReputationStatus::Ok;
        }
        let min_expected = self.ops_seen / MIN_INCLUSION_RATE_DENOMINATOR;
        if min_expected <= self.ops_included + THROTTLING_SLACK {
            ReputationStatus::Ok
        } else if min_expected <= self.ops_included + BAN_SLACK {
            ReputationStatus::Throttled
        } else {
            ReputationStatus::Banned
        }
    }
}

/// Reputation for every entity the bundler has seen.
#[derive(Default)]
pub struct ReputationManager {
    entries: HashMap<Address, ReputationEntry>,
}

impl ReputationManager {
    fn status(&self, addr: &Address) -> ReputationStatus {
        self.entries.get(addr).map(ReputationEntry::status).unwrap_or(ReputationStatus::Ok)
    }

    fn bump_seen(&mut self, addr: Address) {
        self.entries.entry(addr).or_default().ops_seen += 1;
    }

    fn bump_included(&mut self, addr: Address) {
        self.entries.entry(addr).or_default().ops_included += 1;
    }

    fn set(&mut self, addr: Address, ops_seen: u64, ops_included: u64) {
        self.entries.insert(addr, ReputationEntry { ops_seen, ops_included });
    }
}

/// The reputation-tracked entities for an op: its account (sender), plus the
/// factory and paymaster when present.
fn op_entities(op: &UserOperation) -> Vec<Address> {
    let mut v = vec![op.sender];
    if let Some(f) = op.factory {
        v.push(f);
    }
    if let Some(pm) = op.paymaster {
        v.push(pm);
    }
    v
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
    /// Bounded (FIFO eviction past [`MAX_TRACKED`]) so a long-running bundler's
    /// memory doesn't grow without limit as ops accumulate.
    pub tracked: Mutex<TrackedOps>,
    /// Validated UserOps awaiting bundling, in arrival order. Drained by the
    /// background bundling loop and by `debug_bundler_sendBundleNow`.
    pub mempool: Mutex<Vec<PendingUserOp>>,
    /// Current bundling mode; runtime-switchable via `debug_bundler_setBundlingMode`.
    pub bundling_mode: Mutex<BundlingMode>,
    /// Max UserOps packed into a single `handleOps` bundle (overflow re-queues).
    pub max_bundle_size: usize,
    /// Auto-mode bundling cadence.
    pub bundle_interval: Duration,
    /// ERC-7562 per-entity reputation (factory / paymaster / account throttling).
    pub reputation: Mutex<ReputationManager>,
}

/// Upper bound on tracked UserOps held in memory for the by-hash / receipt
/// RPCs. Once exceeded, the oldest entry is evicted as each new op arrives, so
/// only the most recent ~`MAX_TRACKED` ops remain queryable — ample for live
/// clients polling a freshly-submitted op, while capping memory.
const MAX_TRACKED: usize = 100_000;

/// Insertion-ordered, size-bounded store of accepted UserOps. Keeps a FIFO
/// `order` queue alongside the hash map so eviction is O(1) and the two stay
/// consistent under the single [`BundlerState::tracked`] mutex.
#[derive(Default)]
pub struct TrackedOps {
    by_hash: HashMap<B256, TrackedUserOp>,
    order: VecDeque<B256>,
}

impl TrackedOps {
    /// Record (or replace) an op. New hashes extend the FIFO queue and evict
    /// the oldest entries once the map exceeds [`MAX_TRACKED`]; re-inserting an
    /// existing hash updates it in place without disturbing eviction order.
    fn insert(&mut self, hash: B256, op: TrackedUserOp) {
        if self.by_hash.insert(hash, op).is_none() {
            self.order.push_back(hash);
            while self.order.len() > MAX_TRACKED {
                if let Some(evicted) = self.order.pop_front() {
                    self.by_hash.remove(&evicted);
                }
            }
        }
    }

    /// A clone of the tracked op, if still retained (not evicted).
    fn get(&self, hash: &B256) -> Option<TrackedUserOp> {
        self.by_hash.get(hash).cloned()
    }

    /// Number of currently-tracked ops (test/observability).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_hash.len()
    }
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
            tracked: Mutex::new(TrackedOps::default()),
            mempool: Mutex::new(Vec::new()),
            bundling_mode: Mutex::new(BundlingMode::Auto),
            max_bundle_size: DEFAULT_MAX_BUNDLE_SIZE,
            bundle_interval: Duration::from_millis(DEFAULT_BUNDLE_INTERVAL_MS),
            reputation: Mutex::new(ReputationManager::default()),
        }
    }

    /// Configure bundling behaviour (mode / bundle size / cadence). Chained off
    /// [`Self::new`] or [`Self::from_config`] by the runtime.
    pub fn with_bundling(
        mut self,
        mode: BundlingMode,
        max_bundle_size: usize,
        bundle_interval: Duration,
    ) -> Self {
        *self.bundling_mode.get_mut().expect("fresh mutex") = mode;
        self.max_bundle_size = max_bundle_size.max(1);
        self.bundle_interval = bundle_interval;
        self
    }

    /// The current bundling mode.
    pub fn mode(&self) -> BundlingMode {
        self.bundling_mode.lock().map(|m| *m).unwrap_or_default()
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

    /// Build from resolved `[bundler]` config. `entry_points`/`beneficiary` are
    /// parsed from their string forms (`0x…`/TRON/base58); the caller resolves
    /// `signing_key`/`bundler_address` from the configured key source.
    /// `beneficiary` defaults to the bundler's own address.
    pub fn from_config(
        entry_points: &[String],
        signing_key: [u8; 32],
        bundler_address: [u8; 21],
        beneficiary: Option<&str>,
        fee_limit: i64,
    ) -> Result<Self, String> {
        let eps = entry_points
            .iter()
            .map(|s| {
                parse_addr_evm(s).map_err(|e| format!("[bundler] entry_point `{s}`: {}", e.message))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if eps.is_empty() {
            return Err("[bundler] entry_points must list at least one EntryPoint".into());
        }
        let benef = match beneficiary {
            Some(b) => {
                parse_addr_evm(b).map_err(|e| format!("[bundler] beneficiary: {}", e.message))?
            }
            None => Address::from_slice(&bundler_address[1..]),
        };
        Ok(Self::new(eps, signing_key, bundler_address, benef, fee_limit))
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

/// Raw outcome of a constant-call simulation. The bundler branches on
/// [`SimResult::Revert`] to decode the EntryPoint's `FailedOp` opIndex and drop
/// the offending op from a bundle, which [`sim_call`]'s flattened `Result` form
/// can't express.
enum SimResult {
    Ok { return_data: Vec<u8>, energy_used: u64, logs: Vec<VmLog> },
    Revert(Vec<u8>),
    Failed(RpcError),
}

/// Simulate a call from `owner` (21-byte `0x41` TRON address) to `contract`
/// (20-byte EVM) through the constant-call VM (the session is never committed —
/// read-only, like `eth_call`), returning the raw outcome.
fn sim_call_outcome(
    s: &RpcState,
    owner: Vec<u8>,
    contract: Address,
    calldata: Vec<u8>,
) -> SimResult {
    let Some(b) = &s.eth_call_backends else {
        return SimResult::Failed(RpcError::internal(
            "bundler: server built without EVM call backends",
        ));
    };
    let vm_stores = build_call_vm_stores(b);
    let block_env = VmBlockEnv {
        block_number: s.dyn_props.latest_block_header_number().unwrap_or(0),
        block_timestamp_ms: s.dyn_props.latest_block_header_timestamp().unwrap_or(0),
    };
    let trigger = TriggerSmartContract {
        owner_address: owner,
        contract_address: tron_addr_21(contract),
        call_value: 0,
        data: calldata,
        call_token_value: 0,
        token_id: 0,
    };
    let (outcome, _penalty) =
        dispatch_constant_trigger(s, &vm_stores, block_env, &trigger, s.eth_call_gas_cap);
    match outcome {
        VmOutcome::Success { return_data, energy_used, logs } => {
            SimResult::Ok { return_data, energy_used, logs }
        }
        VmOutcome::Revert { return_data, .. } => SimResult::Revert(return_data),
        VmOutcome::Halt { reason, .. } => {
            SimResult::Failed(RpcError::server_error(format!("entrypoint call halted: {reason}")))
        }
        _ => SimResult::Failed(RpcError::server_error("entrypoint call did not complete")),
    }
}

/// As [`sim_call_outcome`] but flattened to a `Result`, with a revert decoded
/// to its `FailedOp` reason (e.g. "op 0: AA24 signature error").
fn sim_call(
    s: &RpcState,
    owner: Vec<u8>,
    contract: Address,
    calldata: Vec<u8>,
) -> Result<(Vec<u8>, u64), RpcError> {
    match sim_call_outcome(s, owner, contract, calldata) {
        SimResult::Ok { return_data, energy_used, .. } => Ok((return_data, energy_used)),
        SimResult::Revert(data) => {
            let reason = decode_failed_op(&data)
                .unwrap_or_else(|| format!("execution reverted: 0x{}", hex::encode(&data)));
            Err(RpcError::invalid_request(reason))
        }
        SimResult::Failed(e) => Err(e),
    }
}

/// `eth_sendUserOperation(userOp, entryPoint)` — validate the op by simulating
/// `EntryPoint.handleOps` (reject on revert, surfacing the `FailedOp` reason),
/// then accept it into the bundler's mempool. The background bundling loop
/// (auto mode) or `debug_bundler_sendBundleNow` (manual mode) packs it together
/// with other pending ops into one signed `handleOps` transaction and submits
/// it (the mempool auto-relays to peers). Returns the userOpHash, computed by
/// the EntryPoint itself so it matches whatever EntryPoint version is deployed.
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
    let (hash_ret, _) = sim_call(
        s,
        bundler.bundler_address.to_vec(),
        entry_point,
        getUserOpHashCall { userOp: packed.clone() }.abi_encode(),
    )?;
    if hash_ret.len() < 32 {
        return Err(RpcError::internal("EntryPoint.getUserOpHash returned < 32 bytes"));
    }
    let user_op_hash = B256::from_slice(&hash_ret[..32]);

    // Validate: simulate handleOps([op]); reject (with the decoded FailedOp
    // reason) if it reverts, so a bad op never enters the mempool.
    let handle_data =
        handleOpsCall { ops: vec![packed], beneficiary: bundler.beneficiary }.abi_encode();
    sim_call(s, bundler.bundler_address.to_vec(), entry_point, handle_data)?;

    // ERC-7562 reputation: reject ops whose account / factory / paymaster is
    // BANNED, cap a THROTTLED entity's mempool presence, and bump opsSeen.
    let entities = op_entities(&op);
    let present: HashMap<Address, usize> = {
        let mp = bundler
            .mempool
            .lock()
            .map_err(|_| RpcError::internal("bundler mempool lock poisoned"))?;
        entities
            .iter()
            .map(|e| (*e, mp.iter().filter(|o| op_entities(&o.user_op).contains(e)).count()))
            .collect()
    };
    {
        let mut rep = bundler
            .reputation
            .lock()
            .map_err(|_| RpcError::internal("bundler reputation lock poisoned"))?;
        for e in &entities {
            match rep.status(e) {
                ReputationStatus::Banned => {
                    return Err(RpcError::invalid_request(format!(
                        "entity 0x{} is banned (too many UserOps never included)",
                        hex::encode(e.as_slice())
                    )));
                }
                ReputationStatus::Throttled
                    if present.get(e).copied().unwrap_or(0) >= THROTTLED_ENTITY_MEMPOOL_COUNT =>
                {
                    return Err(RpcError::invalid_request(format!(
                        "entity 0x{} is throttled and already has a pending op",
                        hex::encode(e.as_slice())
                    )));
                }
                _ => {}
            }
        }
        for e in &entities {
            rep.bump_seen(*e);
        }
    }

    // Accept into the mempool; the bundling loop (auto) or
    // debug_bundler_sendBundleNow (manual) submits it bundled with other ops.
    if let Ok(mut mp) = bundler.mempool.lock() {
        mp.push(PendingUserOp { user_op: op.clone(), entry_point, user_op_hash });
    }
    if let Ok(mut tracked) = bundler.tracked.lock() {
        tracked.insert(user_op_hash, TrackedUserOp { user_op: op, entry_point, tx_id: None });
    }
    Ok(Value::String(format!("0x{}", hex::encode(user_op_hash.as_slice()))))
}

// =============================================================================
// Bundling: drain the mempool into handleOps transactions
// =============================================================================

/// `&BundlerState` if the node is configured as a bundler, else the standard
/// "not enabled" error.
fn require_bundler(s: &RpcState) -> Result<&BundlerState, RpcError> {
    s.bundler.as_deref().ok_or_else(|| {
        RpcError::invalid_request("bundler not enabled on this node (set [bundler] enable = true)")
    })
}

/// The `opIndex` carried by a `FailedOp` / `FailedOpWithRevert` revert, so a
/// single failing op can be dropped from a bundle and the rest still submitted.
fn failed_op_index(revert_data: &[u8]) -> Option<usize> {
    let idx = if let Ok(e) = FailedOp::abi_decode(revert_data) {
        e.opIndex
    } else if let Ok(e) = FailedOpWithRevert::abi_decode(revert_data) {
        e.opIndex
    } else {
        return None;
    };
    u256_to_usize(idx)
}

/// A `U256` as `usize`, or `None` if it doesn't fit (defensive — opIndex is a
/// small bundle position).
fn u256_to_usize(v: U256) -> Option<usize> {
    let be = v.to_be_bytes::<32>();
    if be[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&be[24..32]);
    usize::try_from(u64::from_be_bytes(low)).ok()
}

/// Sign and submit a `handleOps` transaction to the mempool (which auto-relays
/// to peers); returns the tx id.
fn submit_handle_ops(
    s: &RpcState,
    bundler: &BundlerState,
    entry_point: Address,
    handle_data: Vec<u8>,
) -> Result<[u8; 32], RpcError> {
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
    match mempool.submit_tron(&tx.encode_to_vec()) {
        crate::mempool::SubmitOutcome::Accepted(id) => Ok(id),
        crate::mempool::SubmitOutcome::Rejected(reason) => {
            Err(RpcError::server_error(format!("bundle tx rejected: {reason}")))
        }
        crate::mempool::SubmitOutcome::Unsupported => {
            Err(RpcError::internal("bundle tx submission unsupported by mempool"))
        }
    }
}

/// Outcome of submitting one EntryPoint's bundle.
struct BundleOutcome {
    tx_id: [u8; 32],
    included: Vec<B256>,
}

/// Build a `handleOps` bundle from `ops` for one EntryPoint: re-simulate the
/// whole bundle and, if the EntryPoint rejects an op (`FailedOp` opIndex), drop
/// that op and retry, so one bad op can't wedge the rest. Sign + submit the
/// surviving bundle. Ops that drop out (or a whole-bundle submit failure) are
/// recorded in `dropped` as `(userOpHash, reason)`.
fn build_and_submit_bundle(
    s: &RpcState,
    bundler: &BundlerState,
    entry_point: Address,
    mut ops: Vec<PendingUserOp>,
    dropped: &mut Vec<(B256, String)>,
) -> Option<BundleOutcome> {
    loop {
        if ops.is_empty() {
            return None;
        }
        let packed: Vec<PackedUserOperation> = ops.iter().map(|o| o.user_op.pack()).collect();
        let handle_data =
            handleOpsCall { ops: packed, beneficiary: bundler.beneficiary }.abi_encode();
        match sim_call_outcome(
            s,
            bundler.bundler_address.to_vec(),
            entry_point,
            handle_data.clone(),
        ) {
            SimResult::Ok { .. } => match submit_handle_ops(s, bundler, entry_point, handle_data) {
                Ok(tx_id) => {
                    let included: Vec<B256> = ops.iter().map(|o| o.user_op_hash).collect();
                    if let Ok(mut tracked) = bundler.tracked.lock() {
                        for o in &ops {
                            tracked.insert(
                                o.user_op_hash,
                                TrackedUserOp {
                                    user_op: o.user_op.clone(),
                                    entry_point,
                                    tx_id: Some(tx_id),
                                },
                            );
                        }
                    }
                    // ERC-7562: credit opsIncluded to each included op's entities.
                    if let Ok(mut rep) = bundler.reputation.lock() {
                        for o in &ops {
                            for e in op_entities(&o.user_op) {
                                rep.bump_included(e);
                            }
                        }
                    }
                    return Some(BundleOutcome { tx_id, included });
                }
                Err(e) => {
                    for o in &ops {
                        dropped.push((o.user_op_hash, e.message.clone()));
                    }
                    return None;
                }
            },
            SimResult::Revert(data) => {
                let reason =
                    decode_failed_op(&data).unwrap_or_else(|| format!("0x{}", hex::encode(&data)));
                match failed_op_index(&data) {
                    Some(idx) if idx < ops.len() => {
                        let bad = ops.remove(idx);
                        dropped.push((bad.user_op_hash, reason));
                        // retry the bundle without the offending op
                    }
                    _ => {
                        for o in &ops {
                            dropped.push((o.user_op_hash, reason.clone()));
                        }
                        return None;
                    }
                }
            }
            SimResult::Failed(e) => {
                for o in &ops {
                    dropped.push((o.user_op_hash, e.message.clone()));
                }
                return None;
            }
        }
    }
}

/// `[{userOpHash, reason}]` JSON for a list of dropped ops.
fn dropped_json(dropped: &[(B256, String)]) -> Vec<Value> {
    dropped
        .iter()
        .map(|(h, why)| {
            json!({ "userOpHash": format!("0x{}", hex::encode(h.as_slice())), "reason": why })
        })
        .collect()
}

/// Drain the mempool and submit ready ops as bundled `handleOps` transactions —
/// one per EntryPoint, capped at `max_bundle_size` (overflow re-queues). Returns
/// a JSON summary per EntryPoint touched. Safe to call from the auto loop or
/// `debug_bundler_sendBundleNow`; a no-op when the mempool is empty.
pub fn try_bundle(s: &RpcState) -> Vec<Value> {
    let Some(bundler) = &s.bundler else {
        return Vec::new();
    };
    let drained: Vec<PendingUserOp> = match bundler.mempool.lock() {
        Ok(mut mp) => std::mem::take(&mut *mp),
        Err(_) => return Vec::new(),
    };
    if drained.is_empty() {
        return Vec::new();
    }
    // Group by EntryPoint, preserving arrival order (and first-seen EP order).
    let mut by_ep: HashMap<Address, Vec<PendingUserOp>> = HashMap::new();
    let mut ep_order: Vec<Address> = Vec::new();
    for op in drained {
        let bucket = by_ep.entry(op.entry_point).or_default();
        if bucket.is_empty() {
            ep_order.push(op.entry_point);
        }
        bucket.push(op);
    }
    let mut results = Vec::new();
    let mut requeue: Vec<PendingUserOp> = Vec::new();
    for ep in ep_order {
        let mut ops = by_ep.remove(&ep).unwrap_or_default();
        if ops.len() > bundler.max_bundle_size {
            requeue.extend(ops.split_off(bundler.max_bundle_size));
        }
        let mut dropped: Vec<(B256, String)> = Vec::new();
        let outcome = build_and_submit_bundle(s, bundler, ep, ops, &mut dropped);
        let ep_hex = format!("0x{}", hex::encode(ep.as_slice()));
        match outcome {
            Some(BundleOutcome { tx_id, included }) => results.push(json!({
                "entryPoint": ep_hex,
                "transactionHash": format!("0x{}", hex::encode(tx_id)),
                "userOpHashes": included
                    .iter()
                    .map(|h| format!("0x{}", hex::encode(h.as_slice())))
                    .collect::<Vec<_>>(),
                "dropped": dropped_json(&dropped),
            })),
            None if !dropped.is_empty() => results.push(json!({
                "entryPoint": ep_hex,
                "transactionHash": Value::Null,
                "userOpHashes": Vec::<String>::new(),
                "dropped": dropped_json(&dropped),
            })),
            None => {}
        }
    }
    // Re-queue overflow ahead of anything that arrived mid-bundle, FIFO-fair.
    if !requeue.is_empty() {
        if let Ok(mut mp) = bundler.mempool.lock() {
            requeue.append(&mut mp);
            *mp = requeue;
        }
        // (overflow re-queued ahead of mid-bundle arrivals, FIFO-fair)
    }
    results
}

/// `debug_bundler_sendBundleNow` — force an immediate bundling pass and return
/// the submitted bundles (with any dropped ops). Drives manual mode and tests.
pub fn debug_bundler_send_bundle_now(s: &RpcState) -> Result<Value, RpcError> {
    require_bundler(s)?;
    Ok(json!(try_bundle(s)))
}

/// `debug_bundler_setBundlingMode("auto" | "manual")`.
pub fn debug_bundler_set_bundling_mode(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    let mode_str = p
        .get(0)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing mode (\"auto\" | \"manual\")"))?;
    let mode = BundlingMode::parse(mode_str)
        .ok_or_else(|| RpcError::invalid_params("mode must be \"auto\" or \"manual\""))?;
    if let Ok(mut m) = bundler.bundling_mode.lock() {
        *m = mode;
    }
    Ok(json!(mode.as_str()))
}

/// `debug_bundler_dumpMempool([entryPoint])` — the pending (un-bundled) UserOps,
/// oldest first, optionally filtered to one EntryPoint.
pub fn debug_bundler_dump_mempool(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    let ep = match p.get(0).and_then(Value::as_str) {
        Some(addr) => Some(parse_addr_evm(addr)?),
        None => None,
    };
    let mp = bundler
        .mempool
        .lock()
        .map_err(|_| RpcError::internal("bundler mempool lock poisoned"))?;
    let ops: Vec<Value> = mp
        .iter()
        .filter(|o| ep.map_or(true, |e| o.entry_point == e))
        .map(|o| o.user_op.to_json())
        .collect();
    Ok(json!(ops))
}

/// `debug_bundler_clearMempool` — drop all pending (un-bundled) ops.
pub fn debug_bundler_clear_mempool(s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    if let Ok(mut mp) = bundler.mempool.lock() {
        mp.clear();
    }
    Ok(json!("ok"))
}

/// `debug_bundler_clearState` — drop the mempool, tracked-op history, AND
/// reputation.
pub fn debug_bundler_clear_state(s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    if let Ok(mut mp) = bundler.mempool.lock() {
        mp.clear();
    }
    if let Ok(mut t) = bundler.tracked.lock() {
        *t = TrackedOps::default();
    }
    if let Ok(mut rep) = bundler.reputation.lock() {
        *rep = ReputationManager::default();
    }
    Ok(json!("ok"))
}

/// A reputation count from a JSON number or `0x…` / decimal string.
fn json_count(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?;
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse::<u64>().ok(),
    }
}

/// `debug_bundler_dumpReputation([entryPoint])` — every tracked entity with its
/// opsSeen / opsIncluded and derived status, sorted by address.
pub fn debug_bundler_dump_reputation(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    let rep = bundler
        .reputation
        .lock()
        .map_err(|_| RpcError::internal("bundler reputation lock poisoned"))?;
    let mut out: Vec<Value> = rep
        .entries
        .iter()
        .map(|(addr, e)| {
            json!({
                "address": format!("0x{}", hex::encode(addr.as_slice())),
                "opsSeen": e.ops_seen,
                "opsIncluded": e.ops_included,
                "status": e.status().as_str(),
            })
        })
        .collect();
    out.sort_by(|a, b| a["address"].as_str().cmp(&b["address"].as_str()));
    Ok(json!(out))
}

/// `debug_bundler_setReputation([{address, opsSeen, opsIncluded}], entryPoint)`
/// — overwrite reputation entries (test / admin).
pub fn debug_bundler_set_reputation(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    let arr = p
        .get(0)
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::invalid_params("missing reputation array (params[0])"))?;
    let mut rep = bundler
        .reputation
        .lock()
        .map_err(|_| RpcError::internal("bundler reputation lock poisoned"))?;
    for entry in arr {
        let addr = parse_addr_evm(
            entry
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params("reputation entry missing `address`"))?,
        )?;
        let seen = entry.get("opsSeen").and_then(json_count).unwrap_or(0);
        let included = entry.get("opsIncluded").and_then(json_count).unwrap_or(0);
        rep.set(addr, seen, included);
    }
    Ok(json!("ok"))
}

/// `debug_bundler_clearReputation` — reset all entity reputation.
pub fn debug_bundler_clear_reputation(s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    if let Ok(mut rep) = bundler.reputation.lock() {
        *rep = ReputationManager::default();
    }
    Ok(json!("ok"))
}

/// EntryPoint stake/deposit status for `addr`, decoded from `getDepositInfo`.
fn stake_status(
    s: &RpcState,
    bundler: &BundlerState,
    entry_point: Address,
    addr: Address,
) -> Result<Value, RpcError> {
    let data = getDepositInfoCall { account: addr }.abi_encode();
    let (ret, _) = sim_call(s, bundler.bundler_address.to_vec(), entry_point, data)?;
    // DepositInfo = (uint256 deposit, bool staked, uint112 stake,
    // uint32 unstakeDelaySec, uint48 withdrawTime) — all static 32-byte slots.
    if ret.len() < 160 {
        return Err(RpcError::internal("EntryPoint.getDepositInfo returned too few bytes"));
    }
    let staked = ret[63] != 0;
    let stake = U256::from_be_slice(&ret[64..96]);
    let unstake_delay = U256::from_be_slice(&ret[96..128]);
    Ok(json!({
        "stakeInfo": {
            "addr": format!("0x{}", hex::encode(addr.as_slice())),
            "stake": format!("0x{stake:x}"),
            "unstakeDelaySec": format!("0x{unstake_delay:x}"),
        },
        "isStaked": staked,
    }))
}

/// `debug_bundler_getStakeStatus(address[, entryPoint])` — the entity's stake in
/// the EntryPoint and whether it qualifies as staked.
pub fn debug_bundler_get_stake_status(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let bundler = require_bundler(s)?;
    let addr = parse_addr_evm(
        p.get(0)
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("missing address (params[0])"))?,
    )?;
    let entry_point = match p.get(1).and_then(Value::as_str) {
        Some(ep) => parse_addr_evm(ep)?,
        None => *bundler
            .entry_points
            .first()
            .ok_or_else(|| RpcError::internal("bundler has no configured EntryPoint"))?,
    };
    if !bundler.supports(&entry_point) {
        return Err(RpcError::invalid_params(
            "unsupported entryPoint (see eth_supportedEntryPoints)",
        ));
    }
    stake_status(s, bundler, entry_point, addr)
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
    let Some(tracked) = bundler.tracked.lock().ok().and_then(|t| t.get(&hash)) else {
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
    let Some(tracked) = bundler.tracked.lock().ok().and_then(|t| t.get(&hash)) else {
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

// Generous ceilings the gas binary-search starts from; each search narrows to
// the minimum value at which the op still simulates successfully.
const SIM_VERIFICATION_GAS: u64 = 3_000_000;
const SIM_CALL_GAS: u64 = 10_000_000;
/// The gas search stops once its window is this narrow and returns the upper
/// bound — caps each search at ~log2(ceiling / STEP) simulations.
const GAS_SEARCH_STEP: u64 = 1_000;

/// Smallest `x` in `[lo, hi]` for which `pred(x)` holds, assuming `pred` is
/// monotone (false below a threshold, true at/above it) and `pred(hi)` holds.
/// Narrows to within [`GAS_SEARCH_STEP`] and returns the known-good upper bound.
fn search_min_gas(mut lo: u64, mut hi: u64, pred: impl Fn(u64) -> bool) -> u64 {
    while hi - lo > GAS_SEARCH_STEP {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    hi
}

/// The `success` flag of the `UserOperationEvent` for `hash` among simulation
/// `logs` (the 2nd ABI word of the event data), or `None` if absent.
fn user_op_event_success(logs: &[VmLog], hash: &B256) -> Option<bool> {
    let sig = UserOperationEvent::SIGNATURE_HASH;
    for log in logs {
        if log.topics.len() < 2 || log.topics[0] != sig.0 || log.topics[1] != hash.0 {
            continue;
        }
        // data = abi(nonce, success, actualGasCost, actualGasUsed)
        if log.data.len() < 64 {
            return Some(false);
        }
        return Some(log.data[63] != 0);
    }
    None
}

/// `eth_estimateUserOperationGas(userOp, entryPoint)` — estimate the op's gas
/// fields by binary-searching each limit against `handleOps` simulations: the
/// smallest `verificationGasLimit` (and `paymasterVerificationGasLimit`) at
/// which the bundle doesn't revert, and the smallest `callGasLimit` at which the
/// op's `UserOperationEvent` reports success. `preVerificationGas` is the
/// calldata-size overhead. A small safety margin is added so a state shift
/// before inclusion can't push the real cost over the estimate.
pub fn eth_estimate_user_operation_gas(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
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
    let has_paymaster = op.paymaster.is_some();

    // userOpHash from the EntryPoint, to match this op's UserOperationEvent in
    // the simulation logs.
    let (hash_ret, _) = sim_call(
        s,
        bundler.bundler_address.to_vec(),
        entry_point,
        getUserOpHashCall { userOp: op.pack() }.abi_encode(),
    )?;
    if hash_ret.len() < 32 {
        return Err(RpcError::internal("EntryPoint.getUserOpHash returned < 32 bytes"));
    }
    let user_op_hash = B256::from_slice(&hash_ret[..32]);

    // One handleOps simulation of `op` with the given gas limits (paymaster
    // post-op kept generous; preVerificationGas left as the caller set it).
    let sim_with = |vgl: u64, cgl: u64, pm_vgl: u64| -> SimResult {
        let mut o = op.clone();
        o.verification_gas_limit = U256::from(vgl);
        o.call_gas_limit = U256::from(cgl);
        if has_paymaster {
            o.paymaster_verification_gas_limit = U256::from(pm_vgl);
            o.paymaster_post_op_gas_limit = U256::from(SIM_VERIFICATION_GAS);
        }
        let data =
            handleOpsCall { ops: vec![o.pack()], beneficiary: bundler.beneficiary }.abi_encode();
        sim_call_outcome(s, bundler.bundler_address.to_vec(), entry_point, data)
    };
    let not_reverted = |r: &SimResult| matches!(r, SimResult::Ok { .. });
    let executed_ok = |r: &SimResult| {
        matches!(r, SimResult::Ok { logs, .. } if user_op_event_success(logs, &user_op_hash) == Some(true))
    };

    // Probe at generous limits: a revert means validation fails outright (bad
    // signature / nonce / prefund) — surface why; a non-success at generous gas
    // means execution reverts for a non-gas reason. Either way, can't estimate.
    let probe = sim_with(SIM_VERIFICATION_GAS, SIM_CALL_GAS, SIM_VERIFICATION_GAS);
    match &probe {
        SimResult::Revert(data) => {
            let reason =
                decode_failed_op(data).unwrap_or_else(|| format!("0x{}", hex::encode(data)));
            return Err(RpcError::invalid_request(reason));
        }
        SimResult::Failed(e) => return Err(RpcError::internal(e.message.clone())),
        SimResult::Ok { logs, .. } => {
            if user_op_event_success(logs, &user_op_hash) != Some(true) {
                return Err(RpcError::invalid_request(
                    "UserOperation execution reverts even at generous gas — not a gas-limit issue",
                ));
            }
        }
    }

    // verificationGasLimit: least account-verification gas the bundle tolerates.
    let verification_gas = search_min_gas(0, SIM_VERIFICATION_GAS, |v| {
        not_reverted(&sim_with(v, SIM_CALL_GAS, SIM_VERIFICATION_GAS))
    });
    // paymasterVerificationGasLimit, when a paymaster is set.
    let pm_verification_gas = if has_paymaster {
        search_min_gas(0, SIM_VERIFICATION_GAS, |pv| {
            not_reverted(&sim_with(verification_gas, SIM_CALL_GAS, pv))
        })
    } else {
        0
    };
    // callGasLimit: least execution gas at which the op succeeds, holding the
    // verification limits found above.
    let call_gas = search_min_gas(0, SIM_CALL_GAS, |c| {
        executed_ok(&sim_with(verification_gas, c, pm_verification_gas))
    });

    // +12.5% margin against pre-inclusion state drift.
    let pad = |g: u64| g + g / 8;
    let packed_len = handleOpsCall { ops: vec![op.pack()], beneficiary: bundler.beneficiary }
        .abi_encode()
        .len() as u64;
    let pre_verification = 21_000u64 + packed_len * 8;
    // postOp: honour the op's own limit when set, else a conservative floor (the
    // EntryPoint requires a non-zero postOp budget whenever a paymaster is used).
    let pm_post = if has_paymaster {
        (u256_to_usize(op.paymaster_post_op_gas_limit).unwrap_or(0) as u64).max(40_000)
    } else {
        0
    };

    Ok(json!({
        "preVerificationGas": format!("0x{pre_verification:x}"),
        "verificationGasLimit": format!("0x{:x}", pad(verification_gas)),
        "callGasLimit": format!("0x{:x}", pad(call_gas)),
        "paymasterVerificationGasLimit": format!("0x{:x}", pad(pm_verification_gas)),
        "paymasterPostOpGasLimit": format!("0x{pm_post:x}"),
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
    fn from_config_parses_and_validates() {
        let st = BundlerState::from_config(
            &["0xabababababababababababababababababababab".to_string()],
            [9u8; 32],
            [0x41u8; 21],
            None,
            1000,
        )
        .unwrap();
        assert_eq!(st.entry_points.len(), 1);
        // beneficiary defaults to the bundler's own 20-byte address
        assert_eq!(st.beneficiary, Address::from_slice(&[0x41u8; 21][1..]));
        // empty entry_points and bad addresses are rejected
        assert!(BundlerState::from_config(&[], [0u8; 32], [0x41u8; 21], None, 0).is_err());
        assert!(BundlerState::from_config(
            &["nothex".to_string()],
            [0u8; 32],
            [0x41u8; 21],
            None,
            0
        )
        .is_err());
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
        // estimate shares the same gating
        assert!(eth_estimate_user_operation_gas(&p, &base())
            .unwrap_err()
            .message
            .contains("bundler not enabled"));
        assert!(eth_estimate_user_operation_gas(&p, &s)
            .unwrap_err()
            .message
            .contains("unsupported entryPoint"));
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

    #[test]
    fn tracked_ops_bounded_fifo_eviction() {
        let mut t = TrackedOps::default();
        let op = |b: u8| TrackedUserOp {
            user_op: sample(None, None),
            entry_point: Address::repeat_byte(b),
            tx_id: None,
        };
        let h = |i: u64| B256::from(U256::from(i).to_be_bytes::<32>());
        // Overflow the cap by a few entries.
        for i in 0..(MAX_TRACKED as u64 + 5) {
            t.insert(h(i), op(0x11));
        }
        assert_eq!(t.len(), MAX_TRACKED, "map stays bounded at the cap");
        assert!(t.get(&h(0)).is_none(), "oldest entries evicted (FIFO)");
        assert!(t.get(&h(MAX_TRACKED as u64 + 4)).is_some(), "newest retained");
        // Re-inserting an existing hash updates in place without growing/reordering.
        let len_before = t.len();
        t.insert(h(MAX_TRACKED as u64 + 4), op(0x22));
        assert_eq!(t.len(), len_before, "re-insert of a tracked hash is in-place");
        assert_eq!(
            t.get(&h(MAX_TRACKED as u64 + 4)).unwrap().entry_point,
            Address::repeat_byte(0x22),
            "re-insert overwrites the value"
        );
    }

    #[test]
    fn bundling_mode_parse_and_default() {
        assert_eq!(BundlingMode::parse("auto"), Some(BundlingMode::Auto));
        assert_eq!(BundlingMode::parse("MANUAL"), Some(BundlingMode::Manual));
        assert_eq!(BundlingMode::parse("  Manual "), Some(BundlingMode::Manual));
        assert_eq!(BundlingMode::parse("nope"), None);
        assert_eq!(BundlingMode::default(), BundlingMode::Auto);
        assert_eq!(BundlingMode::Manual.as_str(), "manual");
    }

    #[test]
    fn with_bundling_configures_state() {
        let st = BundlerState::new(
            vec![Address::repeat_byte(1)],
            [0u8; 32],
            [0x41u8; 21],
            Address::repeat_byte(2),
            1,
        )
        .with_bundling(BundlingMode::Manual, 7, Duration::from_millis(500));
        assert_eq!(st.mode(), BundlingMode::Manual);
        assert_eq!(st.max_bundle_size, 7);
        assert_eq!(st.bundle_interval, Duration::from_millis(500));
        // max_bundle_size floors at 1 so a bundle can always make progress
        let st2 = BundlerState::new(vec![], [0u8; 32], [0x41u8; 21], Address::repeat_byte(2), 1)
            .with_bundling(BundlingMode::Auto, 0, Duration::from_millis(1));
        assert_eq!(st2.max_bundle_size, 1);
    }

    #[test]
    fn failed_op_index_and_u256() {
        let enc = FailedOp { opIndex: U256::from(3u64), reason: "x".into() }.abi_encode();
        assert_eq!(failed_op_index(&enc), Some(3));
        assert_eq!(failed_op_index(&[0x00]), None);
        assert_eq!(u256_to_usize(U256::from(42u64)), Some(42));
        assert_eq!(u256_to_usize(U256::MAX), None);
    }

    fn enabled_state() -> (std::sync::Arc<BundlerState>, RpcState) {
        use std::sync::Arc;
        use tron_chainbase::{KvBackend, MemBackend};
        let mem = || Arc::new(MemBackend::new()) as Arc<dyn KvBackend>;
        let bundler = Arc::new(BundlerState::new(
            vec![Address::repeat_byte(0x11)],
            [7u8; 32],
            [0x41u8; 21],
            Address::repeat_byte(0xcc),
            1_000_000_000,
        ));
        let s = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111).with_bundler(bundler.clone());
        (bundler, s)
    }

    fn pending(ep: u8, h: u8) -> PendingUserOp {
        PendingUserOp {
            user_op: sample(None, None),
            entry_point: Address::repeat_byte(ep),
            user_op_hash: B256::repeat_byte(h),
        }
    }

    #[test]
    fn debug_bundler_dump_clear_and_mode() {
        let (bundler, s) = enabled_state();
        bundler.mempool.lock().unwrap().extend([pending(0x11, 1), pending(0x11, 2)]);
        // dumpMempool (no filter) returns both pending ops
        assert_eq!(debug_bundler_dump_mempool(&json!([]), &s).unwrap().as_array().unwrap().len(), 2);
        // filtered to a different EntryPoint -> none
        let other = json!(["0x9999999999999999999999999999999999999999"]);
        assert_eq!(debug_bundler_dump_mempool(&other, &s).unwrap().as_array().unwrap().len(), 0);
        // setBundlingMode flips the runtime mode
        assert_eq!(debug_bundler_set_bundling_mode(&json!(["manual"]), &s).unwrap(), json!("manual"));
        assert_eq!(bundler.mode(), BundlingMode::Manual);
        assert!(debug_bundler_set_bundling_mode(&json!(["bogus"]), &s).is_err());
        // clearMempool empties it
        debug_bundler_clear_mempool(&s).unwrap();
        assert!(bundler.mempool.lock().unwrap().is_empty());
        // all debug methods gate on the bundler being enabled
        use std::sync::Arc;
        use tron_chainbase::{KvBackend, MemBackend};
        let mem = || Arc::new(MemBackend::new()) as Arc<dyn KvBackend>;
        let bare = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
        assert!(debug_bundler_send_bundle_now(&bare).is_err());
        assert!(debug_bundler_dump_mempool(&json!([]), &bare).is_err());
        assert!(debug_bundler_clear_state(&bare).is_err());
    }

    #[test]
    fn send_bundle_now_drains_and_reports() {
        let (bundler, s) = enabled_state();
        // Empty mempool -> empty result, no work.
        assert_eq!(debug_bundler_send_bundle_now(&s).unwrap().as_array().unwrap().len(), 0);
        // One pending op: with no EVM backends attached the bundle sim fails, so
        // the op is dropped (reported) and the mempool drained — exercises the
        // drain + drop path without a deployed EntryPoint.
        bundler.mempool.lock().unwrap().push(pending(0x11, 9));
        let res = debug_bundler_send_bundle_now(&s).unwrap();
        let arr = res.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(arr[0]["transactionHash"].is_null());
        assert_eq!(arr[0]["dropped"].as_array().unwrap().len(), 1);
        assert!(bundler.mempool.lock().unwrap().is_empty(), "mempool drained");
    }

    #[test]
    fn search_min_gas_finds_threshold() {
        // pred turns true at/above 50_000; result is the upper bound within STEP.
        let r = search_min_gas(0, 10_000_000, |x| x >= 50_000);
        assert!(r >= 50_000 && r <= 50_000 + GAS_SEARCH_STEP, "got {r}");
        // true everywhere -> converges at the low end
        assert!(search_min_gas(0, 1_000_000, |_| true) <= GAS_SEARCH_STEP);
    }

    #[test]
    fn user_op_event_success_decodes() {
        let hash = B256::repeat_byte(0xab);
        let sig = UserOperationEvent::SIGNATURE_HASH;
        // data = nonce(32) ++ success(32) ++ cost(32) ++ used(32)
        let mut ok_data = vec![0u8; 128];
        ok_data[63] = 1; // success word, low byte
        let ok = VmLog {
            address: [0u8; 20],
            topics: vec![sig.0, hash.0, [0u8; 32], [0u8; 32]],
            data: ok_data,
        };
        assert_eq!(user_op_event_success(&[ok], &hash), Some(true));
        // success word zero -> false
        let failed = VmLog { address: [0u8; 20], topics: vec![sig.0, hash.0], data: vec![0u8; 128] };
        assert_eq!(user_op_event_success(&[failed], &hash), Some(false));
        // different userOpHash in topic[1] -> not this op's event
        let other = VmLog {
            address: [0u8; 20],
            topics: vec![sig.0, B256::repeat_byte(1).0],
            data: vec![0u8; 128],
        };
        assert_eq!(user_op_event_success(&[other], &hash), None);
        // no logs at all -> None
        assert_eq!(user_op_event_success(&[], &hash), None);
    }

    #[test]
    fn reputation_status_thresholds() {
        let st = |seen, incl| ReputationEntry { ops_seen: seen, ops_included: incl }.status();
        // warm-up slack: <= THROTTLING_SLACK seen is always OK
        assert_eq!(st(10, 0), ReputationStatus::Ok);
        assert_eq!(st(100, 0), ReputationStatus::Ok); // min_expected 10 <= 0+10
        // 1000 seen -> min_expected 100
        assert_eq!(st(1000, 90), ReputationStatus::Ok); // 100 <= 90+10
        assert_eq!(st(1000, 50), ReputationStatus::Throttled); // 100 <= 50+50, not 50+10
        assert_eq!(st(1000, 49), ReputationStatus::Banned); // 100 > 49+50
    }

    #[test]
    fn reputation_manager_counts_and_resets() {
        let mut m = ReputationManager::default();
        let a = Address::repeat_byte(1);
        assert_eq!(m.status(&a), ReputationStatus::Ok); // unknown entity -> OK
        for _ in 0..1000 {
            m.bump_seen(a);
        }
        for _ in 0..40 {
            m.bump_included(a);
        }
        assert_eq!(m.status(&a), ReputationStatus::Banned);
        m.set(a, 0, 0);
        assert_eq!(m.status(&a), ReputationStatus::Ok);
    }

    #[test]
    fn op_entities_collects_account_factory_paymaster() {
        let mut op = sample(Some(Address::repeat_byte(2)), Some(Address::repeat_byte(3)));
        op.sender = Address::repeat_byte(1);
        assert_eq!(
            op_entities(&op),
            vec![Address::repeat_byte(1), Address::repeat_byte(2), Address::repeat_byte(3)]
        );
        assert_eq!(op_entities(&sample(None, None)), vec![Address::repeat_byte(0x11)]);
    }

    #[test]
    fn debug_bundler_reputation_methods() {
        let (_bundler, s) = enabled_state();
        let a = "0x1111111111111111111111111111111111111111";
        // setReputation([{address, opsSeen, opsIncluded}], entryPoint)
        let set = json!([[{ "address": a, "opsSeen": 1000, "opsIncluded": 40 }], "0x00"]);
        debug_bundler_set_reputation(&set, &s).unwrap();
        // dumpReputation reflects counts + derived status
        let dump = debug_bundler_dump_reputation(&json!([]), &s).unwrap();
        let arr = dump.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["opsSeen"].as_u64(), Some(1000));
        assert_eq!(arr[0]["status"], "banned");
        // clearReputation empties the table
        debug_bundler_clear_reputation(&s).unwrap();
        assert_eq!(debug_bundler_dump_reputation(&json!([]), &s).unwrap().as_array().unwrap().len(), 0);
        // gates on the bundler being enabled
        use std::sync::Arc;
        use tron_chainbase::{KvBackend, MemBackend};
        let mem = || Arc::new(MemBackend::new()) as Arc<dyn KvBackend>;
        let bare = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
        assert!(debug_bundler_dump_reputation(&json!([]), &bare).is_err());
        assert!(debug_bundler_get_stake_status(&json!([a]), &bare).is_err());
    }
}
