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
use alloy_sol_types::sol;
use serde_json::{json, Value};

use crate::methods::RpcError;
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
    pub entry_point: Address,
    pub sender: Address,
    pub nonce: U256,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

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
}
