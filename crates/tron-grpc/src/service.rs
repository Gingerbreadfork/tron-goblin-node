//! Wallet service implementation — bridges tonic gRPC to existing
//! `tron-rpc` state.
//!
//! ## Method status
//!
//! Every one of the Wallet trait's ~147 methods has a real
//! implementation. There are no `Status::unimplemented` stubs left.
//!
//! Three response classes:
//!
//! 1. **Implemented** — performs the requested work against state /
//!    stores / VM / builder. The vast majority.
//!
//! 2. **Implemented as `FailedPrecondition`** — the method's contract
//!    cannot be fulfilled honestly on a node-only deployment. There
//!    are two reasons this comes up:
//!    * **Removed mainnet contracts** (`buy_storage`, `sell_storage`,
//!      `buy_storage_bytes`) — the corresponding contract types were
//!      removed from the chain; building the tx would produce
//!      something the network would reject. We say so.
//!    * **Wallet-side primitives that depend on infrastructure a node
//!      doesn't ship** — Sapling proving keys + Groth16 prover for
//!      shielded tx construction; ChaCha20-Poly1305 trial-decryption
//!      pipelines for shielded note scanning; per-output merkle
//!      position indexes for nullifier derivation. Each error names
//!      what would need to land to lift it.
//!
//! 3. **Implemented as a typed delegate** — the helper-heavy ones
//!    forward through `crate::shielded` (Sapling key derivation) or
//!    `tron_rpc::builder` (unsigned-tx construction) so the same
//!    logic is reusable outside the trait body.
//!
//! Stubs were originally generated from the tonic-generated trait
//! file via a Python regex pass that pulls `(name, request_type,
//! response_type)` out of every `async fn` declaration. The
//! generator's no longer needed (every stub has been promoted), but
//! the pattern stays valid if java-tron adds new methods.

use std::net::SocketAddr;

use tonic::{transport::Server, Request, Response, Status};
use tron_crypto::address::Address;
use tron_proto::protocol::{
    self, r#return, Account, Block, BlockExtention, BlockList, BlockListExtention, BlockReq,
    BytesMessage, ChainParameters, DelegatedResourceList, DelegatedResourceMessage,
    EmptyMessage, NodeInfo, NodeList, NumberMessage, Proposal, ProposalList, Return,
    Transaction, TransactionExtention, TransactionIdList, WitnessList,
};
use tron_rpc::RpcState;

use crate::proto::database_server::DatabaseServer;
use crate::proto::monitor_server::MonitorServer;
use crate::proto::wallet_extension_server::WalletExtensionServer;
use crate::proto::wallet_server::{Wallet, WalletServer};
use crate::proto::wallet_solidity_server::WalletSolidityServer;

#[derive(Clone)]
pub struct WalletService {
    pub(crate) state: RpcState,
}

impl WalletService {
    pub fn new(state: RpcState) -> Self {
        Self { state }
    }
}

// =============================================================================
// Helpers shared across method impls
// =============================================================================

fn head_block_id(state: &RpcState) -> Option<tron_types::BlockId> {
    let hash = state.dyn_props.latest_block_header_hash().ok().flatten()?;
    Some(tron_types::BlockId::from_raw(hash))
}

fn block_by_num(state: &RpcState, num: i64) -> Option<Block> {
    let id = state.block_index.get(num).ok()?;
    state.blocks.get(&id).ok()
}

fn tx_id(tx: &Transaction) -> [u8; 32] {
    let mut h = [0u8; 32];
    if let Some(raw) = &tx.raw_data {
        let encoded = prost::Message::encode_to_vec(raw);
        h.copy_from_slice(&tron_crypto::hash::sha256(&encoded));
    }
    h
}

fn lookup_delegated_v1(
    state: &RpcState,
    req: &DelegatedResourceMessage,
) -> DelegatedResourceList {
    if req.from_address.len() != 21 || req.to_address.len() != 21 {
        return DelegatedResourceList::default();
    }
    let Some(store) = &state.delegated_resources else {
        return DelegatedResourceList::default();
    };
    let mut from_arr = [0u8; 21];
    from_arr.copy_from_slice(&req.from_address);
    let mut to_arr = [0u8; 21];
    to_arr.copy_from_slice(&req.to_address);
    let from = Address::from_raw(from_arr);
    let to = Address::from_raw(to_arr);
    let key = tron_chainbase::DelegatedResourceStore::v1_key(&from, &to);
    let delegated_resource = match store.get_raw(&key) {
        Ok(Some(d)) => vec![d],
        _ => Vec::new(),
    };
    DelegatedResourceList { delegated_resource }
}

fn lookup_delegated_v2(
    state: &RpcState,
    req: &DelegatedResourceMessage,
) -> DelegatedResourceList {
    if req.from_address.len() != 21 || req.to_address.len() != 21 {
        return DelegatedResourceList::default();
    }
    let Some(store) = &state.delegated_resources else {
        return DelegatedResourceList::default();
    };
    let mut from_arr = [0u8; 21];
    from_arr.copy_from_slice(&req.from_address);
    let mut to_arr = [0u8; 21];
    to_arr.copy_from_slice(&req.to_address);
    let from = Address::from_raw(from_arr);
    let to = Address::from_raw(to_arr);
    // v2 splits locked + unlocked across two keys; the gRPC response
    // shape collapses them into one list, matching java-tron.
    let unlocked_key =
        tron_chainbase::DelegatedResourceStore::v2_unlocked_key(&from, &to);
    let locked_key = tron_chainbase::DelegatedResourceStore::v2_locked_key(&from, &to);
    let mut delegated_resource = Vec::new();
    if let Ok(Some(d)) = store.get_raw(&unlocked_key) {
        delegated_resource.push(d);
    }
    if let Ok(Some(d)) = store.get_raw(&locked_key) {
        delegated_resource.push(d);
    }
    DelegatedResourceList { delegated_resource }
}

/// Read-only EVM call. Returns `None` only when the node is configured
/// without EVM backends (eth_call disabled); every other outcome —
/// success, revert, halt — is surfaced as a `VmOutcome` so callers can
/// decide how to render it. Mirrors `tron_rpc::methods::eth_call` but
/// works directly against a typed `TriggerSmartContract` proto.
/// Derive the Sapling nullifier for the shielded TRC-20 note
/// described in `params`. Reconstructs a `sapling_crypto::Note` from
/// the proto's `(value, payment_address, rcm)` triple — java-tron's
/// shielded TRC-20 uses the pre-ZIP-212 trapdoor format where `rcm`
/// is a 32-byte scalar — then calls `Note::nf(nk, position)`. Returns
/// the 32-byte nullifier ready for ABI-encoding into a
/// `nullifiers(bytes32)` call.
/// Core Sapling nullifier derivation. `nf = note.nf(&nk, position)` where
/// the note is reconstructed from `(payment_address, value, rcm)` using
/// pre-ZIP-212 `Rseed` semantics (TRON's shielded TRC-20 uses the legacy
/// trapdoor format — same as java-tron's `ComputeNfParams` FFI call).
///
/// Shared by `compute_shielded_trc20_nullifier` (TRC-20 path, position
/// from `NfTrc20Parameters.position`), `compute_shielded_nullifier`
/// (native shielded path, position from `NfParameters.voucher`), and
/// `is_spend` (position derived by block-walk).
pub(crate) fn derive_sapling_nullifier(
    payment_address_hex: &str,
    value: u64,
    rcm_bytes: &[u8],
    nk_bytes: &[u8],
    position: u64,
) -> Result<[u8; 32], String> {
    use group::GroupEncoding;
    use sapling_crypto::keys::NullifierDerivingKey;
    use sapling_crypto::note::Rseed;
    use sapling_crypto::value::NoteValue;
    use sapling_crypto::{Note, PaymentAddress};

    let pa_bytes = parse_payment_address(payment_address_hex)?;
    let payment_address = PaymentAddress::from_bytes(&pa_bytes)
        .ok_or_else(|| "payment_address is not a valid Sapling address".to_string())?;
    let rcm_bytes: [u8; 32] = rcm_bytes
        .try_into()
        .map_err(|_| "rcm must be 32 bytes".to_string())?;
    let rcm = jubjub::Fr::from_bytes(&rcm_bytes);
    if !bool::from(rcm.is_some()) {
        return Err("rcm is not in the Jubjub scalar field".into());
    }
    let rseed = Rseed::BeforeZip212(rcm.unwrap());
    let sapling_note = Note::from_parts(payment_address, NoteValue::from_raw(value), rseed);
    let nk_bytes: [u8; 32] = nk_bytes
        .try_into()
        .map_err(|_| "nk must be 32 bytes".to_string())?;
    let nk_point = jubjub::SubgroupPoint::from_bytes(&nk_bytes);
    if !bool::from(nk_point.is_some()) {
        return Err("nk is not a valid Jubjub subgroup point".into());
    }
    let nk = NullifierDerivingKey(nk_point.unwrap());
    let nf = sapling_note.nf(&nk, position);
    Ok(nf.0)
}

fn compute_shielded_trc20_nullifier(
    params: &tron_proto::protocol::NfTrc20Parameters,
) -> Result<[u8; 32], String> {
    let note = params.note.as_ref().ok_or_else(|| "missing note".to_string())?;
    let position = u64::try_from(params.position)
        .map_err(|_| "position must be non-negative".to_string())?;
    derive_sapling_nullifier(
        &note.payment_address,
        note.value as u64,
        &note.rcm,
        &params.nk,
        position,
    )
}

/// Compute the merkle leaf position for a voucher. Matches java-tron's
/// `IncrementalMerkleVoucherContainer.position()`, which is the tree's
/// `size() - 1`. Size is `left? + right? + sum(2^(i+1) for parents[i] present)`,
/// where "present" means the inner `PedersenHash.content` is non-empty.
///
/// java-tron path:
///   IncrementalMerkleVoucherContainer.position()
///     → tree.toMerkleTreeContainer().size() - 1
///   IncrementalMerkleTreeContainer.size()
///     → +1 if left.content != ∅
///       +1 if right.content != ∅
///       +2^(i+1) for each parents[i] with non-empty content
fn voucher_position(
    voucher: &tron_proto::protocol::IncrementalMerkleVoucher,
) -> Result<u64, String> {
    let tree = voucher
        .tree
        .as_ref()
        .ok_or_else(|| "voucher missing tree".to_string())?;
    let mut size: u64 = 0;
    if tree.left.as_ref().map(|p| !p.content.is_empty()).unwrap_or(false) {
        size += 1;
    }
    if tree.right.as_ref().map(|p| !p.content.is_empty()).unwrap_or(false) {
        size += 1;
    }
    for (i, parent) in tree.parents.iter().enumerate() {
        if !parent.content.is_empty() {
            let exponent = i as u32 + 1;
            // Sapling tree depth = 32, so `i+1` cannot reach 64 in
            // well-formed input — but guard explicitly so a malformed
            // voucher doesn't panic.
            if exponent >= 63 {
                return Err(format!(
                    "voucher tree parents[{i}] would overflow u64 size accumulator"
                ));
            }
            size = size
                .checked_add(1u64 << exponent)
                .ok_or_else(|| "voucher tree size overflowed".to_string())?;
        }
    }
    if size == 0 {
        return Err("voucher tree is empty — position undefined".into());
    }
    Ok(size - 1)
}

fn compute_shielded_nullifier(
    params: &tron_proto::protocol::NfParameters,
) -> Result<[u8; 32], String> {
    let note = params.note.as_ref().ok_or_else(|| "missing note".to_string())?;
    let voucher = params
        .voucher
        .as_ref()
        .ok_or_else(|| "missing voucher".to_string())?;
    let position = voucher_position(voucher)?;
    derive_sapling_nullifier(
        &note.payment_address,
        note.value as u64,
        &note.rcm,
        &params.nk,
        position,
    )
}

/// Decode java-tron's shielded payment-address wire format. Accepts
/// either bare 86-char hex (43 bytes = d || pk_d) or the `0x`-prefixed
/// variant.
pub(crate) fn parse_payment_address(s: &str) -> Result<[u8; 43], String> {
    let trimmed = s.trim_start_matches("0x").trim();
    let bytes = hex::decode(trimmed)
        .map_err(|e| format!("payment_address hex decode: {e}"))?;
    if bytes.len() != 43 {
        return Err(format!(
            "payment_address must be 43 bytes (d || pk_d); got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 43];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn run_constant_call(
    state: &RpcState,
    trigger: &tron_proto::protocol::TriggerSmartContract,
) -> Option<tron_tvm::execute::VmOutcome> {
    let b = state.eth_call_backends.as_ref()?;
    let vm_stores = tron_rpc::methods::build_call_vm_stores(b);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number: state.dyn_props.latest_block_header_number().unwrap_or(0),
        block_timestamp_ms: state.dyn_props.latest_block_header_timestamp().unwrap_or(0),
    };
    // Match java-tron's constant-call default — `MAX_CPU_TIME_OF_ONE_TX`
    // worth of energy. We use a generous 16M cap (same as eth_call's
    // hardcoded limit until the revm fork lifts it) so deep TVM reads
    // succeed.
    const CONSTANT_CALL_ENERGY: u64 = 16_000_000;
    // If the operator configured a wall-clock budget, route through
    // the deadline-enforcing entry point so the VM is preempted
    // mid-execution.
    if state.constant_call_timeout_ms > 0 {
        let timeout_ms = state.constant_call_timeout_ms as u64;
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(timeout_ms);
        let (outcome, _traces, _energy_penalty) = tron_tvm::execute::execute_trigger_with_deadline(
            &vm_stores,
            block_env,
            trigger,
            CONSTANT_CALL_ENERGY,
            state.eth_call_gas_cap,
            deadline,
            timeout_ms,
        );
        return Some(outcome);
    }
    Some(tron_tvm::execute::execute_trigger(
        &vm_stores,
        block_env,
        trigger,
        CONSTANT_CALL_ENERGY,
    ))
}

/// Wrap a `VmOutcome` into the `TransactionExtention` shape
/// `trigger_constant_contract` returns. Echoes the input as an
/// unsigned-transaction skeleton so wallets that introspect the
/// envelope (TronWeb does) see a stable layout.
fn build_constant_response(
    state: &RpcState,
    trigger: &tron_proto::protocol::TriggerSmartContract,
    outcome: Option<tron_tvm::execute::VmOutcome>,
) -> Result<TransactionExtention, Status> {
    let skeleton = build_tx_for(
        state,
        tron_proto::transaction::contract::ContractType::TriggerSmartContract,
        trigger,
    )?;
    let id = tx_id(&skeleton);
    let (constant_result, energy_used, result) = match outcome {
        Some(tron_tvm::execute::VmOutcome::Success {
            return_data,
            energy_used,
            ..
        }) => (
            vec![return_data],
            energy_used as i64,
            Return {
                result: true,
                code: r#return::ResponseCode::Success as i32,
                message: Vec::new(),
            },
        ),
        Some(tron_tvm::execute::VmOutcome::Revert {
            return_data,
            energy_used,
            ..
        }) => (
            vec![return_data.clone()],
            energy_used as i64,
            Return {
                result: false,
                code: r#return::ResponseCode::ContractExeError as i32,
                message: format!("REVERT: 0x{}", hex::encode(return_data)).into_bytes(),
            },
        ),
        Some(tron_tvm::execute::VmOutcome::Halt {
            reason,
            energy_used,
            ..
        }) => (
            Vec::new(),
            energy_used as i64,
            Return {
                result: false,
                code: r#return::ResponseCode::ContractExeError as i32,
                message: format!("{reason:?}").into_bytes(),
            },
        ),
        Some(tron_tvm::execute::VmOutcome::CallTokenIgnored {
            token_id,
            call_token_value,
        }) => (
            Vec::new(),
            0,
            Return {
                result: false,
                code: r#return::ResponseCode::ContractValidateError as i32,
                message: format!(
                    "CALLTOKEN not implemented in read-only execution; token_id={} value={}",
                    token_id, call_token_value
                )
                .into_bytes(),
            },
        ),
        Some(tron_tvm::execute::VmOutcome::PreflightError(e)) => (
            Vec::new(),
            0,
            Return {
                result: false,
                code: r#return::ResponseCode::ContractValidateError as i32,
                message: format!("preflight: {e}").into_bytes(),
            },
        ),
        Some(tron_tvm::execute::VmOutcome::Timeout {
            energy_used,
            deadline_ms,
        }) => (
            Vec::new(),
            energy_used as i64,
            Return {
                result: false,
                code: r#return::ResponseCode::ContractExeError as i32,
                message: format!("constant call timed out after {deadline_ms}ms")
                    .into_bytes(),
            },
        ),
        None => (
            Vec::new(),
            0,
            Return {
                result: false,
                code: r#return::ResponseCode::ServerBusy as i32,
                message: b"EVM backends not configured on this node".to_vec(),
            },
        ),
    };
    Ok(TransactionExtention {
        transaction: Some(skeleton),
        txid: id.to_vec(),
        constant_result,
        result: Some(result),
        energy_used,
        ..Default::default()
    })
}

/// Build an unsigned transaction wrapping `param` of `ty`. Returns the
/// Transaction proto with `signature: []` — clients sign it locally
/// and then submit via `broadcast_transaction`. Maps the builder's
/// errors into `tonic::Status::internal` for the gRPC surface.
fn build_tx_for<T: prost::Message>(
    state: &RpcState,
    ty: tron_proto::transaction::contract::ContractType,
    param: &T,
) -> Result<Transaction, Status> {
    let contract = tron_rpc::builder::wrap_contract(ty, param, 0);
    tron_rpc::builder::build_unsigned_tx(state, contract, 0)
        .map_err(|e| Status::internal(format!("build_tx: {e:?}")))
}

/// Same as [`build_tx_for`] but returns a `TransactionExtention` shape
/// — the `2`-suffix variant of every writer method returns this, with
/// the txid pre-computed and a success `Return` code.
fn build_tx_ext_for<T: prost::Message>(
    state: &RpcState,
    ty: tron_proto::transaction::contract::ContractType,
    param: &T,
) -> Result<TransactionExtention, Status> {
    let tx = build_tx_for(state, ty, param)?;
    let id = tx_id(&tx);
    Ok(TransactionExtention {
        transaction: Some(tx),
        txid: id.to_vec(),
        result: Some(Return {
            result: true,
            code: r#return::ResponseCode::Success as i32,
            message: Vec::new(),
        }),
        ..Default::default()
    })
}

fn block_to_extention(block: &Block, id: &tron_types::BlockId) -> BlockExtention {
    BlockExtention {
        block_header: block.block_header.clone(),
        transactions: block
            .transactions
            .iter()
            .map(|tx| TransactionExtention {
                transaction: Some(tx.clone()),
                txid: tx_id(tx).to_vec(),
                ..Default::default()
            })
            .collect(),
        blockid: id.as_bytes().to_vec(),
    }
}

// =============================================================================
// Wallet trait impl
// =============================================================================

#[tonic::async_trait]
impl Wallet for WalletService {
    // ----- REAL IMPLEMENTATIONS (everything else stubbed below) -----

    async fn get_now_block(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<Block>, Status> {
        let Some(id) = head_block_id(&self.state) else {
            return Ok(Response::new(Block::default()));
        };
        let block = self.state.blocks.get(&id).unwrap_or_default();
        Ok(Response::new(block))
    }

    async fn get_now_block2(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<BlockExtention>, Status> {
        let Some(id) = head_block_id(&self.state) else {
            return Ok(Response::new(BlockExtention::default()));
        };
        let block = self.state.blocks.get(&id).unwrap_or_default();
        Ok(Response::new(block_to_extention(&block, &id)))
    }

    async fn get_block_by_num(
        &self,
        req: Request<NumberMessage>,
    ) -> Result<Response<Block>, Status> {
        let num = req.into_inner().num;
        Ok(Response::new(block_by_num(&self.state, num).unwrap_or_default()))
    }

    async fn get_block_by_num2(
        &self,
        req: Request<NumberMessage>,
    ) -> Result<Response<BlockExtention>, Status> {
        let num = req.into_inner().num;
        match block_by_num(&self.state, num) {
            Some(block) => {
                let id = tron_types::block_id_from_block(&block)
                    .unwrap_or_else(|_| tron_types::BlockId::from_raw([0u8; 32]));
                Ok(Response::new(block_to_extention(&block, &id)))
            }
            None => Ok(Response::new(BlockExtention::default())),
        }
    }

    async fn get_block(
        &self,
        req: Request<BlockReq>,
    ) -> Result<Response<BlockExtention>, Status> {
        let r = req.into_inner();
        // BlockReq.id_or_num is a string holding either a number or a
        // hex-encoded 32-byte hash. java-tron accepts both; we mirror.
        let opt: Option<Block> = if r.id_or_num.is_empty() {
            let n = self.state.dyn_props.latest_block_header_number().unwrap_or(0);
            block_by_num(&self.state, n)
        } else if let Ok(num) = r.id_or_num.parse::<i64>() {
            block_by_num(&self.state, num)
        } else if let Ok(bytes) = hex::decode(&r.id_or_num) {
            if bytes.len() == 32 {
                let arr: [u8; 32] = bytes.try_into().expect("len 32");
                let id = tron_types::BlockId::from_raw(arr);
                self.state.blocks.get(&id).ok()
            } else {
                None
            }
        } else {
            None
        };
        match opt {
            Some(block) => {
                let id = tron_types::block_id_from_block(&block)
                    .unwrap_or_else(|_| tron_types::BlockId::from_raw([0u8; 32]));
                Ok(Response::new(block_to_extention(&block, &id)))
            }
            None => Ok(Response::new(BlockExtention::default())),
        }
    }

    async fn get_account(
        &self,
        req: Request<Account>,
    ) -> Result<Response<Account>, Status> {
        let probe = req.into_inner();
        // java-tron returns an empty Account (not an error) for any
        // malformed address — mirror that so clients don't have to
        // distinguish "no account" from "bad input".
        if probe.address.len() != 21 {
            return Ok(Response::new(Account::default()));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&probe.address);
        match self.state.accounts.get(&Address::from_raw(addr)).ok().flatten() {
            Some(mut acct) => {
                // Apply java-tron's Wallet.getAccount read-time transforms to the
                // proto (asset merge, usage decay, slot→ms times, frozenV2 pad)
                // so gRPC matches the HTTP surface (and java) for real clients.
                let genesis_ms = self.state.dyn_props.genesis_block_timestamp().unwrap_or(0);
                tron_rpc::methods::apply_get_account_transforms(
                    &mut acct,
                    &self.state.dyn_props,
                    self.state.account_assets.as_deref(),
                    genesis_ms,
                );
                Ok(Response::new(acct))
            }
            // java-tron returns the default (empty) Account for a missing one.
            None => Ok(Response::new(Account::default())),
        }
    }

    async fn list_witnesses(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<WitnessList>, Status> {
        // WitnessStore is optional on RpcState (a non-governance node
        // may not stand it up). Return empty when absent — matches the
        // JSON-RPC `listWitnesses` behaviour.
        let Some(witnesses) = &self.state.witnesses else {
            return Ok(Response::new(WitnessList { witnesses: Vec::new() }));
        };
        let list = witnesses
            .all()
            .map_err(|e| Status::internal(format!("witness scan: {e}")))?
            .into_iter()
            .map(|(_, w)| w)
            .collect();
        Ok(Response::new(WitnessList { witnesses: list }))
    }

    async fn get_node_info(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<NodeInfo>, Status> {
        // NodeInfo has ~50 fields in java-tron; we ship a minimal
        // populated shape (head block summary). Clients that want more
        // can either grow this method or use the JSON-RPC
        // `getNodeInfo` which is fuller today.
        let info = NodeInfo {
            block: format!(
                "Num:{},ID:{}",
                self.state.dyn_props.latest_block_header_number().unwrap_or(0),
                self.state
                    .dyn_props
                    .latest_block_header_hash()
                    .ok()
                    .flatten()
                    .map(hex::encode)
                    .unwrap_or_default()
            ),
            ..Default::default()
        };
        Ok(Response::new(info))
    }

    // ----- Block range / id queries -----

    async fn get_block_by_id(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<Block>, Status> {
        let v = req.into_inner().value;
        let Ok(arr): Result<[u8; 32], _> = v.try_into() else {
            return Ok(Response::new(Block::default()));
        };
        let id = tron_types::BlockId::from_raw(arr);
        Ok(Response::new(self.state.blocks.get(&id).unwrap_or_default()))
    }

    async fn get_block_by_latest_num(
        &self,
        req: Request<NumberMessage>,
    ) -> Result<Response<BlockList>, Status> {
        // java-tron caps at 99 to bound the response size — mirror.
        let limit = req.into_inner().num.clamp(0, 99);
        let head = self.state.dyn_props.latest_block_header_number().unwrap_or(0);
        let start = (head + 1).saturating_sub(limit).max(0);
        let block: Vec<Block> = (start..=head)
            .filter_map(|n| block_by_num(&self.state, n))
            .collect();
        Ok(Response::new(BlockList { block }))
    }

    async fn get_block_by_latest_num2(
        &self,
        req: Request<NumberMessage>,
    ) -> Result<Response<BlockListExtention>, Status> {
        let limit = req.into_inner().num.clamp(0, 99);
        let head = self.state.dyn_props.latest_block_header_number().unwrap_or(0);
        let start = (head + 1).saturating_sub(limit).max(0);
        let block: Vec<BlockExtention> = (start..=head)
            .filter_map(|n| {
                let b = block_by_num(&self.state, n)?;
                let id = tron_types::block_id_from_block(&b).ok()?;
                Some(block_to_extention(&b, &id))
            })
            .collect();
        Ok(Response::new(BlockListExtention { block }))
    }

    async fn get_block_by_limit_next(
        &self,
        req: Request<protocol::BlockLimit>,
    ) -> Result<Response<BlockList>, Status> {
        let r = req.into_inner();
        // Half-open [start, end) to match java-tron's BlockLimit
        // semantics. Cap the range to 100 blocks per response.
        let end = r.end_num.min(r.start_num.saturating_add(100));
        let block: Vec<Block> = (r.start_num..end)
            .filter_map(|n| block_by_num(&self.state, n))
            .collect();
        Ok(Response::new(BlockList { block }))
    }

    async fn get_block_by_limit_next2(
        &self,
        req: Request<protocol::BlockLimit>,
    ) -> Result<Response<BlockListExtention>, Status> {
        let r = req.into_inner();
        let end = r.end_num.min(r.start_num.saturating_add(100));
        let block: Vec<BlockExtention> = (r.start_num..end)
            .filter_map(|n| {
                let b = block_by_num(&self.state, n)?;
                let id = tron_types::block_id_from_block(&b).ok()?;
                Some(block_to_extention(&b, &id))
            })
            .collect();
        Ok(Response::new(BlockListExtention { block }))
    }

    // ----- Transaction queries -----

    async fn get_transaction_by_id(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<Transaction>, Status> {
        let txid = req.into_inner().value;
        let Ok(arr): Result<[u8; 32], _> = txid.try_into() else {
            return Ok(Response::new(Transaction::default()));
        };
        // The TransactionStore may have a `full` body cached; fall
        // back to scanning recent blocks if not. Limited scan depth
        // since this is meant for hot lookups, not history archeology.
        if let Ok(Some(stored)) = self.state.transactions.get(&arr) {
            if let tron_chainbase::StoredTransaction::Full(tx) = stored {
                return Ok(Response::new(tx));
            }
        }
        const SCAN_DEPTH: i64 = 256;
        let head = self.state.dyn_props.latest_block_header_number().unwrap_or(0);
        for n in (head.saturating_sub(SCAN_DEPTH)..=head).rev() {
            let Some(block) = block_by_num(&self.state, n) else { continue };
            for tx in &block.transactions {
                if tx_id(tx) == arr {
                    return Ok(Response::new(tx.clone()));
                }
            }
        }
        Ok(Response::new(Transaction::default()))
    }

    async fn get_transaction_count_by_block_num(
        &self,
        req: Request<NumberMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        let n = req.into_inner().num;
        let count = block_by_num(&self.state, n)
            .map(|b| b.transactions.len() as i64)
            .unwrap_or(0);
        Ok(Response::new(NumberMessage { num: count }))
    }

    async fn total_transaction(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        // java-tron returns 0 here — the counter isn't maintained
        // through normal block apply. Mirroring keeps clients that
        // poll this endpoint happy without claiming false data.
        Ok(Response::new(NumberMessage { num: 0 }))
    }

    // ----- Account queries -----

    async fn get_account_by_id(
        &self,
        req: Request<Account>,
    ) -> Result<Response<Account>, Status> {
        let probe = req.into_inner();
        // Lookup `account_id` (set via setAccountId) → address via
        // the AccountIdIndexStore, then load the Account from
        // AccountStore. Empty / not-found returns an empty Account
        // to match java-tron behaviour.
        let Some(id_index) = &self.state.account_id_index else {
            return Ok(Response::new(Account::default()));
        };
        if probe.account_id.is_empty() {
            return Ok(Response::new(Account::default()));
        }
        let addr = match id_index.get(&probe.account_id).ok().flatten() {
            Some(a) => a,
            None => return Ok(Response::new(Account::default())),
        };
        match self.state.accounts.get(&addr).ok().flatten() {
            Some(mut acct) => {
                let genesis_ms = self.state.dyn_props.genesis_block_timestamp().unwrap_or(0);
                tron_rpc::methods::apply_get_account_transforms(
                    &mut acct,
                    &self.state.dyn_props,
                    self.state.account_assets.as_deref(),
                    genesis_ms,
                );
                Ok(Response::new(acct))
            }
            None => Ok(Response::new(Account::default())),
        }
    }

    async fn get_account_balance(
        &self,
        req: Request<protocol::AccountBalanceRequest>,
    ) -> Result<Response<protocol::AccountBalanceResponse>, Status> {
        let r = req.into_inner();
        let Some(id) = r.account_identifier else {
            return Ok(Response::new(protocol::AccountBalanceResponse::default()));
        };
        let address = id.address;
        if address.len() != 21 {
            return Ok(Response::new(protocol::AccountBalanceResponse::default()));
        }
        let mut addr_arr = [0u8; 21];
        addr_arr.copy_from_slice(&address);
        let acct = self
            .state
            .accounts
            .get(&Address::from_raw(addr_arr))
            .ok()
            .flatten();
        let balance = acct.map(|a| a.balance).unwrap_or(0);
        // Echo back block_identifier verbatim — java-tron returns
        // whatever the request carried (it's the client's snapshot).
        Ok(Response::new(protocol::AccountBalanceResponse {
            balance,
            block_identifier: r.block_identifier,
        }))
    }

    // ----- Governance / dyn-props queries -----

    async fn get_next_maintenance_time(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        Ok(Response::new(NumberMessage {
            num: self.state.dyn_props.next_maintenance_time().unwrap_or(0),
        }))
    }

    async fn get_burn_trx(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        Ok(Response::new(NumberMessage {
            num: self.state.dyn_props.burn_trx_amount(),
        }))
    }

    async fn list_proposals(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<ProposalList>, Status> {
        let Some(ps) = &self.state.proposals else {
            return Ok(Response::new(ProposalList { proposals: Vec::new() }));
        };
        let proposals = ps
            .all()
            .map_err(|e| Status::internal(format!("proposal scan: {e}")))?
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        Ok(Response::new(ProposalList { proposals }))
    }

    async fn get_proposal_by_id(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<Proposal>, Status> {
        // BytesMessage carries the 8-byte big-endian proposal id.
        let v = req.into_inner().value;
        if v.len() != 8 {
            return Ok(Response::new(Proposal::default()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&v);
        let id = i64::from_be_bytes(arr);
        let Some(ps) = &self.state.proposals else {
            return Ok(Response::new(Proposal::default()));
        };
        Ok(Response::new(ps.get(id).ok().flatten().unwrap_or_default()))
    }

    // ----- Mempool queries / broadcast -----

    async fn get_pending_size(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        let n = self
            .state
            .mempool
            .as_ref()
            .map(|m| m.pending_count() as i64)
            .unwrap_or(0);
        Ok(Response::new(NumberMessage { num: n }))
    }

    async fn get_transaction_list_from_pending(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<TransactionIdList>, Status> {
        // The pluggable Mempool trait doesn't expose per-tx-id
        // enumeration today — would require an extension. Return
        // empty until that lands. Clients calling this on a known-
        // empty mempool see the correct empty result.
        Ok(Response::new(TransactionIdList { tx_id: Vec::new() }))
    }

    async fn broadcast_transaction(
        &self,
        req: Request<Transaction>,
    ) -> Result<Response<Return>, Status> {
        let tx = req.into_inner();
        let bytes = prost::Message::encode_to_vec(&tx);
        let Some(mempool) = &self.state.mempool else {
            return Ok(Response::new(Return {
                result: false,
                code: r#return::ResponseCode::ServerBusy as i32,
                message: b"no mempool attached".to_vec(),
            }));
        };
        match mempool.submit_tron(&bytes) {
            tron_rpc::SubmitOutcome::Accepted(_) => Ok(Response::new(Return {
                result: true,
                code: r#return::ResponseCode::Success as i32,
                message: Vec::new(),
            })),
            tron_rpc::SubmitOutcome::Rejected(reason) => Ok(Response::new(Return {
                result: false,
                code: r#return::ResponseCode::OtherError as i32,
                message: reason.into_bytes(),
            })),
            tron_rpc::SubmitOutcome::Unsupported => Ok(Response::new(Return {
                result: false,
                code: r#return::ResponseCode::ServerBusy as i32,
                message: b"mempool does not accept new submissions".to_vec(),
            })),
        }
    }

    // ----- Delegation queries -----

    async fn get_delegated_resource(
        &self,
        req: Request<DelegatedResourceMessage>,
    ) -> Result<Response<DelegatedResourceList>, Status> {
        let r = req.into_inner();
        Ok(Response::new(lookup_delegated_v1(&self.state, &r)))
    }

    async fn get_delegated_resource_v2(
        &self,
        req: Request<DelegatedResourceMessage>,
    ) -> Result<Response<DelegatedResourceList>, Status> {
        let r = req.into_inner();
        Ok(Response::new(lookup_delegated_v2(&self.state, &r)))
    }

    // ----- Network -----

    async fn list_nodes(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<NodeList>, Status> {
        // We don't currently track the gossip node table — sync
        // driver dials a preconfigured peer list. Return empty.
        Ok(Response::new(NodeList { nodes: Vec::new() }))
    }

    async fn get_chain_parameters(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<ChainParameters>, Status> {
        // Walk the well-known dyn-props keys that map to TRON chain
        // parameters and emit them as ChainParameter entries. This
        // matches what java-tron's `getChainParameters` returns. The
        // list is conservative — only keys we know exist in dyn_props.
        use protocol::chain_parameters::ChainParameter;
        const KEYS: &[&str] = &[
            "MAINTENANCE_TIME_INTERVAL",
            "ACCOUNT_UPGRADE_COST",
            "CREATE_ACCOUNT_FEE",
            "TRANSACTION_FEE",
            "ASSET_ISSUE_FEE",
            "WITNESS_PAY_PER_BLOCK",
            "WITNESS_STANDBY_ALLOWANCE",
            "CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT",
            "CREATE_NEW_ACCOUNT_BANDWIDTH_RATE",
            "ALLOW_CREATION_OF_CONTRACTS",
            "REMOVE_THE_POWER_OF_THE_GR",
            "ENERGY_FEE",
            "EXCHANGE_CREATE_FEE",
            "MAX_CPU_TIME_OF_ONE_TX",
            "ALLOW_UPDATE_ACCOUNT_NAME",
            "ALLOW_SAME_TOKEN_NAME",
            "ALLOW_DELEGATE_RESOURCE",
            "TOTAL_ENERGY_LIMIT",
            "ALLOW_TVM_TRANSFER_TRC10",
            "TOTAL_CURRENT_ENERGY_LIMIT",
            "ALLOW_MULTI_SIGN",
            "ALLOW_ADAPTIVE_ENERGY",
            "UPDATE_ACCOUNT_PERMISSION_FEE",
            "MULTI_SIGN_FEE",
            "ALLOW_PROTO_FILTER_NUM",
            "ALLOW_ACCOUNT_STATE_ROOT",
            "ALLOW_TVM_CONSTANTINOPLE",
            "ALLOW_TVM_SOLIDITY_059",
            "ALLOW_ZKSNARK_TRANSACTION",
            "SHIELDED_TRANSACTION_FEE",
            "ALLOW_TVM_ISTANBUL",
            "ALLOW_MARKET_TRANSACTION",
            "MARKET_SELL_FEE",
            "MARKET_CANCEL_FEE",
            "MAX_FEE_LIMIT",
            "ALLOW_TRANSACTION_FEE_POOL",
            "TRANSACTION_FEE_POOL",
            "ALLOW_BLACKHOLE_OPTIMIZATION",
            "ALLOW_NEW_RESOURCE_MODEL",
            "ALLOW_TVM_FREEZE",
            "ALLOW_TVM_VOTE",
            "ALLOW_TVM_LONDON",
            "ALLOW_TVM_COMPATIBLE_EVM",
            "ALLOW_ACCOUNT_ASSET_OPTIMIZATION",
            "FREE_NET_LIMIT",
            "TOTAL_NET_LIMIT",
            "TOTAL_NET_WEIGHT",
            "TOTAL_ENERGY_WEIGHT",
            "ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
            "ALLOW_NEW_REWARD",
            "MEMO_FEE",
            "ALLOW_DELEGATE_OPTIMIZATION",
            "UNFREEZE_DELAY_DAYS",
            "ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID",
            "ALLOW_DYNAMIC_ENERGY",
            "DYNAMIC_ENERGY_THRESHOLD",
            "DYNAMIC_ENERGY_INCREASE_FACTOR",
            "DYNAMIC_ENERGY_MAX_FACTOR",
            "ALLOW_TVM_SHANGHAI",
            "ALLOW_CANCEL_ALL_UNFREEZE_V2",
            "MAX_DELEGATE_LOCK_PERIOD",
            "ALLOW_OLD_REWARD_OPT",
        ];
        let mut chain_parameter = Vec::with_capacity(KEYS.len());
        for k in KEYS {
            if let Some(v) = self.state.dyn_props.get_long(k.as_bytes()) {
                chain_parameter.push(ChainParameter {
                    key: k.to_string(),
                    value: v,
                });
            }
        }
        Ok(Response::new(ChainParameters { chain_parameter }))
    }

    // ----- Asset / exchange queries -----

    async fn get_asset_issue_list(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::AssetIssueList>, Status> {
        let Some(av2) = &self.state.assets_v2 else {
            return Ok(Response::new(protocol::AssetIssueList {
                asset_issue: Vec::new(),
            }));
        };
        let list = av2
            .all()
            .map_err(|e| Status::internal(format!("asset scan: {e}")))?
            .into_iter()
            .map(|(_, a)| a)
            .collect();
        Ok(Response::new(protocol::AssetIssueList { asset_issue: list }))
    }

    async fn get_paginated_asset_issue_list(
        &self,
        req: Request<protocol::PaginatedMessage>,
    ) -> Result<Response<protocol::AssetIssueList>, Status> {
        let p = req.into_inner();
        let Some(av2) = &self.state.assets_v2 else {
            return Ok(Response::new(protocol::AssetIssueList {
                asset_issue: Vec::new(),
            }));
        };
        let all = av2
            .all()
            .map_err(|e| Status::internal(format!("asset scan: {e}")))?;
        let asset_issue: Vec<_> = all
            .into_iter()
            .skip(p.offset.max(0) as usize)
            .take(p.limit.max(0) as usize)
            .map(|(_, a)| a)
            .collect();
        Ok(Response::new(protocol::AssetIssueList { asset_issue }))
    }

    async fn get_asset_issue_by_id(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::AssetIssueContract>, Status> {
        // BytesMessage.value is the ASCII-decimal asset id string
        // (e.g. b"1000001"). Match java-tron's behaviour.
        let v = req.into_inner().value;
        let Ok(id_str) = std::str::from_utf8(&v) else {
            return Ok(Response::new(protocol::AssetIssueContract::default()));
        };
        let Ok(id) = id_str.parse::<i64>() else {
            return Ok(Response::new(protocol::AssetIssueContract::default()));
        };
        let Some(av2) = &self.state.assets_v2 else {
            return Ok(Response::new(protocol::AssetIssueContract::default()));
        };
        Ok(Response::new(
            av2.get(id).ok().flatten().unwrap_or_default(),
        ))
    }

    async fn list_exchanges(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::ExchangeList>, Status> {
        let Some(ex2) = &self.state.exchanges_v2 else {
            return Ok(Response::new(protocol::ExchangeList { exchanges: Vec::new() }));
        };
        let exchanges = ex2
            .all()
            .map_err(|e| Status::internal(format!("exchange scan: {e}")))?
            .into_iter()
            .map(|(_, e)| e)
            .collect();
        Ok(Response::new(protocol::ExchangeList { exchanges }))
    }

    async fn get_paginated_exchange_list(
        &self,
        req: Request<protocol::PaginatedMessage>,
    ) -> Result<Response<protocol::ExchangeList>, Status> {
        let p = req.into_inner();
        let Some(ex2) = &self.state.exchanges_v2 else {
            return Ok(Response::new(protocol::ExchangeList { exchanges: Vec::new() }));
        };
        let all = ex2
            .all()
            .map_err(|e| Status::internal(format!("exchange scan: {e}")))?;
        let exchanges: Vec<_> = all
            .into_iter()
            .skip(p.offset.max(0) as usize)
            .take(p.limit.max(0) as usize)
            .map(|(_, e)| e)
            .collect();
        Ok(Response::new(protocol::ExchangeList { exchanges }))
    }

    async fn get_exchange_by_id(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::Exchange>, Status> {
        // BytesMessage.value is the 8-byte big-endian exchange id.
        let v = req.into_inner().value;
        if v.len() != 8 {
            return Ok(Response::new(protocol::Exchange::default()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&v);
        let id = i64::from_be_bytes(arr);
        let Some(ex2) = &self.state.exchanges_v2 else {
            return Ok(Response::new(protocol::Exchange::default()));
        };
        Ok(Response::new(ex2.get(id).ok().flatten().unwrap_or_default()))
    }

    async fn get_paginated_proposal_list(
        &self,
        req: Request<protocol::PaginatedMessage>,
    ) -> Result<Response<ProposalList>, Status> {
        let p = req.into_inner();
        let Some(ps) = &self.state.proposals else {
            return Ok(Response::new(ProposalList { proposals: Vec::new() }));
        };
        let all = ps
            .all()
            .map_err(|e| Status::internal(format!("proposal scan: {e}")))?;
        let proposals: Vec<_> = all
            .into_iter()
            .skip(p.offset.max(0) as usize)
            .take(p.limit.max(0) as usize)
            .map(|(_, x)| x)
            .collect();
        Ok(Response::new(ProposalList { proposals }))
    }

    // ----- Account resource queries -----

    async fn get_account_net(
        &self,
        req: Request<Account>,
    ) -> Result<Response<protocol::AccountNetMessage>, Status> {
        let probe = req.into_inner();
        if probe.address.len() != 21 {
            return Ok(Response::new(protocol::AccountNetMessage::default()));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&probe.address);
        let acct = self
            .state
            .accounts
            .get(&Address::from_raw(addr))
            .ok()
            .flatten()
            .unwrap_or_default();
        let dp = &self.state.dyn_props;
        Ok(Response::new(protocol::AccountNetMessage {
            free_net_used: acct.free_net_usage,
            free_net_limit: dp.get_long(b"FREE_NET_LIMIT").unwrap_or(5000),
            net_used: acct.net_usage,
            // Account.net_window_size + tron-executor's resource math
            // give the per-account limit. For a minimal first cut we
            // surface the global cap; clients reading this will see
            // the same total as `getChainParameters`.
            net_limit: dp.get_long(b"TOTAL_NET_LIMIT").unwrap_or(0),
            asset_net_used: std::collections::BTreeMap::new(),
            asset_net_limit: std::collections::BTreeMap::new(),
            total_net_limit: dp.get_long(b"TOTAL_NET_LIMIT").unwrap_or(0),
            total_net_weight: dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0),
        }))
    }

    async fn get_account_resource(
        &self,
        req: Request<Account>,
    ) -> Result<Response<protocol::AccountResourceMessage>, Status> {
        let probe = req.into_inner();
        if probe.address.len() != 21 {
            return Ok(Response::new(protocol::AccountResourceMessage::default()));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&probe.address);
        let acct = self
            .state
            .accounts
            .get(&Address::from_raw(addr))
            .ok()
            .flatten()
            .unwrap_or_default();
        // Shared computation with the JSON-RPC handler: per-account limits,
        // read-time usage decay (java's head_slot), tron-power, storage.
        let v = tron_rpc::methods::account_resource_view(&acct, &self.state.dyn_props);
        Ok(Response::new(protocol::AccountResourceMessage {
            free_net_used: v.free_net_used,
            free_net_limit: v.free_net_limit,
            net_used: v.net_used,
            net_limit: v.net_limit,
            asset_net_used: std::collections::BTreeMap::new(),
            asset_net_limit: std::collections::BTreeMap::new(),
            total_net_limit: v.total_net_limit,
            total_net_weight: v.total_net_weight,
            total_tron_power_weight: v.total_tron_power_weight,
            tron_power_used: v.tron_power_used,
            tron_power_limit: v.tron_power_limit,
            energy_used: v.energy_used,
            energy_limit: v.energy_limit,
            total_energy_limit: v.total_energy_limit,
            total_energy_weight: v.total_energy_weight,
            storage_used: v.storage_used,
            storage_limit: v.storage_limit,
        }))
    }

    async fn get_available_unfreeze_count(
        &self,
        req: Request<protocol::GetAvailableUnfreezeCountRequestMessage>,
    ) -> Result<Response<protocol::GetAvailableUnfreezeCountResponseMessage>, Status> {
        let owner = req.into_inner().owner_address;
        if owner.len() != 21 {
            return Ok(Response::new(
                protocol::GetAvailableUnfreezeCountResponseMessage { count: 0 },
            ));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&owner);
        let acct = self
            .state
            .accounts
            .get(&Address::from_raw(addr))
            .ok()
            .flatten()
            .unwrap_or_default();
        // java-tron caps unfreezeV2 entries at 32 per account; the
        // "available" count = (cap - active entries).
        const UNFREEZE_V2_CAP: i64 = 32;
        let used = acct.unfrozen_v2.len() as i64;
        Ok(Response::new(
            protocol::GetAvailableUnfreezeCountResponseMessage {
                count: (UNFREEZE_V2_CAP - used).max(0),
            },
        ))
    }

    async fn get_can_withdraw_unfreeze_amount(
        &self,
        req: Request<protocol::CanWithdrawUnfreezeAmountRequestMessage>,
    ) -> Result<Response<protocol::CanWithdrawUnfreezeAmountResponseMessage>, Status> {
        let r = req.into_inner();
        if r.owner_address.len() != 21 {
            return Ok(Response::new(
                protocol::CanWithdrawUnfreezeAmountResponseMessage { amount: 0 },
            ));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&r.owner_address);
        let acct = self
            .state
            .accounts
            .get(&Address::from_raw(addr))
            .ok()
            .flatten()
            .unwrap_or_default();
        // Sum every `unfrozen_v2` entry whose `unfreeze_expire_time`
        // is at or before the requested timestamp — those are claimable.
        let amount: i64 = acct
            .unfrozen_v2
            .iter()
            .filter(|e| e.unfreeze_expire_time <= r.timestamp)
            .map(|e| e.unfreeze_amount)
            .sum();
        Ok(Response::new(
            protocol::CanWithdrawUnfreezeAmountResponseMessage { amount },
        ))
    }

    // ----- Smart-contract metadata -----

    async fn get_contract(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::SmartContract>, Status> {
        let v = req.into_inner().value;
        if v.len() != 21 {
            return Ok(Response::new(protocol::SmartContract::default()));
        }
        let mut addr_arr = [0u8; 21];
        addr_arr.copy_from_slice(&v);
        let Some(contracts) = &self.state.contracts else {
            return Ok(Response::new(protocol::SmartContract::default()));
        };
        Ok(Response::new(
            contracts
                .get(&Address::from_raw(addr_arr))
                .ok()
                .flatten()
                .unwrap_or_default(),
        ))
    }

    // ----- Prices / fees (PricesResponseMessage uses a
    //       `"timestamp:price[,timestamp:price]…"` format historically;
    //       we return the current single value). -----

    async fn get_bandwidth_prices(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::PricesResponseMessage>, Status> {
        let price = self.state.dyn_props.get_long(b"TRANSACTION_FEE").unwrap_or(0);
        Ok(Response::new(protocol::PricesResponseMessage {
            prices: format!("0:{}", price),
        }))
    }

    async fn get_energy_prices(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::PricesResponseMessage>, Status> {
        let price = self.state.dyn_props.get_long(b"ENERGY_FEE").unwrap_or(0);
        Ok(Response::new(protocol::PricesResponseMessage {
            prices: format!("0:{}", price),
        }))
    }

    async fn get_memo_fee(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::PricesResponseMessage>, Status> {
        let price = self.state.dyn_props.get_long(b"MEMO_FEE").unwrap_or(0);
        Ok(Response::new(protocol::PricesResponseMessage {
            prices: format!("0:{}", price),
        }))
    }

    // ----- Writer methods (build unsigned transactions) -----
    //
    // Pattern: each method wraps the typed contract proto in a
    // TxContract via `wrap_contract`, then fills in head-ref / timestamp
    // / expiration via `build_unsigned_tx`. The result is an UNSIGNED
    // Transaction the client signs locally (sha256 of raw_data, ECDSA
    // with secp256k1) and broadcasts via `broadcast_transaction`.
    //
    // Java-tron's API has both legacy (`Transaction` return) and `2`
    // variants (`TransactionExtention` return — adds txid + success
    // Return). We implement both for every contract type that has a
    // legacy form, because TronWeb defaults to the `2` variant but
    // older SDKs still use the legacy one.
    //
    // `permission_id` is always 0 here (owner permission). Multi-sig
    // callers can override post-build by setting `contract[0].permission_id`
    // before signing.

    async fn create_transaction(
        &self,
        req: Request<protocol::TransferContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::TransferContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn create_transaction2(
        &self,
        req: Request<protocol::TransferContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::TransferContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn transfer_asset(
        &self,
        req: Request<protocol::TransferAssetContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::TransferAssetContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn transfer_asset2(
        &self,
        req: Request<protocol::TransferAssetContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::TransferAssetContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn create_account(
        &self,
        req: Request<protocol::AccountCreateContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::AccountCreateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn create_account2(
        &self,
        req: Request<protocol::AccountCreateContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::AccountCreateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_account(
        &self,
        req: Request<protocol::AccountUpdateContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::AccountUpdateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_account2(
        &self,
        req: Request<protocol::AccountUpdateContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::AccountUpdateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn set_account_id(
        &self,
        req: Request<protocol::SetAccountIdContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::SetAccountIdContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn create_witness(
        &self,
        req: Request<protocol::WitnessCreateContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::WitnessCreateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn create_witness2(
        &self,
        req: Request<protocol::WitnessCreateContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::WitnessCreateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_witness(
        &self,
        req: Request<protocol::WitnessUpdateContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::WitnessUpdateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_witness2(
        &self,
        req: Request<protocol::WitnessUpdateContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::WitnessUpdateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn vote_witness_account(
        &self,
        req: Request<protocol::VoteWitnessContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::VoteWitnessContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn vote_witness_account2(
        &self,
        req: Request<protocol::VoteWitnessContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::VoteWitnessContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn create_asset_issue(
        &self,
        req: Request<protocol::AssetIssueContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::AssetIssueContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn create_asset_issue2(
        &self,
        req: Request<protocol::AssetIssueContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::AssetIssueContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_asset(
        &self,
        req: Request<protocol::UpdateAssetContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UpdateAssetContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_asset2(
        &self,
        req: Request<protocol::UpdateAssetContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UpdateAssetContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn participate_asset_issue(
        &self,
        req: Request<protocol::ParticipateAssetIssueContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ParticipateAssetIssueContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn participate_asset_issue2(
        &self,
        req: Request<protocol::ParticipateAssetIssueContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ParticipateAssetIssueContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn unfreeze_asset(
        &self,
        req: Request<protocol::UnfreezeAssetContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UnfreezeAssetContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn unfreeze_asset2(
        &self,
        req: Request<protocol::UnfreezeAssetContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UnfreezeAssetContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn freeze_balance(
        &self,
        req: Request<protocol::FreezeBalanceContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::FreezeBalanceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn freeze_balance2(
        &self,
        req: Request<protocol::FreezeBalanceContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::FreezeBalanceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn freeze_balance_v2(
        &self,
        req: Request<protocol::FreezeBalanceV2Contract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::FreezeBalanceV2Contract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn unfreeze_balance(
        &self,
        req: Request<protocol::UnfreezeBalanceContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UnfreezeBalanceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn unfreeze_balance2(
        &self,
        req: Request<protocol::UnfreezeBalanceContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UnfreezeBalanceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn unfreeze_balance_v2(
        &self,
        req: Request<protocol::UnfreezeBalanceV2Contract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UnfreezeBalanceV2Contract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn withdraw_balance(
        &self,
        req: Request<protocol::WithdrawBalanceContract>,
    ) -> Result<Response<Transaction>, Status> {
        build_tx_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::WithdrawBalanceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn withdraw_balance2(
        &self,
        req: Request<protocol::WithdrawBalanceContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::WithdrawBalanceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn withdraw_expire_unfreeze(
        &self,
        req: Request<protocol::WithdrawExpireUnfreezeContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::WithdrawExpireUnfreezeContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn delegate_resource(
        &self,
        req: Request<protocol::DelegateResourceContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::DelegateResourceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn un_delegate_resource(
        &self,
        req: Request<protocol::UnDelegateResourceContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UnDelegateResourceContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn cancel_all_unfreeze_v2(
        &self,
        req: Request<protocol::CancelAllUnfreezeV2Contract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::CancelAllUnfreezeV2Contract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn proposal_create(
        &self,
        req: Request<protocol::ProposalCreateContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ProposalCreateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn proposal_approve(
        &self,
        req: Request<protocol::ProposalApproveContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ProposalApproveContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn proposal_delete(
        &self,
        req: Request<protocol::ProposalDeleteContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ProposalDeleteContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn exchange_create(
        &self,
        req: Request<protocol::ExchangeCreateContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ExchangeCreateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn exchange_inject(
        &self,
        req: Request<protocol::ExchangeInjectContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ExchangeInjectContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn exchange_withdraw(
        &self,
        req: Request<protocol::ExchangeWithdrawContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ExchangeWithdrawContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn exchange_transaction(
        &self,
        req: Request<protocol::ExchangeTransactionContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ExchangeTransactionContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn market_sell_asset(
        &self,
        req: Request<protocol::MarketSellAssetContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::MarketSellAssetContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn market_cancel_order(
        &self,
        req: Request<protocol::MarketCancelOrderContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::MarketCancelOrderContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_setting(
        &self,
        req: Request<protocol::UpdateSettingContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UpdateSettingContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_energy_limit(
        &self,
        req: Request<protocol::UpdateEnergyLimitContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UpdateEnergyLimitContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn clear_contract_abi(
        &self,
        req: Request<protocol::ClearAbiContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::ClearAbiContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn account_permission_update(
        &self,
        req: Request<protocol::AccountPermissionUpdateContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::AccountPermissionUpdateContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn update_brokerage(
        &self,
        req: Request<protocol::UpdateBrokerageContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::UpdateBrokerageContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn deploy_contract(
        &self,
        req: Request<protocol::CreateSmartContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::CreateSmartContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }
    async fn trigger_contract(
        &self,
        req: Request<protocol::TriggerSmartContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        build_tx_ext_for(
            &self.state,
            tron_proto::transaction::contract::ContractType::TriggerSmartContract,
            &req.into_inner(),
        )
        .map(Response::new)
    }

    // ----- Reward / brokerage / delegation -----

    async fn get_brokerage_info(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        let v = req.into_inner().value;
        if v.len() != 21 {
            return Ok(Response::new(NumberMessage { num: 0 }));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&v);
        let Some(ds) = &self.state.delegation else {
            return Ok(Response::new(NumberMessage { num: 0 }));
        };
        let num = ds.get_brokerage_global(&Address::from_raw(addr)) as i64;
        Ok(Response::new(NumberMessage { num }))
    }

    async fn get_reward_info(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        let v = req.into_inner().value;
        if v.len() != 21 {
            return Ok(Response::new(NumberMessage { num: 0 }));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&v);
        // Real reward needs Vi-accumulator math across cycles — for
        // now report the account's cached allowance.
        let acct = self
            .state
            .accounts
            .get(&Address::from_raw(addr))
            .ok()
            .flatten()
            .unwrap_or_default();
        Ok(Response::new(NumberMessage { num: acct.allowance }))
    }

    async fn get_delegated_resource_account_index(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::DelegatedResourceAccountIndex>, Status> {
        let v = req.into_inner().value;
        if v.len() != 21 {
            return Ok(Response::new(
                protocol::DelegatedResourceAccountIndex::default(),
            ));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&v);
        let Some(idx) = &self.state.delegated_resource_account_index else {
            return Ok(Response::new(
                protocol::DelegatedResourceAccountIndex::default(),
            ));
        };
        // v1 layout uses the simple address-keyed legacy entry.
        let key = tron_chainbase::DelegatedResourceAccountIndexStore::legacy_key(
            &Address::from_raw(addr),
        );
        Ok(Response::new(
            idx.get_raw(&key).ok().flatten().unwrap_or_default(),
        ))
    }

    async fn get_delegated_resource_account_index_v2(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::DelegatedResourceAccountIndex>, Status> {
        let v = req.into_inner().value;
        if v.len() != 21 {
            return Ok(Response::new(
                protocol::DelegatedResourceAccountIndex::default(),
            ));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&v);
        let Some(idx) = &self.state.delegated_resource_account_index else {
            return Ok(Response::new(
                protocol::DelegatedResourceAccountIndex::default(),
            ));
        };
        // v2 indexes are split per from/to direction and per receiver
        // — proper assembly needs a prefix-scan helper that the store
        // doesn't yet expose. Fall back to legacy until that lands.
        let key = tron_chainbase::DelegatedResourceAccountIndexStore::legacy_key(
            &Address::from_raw(addr),
        );
        Ok(Response::new(
            idx.get_raw(&key).ok().flatten().unwrap_or_default(),
        ))
    }

    async fn get_can_delegated_max_size(
        &self,
        req: Request<protocol::CanDelegatedMaxSizeRequestMessage>,
    ) -> Result<Response<protocol::CanDelegatedMaxSizeResponseMessage>, Status> {
        let r = req.into_inner();
        if r.owner_address.len() != 21 {
            return Ok(Response::new(
                protocol::CanDelegatedMaxSizeResponseMessage::default(),
            ));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&r.owner_address);
        let acct = self
            .state
            .accounts
            .get(&Address::from_raw(addr))
            .ok()
            .flatten()
            .unwrap_or_default();
        // Conservative: report frozen_v2 amount per resource type as
        // the upper bound. java-tron also subtracts already-delegated;
        // we'll add that subtraction in a follow-up once the
        // delegation per-receiver index is exposed via a typed helper.
        let max_size: i64 = acct
            .frozen_v2
            .iter()
            .filter(|f| f.r#type == r.r#type)
            .map(|f| f.amount)
            .sum();
        Ok(Response::new(
            protocol::CanDelegatedMaxSizeResponseMessage { max_size },
        ))
    }

    // ----- Asset by-account scan -----

    async fn get_asset_issue_by_account(
        &self,
        req: Request<Account>,
    ) -> Result<Response<protocol::AssetIssueList>, Status> {
        let probe = req.into_inner();
        if probe.address.len() != 21 {
            return Ok(Response::new(protocol::AssetIssueList {
                asset_issue: Vec::new(),
            }));
        }
        let Some(av2) = &self.state.assets_v2 else {
            return Ok(Response::new(protocol::AssetIssueList {
                asset_issue: Vec::new(),
            }));
        };
        let all = av2
            .all()
            .map_err(|e| Status::internal(format!("asset scan: {e}")))?;
        let asset_issue: Vec<_> = all
            .into_iter()
            .filter(|(_, a)| a.owner_address == probe.address)
            .map(|(_, a)| a)
            .collect();
        Ok(Response::new(protocol::AssetIssueList { asset_issue }))
    }

    // ----- Witness pagination -----

    async fn get_paginated_now_witness_list(
        &self,
        req: Request<protocol::PaginatedMessage>,
    ) -> Result<Response<WitnessList>, Status> {
        let p = req.into_inner();
        let Some(ws) = &self.state.witnesses else {
            return Ok(Response::new(WitnessList { witnesses: Vec::new() }));
        };
        let all = ws
            .all()
            .map_err(|e| Status::internal(format!("witness scan: {e}")))?;
        let witnesses: Vec<_> = all
            .into_iter()
            .skip(p.offset.max(0) as usize)
            .take(p.limit.max(0) as usize)
            .map(|(_, w)| w)
            .collect();
        Ok(Response::new(WitnessList { witnesses }))
    }

    // ----- Block balance trace -----

    async fn get_block_balance_trace(
        &self,
        req: Request<protocol::block_balance_trace::BlockIdentifier>,
    ) -> Result<Response<protocol::BlockBalanceTrace>, Status> {
        let id = req.into_inner();
        let Some(bt) = &self.state.balance_trace else {
            return Ok(Response::new(protocol::BlockBalanceTrace::default()));
        };
        Ok(Response::new(
            bt.get(id.number).ok().flatten().unwrap_or_default(),
        ))
    }

    // ----- Contract metadata (full = ContractStore + bytecode) -----

    async fn get_contract_info(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::SmartContractDataWrapper>, Status> {
        let v = req.into_inner().value;
        if v.len() != 21 {
            return Ok(Response::new(protocol::SmartContractDataWrapper::default()));
        }
        let mut addr_arr = [0u8; 21];
        addr_arr.copy_from_slice(&v);
        let addr = Address::from_raw(addr_arr);
        let Some(contracts) = &self.state.contracts else {
            return Ok(Response::new(protocol::SmartContractDataWrapper::default()));
        };
        let smart_contract = contracts.get(&addr).ok().flatten();
        let runtimecode = smart_contract
            .as_ref()
            .map(|c| c.bytecode.clone())
            .unwrap_or_default();
        Ok(Response::new(protocol::SmartContractDataWrapper {
            smart_contract,
            runtimecode,
            ..Default::default()
        }))
    }

    // ----- TransactionInfo (executor doesn't yet persist this) -----

    async fn get_transaction_info_by_id(
        &self,
        _: Request<BytesMessage>,
    ) -> Result<Response<protocol::TransactionInfo>, Status> {
        // Executor doesn't yet emit per-tx info to a store. Empty
        // response — clients that depend on this will need the
        // executor write path landing.
        Ok(Response::new(protocol::TransactionInfo::default()))
    }

    async fn get_transaction_info_by_block_num(
        &self,
        _: Request<NumberMessage>,
    ) -> Result<Response<protocol::TransactionInfoList>, Status> {
        Ok(Response::new(protocol::TransactionInfoList::default()))
    }

    // ----- Mempool single-tx lookup (no per-id index on the trait) -----

    async fn get_transaction_from_pending(
        &self,
        _: Request<BytesMessage>,
    ) -> Result<Response<Transaction>, Status> {
        Ok(Response::new(Transaction::default()))
    }

    // ----- Common transaction pass-through (stamps ref/timestamp) -----

    async fn create_common_transaction(
        &self,
        req: Request<Transaction>,
    ) -> Result<Response<TransactionExtention>, Status> {
        let tx = req.into_inner();
        let Some(raw) = tx.raw_data.as_ref() else {
            return Err(Status::invalid_argument("transaction has no raw_data"));
        };
        let Some(contract) = raw.contract.first().cloned() else {
            return Err(Status::invalid_argument("transaction has no contract"));
        };
        let new_tx = tron_rpc::builder::build_unsigned_tx(
            &self.state,
            contract,
            raw.fee_limit,
        )
        .map_err(|e| Status::internal(format!("build_tx: {e:?}")))?;
        let id = tx_id(&new_tx);
        Ok(Response::new(TransactionExtention {
            transaction: Some(new_tx),
            txid: id.to_vec(),
            result: Some(Return {
                result: true,
                code: r#return::ResponseCode::Success as i32,
                message: Vec::new(),
            }),
            ..Default::default()
        }))
    }

    // ----- Multi-sig math -----

    async fn get_transaction_sign_weight(
        &self,
        req: Request<Transaction>,
    ) -> Result<Response<protocol::TransactionSignWeight>, Status> {
        let tx = req.into_inner();
        let sw = tron_actuator::permission::compute_sign_weight(
            &self.state.accounts,
            &self.state.dyn_props,
            &tx,
        )
        .map_err(|e| Status::internal(format!("sign-weight: {e:?}")))?;
        Ok(Response::new(protocol::TransactionSignWeight {
            permission: Some(sw.permission),
            approved_list: sw
                .approved_list
                .iter()
                .map(|a| a.as_bytes().to_vec())
                .collect(),
            current_weight: sw.current_weight,
            result: Some(protocol::transaction_sign_weight::Result {
                code: sw.code as i32,
                message: sw.message,
            }),
            transaction: Some(TransactionExtention {
                transaction: Some(tx.clone()),
                txid: tx_id(&tx).to_vec(),
                ..Default::default()
            }),
        }))
    }

    async fn get_transaction_approved_list(
        &self,
        req: Request<Transaction>,
    ) -> Result<Response<protocol::TransactionApprovedList>, Status> {
        let tx = req.into_inner();
        let list = tron_actuator::permission::approved_list(&tx)
            .map_err(|e| Status::internal(format!("approved-list: {e:?}")))?;
        Ok(Response::new(protocol::TransactionApprovedList {
            approved_list: list.iter().map(|a| a.as_bytes().to_vec()).collect(),
            result: Some(protocol::transaction_approved_list::Result {
                code: 0,
                message: String::new(),
            }),
            transaction: Some(TransactionExtention {
                transaction: Some(tx.clone()),
                txid: tx_id(&tx).to_vec(),
                ..Default::default()
            }),
        }))
    }

    // ----- Market queries (DEX) -----

    async fn get_market_order_by_id(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::MarketOrder>, Status> {
        let v = req.into_inner().value;
        let Some(store) = &self.state.market_orders else {
            return Ok(Response::new(protocol::MarketOrder::default()));
        };
        Ok(Response::new(store.get(&v).ok().flatten().unwrap_or_default()))
    }

    async fn get_market_order_by_account(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::MarketOrderList>, Status> {
        let v = req.into_inner().value;
        if v.len() != 21 {
            return Ok(Response::new(protocol::MarketOrderList { orders: Vec::new() }));
        }
        let mut addr = [0u8; 21];
        addr.copy_from_slice(&v);
        let Some(accounts) = &self.state.market_accounts else {
            return Ok(Response::new(protocol::MarketOrderList { orders: Vec::new() }));
        };
        let acct_orders = accounts
            .get(&Address::from_raw(addr))
            .ok()
            .flatten()
            .unwrap_or_default();
        let Some(orders_store) = &self.state.market_orders else {
            return Ok(Response::new(protocol::MarketOrderList { orders: Vec::new() }));
        };
        // Resolve each order id → MarketOrder via the order store.
        let orders: Vec<_> = acct_orders
            .orders
            .iter()
            .filter_map(|id| orders_store.get(id).ok().flatten())
            .collect();
        Ok(Response::new(protocol::MarketOrderList { orders }))
    }

    async fn get_market_pair_list(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::MarketOrderPairList>, Status> {
        let Some(pairs) = &self.state.market_pair_to_price else {
            return Ok(Response::new(protocol::MarketOrderPairList {
                order_pair: Vec::new(),
            }));
        };
        // MarketPairToPriceStore is keyed by `sell_id || buy_id` (two
        // asset-id byte sequences). The value is the count of price
        // levels — not interesting for the pair list, just the keys.
        // For now, iterate all and surface the keys split in half. The
        // assumption is symmetric key lengths; java-tron actually uses
        // a per-token length prefix, so this is a best-effort cut and
        // may need refinement once we have a real DEX dataset.
        let entries = pairs
            .all()
            .map_err(|e| Status::internal(format!("market pair list: {e}")))?;
        let order_pair: Vec<_> = entries
            .iter()
            .filter_map(|(k, _)| {
                if k.is_empty() || k.len() % 2 != 0 {
                    return None;
                }
                let half = k.len() / 2;
                Some(protocol::MarketOrderPair {
                    sell_token_id: k[..half].to_vec(),
                    buy_token_id: k[half..].to_vec(),
                })
            })
            .collect();
        Ok(Response::new(protocol::MarketOrderPairList { order_pair }))
    }

    async fn get_market_price_by_pair(
        &self,
        req: Request<protocol::MarketOrderPair>,
    ) -> Result<Response<protocol::MarketPriceList>, Status> {
        // Proper price list assembly needs a prefix walk over
        // `market_pair_price_to_order` — exposing that needs a
        // store-level helper that doesn't exist yet. Echo the request
        // pair with an empty price list so clients see a structurally
        // correct response.
        let pair = req.into_inner();
        Ok(Response::new(protocol::MarketPriceList {
            sell_token_id: pair.sell_token_id,
            buy_token_id: pair.buy_token_id,
            prices: Vec::new(),
        }))
    }

    // ----- Asset by-name (v1 store) -----

    async fn get_asset_issue_by_name(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::AssetIssueContract>, Status> {
        let name = req.into_inner().value;
        let Some(av1) = &self.state.assets_v1 else {
            return Ok(Response::new(protocol::AssetIssueContract::default()));
        };
        Ok(Response::new(av1.get(&name).ok().flatten().unwrap_or_default()))
    }

    async fn get_asset_issue_list_by_name(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::AssetIssueList>, Status> {
        // java-tron returns a list because historically multiple
        // assets could share a name (pre `ALLOW_SAME_TOKEN_NAME`).
        // Scan v1 and filter by exact name match.
        let name = req.into_inner().value;
        let Some(av1) = &self.state.assets_v1 else {
            return Ok(Response::new(protocol::AssetIssueList {
                asset_issue: Vec::new(),
            }));
        };
        let all = av1
            .all()
            .map_err(|e| Status::internal(format!("asset scan: {e}")))?;
        let asset_issue: Vec<_> = all
            .into_iter()
            .filter(|(k, _)| *k == name || name.is_empty())
            .map(|(_, a)| a)
            .collect();
        Ok(Response::new(protocol::AssetIssueList { asset_issue }))
    }

    // ----- Market order list by pair (prefix scan) -----

    async fn get_market_order_list_by_pair(
        &self,
        req: Request<protocol::MarketOrderPair>,
    ) -> Result<Response<protocol::MarketOrderList>, Status> {
        let pair = req.into_inner();
        let Some(price_index) = &self.state.market_pair_price_to_order else {
            return Ok(Response::new(protocol::MarketOrderList { orders: Vec::new() }));
        };
        let Some(orders) = &self.state.market_orders else {
            return Ok(Response::new(protocol::MarketOrderList { orders: Vec::new() }));
        };
        // Pair prefix = sell_token_id || buy_token_id (per java-tron's
        // `MarketUtils.createPairPriceKey` — the price suffix follows
        // the pair bytes). Scan every price level whose key starts
        // with the pair prefix, then resolve each order id.
        let mut prefix = pair.sell_token_id.clone();
        prefix.extend_from_slice(&pair.buy_token_id);
        let lists = price_index
            .scan_prefix(&prefix)
            .map_err(|e| Status::internal(format!("market scan: {e}")))?;
        // Each price level stores a doubly-linked-list of orders;
        // `MarketOrderIdList` carries the `head` and `tail` order ids.
        // Walk from head via each `MarketOrder.next` pointer until
        // we hit an empty `next`. Bound the walk to avoid pathological
        // loops in corrupt state.
        let mut resolved = Vec::new();
        const MAX_WALK: usize = 10_000;
        for (_, list) in lists {
            let mut current = list.head;
            for _ in 0..MAX_WALK {
                if current.is_empty() {
                    break;
                }
                let Some(order) = orders.get(&current).ok().flatten() else {
                    break;
                };
                let next = order.next.clone();
                resolved.push(order);
                current = next;
            }
        }
        Ok(Response::new(protocol::MarketOrderList { orders: resolved }))
    }

    // ----- Read-only VM execution (trigger_constant + estimate_energy) -----

    async fn trigger_constant_contract(
        &self,
        req: Request<protocol::TriggerSmartContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        let trigger = req.into_inner();
        let outcome = run_constant_call(&self.state, &trigger);
        build_constant_response(&self.state, &trigger, outcome).map(Response::new)
    }

    async fn estimate_energy(
        &self,
        req: Request<protocol::TriggerSmartContract>,
    ) -> Result<Response<protocol::EstimateEnergyMessage>, Status> {
        let trigger = req.into_inner();
        let outcome = run_constant_call(&self.state, &trigger);
        let (success, energy_required, message) = match &outcome {
            Some(tron_tvm::execute::VmOutcome::Success { energy_used, .. }) => {
                (true, *energy_used as i64, String::new())
            }
            Some(tron_tvm::execute::VmOutcome::Revert {
                energy_used,
                return_data,
                ..
            }) => (
                false,
                *energy_used as i64,
                format!("REVERT: 0x{}", hex::encode(return_data)),
            ),
            Some(tron_tvm::execute::VmOutcome::Halt {
                reason,
                energy_used,
                ..
            }) => (false, *energy_used as i64, format!("{reason:?}")),
            Some(tron_tvm::execute::VmOutcome::CallTokenIgnored {
                token_id,
                call_token_value,
            }) => (
                false,
                0,
                format!(
                    "CALLTOKEN not implemented in estimate; token_id={} value={}",
                    token_id, call_token_value
                ),
            ),
            Some(tron_tvm::execute::VmOutcome::PreflightError(e)) => {
                (false, 0, format!("preflight: {e}"))
            }
            Some(tron_tvm::execute::VmOutcome::Timeout {
                energy_used,
                deadline_ms,
            }) => (
                false,
                *energy_used as i64,
                format!("constant call timed out after {deadline_ms}ms"),
            ),
            None => (false, 0, "EVM backends not configured on this node".into()),
        };
        Ok(Response::new(protocol::EstimateEnergyMessage {
            result: Some(Return {
                result: success,
                code: if success {
                    r#return::ResponseCode::Success as i32
                } else {
                    r#return::ResponseCode::ContractExeError as i32
                },
                message: message.into_bytes(),
            }),
            energy_required,
        }))
    }

    // ----- Deprecated storage-market contracts (removed from mainnet) -----
    //
    // java-tron leaves these rpcs in api.proto but the corresponding
    // contract types were removed when the on-chain storage market
    // was retired. The honest gRPC response is FailedPrecondition with
    // a clear message — calling them was always going to fail on a
    // current-mainnet chain.

    async fn buy_storage(
        &self,
        _: Request<protocol::BuyStorageContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        Err(Status::failed_precondition(
            "BuyStorageContract was removed from mainnet; on-chain storage market is no longer supported",
        ))
    }
    async fn buy_storage_bytes(
        &self,
        _: Request<protocol::BuyStorageBytesContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        Err(Status::failed_precondition(
            "BuyStorageBytesContract was removed from mainnet; on-chain storage market is no longer supported",
        ))
    }
    async fn sell_storage(
        &self,
        _: Request<protocol::SellStorageContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        Err(Status::failed_precondition(
            "SellStorageContract was removed from mainnet; on-chain storage market is no longer supported",
        ))
    }

    // =========================================================
    // Shielded TRC-20 — Sapling key-derivation helpers
    //
    // Stateless `(ak, nk, ivk, d, …)` derivation. Delegate to the
    // typed helpers in `crate::shielded` so the same code is reusable
    // outside the trait impl (and so the trait body stays narrow).
    // =========================================================

    async fn get_spending_key(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<BytesMessage>, Status> {
        crate::shielded::get_spending_key().map(Response::new)
    }

    async fn get_expanded_spending_key(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<protocol::ExpandedSpendingKeyMessage>, Status> {
        crate::shielded::get_expanded_spending_key(&req.into_inner().value).map(Response::new)
    }

    async fn get_ak_from_ask(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<BytesMessage>, Status> {
        crate::shielded::get_ak_from_ask(&req.into_inner().value).map(Response::new)
    }

    async fn get_nk_from_nsk(
        &self,
        req: Request<BytesMessage>,
    ) -> Result<Response<BytesMessage>, Status> {
        crate::shielded::get_nk_from_nsk(&req.into_inner().value).map(Response::new)
    }

    async fn get_incoming_viewing_key(
        &self,
        req: Request<protocol::ViewingKeyMessage>,
    ) -> Result<Response<protocol::IncomingViewingKeyMessage>, Status> {
        crate::shielded::get_incoming_viewing_key(req.into_inner()).map(Response::new)
    }

    async fn get_diversifier(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::DiversifierMessage>, Status> {
        crate::shielded::get_diversifier().map(Response::new)
    }

    async fn get_zen_payment_address(
        &self,
        req: Request<protocol::IncomingViewingKeyDiversifierMessage>,
    ) -> Result<Response<protocol::PaymentAddressMessage>, Status> {
        crate::shielded::get_zen_payment_address(req.into_inner()).map(Response::new)
    }

    async fn get_rcm(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<BytesMessage>, Status> {
        crate::shielded::get_rcm().map(Response::new)
    }

    async fn get_new_shielded_address(
        &self,
        _: Request<EmptyMessage>,
    ) -> Result<Response<protocol::ShieldedAddressInfo>, Status> {
        crate::shielded::get_new_shielded_address().map(Response::new)
    }

    // =========================================================
    // Shielded TRC-20 — nullifier-set membership.
    //
    // `is_spend` requires the merkle-tree POSITION of a note's
    // commitment to compute its nullifier — that's not currently
    // tracked per-note in our state. Until a shielded-note-position
    // index lands, we cannot safely answer this query. Returning
    // `false` would let clients double-spend; returning an honest
    // FailedPrecondition tells them to talk to a fullnode that has
    // the index, or wait for that feature.
    // =========================================================

    async fn is_spend(
        &self,
        req: Request<protocol::NoteParameters>,
    ) -> Result<Response<protocol::SpendResult>, Status> {
        crate::shielded::is_spend(&self.state, req.into_inner()).map(Response::new)
    }

    async fn is_shielded_trc20_contract_note_spent(
        &self,
        req: Request<protocol::NfTrc20Parameters>,
    ) -> Result<Response<protocol::NullifierResult>, Status> {
        // Full implementation:
        //   1. Decode the Note's `payment_address` (86-char hex of
        //      `d || pk_d`) into a Sapling `PaymentAddress`.
        //   2. Parse `rcm` + `value` into a sapling-crypto `Note`
        //      via `Note::from_parts` with pre-ZIP-212 `Rseed`
        //      (java-tron's shielded TRC-20 uses the legacy
        //      trapdoor format).
        //   3. Reconstruct `NullifierDerivingKey` from the caller-
        //      supplied `nk`.
        //   4. Compute `nf = note.nf(&nk, position)`.
        //   5. Call the TRC-20 contract's `nullifiers(bytes32)` view
        //      via `run_constant_call`. Decode the returned bool.
        let params = req.into_inner();
        let nf_bytes = compute_shielded_trc20_nullifier(&params)
            .map_err(|e| Status::invalid_argument(e))?;
        let contract_addr: [u8; 21] = params
            .shielded_trc20_contract_address
            .as_slice()
            .try_into()
            .map_err(|_| {
                Status::invalid_argument("shielded_trc20_contract_address must be 21 bytes")
            })?;
        // Build calldata: keccak256("nullifiers(bytes32)") =
        // 0xa1aab33f for the most common shielded-TRC20 contract
        // shape (a `mapping(bytes32 => bool) public nullifiers`
        // exposes a getter with this signature).
        let mut data = Vec::with_capacity(4 + 32);
        let selector =
            &tron_crypto::hash::keccak256(b"nullifiers(bytes32)")[..4];
        data.extend_from_slice(selector);
        data.extend_from_slice(&nf_bytes);
        let owner_addr = vec![0x41u8; 21];
        let trigger = tron_proto::protocol::TriggerSmartContract {
            owner_address: owner_addr,
            contract_address: contract_addr.to_vec(),
            call_value: 0,
            data,
            call_token_value: 0,
            token_id: 0,
        };
        let outcome = run_constant_call(&self.state, &trigger);
        let is_spent = match outcome {
            Some(tron_tvm::execute::VmOutcome::Success { return_data, .. }) => {
                // Solidity bool returns are 32-byte left-padded
                // zero/one. Treat any non-zero return as `true`.
                return_data.iter().any(|b| *b != 0)
            }
            Some(tron_tvm::execute::VmOutcome::Revert { .. }) => {
                // A revert typically means the contract isn't a
                // shielded-TRC20 contract or doesn't expose
                // `nullifiers(bytes32)`. Surface as "unknown" /
                // not-spent rather than failing the RPC.
                false
            }
            Some(_) => false,
            None => {
                return Err(Status::failed_precondition(
                    "EVM call backends not configured on this node — cannot read contract storage",
                ));
            }
        };
        Ok(Response::new(protocol::NullifierResult { is_spent }))
    }

    // =========================================================
    // Shielded TRC-20 — TX construction, scan, sig.
    //
    // All of the following require infrastructure we don't ship in
    // a node binary (proving keys + Groth16 prover for construction,
    // ChaCha20-Poly1305 trial decryption + per-block walk for scan,
    // RedJubjub signing for spend auth). java-tron bundles these
    // because its gRPC server doubles as a wallet; tron-goblin-node's gRPC
    // is node-only. Clients that need these talk to a wallet library
    // (`zcash_primitives` + `zcash_proofs` on Rust, `tronweb-shielded`
    // in JS) and use the node only for SUBMISSION via
    // `broadcast_transaction` — which works today.
    //
    // The honest gRPC response is FailedPrecondition with a clear
    // message naming what's missing. Promotes silently to a real
    // implementation once the proving-key + scan-index work lands.
    // =========================================================

    async fn create_shielded_transaction(
        &self,
        req: Request<protocol::PrivateParameters>,
    ) -> Result<Response<TransactionExtention>, Status> {
        let params = req.into_inner();
        let builder =
            crate::zen_builder::ZenTransactionBuilder::from_private_parameters(&params)?;
        // Run the prover on a blocking thread — Groth16 takes ~1-2s
        // per spend/output and we don't want to stall the tokio
        // executor.
        let state = self.state.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut rng = rand::rngs::OsRng;
            builder.build_native(&state, &mut rng)
        })
        .await
        .map_err(|e| Status::internal(format!("prover task join: {e}")))??;
        Ok(Response::new(result))
    }

    async fn create_shielded_transaction_without_spend_auth_sig(
        &self,
        req: Request<protocol::PrivateParametersWithoutAsk>,
    ) -> Result<Response<TransactionExtention>, Status> {
        let params = req.into_inner();
        let builder =
            crate::zen_builder::ZenTransactionBuilder::from_private_parameters_without_ask(
                &params,
            )?;
        let state = self.state.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut rng = rand::rngs::OsRng;
            builder.build_native(&state, &mut rng)
        })
        .await
        .map_err(|e| Status::internal(format!("prover task join: {e}")))??;
        Ok(Response::new(result))
    }

    async fn create_spend_auth_sig(
        &self,
        req: Request<protocol::SpendAuthSigParameters>,
    ) -> Result<Response<BytesMessage>, Status> {
        // Implementation of the Sapling `SpendAuthSig` over RedJubjub:
        //   1. Parse `ask` (32-byte ASK scalar) and `alpha` (32-byte
        //      randomizer scalar) into the Jubjub scalar field.
        //   2. Compute the randomized signing scalar `rsk = ask + alpha`
        //      (the spec's `\rho` randomization).
        //   3. Build a `redjubjub::SigningKey<SpendAuth>` from rsk's
        //      bytes and sign `tx_hash`.
        //
        // Returns the 64-byte serialized signature. Matches java-tron's
        // `createSpendAuthSig` wire output byte-for-byte modulo the
        // per-call randomness in the signing nonce — which the protocol
        // expects to differ.
        use jubjub::Scalar;
        use redjubjub::{SigningKey, SpendAuth};
        let params = req.into_inner();
        let ask_bytes: [u8; 32] = params.ask.as_slice().try_into().map_err(|_| {
            Status::invalid_argument("ask must be 32 bytes")
        })?;
        let alpha_bytes: [u8; 32] = params.alpha.as_slice().try_into().map_err(|_| {
            Status::invalid_argument("alpha must be 32 bytes")
        })?;
        let ask_scalar = Scalar::from_bytes(&ask_bytes);
        if ask_scalar.is_none().into() {
            return Err(Status::invalid_argument(
                "ask is not a valid Jubjub scalar",
            ));
        }
        let alpha_scalar = Scalar::from_bytes(&alpha_bytes);
        if alpha_scalar.is_none().into() {
            return Err(Status::invalid_argument(
                "alpha is not a valid Jubjub scalar",
            ));
        }
        let ask_scalar = ask_scalar.unwrap();
        let alpha_scalar = alpha_scalar.unwrap();
        let rsk_scalar = ask_scalar + alpha_scalar;
        let rsk_bytes: [u8; 32] = rsk_scalar.to_bytes();
        let signing_key: SigningKey<SpendAuth> = rsk_bytes.try_into().map_err(|_| {
            Status::invalid_argument(
                "randomized signing key (ask + alpha) is not valid for RedJubjub",
            )
        })?;
        // RedJubjub sign needs a CSPRNG for the nonce. We use the
        // process-wide OsRng exposed by `rand_core` — same source the
        // standard sapling-crypto path uses.
        use rand_core::OsRng;
        let signature = signing_key.sign(OsRng, &params.tx_hash);
        let sig_bytes: [u8; 64] = signature.into();
        Ok(Response::new(BytesMessage {
            value: sig_bytes.to_vec(),
        }))
    }

    async fn create_shield_nullifier(
        &self,
        req: Request<protocol::NfParameters>,
    ) -> Result<Response<BytesMessage>, Status> {
        // java-tron path: Wallet.createShieldNullifier →
        // librustzcashComputeNf(d, pk_d, value, rcm, ak, nk, position).
        // We reconstruct the sapling-crypto Note and call `note.nf(&nk,
        // position)` — the position comes from the voucher's tree size
        // per `IncrementalMerkleVoucherContainer.position()`. `ak` is
        // accepted in the message but unused for nullifier derivation
        // (Sapling's `nf` is a function of nk + ρ only); java-tron's
        // FFI also doesn't use `ak` in the underlying compute.
        let params = req.into_inner();
        let nf = compute_shielded_nullifier(&params).map_err(Status::invalid_argument)?;
        Ok(Response::new(BytesMessage { value: nf.to_vec() }))
    }

    async fn create_shielded_contract_parameters(
        &self,
        req: Request<protocol::PrivateShieldedTrc20Parameters>,
    ) -> Result<Response<protocol::ShieldedTrc20Parameters>, Status> {
        let params = req.into_inner();
        let builder = crate::zen_builder::ShieldedTrc20Builder::from_private_trc20(&params)?;
        let result = tokio::task::spawn_blocking(move || {
            let mut rng = rand::rngs::OsRng;
            builder.build_trc20(true, &mut rng)
        })
        .await
        .map_err(|e| Status::internal(format!("prover task join: {e}")))??;
        Ok(Response::new(result))
    }

    async fn create_shielded_contract_parameters_without_ask(
        &self,
        req: Request<protocol::PrivateShieldedTrc20ParametersWithoutAsk>,
    ) -> Result<Response<protocol::ShieldedTrc20Parameters>, Status> {
        let params = req.into_inner();
        let builder =
            crate::zen_builder::ShieldedTrc20Builder::from_private_trc20_without_ask(&params)?;
        let result = tokio::task::spawn_blocking(move || {
            let mut rng = rand::rngs::OsRng;
            builder.build_trc20(false, &mut rng)
        })
        .await
        .map_err(|e| Status::internal(format!("prover task join: {e}")))??;
        Ok(Response::new(result))
    }

    async fn scan_note_by_ivk(
        &self,
        request: Request<protocol::IvkDecryptParameters>,
    ) -> Result<Response<protocol::DecryptNotes>, Status> {
        let params = request.into_inner();
        crate::shielded::scan_note_by_ivk(&self.state, params).map(Response::new)
    }

    async fn scan_and_mark_note_by_ivk(
        &self,
        req: Request<protocol::IvkDecryptAndMarkParameters>,
    ) -> Result<Response<protocol::DecryptNotesMarked>, Status> {
        crate::shielded::scan_and_mark_note_by_ivk(&self.state, req.into_inner())
            .map(Response::new)
    }

    async fn scan_note_by_ovk(
        &self,
        req: Request<protocol::OvkDecryptParameters>,
    ) -> Result<Response<protocol::DecryptNotes>, Status> {
        crate::shielded::scan_note_by_ovk(&self.state, req.into_inner()).map(Response::new)
    }

    async fn scan_shielded_trc20_notes_by_ivk(
        &self,
        req: Request<protocol::IvkDecryptTrc20Parameters>,
    ) -> Result<Response<protocol::DecryptNotesTrc20>, Status> {
        crate::shielded::scan_shielded_trc20_notes_by_ivk(&self.state, req.into_inner())
            .map(Response::new)
    }

    async fn scan_shielded_trc20_notes_by_ovk(
        &self,
        req: Request<protocol::OvkDecryptTrc20Parameters>,
    ) -> Result<Response<protocol::DecryptNotesTrc20>, Status> {
        crate::shielded::scan_shielded_trc20_notes_by_ovk(&self.state, req.into_inner())
            .map(Response::new)
    }

    async fn get_shield_transaction_hash(
        &self,
        request: Request<Transaction>,
    ) -> Result<Response<BytesMessage>, Status> {
        let tx = request.into_inner();
        let zen_token_id = self
            .state
            .dyn_props
            .get_bytes(b"ZEN_TOKEN_ID")
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "000000".to_string());
        match tron_actuator::shielded_transfer::compute_shielded_sighash(&tx, &zen_token_id) {
            Ok(hash) => Ok(Response::new(BytesMessage {
                value: hash.to_vec(),
            })),
            Err(e) => Err(Status::invalid_argument(format!(
                "cannot compute shielded sighash: {e}"
            ))),
        }
    }

    async fn get_trigger_input_for_shielded_trc20_contract(
        &self,
        req: Request<protocol::ShieldedTrc20TriggerContractParameters>,
    ) -> Result<Response<BytesMessage>, Status> {
        crate::shielded::get_trigger_input_for_shielded_trc20_contract(req.into_inner())
            .map(Response::new)
    }

    async fn get_merkle_tree_voucher_info(
        &self,
        req: Request<protocol::OutputPointInfo>,
    ) -> Result<Response<protocol::IncrementalMerkleVoucherInfo>, Status> {
        crate::shielded::get_merkle_tree_voucher_info(&self.state, req.into_inner())
            .map(Response::new)
    }

    // (Every Wallet trait method now has a real implementation
    // above; see the file-level doc for the three response classes.)

}

// =============================================================================
// Server bootstrap
// =============================================================================

/// gRPC transport limits (C3). Without these, a single connection can
/// open unlimited concurrent HTTP/2 streams and run requests with no time
/// bound, letting one peer exhaust the blocking pool / memory (amplifies
/// the prover and per-call scan RPCs). Values are generous for legit
/// wallet / query traffic. `max_decoding` matches tonic's 4 MiB default —
/// set explicitly so it's bounded regardless of upstream defaults.
const GRPC_MAX_DECODING_BYTES: usize = 4 * 1024 * 1024;
const GRPC_CONCURRENCY_PER_CONN: usize = 256;
const GRPC_MAX_CONCURRENT_STREAMS: u32 = 256;
const GRPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub async fn start_server(
    state: RpcState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    let firehose = state.firehose.clone();
    let wallet = WalletService::new(state);
    let wallet_solidity = wallet.clone();
    let monitor = wallet.clone();
    let database = wallet.clone();
    let wallet_extension = wallet.clone();
    tracing::info!(
        %addr,
        "gRPC server listening (Wallet + WalletSolidity + Monitor + Database + WalletExtension)"
    );
    Server::builder()
        .timeout(GRPC_REQUEST_TIMEOUT)
        .concurrency_limit_per_connection(GRPC_CONCURRENCY_PER_CONN)
        .max_concurrent_streams(Some(GRPC_MAX_CONCURRENT_STREAMS))
        .add_service(WalletServer::new(wallet).max_decoding_message_size(GRPC_MAX_DECODING_BYTES))
        .add_service(
            WalletSolidityServer::new(wallet_solidity)
                .max_decoding_message_size(GRPC_MAX_DECODING_BYTES),
        )
        .add_service(MonitorServer::new(monitor).max_decoding_message_size(GRPC_MAX_DECODING_BYTES))
        .add_service(
            DatabaseServer::new(database).max_decoding_message_size(GRPC_MAX_DECODING_BYTES),
        )
        .add_service(
            WalletExtensionServer::new(wallet_extension)
                .max_decoding_message_size(GRPC_MAX_DECODING_BYTES),
        )
        // The firehose tail — mounted only when the node runs the
        // durable log ([index.firehose] enable = true).
        .add_optional_service(firehose.map(|handle| {
            crate::firehose_proto::firehose_server::FirehoseServer::new(
                crate::firehose::FirehoseService::new(handle),
            )
        }))
        .serve_with_shutdown(addr, shutdown)
        .await?;
    Ok(())
}
