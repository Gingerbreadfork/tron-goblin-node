//! Sapling-based shielded gRPC helpers.
//!
//! Contains:
//!   * Stateless key-derivation helpers (`get_spending_key`,
//!     `get_ak_from_ask`, `get_nk_from_nsk`, `get_diversifier`,
//!     `get_incoming_viewing_key`, `get_zen_payment_address`,
//!     `get_rcm`, `get_new_shielded_address`).
//!   * Nullifier lookup: `is_spend` (block-walk + nullifier-store
//!     check), with the shared `locate_shielded_output_position`
//!     helper used by `is_spend` and `scanAndMarkNoteByIvk`.
//!   * Voucher witness construction: `get_merkle_tree_voucher_info`,
//!     built on top of `tron_tvm::shielded::IncrementalMerkleVoucher`.
//!   * Block scanners: `scan_note_by_ivk`, `scan_note_by_ovk`,
//!     `scan_and_mark_note_by_ivk`, plus TRC-20-event variants
//!     `scan_shielded_trc20_notes_by_ivk` / `_by_ovk`.
//!   * TRC-20 calldata builder: `get_trigger_input_for_shielded_trc20_contract`
//!     (pure byte-merging — pairs already-proved `ShieldedTrc20Parameters`
//!     with spend-auth signatures and packs into ABI-encoded contract
//!     calldata for the three operations MINT / TRANSFER / BURN).
//!
//! The proof-construction methods (`create_shielded_transaction*`,
//! `create_shielded_contract_parameters*`) use [`crate::prover`] which
//! lazy-loads the embedded ~50 MB Sapling MPC ceremony parameters from
//! the `wagyu-zcash-parameters` companion crate.

use blake2s_simd::Params as Blake2s;
use group::GroupEncoding;
use sapling_crypto::constants::{
    CRH_IVK_PERSONALIZATION, PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR,
};
use sapling_crypto::keys::{Diversifier, ExpandedSpendingKey, SaplingIvk};
use tonic::Status;
use tron_proto::protocol::{
    BytesMessage, DiversifierMessage, ExpandedSpendingKeyMessage,
    IncomingViewingKeyDiversifierMessage, IncomingViewingKeyMessage,
    PaymentAddressMessage, ShieldedAddressInfo, SpendResult, ViewingKeyMessage,
};

/// Fill `buf` with cryptographically-secure random bytes via the OS
/// entropy source. Mapped to `Status::internal` because CSPRNG
/// failure means the host's `/dev/urandom` (or equivalent) is broken.
fn fill_random(buf: &mut [u8]) -> Result<(), Status> {
    getrandom::getrandom(buf).map_err(|e| Status::internal(format!("CSPRNG: {e}")))
}

/// Reject the input if `bytes` is not exactly `expected` long.
fn check_len(bytes: &[u8], expected: usize, label: &str) -> Result<(), Status> {
    if bytes.len() != expected {
        Err(Status::invalid_argument(format!(
            "{label}: expected {expected} bytes, got {}",
            bytes.len()
        )))
    } else {
        Ok(())
    }
}

/// `getSpendingKey()` — generate a fresh 32-byte Sapling spending key
/// from the OS CSPRNG. Wallet helper; no chain state involved.
pub fn get_spending_key() -> Result<BytesMessage, Status> {
    let mut sk = [0u8; 32];
    fill_random(&mut sk)?;
    Ok(BytesMessage { value: sk.to_vec() })
}

/// `getExpandedSpendingKey(sk)` — derive `(ask, nsk, ovk)` from a
/// 32-byte spending key per ZIP-32 § 4. Returns the 96-byte
/// `ExpandedSpendingKey` serialization split into three 32-byte fields.
pub fn get_expanded_spending_key(sk: &[u8]) -> Result<ExpandedSpendingKeyMessage, Status> {
    check_len(sk, 32, "spending key")?;
    let esk = ExpandedSpendingKey::from_spending_key(sk);
    let bytes = esk.to_bytes();
    Ok(ExpandedSpendingKeyMessage {
        ask: bytes[..32].to_vec(),
        nsk: bytes[32..64].to_vec(),
        ovk: bytes[64..96].to_vec(),
    })
}

/// `getAkFromAsk(ask)` — `ak = ask * SPENDING_KEY_GENERATOR`. Returns
/// the 32-byte point encoding.
pub fn get_ak_from_ask(ask_bytes: &[u8]) -> Result<BytesMessage, Status> {
    check_len(ask_bytes, 32, "ask")?;
    let ask = parse_jubjub_scalar(ask_bytes, "ask")?;
    let ak = SPENDING_KEY_GENERATOR * ask;
    Ok(BytesMessage {
        value: ak.to_bytes().to_vec(),
    })
}

/// `getNkFromNsk(nsk)` — `nk = nsk * PROOF_GENERATION_KEY_GENERATOR`.
pub fn get_nk_from_nsk(nsk_bytes: &[u8]) -> Result<BytesMessage, Status> {
    check_len(nsk_bytes, 32, "nsk")?;
    let nsk = parse_jubjub_scalar(nsk_bytes, "nsk")?;
    let nk = PROOF_GENERATION_KEY_GENERATOR * nsk;
    Ok(BytesMessage {
        value: nk.to_bytes().to_vec(),
    })
}

/// `getIncomingViewingKey(ak, nk)` — `ivk = CRH^ivk(ak, nk)` with
/// the Blake2s personalization Zcash uses, then mask the high 5 bits
/// so the result lives in the Jubjub scalar field.
pub fn get_incoming_viewing_key(
    vk: ViewingKeyMessage,
) -> Result<IncomingViewingKeyMessage, Status> {
    check_len(&vk.ak, 32, "ak")?;
    check_len(&vk.nk, 32, "nk")?;
    let mut hasher = Blake2s::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state();
    hasher.update(&vk.ak);
    hasher.update(&vk.nk);
    let mut ivk = [0u8; 32];
    ivk.copy_from_slice(hasher.finalize().as_bytes());
    ivk[31] &= 0x07;
    Ok(IncomingViewingKeyMessage { ivk: ivk.to_vec() })
}

/// `getDiversifier()` — random 11-byte diversifier whose group-hash
/// lives on the Jubjub subgroup. Rejection-samples; ~half of random
/// 11-byte blobs are valid so this usually returns first try.
pub fn get_diversifier() -> Result<DiversifierMessage, Status> {
    for _ in 0..32 {
        let mut buf = [0u8; 11];
        fill_random(&mut buf)?;
        let d = Diversifier(buf);
        if d.g_d().is_some() {
            return Ok(DiversifierMessage { d: buf.to_vec() });
        }
    }
    Err(Status::internal(
        "failed to find a valid diversifier in 32 attempts (statistically impossible)",
    ))
}

/// `getZenPaymentAddress(ivk, d)` — derive the shielded payment
/// address `(d || pk_d)` from an incoming viewing key + diversifier.
pub fn get_zen_payment_address(
    req: IncomingViewingKeyDiversifierMessage,
) -> Result<PaymentAddressMessage, Status> {
    let ivk_msg = req
        .ivk
        .ok_or_else(|| Status::invalid_argument("missing ivk"))?;
    let d_msg = req
        .d
        .ok_or_else(|| Status::invalid_argument("missing diversifier"))?;
    check_len(&ivk_msg.ivk, 32, "ivk")?;
    check_len(&d_msg.d, 11, "diversifier")?;
    let mut ivk_arr = [0u8; 32];
    ivk_arr.copy_from_slice(&ivk_msg.ivk);
    let ivk_scalar = jubjub::Fr::from_bytes(&ivk_arr);
    let ivk_scalar = if ivk_scalar.is_some().into() {
        ivk_scalar.unwrap()
    } else {
        return Err(Status::invalid_argument("ivk not in scalar field"));
    };
    let ivk = SaplingIvk(ivk_scalar);
    let mut d_arr = [0u8; 11];
    d_arr.copy_from_slice(&d_msg.d);
    let diversifier = Diversifier(d_arr);
    let pa = ivk
        .to_payment_address(diversifier)
        .ok_or_else(|| Status::invalid_argument("diversifier does not produce a valid address for this ivk"))?;
    // `pk_d().to_bytes()` is pub(crate); reach the inner SubgroupPoint
    // and use GroupEncoding for serialization.
    let pkd_bytes = pa.pk_d().inner().to_bytes();
    // Payment address text form = base58check(d || pk_d) prefixed
    // with the Sapling network constant. java-tron returns the
    // hex of the 43-byte `d || pk_d` concatenation; mirror that.
    let mut concat = Vec::with_capacity(43);
    concat.extend_from_slice(&d_arr);
    concat.extend_from_slice(&pkd_bytes);
    Ok(PaymentAddressMessage {
        d: Some(DiversifierMessage { d: d_arr.to_vec() }),
        pk_d: pkd_bytes.to_vec(),
        payment_address: hex::encode(&concat),
    })
}

/// `getRcm()` — uniformly-sampled random scalar in the Jubjub Fr
/// field. The `rcm` (commitment randomness) every output description
/// needs. Rejection-samples to make sure the bytes land in the field.
pub fn get_rcm() -> Result<BytesMessage, Status> {
    for _ in 0..32 {
        let mut buf = [0u8; 32];
        fill_random(&mut buf)?;
        // Clear the high 5 bits — matches sapling-crypto's
        // `jubjub::Fr::random` rejection-sampling shortcut.
        buf[31] &= 0x07;
        let cand = jubjub::Fr::from_bytes(&buf);
        if cand.is_some().into() {
            return Ok(BytesMessage { value: buf.to_vec() });
        }
    }
    Err(Status::internal(
        "failed to sample rcm in 32 attempts (statistically impossible)",
    ))
}

/// `getNewShieldedAddress()` — full round-trip: fresh spending key,
/// derive every intermediate, sample a valid diversifier, build the
/// payment address. Single-call shortcut for wallets that want a
/// brand-new shielded recipient.
pub fn get_new_shielded_address() -> Result<ShieldedAddressInfo, Status> {
    let sk_msg = get_spending_key()?;
    let esk = get_expanded_spending_key(&sk_msg.value)?;
    let ak = get_ak_from_ask(&esk.ask)?;
    let nk = get_nk_from_nsk(&esk.nsk)?;
    let ivk = get_incoming_viewing_key(ViewingKeyMessage {
        ak: ak.value.clone(),
        nk: nk.value.clone(),
    })?;
    let d = get_diversifier()?;
    let pa = get_zen_payment_address(IncomingViewingKeyDiversifierMessage {
        ivk: Some(ivk.clone()),
        d: Some(d.clone()),
    })?;
    Ok(ShieldedAddressInfo {
        sk: sk_msg.value,
        ask: esk.ask,
        nsk: esk.nsk,
        ovk: esk.ovk,
        ak: ak.value,
        nk: nk.value,
        ivk: ivk.ivk,
        d: d.d,
        pk_d: pa.pk_d,
        payment_address: pa.payment_address,
    })
}

/// Parse a 32-byte little-endian scalar into the Jubjub `Fr` field.
/// Rejects values that exceed the field order.
fn parse_jubjub_scalar(bytes: &[u8], label: &str) -> Result<jubjub::Fr, Status> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let scalar = jubjub::Fr::from_bytes(&arr);
    if scalar.is_some().into() {
        Ok(scalar.unwrap())
    } else {
        Err(Status::invalid_argument(format!(
            "{label} not in Jubjub scalar field"
        )))
    }
}

/// `isSpend(noteParameters)` — membership check against the
/// `NullifierStore`. The note's nullifier is computed from the supplied
/// `(ak, nk)` viewing key + `note` + the note's merkle-tree position
/// (carried as `index` in the request) — but we don't currently track
/// per-note positions across the chain, so we accept the COMPUTED
/// `isSpend(NoteParameters)` — java-tron's `Wallet.isSpend`.
///
/// Algorithm:
///   1. Locate the output point `(txid, index)` by walking the chain
///      from block 1 to head, counting each shielded
///      `ReceiveDescription` as one global leaf position.
///   2. Derive the Sapling nullifier from `(note, nk, position)` via
///      our shared `derive_sapling_nullifier` core (the same path
///      `create_shield_nullifier` uses).
///   3. Look up the nullifier in [`NullifierStore`]. Present → spent.
///
/// Returns:
///   * `result=false, message="The input note does not exist"` if the
///     output point isn't found in chain history.
///   * `result=true, message="Input note has been spent"` if the
///     derived nullifier is in the store.
///   * `result=false, message="The input note is not spent or does
///     not exist"` otherwise — mirrors java-tron's exact wording.
///
/// The block-walk is O(blocks_with_shielded_tx) per call. TRON's
/// shielded TRX is essentially dormant on mainnet (no new
/// `ShieldedTransferContract` traffic for years), so the walk is
/// short in practice. A future indexer can replace this with an
/// O(1) `(txid, index) → position` lookup without changing the
/// public contract.
pub fn is_spend(
    state: &tron_rpc::RpcState,
    params: tron_proto::protocol::NoteParameters,
) -> Result<SpendResult, Status> {
    let note = params
        .note
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("missing note"))?;
    if params.txid.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "txid must be 32 bytes; got {}",
            params.txid.len()
        )));
    }
    if params.index < 0 {
        return Err(Status::invalid_argument("index must be non-negative"));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&params.txid);

    let Some(nullifiers) = state.nullifiers.as_ref() else {
        return Err(Status::failed_precondition(
            "node has no NullifierStore attached — cannot answer isSpend",
        ));
    };

    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let position = match locate_shielded_output_position(state, head, &txid, params.index) {
        Some(p) => p,
        None => {
            return Ok(SpendResult {
                result: false,
                message: "The input note does not exist".to_string(),
            });
        }
    };

    let nf = crate::service::derive_sapling_nullifier(
        &note.payment_address,
        note.value as u64,
        &note.rcm,
        &params.nk,
        position,
    )
    .map_err(Status::invalid_argument)?;

    let is_spent = nullifiers
        .contains(&nf)
        .map_err(|e| Status::internal(format!("nullifier read: {e}")))?;
    let message = if is_spent {
        "Input note has been spent"
    } else {
        "The input note is not spent or does not exist"
    };
    Ok(SpendResult {
        result: is_spent,
        message: message.to_string(),
    })
}

/// `getMerkleTreeVoucherInfo(OutputPointInfo)` — port of java-tron's
/// `Wallet.getMerkleTreeVoucherInfo`. For each requested output point
/// `(txid, index)`, builds an `IncrementalMerkleVoucher` that
/// witnesses inclusion of that note's commitment in the chain's
/// shielded-pool merkle tree.
///
/// Algorithm:
///   1. For each output point, find its host block by walking the
///      chain (we don't yet maintain java-tron's `TransactionStore.
///      getBlockNumber(txid)` index for shielded txs, so we walk).
///   2. `largeBlockNum = max(block_num)` across requested points.
///   3. Reject any output point whose block is more than 100 blocks
///      behind `largeBlockNum` — matches java-tron's hard-coded
///      window.
///   4. Build each witness by walking blocks `[1..=block_num]`,
///      appending commitments; snapshot when the target is reached;
///      continue appending later commitments in the same block.
///   5. Bring every "lower" witness up to `largeBlockNum`.
///   6. If `req.block_num != 0`, continue updating all witnesses
///      through `[largeBlockNum + 1, req.block_num]`.
///   7. Reset each voucher's `rt` to its current root, encode each
///      witness's merkle path, and return.
///
/// O(history × output_points) — TRON's shielded TRX traffic is
/// dormant, so the walks are short in practice.
pub fn get_merkle_tree_voucher_info(
    state: &tron_rpc::RpcState,
    req: tron_proto::protocol::OutputPointInfo,
) -> Result<tron_proto::protocol::IncrementalMerkleVoucherInfo, Status> {
    use tron_tvm::shielded::IncrementalMerkleVoucher;

    if req.out_points.is_empty() {
        return Err(Status::invalid_argument(
            "out_points must contain at least one entry",
        ));
    }

    // Resolve (txid, index) → host block_num.
    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let mut targets: Vec<TargetOutPoint> = Vec::with_capacity(req.out_points.len());
    let mut large_block_num: i64 = 0;
    for op in &req.out_points {
        if op.hash.len() != 32 {
            return Err(Status::invalid_argument(
                "out_point.hash must be 32 bytes",
            ));
        }
        if op.index < 0 {
            return Err(Status::invalid_argument(
                "out_point.index must be non-negative",
            ));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&op.hash);
        let block_num = find_block_for_shielded_txid(state, head, &txid).ok_or_else(|| {
            Status::not_found(format!(
                "tx is not found: {}",
                hex::encode(txid)
            ))
        })?;
        if block_num > large_block_num {
            large_block_num = block_num;
        }
        targets.push(TargetOutPoint {
            output_point: op.clone(),
            txid,
            target_index: op.index,
            block_num,
        });
    }

    // Hard 100-block window enforced by java-tron's
    // `getMerkleTreeVoucherInfo`. Avoid building witnesses that
    // span huge chain ranges in a single RPC call.
    for t in &targets {
        if t.block_num + 100 < large_block_num {
            return Err(Status::failed_precondition(format!(
                "block_num:{} + 100 < largeBlockNum:{}",
                t.block_num, large_block_num
            )));
        }
    }

    // Build each witness by walking from genesis through the host
    // block's commitments.
    let mut witnesses: Vec<IncrementalMerkleVoucher> = Vec::with_capacity(targets.len());
    for t in &targets {
        let w = build_witness_through_block(state, t)?;
        witnesses.push(w);
    }

    // Bring every witness up to `large_block_num` (in case some
    // targets sat in earlier blocks).
    for (witness, t) in witnesses.iter_mut().zip(targets.iter()) {
        update_witness_through_range(state, witness, t.block_num + 1, large_block_num)?;
    }

    // Optional sync window: continue through `[large + 1,
    // req.block_num]`.
    let sync_block_num = req.block_num as i64;
    if sync_block_num != 0 && sync_block_num > large_block_num {
        for witness in witnesses.iter_mut() {
            update_witness_through_range(
                state,
                witness,
                large_block_num + 1,
                sync_block_num,
            )?;
        }
    }

    // Encode the response.
    let mut vouchers = Vec::with_capacity(witnesses.len());
    let mut paths = Vec::with_capacity(witnesses.len());
    for (witness, t) in witnesses.iter().zip(targets.iter()) {
        vouchers.push(witness.to_proto_with_output_point(t.output_point.clone()));
        let path = witness
            .path()
            .ok_or_else(|| Status::internal("voucher has no path (snapshot tree is empty)"))?;
        paths.push(path.encode());
    }
    Ok(tron_proto::protocol::IncrementalMerkleVoucherInfo { vouchers, paths })
}

struct TargetOutPoint {
    output_point: tron_proto::protocol::OutputPoint,
    txid: [u8; 32],
    target_index: i32,
    block_num: i64,
}

/// Walk the chain looking for a `ShieldedTransferContract` with
/// `txid` matching `target`. Returns the host block number.
fn find_block_for_shielded_txid(
    state: &tron_rpc::RpcState,
    head: i64,
    target: &[u8; 32],
) -> Option<i64> {
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;

    for num in 1..=head {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            if &tx_id != target {
                continue;
            }
            // Must be a ShieldedTransferContract.
            for contract in &raw.contract {
                if contract.r#type
                    == ContractType::ShieldedTransferContract as i32
                {
                    return Some(num);
                }
            }
        }
    }
    None
}

/// Build a fresh witness for `target.output_point` by walking blocks
/// `[1..=target.block_num]`, appending every commitment to a running
/// tree, snapshotting when the target is reached, then continuing
/// to extend the witness through the rest of that block.
fn build_witness_through_block(
    state: &tron_rpc::RpcState,
    target: &TargetOutPoint,
) -> Result<tron_tvm::shielded::IncrementalMerkleVoucher, Status> {
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;
    use tron_proto::ShieldedTransferContract;
    use tron_tvm::shielded::{IncrementalMerkleTree, IncrementalMerkleVoucher};

    let mut tree = IncrementalMerkleTree::default();
    let mut witness: Option<IncrementalMerkleVoucher> = None;

    for num in 1..=target.block_num {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            for contract in &raw.contract {
                if contract.r#type != ContractType::ShieldedTransferContract as i32 {
                    continue;
                }
                let Some(any) = &contract.parameter else { continue };
                let Ok(stc) =
                    ShieldedTransferContract::decode(any.value.as_slice())
                else {
                    continue;
                };
                let is_target_tx = tx_id == target.txid;
                if is_target_tx {
                    if target.target_index as usize >= stc.receive_description.len() {
                        return Err(Status::out_of_range(format!(
                            "out_point.index:{} >= receive_description.len():{}",
                            target.target_index,
                            stc.receive_description.len()
                        )));
                    }
                }
                for (idx, rd) in stc.receive_description.iter().enumerate() {
                    let cm = parse_commitment(&rd.note_commitment)?;
                    if is_target_tx && idx as i32 == target.target_index {
                        // Append target to the tree, then snapshot.
                        tree.append(cm).map_err(|e| {
                            Status::internal(format!("tree append: {e}"))
                        })?;
                        let w = IncrementalMerkleVoucher::from_tree(tree.clone());
                        // Continue with any later commitments in this
                        // same tx — they extend the witness.
                        // The remaining receives in this tx contribute
                        // after we return; loop continues to handle
                        // them. Mark `witness` and let the rest of
                        // the loop append to it.
                        witness = Some(w);
                    } else {
                        match witness.as_mut() {
                            Some(w) => w.append(cm).map_err(|e| {
                                Status::internal(format!("witness append: {e}"))
                            })?,
                            None => tree.append(cm).map_err(|e| {
                                Status::internal(format!("tree append: {e}"))
                            })?,
                        }
                    }
                }
            }
        }
    }
    witness.ok_or_else(|| {
        Status::not_found(format!(
            "commitment not found for tx {} index {}",
            hex::encode(target.txid),
            target.target_index
        ))
    })
}

/// Extend an existing witness through blocks `[start_block, end_block]`
/// inclusive, appending every shielded receive commitment.
fn update_witness_through_range(
    state: &tron_rpc::RpcState,
    witness: &mut tron_tvm::shielded::IncrementalMerkleVoucher,
    start_block: i64,
    end_block: i64,
) -> Result<(), Status> {
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;
    use tron_proto::ShieldedTransferContract;

    if start_block > end_block {
        return Ok(());
    }
    for num in start_block..=end_block {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            for contract in &raw.contract {
                if contract.r#type != ContractType::ShieldedTransferContract as i32 {
                    continue;
                }
                let Some(any) = &contract.parameter else { continue };
                let Ok(stc) =
                    ShieldedTransferContract::decode(any.value.as_slice())
                else {
                    continue;
                };
                for rd in &stc.receive_description {
                    let cm = parse_commitment(&rd.note_commitment)?;
                    witness.append(cm).map_err(|e| {
                        Status::internal(format!("witness append at block {num}: {e}"))
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn parse_commitment(bytes: &[u8]) -> Result<[u8; 32], Status> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Status::internal("note_commitment must be 32 bytes"))?;
    Ok(arr)
}

/// Walk blocks `[1..=head]` looking for the receive description at
/// `(target_txid, target_output_index)`. Returns the leaf position
/// (count of preceding `ReceiveDescription`s across all shielded
/// transactions) when found.
///
/// java-tron does an equivalent O(blocks) walk in `Wallet.createWitness`
/// for the witness construction — we apply the same walk just to
/// count up to the target.
pub fn locate_shielded_output_position(
    state: &tron_rpc::RpcState,
    head: i64,
    target_txid: &[u8; 32],
    target_output_index: i32,
) -> Option<u64> {
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;
    use tron_proto::ShieldedTransferContract;

    let mut position: u64 = 0;
    for num in 1..=head {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            for contract in &raw.contract {
                if contract.r#type != ContractType::ShieldedTransferContract as i32 {
                    continue;
                }
                let Some(any) = &contract.parameter else { continue };
                let Ok(stc) = ShieldedTransferContract::decode(any.value.as_slice())
                else {
                    continue;
                };
                for (idx, _rd) in stc.receive_description.iter().enumerate() {
                    if tx_id == *target_txid && idx as i32 == target_output_index {
                        return Some(position);
                    }
                    position = position.saturating_add(1);
                }
            }
        }
    }
    None
}

// =============================================================================
// scanNoteByIvk — block-walk + trial decrypt of ShieldedTransferContract
// =============================================================================
//
// Mirrors java-tron's `Wallet.scanNoteByIvk`: walk
// `[start_block_index, end_block_index)`, look at every
// `ShieldedTransferContract` in every transaction, try to decrypt each
// `ReceiveDescription` under the user-supplied `ivk`, and surface the
// hits as a list of `(note, txid, index_within_receive_descs)`.

use group::ff::PrimeField;
use prost::Message as _;
use sapling_crypto::keys::PreparedIncomingViewingKey;
use sapling_crypto::note_encryption::{
    try_sapling_note_decryption, SaplingDomain, Zip212Enforcement,
};
use sapling_crypto::value::NoteValue;
use sapling_crypto::Note;
use tron_proto::protocol::{decrypt_notes::NoteTx, DecryptNotes, IvkDecryptParameters, Note as NoteProto};
use tron_rpc::RpcState;
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, ENC_CIPHERTEXT_SIZE};

/// Maximum block range one call can scan. Matches java-tron's hard
/// cap; bigger ranges should be paginated by the caller.
const MAX_SCAN_RANGE: i64 = 1000;

/// Trial-decrypt every Sapling note in `[start, end)` under `ivk`.
/// Returns a [`DecryptNotes`] populated with one entry per matched
/// `ReceiveDescription`.
pub fn scan_note_by_ivk(
    state: &RpcState,
    params: IvkDecryptParameters,
) -> Result<DecryptNotes, Status> {
    if params.end_block_index < params.start_block_index {
        return Err(Status::invalid_argument(
            "end_block_index must be >= start_block_index",
        ));
    }
    if params.end_block_index - params.start_block_index > MAX_SCAN_RANGE {
        return Err(Status::invalid_argument(format!(
            "scan range too large (max {MAX_SCAN_RANGE} blocks)"
        )));
    }
    if params.ivk.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "ivk must be 32 bytes, got {}",
            params.ivk.len()
        )));
    }
    // Parse the raw 32-byte ivk as a jubjub scalar. java-tron stores
    // the ivk as a little-endian field element (matches sapling-crypto's
    // `Fr::from_repr` convention).
    let mut ivk_bytes = [0u8; 32];
    ivk_bytes.copy_from_slice(&params.ivk);
    let ivk_scalar = jubjub::Fr::from_repr(ivk_bytes);
    if bool::from(ivk_scalar.is_none()) {
        return Err(Status::invalid_argument("ivk is not a valid jubjub scalar"));
    }
    let sapling_ivk = SaplingIvk(ivk_scalar.unwrap());
    let prepared = PreparedIncomingViewingKey::new(&sapling_ivk);

    // Snap end_block_index to the current head to avoid spinning past
    // the chain tip. java-tron does the same defensively.
    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let end = params.end_block_index.min(head + 1);

    let mut note_txs = Vec::new();
    for num in params.start_block_index..end {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            for contract in &raw.contract {
                if contract.r#type
                    != tron_proto::transaction::contract::ContractType::ShieldedTransferContract
                        as i32
                {
                    continue;
                }
                let Some(any) = &contract.parameter else { continue };
                let Ok(stc) =
                    tron_proto::ShieldedTransferContract::decode(any.value.as_slice())
                else {
                    continue;
                };
                for (idx, rd) in stc.receive_description.iter().enumerate() {
                    let output = match ReceiveDescriptionView::try_from(rd) {
                        Ok(o) => o,
                        Err(_) => continue, // malformed: skip silently
                    };
                    // ZIP-212 enforcement: TRON's Sapling fork doesn't
                    // strictly enforce ZIP-212 (it was a Zcash NU3
                    // upgrade), but the GracePeriod mode accepts both
                    // pre- and post-ZIP-212 notes — the safe default
                    // for a chain that's never explicitly enforced.
                    if let Some((note, payment_addr, memo)) = try_sapling_note_decryption(
                        &prepared,
                        &output,
                        Zip212Enforcement::GracePeriod,
                    ) {
                        note_txs.push(NoteTx {
                            note: Some(note_to_proto(&note, &payment_addr, &memo)),
                            txid: tx_id.to_vec(),
                            index: idx as i32,
                        });
                    }
                }
            }
        }
    }
    Ok(DecryptNotes { note_txs })
}

/// Adapter: presents a [`tron_proto::ReceiveDescription`] as a
/// `ShieldedOutput<SaplingDomain, ENC_CIPHERTEXT_SIZE>` for
/// sapling-crypto's trial-decryption API.
struct ReceiveDescriptionView<'a> {
    epk: [u8; 32],
    cmu: [u8; 32],
    c_enc: &'a [u8],
}

impl<'a> TryFrom<&'a tron_proto::ReceiveDescription> for ReceiveDescriptionView<'a> {
    type Error = &'static str;
    fn try_from(rd: &'a tron_proto::ReceiveDescription) -> Result<Self, Self::Error> {
        if rd.epk.len() != 32 {
            return Err("epk must be 32 bytes");
        }
        if rd.note_commitment.len() != 32 {
            return Err("note_commitment must be 32 bytes");
        }
        if rd.c_enc.len() != ENC_CIPHERTEXT_SIZE {
            return Err("c_enc wrong length");
        }
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&rd.epk);
        let mut cmu = [0u8; 32];
        cmu.copy_from_slice(&rd.note_commitment);
        Ok(Self {
            epk,
            cmu,
            c_enc: &rd.c_enc,
        })
    }
}

impl<'a> ShieldedOutput<SaplingDomain, ENC_CIPHERTEXT_SIZE> for ReceiveDescriptionView<'a> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu
    }
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        self.c_enc.try_into().expect("checked in TryFrom")
    }
}

// =============================================================================
// scanNoteByOvk — block-walk + OutCiphertext recovery
// =============================================================================
//
// Like `scanNoteByIvk` but uses the OUTGOING viewing key path:
// `try_sapling_output_recovery` opens the 80-byte out_ciphertext to
// recover `(esk, pk_d)`, then decrypts the regular ciphertext to
// reveal the note. Used by senders who want to scan blocks for
// notes THEY created (not received).

/// Trial-recover every Sapling output in `[start, end)` under `ovk`.
pub fn scan_note_by_ovk(
    state: &RpcState,
    params: tron_proto::protocol::OvkDecryptParameters,
) -> Result<DecryptNotes, Status> {
    use sapling_crypto::bundle::OutputDescription;
    use sapling_crypto::keys::OutgoingViewingKey;
    use sapling_crypto::note::ExtractedNoteCommitment;
    use sapling_crypto::note_encryption::try_sapling_output_recovery;
    use sapling_crypto::value::ValueCommitment;

    if params.end_block_index < params.start_block_index {
        return Err(Status::invalid_argument(
            "end_block_index must be >= start_block_index",
        ));
    }
    if params.end_block_index - params.start_block_index > MAX_SCAN_RANGE {
        return Err(Status::invalid_argument(format!(
            "scan range too large (max {MAX_SCAN_RANGE} blocks)"
        )));
    }
    if params.ovk.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "ovk must be 32 bytes, got {}",
            params.ovk.len()
        )));
    }
    let mut ovk_bytes = [0u8; 32];
    ovk_bytes.copy_from_slice(&params.ovk);
    let ovk = OutgoingViewingKey(ovk_bytes);

    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let end = params.end_block_index.min(head + 1);

    let mut note_txs = Vec::new();
    for num in params.start_block_index..end {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            for contract in &raw.contract {
                if contract.r#type
                    != tron_proto::transaction::contract::ContractType::ShieldedTransferContract
                        as i32
                {
                    continue;
                }
                let Some(any) = &contract.parameter else { continue };
                let Ok(stc) =
                    tron_proto::ShieldedTransferContract::decode(any.value.as_slice())
                else {
                    continue;
                };
                for (idx, rd) in stc.receive_description.iter().enumerate() {
                    // Build a typed OutputDescription. Sapling's
                    // `try_sapling_output_recovery` wants the full
                    // bundle shape, not raw bytes.
                    if rd.value_commitment.len() != 32
                        || rd.note_commitment.len() != 32
                        || rd.epk.len() != 32
                        || rd.c_enc.len() != ENC_CIPHERTEXT_SIZE
                        || rd.c_out.len() != 80
                    {
                        continue; // malformed: skip
                    }
                    let cv_bytes: [u8; 32] = rd.value_commitment.as_slice().try_into().unwrap();
                    let cv = match Option::<ValueCommitment>::from(
                        ValueCommitment::from_bytes_not_small_order(&cv_bytes),
                    ) {
                        Some(cv) => cv,
                        None => continue,
                    };
                    let cmu_bytes: [u8; 32] =
                        rd.note_commitment.as_slice().try_into().unwrap();
                    let cmu = match Option::<ExtractedNoteCommitment>::from(
                        ExtractedNoteCommitment::from_bytes(&cmu_bytes),
                    ) {
                        Some(cmu) => cmu,
                        None => continue,
                    };
                    let epk_bytes: [u8; 32] = rd.epk.as_slice().try_into().unwrap();
                    let mut enc_ct = [0u8; ENC_CIPHERTEXT_SIZE];
                    enc_ct.copy_from_slice(&rd.c_enc);
                    let mut out_ct = [0u8; 80];
                    out_ct.copy_from_slice(&rd.c_out);
                    // OutputDescription::from_parts needs a zkproof
                    // value; the recovery API only consumes the
                    // bundle's cv/cmu/epk/enc/out fields, so a
                    // placeholder zkproof is fine.
                    let placeholder_proof: [u8; 192] = [0u8; 192];
                    let output: OutputDescription<[u8; 192]> = OutputDescription::from_parts(
                        cv,
                        cmu,
                        EphemeralKeyBytes(epk_bytes),
                        enc_ct,
                        out_ct,
                        placeholder_proof,
                    );
                    if let Some((note, payment_addr, memo)) = try_sapling_output_recovery(
                        &ovk,
                        &output,
                        Zip212Enforcement::GracePeriod,
                    ) {
                        note_txs.push(NoteTx {
                            note: Some(note_to_proto(&note, &payment_addr, &memo)),
                            txid: tx_id.to_vec(),
                            index: idx as i32,
                        });
                    }
                }
            }
        }
    }
    Ok(DecryptNotes { note_txs })
}

// =============================================================================
// scanAndMarkNoteByIvk — scanNoteByIvk + spent-flag annotation
// =============================================================================
//
// Same trial decryption as `scanNoteByIvk`, but for each matched note
// also computes its nullifier (with `ak`, `nk`, and the leaf
// position) and checks the NullifierStore. The output is
// `DecryptNotesMarked`, where each note carries an `is_spent` bool
// plus the computed nullifier.

/// Trial-decrypt every Sapling note in `[start, end)` under `ivk`
/// AND determine whether each is spent by querying the NullifierStore.
pub fn scan_and_mark_note_by_ivk(
    state: &RpcState,
    params: tron_proto::protocol::IvkDecryptAndMarkParameters,
) -> Result<tron_proto::protocol::DecryptNotesMarked, Status> {
    use tron_proto::protocol::{decrypt_notes_marked::NoteTx as MarkedNoteTx, DecryptNotesMarked};

    if params.end_block_index < params.start_block_index {
        return Err(Status::invalid_argument(
            "end_block_index must be >= start_block_index",
        ));
    }
    if params.end_block_index - params.start_block_index > MAX_SCAN_RANGE {
        return Err(Status::invalid_argument(format!(
            "scan range too large (max {MAX_SCAN_RANGE} blocks)"
        )));
    }
    if params.ivk.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "ivk must be 32 bytes, got {}",
            params.ivk.len()
        )));
    }
    if params.ak.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "ak must be 32 bytes, got {}",
            params.ak.len()
        )));
    }
    if params.nk.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "nk must be 32 bytes, got {}",
            params.nk.len()
        )));
    }
    let Some(nullifiers) = state.nullifiers.as_ref() else {
        return Err(Status::failed_precondition(
            "scanAndMarkNoteByIvk requires a NullifierStore — not attached on this node",
        ));
    };
    let mut ivk_bytes = [0u8; 32];
    ivk_bytes.copy_from_slice(&params.ivk);
    let ivk_scalar = jubjub::Fr::from_repr(ivk_bytes);
    if bool::from(ivk_scalar.is_none()) {
        return Err(Status::invalid_argument("ivk is not a valid jubjub scalar"));
    }
    let sapling_ivk = SaplingIvk(ivk_scalar.unwrap());
    let prepared = PreparedIncomingViewingKey::new(&sapling_ivk);

    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let end = params.end_block_index.min(head + 1);

    // We track the global leaf position by walking ALL blocks from
    // genesis up to `end` and counting receive commitments — same
    // approach as `locate_shielded_output_position`. Inside the
    // `[start, end)` window we additionally trial-decrypt each
    // receive.
    let mut note_txs: Vec<MarkedNoteTx> = Vec::new();
    let mut global_position: u64 = 0;
    let scan_start = params.start_block_index;
    let walk_start = 1i64; // need positions from genesis to be correct
    for num in walk_start..end {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            for contract in &raw.contract {
                if contract.r#type
                    != tron_proto::transaction::contract::ContractType::ShieldedTransferContract
                        as i32
                {
                    continue;
                }
                let Some(any) = &contract.parameter else { continue };
                let Ok(stc) =
                    tron_proto::ShieldedTransferContract::decode(any.value.as_slice())
                else {
                    continue;
                };
                let in_scan_window = num >= scan_start;
                for (idx, rd) in stc.receive_description.iter().enumerate() {
                    let leaf_position = global_position;
                    global_position = global_position.saturating_add(1);
                    if !in_scan_window {
                        continue;
                    }
                    let output = match ReceiveDescriptionView::try_from(rd) {
                        Ok(o) => o,
                        Err(_) => continue,
                    };
                    if let Some((note, payment_addr, memo)) = try_sapling_note_decryption(
                        &prepared,
                        &output,
                        Zip212Enforcement::GracePeriod,
                    ) {
                        // Derive this note's nullifier with the
                        // caller-supplied nk + leaf_position. Mirrors
                        // java-tron's `Note.nullifier(ak, nk, pos)`.
                        use group::GroupEncoding;
                        use sapling_crypto::keys::NullifierDerivingKey;
                        let nk_arr: [u8; 32] = params.nk.as_slice().try_into().unwrap();
                        let nk_point = jubjub::SubgroupPoint::from_bytes(&nk_arr);
                        let is_spent = if bool::from(nk_point.is_some()) {
                            let nk = NullifierDerivingKey(nk_point.unwrap());
                            let nf = note.nf(&nk, leaf_position);
                            nullifiers
                                .contains(&nf.0)
                                .map_err(|e| Status::internal(format!("nullifier read: {e}")))?
                        } else {
                            false
                        };
                        note_txs.push(MarkedNoteTx {
                            note: Some(note_to_proto(&note, &payment_addr, &memo)),
                            txid: tx_id.to_vec(),
                            index: idx as i32,
                            is_spend: is_spent,
                        });
                    }
                }
            }
        }
    }
    Ok(DecryptNotesMarked { note_txs })
}

// =============================================================================
// scanShieldedTrc20NotesByIvk / scanShieldedTrc20NotesByOvk
// =============================================================================
//
// Shielded TRC-20 emits events from a contract whose storage tracks
// merkle commitments and nullifiers. The scan walks block logs for
// the configured contract address and trial-decrypts each event's
// embedded ciphertext.
//
// java-tron uses log topics to identify the event types
// (`NoteSpent`, `MintNewLeaf`, `BurnNewLeaf`, etc.) and event data
// to extract `(epk, cv, cmu, c_enc, c_out, position)`. The output
// proto `DecryptNotesTrc20` matches `DecryptNotes` plus per-note
// position and `txid_string`.
//
// Our chain history doesn't yet ship with a populated log index
// keyed by contract address, so the scan walks every block in the
// range and inspects the SmartContractResult logs directly. That
// works for tests + lightly-used contracts; production would gate
// behind a log-bloom prefilter.

/// Trial-decrypt every shielded-TRC-20 note event in `[start, end)`
/// under `ivk`.
pub fn scan_shielded_trc20_notes_by_ivk(
    state: &RpcState,
    params: tron_proto::protocol::IvkDecryptTrc20Parameters,
) -> Result<tron_proto::protocol::DecryptNotesTrc20, Status> {
    if params.end_block_index < params.start_block_index {
        return Err(Status::invalid_argument(
            "end_block_index must be >= start_block_index",
        ));
    }
    if params.end_block_index - params.start_block_index > MAX_SCAN_RANGE {
        return Err(Status::invalid_argument(format!(
            "scan range too large (max {MAX_SCAN_RANGE} blocks)"
        )));
    }
    if params.shielded_trc20_contract_address.len() != 21 {
        return Err(Status::invalid_argument(
            "shielded_trc20_contract_address must be 21 bytes",
        ));
    }
    if params.ivk.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "ivk must be 32 bytes, got {}",
            params.ivk.len()
        )));
    }
    if params.ak.len() != 32 || params.nk.len() != 32 {
        return Err(Status::invalid_argument(
            "ak and nk must each be 32 bytes",
        ));
    }
    let Some(tx_history) = state.tx_history.as_ref() else {
        return Err(Status::failed_precondition(
            "scanShieldedTrc20NotesByIvk requires the TransactionHistoryStore — not attached on this node",
        ));
    };
    let mut ivk_bytes = [0u8; 32];
    ivk_bytes.copy_from_slice(&params.ivk);
    let ivk_scalar = jubjub::Fr::from_repr(ivk_bytes);
    if bool::from(ivk_scalar.is_none()) {
        return Err(Status::invalid_argument("ivk is not a valid jubjub scalar"));
    }
    let sapling_ivk = SaplingIvk(ivk_scalar.unwrap());
    let prepared = PreparedIncomingViewingKey::new(&sapling_ivk);

    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let end = params.end_block_index.min(head + 1);

    let mut hits = Vec::new();
    for num in params.start_block_index..end {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            let Ok(Some(info)) = tx_history.get(&tx_id) else { continue };
            for event in extract_shielded_trc20_events_from_info(
                &info,
                &params.shielded_trc20_contract_address,
            ) {
                let Some(output) = event.as_receive_view() else { continue };
                if let Some((note, payment_addr, memo)) = try_sapling_note_decryption(
                    &prepared,
                    &output,
                    Zip212Enforcement::GracePeriod,
                ) {
                    hits.push(tron_proto::protocol::decrypt_notes_trc20::NoteTx {
                        note: Some(note_to_proto(&note, &payment_addr, &memo)),
                        position: event.position as i64,
                        is_spent: false, // would require a nullifier-check helper
                        txid: tx_id.to_vec(),
                        index: event.event_index as i32,
                        to_amount: String::new(),
                        transparent_to_address: Vec::new(),
                    });
                }
            }
        }
    }
    Ok(tron_proto::protocol::DecryptNotesTrc20 { note_txs: hits })
}

/// OVK-keyed shielded-TRC-20 scanner.
pub fn scan_shielded_trc20_notes_by_ovk(
    state: &RpcState,
    params: tron_proto::protocol::OvkDecryptTrc20Parameters,
) -> Result<tron_proto::protocol::DecryptNotesTrc20, Status> {
    use sapling_crypto::bundle::OutputDescription;
    use sapling_crypto::keys::OutgoingViewingKey;
    use sapling_crypto::note::ExtractedNoteCommitment;
    use sapling_crypto::note_encryption::try_sapling_output_recovery;
    use sapling_crypto::value::ValueCommitment;

    if params.end_block_index < params.start_block_index {
        return Err(Status::invalid_argument(
            "end_block_index must be >= start_block_index",
        ));
    }
    if params.end_block_index - params.start_block_index > MAX_SCAN_RANGE {
        return Err(Status::invalid_argument(format!(
            "scan range too large (max {MAX_SCAN_RANGE} blocks)"
        )));
    }
    if params.shielded_trc20_contract_address.len() != 21 {
        return Err(Status::invalid_argument(
            "shielded_trc20_contract_address must be 21 bytes",
        ));
    }
    if params.ovk.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "ovk must be 32 bytes, got {}",
            params.ovk.len()
        )));
    }
    let Some(tx_history) = state.tx_history.as_ref() else {
        return Err(Status::failed_precondition(
            "scanShieldedTrc20NotesByOvk requires the TransactionHistoryStore — not attached on this node",
        ));
    };
    let mut ovk_bytes = [0u8; 32];
    ovk_bytes.copy_from_slice(&params.ovk);
    let ovk = OutgoingViewingKey(ovk_bytes);

    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let end = params.end_block_index.min(head + 1);

    let mut hits = Vec::new();
    for num in params.start_block_index..end {
        let Ok(block_id) = state.block_index.get(num) else {
            continue;
        };
        let Ok(block) = state.blocks.get(&block_id) else {
            continue;
        };
        for tx in &block.transactions {
            let Some(raw) = &tx.raw_data else { continue };
            let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
            let Ok(Some(info)) = tx_history.get(&tx_id) else { continue };
            for event in extract_shielded_trc20_events_from_info(
                &info,
                &params.shielded_trc20_contract_address,
            ) {
                let Some(cv_bytes) = event.cv_bytes else { continue };
                let cv = match Option::<ValueCommitment>::from(
                    ValueCommitment::from_bytes_not_small_order(&cv_bytes),
                ) {
                    Some(cv) => cv,
                    None => continue,
                };
                let cmu = match Option::<ExtractedNoteCommitment>::from(
                    ExtractedNoteCommitment::from_bytes(&event.cmu_bytes),
                ) {
                    Some(cmu) => cmu,
                    None => continue,
                };
                let mut enc_ct = [0u8; ENC_CIPHERTEXT_SIZE];
                enc_ct.copy_from_slice(&event.c_enc);
                let Some(c_out_bytes) = event.c_out.as_ref() else { continue };
                let mut out_ct = [0u8; 80];
                out_ct.copy_from_slice(c_out_bytes);
                let placeholder_proof: [u8; 192] = [0u8; 192];
                let output: OutputDescription<[u8; 192]> = OutputDescription::from_parts(
                    cv,
                    cmu,
                    EphemeralKeyBytes(event.epk_bytes),
                    enc_ct,
                    out_ct,
                    placeholder_proof,
                );
                if let Some((note, payment_addr, memo)) = try_sapling_output_recovery(
                    &ovk,
                    &output,
                    Zip212Enforcement::GracePeriod,
                ) {
                    hits.push(tron_proto::protocol::decrypt_notes_trc20::NoteTx {
                        note: Some(note_to_proto(&note, &payment_addr, &memo)),
                        position: event.position as i64,
                        is_spent: false,
                        txid: tx_id.to_vec(),
                        index: event.event_index as i32,
                        to_amount: String::new(),
                        transparent_to_address: Vec::new(),
                    });
                }
            }
        }
    }
    Ok(tron_proto::protocol::DecryptNotesTrc20 { note_txs: hits })
}

/// A shielded-TRC-20 note event extracted from a tx's contract log.
/// Java-tron's shielded TRC-20 contract emits NoteMint / NoteSpend
/// events whose data is the concatenation of fixed-width fields. We
/// represent the parsed fields in this struct.
struct ShieldedTrc20Event {
    /// 32-byte ephemeral key.
    epk_bytes: [u8; 32],
    /// 32-byte note commitment (cmu).
    cmu_bytes: [u8; 32],
    /// ENC_CIPHERTEXT_SIZE-byte encrypted note ciphertext.
    c_enc: Vec<u8>,
    /// 80-byte outgoing ciphertext, when present.
    c_out: Option<Vec<u8>>,
    /// 32-byte value commitment, when present.
    cv_bytes: Option<[u8; 32]>,
    /// Leaf position (relative to the contract's tree).
    position: u64,
    /// Event index within the host transaction's log list.
    event_index: usize,
}

impl ShieldedTrc20Event {
    fn as_receive_view(&self) -> Option<ReceiveDescriptionView<'_>> {
        if self.c_enc.len() != ENC_CIPHERTEXT_SIZE {
            return None;
        }
        Some(ReceiveDescriptionView {
            epk: self.epk_bytes,
            cmu: self.cmu_bytes,
            c_enc: &self.c_enc,
        })
    }
}

/// Walk `info.log` looking for shielded-TRC-20 events emitted by
/// `contract_address`. Each event's `data` packs:
///   `position(u64 BE) || epk(32) || cmu(32) [|| cv(32)] || c_enc(580) [|| c_out(80)]`
/// The `cv` and `c_out` segments are optional — when absent, OVK
/// scanning silently skips that event (only IVK can decrypt without
/// them). `contract_address` is the 21-byte TRON address.
fn extract_shielded_trc20_events_from_info(
    info: &tron_proto::TransactionInfo,
    contract_address: &[u8],
) -> Vec<ShieldedTrc20Event> {
    // TVM log addresses are 20-byte Ethereum-style. TRON addresses are
    // 21-byte (`0x41` prefix + 20 bytes). Compare on the trailing 20
    // bytes when the caller supplies a 21-byte TRON address.
    let target_20: Vec<u8> = if contract_address.len() == 21 {
        contract_address[1..].to_vec()
    } else {
        contract_address.to_vec()
    };
    let mut events = Vec::new();
    {
        for (event_index, log) in info.log.iter().enumerate() {
            if log.address != target_20 {
                continue;
            }
            // Each shielded note event's `data` packs:
            //   position (8 bytes, big-endian)
            // | epk (32)
            // | cmu (32)
            // | cv  (32, optional — when missing, only IVK scans work)
            // | c_enc (580)
            // | c_out (80, optional — when missing, only IVK scans work)
            // We parse defensively: any prefix of the above counts.
            const POS_LEN: usize = 8;
            const HASH_LEN: usize = 32;
            const ENC_LEN: usize = ENC_CIPHERTEXT_SIZE;
            const OUT_LEN: usize = 80;
            let data = &log.data;
            // Minimum payload: position + epk + cmu + c_enc.
            const MIN_LEN: usize = POS_LEN + HASH_LEN + HASH_LEN + ENC_LEN;
            if data.len() < MIN_LEN {
                continue;
            }
            let mut offset = 0;
            let mut pos_bytes = [0u8; POS_LEN];
            pos_bytes.copy_from_slice(&data[offset..offset + POS_LEN]);
            offset += POS_LEN;
            let position = u64::from_be_bytes(pos_bytes);

            let mut epk = [0u8; HASH_LEN];
            epk.copy_from_slice(&data[offset..offset + HASH_LEN]);
            offset += HASH_LEN;
            let mut cmu = [0u8; HASH_LEN];
            cmu.copy_from_slice(&data[offset..offset + HASH_LEN]);
            offset += HASH_LEN;

            // Optional cv comes before c_enc when the payload is long
            // enough to include cv + c_enc together.
            let (cv_bytes, c_enc_offset) = if data.len() >= offset + HASH_LEN + ENC_LEN {
                let mut cv = [0u8; HASH_LEN];
                cv.copy_from_slice(&data[offset..offset + HASH_LEN]);
                (Some(cv), offset + HASH_LEN)
            } else {
                (None, offset)
            };
            if data.len() < c_enc_offset + ENC_LEN {
                continue;
            }
            let c_enc = data[c_enc_offset..c_enc_offset + ENC_LEN].to_vec();
            let after_enc = c_enc_offset + ENC_LEN;

            // Optional c_out tail.
            let c_out = if data.len() >= after_enc + OUT_LEN {
                Some(data[after_enc..after_enc + OUT_LEN].to_vec())
            } else {
                None
            };

            events.push(ShieldedTrc20Event {
                epk_bytes: epk,
                cmu_bytes: cmu,
                c_enc,
                c_out,
                cv_bytes,
                position,
                event_index,
            });
        }
    }
    events
}

/// Render a decrypted Sapling note into the wire-format [`NoteProto`].
fn note_to_proto(
    note: &Note,
    payment_addr: &sapling_crypto::PaymentAddress,
    memo: &[u8; 512],
) -> NoteProto {
    // Memo is right-padded with zeros; strip trailing zero bytes for
    // display (matches java-tron's `Note.parseFrom` post-processing).
    let trimmed_memo: Vec<u8> = memo
        .iter()
        .rposition(|b| *b != 0)
        .map(|last| memo[..=last].to_vec())
        .unwrap_or_default();
    // Payment address text form mirrors `get_zen_payment_address`:
    // hex of `(d || pk_d)` (43 bytes, 86 hex chars).
    let mut concat = Vec::with_capacity(43);
    concat.extend_from_slice(payment_addr.diversifier().0.as_ref());
    concat.extend_from_slice(&payment_addr.pk_d().inner().to_bytes());
    NoteProto {
        value: NoteValue::inner(&note.value()) as i64,
        payment_address: hex::encode(&concat),
        rcm: note.rcm().to_repr().to_vec(),
        memo: trimmed_memo,
    }
}

// =============================================================================
// getTriggerInputForShieldedTrc20Contract — ABI-encode already-proved
// ShieldedTrc20Parameters into contract calldata.
// =============================================================================
//
// Port of `Wallet.getTriggerInputForShieldedTRC20Contract` + the three
// `ShieldedTRC20ParametersBuilder.*ParamsToHexString` encoders. Pure
// byte-merging — no cryptography here. The caller has already
// constructed the proofs via `createShieldedContractParameters`; this
// method just packs them in the layout the shielded-TRC-20 Solidity
// contract expects.

const SAPLING_SPEND_DESCRIPTION_LEN: usize = 32 + 32 + 32 + 32 + 192;
const SAPLING_RECEIVE_DESCRIPTION_LEN: usize = 32 + 32 + 32 + 192;
const SAPLING_CIPHERTEXT_PAYLOAD_LEN: usize = 580 + 80 + 12;

pub fn get_trigger_input_for_shielded_trc20_contract(
    params: tron_proto::protocol::ShieldedTrc20TriggerContractParameters,
) -> Result<BytesMessage, Status> {
    let Some(p) = params.shielded_trc20_parameters.as_ref() else {
        return Err(Status::invalid_argument(
            "shielded_trc20_parameters missing",
        ));
    };
    let spend_auth_sigs = &params.spend_authority_signature;
    if p.spend_description.len() != spend_auth_sigs.len() {
        return Err(Status::invalid_argument(
            "spend_description and spend_authority_signature must be the same length",
        ));
    }
    let amount = parse_unsigned_decimal(&params.amount)?;
    let transparent_to_tvm = if params.transparent_to_address.is_empty() {
        [0u8; 20]
    } else if params.transparent_to_address.len() == 21 {
        let mut a = [0u8; 20];
        a.copy_from_slice(&params.transparent_to_address[1..]);
        a
    } else {
        return Err(Status::invalid_argument(
            "transparent_to_address must be 21 bytes (0x41 prefix)",
        ));
    };

    let bytes = match p.parameter_type.as_str() {
        "mint" => mint_params_to_bytes(p, amount)?,
        "transfer" => transfer_params_to_bytes(p, spend_auth_sigs, false)?,
        "burn" => burn_params_to_bytes(p, spend_auth_sigs, amount, &transparent_to_tvm, false)?,
        other => {
            return Err(Status::invalid_argument(format!(
                "unknown parameter_type '{other}' (must be mint, transfer, or burn)"
            )))
        }
    };
    Ok(BytesMessage { value: bytes })
}

/// Parse a decimal string into a non-negative 256-bit value (java-tron's
/// `getBigIntegerFromString` + `checkBigIntegerRange`).
fn parse_unsigned_decimal(s: &str) -> Result<u128, Status> {
    if s.is_empty() {
        return Ok(0);
    }
    s.parse::<u128>().map_err(|e| {
        Status::invalid_argument(format!("amount must be a non-negative decimal: {e}"))
    })
}

/// Big-endian 32-byte representation of `n` (zero-padded high).
fn u128_to_be_32(n: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&n.to_be_bytes());
    out
}

/// Big-endian 32-byte representation of a u64 (java-tron's `longTo32Bytes`).
fn u64_to_be_32(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

/// MINT: pack `(value, cmu, cv, epk, zkproof, binding_sig, c_enc, c_out, zeros[12])`
/// from the first receive description. Length: 32 + (32+32+32+192) +
/// 64 + 580 + 80 + 12 = 32 + 288 + 64 + 580 + 80 + 12 = 1056.
fn mint_params_to_bytes(
    p: &tron_proto::protocol::ShieldedTrc20Parameters,
    value: u128,
) -> Result<Vec<u8>, Status> {
    if value == 0 {
        return Err(Status::invalid_argument(
            "mint value must be positive",
        ));
    }
    let rd = p
        .receive_description
        .first()
        .ok_or_else(|| Status::invalid_argument("mint requires a receive description"))?;
    check_len(&rd.note_commitment, 32, "note_commitment")?;
    check_len(&rd.value_commitment, 32, "value_commitment")?;
    check_len(&rd.epk, 32, "epk")?;
    check_len(&rd.zkproof, 192, "zkproof")?;
    check_len(&p.binding_signature, 64, "binding_signature")?;
    check_len(&rd.c_enc, 580, "c_enc")?;
    check_len(&rd.c_out, 80, "c_out")?;

    let mut out = Vec::with_capacity(32 + 288 + 64 + 580 + 80 + 12);
    out.extend_from_slice(&u128_to_be_32(value));
    out.extend_from_slice(&rd.note_commitment);
    out.extend_from_slice(&rd.value_commitment);
    out.extend_from_slice(&rd.epk);
    out.extend_from_slice(&rd.zkproof);
    out.extend_from_slice(&p.binding_signature);
    out.extend_from_slice(&rd.c_enc);
    out.extend_from_slice(&rd.c_out);
    out.extend_from_slice(&[0u8; 12]);
    Ok(out)
}

/// TRANSFER: ABI-style packed with offset table for dynamic arrays
/// (spend list, spend-auth-sig list, receive list, ciphertext list).
/// Mirrors java-tron's `transferParamsToHexString`.
fn transfer_params_to_bytes(
    p: &tron_proto::protocol::ShieldedTrc20Parameters,
    spend_auth_sigs: &[BytesMessage],
    with_ask: bool,
) -> Result<Vec<u8>, Status> {
    let spend_count = p.spend_description.len() as u64;
    if !(1..=2).contains(&spend_count) {
        return Err(Status::invalid_argument(
            "transfer requires 1 or 2 spends",
        ));
    }
    let receive_count = p.receive_description.len() as u64;
    check_len(&p.binding_signature, 64, "binding_signature")?;

    // Validate spend description widths.
    for sd in &p.spend_description {
        check_len(&sd.nullifier, 32, "spend.nullifier")?;
        check_len(&sd.anchor, 32, "spend.anchor")?;
        check_len(&sd.value_commitment, 32, "spend.value_commitment")?;
        check_len(&sd.rk, 32, "spend.rk")?;
        check_len(&sd.zkproof, 192, "spend.zkproof")?;
        if with_ask {
            check_len(&sd.spend_authority_signature, 64, "spend.spend_auth_sig")?;
        }
    }
    if !with_ask {
        for sig in spend_auth_sigs {
            check_len(&sig.value, 64, "spend_authority_signature")?;
        }
    }
    for rd in &p.receive_description {
        check_len(&rd.note_commitment, 32, "receive.note_commitment")?;
        check_len(&rd.value_commitment, 32, "receive.value_commitment")?;
        check_len(&rd.epk, 32, "receive.epk")?;
        check_len(&rd.zkproof, 192, "receive.zkproof")?;
        check_len(&rd.c_enc, 580, "receive.c_enc")?;
        check_len(&rd.c_out, 80, "receive.c_out")?;
    }

    let input_offset = 192u64;
    let auth_offset = 192 + 32 + SAPLING_SPEND_DESCRIPTION_LEN as u64 * spend_count;
    let output_offset = auth_offset + 32 + 64 * spend_count;
    let c_offset = output_offset + 32 + SAPLING_RECEIVE_DESCRIPTION_LEN as u64 * receive_count;

    let mut out = Vec::new();
    out.extend_from_slice(&u64_to_be_32(input_offset));
    out.extend_from_slice(&u64_to_be_32(auth_offset));
    out.extend_from_slice(&u64_to_be_32(output_offset));
    out.extend_from_slice(&p.binding_signature);
    out.extend_from_slice(&u64_to_be_32(c_offset));

    // input section: <count><spends...>.
    out.extend_from_slice(&u64_to_be_32(spend_count));
    for sd in &p.spend_description {
        out.extend_from_slice(&sd.nullifier);
        out.extend_from_slice(&sd.anchor);
        out.extend_from_slice(&sd.value_commitment);
        out.extend_from_slice(&sd.rk);
        out.extend_from_slice(&sd.zkproof);
    }
    // spend-auth-sig section: <count><sigs...>.
    out.extend_from_slice(&u64_to_be_32(spend_count));
    if with_ask {
        for sd in &p.spend_description {
            out.extend_from_slice(&sd.spend_authority_signature);
        }
    } else {
        for sig in spend_auth_sigs {
            out.extend_from_slice(&sig.value);
        }
    }
    // output section: <count><receives...>.
    out.extend_from_slice(&u64_to_be_32(receive_count));
    for rd in &p.receive_description {
        out.extend_from_slice(&rd.note_commitment);
        out.extend_from_slice(&rd.value_commitment);
        out.extend_from_slice(&rd.epk);
        out.extend_from_slice(&rd.zkproof);
    }
    // ciphertext section: <count><c_enc|c_out|zeros[12] ...>.
    out.extend_from_slice(&u64_to_be_32(receive_count));
    for rd in &p.receive_description {
        out.extend_from_slice(&rd.c_enc);
        out.extend_from_slice(&rd.c_out);
        out.extend_from_slice(&[0u8; 12]);
    }
    Ok(out)
}

/// BURN: pack `(spendDesc, spendAuthSig, value, bindingSig, payTo,
/// burnCipher, zeros[16])` + optional receive-description tail.
fn burn_params_to_bytes(
    p: &tron_proto::protocol::ShieldedTrc20Parameters,
    spend_auth_sigs: &[BytesMessage],
    value: u128,
    transparent_to_tvm: &[u8; 20],
    with_ask: bool,
) -> Result<Vec<u8>, Status> {
    if value == 0 {
        return Err(Status::invalid_argument(
            "burn value must be positive",
        ));
    }
    if transparent_to_tvm == &[0u8; 20] {
        return Err(Status::invalid_argument(
            "transparent_to_address must be non-empty for burn",
        ));
    }
    let sd = p
        .spend_description
        .first()
        .ok_or_else(|| Status::invalid_argument("burn requires a spend description"))?;
    check_len(&sd.nullifier, 32, "spend.nullifier")?;
    check_len(&sd.anchor, 32, "spend.anchor")?;
    check_len(&sd.value_commitment, 32, "spend.value_commitment")?;
    check_len(&sd.rk, 32, "spend.rk")?;
    check_len(&sd.zkproof, 192, "spend.zkproof")?;
    check_len(&p.binding_signature, 64, "binding_signature")?;
    let spend_auth_sig = if with_ask {
        check_len(&sd.spend_authority_signature, 64, "spend.spend_auth_sig")?;
        sd.spend_authority_signature.as_slice()
    } else {
        let s = spend_auth_sigs
            .first()
            .ok_or_else(|| Status::invalid_argument("burn requires spend_authority_signature"))?;
        check_len(&s.value, 64, "spend_authority_signature")?;
        s.value.as_slice()
    };

    // Burn ciphertext (80 bytes) hex-encoded in `trigger_contract_input`.
    let burn_cipher = if p.trigger_contract_input.is_empty() {
        Vec::new()
    } else {
        let decoded = hex::decode(&p.trigger_contract_input).map_err(|e| {
            Status::invalid_argument(format!(
                "burn trigger_contract_input must be hex: {e}"
            ))
        })?;
        if decoded.len() != 80 {
            return Err(Status::invalid_argument(format!(
                "burn ciphertext must be 80 bytes, got {}",
                decoded.len()
            )));
        }
        decoded
    };

    // payTo = [0; 11] || 0x41 || transparent_to_tvm. Java pads with a
    // 12-byte zero prefix and writes the address-prefix at index 11.
    let mut pay_to = [0u8; 32];
    pay_to[11] = 0x41;
    pay_to[12..32].copy_from_slice(transparent_to_tvm);

    let mut merged: Vec<u8> = Vec::new();
    merged.extend_from_slice(&sd.nullifier);
    merged.extend_from_slice(&sd.anchor);
    merged.extend_from_slice(&sd.value_commitment);
    merged.extend_from_slice(&sd.rk);
    merged.extend_from_slice(&sd.zkproof);
    merged.extend_from_slice(spend_auth_sig);
    merged.extend_from_slice(&u128_to_be_32(value));
    merged.extend_from_slice(&p.binding_signature);
    merged.extend_from_slice(&pay_to);
    if !burn_cipher.is_empty() {
        merged.extend_from_slice(&burn_cipher);
        merged.extend_from_slice(&[0u8; 16]);
    }

    let receive_count = p.receive_description.len();
    let mut tail = Vec::new();
    if receive_count == 0 {
        let output_offset = merged.len() as u64 + 32 * 2;
        let output_count = 0u64;
        let c_offset = merged.len() as u64 + 32 * 3;
        let count_bytes = 0u64;
        tail.extend_from_slice(&u64_to_be_32(output_offset));
        tail.extend_from_slice(&u64_to_be_32(c_offset));
        tail.extend_from_slice(&u64_to_be_32(output_count));
        tail.extend_from_slice(&u64_to_be_32(count_bytes));
    } else {
        let output_offset = merged.len() as u64 + 32 * 2;
        let output_count = 1u64;
        let c_offset = merged.len() as u64 + 32 * 3 + 32 * 9;
        let count_bytes = 1u64;
        let rd = p
            .receive_description
            .first()
            .expect("checked receive_count > 0");
        check_len(&rd.note_commitment, 32, "receive.note_commitment")?;
        check_len(&rd.value_commitment, 32, "receive.value_commitment")?;
        check_len(&rd.epk, 32, "receive.epk")?;
        check_len(&rd.zkproof, 192, "receive.zkproof")?;
        check_len(&rd.c_enc, 580, "receive.c_enc")?;
        check_len(&rd.c_out, 80, "receive.c_out")?;
        tail.extend_from_slice(&u64_to_be_32(output_offset));
        tail.extend_from_slice(&u64_to_be_32(c_offset));
        tail.extend_from_slice(&u64_to_be_32(output_count));
        tail.extend_from_slice(&rd.note_commitment);
        tail.extend_from_slice(&rd.value_commitment);
        tail.extend_from_slice(&rd.epk);
        tail.extend_from_slice(&rd.zkproof);
        tail.extend_from_slice(&u64_to_be_32(count_bytes));
        tail.extend_from_slice(&rd.c_enc);
        tail.extend_from_slice(&rd.c_out);
        tail.extend_from_slice(&[0u8; 12]);
    }
    merged.extend_from_slice(&tail);
    Ok(merged)
}

// Suppress dead_code warning on the constant — used implicitly via
// the offset math in transfer_params_to_bytes.
#[allow(dead_code)]
const _: () = {
    assert!(SAPLING_CIPHERTEXT_PAYLOAD_LEN == 580 + 80 + 12);
};

#[cfg(test)]
mod scan_tests {
    use super::*;
    use std::sync::Arc;
    use tron_chainbase::{
        AccountStore, BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend,
        MemBackend, TransactionStore,
    };
    use tron_proto::{
        block_header::Raw as BlockHeaderRaw, transaction::contract::ContractType,
        transaction::Contract as TxContract, transaction::Raw as TxRaw, Block, BlockHeader,
        ReceiveDescription, ShieldedTransferContract, Transaction,
    };
    use tron_rpc::MAINNET_CHAIN_ID;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    /// Build an RpcState with one block at num=1 containing a single
    /// transaction whose ShieldedTransferContract has one
    /// ReceiveDescription. Returns (state, ivk_bytes, expected_value).
    fn fixture_with_shielded_block() -> (RpcState, [u8; 32], u64) {
        use rand::SeedableRng;
        use sapling_crypto::keys::{Diversifier, ExpandedSpendingKey};
        use sapling_crypto::note::Rseed;
        use sapling_crypto::note_encryption::sapling_note_encryption;

        // Deterministic CSPRNG so the test is reproducible.
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Derive a Sapling key, fvk, ivk.
        let sk_bytes = [0x11u8; 32];
        let esk = ExpandedSpendingKey::from_spending_key(&sk_bytes);
        let vk = esk.proof_generation_key().to_viewing_key();
        let ivk = vk.ivk();
        let ivk_bytes = ivk.to_repr();

        // Find a diversifier that produces a valid payment address.
        // Try a few canonical ones — `[0u8;11]` and ascending bytes
        // usually work.
        let payment_addr = (0u8..255)
            .find_map(|seed| {
                let mut d = [0u8; 11];
                d[0] = seed;
                let diversifier = Diversifier(d);
                ivk.to_payment_address(diversifier)
            })
            .expect("found a valid payment address");

        // Build a fresh note: value 1234 sun, fresh rseed.
        let value = NoteValue::from_raw(1234);
        let mut rseed_bytes = [0u8; 32];
        use rand::RngCore as _;
        rng.fill_bytes(&mut rseed_bytes);
        let note = Note::from_parts(payment_addr, value, Rseed::AfterZip212(rseed_bytes));

        // Encrypt the note: produces (epk, c_enc).
        let encryption = sapling_note_encryption(None, note.clone(), [0u8; 512], &mut rng);
        let c_enc = encryption.encrypt_note_plaintext();
        // We need epk bytes for the ReceiveDescription.
        let epk_bytes = {
            use zcash_note_encryption::Domain as _;
            SaplingDomain::epk_bytes(encryption.epk()).0.to_vec()
        };
        let cmu_bytes = note.cmu().to_bytes();

        // Build a ShieldedTransferContract with this one receive desc.
        let stc = ShieldedTransferContract {
            transparent_from_address: vec![],
            from_amount: 0,
            transparent_to_address: vec![],
            to_amount: 0,
            binding_signature: vec![0u8; 64],
            spend_description: vec![],
            receive_description: vec![ReceiveDescription {
                value_commitment: vec![0u8; 32],
                note_commitment: cmu_bytes.to_vec(),
                epk: epk_bytes,
                c_enc: c_enc.to_vec(),
                c_out: vec![0u8; 80],
                zkproof: vec![0u8; 192],
            }],
        };
        use prost::Message as _;
        let mut any_value = Vec::with_capacity(stc.encoded_len());
        stc.encode(&mut any_value).unwrap();
        let any = prost_types::Any {
            type_url: "type.googleapis.com/protocol.ShieldedTransferContract".into(),
            value: any_value,
        };
        let tx = Transaction {
            raw_data: Some(TxRaw {
                contract: vec![TxContract {
                    r#type: ContractType::ShieldedTransferContract as i32,
                    parameter: Some(any),
                    ..Default::default()
                }],
                timestamp: 1_700_000_000_000,
                ..Default::default()
            }),
            signature: vec![],
            ret: vec![],
            unparsed_field10: None,
        };

        let block = Block {
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: 1,
                    parent_hash: vec![0u8; 32],
                    timestamp: 1_700_000_000_000,
                    witness_address: vec![0x41u8; 21],
                    tx_trie_root: tron_types::calc_tx_trie_root(&[tx.clone()])
                        .map(|h| h.to_vec())
                        .unwrap_or_default(),
                    ..Default::default()
                }),
                witness_signature: vec![],
            }),
            transactions: vec![tx],
        };
        let block_id = tron_types::block_id_from_block(&block).unwrap();

        // Wire it into a fresh RpcState.
        let blocks_be = mem();
        let block_index_be = mem();
        let dp_be = mem();
        BlockStore::new(blocks_be.clone()).put(&block_id, &block).unwrap();
        BlockIndexStore::new(block_index_be.clone()).put(&block_id).unwrap();
        let dp = DynamicPropertiesStore::new(dp_be.clone());
        dp.save_latest_block_header_number(1);
        dp.save_latest_block_header_hash(block_id.as_bytes());
        let _ = (
            AccountStore::new(mem()),
            TransactionStore::new(mem()),
        );

        let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, MAINNET_CHAIN_ID);
        (state, ivk_bytes, 1234)
    }

    #[test]
    fn scan_finds_a_decryptable_note() {
        let (state, ivk_bytes, expected_value) = fixture_with_shielded_block();
        let params = IvkDecryptParameters {
            start_block_index: 1,
            end_block_index: 2,
            ivk: ivk_bytes.to_vec(),
        };
        let result = scan_note_by_ivk(&state, params).expect("scan");
        assert_eq!(result.note_txs.len(), 1, "expected exactly one decrypted note");
        let nt = &result.note_txs[0];
        assert_eq!(nt.index, 0);
        let note = nt.note.as_ref().expect("note");
        assert_eq!(note.value, expected_value as i64);
        assert_eq!(note.rcm.len(), 32);
        assert!(
            note.payment_address.len() == 86,
            "payment_address is hex of (d || pk_d), 86 hex chars; got {}",
            note.payment_address.len()
        );
    }

    #[test]
    fn scan_returns_empty_for_wrong_ivk() {
        let (state, _correct_ivk, _) = fixture_with_shielded_block();
        // A different valid scalar — won't decrypt the note.
        let wrong_ivk = [0x22u8; 32];
        // Ensure it's a valid scalar; if not, try another seed.
        let mut ivk_bytes = wrong_ivk;
        if bool::from(jubjub::Fr::from_repr(ivk_bytes).is_none()) {
            ivk_bytes[31] = 0; // top byte 0 keeps us in range
        }
        let params = IvkDecryptParameters {
            start_block_index: 1,
            end_block_index: 2,
            ivk: ivk_bytes.to_vec(),
        };
        let result = scan_note_by_ivk(&state, params).expect("scan");
        assert_eq!(
            result.note_txs.len(),
            0,
            "wrong ivk should not decrypt the seeded note"
        );
    }

    #[test]
    fn scan_rejects_invalid_ivk_length() {
        let (state, _, _) = fixture_with_shielded_block();
        let params = IvkDecryptParameters {
            start_block_index: 1,
            end_block_index: 2,
            ivk: vec![0u8; 31],
        };
        let err = scan_note_by_ivk(&state, params).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn scan_rejects_oversized_range() {
        let (state, ivk, _) = fixture_with_shielded_block();
        let params = IvkDecryptParameters {
            start_block_index: 0,
            end_block_index: 5_000, // > MAX_SCAN_RANGE
            ivk: ivk.to_vec(),
        };
        let err = scan_note_by_ivk(&state, params).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("scan range too large"));
    }

    #[test]
    fn scan_with_empty_block_range_returns_empty() {
        let (state, ivk, _) = fixture_with_shielded_block();
        let params = IvkDecryptParameters {
            start_block_index: 100,
            end_block_index: 110, // beyond head; we clamp end to head+1 → no blocks
            ivk: ivk.to_vec(),
        };
        let result = scan_note_by_ivk(&state, params).expect("scan");
        assert_eq!(result.note_txs.len(), 0);
    }
}
