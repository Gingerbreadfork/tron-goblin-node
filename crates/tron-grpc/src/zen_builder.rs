//! Port of java-tron's `ZenTransactionBuilder` and
//! `ShieldedTRC20ParametersBuilder`. Orchestrates the per-spend /
//! per-output proving primitives in [`crate::prover`] into a
//! complete shielded transaction (native shielded TRX) or shielded
//! TRC-20 parameter set.
//!
//! Pipeline (native, `build_native`):
//!   1. Decode `PrivateParameters` / `PrivateParametersWithoutAsk`
//!      into a list of `SpendBuildInfo` + `ReceiveBuildInfo`.
//!   2. Run the prover for each spend / output, getting wire-ready
//!      `SpendDescription` + `ReceiveDescription` byte tuples and
//!      the running `bsk` accumulator.
//!   3. Wrap the contract in an unsigned `Transaction` (with header
//!      from chain tip + the caller-supplied `timeout`).
//!   4. Compute the shielded-tx sighash via
//!      `tron_actuator::shielded_transfer::compute_shielded_sighash`.
//!   5. When `with_ask`: sign each spend's `(ask, alpha, sighash)`
//!      → `spend_authority_signature`.
//!   6. Compute `binding_sig(sighash)` from the prover.
//!   7. Repack the contract with the populated sig fields and return
//!      the final `Transaction`.

use std::convert::TryInto;

use group::GroupEncoding;
use prost::Message as _;
use rand_core::{CryptoRng, RngCore};
use sapling_crypto::keys::OutgoingViewingKey;
use sapling_crypto::{Diversifier, MerklePath, Node, PaymentAddress, ProofGenerationKey};
use tonic::Status;
use tron_proto::protocol::{
    PrivateParameters, PrivateParametersWithoutAsk, ReceiveNote, SpendNote, TransactionExtention,
};
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::Contract as TxContract;
use tron_proto::{ReceiveDescription, ShieldedTransferContract, SpendDescription};
use tron_rpc::RpcState;

use crate::prover::SaplingProver;

/// Inputs the builder needs for ONE spend. Mirrors java-tron's
/// `SpendDescriptionInfo`.
pub struct SpendBuildInfo {
    pub ak: [u8; 32],
    pub nsk: [u8; 32],
    pub diversifier: Diversifier,
    pub value: u64,
    pub rcm: jubjub::Fr,
    pub alpha: jubjub::Fr,
    pub anchor: [u8; 32],
    pub merkle_path: MerklePath,
}

/// Inputs the builder needs for ONE output.
pub struct ReceiveBuildInfo {
    pub ovk: OutgoingViewingKey,
    pub payment_address: PaymentAddress,
    pub value: u64,
    pub memo: [u8; 512],
    pub rcm: jubjub::Fr,
}

/// Stateful builder. Accumulates spends/outputs + value-balance
/// before `build_native` packs them into a final `Transaction`.
pub struct ZenTransactionBuilder {
    transparent_from_address: Vec<u8>,
    from_amount: i64,
    transparent_to_address: Vec<u8>,
    to_amount: i64,
    spends: Vec<SpendBuildInfo>,
    receives: Vec<ReceiveBuildInfo>,
    /// `value_balance = Σ spend_values + from_amount − Σ receive_values − to_amount`.
    /// Tracked here for the binding-sig prover input (java-tron sets
    /// it on the BindingSigParams) but the actual binding signature
    /// derives it from the prover's `bsk` instead, so this is
    /// informational.
    value_balance: i64,
    /// Caller-supplied timeout (seconds). `0` keeps the
    /// `builder::DEFAULT_EXPIRATION_MS` default.
    timeout_seconds: i64,
    /// Optional ask scalars (one per spend) kept in step with
    /// `spends`. `None` for the `withoutSpendAuthSig` flow.
    asks: Vec<Option<[u8; 32]>>,
}

impl ZenTransactionBuilder {
    pub fn new() -> Self {
        Self {
            transparent_from_address: Vec::new(),
            from_amount: 0,
            transparent_to_address: Vec::new(),
            to_amount: 0,
            spends: Vec::new(),
            receives: Vec::new(),
            value_balance: 0,
            timeout_seconds: 0,
            asks: Vec::new(),
        }
    }

    /// Decode `PrivateParameters` (with-ask flow). Derives
    /// `(ak, nsk)` from the supplied `ask`+`nsk` and remembers
    /// `ask` for the later spend-auth-sig step.
    pub fn from_private_parameters(params: &PrivateParameters) -> Result<Self, Status> {
        let mut b = Self::new();
        b.timeout_seconds = params.timeout;
        b.transparent_from_address = params.transparent_from_address.clone();
        b.from_amount = params.from_amount;
        b.transparent_to_address = params.transparent_to_address.clone();
        b.to_amount = params.to_amount;

        let has_ask = !params.ask.is_empty();
        let has_transparent_from = !params.transparent_from_address.is_empty();
        // A shielded-source tx needs ALL of (ask, nsk, ovk); a
        // transparent-only-source skips them. Match java-tron.
        if !has_ask && !has_transparent_from {
            return Err(Status::invalid_argument(
                "no input source (need either ask+nsk+ovk or transparent_from_address)",
            ));
        }
        let has_shielded_spends = !params.shielded_spends.is_empty();
        let has_shielded_receives = !params.shielded_receives.is_empty();

        let ask: Option<[u8; 32]> = if has_ask {
            Some(parse_bytes_32(&params.ask, "ask")?)
        } else {
            if has_shielded_spends {
                return Err(Status::invalid_argument(
                    "shielded_spends requires `ask` (with-ask flow)",
                ));
            }
            None
        };
        // `nsk` is needed for any shielded spend (to derive nf via nk = nsk*G).
        let nsk_opt: Option<jubjub::Fr> = if has_shielded_spends {
            Some(parse_scalar_32(&params.nsk, "nsk")?)
        } else {
            None
        };
        // `ovk` is needed for any shielded receive (output ciphertext recovery).
        let ovk_opt: Option<[u8; 32]> = if has_shielded_receives {
            Some(parse_bytes_32(&params.ovk, "ovk")?)
        } else {
            None
        };

        if has_shielded_spends {
            let ak = ak_from_ask(&ask.expect("checked above"))?;
            let nsk = nsk_opt.expect("checked above");
            for spend in &params.shielded_spends {
                b.add_spend(ak, nsk, spend, ask)?;
            }
        }
        if let Some(ovk) = ovk_opt {
            for recv in &params.shielded_receives {
                b.add_receive(OutgoingViewingKey(ovk), recv)?;
            }
        }
        Ok(b)
    }

    /// Decode `PrivateParametersWithoutAsk`. The caller provides
    /// `ak` (pubkey form) directly; no spend-auth-sig is generated.
    pub fn from_private_parameters_without_ask(
        params: &PrivateParametersWithoutAsk,
    ) -> Result<Self, Status> {
        let mut b = Self::new();
        b.timeout_seconds = params.timeout;
        b.transparent_from_address = params.transparent_from_address.clone();
        b.from_amount = params.from_amount;
        b.transparent_to_address = params.transparent_to_address.clone();
        b.to_amount = params.to_amount;

        let has_ak = !params.ak.is_empty();
        let has_transparent_from = !params.transparent_from_address.is_empty();
        if !has_ak && !has_transparent_from {
            return Err(Status::invalid_argument(
                "no input source (need either ak+nsk+ovk or transparent_from_address)",
            ));
        }
        let has_shielded_spends = !params.shielded_spends.is_empty();
        let has_shielded_receives = !params.shielded_receives.is_empty();

        let ak_opt: Option<[u8; 32]> = if has_ak {
            Some(parse_bytes_32(&params.ak, "ak")?)
        } else {
            if has_shielded_spends {
                return Err(Status::invalid_argument(
                    "shielded_spends requires `ak` (without-ask flow)",
                ));
            }
            None
        };
        let nsk_opt: Option<jubjub::Fr> = if has_shielded_spends {
            Some(parse_scalar_32(&params.nsk, "nsk")?)
        } else {
            None
        };
        let ovk_opt: Option<[u8; 32]> = if has_shielded_receives {
            Some(parse_bytes_32(&params.ovk, "ovk")?)
        } else {
            None
        };

        if has_shielded_spends {
            let ak = ak_opt.expect("checked above");
            let nsk = nsk_opt.expect("checked above");
            for spend in &params.shielded_spends {
                b.add_spend(ak, nsk, spend, None)?;
            }
        }
        if let Some(ovk) = ovk_opt {
            for recv in &params.shielded_receives {
                b.add_receive(OutgoingViewingKey(ovk), recv)?;
            }
        }
        Ok(b)
    }

    fn add_spend(
        &mut self,
        ak: [u8; 32],
        nsk: jubjub::Fr,
        spend: &SpendNote,
        ask: Option<[u8; 32]>,
    ) -> Result<(), Status> {
        let note = spend
            .note
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("spend.note missing"))?;
        let payment_addr_bytes = crate::service::parse_payment_address(&note.payment_address)
            .map_err(Status::invalid_argument)?;
        let mut d_bytes = [0u8; 11];
        d_bytes.copy_from_slice(&payment_addr_bytes[..11]);
        let diversifier = Diversifier(d_bytes);
        let rcm = parse_scalar_32(&note.rcm, "spend.note.rcm")?;

        let alpha = if spend.alpha.is_empty() {
            // java-tron's SpendDescriptionInfo samples alpha via
            // librustzcashSaplingGenerateR when not supplied. We
            // mirror with a fresh OS-entropy scalar.
            let mut alpha_bytes = [0u8; 32];
            getrandom::getrandom(&mut alpha_bytes)
                .map_err(|e| Status::internal(format!("CSPRNG: {e}")))?;
            let opt = jubjub::Fr::from_bytes(&alpha_bytes);
            if !bool::from(opt.is_some()) {
                return Err(Status::internal(
                    "CSPRNG produced non-canonical jubjub scalar (retry)",
                ));
            }
            opt.unwrap()
        } else {
            parse_scalar_32(&spend.alpha, "spend.alpha")?
        };

        let voucher_proto = spend
            .voucher
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("spend.voucher missing"))?;
        let voucher = tron_tvm::shielded::IncrementalMerkleVoucher::from_proto(voucher_proto);
        let anchor = voucher.root();
        let position = voucher.position();

        // Build sapling-crypto MerklePath from the witness state.
        // Our MerklePath has root-first siblings (java-tron convention);
        // sapling-crypto wants leaf-first. We reverse.
        let our_path = voucher.path().ok_or_else(|| {
            Status::invalid_argument("voucher.path() failed (snapshot tree empty)")
        })?;
        let mut leaf_first: Vec<Node> = our_path
            .siblings
            .iter()
            .map(|h| Node::from_bytes(*h))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|opt| {
                if bool::from(opt.is_some()) {
                    Ok(opt.unwrap())
                } else {
                    Err(Status::invalid_argument(
                        "voucher path contains non-canonical Node bytes",
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        leaf_first.reverse();
        let merkle_path =
            MerklePath::from_parts(leaf_first, incrementalmerkletree::Position::from(position))
                .map_err(|_| {
                    Status::internal("merkle path length doesn't match Sapling tree depth")
                })?;

        self.value_balance = self
            .value_balance
            .checked_add(note.value)
            .ok_or_else(|| Status::invalid_argument("value balance overflow"))?;
        self.spends.push(SpendBuildInfo {
            ak,
            nsk: nsk.to_bytes(),
            diversifier,
            value: note.value as u64,
            rcm,
            alpha,
            anchor,
            merkle_path,
        });
        self.asks.push(ask);
        Ok(())
    }

    fn add_receive(
        &mut self,
        ovk: OutgoingViewingKey,
        recv: &ReceiveNote,
    ) -> Result<(), Status> {
        let note = recv
            .note
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("receive.note missing"))?;
        let payment_addr_bytes = crate::service::parse_payment_address(&note.payment_address)
            .map_err(Status::invalid_argument)?;
        let payment_address = PaymentAddress::from_bytes(&payment_addr_bytes)
            .ok_or_else(|| Status::invalid_argument("receive.payment_address invalid"))?;
        let rcm = parse_scalar_32(&note.rcm, "receive.note.rcm")?;
        // Memo is 512 bytes; pad with zeros if shorter.
        let mut memo = [0u8; 512];
        let copy_len = note.memo.len().min(512);
        memo[..copy_len].copy_from_slice(&note.memo[..copy_len]);

        self.value_balance = self
            .value_balance
            .checked_sub(note.value)
            .ok_or_else(|| Status::invalid_argument("value balance underflow"))?;
        self.receives.push(ReceiveBuildInfo {
            ovk,
            payment_address,
            value: note.value as u64,
            memo,
            rcm,
        });
        Ok(())
    }

    /// Build the final Transaction. Mirrors `ZenTransactionBuilder.build(withAsk)`.
    pub fn build_native<R: RngCore + CryptoRng>(
        self,
        state: &RpcState,
        rng: &mut R,
    ) -> Result<TransactionExtention, Status> {
        if self.spends.is_empty() && self.receives.is_empty() {
            return Err(Status::invalid_argument(
                "shielded transaction needs at least one spend or one receive",
            ));
        }
        let mut prover = SaplingProver::new();
        let mut spend_descriptions: Vec<SpendDescription> = Vec::with_capacity(self.spends.len());
        let mut receive_descriptions: Vec<ReceiveDescription> =
            Vec::with_capacity(self.receives.len());

        for spend_info in &self.spends {
            let proved = prover
                .build_spend(
                    pgk_from(spend_info.ak, &spend_info.nsk)?,
                    spend_info.diversifier,
                    spend_info.value,
                    spend_info.rcm,
                    spend_info.alpha,
                    spend_info.merkle_path.clone(),
                    spend_info.anchor,
                    rng,
                )
                .map_err(|e| Status::internal(format!("spend proof: {e}")))?;
            spend_descriptions.push(SpendDescription {
                value_commitment: proved.cv.to_bytes().to_vec(),
                anchor: proved.anchor.to_vec(),
                nullifier: proved.nullifier.to_vec(),
                rk: proved.rk.to_vec(),
                zkproof: proved.zkproof.to_vec(),
                spend_authority_signature: Vec::new(), // filled in if with_ask
            });
        }

        for recv_info in &self.receives {
            let proved = prover
                .build_output(
                    recv_info.payment_address.clone(),
                    recv_info.value,
                    recv_info.memo,
                    recv_info.rcm,
                    Some(recv_info.ovk),
                    rng,
                )
                .map_err(|e| Status::internal(format!("output proof: {e}")))?;
            receive_descriptions.push(ReceiveDescription {
                value_commitment: proved.cv.to_bytes().to_vec(),
                note_commitment: proved.cmu.to_vec(),
                epk: proved.ephemeral_key.to_vec(),
                c_enc: proved.enc_ciphertext.to_vec(),
                c_out: proved.out_ciphertext.to_vec(),
                zkproof: proved.zkproof.to_vec(),
            });
        }

        let contract = ShieldedTransferContract {
            transparent_from_address: self.transparent_from_address.clone(),
            from_amount: self.from_amount,
            transparent_to_address: self.transparent_to_address.clone(),
            to_amount: self.to_amount,
            spend_description: spend_descriptions,
            receive_description: receive_descriptions,
            binding_signature: vec![0u8; 64], // filled in below
        };

        // Wrap the contract into an unsigned Transaction.
        let any = prost_types::Any {
            type_url: "type.googleapis.com/protocol.ShieldedTransferContract".into(),
            value: contract.encode_to_vec(),
        };
        let tx_contract = TxContract {
            r#type: ContractType::ShieldedTransferContract as i32,
            parameter: Some(any),
            ..Default::default()
        };
        let mut tx = tron_rpc::builder::build_unsigned_tx(state, tx_contract, 0)
            .map_err(|e| Status::internal(format!("tx envelope: {e:?}")))?;
        // Apply timeout override: if `timeout_seconds > 0` set
        // expiration = now + timeout * 1000 (overrides the 60s
        // default).
        if self.timeout_seconds > 0 {
            if let Some(raw) = tx.raw_data.as_mut() {
                raw.expiration = raw.timestamp + self.timeout_seconds * 1_000;
            }
        }

        // Compute shielded sighash over the assembled tx.
        let zen_token_id = read_zen_token_id(state);
        let sighash = tron_actuator::shielded_transfer::compute_shielded_sighash(
            &tx,
            &zen_token_id,
        )
        .map_err(|e| Status::internal(format!("shielded sighash: {e}")))?;

        // Re-extract the contract so we can populate sigs.
        let mut populated_contract = contract.clone();
        for (idx, ask_opt) in self.asks.iter().enumerate() {
            if let Some(ask_bytes) = ask_opt {
                let sig = sign_spend_auth(*ask_bytes, self.spends[idx].alpha, &sighash, rng)?;
                populated_contract.spend_description[idx].spend_authority_signature = sig.to_vec();
            }
        }
        let binding_sig = prover
            .binding_sig(&sighash, rng)
            .map_err(|e| Status::internal(format!("binding sig: {e}")))?;
        populated_contract.binding_signature = binding_sig.to_vec();

        // Repack the contract back into the tx.
        let any = prost_types::Any {
            type_url: "type.googleapis.com/protocol.ShieldedTransferContract".into(),
            value: populated_contract.encode_to_vec(),
        };
        if let Some(raw) = tx.raw_data.as_mut() {
            raw.contract = vec![TxContract {
                r#type: ContractType::ShieldedTransferContract as i32,
                parameter: Some(any),
                ..Default::default()
            }];
        }
        let raw_bytes = tx
            .raw_data
            .as_ref()
            .expect("raw_data present")
            .encode_to_vec();
        let txid = tron_crypto::hash::sha256(&raw_bytes);

        Ok(TransactionExtention {
            transaction: Some(tx),
            txid: txid.to_vec(),
            ..Default::default()
        })
    }
}

fn parse_scalar_32(bytes: &[u8], label: &str) -> Result<jubjub::Fr, Status> {
    if bytes.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "{label} must be 32 bytes; got {}",
            bytes.len()
        )));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(bytes);
    let opt = jubjub::Fr::from_bytes(&a);
    if bool::from(opt.is_some()) {
        Ok(opt.unwrap())
    } else {
        Err(Status::invalid_argument(format!(
            "{label} is not in the Jubjub scalar field"
        )))
    }
}

fn parse_bytes_32(bytes: &[u8], label: &str) -> Result<[u8; 32], Status> {
    if bytes.len() != 32 {
        return Err(Status::invalid_argument(format!(
            "{label} must be 32 bytes; got {}",
            bytes.len()
        )));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(bytes);
    Ok(a)
}

/// Reconstruct `ak` from `ask`: `ak = ask * G_SpendAuth`.
fn ak_from_ask(ask: &[u8; 32]) -> Result<[u8; 32], Status> {
    use sapling_crypto::constants::SPENDING_KEY_GENERATOR;
    let opt = jubjub::Fr::from_bytes(ask);
    if !bool::from(opt.is_some()) {
        return Err(Status::invalid_argument(
            "ask is not in the Jubjub scalar field",
        ));
    }
    let ask_scalar = opt.unwrap();
    let ak_point = SPENDING_KEY_GENERATOR * ask_scalar;
    let bytes: [u8; 32] = ak_point.to_bytes().as_ref().try_into().unwrap();
    Ok(bytes)
}

/// Reconstruct a `ProofGenerationKey` from `(ak_bytes, nsk_bytes)`.
///
/// Uses sapling-crypto's `temporary-zcashd` feature — the only path
/// that lets external callers reconstruct a `SpendValidatingKey`
/// directly from `ak`'s 32-byte wire encoding (java-tron's
/// `librustzcashSaplingSpendProof` takes ak directly; sapling-crypto's
/// default API hides the constructor because Zcash wallets derive
/// ak via the PRF tree, but TRON's HTTP/gRPC API accepts ak/nsk as
/// inputs directly).
fn pgk_from(ak_bytes: [u8; 32], nsk_bytes: &[u8; 32]) -> Result<ProofGenerationKey, Status> {
    use sapling_crypto::keys::SpendValidatingKey;
    let ak = SpendValidatingKey::temporary_zcash_from_bytes(&ak_bytes)
        .ok_or_else(|| Status::invalid_argument("ak is not a valid SpendValidatingKey"))?;
    let nsk_scalar = jubjub::Fr::from_bytes(nsk_bytes);
    if !bool::from(nsk_scalar.is_some()) {
        return Err(Status::invalid_argument(
            "nsk is not in the Jubjub scalar field",
        ));
    }
    Ok(ProofGenerationKey {
        ak,
        nsk: nsk_scalar.unwrap(),
    })
}

/// Sign `sighash` with `(ask, alpha)` to produce a 64-byte
/// RedJubjub SpendAuth signature.
fn sign_spend_auth<R: RngCore + CryptoRng>(
    ask: [u8; 32],
    alpha: jubjub::Fr,
    sighash: &[u8; 32],
    rng: &mut R,
) -> Result<[u8; 64], Status> {
    use redjubjub::{SigningKey, SpendAuth};
    // rsk = ask + alpha (rerandomized signing key).
    let ask_scalar = jubjub::Fr::from_bytes(&ask);
    if !bool::from(ask_scalar.is_some()) {
        return Err(Status::invalid_argument("ask not a valid jubjub scalar"));
    }
    let rsk = ask_scalar.unwrap() + alpha;
    let rsk_bytes: [u8; 32] = rsk.to_bytes();
    let signing_key: SigningKey<SpendAuth> = rsk_bytes
        .try_into()
        .map_err(|_| Status::internal("rsk invalid for SpendAuth"))?;
    let sig = signing_key.sign(rng, sighash);
    Ok(sig.into())
}

fn read_zen_token_id(state: &RpcState) -> String {
    state
        .dyn_props
        .get_bytes(b"ZEN_TOKEN_ID")
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "000000".to_string())
}

impl Default for ZenTransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Shielded TRC-20 builder
//
// Port of `ShieldedTRC20ParametersBuilder.build(withAsk)`. Differs
// from native shielded TRX in three ways:
//   1. Input shape comes from `SpendNoteTrc20` (root + path[1024] + pos)
//      rather than a structured voucher — the path is the encoded
//      merkle authentication path (32 levels × 32 bytes each).
//   2. Output is a `ShieldedTrc20Parameters` proto (spend_descs +
//      receive_descs + binding_sig + message_hash +
//      trigger_contract_input + parameter_type) — NOT a full
//      `Transaction` wrapper.
//   3. The signing-side `message_hash` is sha256 over a contract-
//      addressed, mode-specific merge of the proven descriptions
//      (NOT the full TRON transaction sighash). The binding sig and
//      each spend-auth sig sign that hash.
// =============================================================================

use tron_proto::protocol::{
    BytesMessage as TronBytesMessage, PrivateShieldedTrc20Parameters,
    PrivateShieldedTrc20ParametersWithoutAsk, ShieldedTrc20Parameters, SpendNoteTrc20,
};
use tron_proto::ReceiveDescription as ReceiveDescriptionProto;
use tron_proto::SpendDescription as SpendDescriptionProto;

/// MINT / TRANSFER / BURN. Determined by input-shape rules
/// java-tron's `Wallet.createShieldedContractParameters` enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trc20Mode {
    Mint,
    Transfer,
    Burn,
}

impl Trc20Mode {
    fn as_str(self) -> &'static str {
        match self {
            Trc20Mode::Mint => "mint",
            Trc20Mode::Transfer => "transfer",
            Trc20Mode::Burn => "burn",
        }
    }
}

/// Encoded merkle authentication path length matching java-tron's
/// `MERKLE_TREE_PATH_LENGTH = 32 * 32 = 1024`. The wire format is
/// 32 sibling Pedersen hashes leaf-first (no length prefix — the
/// reader infers depth from length / 32).
const TRC20_MERKLE_PATH_BYTES: usize = 1024;

struct Trc20SpendInfo {
    ak: [u8; 32],
    nsk: [u8; 32],
    diversifier: Diversifier,
    value: u64,
    rcm: jubjub::Fr,
    alpha: jubjub::Fr,
    anchor: [u8; 32],
    merkle_path: MerklePath,
}

/// Builder for `ShieldedTrc20Parameters`. One per RPC call.
pub struct ShieldedTrc20Builder {
    mode: Trc20Mode,
    /// 20-byte TVM-format contract address (caller passes 21-byte
    /// TRON address; we strip the 0x41 prefix internally).
    contract_address_tvm: [u8; 20],
    spends: Vec<Trc20SpendInfo>,
    receives: Vec<ReceiveBuildInfo>,
    /// Per-spend ask. None for the without-ask flow (caller signs
    /// externally).
    asks: Vec<Option<[u8; 32]>>,
    /// MINT: fromAmount > 0; TRANSFER: 0; BURN: 0.
    transparent_from_amount: u64,
    /// BURN: 20-byte TVM-format recipient address.
    transparent_to_address_tvm: Option<[u8; 20]>,
    /// BURN: toAmount > 0; others: 0.
    transparent_to_amount: u64,
    /// BURN: 80-byte ChaCha20-Poly1305 ciphertext of (amount,
    /// transparent_to_addr) under OVK.
    burn_ciphertext: Option<[u8; 80]>,
    /// Used by binding-signature path (informational; actual binding
    /// sig comes from the prover's bsk accumulator).
    value_balance: i64,
}

impl ShieldedTrc20Builder {
    pub fn from_private_trc20(
        params: &PrivateShieldedTrc20Parameters,
    ) -> Result<Self, Status> {
        let contract_addr = parse_contract_address(&params.shielded_trc20_contract_address)?;
        let from_amount = parse_unsigned_decimal_u64(&params.from_amount, "from_amount")?;
        let to_amount = parse_unsigned_decimal_u64(&params.to_amount, "to_amount")?;
        let spend_size = params.shielded_spends.len();
        let receive_size = params.shielded_receives.len();
        let receive_first_value = params
            .shielded_receives
            .first()
            .and_then(|r| r.note.as_ref())
            .map(|n| n.value as u64)
            .unwrap_or(0);
        let total_to_amount = if to_amount > 0 {
            if receive_size == 0 {
                to_amount
            } else {
                to_amount
                    .checked_add(receive_first_value)
                    .ok_or_else(|| Status::invalid_argument("burn total_to_amount overflow"))?
            }
        } else {
            0
        };

        // Shape detection — exact mirror of Wallet.java.
        let mode = if from_amount > 0
            && spend_size == 0
            && receive_size == 1
            && from_amount == receive_first_value
            && to_amount == 0
        {
            Trc20Mode::Mint
        } else if from_amount == 0
            && (1..=2).contains(&spend_size)
            && (1..=2).contains(&receive_size)
            && to_amount == 0
        {
            Trc20Mode::Transfer
        } else if from_amount == 0
            && spend_size == 1
            && receive_size <= 1
            && to_amount > 0
            && total_to_amount
                == params.shielded_spends[0]
                    .note
                    .as_ref()
                    .map(|n| n.value as u64)
                    .unwrap_or(0)
        {
            Trc20Mode::Burn
        } else {
            return Err(Status::invalid_argument(
                "invalid shielded TRC-20 parameters (shape doesn't match mint/transfer/burn)",
            ));
        };

        let mut b = Self {
            mode,
            contract_address_tvm: contract_addr,
            spends: Vec::new(),
            receives: Vec::new(),
            asks: Vec::new(),
            transparent_from_amount: from_amount,
            transparent_to_address_tvm: None,
            transparent_to_amount: to_amount,
            burn_ciphertext: None,
            value_balance: 0,
        };

        match mode {
            Trc20Mode::Mint => {
                let ovk = parse_bytes_32(&params.ovk, "ovk")?;
                b.add_receive(OutgoingViewingKey(ovk), &params.shielded_receives[0])?;
            }
            Trc20Mode::Transfer => {
                let ask = parse_bytes_32(&params.ask, "ask")?;
                let nsk = parse_scalar_32(&params.nsk, "nsk")?;
                let ovk = parse_bytes_32(&params.ovk, "ovk")?;
                let ak = ak_from_ask(&ask)?;
                for spend in &params.shielded_spends {
                    b.add_trc20_spend(ak, nsk, spend, Some(ask))?;
                }
                for recv in &params.shielded_receives {
                    b.add_receive(OutgoingViewingKey(ovk), recv)?;
                }
            }
            Trc20Mode::Burn => {
                let ask = parse_bytes_32(&params.ask, "ask")?;
                let nsk = parse_scalar_32(&params.nsk, "nsk")?;
                let ovk = parse_bytes_32(&params.ovk, "ovk")?;
                let ak = ak_from_ask(&ask)?;
                let transparent_to = parse_transparent_to(&params.transparent_to_address)?;
                b.transparent_to_address_tvm = Some(transparent_to.tvm);
                b.burn_ciphertext = Some(encrypt_burn_message_by_ovk(
                    &ovk,
                    to_amount,
                    &transparent_to.full,
                )?);
                b.add_trc20_spend(ak, nsk, &params.shielded_spends[0], Some(ask))?;
                if receive_size == 1 {
                    b.add_receive(OutgoingViewingKey(ovk), &params.shielded_receives[0])?;
                }
            }
        }
        Ok(b)
    }

    pub fn from_private_trc20_without_ask(
        params: &PrivateShieldedTrc20ParametersWithoutAsk,
    ) -> Result<Self, Status> {
        let contract_addr = parse_contract_address(&params.shielded_trc20_contract_address)?;
        let from_amount = parse_unsigned_decimal_u64(&params.from_amount, "from_amount")?;
        let to_amount = parse_unsigned_decimal_u64(&params.to_amount, "to_amount")?;
        let spend_size = params.shielded_spends.len();
        let receive_size = params.shielded_receives.len();
        let receive_first_value = params
            .shielded_receives
            .first()
            .and_then(|r| r.note.as_ref())
            .map(|n| n.value as u64)
            .unwrap_or(0);
        let total_to_amount = if to_amount > 0 {
            if receive_size == 0 {
                to_amount
            } else {
                to_amount
                    .checked_add(receive_first_value)
                    .ok_or_else(|| Status::invalid_argument("burn total_to_amount overflow"))?
            }
        } else {
            0
        };

        let mode = if from_amount > 0
            && spend_size == 0
            && receive_size == 1
            && from_amount == receive_first_value
            && to_amount == 0
        {
            Trc20Mode::Mint
        } else if from_amount == 0
            && (1..=2).contains(&spend_size)
            && (1..=2).contains(&receive_size)
            && to_amount == 0
        {
            Trc20Mode::Transfer
        } else if from_amount == 0
            && spend_size == 1
            && receive_size <= 1
            && to_amount > 0
            && total_to_amount
                == params.shielded_spends[0]
                    .note
                    .as_ref()
                    .map(|n| n.value as u64)
                    .unwrap_or(0)
        {
            Trc20Mode::Burn
        } else {
            return Err(Status::invalid_argument(
                "invalid shielded TRC-20 parameters (shape doesn't match mint/transfer/burn)",
            ));
        };

        let mut b = Self {
            mode,
            contract_address_tvm: contract_addr,
            spends: Vec::new(),
            receives: Vec::new(),
            asks: Vec::new(),
            transparent_from_amount: from_amount,
            transparent_to_address_tvm: None,
            transparent_to_amount: to_amount,
            burn_ciphertext: None,
            value_balance: 0,
        };

        match mode {
            Trc20Mode::Mint => {
                let ovk = parse_bytes_32(&params.ovk, "ovk")?;
                b.add_receive(OutgoingViewingKey(ovk), &params.shielded_receives[0])?;
            }
            Trc20Mode::Transfer => {
                let ak = parse_bytes_32(&params.ak, "ak")?;
                let nsk = parse_scalar_32(&params.nsk, "nsk")?;
                let ovk = parse_bytes_32(&params.ovk, "ovk")?;
                for spend in &params.shielded_spends {
                    b.add_trc20_spend(ak, nsk, spend, None)?;
                }
                for recv in &params.shielded_receives {
                    b.add_receive(OutgoingViewingKey(ovk), recv)?;
                }
            }
            Trc20Mode::Burn => {
                let ak = parse_bytes_32(&params.ak, "ak")?;
                let nsk = parse_scalar_32(&params.nsk, "nsk")?;
                let ovk = parse_bytes_32(&params.ovk, "ovk")?;
                let transparent_to = parse_transparent_to(&params.transparent_to_address)?;
                b.transparent_to_address_tvm = Some(transparent_to.tvm);
                b.burn_ciphertext = Some(encrypt_burn_message_by_ovk(
                    &ovk,
                    to_amount,
                    &transparent_to.full,
                )?);
                b.add_trc20_spend(ak, nsk, &params.shielded_spends[0], None)?;
                if receive_size == 1 {
                    b.add_receive(OutgoingViewingKey(ovk), &params.shielded_receives[0])?;
                }
            }
        }
        Ok(b)
    }

    fn add_trc20_spend(
        &mut self,
        ak: [u8; 32],
        nsk: jubjub::Fr,
        spend: &SpendNoteTrc20,
        ask: Option<[u8; 32]>,
    ) -> Result<(), Status> {
        let note = spend
            .note
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("trc20 spend.note missing"))?;
        let payment_addr_bytes =
            crate::service::parse_payment_address(&note.payment_address)
                .map_err(Status::invalid_argument)?;
        let mut d_bytes = [0u8; 11];
        d_bytes.copy_from_slice(&payment_addr_bytes[..11]);
        let diversifier = Diversifier(d_bytes);
        let rcm = parse_scalar_32(&note.rcm, "trc20 spend.note.rcm")?;
        let alpha = if spend.alpha.is_empty() {
            // Generate fresh alpha — java-tron does the same when not
            // supplied.
            let mut alpha_bytes = [0u8; 32];
            getrandom::getrandom(&mut alpha_bytes)
                .map_err(|e| Status::internal(format!("CSPRNG: {e}")))?;
            let opt = jubjub::Fr::from_bytes(&alpha_bytes);
            if !bool::from(opt.is_some()) {
                return Err(Status::internal(
                    "CSPRNG produced non-canonical jubjub scalar",
                ));
            }
            opt.unwrap()
        } else {
            parse_scalar_32(&spend.alpha, "trc20 spend.alpha")?
        };
        if spend.root.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "trc20 spend.root must be 32 bytes; got {}",
                spend.root.len()
            )));
        }
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&spend.root);
        if spend.path.len() != TRC20_MERKLE_PATH_BYTES {
            return Err(Status::invalid_argument(format!(
                "trc20 spend.path must be {TRC20_MERKLE_PATH_BYTES} bytes; got {}",
                spend.path.len()
            )));
        }
        if spend.pos < 0 {
            return Err(Status::invalid_argument(
                "trc20 spend.pos must be non-negative",
            ));
        }
        // Parse 1024-byte path into 32 sibling Nodes, leaf-first.
        let mut siblings: Vec<Node> = Vec::with_capacity(32);
        for i in 0..32 {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&spend.path[i * 32..(i + 1) * 32]);
            let opt = Node::from_bytes(buf);
            if !bool::from(opt.is_some()) {
                return Err(Status::invalid_argument(format!(
                    "trc20 spend.path[{i}] is not a canonical Node encoding"
                )));
            }
            siblings.push(opt.unwrap());
        }
        let merkle_path = MerklePath::from_parts(
            siblings,
            incrementalmerkletree::Position::from(spend.pos as u64),
        )
        .map_err(|_| Status::internal("trc20 merkle path length wrong"))?;

        self.value_balance = self
            .value_balance
            .checked_add(note.value)
            .ok_or_else(|| Status::invalid_argument("value balance overflow"))?;
        self.spends.push(Trc20SpendInfo {
            ak,
            nsk: nsk.to_bytes(),
            diversifier,
            value: note.value as u64,
            rcm,
            alpha,
            anchor,
            merkle_path,
        });
        self.asks.push(ask);
        Ok(())
    }

    fn add_receive(
        &mut self,
        ovk: OutgoingViewingKey,
        recv: &ReceiveNote,
    ) -> Result<(), Status> {
        let note = recv
            .note
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("receive.note missing"))?;
        let payment_addr_bytes =
            crate::service::parse_payment_address(&note.payment_address)
                .map_err(Status::invalid_argument)?;
        let payment_address = PaymentAddress::from_bytes(&payment_addr_bytes)
            .ok_or_else(|| Status::invalid_argument("receive.payment_address invalid"))?;
        let rcm = parse_scalar_32(&note.rcm, "receive.note.rcm")?;
        let mut memo = [0u8; 512];
        let copy_len = note.memo.len().min(512);
        memo[..copy_len].copy_from_slice(&note.memo[..copy_len]);
        self.value_balance = self
            .value_balance
            .checked_sub(note.value)
            .ok_or_else(|| Status::invalid_argument("value balance underflow"))?;
        self.receives.push(ReceiveBuildInfo {
            ovk,
            payment_address,
            value: note.value as u64,
            memo,
            rcm,
        });
        Ok(())
    }

    pub fn build_trc20<R: RngCore + CryptoRng>(
        self,
        with_ask: bool,
        rng: &mut R,
    ) -> Result<ShieldedTrc20Parameters, Status> {
        let mut prover = SaplingProver::new();
        let mut spend_descs: Vec<SpendDescriptionProto> = Vec::with_capacity(self.spends.len());
        for spend in &self.spends {
            let proved = prover
                .build_spend(
                    pgk_from(spend.ak, &spend.nsk)?,
                    spend.diversifier,
                    spend.value,
                    spend.rcm,
                    spend.alpha,
                    spend.merkle_path.clone(),
                    spend.anchor,
                    rng,
                )
                .map_err(|e| Status::internal(format!("trc20 spend proof: {e}")))?;
            spend_descs.push(SpendDescriptionProto {
                value_commitment: proved.cv.to_bytes().to_vec(),
                anchor: proved.anchor.to_vec(),
                nullifier: proved.nullifier.to_vec(),
                rk: proved.rk.to_vec(),
                zkproof: proved.zkproof.to_vec(),
                spend_authority_signature: Vec::new(),
            });
        }
        let mut receive_descs: Vec<ReceiveDescriptionProto> =
            Vec::with_capacity(self.receives.len());
        for recv in &self.receives {
            let proved = prover
                .build_output(
                    recv.payment_address.clone(),
                    recv.value,
                    recv.memo,
                    recv.rcm,
                    Some(recv.ovk),
                    rng,
                )
                .map_err(|e| Status::internal(format!("trc20 output proof: {e}")))?;
            receive_descs.push(ReceiveDescriptionProto {
                value_commitment: proved.cv.to_bytes().to_vec(),
                note_commitment: proved.cmu.to_vec(),
                epk: proved.ephemeral_key.to_vec(),
                c_enc: proved.enc_ciphertext.to_vec(),
                c_out: proved.out_ciphertext.to_vec(),
                zkproof: proved.zkproof.to_vec(),
            });
        }

        // Compute mergedBytes per mode.
        let merged_bytes = match self.mode {
            Trc20Mode::Mint => {
                let rd = &receive_descs[0];
                let value = self.receives[0].value;
                let mut out = Vec::new();
                out.extend_from_slice(&self.contract_address_tvm);
                out.extend_from_slice(&value.to_be_bytes()); // 8 bytes BE
                out.extend_from_slice(&encode_receive_without_c(rd));
                out.extend_from_slice(&encode_c_enc_c_out_pad(rd));
                out
            }
            Trc20Mode::Transfer => {
                let mut out = Vec::new();
                out.extend_from_slice(&self.contract_address_tvm);
                for sd in &spend_descs {
                    out.extend_from_slice(&encode_spend_without_auth_sig(sd));
                }
                let mut cenc_cout = Vec::new();
                for rd in &receive_descs {
                    out.extend_from_slice(&encode_receive_without_c(rd));
                    cenc_cout.extend_from_slice(&encode_c_enc_c_out_pad(rd));
                }
                out.extend_from_slice(&cenc_cout);
                out
            }
            Trc20Mode::Burn => {
                let sd = &spend_descs[0];
                let mut out = Vec::new();
                out.extend_from_slice(&self.contract_address_tvm);
                out.extend_from_slice(&encode_spend_without_auth_sig(sd));
                if let Some(rd) = receive_descs.first() {
                    out.extend_from_slice(&encode_receive_without_c(rd));
                    out.extend_from_slice(&encode_c_enc_c_out_pad(rd));
                }
                let to_tvm = self
                    .transparent_to_address_tvm
                    .expect("burn requires transparent_to_address (checked at build time)");
                out.extend_from_slice(&to_tvm);
                out.extend_from_slice(&(self.value_balance as u64).to_be_bytes());
                out
            }
        };
        let message_hash = tron_crypto::hash::sha256(&merged_bytes).to_vec();

        // Spend-auth-sigs (with-ask only).
        let mut spend_descs_signed = spend_descs.clone();
        if with_ask {
            for (i, ask_opt) in self.asks.iter().enumerate() {
                if let Some(ask_bytes) = ask_opt {
                    let sig = sign_spend_auth(
                        *ask_bytes,
                        self.spends[i].alpha,
                        message_hash
                            .as_slice()
                            .try_into()
                            .expect("sha256 = 32 bytes"),
                        rng,
                    )?;
                    spend_descs_signed[i].spend_authority_signature = sig.to_vec();
                }
            }
        }

        // Binding signature over the message hash.
        let binding_sig = prover
            .binding_sig(
                message_hash
                    .as_slice()
                    .try_into()
                    .expect("sha256 = 32 bytes"),
                rng,
            )
            .map_err(|e| Status::internal(format!("binding sig: {e}")))?;

        // Build the parameter type string for the proto.
        let parameter_type = self.mode.as_str().to_string();

        // For the with-ask path or MINT, compute trigger_contract_input
        // via the existing ABI encoders (mint_params_to_bytes etc.).
        // For without-ask + BURN, set trigger_contract_input to the
        // hex-encoded burnCiphertext (java-tron mirror).
        let mut params_proto = ShieldedTrc20Parameters {
            spend_description: spend_descs_signed,
            receive_description: receive_descs,
            binding_signature: binding_sig.to_vec(),
            message_hash,
            trigger_contract_input: String::new(),
            parameter_type,
        };

        let value_for_trigger = match self.mode {
            Trc20Mode::Mint => self.transparent_from_amount as u128,
            Trc20Mode::Transfer => 0u128,
            Trc20Mode::Burn => self.transparent_to_amount as u128,
        };

        if with_ask || self.mode == Trc20Mode::Mint {
            // For BURN-without-ask we also need the burn ciphertext on
            // params_proto.trigger_contract_input as a HEX STRING for
            // the encoder to read. Pre-set it.
            if self.mode == Trc20Mode::Burn {
                if let Some(bc) = self.burn_ciphertext {
                    params_proto.trigger_contract_input = hex::encode(bc);
                }
            }
            let mut trans_to_full = [0u8; 21];
            if let Some(tvm) = self.transparent_to_address_tvm {
                trans_to_full[0] = 0x41;
                trans_to_full[1..].copy_from_slice(&tvm);
            }
            let trigger_params =
                tron_proto::protocol::ShieldedTrc20TriggerContractParameters {
                    shielded_trc20_parameters: Some(params_proto.clone()),
                    spend_authority_signature: Vec::new(), // with_ask=true uses inline sigs
                    amount: value_for_trigger.to_string(),
                    transparent_to_address: if self.mode == Trc20Mode::Burn {
                        trans_to_full.to_vec()
                    } else {
                        Vec::new()
                    },
                };
            // Re-run the calldata encoder (it walks the just-built
            // SpendDescription / ReceiveDescription set). For with-ask
            // BURN/Transfer, the inline `spend_authority_signature`
            // fields on each SpendDescription get picked up.
            let calldata = if with_ask {
                build_trigger_input_with_ask(&trigger_params)?
            } else {
                // MINT: no spend descriptions, no with-ask needed.
                crate::shielded::get_trigger_input_for_shielded_trc20_contract(trigger_params)?
                    .value
            };
            params_proto.trigger_contract_input = hex::encode(calldata);
        } else if self.mode == Trc20Mode::Burn {
            // !with_ask && BURN: trigger_contract_input is just the
            // hex of the burn ciphertext (java-tron mirror).
            if let Some(bc) = self.burn_ciphertext {
                params_proto.trigger_contract_input = hex::encode(bc);
            }
        }

        Ok(params_proto)
    }
}

/// Calldata encoder for the with-ask flow: same as the public
/// `get_trigger_input_for_shielded_trc20_contract` but uses each
/// SpendDescription's inline `spend_authority_signature` field
/// instead of the external `spend_authority_signature` list.
fn build_trigger_input_with_ask(
    params: &tron_proto::protocol::ShieldedTrc20TriggerContractParameters,
) -> Result<Vec<u8>, Status> {
    let p = params
        .shielded_trc20_parameters
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("shielded_trc20_parameters missing"))?;
    // Build a synthetic `external` sigs list from the inline ones so
    // we can reuse the existing encoder. For mint, no spends, no sigs.
    let external_sigs: Vec<TronBytesMessage> = p
        .spend_description
        .iter()
        .map(|sd| TronBytesMessage {
            value: sd.spend_authority_signature.clone(),
        })
        .collect();
    let mut params = params.clone();
    params.spend_authority_signature = external_sigs;
    Ok(crate::shielded::get_trigger_input_for_shielded_trc20_contract(params)?.value)
}

/// `spend_desc_without_auth_sig` encoder for the message-hash merge.
fn encode_spend_without_auth_sig(sd: &SpendDescriptionProto) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 32 + 32 + 192);
    out.extend_from_slice(&sd.nullifier);
    out.extend_from_slice(&sd.anchor);
    out.extend_from_slice(&sd.value_commitment);
    out.extend_from_slice(&sd.rk);
    out.extend_from_slice(&sd.zkproof);
    out
}

/// `receive_desc_without_c` encoder.
fn encode_receive_without_c(rd: &ReceiveDescriptionProto) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 32 + 192);
    out.extend_from_slice(&rd.note_commitment);
    out.extend_from_slice(&rd.value_commitment);
    out.extend_from_slice(&rd.epk);
    out.extend_from_slice(&rd.zkproof);
    out
}

/// `c_enc || c_out || zeros[12]` — 672 bytes total.
fn encode_c_enc_c_out_pad(rd: &ReceiveDescriptionProto) -> Vec<u8> {
    let mut out = Vec::with_capacity(580 + 80 + 12);
    out.extend_from_slice(&rd.c_enc);
    out.extend_from_slice(&rd.c_out);
    out.extend_from_slice(&[0u8; 12]);
    out
}

/// Parse + strip the `0x41` prefix from a 21-byte TRON address.
struct TransparentAddress {
    /// 21-byte TRON format (0x41 prefix + 20 bytes).
    full: [u8; 21],
    /// 20-byte TVM format.
    tvm: [u8; 20],
}

fn parse_contract_address(bytes: &[u8]) -> Result<[u8; 20], Status> {
    if bytes.len() != 21 {
        return Err(Status::invalid_argument(format!(
            "shielded_trc20_contract_address must be 21 bytes; got {}",
            bytes.len()
        )));
    }
    let mut tvm = [0u8; 20];
    tvm.copy_from_slice(&bytes[1..]);
    Ok(tvm)
}

fn parse_transparent_to(bytes: &[u8]) -> Result<TransparentAddress, Status> {
    if bytes.len() != 21 {
        return Err(Status::invalid_argument(format!(
            "transparent_to_address must be 21 bytes (0x41 prefix); got {}",
            bytes.len()
        )));
    }
    let mut full = [0u8; 21];
    full.copy_from_slice(bytes);
    let mut tvm = [0u8; 20];
    tvm.copy_from_slice(&bytes[1..]);
    Ok(TransparentAddress { full, tvm })
}

fn parse_unsigned_decimal_u64(s: &str, label: &str) -> Result<u64, Status> {
    if s.is_empty() {
        return Ok(0);
    }
    s.parse::<u64>().map_err(|e| {
        Status::invalid_argument(format!("{label} must be a non-negative decimal u64: {e}"))
    })
}

/// ChaCha20-Poly1305 burn-message encryption. Mirrors java-tron's
/// `NoteEncryption.Encryption.encryptBurnMessageByOvk`:
///   * plaintext = `amount(32 bytes BE) || transparent_to_address(21) || zeros(11)` = 64 bytes
///   * key = OVK (32 bytes)
///   * nonce = zeros (12 bytes)
///   * no AAD
///   * output = 80 bytes (64 plaintext + 16 Poly1305 tag)
fn encrypt_burn_message_by_ovk(
    ovk: &[u8; 32],
    to_amount: u64,
    transparent_to: &[u8; 21],
) -> Result<[u8; 80], Status> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;

    let mut plaintext = [0u8; 64];
    // u64 amount → right-aligned in the 32-byte high half.
    let amount_be = to_amount.to_be_bytes();
    plaintext[24..32].copy_from_slice(&amount_be);
    plaintext[32..53].copy_from_slice(transparent_to);
    // bytes [53..64] are already zero-initialised.

    let mut buffer = plaintext.to_vec();
    let cipher = ChaCha20Poly1305::new(ovk.into());
    let nonce = [0u8; 12];
    let tag = cipher
        .encrypt_in_place_detached(&nonce.into(), &[], &mut buffer)
        .map_err(|e| Status::internal(format!("burn ciphertext encrypt: {e}")))?;
    let mut out = [0u8; 80];
    out[..64].copy_from_slice(&buffer);
    out[64..80].copy_from_slice(&tag);
    Ok(out)
}
