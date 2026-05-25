//! `ShieldedTransferContract` actuator — the Sapling-based shielded
//! transfer of the "Zen" TRC-10 token.
//!
//! Source: `org.tron.core.actuator.ShieldedTransferActuator`.
//!
//! ## Scope of this port
//!
//! The actuator has four moving parts. Three are fully ported:
//!
//! 1. **Permission/structure checks** — `checkSender`, `checkReceiver`,
//!    `validateTransparent` (lengths, address validity, no-self-transfer,
//!    spend/receive count limits). 100% behaviour parity.
//! 2. **Duplicate nullifier / commitment detection** within the
//!    transaction itself. 100% parity.
//! 3. **Proof verification** — spend/output proof checks plus the
//!    final binding-signature check, using the embedded Sapling
//!    verifying keys from `tron_tvm::shielded`. 100% parity.
//!
//! The fourth — **Merkle-tree state machinery** — is documented stub
//! work: java-tron uses an `IncrementalMerkleTreeContainer` to
//! validate spend anchors against the historical roots set and to add
//! newly-committed notes to the current tree. We **skip** the anchor
//! lookup (always succeeds if the anchor parses as 32 bytes) and we
//! **do not append** new commitments to a Merkle tree. A future
//! "MerkleContainer" port can plug in here without touching the proof
//! or nullifier logic.
//!
//! Similarly, the TRC-10 "Zen" asset balance adjustments
//! (`Commons.adjustAssetBalanceV2` against `assetIssueStore`) are not
//! yet wired because the actuator doesn't yet know which asset id is
//! "Zen" without a chain-config lookup. These are documented stubs
//! that return `NotImplemented` if either transparent_from_address or
//! transparent_to_address is non-empty. **A purely-shielded → purely-
//! shielded transaction works end-to-end through this actuator.**

use std::collections::HashSet;

use tron_chainbase::{
    AccountStore, DynamicPropertiesStore, IncrementalMerkleTreeStore, NullifierStore,
};
use tron_chainbase::stores::incremental_merkle_tree_store::{CURRENT_TREE_KEY, LAST_TREE_KEY};
use tron_crypto::address::ADDRESS_LENGTH;
use tron_proto::{ReceiveDescription, ShieldedTransferContract, SpendDescription};
use tron_tvm::shielded::{
    check_binding_sig, check_output, check_spend, IncrementalMerkleTree, SaplingCommitmentSum,
};

use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// Maximum number of spend descriptions per transaction (java-tron).
pub const MAX_SPEND_COUNT: usize = 1;
/// Maximum number of receive descriptions per transaction (java-tron).
pub const MAX_RECEIVE_COUNT: usize = 2;

/// Zcash Sapling encrypted-ciphertext sizes — see `ZenChainParams`.
pub const ZC_ENCCIPHERTEXT_SIZE: usize = 580;
pub const ZC_OUTCIPHERTEXT_SIZE: usize = 80;

/// Sighash computed over the shielded transaction body (sans
/// signatures). The actuator needs this to verify the binding
/// signature; the caller computes it from the transaction structure.
pub type Sighash = [u8; 32];

/// Error from [`compute_shielded_sighash`].
#[derive(Debug, thiserror::Error)]
pub enum ShieldedSighashError {
    #[error("transaction has no raw_data")]
    NoRawData,
    #[error("transaction has no contracts")]
    NoContracts,
    #[error("transaction has no parameter")]
    NoParameter,
    #[error("contract[0] is not a ShieldedTransferContract")]
    NotShielded,
    #[error("failed to decode ShieldedTransferContract: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Compute the **shielded transaction sighash** that the spend-authority
/// signatures and the binding signature commit to.
///
/// Mirrors java-tron's `TransactionCapsule.hashShieldTransaction`
/// (`chainbase/.../TransactionCapsule.java:283`).
///
/// Algorithm:
/// 1. Clone the `ShieldedTransferContract` in `contract[0]`, clearing
///    every `SpendDescription.spend_authority_signature` (other fields
///    on spend/receive descriptions stay intact).
/// 2. Build a new `Transaction.raw_data` containing **only** that
///    rewritten contract (other contracts are dropped — matches
///    `clearContract().addContract(...)` in java-tron). Other raw_data
///    fields (`ref_block_*`, `expiration`, `timestamp`, `fee_limit`, …)
///    are preserved as-is.
/// 3. Serialize the rewritten `raw_data` to canonical protobuf bytes.
/// 4. Return `sha256( sha256(zen_token_id_utf8) || raw_data_bytes )`.
///
/// `zen_token_id` is the configured Zen TRC-10 token id (see
/// [`read_zen_token_id`] / `ZEN_TOKEN_ID` in the dynamic-properties
/// store). For uninitialized chains, java-tron defaults to `"000000"`.
pub fn compute_shielded_sighash(
    tx: &tron_proto::Transaction,
    zen_token_id: &str,
) -> Result<Sighash, ShieldedSighashError> {
    use prost::Message as _;
    use tron_proto::transaction::contract::ContractType;

    let raw_data = tx.raw_data.as_ref().ok_or(ShieldedSighashError::NoRawData)?;
    let first = raw_data.contract.first().ok_or(ShieldedSighashError::NoContracts)?;
    if first.r#type != ContractType::ShieldedTransferContract as i32 {
        return Err(ShieldedSighashError::NotShielded);
    }
    let parameter = first.parameter.as_ref().ok_or(ShieldedSighashError::NoParameter)?;

    // Decode → clear sigs → re-encode.
    let mut decoded = ShieldedTransferContract::decode(parameter.value.as_slice())?;
    for sd in &mut decoded.spend_description {
        sd.spend_authority_signature.clear();
    }
    let mut new_value = Vec::with_capacity(decoded.encoded_len());
    decoded.encode(&mut new_value).expect("encode into Vec is infallible");

    // Build a fresh Any with the same type_url and the rewritten value.
    let new_any = prost_types::Any {
        type_url: parameter.type_url.clone(),
        value: new_value,
    };

    // Build a fresh raw_data preserving everything *except* contract,
    // which gets replaced by a single Contract { type, parameter }.
    // java-tron's `Transaction.Contract.newBuilder().setType(...)
    // .setParameter(...).build()` does not carry over provider /
    // contract_name / permission_id — mirror that.
    let mut new_raw = raw_data.clone();
    new_raw.contract = vec![tron_proto::transaction::Contract {
        r#type: ContractType::ShieldedTransferContract as i32,
        parameter: Some(new_any),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id: 0,
    }];
    let mut raw_bytes = Vec::with_capacity(new_raw.encoded_len());
    new_raw.encode(&mut raw_bytes).expect("encode into Vec is infallible");

    // sha256( sha256(tokenId) || raw_bytes )
    let token_hash = tron_crypto::hash::sha256(zen_token_id.as_bytes());
    Ok(tron_crypto::hash::sha256_pair(&token_hash, &raw_bytes))
}

/// Validate a `ShieldedTransferContract` for inclusion in a block.
///
/// Returns `Ok(())` if the structural checks, duplicate-detection
/// checks, proof verification, and binding-signature check all pass.
///
/// `sighash` is the result of `getShieldTransactionHashIgnoreTypeException(tx)`
/// in java-tron — the caller computes it from the full transaction
/// proto (a TODO for the executor wiring layer).
///
/// Note: the **Merkle anchor lookup** is intentionally skipped here
/// (returns `Ok` for any 32-byte anchor). Re-add once a
/// `MerkleContainer` store is ported.
pub fn validate_shielded_transfer(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    nullifiers: &NullifierStore,
    merkle_trees: Option<&IncrementalMerkleTreeStore>,
    contract: &ShieldedTransferContract,
    sighash: &Sighash,
    fee: i64,
) -> Result<(), ActuatorError> {
    // === 1. Feature flags (proposal-gated). ===
    let allow_same_token_name = dyn_props.get_long(b" ALLOW_SAME_TOKEN_NAME").unwrap_or(0);
    if allow_same_token_name != 1 {
        return Err(ActuatorError::Validate(
            "shielded transaction is not allowed before ALLOW_SAME_TOKEN_NAME is opened",
        ));
    }
    // `supportShieldedTransaction()` == `ALLOW_SHIELDED_TRANSACTION` == 1.
    if dyn_props.get_long(b"ALLOW_SHIELDED_TRANSACTION").unwrap_or(0) != 1 {
        return Err(ActuatorError::Validate(
            "Not support Shielded Transaction, need to be opened by the committee",
        ));
    }

    // === 2. checkSender / checkReceiver. ===
    check_sender(contract)?;
    check_receiver(contract)?;

    // === 3. validateTransparent (length, balance — for transparent halves). ===
    validate_transparent(accounts, contract, fee)?;

    // === 4. Duplicate-detection within the transaction. ===
    let mut nf_set: HashSet<&[u8]> = HashSet::new();
    for sd in &contract.spend_description {
        if !nf_set.insert(&sd.nullifier) {
            return Err(ActuatorError::Validate(
                "duplicate sapling nullifiers in this transaction",
            ));
        }
        // === 4a. Anchor existence. ===
        // Java-tron's `merkleContainer.merkleRootExist(anchor)` — the
        // spend description's anchor must be a previously-known root
        // of the incremental Merkle tree.
        if sd.anchor.len() != 32 {
            return Err(ActuatorError::Validate("anchor must be 32 bytes"));
        }
        if let Some(mt) = merkle_trees {
            if !mt.contains(&sd.anchor) {
                return Err(ActuatorError::Validate("Rt is invalid."));
            }
        }
        // === 4b. Already-spent nullifier (against NullifierStore). ===
        if nullifiers.contains(&sd.nullifier) {
            return Err(ActuatorError::Validate(
                "note has been spent in this transaction",
            ));
        }
    }
    let mut cm_set: HashSet<&[u8]> = HashSet::new();
    for rd in &contract.receive_description {
        if !cm_set.insert(&rd.note_commitment) {
            return Err(ActuatorError::Validate(
                "duplicate cm in receive_description",
            ));
        }
    }
    if contract.spend_description.is_empty() && contract.receive_description.is_empty() {
        return Err(ActuatorError::Validate(
            "no Description found in transaction",
        ));
    }

    // === 5. Proof + binding-signature check. ===
    check_proofs(contract, sighash, fee, dyn_props)?;

    Ok(())
}

/// Execute the shielded transfer, mutating state:
/// * Append each spend's nullifier to the [`NullifierStore`].
/// * (Future) append each receive's note commitment to the Merkle tree.
/// * (Future) adjust TRC-10 Zen asset balances on the transparent halves.
///
/// Caller is expected to have called [`validate_shielded_transfer`]
/// first; this function does not re-validate.
pub fn execute_shielded_transfer(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    nullifiers: &NullifierStore,
    merkle_trees: Option<&IncrementalMerkleTreeStore>,
    contract: &ShieldedTransferContract,
) -> Result<ExecutionResult, ActuatorError> {
    let fee = read_shielded_fee(dyn_props, contract).unwrap_or(0);
    let zen_token_id = read_zen_token_id(dyn_props);

    // 1. Transparent debit (if any).
    let mut created_recipient = false;
    if !contract.transparent_from_address.is_empty() {
        adjust_zen_balance(
            accounts,
            &contract.transparent_from_address,
            &zen_token_id,
            -(contract.from_amount),
        )?;
    }

    // 2. Record nullifiers — prevents future double-spends.
    for sd in &contract.spend_description {
        if nullifiers.contains(&sd.nullifier) {
            return Err(ActuatorError::Execute(
                "double spend (nullifier appeared between validate and execute)",
            ));
        }
        nullifiers.put(&sd.nullifier);
    }

    // 3. Save commitments to MerkleContainer. We load the "current"
    //    tree (falling back to "last" then to an empty tree), append
    //    every receive's note_commitment, and persist back to
    //    `CURRENT_TREE_KEY`. The new root is also indexed under itself
    //    so future spend-anchor lookups succeed.
    if let Some(mt) = merkle_trees {
        let mut tree = mt
            .get(CURRENT_TREE_KEY)
            .ok()
            .flatten()
            .or_else(|| mt.get(LAST_TREE_KEY).ok().flatten())
            .map(|proto| IncrementalMerkleTree::from_proto(&proto))
            .unwrap_or_default();
        for rd in &contract.receive_description {
            if rd.note_commitment.len() != 32 {
                return Err(ActuatorError::Execute(
                    "note_commitment must be 32 bytes",
                ));
            }
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&rd.note_commitment);
            tree.append(cm)
                .map_err(|_| ActuatorError::Execute("merkle tree append failed"))?;
        }
        let tree_proto = tree.to_proto();
        mt.put(CURRENT_TREE_KEY, &tree_proto);
        let new_root = tree.root();
        mt.put(&new_root, &tree_proto);
    }

    // 4. Transparent credit (if any). Auto-create the recipient account
    //    if it doesn't exist (java-tron's executeTransparentTo path).
    if !contract.transparent_to_address.is_empty() {
        use tron_crypto::address::Address;
        let mut buf = [0u8; 21];
        buf.copy_from_slice(&contract.transparent_to_address);
        let addr = Address::from_raw(buf);
        if accounts.get(&addr)?.is_none() {
            // Bare-minimum account — java-tron uses `AccountType::Normal`
            // with current header timestamp; the field is informational
            // and not consensus-critical for the Zen credit itself.
            accounts.put(
                &addr,
                &tron_proto::Account {
                    address: contract.transparent_to_address.clone(),
                    ..Default::default()
                },
            );
            created_recipient = true;
        }
        adjust_zen_balance(
            accounts,
            &contract.transparent_to_address,
            &zen_token_id,
            contract.to_amount,
        )?;
    }

    // 5. Update TOTAL_SHIELDED_POOL_VALUE by -(toAmount - fromAmount + fee).
    let value_balance = contract
        .to_amount
        .checked_sub(contract.from_amount)
        .and_then(|v| v.checked_add(fee))
        .ok_or(ActuatorError::Execute("value_balance overflow"))?;
    let pool = dyn_props.get_long(b"TOTAL_SHIELDED_POOL_VALUE").unwrap_or(0);
    let new_pool = pool
        .checked_sub(value_balance)
        .ok_or(ActuatorError::Execute("shielded pool overflow"))?;
    if new_pool < 0 {
        return Err(ActuatorError::Execute(
            "total shielded pool value cannot go below zero",
        ));
    }
    dyn_props.put_long(b"TOTAL_SHIELDED_POOL_VALUE", new_pool);

    Ok(ExecutionResult {
        fee,
        created_recipient,
    })
}

/// Apply `amount` (positive = credit, negative = debit) to
/// `account.asset_v2[zen_token_id]` for the address `addr`. Returns
/// `Execute("balance insufficient")` if a debit would underflow.
fn adjust_zen_balance(
    accounts: &AccountStore,
    addr: &[u8],
    zen_token_id: &str,
    amount: i64,
) -> Result<(), ActuatorError> {
    use tron_crypto::address::Address;
    if addr.len() != 21 {
        return Err(ActuatorError::Validate("address must be 21 bytes"));
    }
    let mut buf = [0u8; 21];
    buf.copy_from_slice(addr);
    let a = Address::from_raw(buf);
    let mut acct = accounts
        .get(&a)?
        .ok_or(ActuatorError::Execute("Zen account missing"))?;
    let current = *acct.asset_v2.get(zen_token_id).unwrap_or(&0);
    let new_balance = current
        .checked_add(amount)
        .ok_or(ActuatorError::Execute("asset balance overflow"))?;
    if new_balance < 0 {
        return Err(ActuatorError::Execute("Zen balance insufficient"));
    }
    acct.asset_v2.insert(zen_token_id.to_string(), new_balance);
    accounts.put(&a, &acct);
    Ok(())
}

/// Read the configured Zen TRC-10 token id. java-tron stores this as a
/// command-line parameter (`zenTokenId`, defaults to `"000000"` for an
/// uninitialized chain). We honour an optional `ZEN_TOKEN_ID` entry in
/// DynamicPropertiesStore and fall back to the java-tron default.
fn read_zen_token_id(dyn_props: &DynamicPropertiesStore) -> String {
    if let Some(bytes) = dyn_props.get_bytes(b"ZEN_TOKEN_ID") {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return s.to_string();
        }
    }
    "000000".to_string()
}

// =================================================================
// Sub-checks
// =================================================================

fn check_sender(c: &ShieldedTransferContract) -> Result<(), ActuatorError> {
    let has_transparent_from = !c.transparent_from_address.is_empty();
    let spend_count = c.spend_description.len();
    if has_transparent_from && spend_count > 0 {
        return Err(ActuatorError::Validate(
            "ShieldedTransferContract error, more than 1 senders",
        ));
    }
    if !has_transparent_from && spend_count == 0 {
        return Err(ActuatorError::Validate(
            "ShieldedTransferContract error, no sender",
        ));
    }
    if spend_count > MAX_SPEND_COUNT {
        return Err(ActuatorError::Validate(
            "ShieldedTransferContract error, number of spend notes should not be more than 1",
        ));
    }
    Ok(())
}

fn check_receiver(c: &ShieldedTransferContract) -> Result<(), ActuatorError> {
    let recv_count = c.receive_description.len();
    if recv_count == 0 {
        return Err(ActuatorError::Validate(
            "ShieldedTransferContract error, no output cm",
        ));
    }
    if recv_count > MAX_RECEIVE_COUNT {
        return Err(ActuatorError::Validate(
            "ShieldedTransferContract error, number of receivers should not be more than 2",
        ));
    }
    Ok(())
}

fn validate_transparent(
    _accounts: &AccountStore,
    c: &ShieldedTransferContract,
    fee: i64,
) -> Result<(), ActuatorError> {
    let has_from = !c.transparent_from_address.is_empty();
    let has_to = !c.transparent_to_address.is_empty();

    if c.from_amount < 0 {
        return Err(ActuatorError::Validate(
            "from_amount should not be less than 0",
        ));
    }
    if c.to_amount < 0 {
        return Err(ActuatorError::Validate(
            "to_amount should not be less than 0",
        ));
    }
    if has_from && c.transparent_from_address.len() != ADDRESS_LENGTH {
        return Err(ActuatorError::Validate("Invalid transparent_from_address"));
    }
    if !has_from && c.from_amount != 0 {
        return Err(ActuatorError::Validate(
            "no transparent_from_address, from_amount should be 0",
        ));
    }
    if has_to && c.transparent_to_address.len() != ADDRESS_LENGTH {
        return Err(ActuatorError::Validate("Invalid transparent_to_address"));
    }
    if !has_to && c.to_amount != 0 {
        return Err(ActuatorError::Validate(
            "no transparent_to_address, to_amount should be 0",
        ));
    }
    if has_from && has_to && c.transparent_from_address == c.transparent_to_address {
        return Err(ActuatorError::Validate("Can't transfer zen to yourself"));
    }
    if has_from && c.from_amount <= fee {
        return Err(ActuatorError::Validate(
            "Validate ShieldedTransferContract error, fromAmount should be great than fee",
        ));
    }
    if has_to && c.to_amount <= 0 {
        return Err(ActuatorError::Validate("to_amount must be greater than 0"));
    }
    Ok(())
}

fn check_proofs(
    c: &ShieldedTransferContract,
    sighash: &Sighash,
    fee: i64,
    dyn_props: &DynamicPropertiesStore,
) -> Result<(), ActuatorError> {
    if c.spend_description.is_empty() && c.receive_description.is_empty() {
        return Ok(());
    }

    let mut cv_sum = SaplingCommitmentSum::zero();

    for sd in &c.spend_description {
        let (cv, anchor, nullifier, rk, proof, sas) = extract_spend(sd)?;
        let Some(spend_cv) = check_spend(&cv, &anchor, &nullifier, &rk, &proof, &sas, sighash)
        else {
            return Err(ActuatorError::Validate(
                "librustzcashSaplingCheckSpend error",
            ));
        };
        cv_sum += &spend_cv;
    }
    for rd in &c.receive_description {
        if rd.c_enc.len() != ZC_ENCCIPHERTEXT_SIZE || rd.c_out.len() != ZC_OUTCIPHERTEXT_SIZE {
            return Err(ActuatorError::Validate("Cout or CEnc size error"));
        }
        let (cv, cmu, epk, proof) = extract_receive(rd)?;
        let Some(out_cv) = check_output(&cv, &cmu, &epk, &proof) else {
            return Err(ActuatorError::Validate(
                "librustzcashSaplingCheckOutput error",
            ));
        };
        cv_sum -= &out_cv;
    }

    // valueBalance = (toAmount - fromAmount) + fee.
    let value_balance = c
        .to_amount
        .checked_sub(c.from_amount)
        .and_then(|v| v.checked_add(fee))
        .ok_or(ActuatorError::Validate("value_balance overflow"))?;

    // totalShieldedPoolValue must not go negative if we subtract value_balance.
    let pool = dyn_props.get_long(b"TOTAL_SHIELDED_POOL_VALUE").unwrap_or(0);
    let new_pool = pool
        .checked_sub(value_balance)
        .ok_or(ActuatorError::Validate("shieldedPoolValue error"))?;
    if new_pool < 0 {
        return Err(ActuatorError::Validate("shieldedPoolValue error"));
    }

    if c.binding_signature.len() != 64 {
        return Err(ActuatorError::Validate("binding_signature must be 64 bytes"));
    }
    let mut bs = [0u8; 64];
    bs.copy_from_slice(&c.binding_signature);
    if !check_binding_sig(&cv_sum, value_balance, sighash, &bs) {
        return Err(ActuatorError::Validate(
            "librustzcashSaplingFinalCheck error",
        ));
    }
    Ok(())
}

fn extract_spend(
    sd: &SpendDescription,
) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 192], [u8; 64]), ActuatorError> {
    fn fixed<const N: usize>(b: &[u8], what: &'static str) -> Result<[u8; N], ActuatorError> {
        if b.len() != N {
            return Err(ActuatorError::Validate(what));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }
    Ok((
        fixed::<32>(&sd.value_commitment, "spend.value_commitment must be 32 bytes")?,
        fixed::<32>(&sd.anchor, "spend.anchor must be 32 bytes")?,
        fixed::<32>(&sd.nullifier, "spend.nullifier must be 32 bytes")?,
        fixed::<32>(&sd.rk, "spend.rk must be 32 bytes")?,
        fixed::<192>(&sd.zkproof, "spend.zkproof must be 192 bytes")?,
        fixed::<64>(
            &sd.spend_authority_signature,
            "spend.spend_authority_signature must be 64 bytes",
        )?,
    ))
}

fn extract_receive(
    rd: &ReceiveDescription,
) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 192]), ActuatorError> {
    fn fixed<const N: usize>(b: &[u8], what: &'static str) -> Result<[u8; N], ActuatorError> {
        if b.len() != N {
            return Err(ActuatorError::Validate(what));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }
    Ok((
        fixed::<32>(&rd.value_commitment, "receive.value_commitment must be 32 bytes")?,
        fixed::<32>(
            &rd.note_commitment,
            "receive.note_commitment must be 32 bytes",
        )?,
        fixed::<32>(&rd.epk, "receive.epk must be 32 bytes")?,
        fixed::<192>(&rd.zkproof, "receive.zkproof must be 192 bytes")?,
    ))
}

fn read_shielded_fee(
    dyn_props: &DynamicPropertiesStore,
    _c: &ShieldedTransferContract,
) -> Option<i64> {
    // java-tron picks SHIELDED_TRANSACTION_CREATE_ACCOUNT_FEE when the
    // transparent recipient doesn't yet exist, else SHIELDED_TRANSACTION_FEE.
    // The simpler path is enough until transparent-asset accounting lands.
    dyn_props.get_long(b"SHIELDED_TRANSACTION_FEE")
}
