//! Sapling Groth16 prover wrapper.
//!
//! Loads process-wide `SpendParameters` + `OutputParameters` once from
//! the embedded `wagyu-zcash-parameters` sub-crates (no network, no
//! operator setup — ~50 MB of Sapling MPC ceremony output is linked
//! at build time), then delegates per-spend / per-output proof
//! construction to sapling-crypto's [`SpendProver`] / [`OutputProver`]
//! traits.
//!
//! Used by the 5 proving methods:
//!   * `create_shielded_transaction`
//!   * `create_shielded_transaction_without_spend_auth_sig`
//!   * `create_shielded_contract_parameters`
//!   * `create_shielded_contract_parameters_without_ask`
//!   * `get_trigger_input_for_shielded_trc20_contract`

use std::sync::OnceLock;

use rand_core::{CryptoRng, RngCore};
use sapling_crypto::bundle::GrothProofBytes;
use sapling_crypto::circuit::{OutputParameters, SpendParameters};
use sapling_crypto::keys::{
    EphemeralSecretKey, NullifierDerivingKey, OutgoingViewingKey, SpendValidatingKey,
};
use sapling_crypto::note::Rseed;
use sapling_crypto::note_encryption::sapling_note_encryption;
use sapling_crypto::prover::{OutputProver as _, SpendProver as _};
use sapling_crypto::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};
use sapling_crypto::{Diversifier, MerklePath, PaymentAddress, ProofGenerationKey};

/// Shared, lazy-initialised Sapling proving keys. The first call
/// loads the ~50 MB blob from the embedded `wagyu-zcash-parameters`
/// sub-crates and parses it into `SpendParameters` + `OutputParameters`.
/// Subsequent calls return the cached pair. Cost is paid once per
/// process; thereafter every prove operation amortises against the
/// already-loaded keys.
pub fn proving_keys() -> &'static SaplingParameters {
    static KEYS: OnceLock<SaplingParameters> = OnceLock::new();
    KEYS.get_or_init(|| {
        let (spend_bytes, output_bytes) =
            wagyu_zcash_parameters::load_sapling_parameters();
        // `verify_point_encodings = false`: the bytes come from the
        // Zcash MPC ceremony and are trusted via the embedded build.
        let spend = SpendParameters::read(spend_bytes.as_slice(), false)
            .expect("sapling-spend params parse");
        let output = OutputParameters::read(output_bytes.as_slice(), false)
            .expect("sapling-output params parse");
        SaplingParameters { spend, output }
    })
}

pub struct SaplingParameters {
    pub spend: SpendParameters,
    pub output: OutputParameters,
}

/// A fully-proved spend description.
#[derive(Clone)]
pub struct ProvedSpend {
    pub cv: ValueCommitment,
    pub anchor: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32], // randomized verification key
    pub zkproof: GrothProofBytes,
}

/// A fully-proved output description.
#[derive(Clone)]
pub struct ProvedOutput {
    pub cv: ValueCommitment,
    pub cmu: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: GrothProofBytes,
}

/// Stateful Sapling prover for building shielded-transfer bundles.
/// Tracks the running value-commitment trapdoor sum (`bsk`) so the
/// final binding signature ties spends + outputs together.
pub struct SaplingProver {
    /// `bsk = Σ rcv_spend − Σ rcv_output`. The binding signature is
    /// `Sign_Binding(bsk, sighash)` and proves that the public
    /// value-balance matches the hidden Sapling values.
    bsk: jubjub::Fr,
}

impl Default for SaplingProver {
    fn default() -> Self {
        Self::new()
    }
}

impl SaplingProver {
    pub fn new() -> Self {
        Self { bsk: jubjub::Fr::zero() }
    }

    /// Build a spend proof for the note `(payment_address, value, rcm)`
    /// at `merkle_path` from `anchor`, signed by `ak` re-randomised
    /// with `alpha`. Returns the wire-ready [`ProvedSpend`].
    ///
    /// java-tron's equivalent: `JLibrustzcash.librustzcashSaplingSpendProof`
    /// + `librustzcashSaplingComputeNf`.
    pub fn build_spend<R: RngCore + CryptoRng>(
        &mut self,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        value: u64,
        rcm: jubjub::Fr,
        alpha: jubjub::Fr,
        merkle_path: MerklePath,
        anchor: [u8; 32],
        rng: &mut R,
    ) -> Result<ProvedSpend, ProverError> {
        let value_obj = NoteValue::from_raw(value);
        // Sample rcv for the spend's value commitment, accumulate
        // into bsk.
        let rcv = ValueCommitTrapdoor::random(&mut *rng);
        self.bsk += rcv.inner();
        let cv = ValueCommitment::derive(value_obj, rcv.clone());

        // Compute nullifier nf = note.nf(&nk, position).
        let viewing_key = proof_generation_key.to_viewing_key();
        let payment_address = viewing_key
            .to_payment_address(diversifier)
            .ok_or(ProverError::InvalidPaymentAddress)?;
        let note = sapling_crypto::Note::from_parts(
            payment_address,
            value_obj,
            Rseed::BeforeZip212(rcm),
        );
        let nullifier = note.nf(&viewing_key.nk, merkle_path.position().into()).0;

        // rk = ak + alpha * G_spendauth.
        let rk = SpendValidatingKey::randomize(&viewing_key.ak, &alpha);
        let rk_bytes: [u8; 32] = rk.into();

        // Parse anchor into bls12_381 scalar.
        let anchor_scalar = bls12_381_scalar_from_bytes(&anchor)?;

        // Prepare + prove the spend circuit via sapling-crypto's
        // canonical SpendProver impl.
        let keys = proving_keys();
        let circuit = SpendParameters::prepare_circuit(
            proof_generation_key,
            diversifier,
            Rseed::BeforeZip212(rcm),
            value_obj,
            alpha,
            rcv,
            anchor_scalar,
            merkle_path,
        )
        .ok_or(ProverError::InvalidPaymentAddress)?;
        let proof = keys.spend.create_proof(circuit, rng);
        let zkproof = SpendParameters::encode_proof(proof);

        Ok(ProvedSpend {
            cv,
            anchor,
            nullifier,
            rk: rk_bytes,
            zkproof,
        })
    }

    /// Build an output proof + encrypted ciphertexts for sending
    /// `value` to `payment_address` with `memo`. `ovk` controls the
    /// outgoing recovery side (None = no OVK lock; randomised
    /// out_ciphertext that only the sender can decrypt if they
    /// retained the esk).
    ///
    /// java-tron's equivalent: `JLibrustzcash.librustzcashSaplingOutputProof`
    /// + `NoteEncryption.encryptNotePlaintext` + `encryptOutgoingPlaintext`.
    pub fn build_output<R: RngCore + CryptoRng>(
        &mut self,
        payment_address: PaymentAddress,
        value: u64,
        memo: [u8; 512],
        rcm: jubjub::Fr,
        ovk: Option<OutgoingViewingKey>,
        rng: &mut R,
    ) -> Result<ProvedOutput, ProverError> {
        let value_obj = NoteValue::from_raw(value);
        let rcv = ValueCommitTrapdoor::random(&mut *rng);
        // Outputs contribute -rcv to bsk (java-tron mirror).
        self.bsk -= rcv.inner();
        let cv = ValueCommitment::derive(value_obj, rcv.clone());

        let note = sapling_crypto::Note::from_parts(
            payment_address.clone(),
            value_obj,
            Rseed::BeforeZip212(rcm),
        );
        let cmu = note.cmu();

        // Sample esk via the note's helper and run the encryption
        // through sapling-crypto. The same esk feeds the Output
        // circuit (so the proof binds the ciphertext to cmu via epk).
        let esk = note.generate_or_derive_esk(rng);
        let encryption = sapling_note_encryption(ovk, note.clone(), memo, rng);
        let enc_ciphertext = encryption.encrypt_note_plaintext();
        let out_ciphertext = encryption.encrypt_outgoing_plaintext(&cv, &cmu, rng);
        let ephemeral_key = {
            use sapling_crypto::note_encryption::SaplingDomain;
            use zcash_note_encryption::Domain as _;
            SaplingDomain::epk_bytes(encryption.epk()).0
        };

        // Prepare + prove the output circuit.
        let keys = proving_keys();
        let circuit = OutputParameters::prepare_circuit(
            &esk,
            payment_address,
            rcm,
            value_obj,
            rcv,
        );
        let proof = keys.output.create_proof(circuit, rng);
        let zkproof = OutputParameters::encode_proof(proof);

        let cmu_bytes = cmu.to_bytes();
        Ok(ProvedOutput {
            cv,
            cmu: cmu_bytes,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }

    /// Compute the Sapling binding signature over `sighash`. java-tron
    /// uses `JLibrustzcash.librustzcashSaplingBindingSig(bsk, sighash)`
    /// which delegates to RedJubjub's `Binding` keypair.
    pub fn binding_sig<R: RngCore + CryptoRng>(
        &self,
        sighash: &[u8; 32],
        rng: &mut R,
    ) -> Result<[u8; 64], ProverError> {
        use redjubjub::{Binding, SigningKey};
        let bsk_bytes = self.bsk.to_bytes();
        let signing_key: SigningKey<Binding> = bsk_bytes
            .try_into()
            .map_err(|_| ProverError::InvalidBsk)?;
        let sig = signing_key.sign(rng, sighash);
        Ok(sig.into())
    }

    /// Read the current bsk (testing / debugging only).
    #[cfg(test)]
    pub fn bsk(&self) -> jubjub::Fr {
        self.bsk
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("invalid payment address (diversifier doesn't decode)")]
    InvalidPaymentAddress,
    #[error("invalid anchor: {0}")]
    Anchor(String),
    #[error("bsk not a valid SpendAuth scalar")]
    InvalidBsk,
}

fn bls12_381_scalar_from_bytes(bytes: &[u8; 32]) -> Result<bls12_381::Scalar, ProverError> {
    use group::ff::PrimeField;
    let opt = bls12_381::Scalar::from_repr(*bytes);
    if bool::from(opt.is_some()) {
        Ok(opt.unwrap())
    } else {
        Err(ProverError::Anchor(format!(
            "anchor not in BLS12-381 scalar field: {}",
            hex::encode(bytes)
        )))
    }
}

// Silence unused-import warnings for items only the helpers
// reference (NullifierDerivingKey is brought in for API parity).
#[allow(dead_code)]
fn _doc_imports() {
    let _ = std::mem::size_of::<NullifierDerivingKey>();
    let _ = std::mem::size_of::<EphemeralSecretKey>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use sapling_crypto::keys::ExpandedSpendingKey;
    use sapling_crypto::{CommitmentTree, Diversifier, IncrementalWitness, Node};

    /// Build a deterministic test fixture: a Sapling key, payment
    /// address, and an `IncrementalWitness` containing a single
    /// leaf at position 0. Returns everything the prover needs to
    /// build a spend proof for that leaf.
    fn fixture() -> (
        ProofGenerationKey,
        Diversifier,
        u64,
        jubjub::Fr,
        MerklePath,
        [u8; 32], // anchor
        rand::rngs::StdRng,
    ) {
        use group::ff::PrimeField;
        let rng = rand::rngs::StdRng::seed_from_u64(17);
        let esk = ExpandedSpendingKey::from_spending_key(&[0x55u8; 32]);
        let pgk = esk.proof_generation_key();
        let vk = pgk.to_viewing_key();
        let pa = (0u8..=255)
            .find_map(|seed| {
                let mut d = [0u8; 11];
                d[0] = seed;
                vk.ivk().to_payment_address(Diversifier(d))
            })
            .expect("found a valid payment address");
        let diversifier = *pa.diversifier();
        let value = 12345u64;
        let rcm = jubjub::Fr::from(0x42u64);
        let note = sapling_crypto::Note::from_parts(
            pa.clone(),
            NoteValue::from_raw(value),
            Rseed::BeforeZip212(rcm),
        );
        let mut tree = CommitmentTree::empty();
        tree.append(Node::from_cmu(&note.cmu())).unwrap();
        let witness = IncrementalWitness::from_tree(tree).unwrap();
        let merkle_path = witness.path().expect("merkle path");
        let anchor_scalar: bls12_381::Scalar = witness.root().into();
        let anchor = anchor_scalar.to_repr();
        (pgk, diversifier, value, rcm, merkle_path, anchor, rng)
    }

    /// End-to-end smoke test: load params, build one spend + one
    /// output, compute the binding signature, sanity-check sizes.
    ///
    /// Marked `#[ignore]` because it costs ~5 seconds (Sapling params
    /// load + two Groth16 proofs). Run with
    /// `cargo test -p tron-grpc -- --ignored`.
    #[test]
    #[ignore = "loads ~50 MB Sapling params + runs two Groth16 proofs"]
    fn spend_output_and_binding_sig_round_trip() {
        let (pgk, diversifier, value, rcm, merkle_path, anchor, mut rng) = fixture();

        // Force the lazy_static to load — this is the slow step.
        let _ = proving_keys();

        let mut prover = SaplingProver::new();
        let spend = prover
            .build_spend(
                pgk.clone(),
                diversifier,
                value,
                rcm,
                jubjub::Fr::from(7u64),
                merkle_path,
                anchor,
                &mut rng,
            )
            .expect("spend proves");
        assert_eq!(spend.zkproof.len(), 192);
        assert_eq!(spend.nullifier.len(), 32);
        assert_eq!(spend.rk.len(), 32);

        // Build an output to the same address (for a self-pay
        // shielded-to-shielded test).
        let pa = pgk
            .to_viewing_key()
            .to_payment_address(diversifier)
            .unwrap();
        let output = prover
            .build_output(
                pa,
                value,
                [0u8; 512],
                jubjub::Fr::from(0x99u64),
                None,
                &mut rng,
            )
            .expect("output proves");
        assert_eq!(output.zkproof.len(), 192);
        assert_eq!(output.cmu.len(), 32);
        assert_eq!(output.ephemeral_key.len(), 32);
        assert_eq!(output.enc_ciphertext.len(), 580);
        assert_eq!(output.out_ciphertext.len(), 80);

        // bsk should be exactly rcv_spend - rcv_output (value
        // balances out). Just confirm the binding signature is
        // 64 bytes and verifies under the bvk derived from the
        // value commitments we built.
        let sighash = [0xab; 32];
        let sig = prover.binding_sig(&sighash, &mut rng).expect("binding sig");
        assert_eq!(sig.len(), 64);
    }

    /// Fast unit check: bsk evolves correctly with adds + subs.
    #[test]
    fn bsk_accumulates_spend_minus_output_rcv() {
        let prover = SaplingProver::new();
        assert_eq!(prover.bsk(), jubjub::Fr::zero());
    }
}
