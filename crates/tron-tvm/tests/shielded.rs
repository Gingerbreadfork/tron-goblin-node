//! Tests for the shielded TRC-20 precompiles.
//!
//! `MerkleHash` (0x01000004) is fully implemented and validated here.
//! The three SNARK verifiers (`VerifyMintProof`, `VerifyTransferProof`,
//! `VerifyBurnProof`) are tested for: VK decoding, input-length
//! validation, and rejection of malformed/zero proofs. End-to-end
//! verification against real shielded TRC-20 proofs requires test
//! vectors from a live shielded transaction, which we don't yet have.

use tron_tvm::shielded::{
    decode_merkle_hash_input, merkle_hash, prepared_output_vk, prepared_spend_vk,
    verify_burn_proof, verify_mint_proof, verify_transfer_proof, IncrementalMerkleTree,
    MERKLE_TREE_DEPTH,
};

#[test]
fn merkle_hash_is_deterministic() {
    let lhs = [0xaau8; 32];
    let rhs = [0xbbu8; 32];
    let r1 = merkle_hash(0, &lhs, &rhs);
    let r2 = merkle_hash(0, &lhs, &rhs);
    assert_eq!(r1, r2);
}

#[test]
fn merkle_hash_depth_affects_output() {
    let lhs = [0xaau8; 32];
    let rhs = [0xbbu8; 32];
    let at_0 = merkle_hash(0, &lhs, &rhs);
    let at_5 = merkle_hash(5, &lhs, &rhs);
    assert_ne!(
        at_0, at_5,
        "Personalization::MerkleTree(depth) must affect the hash"
    );
}

#[test]
fn merkle_hash_lhs_rhs_order_matters() {
    let a = [0xaau8; 32];
    let b = [0xbbu8; 32];
    let ab = merkle_hash(0, &a, &b);
    let ba = merkle_hash(0, &b, &a);
    assert_ne!(ab, ba, "lhs/rhs swap should change the hash");
}

#[test]
fn merkle_hash_output_is_32_bytes() {
    let r = merkle_hash(0, &[0u8; 32], &[0u8; 32]);
    assert_eq!(r.len(), 32);
}

#[test]
fn decode_rejects_wrong_length() {
    assert!(decode_merkle_hash_input(&[]).is_none());
    assert!(decode_merkle_hash_input(&[0u8; 95]).is_none());
    assert!(decode_merkle_hash_input(&[0u8; 97]).is_none());
}

#[test]
fn decode_rejects_oversized_depth() {
    let mut input = [0u8; 96];
    // depth = 1000 — well outside the Sapling tree depth limit.
    input[24..32].copy_from_slice(&1000u64.to_be_bytes());
    assert!(decode_merkle_hash_input(&input).is_none());
}

#[test]
fn decode_accepts_well_formed_input() {
    let mut input = [0u8; 96];
    input[31] = 5; // depth = 5
    input[32..64].fill(0x11); // lhs
    input[64..96].fill(0x22); // rhs

    let (depth, lhs, rhs) = decode_merkle_hash_input(&input).expect("valid");
    assert_eq!(depth, 5);
    assert_eq!(lhs, [0x11u8; 32]);
    assert_eq!(rhs, [0x22u8; 32]);
}

/// End-to-end: feed the well-formed input through the dispatched
/// precompile and confirm we get back a 32-byte response.
#[test]
fn merkle_hash_precompile_routes_through_registry() {
    use tron_tvm::precompiles::PrecompileImpl;

    // Build a minimal MockContext — same shape as our other precompile
    // tests but inlined here since MerkleHash needs no state access.
    struct EmptyCtx;
    impl tron_tvm::EvmContext for EmptyCtx {
        fn caller(&self) -> tron_crypto::address::Address {
            tron_crypto::address::Address::from_raw([0u8; 21])
        }
        fn callee(&self) -> tron_crypto::address::Address {
            tron_crypto::address::Address::from_raw([0u8; 21])
        }
        fn get_account(
            &self,
            _a: &tron_crypto::address::Address,
        ) -> Result<Option<tron_proto::Account>, tron_tvm::EvmContextError> {
            Ok(None)
        }
        fn get_witness(
            &self,
            _a: &tron_crypto::address::Address,
        ) -> Result<Option<tron_proto::Witness>, tron_tvm::EvmContextError> {
            Ok(None)
        }
        fn chain_parameter_long(
            &self,
            _key: &[u8],
        ) -> Result<Option<i64>, tron_tvm::EvmContextError> {
            Ok(None)
        }
        fn block_number(&self) -> i64 {
            0
        }
        fn block_timestamp_ms(&self) -> i64 {
            0
        }
        fn all_witnesses(
            &self,
        ) -> Result<Vec<tron_proto::Witness>, tron_tvm::EvmContextError> {
            Ok(Vec::new())
        }
        fn get_delegated_resource(
            &self,
            _from: &tron_crypto::address::Address,
            _to: &tron_crypto::address::Address,
        ) -> Result<Option<tron_proto::DelegatedResource>, tron_tvm::EvmContextError> {
            Ok(None)
        }
        fn dynamic_energy_factor(
            &self,
            _contract: &tron_crypto::address::Address,
        ) -> Result<i64, tron_tvm::EvmContextError> {
            Ok(0)
        }
    }

    let mut input = [0u8; 96];
    input[31] = 3; // depth = 3
    input[32..64].fill(0x01);
    input[64..96].fill(0x02);

    let out = PrecompileImpl::MerkleHash
        .execute(&input, &EmptyCtx)
        .expect("MerkleHash should succeed for valid input");
    assert_eq!(out.len(), 32);
}

// =================================================================
// SNARK verifier framework — VK decoding + input validation
// =================================================================

#[test]
fn embedded_spend_vk_decodes_successfully() {
    // Forces lazy decode of SPEND_VK_BYTES through bellman::VerifyingKey::read.
    let _ = prepared_spend_vk();
}

#[test]
fn embedded_output_vk_decodes_successfully() {
    let _ = prepared_output_vk();
}

#[test]
fn verify_mint_proof_rejects_empty_input() {
    let out = verify_mint_proof(&[]);
    assert_eq!(out, vec![0u8; 32]);
}

#[test]
fn verify_mint_proof_rejects_wrong_size() {
    // Must be exactly 1504 bytes.
    assert_eq!(verify_mint_proof(&[0u8; 1503]), vec![0u8; 32]);
    assert_eq!(verify_mint_proof(&[0u8; 1505]), vec![0u8; 32]);
}

#[test]
fn verify_mint_proof_rejects_all_zero_input() {
    // 1504-byte zero input: cv/cm/epk/proof are all-zero, which the
    // verifier rejects when decoding (cv is small order, epk is
    // identity, proof is malformed). Expect 32-byte zero.
    let out = verify_mint_proof(&[0u8; 1504]);
    assert_eq!(out, vec![0u8; 32]);
}

#[test]
fn verify_burn_proof_rejects_empty_input() {
    assert_eq!(verify_burn_proof(&[]), vec![0u8; 32]);
}

#[test]
fn verify_burn_proof_rejects_wrong_size() {
    assert_eq!(verify_burn_proof(&[0u8; 511]), vec![0u8; 32]);
    assert_eq!(verify_burn_proof(&[0u8; 513]), vec![0u8; 32]);
}

#[test]
fn verify_burn_proof_rejects_all_zero_input() {
    assert_eq!(verify_burn_proof(&[0u8; 512]), vec![0u8; 32]);
}

#[test]
fn verify_transfer_proof_rejects_invalid_sizes() {
    // Valid sizes are exactly {2080, 2368, 2464, 2752}.
    assert_eq!(verify_transfer_proof(&[]), vec![0u8; 32]);
    assert_eq!(verify_transfer_proof(&[0u8; 100]), vec![0u8; 32]);
    assert_eq!(verify_transfer_proof(&[0u8; 2079]), vec![0u8; 32]);
    assert_eq!(verify_transfer_proof(&[0u8; 2081]), vec![0u8; 32]);
}

#[test]
fn verify_transfer_proof_rejects_all_zero_valid_size() {
    // All-zero 2080-byte input: offsets are all 0 which means spend/
    // output counts read from offset 0 — they'll be 0 too, which fails
    // the 1<=count<=2 check.
    assert_eq!(verify_transfer_proof(&[0u8; 2080]), vec![0u8; 32]);
}

// =================================================================
// IncrementalMerkleTree
// =================================================================

#[test]
fn empty_tree_has_size_zero() {
    let t = IncrementalMerkleTree::new();
    assert_eq!(t.size(), 0);
    assert!(!t.is_complete());
}

#[test]
fn appending_grows_size_and_progresses_through_left_right_then_parents() {
    let mut t = IncrementalMerkleTree::new();
    t.append([1u8; 32]).unwrap();
    assert_eq!(t.size(), 1);
    assert_eq!(t.left, Some([1u8; 32]));
    assert!(t.right.is_none());

    t.append([2u8; 32]).unwrap();
    assert_eq!(t.size(), 2);
    assert_eq!(t.right, Some([2u8; 32]));

    // Third leaf: collapses left+right into parents[0], resets left=leaf, right=None.
    t.append([3u8; 32]).unwrap();
    assert_eq!(t.size(), 3);
    assert_eq!(t.left, Some([3u8; 32]));
    assert!(t.right.is_none());
    assert_eq!(t.parents.len(), 1);
    assert!(t.parents[0].is_some());

    t.append([4u8; 32]).unwrap();
    assert_eq!(t.size(), 4);
    // After 4 leaves: left=3, right=4, parents[0] holds combine(1,2).
}

#[test]
fn root_is_deterministic_for_same_leaves() {
    let mut a = IncrementalMerkleTree::new();
    let mut b = IncrementalMerkleTree::new();
    for i in 0..5u8 {
        a.append([i; 32]).unwrap();
        b.append([i; 32]).unwrap();
    }
    assert_eq!(a.root(), b.root());
}

#[test]
fn root_changes_when_leaves_change() {
    let mut a = IncrementalMerkleTree::new();
    let mut b = IncrementalMerkleTree::new();
    a.append([0xaau8; 32]).unwrap();
    b.append([0xbbu8; 32]).unwrap();
    assert_ne!(a.root(), b.root());
}

#[test]
fn proto_round_trip_preserves_state() {
    let mut t = IncrementalMerkleTree::new();
    for i in 0..7u8 {
        t.append([i; 32]).unwrap();
    }
    let proto = t.to_proto();
    let decoded = IncrementalMerkleTree::from_proto(&proto);
    assert_eq!(t, decoded);
    assert_eq!(t.root(), decoded.root());
}

#[test]
fn tree_depth_constant_matches_sapling_spec() {
    assert_eq!(MERKLE_TREE_DEPTH, 32);
}
