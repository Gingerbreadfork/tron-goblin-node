//! Block-producer tests: a block produced by our SR-side code must
//! pass the same verification the network-side code applies to incoming
//! blocks. This round-trip is the consensus invariant — produce →
//! verify yields no error.

use prost::Message;
use tron_consensus::{assemble_block, produce_block, ProducerError};
use tron_crypto::{address::Address, signature::RecoverableSignature};
use tron_proto::{transaction::Raw as TxRaw, Transaction};
use tron_types::{block_id_from_block, verify_parent_link, verify_tx_trie_root, verify_witness_signature, BlockId};

/// Make a synthetic transaction so we can exercise the tx_trie_root path.
fn dummy_tx() -> Transaction {
    Transaction {
        raw_data: Some(TxRaw {
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    }
}

/// Derive a witness keypair from a fixed scalar. Same trick used in
/// other tests in this crate — deterministic + lets us assert addresses.
fn witness_keypair(seed: u8) -> ([u8; 32], Address) {
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x01;
    priv_key[31] = seed;

    // Derive the address by recovering it from a signature we make over
    // a known input — same trick `tron-crypto::signature` already
    // exercises end-to-end.
    let dummy_hash = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy_hash).expect("sign");
    let pub_key = sig
        .recover_uncompressed_pubkey(&dummy_hash)
        .expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut bytes = [0u8; 21];
    bytes[0] = 0x41;
    bytes[1..].copy_from_slice(&h[12..]);
    (priv_key, Address::from_raw(bytes))
}

fn genesis_block_id() -> BlockId {
    let mut raw = [0u8; 32];
    raw[..8].copy_from_slice(&100i64.to_be_bytes());
    raw[8..].fill(0xab);
    BlockId::from_raw(raw)
}

#[test]
fn produced_block_passes_parent_link_check() {
    let (priv_key, witness) = witness_keypair(0xa1);
    let parent = genesis_block_id();
    let txs = vec![dummy_tx(), dummy_tx()];

    let (block, _id) = produce_block(
        &parent,
        101,
        1_700_000_003_000,
        &witness,
        &priv_key,
        txs,
        29,
    )
    .expect("produce_block");

    verify_parent_link(&block, parent).expect("parent link check");
}

#[test]
fn produced_block_passes_tx_trie_root_check() {
    let (priv_key, witness) = witness_keypair(0xa2);
    let parent = genesis_block_id();
    let txs = vec![dummy_tx(), dummy_tx(), dummy_tx()];

    let (block, _id) = produce_block(
        &parent,
        101,
        1_700_000_003_000,
        &witness,
        &priv_key,
        txs,
        29,
    )
    .unwrap();

    verify_tx_trie_root(&block).expect("tx trie root check");
}

#[test]
fn produced_block_signature_recovers_to_witness_address() {
    let (priv_key, witness) = witness_keypair(0xa3);
    let parent = genesis_block_id();

    let (block, _id) = produce_block(
        &parent,
        101,
        1_700_000_003_000,
        &witness,
        &priv_key,
        vec![],
        29,
    )
    .unwrap();

    let recovered = verify_witness_signature(&block, None).expect("recover signer");
    assert_eq!(recovered, witness);
}

#[test]
fn produce_block_rejects_non_monotonic_number() {
    let (priv_key, witness) = witness_keypair(0xa4);
    let parent = genesis_block_id(); // num = 100

    let result = produce_block(&parent, 100, 0, &witness, &priv_key, vec![], 29);
    match result.unwrap_err() {
        ProducerError::NonMonotonicNumber { parent: p, got: g } => {
            assert_eq!(p, 100);
            assert_eq!(g, 100);
        }
        other => panic!("expected NonMonotonicNumber, got {other:?}"),
    }
}

#[test]
fn assemble_block_sets_witness_address_in_header() {
    let (_priv, witness) = witness_keypair(0xa5);
    let parent = genesis_block_id();

    let block = assemble_block(&parent, 101, 1_700_000_003_000, &witness, vec![], 29).unwrap();
    let raw = block.block_header.as_ref().unwrap().raw_data.as_ref().unwrap();
    assert_eq!(raw.witness_address, witness.as_bytes());
    assert_eq!(raw.number, 101);
    assert_eq!(raw.timestamp, 1_700_000_003_000);
    assert_eq!(raw.parent_hash, parent.as_bytes());
}

#[test]
fn produced_block_id_is_consistent_with_block_header() {
    let (priv_key, witness) = witness_keypair(0xa6);
    let parent = genesis_block_id();
    let (block, id) =
        produce_block(&parent, 101, 1_700_000_003_000, &witness, &priv_key, vec![], 29).unwrap();
    let recomputed = block_id_from_block(&block).unwrap();
    assert_eq!(recomputed, id);
}

#[test]
fn block_for_broadcast_round_trips_through_prost() {
    let (priv_key, witness) = witness_keypair(0xa7);
    let parent = genesis_block_id();
    let (block, _) = produce_block(
        &parent,
        101,
        1_700_000_003_000,
        &witness,
        &priv_key,
        vec![dummy_tx()],
        29,
    )
    .unwrap();

    let bytes = tron_consensus::encode_for_broadcast(&block);
    let decoded = tron_proto::Block::decode(bytes.as_slice()).expect("re-decode");
    assert_eq!(decoded, block);
}
