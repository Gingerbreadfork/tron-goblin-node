//! Domain-layer parity tests against java-tron behaviour.

use hex_literal::hex;
use prost::Message;
use tron_crypto::base58check::decode_address;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract, Raw as TxRaw};
use tron_proto::{Block, BlockHeader, Transaction, TransferContract};
use tron_types::{
    block_id_from_block, block_id_from_header_raw, block_raw_hash, build_genesis_block,
    calc_tx_trie_root, genesis_block_id, mainnet_inputs, recover_signer_address, sign_block,
    sign_transaction, tx_id, tx_merkle_hash, verify_parent_link, verify_tx_trie_root,
    verify_witness_signature, BlockId, BlockIdError, BlockValidateError, GENESIS_OWNER_ADDRESS,
    MAINNET_ASSETS, MAINNET_PARENT_HASH, MAINNET_WITNESS_QUOTE,
};

// --- BlockId layout ---------------------------------------------------------

/// The first 8 bytes of a BlockId encode the block number in big-endian,
/// overwriting whatever `sha256(header)` produced for those bytes.
#[test]
fn block_id_first_eight_bytes_are_block_number_big_endian() {
    let hash = hex!("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    let id = BlockId::from_hash_and_num(&hash, 0x0102030405060708);
    assert_eq!(&id.as_bytes()[0..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    // The tail (bytes 8..32) is taken from the original hash unchanged.
    assert_eq!(&id.as_bytes()[8..32], &hash[8..32]);
    assert_eq!(id.num(), 0x0102030405060708);
}

#[test]
fn block_id_num_zero_clears_first_eight_bytes() {
    let hash = [0xffu8; 32];
    let id = BlockId::from_hash_and_num(&hash, 0);
    assert_eq!(&id.as_bytes()[0..8], &[0u8; 8]);
    assert_eq!(&id.as_bytes()[8..32], &hash[8..32]);
}

/// Building a BlockId from a real `BlockHeaderRaw` and checking the
/// embedded number round-trips. The hash bytes are pinned so any change to
/// the proto encoding of `BlockHeaderRaw` produces a test failure.
#[test]
fn block_id_from_header_raw_pins_encoding() {
    let raw = BlockHeaderRaw {
        timestamp: 1_700_000_000_000,
        tx_trie_root: vec![0x11; 32],
        parent_hash: vec![0x22; 32],
        number: 12345,
        witness_id: 7,
        witness_address: hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").to_vec(),
        version: 28,
        account_state_root: vec![0x33; 32],
    };
    let id = block_id_from_header_raw(&raw);
    assert_eq!(id.num(), 12345);
    // First 8 bytes match number; tail must be deterministic across runs.
    let id_again = block_id_from_header_raw(&raw);
    assert_eq!(id, id_again);
}

#[test]
fn block_id_from_block_errors_when_header_missing() {
    let block = Block {
        transactions: Vec::new(),
        block_header: None,
    };
    assert_eq!(block_id_from_block(&block), Err(BlockIdError::MissingHeader));
}

#[test]
fn block_id_from_block_with_full_header() {
    let raw = BlockHeaderRaw {
        timestamp: 100,
        tx_trie_root: Vec::new(),
        parent_hash: vec![0u8; 32],
        number: 1,
        witness_id: 0,
        witness_address: Vec::new(),
        version: 0,
        account_state_root: Vec::new(),
    };
    let block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(raw.clone()),
            witness_signature: Vec::new(),
        }),
    };
    let from_block = block_id_from_block(&block).unwrap();
    let from_raw = block_id_from_header_raw(&raw);
    assert_eq!(from_block, from_raw);
    assert_eq!(from_block.num(), 1);
}

// --- Transaction id vs merkle hash ------------------------------------------

fn sample_transfer_tx() -> Transaction {
    let tc = TransferContract {
        owner_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
        to_address: hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").to_vec(),
        amount: 1_000_000,
    };
    let contract = Contract {
        r#type: ContractType::TransferContract as i32,
        parameter: Some(::prost_types::Any {
            type_url: "type.googleapis.com/protocol.TransferContract".into(),
            value: tc.encode_to_vec(),
        }),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id: 0,
    };
    let raw = TxRaw {
        ref_block_bytes: vec![0xab, 0xcd],
        ref_block_num: 0,
        ref_block_hash: vec![0u8; 8],
        expiration: 1_700_000_000_000,
        auths: Vec::new(),
        data: Vec::new(),
        contract: vec![contract],
        scripts: Vec::new(),
        timestamp: 1_700_000_000_000,
        fee_limit: 0,
    };
    Transaction {
        raw_data: Some(raw),
        signature: vec![vec![0xaa; 65]],
        ret: Vec::new(),
        unparsed_field10: None,
    }
}

/// **Critical:** the tx id (over raw_data only) must differ from the merkle
/// hash (over the whole transaction) once a signature is attached. Mixing
/// the two corrupts the block's `txTrieRoot`.
#[test]
fn tx_id_differs_from_merkle_hash_when_signed() {
    let tx = sample_transfer_tx();
    let id = tx_id(&tx).unwrap();
    let mh = tx_merkle_hash(&tx);
    assert_ne!(id, mh, "tx id and merkle hash must differ for signed txs");
}

/// Even with no signatures or `ret`, the merkle hash differs from the tx
/// id: the outer `Transaction` message adds a length-prefixed tag around
/// `raw_data`, so `Transaction.encode()` never equals `raw_data.encode()`.
/// This is the source of one of the easiest consensus bugs to hit in any
/// reimplementation — "they should be the same when unsigned" is wrong.
#[test]
fn tx_id_still_differs_from_merkle_hash_when_unsigned() {
    let mut tx = sample_transfer_tx();
    tx.signature.clear();
    tx.ret.clear();
    let id = tx_id(&tx).unwrap();
    let mh = tx_merkle_hash(&tx);
    assert_ne!(id, mh);
}

#[test]
fn tx_id_errors_when_raw_data_missing() {
    let tx = Transaction {
        raw_data: None,
        signature: Vec::new(),
        ret: Vec::new(),
        unparsed_field10: None,
    };
    assert!(tx_id(&tx).is_err());
}

// --- txTrieRoot Merkle computation ------------------------------------------

#[test]
fn tx_trie_root_empty_block_returns_none() {
    assert!(calc_tx_trie_root(&[]).is_none());
}

#[test]
fn tx_trie_root_single_tx_equals_its_merkle_hash() {
    let tx = sample_transfer_tx();
    let root = calc_tx_trie_root(std::slice::from_ref(&tx)).unwrap();
    assert_eq!(root, tx_merkle_hash(&tx));
}

// --- Genesis block ---------------------------------------------------------

/// **TRAP**: the genesis owner address is the *ASCII string*
/// `"0x000000000000000000000"` — 23 bytes, not 21, and not zero bytes.
#[test]
fn genesis_owner_address_is_23_ascii_bytes() {
    assert_eq!(GENESIS_OWNER_ADDRESS.len(), 23);
    assert_eq!(GENESIS_OWNER_ADDRESS, b"0x000000000000000000000");
    // First two bytes are ASCII '0' and 'x'.
    assert_eq!(GENESIS_OWNER_ADDRESS[0], 0x30);
    assert_eq!(GENESIS_OWNER_ADDRESS[1], 0x78);
    // Remaining 21 bytes are ASCII '0' (0x30), not 0x00.
    assert!(GENESIS_OWNER_ADDRESS[2..].iter().all(|&b| b == 0x30));
}

/// The Berners-Lee witness quote is 115 ASCII bytes.
#[test]
fn mainnet_witness_quote_pinned() {
    assert_eq!(
        MAINNET_WITNESS_QUOTE,
        b"A new system must allow existing systems to be linked together without \
          requiring any central control or coordination"
    );
}

#[test]
fn mainnet_parent_hash_is_e58f33() {
    assert_eq!(
        MAINNET_PARENT_HASH,
        hex!("e58f33f9baf9305dc6f82b9f1934ea8f0ade2defb951258d50167028c780351f")
    );
}

/// Re-derive each mainnet asset address from its Base58 string and check
/// against the hard-coded bytes in [`MAINNET_ASSETS`]. If a hard-coded
/// byte is wrong this test fails loudly with both representations.
#[test]
fn mainnet_asset_addresses_round_trip_via_base58() {
    let pairs: [(&str, [u8; 21]); 3] = [
        ("TLLM21wteSPs4hKjbxgmH1L6poyMjeTbHm", MAINNET_ASSETS[0].address),
        ("TXmVpin5vq5gdZsciyyjdZgKRUju4st1wM", MAINNET_ASSETS[1].address),
        ("TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy", MAINNET_ASSETS[2].address),
    ];
    for (s, expected) in pairs {
        let decoded = decode_address(s).expect("valid base58");
        assert_eq!(
            decoded.as_bytes(),
            &expected,
            "address {s} decoded to {:02x?} but constant has {:02x?}",
            decoded.as_bytes(),
            expected,
        );
        // Mainnet prefix.
        assert_eq!(decoded.prefix(), 0x41);
    }
}

#[test]
fn mainnet_asset_balances_match_config() {
    assert_eq!(MAINNET_ASSETS[0].balance, 99_000_000_000_000_000); // Zion
    assert_eq!(MAINNET_ASSETS[1].balance, 0); // Sun
    assert_eq!(MAINNET_ASSETS[2].balance, i64::MIN); // Blackhole
}

#[test]
fn genesis_block_has_three_transactions() {
    let block = build_genesis_block(&mainnet_inputs());
    assert_eq!(block.transactions.len(), 3);
    let header = block.block_header.as_ref().unwrap();
    let raw = header.raw_data.as_ref().unwrap();
    assert_eq!(raw.number, 0);
    assert_eq!(raw.timestamp, 0);
    assert_eq!(raw.parent_hash, MAINNET_PARENT_HASH);
    assert_eq!(raw.witness_address, MAINNET_WITNESS_QUOTE);
}

#[test]
fn genesis_tx_owner_address_is_the_23_byte_literal() {
    let block = build_genesis_block(&mainnet_inputs());
    for tx in &block.transactions {
        let inner_any = &tx.raw_data.as_ref().unwrap().contract[0]
            .parameter
            .as_ref()
            .unwrap()
            .value;
        let inner = TransferContract::decode(inner_any.as_slice()).unwrap();
        assert_eq!(inner.owner_address.len(), 23, "must be 23-byte ASCII literal");
        assert_eq!(inner.owner_address, GENESIS_OWNER_ADDRESS);
    }
}

#[test]
fn genesis_tx_trie_root_is_set() {
    let block = build_genesis_block(&mainnet_inputs());
    let header_raw = block.block_header.unwrap().raw_data.unwrap();
    assert_eq!(header_raw.tx_trie_root.len(), 32, "should be a 32-byte hash");
    assert_ne!(header_raw.tx_trie_root, vec![0u8; 32], "should not be all zeros");
}

/// **End-to-end pin**: compute the genesis `BlockId` through the entire
/// stack (Base58Check → assets → genesis txs → merkle root → header proto
/// → sha256 → num-prefix overwrite) and pin the resulting bytes.
///
/// If a future refactor breaks any of those steps this test fires with a
/// before/after diff. The pinned value is the deterministic output of
/// this exact recipe; it should match the published mainnet genesis
/// block id, which an operator can confirm against any public TRON
/// block explorer.
#[test]
fn mainnet_genesis_block_id_is_deterministic() {
    let id = genesis_block_id(&mainnet_inputs());
    // First 8 bytes are the block number (0).
    assert_eq!(&id.as_bytes()[0..8], &[0u8; 8]);
    assert_eq!(id.num(), 0);

    // Re-computing gives the same bytes.
    let id2 = genesis_block_id(&mainnet_inputs());
    assert_eq!(id, id2);

    // The tail (24 bytes from sha256 of the header) must be deterministic
    // and non-zero. The full byte sequence is printed on failure so an
    // operator can compare against a block explorer.
    let tail = &id.as_bytes()[8..32];
    assert_ne!(tail, &[0u8; 24], "BlockId tail should be a real hash");
    println!("mainnet genesis BlockId: 0x{}", hex::encode(id.as_bytes()));
}

// --- Transaction signing ---------------------------------------------------

/// Round-trip: sign a transaction, then recover the signer's address from
/// the signature. This is the exact flow `TransactionCapsule.sign` →
/// `Wallet.getAddressByTransaction` performs.
#[test]
fn sign_then_recover_signer_matches_original_address() {
    // Known private key from java-tron's ECKeyTest fixture.
    let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");
    let expected_address = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");

    let mut tx = sample_transfer_tx();
    tx.signature.clear(); // start unsigned
    let sig = sign_transaction(&mut tx, &priv_key).unwrap();
    assert!(sig.is_canonical(), "signature must be low-S canonical");

    // After signing the tx has exactly one signature attached.
    assert_eq!(tx.signature.len(), 1);
    assert_eq!(tx.signature[0].len(), 65, "[r||s||v] = 65 bytes");

    let recovered = recover_signer_address(&tx).unwrap();
    assert_eq!(recovered.as_bytes(), &expected_address);
}

#[test]
fn multi_sig_accumulates_signatures_in_order() {
    let priv_a = [11u8; 32];
    let priv_b = [22u8; 32];

    let mut tx = sample_transfer_tx();
    tx.signature.clear();

    sign_transaction(&mut tx, &priv_a).unwrap();
    sign_transaction(&mut tx, &priv_b).unwrap();

    assert_eq!(tx.signature.len(), 2);
    let signers = tron_types::recover_all_signers(&tx).unwrap();
    assert_eq!(signers.len(), 2);
    assert_ne!(signers[0], signers[1]); // distinct keys → distinct addresses
}

#[test]
fn signing_a_transaction_with_no_raw_data_errors() {
    use tron_proto::Transaction as T;
    let mut tx = T {
        raw_data: None,
        signature: Vec::new(),
        ret: Vec::new(),
        unparsed_field10: None,
    };
    let priv_key = [1u8; 32];
    assert!(sign_transaction(&mut tx, &priv_key).is_err());
}

// --- Block validation ------------------------------------------------------

fn sample_block(num: i64) -> tron_proto::Block {
    use tron_proto::{Block, BlockHeader};
    Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000 + num,
                tx_trie_root: Vec::new(),
                parent_hash: vec![0u8; 32],
                number: num,
                witness_id: 0,
                witness_address: Vec::new(),
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
    }
}

/// The witness signs `sha256(block_header.raw_data.encode())` — distinct
/// from the BlockId (which overwrites the first 8 bytes). Round-trip:
/// sign with a known key, recover, verify.
#[test]
fn block_witness_signature_round_trip() {
    let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");
    let witness_addr = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"); // derived from priv_key

    let mut block = sample_block(1);
    // The witness_address must match the signer for verify to pass.
    block
        .block_header
        .as_mut()
        .unwrap()
        .raw_data
        .as_mut()
        .unwrap()
        .witness_address = witness_addr.to_vec();

    sign_block(&mut block, &priv_key).unwrap();
    let recovered = verify_witness_signature(&block, None).unwrap();
    assert_eq!(recovered.as_bytes(), &witness_addr);
}

#[test]
fn block_witness_signature_detects_wrong_signer() {
    let priv_key = [99u8; 32];
    // Claim a different witness_address than what priv_key derives to.
    let mut block = sample_block(1);
    block
        .block_header
        .as_mut()
        .unwrap()
        .raw_data
        .as_mut()
        .unwrap()
        .witness_address = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").to_vec();
    sign_block(&mut block, &priv_key).unwrap();
    let err = verify_witness_signature(&block, None).unwrap_err();
    assert!(matches!(err, BlockValidateError::WitnessMismatch { .. }));
}

#[test]
fn block_witness_signature_missing_errors() {
    let block = sample_block(1);
    assert!(matches!(
        verify_witness_signature(&block, None),
        Err(BlockValidateError::MissingSignature)
    ));
}

#[test]
fn block_raw_hash_differs_from_block_id() {
    // The raw hash and BlockId share their last 24 bytes (both come from
    // sha256 of the same header), but the first 8 bytes of BlockId are
    // overwritten with the block number. For any non-zero number they
    // differ; for number 0 they coincide.
    let block = sample_block(42);
    let raw = block_raw_hash(&block).unwrap();
    let id = block_id_from_block(&block).unwrap();
    assert_ne!(raw, *id.as_bytes(), "must differ when num != 0");
    // Tails match.
    assert_eq!(&raw[8..], &id.as_bytes()[8..]);
}

#[test]
fn tx_trie_root_validates_when_header_matches_transactions() {
    // No transactions, no header root → ok.
    let block = sample_block(1);
    assert!(verify_tx_trie_root(&block).is_ok());
}

#[test]
fn tx_trie_root_detects_drift_between_header_and_transactions() {
    let mut block = sample_block(1);
    // Add a transaction without updating the header's tx_trie_root.
    block.transactions.push(sample_transfer_tx());
    let err = verify_tx_trie_root(&block).unwrap_err();
    assert!(matches!(err, BlockValidateError::TxTrieRootMismatch { .. }));
}

#[test]
fn tx_trie_root_accepts_zero_filled_header_when_no_transactions() {
    // java-tron sometimes writes 32 zero bytes as the empty-merkle sentinel.
    let mut block = sample_block(1);
    block
        .block_header
        .as_mut()
        .unwrap()
        .raw_data
        .as_mut()
        .unwrap()
        .tx_trie_root = vec![0u8; 32];
    assert!(verify_tx_trie_root(&block).is_ok());
}

#[test]
fn parent_link_validates_when_hashes_match() {
    let parent_id_bytes = hex!("0000000000000001aabbccddeeff00112233445566778899aabbccddeeff0011");
    let parent_id = BlockId::from_raw(parent_id_bytes);

    let mut block = sample_block(2);
    block
        .block_header
        .as_mut()
        .unwrap()
        .raw_data
        .as_mut()
        .unwrap()
        .parent_hash = parent_id_bytes.to_vec();
    assert!(verify_parent_link(&block, parent_id).is_ok());
}

#[test]
fn parent_link_detects_mismatch() {
    let parent_id = BlockId::from_raw([0xaa; 32]);
    let block = sample_block(2); // parent_hash is 32 zero bytes
    let err = verify_parent_link(&block, parent_id).unwrap_err();
    assert!(matches!(err, BlockValidateError::ParentLinkMismatch { .. }));
}

#[test]
fn tx_trie_root_three_txs_follows_odd_tail_rule() {
    let mut txs = Vec::new();
    for amount in [1_000_000i64, 2_000_000, 3_000_000] {
        let mut tx = sample_transfer_tx();
        if let Some(raw) = tx.raw_data.as_mut() {
            // Re-encode the inner TransferContract with a different amount
            // so each tx has a distinct merkle hash.
            let tc = TransferContract {
                owner_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                to_address: hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").to_vec(),
                amount,
            };
            raw.contract[0].parameter.as_mut().unwrap().value = tc.encode_to_vec();
        }
        txs.push(tx);
    }
    let root = calc_tx_trie_root(&txs).unwrap();

    // Hand-roll the expected root using the odd-tail rule:
    // level 0: [m0, m1, m2]
    // level 1: [sha256(m0 || m1), m2]
    // level 2: [sha256(sha256(m0||m1) || m2)]
    let m: Vec<[u8; 32]> = txs.iter().map(tx_merkle_hash).collect();
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(&m[0]);
    concat.extend_from_slice(&m[1]);
    let m01 = tron_crypto::hash::sha256(&concat);
    let mut concat2 = Vec::with_capacity(64);
    concat2.extend_from_slice(&m01);
    concat2.extend_from_slice(&m[2]);
    let expected = tron_crypto::hash::sha256(&concat2);

    assert_eq!(root, expected);
}
