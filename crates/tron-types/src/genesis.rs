//! Mainnet (and configurable) genesis block construction.
//!
//! Source: `org.tron.core.capsule.utils.BlockUtil.newGenesisBlockCapsule` +
//! `org.tron.core.capsule.utils.TransactionUtil.newGenesisTransaction`.
//!
//! The mainnet genesis recipe contains two non-obvious traps that any
//! reimplementation has to preserve byte-for-byte:
//!
//! 1. **The genesis-transaction owner address is the UTF-8 bytes of the
//!    literal string `"0x000000000000000000000"`** — that's `0x`
//!    followed by 19 ASCII `'0'` characters, encoded as 21 bytes
//!    `[0x30, 0x78, 0x30, 0x30, …, 0x30]`. Not actual zero bytes.
//!    See [`GENESIS_OWNER_ADDRESS`].
//!
//! 2. **The witness address of the genesis block is a UTF-8-encoded
//!    sentence from Tim Berners-Lee** — 115 ASCII bytes. Java's
//!    `setWitness(String)` does `getBytes()` and stores them in
//!    `BlockHeader.raw.witness_address`. See [`MAINNET_WITNESS_QUOTE`].
//!
//! Both quirks are part of consensus: change either byte and the resulting
//! genesis `BlockId` no longer matches the published mainnet value.

use prost::Message;
use prost_types::Any;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract, Raw as TxRaw};
use tron_proto::{Block, BlockHeader, Transaction, TransferContract};

use crate::block_id::BlockId;
use crate::tx_id::calc_tx_trie_root;

/// Mainnet genesis parent hash. From the public main-net config:
/// `0xe58f33f9baf9305dc6f82b9f1934ea8f0ade2defb951258d50167028c780351f`.
pub const MAINNET_PARENT_HASH: [u8; 32] = [
    0xe5, 0x8f, 0x33, 0xf9, 0xba, 0xf9, 0x30, 0x5d, 0xc6, 0xf8, 0x2b, 0x9f, 0x19, 0x34, 0xea, 0x8f,
    0x0a, 0xde, 0x2d, 0xef, 0xb9, 0x51, 0x25, 0x8d, 0x50, 0x16, 0x70, 0x28, 0xc7, 0x80, 0x35, 0x1f,
];

/// **TRAP**: java-tron uses the *literal ASCII bytes* of the string
/// `"0x000000000000000000000"` as the owner_address for every genesis
/// transaction. That is **23 bytes** (`0x` followed by 21 `0`
/// characters) — *not* a valid 21-byte TRON address and *not* zero
/// bytes. The TransferContract proto field is variable-length `bytes`
/// so the over-sized "address" passes through the wire intact.
///
/// Any reimplementation that normalises a "null sender" to actual
/// 21 zero bytes (or 21 ASCII zeroes) will produce a different
/// genesis `txTrieRoot` and silently fork the chain.
///
/// Source: `TransactionUtil.newGenesisTransaction`:
/// `ByteString.copyFrom("0x000000000000000000000".getBytes())`
pub const GENESIS_OWNER_ADDRESS: &[u8] = b"0x000000000000000000000";

/// **The Tim Berners-Lee quote** used as the genesis block's
/// `witness_address` field. Java string:
///
/// > A new system must allow existing systems to be linked together
/// > without requiring any central control or coordination
///
/// Stored as raw UTF-8 (115 ASCII bytes). Source:
/// `BlockUtil.newGenesisBlockCapsule` → `blockCapsule.setWitness(quote)`.
pub const MAINNET_WITNESS_QUOTE: &[u8] =
    b"A new system must allow existing systems to be linked together without \
      requiring any central control or coordination";

/// A genesis-account ("asset") entry: `(raw_address_21_bytes, balance, name)`.
///
/// `name` mirrors `genesis.block.assets[].accountName` from java-tron's
/// `config.conf`. When non-empty it gets written to:
///   - the `Account.account_name` field at `AccountStore[address]`, and
///   - a name → address mapping at `AccountIndexStore[name]`,
/// matching java-tron's `initAccount` flow.
/// Empty name skips both writes.
#[derive(Debug, Clone, Copy)]
pub struct GenesisAsset {
    pub address: [u8; 21],
    pub balance: i64,
    pub name: &'static str,
}

/// Inputs needed to construct a genesis block. Mainnet, Nile, Shasta, and
/// custom networks all use the same recipe with different inputs.
#[derive(Debug, Clone)]
pub struct GenesisInputs<'a> {
    pub timestamp: i64,
    pub parent_hash: [u8; 32],
    pub assets: &'a [GenesisAsset],
    /// Bytes used for the `witness_address` field.
    pub witness_address: &'a [u8],
}

/// Build a genesis block from the given inputs, following the exact recipe
/// java-tron uses. This is pure: same inputs → byte-identical block.
pub fn build_genesis_block(inputs: &GenesisInputs<'_>) -> Block {
    let transactions: Vec<Transaction> = inputs
        .assets
        .iter()
        .map(|asset| genesis_transaction(asset.address, asset.balance))
        .collect();

    let tx_trie_root = calc_tx_trie_root(&transactions)
        .map(|h| h.to_vec())
        .unwrap_or_default();

    let raw = BlockHeaderRaw {
        timestamp: inputs.timestamp,
        tx_trie_root,
        parent_hash: inputs.parent_hash.to_vec(),
        number: 0,
        witness_id: 0,
        witness_address: inputs.witness_address.to_vec(),
        version: 0, // not set in BlockUtil → proto3 default
        account_state_root: Vec::new(),
    };

    Block {
        transactions,
        block_header: Some(BlockHeader {
            raw_data: Some(raw),
            witness_signature: Vec::new(),
        }),
    }
}

/// Convenience: compute the genesis `BlockId` directly.
pub fn genesis_block_id(inputs: &GenesisInputs<'_>) -> BlockId {
    let block = build_genesis_block(inputs);
    crate::block_id::block_id_from_block(&block).expect("genesis always has a header")
}

/// Build a single genesis `Transaction`: a `TransferContract` from
/// [`GENESIS_OWNER_ADDRESS`] (the 23-byte ASCII literal) to
/// `to_address` (a real 21-byte TRON address) with the given amount.
fn genesis_transaction(to_address: [u8; 21], amount: i64) -> Transaction {
    let tc = TransferContract {
        owner_address: GENESIS_OWNER_ADDRESS.to_vec(),
        to_address: to_address.to_vec(),
        amount,
    };
    let contract = Contract {
        r#type: ContractType::TransferContract as i32,
        // Java's `Any.pack` produces `type.googleapis.com/<full_name>`.
        // Full name for `TransferContract` is `protocol.TransferContract`
        // (the proto package is `protocol`).
        parameter: Some(Any {
            type_url: "type.googleapis.com/protocol.TransferContract".into(),
            value: tc.encode_to_vec(),
        }),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id: 0,
    };
    let raw = TxRaw {
        ref_block_bytes: Vec::new(),
        ref_block_num: 0,
        ref_block_hash: Vec::new(),
        expiration: 0,
        auths: Vec::new(),
        data: Vec::new(),
        contract: vec![contract],
        scripts: Vec::new(),
        timestamp: 0,
        fee_limit: 0,
    };
    Transaction {
        raw_data: Some(raw),
        signature: Vec::new(),
        ret: Vec::new(),
        unparsed_field10: None,
    }
}

/// The three mainnet genesis assets, with addresses decoded from the
/// public Base58Check strings in `config.conf`:
///
/// | Name      | Base58 address                          | Balance               |
/// |-----------|------------------------------------------|-----------------------|
/// | Zion      | `TLLM21wteSPs4hKjbxgmH1L6poyMjeTbHm`     |  99_000_000_000_000_000 |
/// | Sun       | `TXmVpin5vq5gdZsciyyjdZgKRUju4st1wM`     |  0                    |
/// | Blackhole | `TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy`     | -9_223_372_036_854_775_808 (i64::MIN) |
///
/// The decoded 21-byte addresses are hard-coded here so the constants are
/// `const`-evaluable. They can be re-derived at runtime via
/// `tron_crypto::base58check::decode_address` — see the tests.
pub const MAINNET_ASSETS: [GenesisAsset; 3] = [
    GenesisAsset {
        // TLLM21wteSPs4hKjbxgmH1L6poyMjeTbHm
        address: [
            0x41, 0x71, 0xb0, 0xaf, 0x54, 0xe0, 0xa1, 0x18, 0x2a, 0x5e, 0x09, 0x47, 0xd6, 0xa6, 0x4f,
            0x3b, 0x22, 0x74, 0x0e, 0xf3, 0x18,
        ],
        balance: 99_000_000_000_000_000,
        name: "Zion",
    },
    GenesisAsset {
        // TXmVpin5vq5gdZsciyyjdZgKRUju4st1wM
        address: [
            0x41, 0xef, 0x1b, 0xd1, 0x5b, 0x5b, 0x65, 0x7f, 0x69, 0x61, 0x1b, 0x05, 0x3a, 0x6f, 0x4f,
            0xcd, 0x72, 0x68, 0xa5, 0x08, 0x58,
        ],
        balance: 0,
        name: "Sun",
    },
    GenesisAsset {
        // TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy
        address: [
            0x41, 0x77, 0x94, 0x4d, 0x19, 0xc0, 0x52, 0xb7, 0x3e, 0xe2, 0x28, 0x68, 0x23, 0xaa, 0x83,
            0xf8, 0x13, 0x8c, 0xb7, 0x03, 0x2f,
        ],
        balance: i64::MIN,
        name: "Blackhole",
    },
];

/// Convenience: inputs for the canonical TRON mainnet genesis block.
pub fn mainnet_inputs() -> GenesisInputs<'static> {
    GenesisInputs {
        timestamp: 0,
        parent_hash: MAINNET_PARENT_HASH,
        assets: &MAINNET_ASSETS,
        witness_address: MAINNET_WITNESS_QUOTE,
    }
}

/// A single genesis Super Representative entry. java-tron sources
/// these from `config.conf`'s `genesis.block.witnesses` block; we
/// hard-code the mainnet defaults from
/// `framework/src/main/resources/config.conf`.
///
/// At genesis init, each entry:
/// 1. Upserts an `Account` row at `address` with `is_witness = true`
///    (creating an `AssetIssue`-type account if none existed).
/// 2. Writes a `Witness` row to `WitnessStore` with the given
///    `vote_count`, `url`, and `is_jobs = true`.
#[derive(Debug, Clone)]
pub struct GenesisWitness {
    pub address: [u8; 21],
    pub vote_count: i64,
    pub url: &'static str,
}

/// Pairs of (base58 address, vote count, URL) — the values from
/// java-tron's `config.conf`. Kept as the source of truth; the
/// 21-byte decoded form is produced on-demand by [`mainnet_witnesses`].
const MAINNET_WITNESS_CONFIG: &[(&str, i64, &str)] = &[
    ("THKJYuUmMKKARNf7s2VT51g5uPY6KEqnat", 100_000_026, "http://GR1.com"),
    ("TVDmPWGYxgi5DNeW8hXrzrhY8Y6zgxPNg4", 100_000_025, "http://GR2.com"),
    ("TWKZN1JJPFydd5rMgMCV5aZTSiwmoksSZv", 100_000_024, "http://GR3.com"),
    ("TDarXEG2rAD57oa7JTK785Yb2Et32UzY32", 100_000_023, "http://GR4.com"),
    ("TAmFfS4Tmm8yKeoqZN8x51ASwdQBdnVizt", 100_000_022, "http://GR5.com"),
    ("TK6V5Pw2UWQWpySnZyCDZaAvu1y48oRgXN", 100_000_021, "http://GR6.com"),
    ("TGqFJPFiEqdZx52ZR4QcKHz4Zr3QXA24VL", 100_000_020, "http://GR7.com"),
    ("TC1ZCj9Ne3j5v3TLx5ZCDLD55MU9g3XqQW", 100_000_019, "http://GR8.com"),
    ("TWm3id3mrQ42guf7c4oVpYExyTYnEGy3JL", 100_000_018, "http://GR9.com"),
    ("TCvwc3FV3ssq2rD82rMmjhT4PVXYTsFcKV", 100_000_017, "http://GR10.com"),
    ("TFuC2Qge4GxA2U9abKxk1pw3YZvGM5XRir", 100_000_016, "http://GR11.com"),
    ("TNGoca1VHC6Y5Jd2B1VFpFEhizVk92Rz85", 100_000_015, "http://GR12.com"),
    ("TLCjmH6SqGK8twZ9XrBDWpBbfyvEXihhNS", 100_000_014, "http://GR13.com"),
    ("TEEzguTtCihbRPfjf1CvW8Euxz1kKuvtR9", 100_000_013, "http://GR14.com"),
    ("TZHvwiw9cehbMxrtTbmAexm9oPo4eFFvLS", 100_000_012, "http://GR15.com"),
    ("TGK6iAKgBmHeQyp5hn3imB71EDnFPkXiPR", 100_000_011, "http://GR16.com"),
    ("TLaqfGrxZ3dykAFps7M2B4gETTX1yixPgN", 100_000_010, "http://GR17.com"),
    ("TX3ZceVew6yLC5hWTXnjrUFtiFfUDGKGty", 100_000_009, "http://GR18.com"),
    ("TYednHaV9zXpnPchSywVpnseQxY9Pxw4do", 100_000_008, "http://GR19.com"),
    ("TCf5cqLffPccEY7hcsabiFnMfdipfyryvr", 100_000_007, "http://GR20.com"),
    ("TAa14iLEKPAetX49mzaxZmH6saRxcX7dT5", 100_000_006, "http://GR21.com"),
    ("TBYsHxDmFaRmfCF3jZNmgeJE8sDnTNKHbz", 100_000_005, "http://GR22.com"),
    ("TEVAq8dmSQyTYK7uP1ZnZpa6MBVR83GsV6", 100_000_004, "http://GR23.com"),
    ("TRKJzrZxN34YyB8aBqqPDt7g4fv6sieemz", 100_000_003, "http://GR24.com"),
    ("TRMP6SKeFUt5NtMLzJv8kdpYuHRnEGjGfe", 100_000_002, "http://GR25.com"),
    ("TDbNE1VajxjpgM5p7FyGNDASt3UVoFbiD3", 100_000_001, "http://GR26.com"),
    ("TLTDZBcPoJ8tZ6TTEeEqEvwYFk2wgotSfD", 100_000_000, "http://GR27.com"),
];

/// Lazily-decoded list of the 27 initial mainnet Super Representatives.
/// Each call returns a fresh `Vec`; cached via a `OnceLock` keyed on
/// the static config table.
pub fn mainnet_witnesses() -> &'static [GenesisWitness] {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<GenesisWitness>> = OnceLock::new();
    CACHE.get_or_init(|| {
        MAINNET_WITNESS_CONFIG
            .iter()
            .map(|(b58, vc, url)| {
                let decoded = tron_crypto::base58check::decode_address(b58)
                    .expect("mainnet witness base58 string must decode");
                GenesisWitness {
                    address: *decoded.as_bytes(),
                    vote_count: *vc,
                    url,
                }
            })
            .collect()
    })
}
