//! `HelloMessage` assembly — the first frame exchanged on any TRON P2P
//! connection. Constructing this correctly proves the full stack
//! (crypto + proto + types + net) is wired up: a Java peer that receives
//! it must accept us as a compatible node on the right network.
//!
//! Source: `org.tron.core.net.message.handshake.HelloMessage`. The Java
//! builder loads genesis/solid/head BlockIds from `ChainBaseManager` and
//! folds them into per-field `(hash, number)` pairs. We mirror that here
//! with a pure-data input struct.

use tron_proto::hello_message::BlockId as WireBlockId;
use tron_proto::{Endpoint, HelloMessage};
use tron_types::BlockId;

/// Mainnet `node.p2p.version`. A peer that doesn't match this version is
/// rejected with [`tron_proto::ReasonCode::IncompatibleVersion`].
pub const MAINNET_P2P_VERSION: i32 = 11_111;
/// Nile testnet `node.p2p.version`.
pub const NILE_P2P_VERSION: i32 = 201_910_292;
/// Shasta testnet `node.p2p.version`.
pub const SHASTA_P2P_VERSION: i32 = 1;

/// Known mainnet seed peers from java-tron's `config.conf` (mainnet
/// `seed.node.ip.list`). Useful as a fallback peer set when the user
/// runs `tron-node start` without `--peer` flags. Public mainnet
/// seeds frequently hit `TOO_MANY_PEERS` — randomizing the dial order
/// across this pool gives a better acceptance rate.
pub const MAINNET_SEEDS: &[&str] = &[
    "3.225.171.164:18888",
    "52.8.46.215:18888",
    "3.79.71.167:18888",
    "108.128.110.16:18888",
    "18.133.82.227:18888",
    "35.180.81.133:18888",
    "13.210.151.5:18888",
    "18.231.27.82:18888",
    "3.12.212.122:18888",
    "52.24.128.7:18888",
    "15.207.144.3:18888",
    "3.39.38.55:18888",
    "54.151.226.240:18888",
];

/// Inputs for assembling a HelloMessage. Each `*_block_id` argument is the
/// 32-byte [`tron_types::BlockId`] (first 8 bytes = number). The wire
/// format carries `(hash, number)` as separate fields — see
/// [`to_wire_block_id`].
pub struct HelloInputs<'a> {
    /// Sender endpoint: ip address, port, 64-byte node id (uncompressed
    /// pubkey without the 0x04 marker).
    pub from: Endpoint,
    /// Network protocol version. `11111` on mainnet.
    pub version: i32,
    pub timestamp_ms: i64,
    pub genesis: BlockId,
    pub solid: BlockId,
    pub head: BlockId,
    /// Node type — `0` = full, `1` = light, `2` = archive in java-tron.
    pub node_type: i32,
    /// `lowestBlockNum` — `0` for non-lite nodes.
    pub lowest_block_num: i64,
    /// Software version string (e.g. `"4.8.2"`); written as raw UTF-8
    /// bytes into the wire field.
    pub code_version: &'a [u8],
}

/// Convert a [`BlockId`] into the per-field-pair format that
/// `HelloMessage` carries on the wire.
///
/// **Redundancy alert**: the `hash` bytes already contain the number in
/// their first 8 bytes (see [`BlockId`] docs). The `number` field is set
/// to the same value as a separate `int64` — this is what java-tron
/// writes, so we match it byte-for-byte.
pub fn to_wire_block_id(id: BlockId) -> WireBlockId {
    WireBlockId {
        hash: id.as_bytes().to_vec(),
        number: id.num() as i64,
    }
}

/// Build a `HelloMessage` proto from typed inputs.
///
/// Does **not** sign — `address` and `signature` fields are left empty.
/// Witness nodes sign by setting these via a separate authenticated
/// handshake path; full nodes connect unauthenticated.
pub fn build_hello(inputs: HelloInputs<'_>) -> HelloMessage {
    HelloMessage {
        from: Some(inputs.from),
        version: inputs.version,
        timestamp: inputs.timestamp_ms,
        genesis_block_id: Some(to_wire_block_id(inputs.genesis)),
        solid_block_id: Some(to_wire_block_id(inputs.solid)),
        head_block_id: Some(to_wire_block_id(inputs.head)),
        address: Vec::new(),
        signature: Vec::new(),
        node_type: inputs.node_type,
        lowest_block_num: inputs.lowest_block_num,
        code_version: inputs.code_version.to_vec(),
    }
}
