//! Index row values — prost-encoded internal messages.
//!
//! Proto-everywhere is the house style: varint-friendly for the integer
//! fields and forward-compatible for *additive optional* fields without
//! a format bump. Rows are NOT individually versioned —
//! `idx_meta/format_version` governs the whole DB (see
//! [`crate::db::FORMAT_VERSION`]).
//!
//! Denormalization rule: a row carries what the **list view and
//! filters** need, nothing more. `height`/`txidx` are NOT in the value
//! (recoverable from the key); `confirmed` is NOT in the value (derived
//! at read time against the solidified mark — it flips ~19 blocks after
//! the row is written and a stored flag would need rewriting).

/// Direction bit: the keyed address is the sender / owner / caller.
pub const DIR_FROM: u32 = 0b01;
/// Direction bit: the keyed address is the receiver / target. A
/// self-transfer gets **one** row with both bits set, never two keys.
pub const DIR_TO: u32 = 0b10;

/// `idx_native` row — one per (involved address, transaction).
#[derive(Clone, PartialEq, prost::Message)]
pub struct NativeRow {
    /// 32-byte transaction id.
    #[prost(bytes = "vec", tag = "1")]
    pub txid: Vec<u8>,
    /// `Tron.proto` `ContractType` enum value of the tx's contract.
    #[prost(int32, tag = "2")]
    pub contract_type: i32,
    /// `owner_address` (21 bytes). May be empty for fully-shielded
    /// transfers with no transparent input.
    #[prost(bytes = "vec", tag = "3")]
    pub from: Vec<u8>,
    /// Named counterparty for the contract type (to / receiver /
    /// created account / called contract), when the type has one.
    #[prost(bytes = "vec", optional, tag = "4")]
    pub to: Option<Vec<u8>>,
    /// Sun, or TRC10 amount, per type table. 0 for non-transfers.
    #[prost(int64, tag = "5")]
    pub amount: i64,
    /// TRC10 asset name/id; `None` for TRX / non-asset transfers.
    #[prost(string, optional, tag = "6")]
    pub asset: Option<String>,
    /// `block_header.raw_data.timestamp` (ms).
    #[prost(int64, tag = "7")]
    pub timestamp_ms: i64,
    /// [`DIR_FROM`] / [`DIR_TO`] bits for the keyed address.
    #[prost(uint32, tag = "8")]
    pub direction: u32,
    /// `Transaction.Result.contractRet == SUCCESS`.
    #[prost(bool, tag = "9")]
    pub success: bool,
}

/// `idx_trc20` row — one per (involved address, qualifying `Transfer`
/// log).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Trc20Row {
    #[prost(bytes = "vec", tag = "1")]
    pub txid: Vec<u8>,
    /// 21-byte sender (`0x41` + last 20 bytes of `topics[1]`).
    #[prost(bytes = "vec", tag = "2")]
    pub from: Vec<u8>,
    /// 21-byte receiver (`0x41` + last 20 bytes of `topics[2]`).
    #[prost(bytes = "vec", tag = "3")]
    pub to: Vec<u8>,
    /// Raw 32-byte big-endian token amount (no decimals applied).
    #[prost(bytes = "vec", tag = "4")]
    pub amount: Vec<u8>,
    /// 21-byte token contract address.
    #[prost(bytes = "vec", tag = "5")]
    pub token: Vec<u8>,
    #[prost(int64, tag = "6")]
    pub timestamp_ms: i64,
    #[prost(uint32, tag = "7")]
    pub direction: u32,
}

/// `idx_trc721` row — one per (involved address, qualifying 4-topic
/// `Transfer` log): the NFT sibling of [`Trc20Row`], with the indexed
/// `tokenId` in place of the data-word amount.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Trc721Row {
    #[prost(bytes = "vec", tag = "1")]
    pub txid: Vec<u8>,
    /// 21-byte sender (`0x41` + last 20 bytes of `topics[1]`).
    #[prost(bytes = "vec", tag = "2")]
    pub from: Vec<u8>,
    /// 21-byte receiver (`0x41` + last 20 bytes of `topics[2]`).
    #[prost(bytes = "vec", tag = "3")]
    pub to: Vec<u8>,
    /// Raw 32-byte big-endian `tokenId` (`topics[3]`).
    #[prost(bytes = "vec", tag = "4")]
    pub token_id: Vec<u8>,
    /// 21-byte NFT contract address.
    #[prost(bytes = "vec", tag = "5")]
    pub token: Vec<u8>,
    #[prost(int64, tag = "6")]
    pub timestamp_ms: i64,
    #[prost(uint32, tag = "7")]
    pub direction: u32,
}

/// `idx_internal` row — one per (involved address, internal
/// transaction).
#[derive(Clone, PartialEq, prost::Message)]
pub struct InternalRow {
    /// Parent transaction id.
    #[prost(bytes = "vec", tag = "1")]
    pub txid: Vec<u8>,
    /// 21-byte frame caller.
    #[prost(bytes = "vec", tag = "2")]
    pub caller: Vec<u8>,
    /// 21-byte frame target (callee / created contract).
    #[prost(bytes = "vec", tag = "3")]
    pub transfer_to: Vec<u8>,
    /// Sun moved by the frame (first `CallValueInfo` with empty
    /// tokenId).
    #[prost(int64, tag = "4")]
    pub call_value: i64,
    /// TRC10 id for in-VM token transfers, when present.
    #[prost(string, optional, tag = "5")]
    pub token_id: Option<String>,
    /// Frame (or ancestor) reverted — kept so consumers can filter,
    /// TronGrid-style, rather than silently dropped.
    #[prost(bool, tag = "6")]
    pub rejected: bool,
    #[prost(int64, tag = "7")]
    pub timestamp_ms: i64,
    #[prost(uint32, tag = "8")]
    pub direction: u32,
}

/// `idx_logs` row (`scope = "all"`): a pointer row — topics/data
/// hydrate from transaction-info via the key's `(height, txidx,
/// logidx)`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LogRow {
    #[prost(bytes = "vec", tag = "1")]
    pub txid: Vec<u8>,
    #[prost(int64, tag = "2")]
    pub timestamp_ms: i64,
}

/// Cached TRC20 token metadata (`idx_meta/token/{addr}`), resolved
/// lazily via the node's own constant-call machinery.
#[derive(Clone, PartialEq, prost::Message)]
pub struct TokenMeta {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub symbol: String,
    #[prost(int32, tag = "3")]
    pub decimals: i32,
    /// False when resolution failed — retried on a later cache miss
    /// rather than poisoning the cache forever.
    #[prost(bool, tag = "4")]
    pub resolved: bool,
}
