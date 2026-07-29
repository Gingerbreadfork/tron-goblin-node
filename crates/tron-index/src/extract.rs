//! Block → index-entry extraction.
//!
//! One engine, one data source: rows are derived from **committed
//! stores only** — the block's transaction protos (native kinds) and
//! the block's stored transaction-info (TRC20 transfers, internal
//! transactions, full logs). The live apply path persists
//! transaction-info at commit and merely *wakes* the follower; it never
//! feeds rows directly, so there is exactly one extraction code path to
//! trust.
//!
//! "An address is *involved in* a transaction" iff it appears in one of
//! the participant roles of the per-contract-type table below
//! (INDEXER_PLAN.md §6.3). Deliberately **not** involving: addresses
//! inside raw calldata, the called contract of a `TriggerSmartContract`
//! (unless `capture_callee_contract`), multi-sig co-signers, and
//! parties named only in non-`Transfer` event topics. Vote targets ARE
//! involved (a `VoteWitnessContract` rows under each voted-for SR).

use std::collections::BTreeMap;

use prost::Message as _;
use tron_proto::transaction::contract::ContractType;
use tron_proto::{Block, Transaction, TransactionRet};

use crate::keys::{self, Addr};
use crate::rows::{InternalRow, LogRow, NativeRow, Trc20Row, Trc721Row, DIR_FROM, DIR_TO};

/// `keccak256("Transfer(address,address,uint256)")` — the TRC20
/// `Transfer` topic-0. Pinned as a literal (cross-checked by test
/// against the well-known constant also pinned in `tron-rpc`'s ABI
/// tests).
pub const TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
    0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
    0xb3, 0xef,
];

/// Which capture dimensions are on — the *effective* set after the
/// `scope` preset and `capture_*` overrides are resolved (the node's
/// config layer owns that precedence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureSet {
    pub native: bool,
    pub trc20: bool,
    /// TRC721 (NFT) transfers — the 4-topic `Transfer` shape, indexed
    /// `tokenId` in `topics[3]`.
    pub trc721: bool,
    pub internal: bool,
    pub logs: bool,
    /// Index the *called* contract of every `TriggerSmartContract`
    /// (powers `/v1/accounts/{contract}/transactions`). Default-off:
    /// it is the single largest row source.
    pub callee_contract: bool,
}

impl CaptureSet {
    /// Whether any captured kind is derived from transaction-info (the VM
    /// side): TRC20/TRC721 transfers, internal transactions, and event logs.
    /// The single source of truth so the engine's txinfo-wait decision and
    /// the extractor's txinfo requirement can never drift apart — omitting
    /// `trc721` here once dropped NFT rows at the tip.
    pub fn wants_vm(&self) -> bool {
        self.trc20 || self.trc721 || self.internal || self.logs
    }

    /// Stable fingerprint of the effective capture set. A mismatch at
    /// open time means rows on disk were written under a different
    /// contract → rebuild (see `db::IndexDb::check_or_init`).
    pub fn fingerprint(&self, start_height: i64) -> u64 {
        // Small fixed domain — a positional bit-pack beats a hash (no
        // collisions, stable across builds).
        let bits = (self.native as u64)
            | (self.trc20 as u64) << 1
            | (self.internal as u64) << 2
            | (self.logs as u64) << 3
            | (self.callee_contract as u64) << 4
            | (self.trc721 as u64) << 5;
        bits | ((start_height as u64) << 8)
    }
}

/// Everything one block contributes to the index, plus bookkeeping.
#[derive(Debug, Default)]
pub struct BlockEntries {
    /// `(key, encoded row)` puts. Keys are unique within a block.
    pub puts: Vec<(Vec<u8>, Vec<u8>)>,
    pub native_rows: u64,
    pub trc20_rows: u64,
    pub trc721_rows: u64,
    pub internal_rows: u64,
    pub log_rows: u64,
    /// True when TRC20/internal/log capture was requested but the
    /// block had no stored transaction-info — those kinds are
    /// silently absent for this block (counted, logged by the engine).
    pub txinfo_missing: bool,
}

/// Normalize a VM-side address (20-byte EVM form or already-prefixed
/// 21-byte TRON form) into the 21-byte `0x41`-prefixed form. Returns
/// `None` for anything else (defensive: malformed stored data must not
/// panic the follower).
fn addr21(bytes: &[u8]) -> Option<Addr> {
    let mut a = [0u8; 21];
    match bytes.len() {
        21 => a.copy_from_slice(bytes),
        20 => {
            a[0] = 0x41;
            a[1..].copy_from_slice(bytes);
        }
        _ => return None,
    }
    Some(a)
}

/// The per-tx row template for `idx_native` — shared by every involved
/// address; only the direction bits differ per key.
struct NativeTemplate {
    contract_type: i32,
    from: Vec<u8>,
    to: Option<Vec<u8>>,
    amount: i64,
    asset: Option<String>,
}

/// Per-tx native participants: address → direction bits. `BTreeMap`
/// for deterministic put order (byte-identical re-derivation is the
/// crash-recovery story).
type Participants = BTreeMap<Addr, u32>;

fn involve(p: &mut Participants, addr: Option<Addr>, dir: u32) {
    if let Some(a) = addr {
        *p.entry(a).or_insert(0) |= dir;
    }
}

macro_rules! unpack {
    ($T:ty, $bytes:expr) => {
        <$T as prost::Message>::decode($bytes).ok()
    };
}

/// Walk a contract message's top-level fields and return the first
/// length-delimited field that looks like a raw TRON address (21
/// bytes, `0x41` prefix). The catch-all owner rule for the long tail
/// of contract types (exchange, market, proposal, witness, asset
/// admin, …) where the owner is the first address field — avoids one
/// typed decoder per rarely-seen type while staying robust to types
/// where `owner_address` is field 2 (the first field is a name/id
/// blob that won't parse as a 21-byte `0x41` value).
fn first_address_field(mut buf: &[u8]) -> Option<Addr> {
    while !buf.is_empty() {
        let (tag, rest) = decode_varint(buf)?;
        buf = rest;
        let wire = (tag & 0x7) as u8;
        match wire {
            0 => {
                let (_, rest) = decode_varint(buf)?;
                buf = rest;
            }
            1 => {
                if buf.len() < 8 {
                    return None;
                }
                buf = &buf[8..];
            }
            2 => {
                let (len, rest) = decode_varint(buf)?;
                let len = len as usize;
                if rest.len() < len {
                    return None;
                }
                let field = &rest[..len];
                if len == 21 && field[0] == 0x41 {
                    let mut a = [0u8; 21];
                    a.copy_from_slice(field);
                    return Some(a);
                }
                buf = &rest[len..];
            }
            5 => {
                if buf.len() < 4 {
                    return None;
                }
                buf = &buf[4..];
            }
            _ => return None, // groups / reserved — bail out safely
        }
    }
    None
}

fn decode_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let mut out: u64 = 0;
    for (i, b) in buf.iter().enumerate().take(10) {
        out |= ((b & 0x7f) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Some((out, &buf[i + 1..]));
        }
    }
    None
}

/// Count a stored block's transactions without decoding the proto —
/// a top-level field walk counting `transactions` (field 1,
/// length-delimited) occurrences. Used by the engine's window
/// tx-budget pre-pass so heavy ranges don't pay a double full decode.
pub fn count_block_txs_raw(mut buf: &[u8]) -> usize {
    let mut count = 0usize;
    while !buf.is_empty() {
        let Some((tag, rest)) = decode_varint(buf) else { return count };
        buf = rest;
        let field = tag >> 3;
        match (tag & 0x7) as u8 {
            0 => {
                let Some((_, rest)) = decode_varint(buf) else { return count };
                buf = rest;
            }
            1 => {
                if buf.len() < 8 {
                    return count;
                }
                buf = &buf[8..];
            }
            2 => {
                let Some((len, rest)) = decode_varint(buf) else { return count };
                let len = len as usize;
                if rest.len() < len {
                    return count;
                }
                if field == 1 {
                    count += 1;
                }
                buf = &rest[len..];
            }
            5 => {
                if buf.len() < 4 {
                    return count;
                }
                buf = &buf[4..];
            }
            _ => return count,
        }
    }
    count
}

/// Created-contract address: `0x41 ‖ keccak256(owner ‖ tx_id)[12..]` —
/// java-tron's `Hash.sha3omit12(owner || tx_id)`, the same derivation
/// `tron-tvm`'s CREATE path uses. Public so every consumer of the rule
/// (the index extractor, the apply hook's TransactionInfo builder)
/// shares ONE copy of this consensus-critical formula.
pub fn created_contract_address(owner: &[u8], tx_id: &[u8; 32]) -> Addr {
    let mut input = Vec::with_capacity(owner.len() + 32);
    input.extend_from_slice(owner);
    input.extend_from_slice(tx_id);
    let h = tron_crypto::hash::keccak256(&input);
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].copy_from_slice(&h[12..]);
    a
}

/// Decode the §6.3 table for one transaction: the native row template
/// plus the involved-address set. Returns `None` for structurally
/// empty txs (no raw_data / no contract).
fn native_participants(
    tx: &Transaction,
    tx_id: &[u8; 32],
    callee_contract: bool,
) -> Option<(NativeTemplate, Participants)> {
    let raw = tx.raw_data.as_ref()?;
    let contract = raw.contract.first()?;
    let param = contract.parameter.as_ref().map(|p| p.value.as_slice()).unwrap_or(&[]);
    let ctype = contract.r#type;

    let mut parts = Participants::new();
    let mut template = NativeTemplate {
        contract_type: ctype,
        from: Vec::new(),
        to: None,
        amount: 0,
        asset: None,
    };

    use tron_proto as p;
    match ContractType::try_from(ctype).ok() {
        Some(ContractType::TransferContract) => {
            let c = unpack!(p::TransferContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            involve(&mut parts, addr21(&c.to_address), DIR_TO);
            template.from = c.owner_address;
            template.to = Some(c.to_address);
            template.amount = c.amount;
        }
        Some(ContractType::TransferAssetContract) => {
            let c = unpack!(p::TransferAssetContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            involve(&mut parts, addr21(&c.to_address), DIR_TO);
            template.from = c.owner_address;
            template.to = Some(c.to_address);
            template.amount = c.amount;
            template.asset = Some(String::from_utf8_lossy(&c.asset_name).into_owned());
        }
        Some(ContractType::ParticipateAssetIssueContract) => {
            let c = unpack!(p::ParticipateAssetIssueContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            involve(&mut parts, addr21(&c.to_address), DIR_TO);
            template.from = c.owner_address;
            template.to = Some(c.to_address);
            template.amount = c.amount;
            template.asset = Some(String::from_utf8_lossy(&c.asset_name).into_owned());
        }
        Some(ContractType::TriggerSmartContract) => {
            let c = unpack!(p::TriggerSmartContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            if callee_contract {
                involve(&mut parts, addr21(&c.contract_address), DIR_TO);
            }
            template.from = c.owner_address;
            template.to = Some(c.contract_address);
            template.amount = c.call_value;
        }
        Some(ContractType::CreateSmartContract) => {
            let c = unpack!(p::CreateSmartContract, param)?;
            let created = created_contract_address(&c.owner_address, tx_id);
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            involve(&mut parts, Some(created), DIR_TO);
            template.from = c.owner_address;
            template.to = Some(created.to_vec());
            template.amount = c.new_contract.as_ref().map(|n| n.call_value).unwrap_or(0);
        }
        Some(ContractType::FreezeBalanceContract) => {
            let c = unpack!(p::FreezeBalanceContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            if !c.receiver_address.is_empty() {
                involve(&mut parts, addr21(&c.receiver_address), DIR_TO);
                template.to = Some(c.receiver_address);
            }
            template.from = c.owner_address;
            template.amount = c.frozen_balance;
        }
        Some(ContractType::UnfreezeBalanceContract) => {
            let c = unpack!(p::UnfreezeBalanceContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            if !c.receiver_address.is_empty() {
                involve(&mut parts, addr21(&c.receiver_address), DIR_TO);
                template.to = Some(c.receiver_address);
            }
            template.from = c.owner_address;
        }
        Some(ContractType::FreezeBalanceV2Contract) => {
            let c = unpack!(p::FreezeBalanceV2Contract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            template.from = c.owner_address;
            template.amount = c.frozen_balance;
        }
        Some(ContractType::UnfreezeBalanceV2Contract) => {
            let c = unpack!(p::UnfreezeBalanceV2Contract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            template.from = c.owner_address;
            template.amount = c.unfreeze_balance;
        }
        Some(ContractType::DelegateResourceContract) => {
            let c = unpack!(p::DelegateResourceContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            involve(&mut parts, addr21(&c.receiver_address), DIR_TO);
            template.from = c.owner_address;
            template.to = Some(c.receiver_address);
            template.amount = c.balance;
        }
        Some(ContractType::UnDelegateResourceContract) => {
            let c = unpack!(p::UnDelegateResourceContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            involve(&mut parts, addr21(&c.receiver_address), DIR_TO);
            template.from = c.owner_address;
            template.to = Some(c.receiver_address);
            template.amount = c.balance;
        }
        Some(ContractType::AccountCreateContract) => {
            let c = unpack!(p::AccountCreateContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            involve(&mut parts, addr21(&c.account_address), DIR_TO);
            template.from = c.owner_address;
            template.to = Some(c.account_address);
        }
        Some(ContractType::ShieldedTransferContract) => {
            let c = unpack!(p::ShieldedTransferContract, param)?;
            // Shielded legs are unindexable by design; only the
            // transparent endpoints (when present) are participants.
            if !c.transparent_from_address.is_empty() {
                involve(&mut parts, addr21(&c.transparent_from_address), DIR_FROM);
                template.amount = c.from_amount;
            }
            if !c.transparent_to_address.is_empty() {
                involve(&mut parts, addr21(&c.transparent_to_address), DIR_TO);
                template.to = Some(c.transparent_to_address.clone());
                if c.transparent_from_address.is_empty() {
                    template.amount = c.to_amount;
                }
            }
            template.from = c.transparent_from_address;
        }
        Some(ContractType::VoteWitnessContract) => {
            let c = unpack!(p::VoteWitnessContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            // Each voted-for witness is involved: an SR's history page
            // shows incoming votes. `to` stays None (no single
            // counterparty); `amount` carries the total vote count.
            for v in &c.votes {
                involve(&mut parts, addr21(&v.vote_address), DIR_TO);
            }
            template.amount = c.votes.iter().map(|v| v.vote_count).sum();
            template.from = c.owner_address;
        }
        // Owner-only types with a dedicated decoder where the owner is
        // NOT field 1 (the generic walk would still find them — these
        // are kept typed for exactness on the common ones).
        Some(ContractType::AccountUpdateContract) => {
            let c = unpack!(p::AccountUpdateContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            template.from = c.owner_address;
        }
        Some(ContractType::SetAccountIdContract) => {
            let c = unpack!(p::SetAccountIdContract, param)?;
            involve(&mut parts, addr21(&c.owner_address), DIR_FROM);
            template.from = c.owner_address;
        }
        // Everything else — witness create/update, asset admin,
        // proposal, exchange, market, brokerage, permission update,
        // withdraw family, …: owner only, via the first-address field
        // walk.
        _ => {
            let owner = first_address_field(param)?;
            involve(&mut parts, Some(owner), DIR_FROM);
            template.from = owner.to_vec();
        }
    }

    Some((template, parts))
}

/// Decoded per-transaction facts, shared with external consumers (the
/// firehose entries carry exactly these). Same §6.3 dispatch table as
/// the embedded index — one decode rulebook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxFacts {
    pub contract_type: i32,
    /// `owner_address` (may be empty for fully-shielded transfers).
    pub from: Vec<u8>,
    /// Named counterparty when the type has one.
    pub to: Option<Vec<u8>>,
    pub amount: i64,
    pub asset: Option<String>,
}

/// Decode one transaction's §6.3 facts. `None` for structurally empty
/// txs (no raw_data / contract).
pub fn tx_facts(tx: &Transaction, tx_id: &[u8; 32]) -> Option<TxFacts> {
    let (t, _) = native_participants(tx, tx_id, false)?;
    Some(TxFacts {
        contract_type: t.contract_type,
        from: t.from,
        to: t.to,
        amount: t.amount,
        asset: t.asset,
    })
}

/// Matches each transaction to its stored `TransactionInfo` within a
/// block's `TransactionRet`: by 32-byte id first, positionally ONLY
/// for an info whose id is empty. One rulebook shared by the index
/// extractor and the firehose entry builder — these previously forked
/// (one accepted any non-empty id) and a malformed stored id would
/// have made the two surfaces disagree about the same block.
pub struct TxInfoMatcher<'a> {
    ret: Option<&'a TransactionRet>,
    by_id: BTreeMap<&'a [u8], &'a tron_proto::TransactionInfo>,
}

impl<'a> TxInfoMatcher<'a> {
    pub fn new(ret: Option<&'a TransactionRet>) -> Self {
        let mut by_id: BTreeMap<&'a [u8], &'a tron_proto::TransactionInfo> = BTreeMap::new();
        if let Some(ret) = ret {
            for info in &ret.transactioninfo {
                if info.id.len() == 32 {
                    by_id.insert(info.id.as_slice(), info);
                }
            }
        }
        Self { ret, by_id }
    }

    pub fn for_tx(
        &self,
        tx_id: &[u8; 32],
        txidx: usize,
    ) -> Option<&'a tron_proto::TransactionInfo> {
        if let Some(info) = self.by_id.get(tx_id.as_slice()) {
            return Some(info);
        }
        self.ret
            .and_then(|r| r.transactioninfo.get(txidx))
            .filter(|info| info.id.is_empty())
    }

    /// The stored id of the info at block position `txidx`, when present
    /// and well-formed (32 bytes). `TransactionRet` rows are written 1:1
    /// in block order (both by our apply hook and by java), and the
    /// stored id is the executor's WIRE-derived tx id — sha256 of the
    /// tx's original `raw_data` bytes — which is the authoritative id
    /// even when a prost re-encode of the decoded tx would hash
    /// differently (unknown raw_data fields). Callers prefer this over
    /// recomputing the id from a decoded tx.
    pub fn positional_id(&self, txidx: usize) -> Option<[u8; 32]> {
        let info = self.ret?.transactioninfo.get(txidx)?;
        if info.id.len() != 32 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&info.id);
        Some(id)
    }
}

/// Extract every index entry one block contributes.
///
/// `txinfo` is the block's stored `TransactionRet` (absent ⇒ the
/// VM-derived kinds are skipped and `txinfo_missing` is set — the
/// honest cost of a snapshot without a transaction-info store; there
/// is no way to regenerate historical receipts without the historical
/// state they executed against).
pub fn extract_block(
    block_num: i64,
    block: &Block,
    txinfo: Option<&TransactionRet>,
    caps: &CaptureSet,
) -> BlockEntries {
    let mut out = BlockEntries::default();
    let timestamp_ms = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .map(|r| r.timestamp)
        .unwrap_or(0);

    // transaction-info matched by tx id, falling back to block
    // position only for id-less infos (the shared rulebook).
    let matcher = TxInfoMatcher::new(txinfo);
    let wants_vm_kinds = caps.wants_vm();
    if wants_vm_kinds && txinfo.is_none() && !block.transactions.is_empty() {
        out.txinfo_missing = true;
    }

    for (txidx, tx) in block.transactions.iter().enumerate() {
        let txidx = txidx as u32;
        let Some(raw) = tx.raw_data.as_ref() else { continue };
        // Authoritative tx id: the stored info's WIRE-derived id when
        // available (see `TxInfoMatcher::positional_id`); the re-encode
        // hash — identical for canonical txs — only as fallback. Without
        // this, a tx whose raw_data carries unknown fields would be
        // indexed under an id nobody looks up.
        let tx_id = matcher
            .positional_id(txidx as usize)
            .unwrap_or_else(|| tron_crypto::hash::sha256(&raw.encode_to_vec()));
        let success = tx
            .ret
            .first()
            .map(|r| r.contract_ret == tron_proto::transaction::result::ContractResult::Success as i32)
            .unwrap_or(false);

        // ---- idx_native: from the tx params alone --------------------
        if caps.native {
            if let Some((template, parts)) = native_participants(tx, &tx_id, caps.callee_contract)
            {
                for (addr, direction) in parts {
                    let row = NativeRow {
                        txid: tx_id.to_vec(),
                        contract_type: template.contract_type,
                        from: template.from.clone(),
                        to: template.to.clone(),
                        amount: template.amount,
                        asset: template.asset.clone(),
                        timestamp_ms,
                        direction,
                        success,
                    };
                    out.puts
                        .push((keys::native_key(&addr, block_num, txidx), row.encode_to_vec()));
                    out.native_rows += 1;
                }
            }
        }

        // ---- VM-derived kinds: from stored transaction-info ----------
        if !wants_vm_kinds {
            continue;
        }
        let Some(info) = matcher.for_tx(&tx_id, txidx as usize) else { continue };

        if caps.trc20 || caps.trc721 || caps.logs {
            for (logidx, log) in info.log.iter().enumerate() {
                let logidx = logidx as u32;
                let Some(contract) = addr21(&log.address) else { continue };

                if caps.logs {
                    let mut topic0 = [0u8; 32];
                    if let Some(t0) = log.topics.first() {
                        if t0.len() == 32 {
                            topic0.copy_from_slice(t0);
                        }
                    }
                    let row = LogRow { txid: tx_id.to_vec(), timestamp_ms };
                    out.puts.push((
                        keys::logs_key(&contract, &topic0, block_num, txidx, logidx),
                        row.encode_to_vec(),
                    ));
                    out.log_rows += 1;
                }

                if !caps.trc20 && !caps.trc721 {
                    continue;
                }
                if log.topics.first().map(|t| t.as_slice()) != Some(TRANSFER_TOPIC.as_slice()) {
                    continue;
                }
                let party = |t: &[u8]| t.len().checked_sub(20).and_then(|off| addr21(&t[off..]));
                // The TRC20 Transfer rule, precisely: exactly 3 topics,
                // topic0 = keccak("Transfer(address,address,uint256)"),
                // and a 32-byte data word (the amount). The TRC721
                // Transfer shares topic0 but indexes all three params:
                // 4 topics, `tokenId` in topics[3], no data word.
                if caps.trc20 && log.topics.len() == 3 && log.data.len() == 32 {
                    let (Some(from), Some(to)) =
                        (party(&log.topics[1]), party(&log.topics[2]))
                    else {
                        continue;
                    };
                    let mut dirs: BTreeMap<Addr, u32> = BTreeMap::new();
                    *dirs.entry(from).or_insert(0) |= DIR_FROM;
                    *dirs.entry(to).or_insert(0) |= DIR_TO;
                    for (addr, direction) in dirs {
                        let row = Trc20Row {
                            txid: tx_id.to_vec(),
                            from: from.to_vec(),
                            to: to.to_vec(),
                            amount: log.data.clone(),
                            token: contract.to_vec(),
                            timestamp_ms,
                            direction,
                        };
                        out.puts.push((
                            keys::trc20_key(&addr, block_num, txidx, logidx),
                            row.encode_to_vec(),
                        ));
                        out.trc20_rows += 1;
                    }
                } else if caps.trc721 && log.topics.len() == 4 && log.topics[3].len() == 32 {
                    let (Some(from), Some(to)) =
                        (party(&log.topics[1]), party(&log.topics[2]))
                    else {
                        continue;
                    };
                    let mut dirs: BTreeMap<Addr, u32> = BTreeMap::new();
                    *dirs.entry(from).or_insert(0) |= DIR_FROM;
                    *dirs.entry(to).or_insert(0) |= DIR_TO;
                    for (addr, direction) in dirs {
                        let row = Trc721Row {
                            txid: tx_id.to_vec(),
                            from: from.to_vec(),
                            to: to.to_vec(),
                            token_id: log.topics[3].clone(),
                            token: contract.to_vec(),
                            timestamp_ms,
                            direction,
                        };
                        out.puts.push((
                            keys::trc721_key(&addr, block_num, txidx, logidx),
                            row.encode_to_vec(),
                        ));
                        out.trc721_rows += 1;
                    }
                }
            }
        }

        if caps.internal {
            for (itxidx, itx) in info.internal_transactions.iter().enumerate() {
                let itxidx = itxidx as u32;
                // Index each endpoint independently: a malformed or empty
                // counterparty address must not erase the internal
                // transfer from the other party's history (mirrors the
                // native extractor's per-participant `involve`).
                let caller = addr21(&itx.caller_address);
                let target = addr21(&itx.transfer_to_address);
                let mut dirs: BTreeMap<Addr, u32> = BTreeMap::new();
                involve(&mut dirs, caller, DIR_FROM);
                involve(&mut dirs, target, DIR_TO);
                if dirs.is_empty() {
                    continue; // neither endpoint decodable — nothing to index
                }
                // The stored row keeps both endpoints: the decodable side
                // in its normalized 21-byte form, an undecodable side in
                // its original bytes so the counterparty stays visible.
                let caller_bytes =
                    caller.map(|a| a.to_vec()).unwrap_or_else(|| itx.caller_address.clone());
                let transfer_to_bytes = target
                    .map(|a| a.to_vec())
                    .unwrap_or_else(|| itx.transfer_to_address.clone());
                let call_value = itx
                    .call_value_info
                    .iter()
                    .find(|cv| cv.token_id.is_empty())
                    .map(|cv| cv.call_value)
                    .unwrap_or(0);
                // The token leg, when present. java-tron's
                // `TransactionUtil.buildInternalTransaction` always emits
                // the native leg as `call_value_info[0]` (empty tokenId)
                // and then appends one entry per token in the frame's
                // `tokenInfo` map. For the ROOT frame of any
                // smart-contract call, that map is populated
                // unconditionally with `String.valueOf(getTokenId())` —
                // so a plain (non-token) call carries a spurious
                // `{tokenId: "0", call_value: 0}` second entry
                // (`InternalTransaction.java`). Token id `"0"` is the
                // no-token sentinel (real TRC10 ids are positive and
                // emitted with leading zeros stripped), so it never
                // denotes an actual token transfer and must not surface
                // as one on the row.
                let token_id = itx
                    .call_value_info
                    .iter()
                    .find(|cv| !cv.token_id.is_empty() && cv.token_id != "0")
                    .map(|cv| cv.token_id.clone());
                for (addr, direction) in dirs {
                    let row = InternalRow {
                        txid: tx_id.to_vec(),
                        caller: caller_bytes.clone(),
                        transfer_to: transfer_to_bytes.clone(),
                        call_value,
                        token_id: token_id.clone(),
                        rejected: itx.rejected,
                        timestamp_ms,
                        direction,
                    };
                    out.puts.push((
                        keys::internal_key(&addr, block_num, txidx, itxidx),
                        row.encode_to_vec(),
                    ));
                    out.internal_rows += 1;
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_internal() -> CaptureSet {
        CaptureSet {
            native: false,
            trc20: false,
            trc721: false,
            internal: true,
            logs: false,
            callee_contract: false,
        }
    }

    fn trigger_tx(owner: [u8; 21], callee: [u8; 21]) -> Transaction {
        let c = tron_proto::TriggerSmartContract {
            owner_address: owner.to_vec(),
            contract_address: callee.to_vec(),
            ..Default::default()
        };
        Transaction {
            raw_data: Some(tron_proto::transaction::Raw {
                contract: vec![tron_proto::transaction::Contract {
                    r#type: ContractType::TriggerSmartContract as i32,
                    parameter: Some(prost_types::Any {
                        type_url: String::new(),
                        value: c.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// An internal transaction whose `transfer_to_address` is
    /// undecodable still indexes the decodable caller — a bad endpoint
    /// must not drop the transfer from the other party's history.
    #[test]
    fn internal_one_bad_endpoint_still_indexes_the_good_side() {
        let caller = [0x41u8; 21];
        let block = Block {
            transactions: vec![trigger_tx(caller, [0x42u8; 21])],
            ..Default::default()
        };
        // A 5-byte target is neither 20- nor 21-byte, so `addr21`
        // rejects it while the caller stays decodable.
        let itx = tron_proto::InternalTransaction {
            caller_address: caller.to_vec(),
            transfer_to_address: vec![1, 2, 3, 4, 5],
            ..Default::default()
        };
        let ret = TransactionRet {
            transactioninfo: vec![tron_proto::TransactionInfo {
                internal_transactions: vec![itx],
                ..Default::default()
            }],
            ..Default::default()
        };
        let entries = extract_block(100, &block, Some(&ret), &caps_internal());
        let internal: Vec<_> =
            entries.puts.iter().filter(|(k, _)| k[0] == keys::NS_INTERNAL).collect();
        assert_eq!(internal.len(), 1, "the decodable caller is still indexed");
        assert_eq!(entries.internal_rows, 1);
        let row = InternalRow::decode(internal[0].1.as_slice()).unwrap();
        assert_eq!(row.direction, DIR_FROM, "caller keyed as the sender");
        assert_eq!(row.caller, caller.to_vec());
        assert_eq!(row.transfer_to, vec![1, 2, 3, 4, 5], "bad endpoint kept verbatim");
    }
}
