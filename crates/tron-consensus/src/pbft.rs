//! PBFT vote-casting + aggregation primitives.
//!
//! Port of java-tron's `org.tron.consensus.pbft.PbftMessageHandle` +
//! `PbftMessageAction`. Provides the building blocks for an SR's
//! prepare/commit voting loop:
//!
//! 1. **[`PbftVoteTally`]** — per-block prepare/commit vote
//!    accumulator. Receives observed votes, tracks whether
//!    thresholds have been crossed, and produces the data needed
//!    to persist a [`tron_chainbase::PbftSignDataStore`] entry once
//!    finality is reached.
//!
//! 2. **[`cast_prepare`] / [`cast_commit`]** — produce a signed
//!    `PbftMessage` for our own vote.
//!
//! 3. **[`recover_signer`]** — given an incoming signed message,
//!    recover the witness address that signed it (for membership
//!    check against the active SR set).
//!
//! ## Algorithm summary
//!
//! ```text
//! Per block at height N:
//!   1. Some SR (the slot's producer) broadcasts a PrePrepare
//!      carrying the block payload.
//!   2. Every SR observing the PrePrepare broadcasts a Prepare
//!      signed by their witness key.
//!   3. When 2/3 + 1 Prepare votes are observed for the same
//!      (block_hash, view_n, epoch), each SR broadcasts a Commit.
//!   4. When 2/3 + 1 Commit votes are observed, the block is
//!      PBFT-solidified — its signature list is written to
//!      PbftSignDataStore[BLOCK<N>] and LATEST_SOLIDIFIED_BLOCK_NUM
//!      advances.
//! ```
//!
//! ## What this module deliberately does NOT do
//!
//! * **Classical view-change.** java-tron declares the `VIEW_CHANGE`
//!   message type and dispatches it to `onChangeView`, but that
//!   handler is empty in upstream (`PbftMessageHandle.java:224-226`).
//!   DPoS already rotates leaders every 3s — a stuck producer simply
//!   yields to the next slot's witness — so the protocol never needs
//!   a PBFT view-change to make progress. This module matches: the
//!   message type round-trips, but recipients treat it as a logged
//!   no-op. The 60s tally [`expire_stale`] + 3s slot rotation are
//!   the actual liveness mechanisms.
//!
//! * **Auto-slashing.** java-tron has zero `slash` / `penalty` call
//!   sites in any PBFT file — there is no protocol-level slashing for
//!   double-signing. Instead, what we provide is structured
//!   evidence collection: [`EquivocationDetector`] watches every
//!   incoming SR-signed message for cross-payload double-votes
//!   (same SR, same `(epoch, view_n, msg_type, data_type)`, different
//!   `data`) and produces [`EquivocationEvidence`] — the two signed
//!   messages — for an off-chain proposal or future on-chain
//!   precompile to consume.
//!
//! * **Per-cycle SR snapshot in chainbase.** Membership-check delegates
//!   to the runtime, which routes by epoch when a cross-rotation
//!   snapshot is attached. The on-disk schedule store stores only the
//!   current active list — same as java-tron.

use std::collections::{BTreeMap, HashMap};

use prost::Message as _;
use tron_crypto::address::Address;
use tron_crypto::hash::sha256;
use tron_crypto::signature::{RecoverableSignature, SigError};
use tron_proto::protocol::pbft_message::{DataType, MsgType, Raw as PbftRaw};
use tron_proto::protocol::PbftMessage;

/// Compute the 2/3+1 vote threshold for `active_witness_count` SRs.
/// Matches java-tron's `Param.getAgreeNodeCount()` — `floor(N * 2 / 3) + 1`.
#[inline]
pub fn agree_node_count(active_witness_count: usize) -> usize {
    if active_witness_count == 0 {
        // No active SRs → no quorum is reachable. Return an impossible
        // threshold so `votes.len() >= threshold` is never satisfied;
        // returning 0 here meant `len() >= 0` was always true and PBFT
        // would solidify every block with zero votes (H-6).
        return usize::MAX;
    }
    active_witness_count * 2 / 3 + 1
}

/// Sign `raw` with `witness_priv_key` and wrap as a [`PbftMessage`].
///
/// Signature target = `sha256(raw.encode_to_vec())`. java-tron uses
/// the same sha256(rawData) digest convention everywhere — block
/// IDs, tx IDs, and PBFT message signing all share the recipe.
pub fn sign_pbft_raw(
    raw: PbftRaw,
    witness_priv_key: &[u8; 32],
) -> Result<PbftMessage, SigError> {
    let encoded = raw.encode_to_vec();
    let digest = sha256(&encoded);
    let sig = RecoverableSignature::sign_prehash(witness_priv_key, &digest)?;
    Ok(PbftMessage {
        raw_data: Some(raw),
        signature: sig.to_bytes().to_vec(),
    })
}

/// Build a signed `PbftMessage` with `msg_type = PREPARE` for a
/// specific block at height `block_num`.
///
/// `data` is the canonical payload identifying the block. For
/// `DataType::Block`, java-tron uses `[block_num_be(8) || block_hash(32)]`
/// — a stable, easy-to-compare key. Mirror that.
pub fn cast_prepare(
    witness_priv_key: &[u8; 32],
    epoch: i64,
    view_n: i64,
    data_type: DataType,
    data: Vec<u8>,
) -> Result<PbftMessage, SigError> {
    let raw = PbftRaw {
        msg_type: MsgType::Prepare as i32,
        data_type: data_type as i32,
        view_n,
        epoch,
        data,
    };
    sign_pbft_raw(raw, witness_priv_key)
}

/// Build a signed `PbftMessage` with `msg_type = COMMIT`. Identical
/// args to [`cast_prepare`].
pub fn cast_commit(
    witness_priv_key: &[u8; 32],
    epoch: i64,
    view_n: i64,
    data_type: DataType,
    data: Vec<u8>,
) -> Result<PbftMessage, SigError> {
    let raw = PbftRaw {
        msg_type: MsgType::Commit as i32,
        data_type: data_type as i32,
        view_n,
        epoch,
        data,
    };
    sign_pbft_raw(raw, witness_priv_key)
}

/// Recover the signer of a `PbftMessage`. Returns `None` if the
/// message is malformed (missing raw_data, signature wrong length,
/// signature doesn't verify).
pub fn recover_signer(msg: &PbftMessage) -> Option<Address> {
    let raw = msg.raw_data.as_ref()?;
    if msg.signature.len() != 65 {
        return None;
    }
    let sig = RecoverableSignature::from_bytes(&msg.signature).ok()?;
    let encoded = raw.encode_to_vec();
    let digest = sha256(&encoded);
    let pubkey = sig.recover_uncompressed_pubkey(&digest).ok()?;
    Address::from_uncompressed_pubkey(&pubkey).ok()
}

/// Encode the (block_num, block_hash) pair as a 40-byte
/// big-endian-num || 32-byte-hash key suitable for the `data` field
/// of a `PbftRaw` with `DataType::Block`. Stable and parseable
/// without consulting any state.
pub fn block_data_payload(block_num: i64, block_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&block_num.to_be_bytes());
    out.extend_from_slice(block_hash);
    out
}

/// Parse a block-data payload back into `(num, hash)`. Returns
/// `None` for malformed input.
pub fn parse_block_data_payload(data: &[u8]) -> Option<(i64, [u8; 32])> {
    if data.len() != 40 {
        return None;
    }
    let mut num_bytes = [0u8; 8];
    num_bytes.copy_from_slice(&data[..8]);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[8..]);
    Some((i64::from_be_bytes(num_bytes), hash))
}

/// Encode an SRL (Super-Representative List) payload as the
/// `data` field of a PBFT message with `DataType::Srl`. Mirrors
/// java-tron's `SRL` proto: `repeated bytes sr_address` of 21-byte
/// addresses, encoded directly (no length-prefix per item since
/// they're fixed-size — but java actually uses the `SRL` proto
/// builder so we mirror that wire format).
pub fn srl_data_payload(sr_addresses: &[Address]) -> Vec<u8> {
    use prost::Message as _;
    let srl = tron_proto::Srl {
        sr_address: sr_addresses
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect(),
    };
    srl.encode_to_vec()
}

/// Decode an SRL payload back into the witness list. Returns `None`
/// for malformed input.
pub fn parse_srl_data_payload(data: &[u8]) -> Option<Vec<Address>> {
    use prost::Message as _;
    let srl = tron_proto::Srl::decode(data).ok()?;
    let mut out = Vec::with_capacity(srl.sr_address.len());
    for addr in srl.sr_address {
        if addr.len() != 21 {
            return None;
        }
        let mut buf = [0u8; 21];
        buf.copy_from_slice(&addr);
        out.push(Address::from_raw(buf));
    }
    Some(out)
}

/// Outcome of [`BlockVoteTally::record_prepare`] /
/// `record_commit`. `Fresh` means a brand-new vote was accepted;
/// `Duplicate` means the signer had already voted with the SAME
/// signature (idempotent); `Equivocation` means the signer is voting
/// AGAIN at the same height with a DIFFERENT signature — that's the
/// classic Byzantine "double sign" pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteRecord {
    Fresh,
    Duplicate,
    /// SR equivocated — voted again at the same height with a different
    /// signature. The vote is **dropped** from the tally entirely (H-5),
    /// so a double-signer contributes nothing toward the threshold;
    /// `first_signature` + `conflicting_signature` are kept as
    /// double-sign evidence.
    Equivocation {
        signer: Address,
        first_signature: Vec<u8>,
        conflicting_signature: Vec<u8>,
    },
}

/// Per-block vote tally. One instance per block we're currently
/// voting on. Stores observed (signer → signature) pairs separately
/// for prepare + commit so the same SR can't double-count.
#[derive(Debug, Default, Clone)]
pub struct BlockVoteTally {
    /// Signer → full signature bytes, prepare phase.
    pub prepare_votes: HashMap<Address, Vec<u8>>,
    /// Signer → full signature bytes, commit phase. `BTreeMap` (not
    /// `HashMap`) because the iteration order — sorted by signer address —
    /// IS the on-disk byte order of the persisted `PbftCommitResult`. See
    /// [`commit_signatures`] and `PbftSignDataStore::put_commit_result`:
    /// the store consumes `signatures.values()` verbatim, so the sort
    /// key has to live in the type, not in a caller convention that a
    /// future writer might forget.
    pub commit_votes: BTreeMap<Address, Vec<u8>>,
    /// True once we've broadcast our own Prepare for this block.
    pub broadcast_prepare: bool,
    /// True once we've broadcast our own Commit for this block.
    pub broadcast_commit: bool,
}

impl BlockVoteTally {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed Prepare vote. Returns a [`VoteRecord`] so
    /// the caller can distinguish a fresh vote from a duplicate or
    /// an equivocation (double-sign).
    pub fn record_prepare(&mut self, signer: Address, signature: Vec<u8>) -> VoteRecord {
        if let Some(existing) = self.prepare_votes.get(&signer) {
            if existing == &signature {
                return VoteRecord::Duplicate;
            }
            let first = existing.clone();
            // H-5: drop the equivocating signer's vote entirely. Keeping
            // the first signature (the old behavior) let one byzantine SR
            // who signed first still count toward a solid decision — a
            // double-signer must contribute nothing.
            self.prepare_votes.remove(&signer);
            return VoteRecord::Equivocation {
                signer,
                first_signature: first,
                conflicting_signature: signature,
            };
        }
        self.prepare_votes.insert(signer, signature);
        VoteRecord::Fresh
    }

    /// Record an observed Commit vote. Same semantics as
    /// [`record_prepare`].
    pub fn record_commit(&mut self, signer: Address, signature: Vec<u8>) -> VoteRecord {
        if let Some(existing) = self.commit_votes.get(&signer) {
            if existing == &signature {
                return VoteRecord::Duplicate;
            }
            let first = existing.clone();
            // H-5: drop the equivocating signer's vote (see record_prepare).
            self.commit_votes.remove(&signer);
            return VoteRecord::Equivocation {
                signer,
                first_signature: first,
                conflicting_signature: signature,
            };
        }
        self.commit_votes.insert(signer, signature);
        VoteRecord::Fresh
    }

    /// True if the prepare-phase threshold is reached.
    pub fn prepare_threshold_met(&self, active_count: usize) -> bool {
        self.prepare_votes.len() >= agree_node_count(active_count)
    }

    /// True if the commit-phase threshold is reached → block is
    /// PBFT-solidified.
    pub fn commit_threshold_met(&self, active_count: usize) -> bool {
        self.commit_votes.len() >= agree_node_count(active_count)
    }

    /// Commit signatures, keyed by signer address. Returns an owned
    /// `BTreeMap` so the caller can release the tally lock before
    /// handing the signatures to `PbftSignDataStore::put_commit_result`.
    /// The sort-by-address invariant (which that store relies on for
    /// byte-parity with java-tron) is enforced by the type, not by
    /// caller discipline.
    pub fn commit_signatures(&self) -> BTreeMap<Address, Vec<u8>> {
        self.commit_votes.clone()
    }
}

/// Multi-block tally — keyed by the canonical block-data payload
/// (40-byte `num_be || hash`). This is what the runtime owns; it
/// looks up the right [`BlockVoteTally`] from each inbound message's
/// `raw_data.data` field.
#[derive(Debug, Default)]
pub struct PbftVoteTally {
    blocks: HashMap<Vec<u8>, BlockVoteTally>,
    /// First-observed timestamp (ms-since-epoch) per data_key. Used
    /// by [`expire_stale`] to time out + prune stuck votes.
    first_seen_ms: HashMap<Vec<u8>, i64>,
}

/// PBFT vote timeout, matching java-tron's `PbftMessageHandle.TIME_OUT`
/// (60s). After this elapses without crossing commit threshold, the
/// tally for that block is dropped and the vote is considered void.
///
/// Note: TRON's PBFT doesn't implement classical view-change with
/// leader rotation — DPoS already rotates the producer every 3s, so
/// a stuck leader simply yields to the next slot's witness. The
/// timeout-and-prune ensures we don't hold votes forever for blocks
/// that lost their producer mid-round.
pub const VOTE_TIMEOUT_MS: i64 = 60_000;

impl PbftVoteTally {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the tally for `data_key`. `data_key` is the
    /// 40-byte block-data payload. `now_ms` is the current wall-clock
    /// time; recorded on first-seen for [`expire_stale`].
    pub fn entry_with_time(
        &mut self,
        data_key: Vec<u8>,
        now_ms: i64,
    ) -> &mut BlockVoteTally {
        self.first_seen_ms.entry(data_key.clone()).or_insert(now_ms);
        self.blocks.entry(data_key).or_default()
    }

    /// Get or create the tally for `data_key` without recording a
    /// timestamp. Tests use this; production should use
    /// [`entry_with_time`].
    pub fn entry(&mut self, data_key: Vec<u8>) -> &mut BlockVoteTally {
        self.blocks.entry(data_key).or_default()
    }

    /// Read-only lookup.
    pub fn get(&self, data_key: &[u8]) -> Option<&BlockVoteTally> {
        self.blocks.get(data_key)
    }

    /// Drop the tally for `data_key` — called once the block is
    /// PBFT-solidified and we've persisted the signature set.
    pub fn forget(&mut self, data_key: &[u8]) {
        self.blocks.remove(data_key);
        self.first_seen_ms.remove(data_key);
    }

    /// Drop all tallies for blocks older than `block_num_threshold`.
    /// Bounded-memory invariant: we cap how far back we hold votes.
    pub fn prune_below(&mut self, block_num_threshold: i64) {
        self.blocks.retain(|key, _| {
            parse_block_data_payload(key)
                .map(|(n, _)| n >= block_num_threshold)
                .unwrap_or(true)
        });
        self.first_seen_ms.retain(|key, _| {
            parse_block_data_payload(key)
                .map(|(n, _)| n >= block_num_threshold)
                .unwrap_or(true)
        });
    }

    /// Drop every tally whose first-seen timestamp is older than
    /// `now_ms - VOTE_TIMEOUT_MS`. Returns the count dropped.
    ///
    /// Mirrors java-tron's `PbftMessageHandle.checkTimer` — runs on a
    /// 1Hz timer in production. Stuck votes (block proposed but
    /// never reached 2/3 commit) get dropped after 60s so the
    /// tally doesn't grow unbounded under chain-stall conditions.
    pub fn expire_stale(&mut self, now_ms: i64) -> usize {
        let threshold = now_ms.saturating_sub(VOTE_TIMEOUT_MS);
        let stale: Vec<Vec<u8>> = self
            .first_seen_ms
            .iter()
            .filter(|(_, &ts)| ts < threshold)
            .map(|(k, _)| k.clone())
            .collect();
        let n = stale.len();
        for key in stale {
            self.forget(&key);
        }
        n
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

/// Composite key for cross-payload equivocation detection. Two
/// messages that share this entire tuple but disagree on the `data`
/// field constitute a double-sign.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EquivocationKey {
    pub epoch: i64,
    pub view_n: i64,
    pub msg_type: i32,
    pub data_type: i32,
    pub signer: Address,
}

/// Cryptographic proof of PBFT double-signing. Both `first` and
/// `conflicting` are full `PbftMessage` records signed by the same
/// SR for the same `(epoch, view_n, msg_type, data_type)` but
/// different `data` payloads. Each verifies independently under the
/// SR's pubkey via [`recover_signer`]; the pair proves the SR
/// violated PBFT safety. Sufficient evidence for an off-chain
/// governance proposal or a future on-chain slashing precompile —
/// nothing else is needed, since recipients can replay the recovery
/// to confirm the signer.
#[derive(Debug, Clone, PartialEq)]
pub struct EquivocationEvidence {
    pub signer: Address,
    pub epoch: i64,
    pub view_n: i64,
    pub msg_type: i32,
    pub data_type: i32,
    pub first: PbftMessage,
    pub conflicting: PbftMessage,
}

#[derive(Debug, Clone)]
struct ObservedVote {
    data: Vec<u8>,
    msg: PbftMessage,
}

/// Cross-payload equivocation detector. Stateful index keyed by
/// `(epoch, view_n, msg_type, data_type, signer)`. The first vote
/// observed for a key is recorded verbatim; a subsequent vote for
/// the same key with a different `data` field produces
/// [`EquivocationEvidence`].
///
/// Differs from [`BlockVoteTally`]'s within-payload equivocation
/// detection: that one fires on `(same signer, same payload,
/// different signature)` — usually benign (signature malleability,
/// re-encoded relay). This one fires on `(same signer, same
/// epoch/view/type, DIFFERENT payload)` — the slashable case.
///
/// Memory bounds:
/// * `first_seen` — pruned via [`prune_below_epoch`].
/// * `evidence` — capped at `evidence_cap`; FIFO eviction on
///   overflow.
#[derive(Debug)]
pub struct EquivocationDetector {
    first_seen: HashMap<EquivocationKey, ObservedVote>,
    evidence: std::collections::VecDeque<EquivocationEvidence>,
    evidence_cap: usize,
}

impl Default for EquivocationDetector {
    fn default() -> Self {
        Self::new(256)
    }
}

impl EquivocationDetector {
    pub fn new(evidence_cap: usize) -> Self {
        Self {
            first_seen: HashMap::new(),
            evidence: std::collections::VecDeque::new(),
            evidence_cap: evidence_cap.max(1),
        }
    }

    /// Inspect `msg` for cross-payload equivocation. Returns
    /// `Some(evidence)` only on a *fresh* detection — repeated
    /// identical votes return `None`. The caller is responsible for
    /// having recovered `signer` from `msg` first.
    pub fn record(
        &mut self,
        signer: Address,
        msg: &PbftMessage,
    ) -> Option<EquivocationEvidence> {
        let raw = msg.raw_data.as_ref()?;
        let key = EquivocationKey {
            epoch: raw.epoch,
            view_n: raw.view_n,
            msg_type: raw.msg_type,
            data_type: raw.data_type,
            signer,
        };
        match self.first_seen.get(&key) {
            Some(prev) if prev.data == raw.data => None,
            Some(prev) => {
                let ev = EquivocationEvidence {
                    signer,
                    epoch: raw.epoch,
                    view_n: raw.view_n,
                    msg_type: raw.msg_type,
                    data_type: raw.data_type,
                    first: prev.msg.clone(),
                    conflicting: msg.clone(),
                };
                self.push_evidence(ev.clone());
                Some(ev)
            }
            None => {
                self.first_seen.insert(
                    key,
                    ObservedVote {
                        data: raw.data.clone(),
                        msg: msg.clone(),
                    },
                );
                None
            }
        }
    }

    fn push_evidence(&mut self, ev: EquivocationEvidence) {
        if self.evidence.len() >= self.evidence_cap {
            self.evidence.pop_front();
        }
        self.evidence.push_back(ev);
    }

    /// Drop every `first_seen` entry whose epoch is strictly below
    /// `threshold`. Evidence is NOT pruned by this — it is retained
    /// until drained or evicted by capacity.
    pub fn prune_below_epoch(&mut self, threshold: i64) {
        self.first_seen.retain(|k, _| k.epoch >= threshold);
    }

    /// Number of collected evidence entries.
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    /// Drain all collected evidence. After this, `evidence_count()` == 0.
    /// Intended for an RPC accessor or governance-proposal pipeline.
    pub fn drain_evidence(&mut self) -> Vec<EquivocationEvidence> {
        self.evidence.drain(..).collect()
    }

    /// Peek at evidence without draining. Useful for metrics emission.
    pub fn peek_evidence(&self) -> impl Iterator<Item = &EquivocationEvidence> {
        self.evidence.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_crypto::base58check::encode_address;

    const ALICE_PRIV: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90,
        0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90,
        0x12, 0x34,
    ];

    fn alice_addr() -> Address {
        let pk = tron_crypto::signature::public_key_from_private(&ALICE_PRIV).unwrap();
        Address::from_uncompressed_pubkey(&pk).unwrap()
    }

    #[test]
    fn agree_node_count_matches_2_3_plus_1() {
        // 27 SRs: 2/3 * 27 = 18; threshold = 19.
        assert_eq!(agree_node_count(27), 19);
        // 5 SRs: 5*2/3 = 3 (truncated); threshold = 4.
        assert_eq!(agree_node_count(5), 4);
        // 0 SRs: no quorum possible.
        assert_eq!(agree_node_count(0), usize::MAX); // H-6: unreachable, not 0
        // 1 SR: 0 + 1 = 1.
        assert_eq!(agree_node_count(1), 1);
    }

    #[test]
    fn block_data_payload_round_trips() {
        let hash = [0x99u8; 32];
        let payload = block_data_payload(12345, &hash);
        assert_eq!(payload.len(), 40);
        let (n, h) = parse_block_data_payload(&payload).expect("parse");
        assert_eq!(n, 12345);
        assert_eq!(h, hash);
    }

    #[test]
    fn signed_prepare_recovers_to_signer() {
        let hash = [0x11u8; 32];
        let data = block_data_payload(42, &hash);
        let msg = cast_prepare(&ALICE_PRIV, 0, 0, DataType::Block, data).unwrap();
        let recovered = recover_signer(&msg).expect("recover");
        let expected = alice_addr();
        assert_eq!(
            recovered.as_bytes(),
            expected.as_bytes(),
            "got {} expected {}",
            encode_address(&recovered),
            encode_address(&expected)
        );
    }

    #[test]
    fn tampered_msg_does_not_recover_to_signer() {
        let hash = [0x11u8; 32];
        let data = block_data_payload(42, &hash);
        let mut msg = cast_prepare(&ALICE_PRIV, 0, 0, DataType::Block, data).unwrap();
        // Flip a bit in the raw_data so the signature no longer
        // matches the recomputed digest.
        if let Some(raw) = msg.raw_data.as_mut() {
            raw.epoch ^= 1;
        }
        let recovered = recover_signer(&msg);
        // The signature still recovers SOME pubkey, just not Alice's.
        if let Some(addr) = recovered {
            assert_ne!(addr.as_bytes(), alice_addr().as_bytes());
        }
    }

    #[test]
    fn malformed_signature_returns_none() {
        let raw = PbftRaw {
            msg_type: MsgType::Prepare as i32,
            data_type: DataType::Block as i32,
            view_n: 0,
            epoch: 0,
            data: vec![1, 2, 3],
        };
        let msg = PbftMessage {
            raw_data: Some(raw),
            signature: vec![0u8; 32], // wrong length
        };
        assert!(recover_signer(&msg).is_none());
    }

    #[test]
    fn tally_dedups_identical_signature() {
        let mut t = BlockVoteTally::new();
        let addr = alice_addr();
        assert_eq!(t.record_prepare(addr, vec![0; 65]), VoteRecord::Fresh);
        // Same signer + same signature → duplicate, not equivocation.
        assert_eq!(t.record_prepare(addr, vec![0; 65]), VoteRecord::Duplicate);
        assert_eq!(t.prepare_votes.len(), 1);
        // The first signature is kept (matches java-tron — second is
        // dropped to prevent flip-flopping the tally).
        assert_eq!(t.prepare_votes.get(&addr), Some(&vec![0; 65]));
    }

    #[test]
    fn tally_flags_equivocation_when_signer_double_votes_with_different_sig() {
        let mut t = BlockVoteTally::new();
        let addr = alice_addr();
        assert_eq!(t.record_prepare(addr, vec![0; 65]), VoteRecord::Fresh);
        let outcome = t.record_prepare(addr, vec![1; 65]);
        match outcome {
            VoteRecord::Equivocation {
                signer,
                first_signature,
                conflicting_signature,
            } => {
                assert_eq!(signer, addr);
                assert_eq!(first_signature, vec![0; 65]);
                assert_eq!(conflicting_signature, vec![1; 65]);
            }
            other => panic!("expected Equivocation, got {other:?}"),
        }
        // H-5: the equivocating signer's vote is dropped entirely.
        assert_eq!(t.prepare_votes.get(&addr), None);
    }

    #[test]
    fn threshold_check_compares_to_2_3_plus_1() {
        let mut t = BlockVoteTally::new();
        // 27 SRs → need 19. Start with 18.
        for i in 0..18 {
            let mut bytes = [0u8; 21];
            bytes[0] = 0x41;
            bytes[20] = i as u8;
            t.record_prepare(Address::from_raw(bytes), vec![0; 65]);
        }
        assert!(!t.prepare_threshold_met(27));
        // 19th vote crosses.
        let mut bytes = [0u8; 21];
        bytes[0] = 0x41;
        bytes[20] = 99;
        t.record_prepare(Address::from_raw(bytes), vec![0; 65]);
        assert!(t.prepare_threshold_met(27));
    }

    #[test]
    fn commit_signatures_are_sorted_by_signer_address() {
        let mut t = BlockVoteTally::new();
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xcc;
        let mut b = [0u8; 21];
        b[0] = 0x41;
        b[20] = 0xaa;
        // Add in reverse address order; BTreeMap iteration order is
        // sorted-by-key (signer address), which is exactly the on-disk
        // order `PbftSignDataStore::put_commit_result` writes.
        t.record_commit(Address::from_raw(a), vec![0xcc; 65]);
        t.record_commit(Address::from_raw(b), vec![0xaa; 65]);
        let sigs = t.commit_signatures();
        let ordered: Vec<&Vec<u8>> = sigs.values().collect();
        // b's signature (0xaa..) should come first.
        assert_eq!(ordered[0][0], 0xaa);
        assert_eq!(ordered[1][0], 0xcc);
    }

    #[test]
    fn tally_prune_drops_old_blocks() {
        let mut t = PbftVoteTally::new();
        for n in 1..=10i64 {
            let _ = t.entry(block_data_payload(n, &[0u8; 32]));
        }
        assert_eq!(t.block_count(), 10);
        t.prune_below(6);
        // Blocks 6..=10 remain.
        assert_eq!(t.block_count(), 5);
    }

    #[test]
    fn expire_stale_drops_votes_older_than_timeout() {
        let mut t = PbftVoteTally::new();
        // Block 1 was first-seen at t=0; block 2 was first-seen at
        // t=70_000ms (10s after the timeout window starts but only
        // 10s before the current `now_ms`).
        let _ = t.entry_with_time(block_data_payload(1, &[0u8; 32]), 0);
        let _ = t.entry_with_time(block_data_payload(2, &[0u8; 32]), 70_000);

        // Now is t=130_000ms (130s in). Block 1's first-seen was at
        // 0, which is 130s ago → past VOTE_TIMEOUT_MS (60s). Block 2's
        // was 60s ago → exactly at the boundary (not yet stale per
        // the strict `<` check).
        let dropped = t.expire_stale(130_000);
        assert_eq!(dropped, 1, "block 1 should be expired");
        assert!(t.get(&block_data_payload(1, &[0u8; 32])).is_none());
        assert!(t.get(&block_data_payload(2, &[0u8; 32])).is_some());
    }

    #[test]
    fn expire_stale_at_zero_drops_nothing() {
        let mut t = PbftVoteTally::new();
        let _ = t.entry_with_time(block_data_payload(1, &[0u8; 32]), 1_700_000_000_000);
        // Calling at a recent time well within the window.
        assert_eq!(t.expire_stale(1_700_000_005_000), 0);
        assert_eq!(t.block_count(), 1);
    }

    // ============================================================
    // EquivocationDetector
    // ============================================================

    fn signed_prepare(priv_key: &[u8; 32], epoch: i64, view_n: i64, data: Vec<u8>) -> PbftMessage {
        cast_prepare(priv_key, epoch, view_n, DataType::Block, data).unwrap()
    }

    fn signed_commit(priv_key: &[u8; 32], epoch: i64, view_n: i64, data: Vec<u8>) -> PbftMessage {
        cast_commit(priv_key, epoch, view_n, DataType::Block, data).unwrap()
    }

    #[test]
    fn detector_records_first_vote_as_no_evidence() {
        let mut det = EquivocationDetector::default();
        let msg = signed_prepare(&ALICE_PRIV, 5, 0, block_data_payload(1, &[0u8; 32]));
        let signer = recover_signer(&msg).unwrap();
        assert!(det.record(signer, &msg).is_none());
        assert_eq!(det.evidence_count(), 0);
    }

    #[test]
    fn detector_ignores_identical_revote() {
        let mut det = EquivocationDetector::default();
        let payload = block_data_payload(1, &[0u8; 32]);
        let msg1 = signed_prepare(&ALICE_PRIV, 5, 0, payload.clone());
        let msg2 = signed_prepare(&ALICE_PRIV, 5, 0, payload);
        let signer = recover_signer(&msg1).unwrap();
        assert!(det.record(signer, &msg1).is_none());
        // Same key + same payload — sig is identical for the deterministic
        // SM2 path, but even if it weren't the data field matches → ignored.
        assert!(det.record(signer, &msg2).is_none());
        assert_eq!(det.evidence_count(), 0);
    }

    #[test]
    fn detector_flags_cross_payload_double_sign() {
        let mut det = EquivocationDetector::default();
        // Alice signs Prepare at (epoch=5, view=0) for TWO DIFFERENT blocks.
        let payload_a = block_data_payload(1, &[0xaa; 32]);
        let payload_b = block_data_payload(1, &[0xbb; 32]);
        let msg_a = signed_prepare(&ALICE_PRIV, 5, 0, payload_a);
        let msg_b = signed_prepare(&ALICE_PRIV, 5, 0, payload_b);
        let signer = recover_signer(&msg_a).unwrap();
        assert!(det.record(signer, &msg_a).is_none());
        let ev = det.record(signer, &msg_b).expect("evidence");
        assert_eq!(ev.signer, signer);
        assert_eq!(ev.epoch, 5);
        assert_eq!(ev.msg_type, MsgType::Prepare as i32);
        assert_eq!(ev.first, msg_a);
        assert_eq!(ev.conflicting, msg_b);
        assert_eq!(det.evidence_count(), 1);
    }

    #[test]
    fn detector_distinguishes_prepare_vs_commit_at_same_height() {
        let mut det = EquivocationDetector::default();
        let payload_a = block_data_payload(1, &[0xaa; 32]);
        let payload_b = block_data_payload(1, &[0xbb; 32]);
        // Prepare for payload A.
        let p = signed_prepare(&ALICE_PRIV, 5, 0, payload_a);
        let signer = recover_signer(&p).unwrap();
        assert!(det.record(signer, &p).is_none());
        // Commit at the same epoch/view but DIFFERENT msg_type — different
        // key, not equivocation.
        let c = signed_commit(&ALICE_PRIV, 5, 0, payload_b);
        assert!(det.record(signer, &c).is_none());
        assert_eq!(det.evidence_count(), 0);
    }

    #[test]
    fn detector_distinguishes_view_n() {
        let mut det = EquivocationDetector::default();
        let payload_a = block_data_payload(1, &[0xaa; 32]);
        let payload_b = block_data_payload(1, &[0xbb; 32]);
        // view 0 → payload A.
        let m_view0 = signed_prepare(&ALICE_PRIV, 5, 0, payload_a);
        let signer = recover_signer(&m_view0).unwrap();
        assert!(det.record(signer, &m_view0).is_none());
        // view 1 → payload B. Legitimate — a view-change would let an SR
        // re-vote at a new view. Different key, not evidence.
        let m_view1 = signed_prepare(&ALICE_PRIV, 5, 1, payload_b);
        assert!(det.record(signer, &m_view1).is_none());
        assert_eq!(det.evidence_count(), 0);
    }

    #[test]
    fn detector_drain_clears_pool() {
        let mut det = EquivocationDetector::default();
        let payload_a = block_data_payload(1, &[0xaa; 32]);
        let payload_b = block_data_payload(1, &[0xbb; 32]);
        let msg_a = signed_prepare(&ALICE_PRIV, 5, 0, payload_a);
        let msg_b = signed_prepare(&ALICE_PRIV, 5, 0, payload_b);
        let signer = recover_signer(&msg_a).unwrap();
        det.record(signer, &msg_a);
        det.record(signer, &msg_b).unwrap();
        let drained = det.drain_evidence();
        assert_eq!(drained.len(), 1);
        assert_eq!(det.evidence_count(), 0);
        assert!(det.drain_evidence().is_empty(), "drain twice ⇒ empty");
    }

    #[test]
    fn detector_evidence_cap_evicts_fifo() {
        let mut det = EquivocationDetector::new(2);
        // Generate three different signer key pairs by mutating the priv
        // key bytes; for each one create A then B at the same epoch/view.
        let priv_keys: [[u8; 32]; 3] = [[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]];
        for priv_key in &priv_keys {
            let payload_a = block_data_payload(1, &[0xaa; 32]);
            let payload_b = block_data_payload(1, &[0xbb; 32]);
            let msg_a = signed_prepare(priv_key, 5, 0, payload_a);
            let msg_b = signed_prepare(priv_key, 5, 0, payload_b);
            let signer = recover_signer(&msg_a).unwrap();
            det.record(signer, &msg_a);
            det.record(signer, &msg_b).unwrap();
        }
        // Cap = 2 → first evidence evicted; latest two retained.
        assert_eq!(det.evidence_count(), 2);
    }

    #[test]
    fn detector_prune_below_epoch_drops_old_first_seen_only() {
        let mut det = EquivocationDetector::default();
        let payload_a = block_data_payload(1, &[0xaa; 32]);
        let payload_b = block_data_payload(1, &[0xbb; 32]);
        // Epoch 5 evidence.
        let m5a = signed_prepare(&ALICE_PRIV, 5, 0, payload_a.clone());
        let m5b = signed_prepare(&ALICE_PRIV, 5, 0, payload_b.clone());
        let signer = recover_signer(&m5a).unwrap();
        det.record(signer, &m5a);
        det.record(signer, &m5b).unwrap();
        // Epoch 10 first observation.
        let m10 = signed_prepare(&ALICE_PRIV, 10, 0, payload_a.clone());
        det.record(signer, &m10);
        // Prune below 8 — drops the (epoch=5) first_seen entry but
        // retains the evidence collected from it.
        det.prune_below_epoch(8);
        // A new conflicting vote at epoch 5 should now register as
        // first-seen (not as evidence), because the prior entry was
        // pruned.
        let m5c = signed_prepare(&ALICE_PRIV, 5, 0, block_data_payload(1, &[0xcc; 32]));
        assert!(det.record(signer, &m5c).is_none());
        // Evidence count from the epoch-5 round is preserved.
        assert_eq!(det.evidence_count(), 1);
        // Epoch-10 first_seen is intact: a conflicting epoch-10 vote
        // produces fresh evidence.
        let m10b = signed_prepare(&ALICE_PRIV, 10, 0, payload_b);
        det.record(signer, &m10b).expect("fresh evidence at epoch 10");
        assert_eq!(det.evidence_count(), 2);
    }
}
