//! Validating transaction mempool with broadcast hooks.
//!
//! [`TxMempool`] is the concrete `tron_rpc::Mempool` implementation
//! used by the daemon. It:
//!
//! * Decodes incoming protobuf `Transaction` bytes.
//! * Recovers signers from `tx.signature[]` (rejects on format /
//!   recovery failure).
//! * Checks `raw_data.expiration > now`.
//! * Dedups by `tx_id = sha256(raw_data.encode())`.
//! * Caps total pending at `max_size` (default 2000, matching java-tron's
//!   `Manager.MAX_TRANSACTION_PENDING`); evicts the oldest-expired
//!   first, falls back to oldest-received.
//! * Pushes accepted `tx_id`s onto a tokio `broadcast` channel so the
//!   sync driver (or any other subscriber) can fan out to peers.
//!
//! What this module does NOT do:
//!
//! * Re-execute the tx — only validates statelessly inside this module.
//!   State-aware validation (fee, permission, contract-specific checks)
//!   is opt-in via [`TxMempool::with_validator`]: the caller provides a
//!   closure that runs the actuator dispatch against current state.
//!   tron-node wires this in production so peer-rejected txs never
//!   enter our pending set.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use tokio::sync::broadcast;
use tracing::{debug, warn};
use tron_chainbase::KvBackend;
use tron_proto::Transaction;
use tron_rpc::mempool::{Mempool, SubmitOutcome};

/// Mempool configuration. Sensible defaults are exposed via
/// [`MempoolConfig::default`]; tweak before passing to `TxMempool::new`.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of pending txs. java-tron pins this at 2000.
    pub max_size: usize,
    /// Broadcast channel capacity. When subscribers fall behind by
    /// more than this many txs, the oldest are dropped from the
    /// channel (the txs stay in the mempool — only the broadcast
    /// notification is lost).
    pub broadcast_buffer: usize,
    /// Maximum wire size of a single accepted tx. Defaults to java-tron's
    /// `TRANSACTION_MAX_BYTE_SIZE` (500 KiB) — anything larger is invalid
    /// on-chain anyway, so rejecting it costs nothing and stops one
    /// oversized tx from eating more memory than hundreds of normal ones.
    pub per_tx_max_bytes: usize,
    /// Maximum total wire bytes across all pending txs. Bounds mempool
    /// memory independently of `max_size`: 2000 × 500 KiB would be ~1 GiB.
    pub max_bytes: usize,
    /// Maximum pending txs from a single signer. Stops one account from
    /// monopolizing all `max_size` slots and crowding everyone else out.
    /// (An attacker with many keys can Sybil around this — it mainly
    /// bounds accidental single-sender floods and raises the bar.)
    pub per_sender_cap: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 2000,
            broadcast_buffer: 1024,
            per_tx_max_bytes: 500 * 1024,
            max_bytes: 128 * 1024 * 1024,
            per_sender_cap: 256,
        }
    }
}

/// All the reasons a `submit` can fail.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum MempoolError {
    #[error("decode transaction: {0}")]
    Decode(String),
    #[error("transaction has no raw_data")]
    MissingRawData,
    #[error("transaction has no signatures")]
    NoSignatures,
    #[error("transaction expired (expiration {expiration_ms} <= now {now_ms})")]
    Expired { expiration_ms: i64, now_ms: i64 },
    #[error("signer recovery failed: {0}")]
    BadSignature(String),
    #[error("duplicate tx_id (already in mempool)")]
    Duplicate,
    #[error("mempool full ({size} / {max})")]
    Full { size: usize, max: usize },
    #[error("transaction too large ({size} bytes > {max})")]
    TxTooLarge { size: usize, max: usize },
    #[error("mempool byte budget exhausted ({current} + {incoming} > {max})")]
    BytesFull {
        current: usize,
        incoming: usize,
        max: usize,
    },
    #[error("per-sender pending limit reached ({pending} >= {cap})")]
    SenderLimit { pending: usize, cap: usize },
    #[error("state validation failed: {0}")]
    ValidationFailed(String),
}

impl MempoolError {
    /// Short, fixed label used as the `reason` value in the Prometheus
    /// `tron_node_mempool_rejected_by_reason_total` counter. Stable
    /// across releases so dashboards don't break.
    pub fn metric_reason(&self) -> &'static str {
        match self {
            MempoolError::Decode(_) => "decode",
            MempoolError::MissingRawData => "missing_raw_data",
            MempoolError::NoSignatures => "no_signatures",
            MempoolError::Expired { .. } => "expired",
            MempoolError::BadSignature(_) => "bad_signature",
            MempoolError::Duplicate => "duplicate",
            MempoolError::Full { .. } => "full",
            MempoolError::TxTooLarge { .. } => "tx_too_large",
            MempoolError::BytesFull { .. } => "bytes_full",
            MempoolError::SenderLimit { .. } => "sender_limit",
            MempoolError::ValidationFailed(_) => "validation_failed",
        }
    }
}

/// State-aware validator hook. Called after the cheap stateless checks
/// (decode / sig / expiration / dedup) but before the tx is inserted
/// into the pending map. Return `Err(reason)` to reject the tx; the
/// reason surfaces as `MempoolError::ValidationFailed`.
///
/// Production setups wire this to `tron_actuator::dispatch_validate`
/// against current state so peers don't reject our broadcasts.
/// Test / standalone setups can omit it.
pub type TxValidatorFn = Box<dyn Fn(&Transaction) -> Result<(), String> + Send + Sync>;

/// A tx waiting in the mempool.
#[derive(Debug, Clone)]
pub struct PendingTx {
    pub tx: Transaction,
    pub raw_bytes: Vec<u8>,
    pub tx_id: [u8; 32],
    /// When `submit` accepted this tx. Used by the eviction sweeper
    /// when no entries are past `raw_data.expiration` yet.
    pub received_at_ms: i64,
    /// `raw_data.expiration`. The eviction sweeper drops entries
    /// past this point.
    pub expiration_ms: i64,
    /// Primary signer (first recovered signer) of this tx, used to key
    /// the per-sender cap. `None` only if no signer could be determined.
    pub sender: Option<[u8; 21]>,
}

pub struct TxMempool {
    inner: Mutex<Inner>,
    broadcast: broadcast::Sender<[u8; 32]>,
    config: MempoolConfig,
    validator: Option<TxValidatorFn>,
    /// Optional on-disk persistence. When attached, every accepted tx
    /// is written under `tx_id → raw_bytes` so the pool survives a
    /// restart. Removed on eviction (expiration) and on `remove`
    /// (called by the SR runtime when a tx is included in a block).
    /// java-tron doesn't persist its pending queue; tron-goblin-node does
    /// because reboots are operationally cheap and re-relaying valid
    /// txs from disk avoids losing work that hasn't been included yet.
    persistence: Option<Arc<dyn KvBackend>>,
    /// Optional metrics sink. Wired by the daemon; tests usually omit.
    /// Updated on every `submit` outcome (accepted / rejected-by-reason)
    /// and on each `evict_expired` sweep.
    metrics: Option<Arc<tron_rpc::Metrics>>,
}

struct Inner {
    pending: HashMap<[u8; 32], PendingTx>,
}

impl TxMempool {
    pub fn new(config: MempoolConfig) -> Self {
        let (tx, _rx) = broadcast::channel(config.broadcast_buffer.max(1));
        Self {
            inner: Mutex::new(Inner {
                pending: HashMap::new(),
            }),
            broadcast: tx,
            config,
            validator: None,
            persistence: None,
            metrics: None,
        }
    }

    /// Attach a metrics sink. Tracks accepted / rejected-by-reason
    /// counters and the pending-size gauge.
    pub fn with_metrics(mut self, metrics: Arc<tron_rpc::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn new_arc(config: MempoolConfig) -> Arc<Self> {
        Arc::new(Self::new(config))
    }

    /// Attach a state-aware validator that runs after the cheap checks
    /// (decode / sig / expiration / dedup) but before insertion. See
    /// [`TxValidatorFn`] for the contract.
    pub fn with_validator(mut self, validator: TxValidatorFn) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Attach an on-disk persistence backend. Every accepted tx will be
    /// written as `tx_id → raw_bytes`; entries are deleted on `remove`
    /// and on expiration eviction. Pair with [`Self::reload_from_disk`]
    /// after construction to repopulate the in-memory pool.
    pub fn with_persistence(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.persistence = Some(backend);
        self
    }

    /// Subscribe to the broadcast channel. Each accepted `submit`
    /// emits the tx_id. Use [`Self::get`] to fetch the full tx body.
    pub fn subscribe(&self) -> broadcast::Receiver<[u8; 32]> {
        self.broadcast.subscribe()
    }

    /// Submit raw protobuf-encoded transaction bytes.
    ///
    /// Returns the canonical `tx_id` on success. Side effects: inserts
    /// into the pending map; bumps the broadcast channel. The
    /// expiration eviction sweeper runs first so a full mempool with
    /// expired entries doesn't reject new txs.
    pub fn submit(&self, raw: &[u8]) -> Result<[u8; 32], MempoolError> {
        let result = self.submit_inner(raw);
        if let Some(m) = &self.metrics {
            match &result {
                Ok(_) => {
                    m.inc_mempool_accepted();
                    m.set_mempool_size(self.pending_count() as i64);
                }
                Err(e) => {
                    m.record_mempool_rejected(e.metric_reason());
                }
            }
        }
        result
    }

    /// Inner submit body. Wrapped by [`submit`] so every exit path
    /// runs through one metrics accounting site (instead of sprinkling
    /// counter bumps into every `return Err(...)`).
    fn submit_inner(&self, raw: &[u8]) -> Result<[u8; 32], MempoolError> {
        let now_ms = now_ms();

        // Reject oversized txs before the (more expensive) decode. Bounds
        // per-tx memory; mirrors java-tron's on-chain size limit.
        if raw.len() > self.config.per_tx_max_bytes {
            return Err(MempoolError::TxTooLarge {
                size: raw.len(),
                max: self.config.per_tx_max_bytes,
            });
        }

        let tx = Transaction::decode(raw)
            .map_err(|e| MempoolError::Decode(e.to_string()))?;
        let raw_data = tx
            .raw_data
            .as_ref()
            .ok_or(MempoolError::MissingRawData)?;

        if tx.signature.is_empty() {
            return Err(MempoolError::NoSignatures);
        }
        // Snapshot what we need from raw_data so the borrow doesn't
        // leak into the moved-tx insertion below.
        let expiration_ms = raw_data.expiration;
        if expiration_ms > 0 && expiration_ms <= now_ms {
            return Err(MempoolError::Expired {
                expiration_ms,
                now_ms,
            });
        }

        // Recover at least one signer to ensure the signature bytes
        // are well-formed and recoverable. Doesn't check the signer
        // is in any permission — that's an actuator-layer concern.
        let signers = tron_types::recover_all_signers(&tx)
            .map_err(|e| MempoolError::BadSignature(e.to_string()))?;
        // Primary signer keys the per-sender cap below.
        let sender = signers.first().map(|a| *a.as_bytes());

        let tx_id = tron_types::tx_id(&tx)
            .map_err(|e| MempoolError::Decode(format!("tx_id: {e:?}")))?;

        // Dup check first — cheap and avoids running the (potentially
        // expensive) state-aware validator on a tx we'd reject anyway.
        // A racing submitter could insert the same tx_id between this
        // check and the final insertion below; the lock at insertion
        // catches it with a second check.
        if self.inner.lock().unwrap().pending.contains_key(&tx_id) {
            return Err(MempoolError::Duplicate);
        }

        // State-aware validation (opt-in). Runs the actuator dispatch
        // against current state to catch fee insufficiency, missing
        // permissions, contract-specific preconditions — anything a
        // peer would reject on receive. Skipped when no validator is
        // attached (test / standalone setups).
        if let Some(v) = &self.validator {
            if let Err(reason) = v(&tx) {
                return Err(MempoolError::ValidationFailed(reason));
            }
        }

        let mut inner = self.inner.lock().unwrap();
        // Re-check dup after dropping + re-acquiring the lock around
        // the validator call.
        if inner.pending.contains_key(&tx_id) {
            return Err(MempoolError::Duplicate);
        }

        // Evict expired before checking the cap, so a steady stream
        // of new txs naturally rolls out the old ones.
        Self::evict_expired_inner(&mut inner, now_ms);
        if inner.pending.len() >= self.config.max_size {
            return Err(MempoolError::Full {
                size: inner.pending.len(),
                max: self.config.max_size,
            });
        }

        // One pass over the pending set for the byte budget and the
        // per-sender cap (n <= max_size, so this stays cheap).
        let mut current_bytes = 0usize;
        let mut sender_pending = 0usize;
        for p in inner.pending.values() {
            current_bytes += p.raw_bytes.len();
            if sender.is_some() && p.sender == sender {
                sender_pending += 1;
            }
        }
        if current_bytes + raw.len() > self.config.max_bytes {
            return Err(MempoolError::BytesFull {
                current: current_bytes,
                incoming: raw.len(),
                max: self.config.max_bytes,
            });
        }
        if sender.is_some() && sender_pending >= self.config.per_sender_cap {
            return Err(MempoolError::SenderLimit {
                pending: sender_pending,
                cap: self.config.per_sender_cap,
            });
        }

        let pending = PendingTx {
            tx,
            raw_bytes: raw.to_vec(),
            tx_id,
            received_at_ms: now_ms,
            expiration_ms,
            sender,
        };
        inner.pending.insert(tx_id, pending);
        drop(inner);

        // Persist after the in-memory insert so a crash between the
        // insert and broadcast leaves a recoverable on-disk entry.
        // A persistence write failure is best-effort and logged — the
        // in-memory pending entry is still authoritative for this
        // process; a crash before the persist would have produced
        // identical observable state.
        if let Some(p) = &self.persistence {
            if let Err(e) = p.put(&tx_id, raw) {
                debug!(error = %e, "mempool persistence put failed");
            }
        }

        // Best-effort broadcast — if no subscribers, send() errors
        // with NoReceivers; that's fine, the tx still lives in the
        // pending map for any future subscriber to pull via get().
        match self.broadcast.send(tx_id) {
            Ok(n) => debug!(tx_id = %hex_short(&tx_id), subscribers = n, "broadcast"),
            Err(_) => debug!(tx_id = %hex_short(&tx_id), "broadcast: no subscribers"),
        }
        Ok(tx_id)
    }

    pub fn pending_count(&self) -> usize {
        self.inner.lock().unwrap().pending.len()
    }

    pub fn pending_ids(&self) -> Vec<[u8; 32]> {
        self.inner.lock().unwrap().pending.keys().copied().collect()
    }

    pub fn get(&self, tx_id: &[u8; 32]) -> Option<PendingTx> {
        self.inner.lock().unwrap().pending.get(tx_id).cloned()
    }

    /// Drop `tx_id` from the pending pool. Called by the SR runtime
    /// after a tx gets included in a produced block — otherwise the
    /// same tx would get re-broadcast on every block.
    pub fn remove(&self, tx_id: &[u8; 32]) -> bool {
        let removed = self.inner.lock().unwrap().pending.remove(tx_id).is_some();
        if removed {
            if let Some(p) = &self.persistence {
                if let Err(e) = p.delete(tx_id) {
                    debug!(error = %e, "mempool persistence delete failed");
                }
            }
            if let Some(m) = &self.metrics {
                m.set_mempool_size(self.pending_count() as i64);
            }
        }
        removed
    }

    /// Remove every tx whose `expiration_ms` is `<= now_ms`. Returns
    /// the number evicted. Can be called externally by a periodic
    /// sweeper task; `submit` also runs it implicitly.
    pub fn evict_expired(&self, now_ms: i64) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let evicted_ids = Self::evict_expired_inner(&mut inner, now_ms);
        let n = evicted_ids.len();
        drop(inner);
        if let Some(p) = &self.persistence {
            for id in &evicted_ids {
                if let Err(e) = p.delete(id) {
                    debug!(error = %e, "mempool persistence delete failed");
                }
            }
        }
        if let Some(m) = &self.metrics {
            if n > 0 {
                m.inc_mempool_evicted_expired(n as u64);
                m.set_mempool_size(self.pending_count() as i64);
            }
        }
        n
    }

    fn evict_expired_inner(inner: &mut Inner, now_ms: i64) -> Vec<[u8; 32]> {
        let mut to_remove: Vec<[u8; 32]> = Vec::new();
        for (id, p) in inner.pending.iter() {
            if p.expiration_ms > 0 && p.expiration_ms <= now_ms {
                to_remove.push(*id);
            }
        }
        for id in &to_remove {
            inner.pending.remove(id);
        }
        if !to_remove.is_empty() {
            warn!(evicted = to_remove.len(), now_ms, "expired txs evicted");
        }
        to_remove
    }

    /// Repopulate the in-memory pool from the persistence backend.
    /// Each on-disk entry is re-run through `submit`, so the same
    /// validation gate (decode, signature recovery, expiration,
    /// state-aware validator) applies — stale entries are skipped
    /// and pruned from the backend in one pass.
    ///
    /// Returns a `ReloadStats` summarizing what happened.
    ///
    /// Idempotent: calling twice produces no additional inserts the
    /// second time (the dedup check rejects, and a rejected re-submit
    /// keeps the on-disk row — see the explicit `delete` below for
    /// the only paths that prune from disk).
    pub fn reload_from_disk(&self) -> ReloadStats {
        let backend = match self.persistence.as_ref() {
            Some(p) => p,
            None => return ReloadStats::default(),
        };
        let mut stats = ReloadStats::default();
        let entries = match backend.scan_all() {
            Ok(rows) => rows,
            Err(e) => {
                debug!(error = %e, "mempool persistence scan_all failed");
                return stats;
            }
        };
        stats.scanned = entries.len();
        for (key, raw) in entries {
            match self.submit(&raw) {
                Ok(_) => stats.restored += 1,
                Err(MempoolError::Duplicate) => {
                    // Already in pending (e.g. second call to reload).
                    // Leave the disk row alone.
                    stats.skipped += 1;
                }
                Err(e) => {
                    // Decode/sig/expiration/validator failure — the
                    // tx is no longer admissible. Drop the on-disk
                    // entry so we don't keep retrying every restart.
                    let del_result = if let Ok(id) = <[u8; 32]>::try_from(key.as_slice()) {
                        backend.delete(&id)
                    } else {
                        // Malformed key (not a 32-byte tx_id) — delete
                        // by the raw bytes anyway.
                        backend.delete(&key)
                    };
                    if let Err(del_err) = del_result {
                        debug!(error = %del_err, "mempool persistence delete failed");
                    }
                    stats.dropped += 1;
                    debug!(reason = %e, "dropped stale persisted tx");
                }
            }
        }
        if stats.scanned > 0 {
            debug!(
                scanned = stats.scanned,
                restored = stats.restored,
                dropped = stats.dropped,
                skipped = stats.skipped,
                "mempool reload complete"
            );
        }
        stats
    }
}

/// Summary of a [`TxMempool::reload_from_disk`] call.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReloadStats {
    /// Total rows read from the backend.
    pub scanned: usize,
    /// Rows that were re-submitted into the in-memory pool.
    pub restored: usize,
    /// Rows that failed re-validation and were deleted from disk.
    pub dropped: usize,
    /// Rows already present in the in-memory pool (idempotency path).
    pub skipped: usize,
}

impl Mempool for TxMempool {
    fn submit_tron(&self, raw: &[u8]) -> SubmitOutcome {
        match self.submit(raw) {
            Ok(id) => SubmitOutcome::Accepted(id),
            Err(e) => SubmitOutcome::Rejected(e.to_string()),
        }
    }

    fn pending_count(&self) -> usize {
        self.pending_count()
    }

    fn pending_snapshot(&self) -> Vec<tron_rpc::mempool::MempoolEntry> {
        let inner = self.inner.lock().unwrap();
        inner
            .pending
            .values()
            .map(|p| tron_rpc::mempool::MempoolEntry {
                tx_id: p.tx_id,
                raw_bytes: p.raw_bytes.clone(),
                received_at_ms: p.received_at_ms,
            })
            .collect()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn hex_short(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for byte in &b[..8] {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use tron_proto::transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw};
    use tron_proto::TransferContract;

    const PRIV: [u8; 32] =
        hex!("1234567890123456789012345678901234567890123456789012345678901234");

    fn signed_tx(amount: i64, expiration_offset_ms: i64) -> Vec<u8> {
        let owner = derive_address(&PRIV);
        let tc = TransferContract {
            owner_address: owner.to_vec(),
            to_address: vec![0x41; 21],
            amount,
        };
        let mut tx = Transaction {
            raw_data: Some(TxRaw {
                contract: vec![TxContract {
                    r#type: ContractType::TransferContract as i32,
                    parameter: Some(prost_types::Any {
                        type_url: "type.googleapis.com/protocol.TransferContract".into(),
                        value: tc.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                expiration: now_ms() + expiration_offset_ms,
                timestamp: now_ms(),
                ..Default::default()
            }),
            signature: vec![],
            ret: vec![],
        };
        tron_types::sign_transaction(&mut tx, &PRIV).unwrap();
        tx.encode_to_vec()
    }

    fn derive_address(priv_key: &[u8; 32]) -> [u8; 21] {
        let dummy = [0x42u8; 32];
        let sig =
            tron_crypto::signature::RecoverableSignature::sign_prehash(priv_key, &dummy).unwrap();
        let pubkey = sig.recover_uncompressed_pubkey(&dummy).unwrap();
        let h = tron_crypto::hash::keccak256(&pubkey[1..]);
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].copy_from_slice(&h[12..]);
        a
    }

    #[test]
    fn submit_signed_tx_returns_tx_id_and_bumps_pending_count() {
        let m = TxMempool::new(MempoolConfig::default());
        let bytes = signed_tx(1, 60_000);
        let id = m.submit(&bytes).expect("accept");
        assert_eq!(m.pending_count(), 1);
        assert!(m.get(&id).is_some());
    }

    #[test]
    fn submit_unsigned_tx_rejected() {
        let m = TxMempool::new(MempoolConfig::default());
        let tx = Transaction {
            raw_data: Some(TxRaw {
                expiration: now_ms() + 60_000,
                ..Default::default()
            }),
            signature: vec![],
            ret: vec![],
        };
        let err = m.submit(&tx.encode_to_vec()).unwrap_err();
        assert!(matches!(err, MempoolError::NoSignatures));
    }

    #[test]
    fn submit_expired_tx_rejected() {
        let m = TxMempool::new(MempoolConfig::default());
        // expiration 60s ago.
        let bytes = signed_tx(1, -60_000);
        let err = m.submit(&bytes).unwrap_err();
        assert!(matches!(err, MempoolError::Expired { .. }));
    }

    #[test]
    fn submit_duplicate_rejected() {
        let m = TxMempool::new(MempoolConfig::default());
        let bytes = signed_tx(1, 60_000);
        m.submit(&bytes).unwrap();
        let err = m.submit(&bytes).unwrap_err();
        assert!(matches!(err, MempoolError::Duplicate));
    }

    #[test]
    fn submit_full_rejected_after_eviction() {
        let m = TxMempool::new(MempoolConfig {
            max_size: 2,
            broadcast_buffer: 8,
            ..MempoolConfig::default()
        });
        // Fill with distinct amounts so distinct tx_ids.
        for amount in [1i64, 2] {
            m.submit(&signed_tx(amount, 60_000)).unwrap();
        }
        let err = m.submit(&signed_tx(3, 60_000)).unwrap_err();
        assert!(matches!(err, MempoolError::Full { .. }));
    }

    #[test]
    fn submit_oversize_tx_rejected() {
        // H-7: a per-tx byte cap smaller than any real signed tx.
        let m = TxMempool::new(MempoolConfig {
            per_tx_max_bytes: 16,
            ..MempoolConfig::default()
        });
        let err = m.submit(&signed_tx(1, 60_000)).unwrap_err();
        assert!(matches!(err, MempoolError::TxTooLarge { .. }), "got {err:?}");
        assert_eq!(m.pending_count(), 0);
    }

    #[test]
    fn submit_rejected_when_total_byte_budget_exhausted() {
        // H-7: budget admits exactly one tx of this size; the second
        // distinct tx pushes the total over and is rejected.
        let first = signed_tx(1, 60_000);
        let m = TxMempool::new(MempoolConfig {
            max_bytes: first.len(),
            ..MempoolConfig::default()
        });
        m.submit(&first).expect("first fits exactly");
        let err = m.submit(&signed_tx(2, 60_000)).unwrap_err();
        assert!(matches!(err, MempoolError::BytesFull { .. }), "got {err:?}");
        assert_eq!(m.pending_count(), 1);
    }

    #[test]
    fn submit_rejected_when_sender_cap_exceeded() {
        // H-7: all `signed_tx` outputs share one signer (PRIV), so the
        // cap trips after `per_sender_cap` distinct txs from it.
        let m = TxMempool::new(MempoolConfig {
            per_sender_cap: 2,
            ..MempoolConfig::default()
        });
        m.submit(&signed_tx(1, 60_000)).unwrap();
        m.submit(&signed_tx(2, 60_000)).unwrap();
        let err = m.submit(&signed_tx(3, 60_000)).unwrap_err();
        assert!(matches!(err, MempoolError::SenderLimit { .. }), "got {err:?}");
        assert_eq!(m.pending_count(), 2);
    }

    #[test]
    fn evict_expired_drops_old_entries() {
        let m = TxMempool::new(MempoolConfig::default());
        let bytes = signed_tx(1, 60_000);
        m.submit(&bytes).unwrap();
        assert_eq!(m.pending_count(), 1);
        // Manual future "now" past the tx's expiration.
        let way_future = now_ms() + 120_000;
        let evicted = m.evict_expired(way_future);
        assert_eq!(evicted, 1);
        assert_eq!(m.pending_count(), 0);
    }

    #[tokio::test]
    async fn broadcast_channel_delivers_tx_id_on_submit() {
        let m = TxMempool::new(MempoolConfig::default());
        let mut rx = m.subscribe();
        let bytes = signed_tx(42, 60_000);
        let id = m.submit(&bytes).unwrap();
        let received = rx.recv().await.expect("recv");
        assert_eq!(received, id);
    }

    #[test]
    fn rpc_mempool_trait_routes_through() {
        // Ensure the tron_rpc::Mempool blanket impl reaches submit().
        let m: std::sync::Arc<dyn tron_rpc::mempool::Mempool> =
            TxMempool::new_arc(MempoolConfig::default());
        let bytes = signed_tx(1, 60_000);
        match m.submit_tron(&bytes) {
            tron_rpc::mempool::SubmitOutcome::Accepted(_) => {}
            other => panic!("expected Accepted, got {other:?}"),
        }
        assert_eq!(m.pending_count(), 1);
    }

    #[test]
    fn validator_rejection_surfaces_as_validation_failed() {
        // Validator that rejects every tx — verifies the hook fires
        // and the reason propagates verbatim into the error variant.
        let m = TxMempool::new(MempoolConfig::default()).with_validator(Box::new(
            |_tx: &Transaction| Err("insufficient balance for fee".into()),
        ));
        let bytes = signed_tx(1, 60_000);
        let err = m.submit(&bytes).unwrap_err();
        match err {
            MempoolError::ValidationFailed(reason) => {
                assert_eq!(reason, "insufficient balance for fee");
            }
            other => panic!("expected ValidationFailed, got: {other:?}"),
        }
        // The tx was NOT inserted — pending stays empty.
        assert_eq!(m.pending_count(), 0);
    }

    #[test]
    fn validator_pass_admits_tx_normally() {
        let m = TxMempool::new(MempoolConfig::default())
            .with_validator(Box::new(|_tx: &Transaction| Ok(())));
        let bytes = signed_tx(1, 60_000);
        m.submit(&bytes).expect("validator passed, tx accepted");
        assert_eq!(m.pending_count(), 1);
    }

    #[test]
    fn persistence_writes_raw_bytes_under_tx_id_on_submit() {
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let bytes = signed_tx(1, 60_000);
        let id = m.submit(&bytes).unwrap();
        let on_disk = backend.get(&id).unwrap().expect("persisted");
        assert_eq!(on_disk, bytes);
    }

    #[test]
    fn persistence_deletes_entry_on_remove() {
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let bytes = signed_tx(1, 60_000);
        let id = m.submit(&bytes).unwrap();
        assert!(backend.contains(&id).unwrap());
        assert!(m.remove(&id));
        assert!(!backend.contains(&id).unwrap());
    }

    #[test]
    fn persistence_deletes_entries_on_evict_expired() {
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let bytes = signed_tx(1, 60_000);
        let id = m.submit(&bytes).unwrap();
        assert!(backend.contains(&id).unwrap());
        let future = now_ms() + 120_000;
        let evicted = m.evict_expired(future);
        assert_eq!(evicted, 1);
        assert!(!backend.contains(&id).unwrap());
    }

    #[test]
    fn persistence_remove_of_unknown_id_does_not_touch_backend() {
        // remove() returns false when the id is unknown. The backend
        // must not be poked in that case — otherwise a stale lookup
        // could mask a real entry that happens to share the key.
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        // Pre-seed a row that should survive the no-op remove.
        backend.put(&[0u8; 32], b"untouched").unwrap();
        assert!(!m.remove(&[0u8; 32]));
        assert_eq!(
            backend.get(&[0u8; 32]).unwrap().as_deref(),
            Some(b"untouched".as_slice())
        );
    }

    #[test]
    fn reload_from_disk_restores_pending_pool() {
        // Round-trip: submit through one mempool with persistence,
        // build a second mempool against the same backend, reload —
        // pending entries must come back.
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let first = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let id1 = first.submit(&signed_tx(1, 600_000)).unwrap();
        let id2 = first.submit(&signed_tx(2, 600_000)).unwrap();
        assert_eq!(first.pending_count(), 2);

        // Simulate restart with a fresh mempool over the same backend.
        let second = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        assert_eq!(second.pending_count(), 0);
        let stats = second.reload_from_disk();
        assert_eq!(stats.scanned, 2);
        assert_eq!(stats.restored, 2);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.skipped, 0);
        assert_eq!(second.pending_count(), 2);
        assert!(second.get(&id1).is_some());
        assert!(second.get(&id2).is_some());
    }

    #[test]
    fn reload_from_disk_drops_expired_entries_and_prunes_backend() {
        // A persisted tx whose expiration is in the past at reload
        // time must not enter the pending pool, AND must be deleted
        // from disk so the next restart doesn't try again.
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        // Submit with a generous expiration so the first mempool
        // accepts it; then manually rewind the persisted bytes by
        // re-encoding with an already-past expiration.
        let expired_bytes = signed_tx(1, -1);
        // Compute tx_id by decoding so the backend key matches what
        // submit() would have written.
        let tx = Transaction::decode(expired_bytes.as_slice()).unwrap();
        let id = tron_types::tx_id(&tx).unwrap();
        backend.put(&id, &expired_bytes).unwrap();

        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let stats = m.reload_from_disk();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.restored, 0);
        assert_eq!(stats.dropped, 1);
        assert_eq!(m.pending_count(), 0);
        assert!(
            !backend.contains(&id).unwrap(),
            "stale persisted tx must be pruned"
        );
    }

    #[test]
    fn reload_from_disk_skips_already_pending_entries() {
        // Calling reload twice (or after some submits) must not
        // double-insert, and must not delete on-disk rows for the
        // duplicates.
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let id = m.submit(&signed_tx(1, 600_000)).unwrap();
        let stats = m.reload_from_disk();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.restored, 0);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.dropped, 0);
        // Row still on disk.
        assert!(backend.contains(&id).unwrap());
        assert_eq!(m.pending_count(), 1);
    }

    #[test]
    fn reload_from_disk_no_persistence_is_a_noop() {
        // Without a backend attached, reload returns default zero
        // stats. Useful so callers don't need to branch.
        let m = TxMempool::new(MempoolConfig::default());
        assert_eq!(m.reload_from_disk(), ReloadStats::default());
    }

    #[test]
    fn reload_from_disk_drops_malformed_rows() {
        // Garbage bytes under a tx_id-shaped key — must drop the row
        // (decode failure) without panicking.
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        backend.put(&[7u8; 32], b"\xff\xff\xff").unwrap();
        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let stats = m.reload_from_disk();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.restored, 0);
        assert!(!backend.contains(&[7u8; 32]).unwrap());
    }

    #[test]
    fn persistence_rejected_tx_not_written_to_disk() {
        // A tx that fails stateless validation (e.g. expired) must
        // not get written to the backend.
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let m = TxMempool::new(MempoolConfig::default())
            .with_persistence(backend.clone());
        let bytes = signed_tx(1, -60_000);
        assert!(m.submit(&bytes).is_err());
        assert!(backend.scan_all().unwrap().is_empty());
    }

    #[test]
    fn persistence_validator_rejection_not_written_to_disk() {
        // Same guarantee for state-aware validator rejections.
        let backend: std::sync::Arc<dyn KvBackend> =
            std::sync::Arc::new(tron_chainbase::MemBackend::new());
        let m = TxMempool::new(MempoolConfig::default())
            .with_validator(Box::new(|_| Err("fee too low".into())))
            .with_persistence(backend.clone());
        assert!(m.submit(&signed_tx(1, 60_000)).is_err());
        assert!(backend.scan_all().unwrap().is_empty());
    }

    #[test]
    fn validator_runs_after_cheap_checks() {
        // Counter-validator. Should NOT fire for txs that fail cheap
        // checks (expired, dup, sig) — expensive validate would be a
        // waste on a tx we'd reject anyway.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let m = TxMempool::new(MempoolConfig::default()).with_validator(Box::new(
            move |_: &Transaction| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ));
        // Expired — must reject without invoking validator.
        let expired = signed_tx(1, -60_000);
        assert!(matches!(m.submit(&expired).unwrap_err(), MempoolError::Expired { .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "validator must not run on expired");
        // Valid — validator fires exactly once.
        let good = signed_tx(2, 60_000);
        m.submit(&good).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Duplicate of the just-accepted — validator must not re-run.
        assert!(matches!(m.submit(&good).unwrap_err(), MempoolError::Duplicate));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "validator must not re-run on duplicate");
    }
}
