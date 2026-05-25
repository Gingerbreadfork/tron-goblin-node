//! Pluggable transaction mempool interface.
//!
//! `eth_sendRawTransaction` and `broadcastTransaction` accept incoming
//! transactions over JSON-RPC. The RPC crate doesn't own a P2P stack
//! or a full mempool implementation — that lives in `tron-net` /
//! `tron-executor`. We expose a trait so the application wiring layer
//! can plug in whichever backend it wants:
//!
//! * A real `tron-net`-backed mempool that broadcasts to peers.
//! * An in-process `InMemoryMempool` for tests and dev nodes.
//! * A `RejectingMempool` (the default when no implementation is
//!   attached) that returns `unsupported` to every submit.

use std::sync::{Arc, Mutex};

/// One pending transaction as surfaced through the trait. Carries
/// just enough for `txpool_content` / `txpool_inspect` to decode and
/// summarise (the protobuf bytes + the canonical `tx_id` +
/// arrival-order timestamp). Decoding stays on the RPC side so the
/// mempool trait can stay TRON-agnostic.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx_id: [u8; 32],
    pub raw_bytes: Vec<u8>,
    /// Wall-clock ms when the mempool first accepted this tx. Used
    /// by `txpool_inspect` to sort the per-sender lists oldest-first.
    pub received_at_ms: i64,
}

/// Outcome of a `submit` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Tx was accepted into the mempool and (if a broadcast backend is
    /// configured) queued for P2P propagation. Returns the canonical
    /// 32-byte transaction id.
    Accepted([u8; 32]),
    /// Rejected for a structural reason (decode failure, signature
    /// invalid, gas too low, etc.). The string is the reason wallets
    /// see in the JSON-RPC error message.
    Rejected(String),
    /// The node has no mempool/broadcast layer configured. Distinct
    /// from `Rejected` so wallets know to retry against a different
    /// node rather than re-encode the same transaction.
    Unsupported,
}

/// Trait every mempool backend implements.
pub trait Mempool: Send + Sync {
    /// Accept a raw transaction. The bytes are protocol-defined: for
    /// TRON, this is the `protobuf-encoded Transaction` (NOT
    /// RLP-encoded as on Ethereum). For Ethereum compatibility via
    /// `eth_sendRawTransaction`, callers should decode RLP first and
    /// re-encode into TRON form before invoking this.
    fn submit_tron(&self, raw: &[u8]) -> SubmitOutcome;

    /// Number of pending transactions awaiting block inclusion.
    fn pending_count(&self) -> usize {
        0
    }

    /// Snapshot every pending transaction. Used by the `txpool_*`
    /// JSON-RPC family (`status` / `content` / `inspect`) to expose
    /// the pool to clients. Default impl returns an empty list — a
    /// no-op for mempools that don't track per-tx state.
    fn pending_snapshot(&self) -> Vec<MempoolEntry> {
        Vec::new()
    }
}

/// Default in-memory implementation. Accepts the bytes, records them
/// in a `Vec`, returns the sha256 as the id. **No broadcast.** Useful
/// for tests and dev nodes; a production node should wire up a real
/// `tron-net` mempool instead.
#[derive(Default)]
pub struct InMemoryMempool {
    pending: Mutex<Vec<Vec<u8>>>,
}

impl InMemoryMempool {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Snapshot every pending transaction. Used by tests + by the
    /// future broadcast layer when it picks up tx to send to peers.
    pub fn drain(&self) -> Vec<Vec<u8>> {
        let mut p = self.pending.lock().unwrap();
        std::mem::take(&mut *p)
    }
}

impl Mempool for InMemoryMempool {
    fn submit_tron(&self, raw: &[u8]) -> SubmitOutcome {
        if raw.is_empty() {
            return SubmitOutcome::Rejected("empty payload".into());
        }
        let tx_id = tron_crypto::hash::sha256(raw);
        self.pending.lock().unwrap().push(raw.to_vec());
        SubmitOutcome::Accepted(tx_id)
    }

    fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    fn pending_snapshot(&self) -> Vec<MempoolEntry> {
        // No real timestamp tracking — synthesise a monotonic value
        // from insertion order so callers that sort by `received_at_ms`
        // get a stable ordering.
        let pending = self.pending.lock().unwrap();
        pending
            .iter()
            .enumerate()
            .map(|(idx, raw)| MempoolEntry {
                tx_id: tron_crypto::hash::sha256(raw),
                raw_bytes: raw.clone(),
                received_at_ms: idx as i64,
            })
            .collect()
    }
}
