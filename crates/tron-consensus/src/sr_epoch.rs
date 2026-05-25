//! Cross-rotation SR snapshot shared between the maintenance hook and
//! the PBFT runtime.
//!
//! ## Why a shared in-memory snapshot
//!
//! The `WitnessScheduleStore` on disk holds **one** active list at a
//! time — the post-maintenance set. Java-tron does the same thing for
//! persistent state (see `MaintenanceManager.applyBlock` —
//! `consensusDelegate.getActiveWitnesses()` is the only persisted
//! list). But the PBFT layer needs a brief window where votes signed
//! by the **pre-rotation** SR set are still acceptable: a Prepare
//! cast just before the maintenance block fires can arrive at this
//! node just after we've rotated.
//!
//! `SrEpochSnapshot` is the in-memory cache that records `before`
//! (pre-rotation active list) and `before_maintenance_time_ms` so the
//! PBFT runtime can validate cross-rotation messages exactly the way
//! java-tron does in [`PbftManager.verifyMsg`]:
//!
//! ```text
//! if msg.epoch > before_maintenance_time_ms { use current }
//! else                                       { use before }
//! ```
//!
//! ## Lifecycle
//!
//! 1. Node startup: `current = WitnessScheduleStore::load_active()`,
//!    `before = []`, `before_maintenance_time_ms = 0`. Late votes for
//!    epochs that ended before our boot are rejected (matches java-tron
//!    after a restart — there's no persistent before-snapshot).
//! 2. Each block: the executor checks `is_maintenance_boundary`. If
//!    true and `block_num != 1`, it calls `rotate()` with the
//!    just-computed `prev_active` / `new_active` and the
//!    next-maintenance-time-pre-rotation value.
//! 3. PBFT runtime: every inbound vote calls
//!    [`SrEpochSnapshot::active_set_for_epoch`] to decide which list
//!    to validate against.
//!
//! [`PbftManager.verifyMsg`]: in `actuator/.../pbft/PbftManager.java`
//! line ~104.

use std::sync::{Arc, RwLock};

use tron_crypto::address::Address;

/// In-memory cache of the two most recent SR active lists.
#[derive(Debug, Clone, Default)]
pub struct SrEpochSnapshot {
    /// Post-maintenance active SR list. Synchronised with
    /// `WitnessScheduleStore::load_active()` after every rotation.
    pub current: Vec<Address>,
    /// Pre-rotation active SR list. Empty at node boot (no prior
    /// rotation observed in-memory).
    pub before: Vec<Address>,
    /// The `NEXT_MAINTENANCE_TIME` value at the moment the `before`
    /// snapshot was taken. PBFT messages whose `epoch` is **greater
    /// than** this value are validated against `current`; messages
    /// with `epoch <= before_maintenance_time_ms` are validated
    /// against `before`. Mirrors java-tron's
    /// `MaintenanceManager.beforeMaintenanceTime`.
    pub before_maintenance_time_ms: i64,
}

impl SrEpochSnapshot {
    /// Fresh snapshot from a single `current` list (no prior rotation).
    pub fn from_current(current: Vec<Address>) -> Self {
        Self {
            current,
            before: Vec::new(),
            before_maintenance_time_ms: 0,
        }
    }

    /// Choose the witness list a PBFT message at `epoch` should be
    /// validated against.
    ///
    /// `epoch > before_maintenance_time_ms` → `current`. Otherwise →
    /// `before`. Matches java-tron's `PbftManager.verifyMsg`.
    pub fn active_set_for_epoch(&self, epoch: i64) -> &[Address] {
        if epoch > self.before_maintenance_time_ms {
            &self.current
        } else {
            &self.before
        }
    }

    /// Apply a rotation: the just-rolled-over SR list becomes
    /// `before`, the freshly-active list becomes `current`, and the
    /// `next_maintenance_time` value AT the moment of rotation
    /// becomes `before_maintenance_time_ms`. Idempotent in the sense
    /// that calling with the same `(prev, new, time)` twice is a
    /// no-op when state hasn't changed.
    pub fn rotate(
        &mut self,
        prev_active: Vec<Address>,
        new_active: Vec<Address>,
        before_maintenance_time_ms: i64,
    ) {
        self.before = prev_active;
        self.current = new_active;
        self.before_maintenance_time_ms = before_maintenance_time_ms;
    }
}

/// Cheap-to-clone handle for sharing one [`SrEpochSnapshot`] across
/// the executor + the PBFT runtime + tests.
pub type SharedSrEpochSnapshot = Arc<RwLock<SrEpochSnapshot>>;

/// Construct a new shared snapshot.
pub fn shared_from_current(current: Vec<Address>) -> SharedSrEpochSnapshot {
    Arc::new(RwLock::new(SrEpochSnapshot::from_current(current)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        let mut raw = [0u8; 21];
        raw[0] = 0x41;
        raw[1..].fill(b);
        Address::from_raw(raw)
    }

    #[test]
    fn fresh_snapshot_routes_all_epochs_to_current() {
        let snap = SrEpochSnapshot::from_current(vec![addr(0x11), addr(0x22)]);
        // Every epoch > 0 → current. Epoch == 0 → before (empty).
        assert_eq!(snap.active_set_for_epoch(1).len(), 2);
        assert_eq!(snap.active_set_for_epoch(1_000_000_000_000).len(), 2);
        assert_eq!(snap.active_set_for_epoch(0).len(), 0);
    }

    #[test]
    fn rotate_swaps_lists_and_records_boundary_time() {
        let mut snap = SrEpochSnapshot::from_current(vec![addr(0x11)]);
        snap.rotate(
            vec![addr(0x11)],
            vec![addr(0x22), addr(0x33)],
            1_700_000_000_000,
        );
        assert_eq!(snap.before, vec![addr(0x11)]);
        assert_eq!(snap.current, vec![addr(0x22), addr(0x33)]);
        assert_eq!(snap.before_maintenance_time_ms, 1_700_000_000_000);
    }

    #[test]
    fn epoch_at_boundary_routes_to_before() {
        // Per java-tron: `epoch > beforeMaintenanceTime` ⇒ current.
        // So epoch == before_maintenance_time → before (the just-ended
        // epoch). epoch == before_maintenance_time + 1 → current.
        let mut snap = SrEpochSnapshot::default();
        snap.rotate(vec![addr(0x11)], vec![addr(0x22)], 100);
        assert_eq!(snap.active_set_for_epoch(100), &[addr(0x11)][..]);
        assert_eq!(snap.active_set_for_epoch(101), &[addr(0x22)][..]);
        assert_eq!(snap.active_set_for_epoch(99), &[addr(0x11)][..]);
    }

    #[test]
    fn shared_snapshot_is_cheap_to_clone_and_share() {
        let s1 = shared_from_current(vec![addr(0x11)]);
        let s2 = Arc::clone(&s1);
        s2.write().unwrap().rotate(
            vec![addr(0x11)],
            vec![addr(0x22)],
            500,
        );
        // Reader on the original handle sees the write.
        let snap = s1.read().unwrap();
        assert_eq!(snap.before, vec![addr(0x11)]);
        assert_eq!(snap.current, vec![addr(0x22)]);
        assert_eq!(snap.before_maintenance_time_ms, 500);
    }
}
