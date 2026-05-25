//! `KhaosDatabase` — in-memory fork-tree of recent blocks.
//!
//! Port of `org.tron.core.db.KhaosDatabase` from java-tron. Used by the
//! sync driver and the SR runtime to:
//!
//! * **Deduplicate** received blocks (`contain_block`).
//! * **Buffer orphans** whose parent we haven't seen yet
//!   (`mini_unlinked_store`).
//! * **Detect competing forks** and find the most-recent common
//!   ancestor (`get_branch`) — the prerequisite for any state-rollback
//!   reorg.
//! * **Track the canonical head** as the highest-num block in the
//!   linked store; switch heads when a longer fork lands.
//!
//! # Storage layout
//!
//! Two [`KhaosStore`]s sit side by side:
//!
//! * `mini_store` — blocks whose parent chain is known (linked back to
//!   the head we started with).
//! * `mini_unlinked_store` — orphans whose parent isn't in either
//!   store yet. When the parent later arrives via `push`, we do NOT
//!   automatically promote — java-tron leaves orphan promotion to the
//!   caller, which retries `push` with the now-known parent. We mirror
//!   that.
//!
//! Each store keeps two indexes:
//! * `by_hash` — `BlockId → Arc<KhaosBlock>` for O(1) lookup.
//! * `by_num` — `block_num → Vec<Arc<KhaosBlock>>` for fork
//!   enumeration at a given height.
//!
//! When a block is older than `head.num - max_capacity` (default
//! 1024), both indexes drop it. Children keep a `Weak<KhaosBlock>` to
//! their parent so the pruned block falls out for real — `parent()`
//! returns `None` once pruned. **Walking the chain backwards stops at
//! pruning depth**; callers handling deep reorgs must consult the
//! BlockStore for older ancestors.
//!
//! # Concurrency
//!
//! Java-tron synchronizes every method on the store. We mirror that
//! coarse-grained locking: each [`KhaosStore`] is wrapped in a
//! [`Mutex`] when used through [`KhaosDb`]. The data structure isn't
//! contention-sensitive (push is the only write path; reads are
//! infrequent), so finer-grained locking would buy nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};

use tron_proto::Block;
use tron_types::{block_id_from_block, BlockId};

/// One node in the fork tree.
///
/// `parent` is a [`Weak`] reference — when the parent block is pruned
/// from the store its `Arc` drops, and `parent()` on every child
/// returns `None`. This matches java-tron's `WeakReference<KhaosBlock>`.
pub struct KhaosBlock {
    pub block: Block,
    pub id: BlockId,
    pub num: i64,
    parent: Mutex<Weak<KhaosBlock>>,
}

impl KhaosBlock {
    /// Build a node from a raw [`Block`]. Caller must guarantee the
    /// block has a populated `block_header.raw_data` — otherwise this
    /// returns `None`.
    pub fn new(block: Block) -> Option<Arc<Self>> {
        let id = block_id_from_block(&block).ok()?;
        let num = id.num() as i64;
        Some(Arc::new(Self {
            block,
            id,
            num,
            parent: Mutex::new(Weak::new()),
        }))
    }

    /// The 32-byte parent-hash field from the wire format. Empty when
    /// genesis; otherwise a `BlockId` constructable from the bytes.
    ///
    /// java-tron stores `BlockId` as `[num_be(8) || hash(24)]` and uses
    /// that exact layout on the wire for `parent_hash`, so we can wrap
    /// the bytes directly without re-deriving the num.
    pub fn parent_id(&self) -> Option<BlockId> {
        let raw = self.block.block_header.as_ref()?.raw_data.as_ref()?;
        if raw.parent_hash.len() != 32 {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&raw.parent_hash);
        Some(BlockId::from_raw(buf))
    }

    /// Strong-upgrade the parent pointer. `None` if the parent was
    /// pruned (or was never set — e.g. genesis).
    pub fn parent(&self) -> Option<Arc<KhaosBlock>> {
        self.parent.lock().ok()?.upgrade()
    }

    fn set_parent(&self, p: &Arc<KhaosBlock>) {
        if let Ok(mut slot) = self.parent.lock() {
            *slot = Arc::downgrade(p);
        }
    }
}

impl std::fmt::Debug for KhaosBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KhaosBlock")
            .field("id", &self.id)
            .field("num", &self.num)
            .field(
                "parent_present",
                &self.parent.lock().map(|p| p.upgrade().is_some()).unwrap_or(false),
            )
            .finish()
    }
}

/// Errors from [`KhaosDb::push`].
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// The block has a non-zero parent hash but the parent isn't in the
    /// linked store. The block has been stashed in
    /// `mini_unlinked_store`. Caller should request the parent and
    /// retry.
    #[error("block parent not in linked store; stashed as orphan")]
    Unlinked,
    /// The block's `num` doesn't equal `parent.num + 1`. The block is
    /// rejected outright — this is malformed beyond a normal fork.
    #[error("bad block number: parent at {parent_num}, block at {block_num}")]
    BadNumber { parent_num: i64, block_num: i64 },
    /// `block_header.raw_data` is missing or malformed. Rejected.
    #[error("malformed block header")]
    Malformed,
}

/// In-memory fork-tree.
///
/// Construct with [`KhaosDb::new`] (no head) and seed via [`start`]
/// when the persistent head is known; thereafter feed every received
/// block through [`push`].
///
/// [`start`]: KhaosDb::start
/// [`push`]: KhaosDb::push
pub struct KhaosDb {
    inner: Mutex<Inner>,
}

struct Inner {
    head: Option<Arc<KhaosBlock>>,
    mini_store: KhaosStore,
    mini_unlinked_store: KhaosStore,
    max_capacity: usize,
}

impl KhaosDb {
    /// Empty store with the default capacity (1024 blocks per store).
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                head: None,
                mini_store: KhaosStore::default(),
                mini_unlinked_store: KhaosStore::default(),
                max_capacity: 1024,
            }),
        }
    }

    /// Set the per-store eviction cap. Blocks older than
    /// `head.num - max_capacity` are pruned on the next insert.
    pub fn set_max_size(&self, max_size: usize) {
        let mut g = self.inner.lock().unwrap();
        g.max_capacity = max_size;
    }

    /// Seed the head from a persisted block (called once at startup,
    /// after replaying from disk). java-tron equivalent:
    /// `KhaosDatabase.start(BlockCapsule)`.
    pub fn start(&self, block: Block) -> Result<(), PushError> {
        let kblock = KhaosBlock::new(block).ok_or(PushError::Malformed)?;
        let mut g = self.inner.lock().unwrap();
        g.mini_store.insert(&kblock);
        g.head = Some(kblock);
        Ok(())
    }

    /// True if the block is in either store.
    pub fn contains(&self, id: &BlockId) -> bool {
        let g = self.inner.lock().unwrap();
        g.mini_store.by_hash.contains_key(id) || g.mini_unlinked_store.by_hash.contains_key(id)
    }

    /// True if the block is in the linked (canonical-fork-tree) store.
    /// Stronger guarantee than `contains` — used to skip blocks we've
    /// already integrated into the fork tree.
    pub fn contains_in_linked(&self, id: &BlockId) -> bool {
        let g = self.inner.lock().unwrap();
        g.mini_store.by_hash.contains_key(id)
    }

    /// Look up a block by hash in either store.
    pub fn get(&self, id: &BlockId) -> Option<Arc<KhaosBlock>> {
        let g = self.inner.lock().unwrap();
        g.mini_store
            .by_hash
            .get(id)
            .or_else(|| g.mini_unlinked_store.by_hash.get(id))
            .cloned()
    }

    /// Snapshot of the current head. `None` until [`start`] has been
    /// called.
    ///
    /// [`start`]: KhaosDb::start
    pub fn head(&self) -> Option<Arc<KhaosBlock>> {
        self.inner.lock().unwrap().head.clone()
    }

    /// Push a block into the fork tree. Returns the new head after
    /// insertion — which may be the same as before (extension on a
    /// non-best fork) or change (extension on the longest fork).
    pub fn push(&self, block: Block) -> Result<Arc<KhaosBlock>, PushError> {
        let kblock = KhaosBlock::new(block).ok_or(PushError::Malformed)?;
        let mut g = self.inner.lock().unwrap();

        // If we already know about this block, return the current head
        // unchanged — `containBlock` dedup matches java-tron behavior.
        if g.mini_store.by_hash.contains_key(&kblock.id)
            || g.mini_unlinked_store.by_hash.contains_key(&kblock.id)
        {
            return Ok(g.head.clone().unwrap_or_else(|| kblock.clone()));
        }

        // If we have a head, validate the parent linkage. Genesis-like
        // pushes (parent_hash all zero) skip this check, matching the
        // `block.parent_hash != ZERO_HASH` short-circuit in java-tron.
        let parent_id_opt = kblock.parent_id();
        let has_nonzero_parent = parent_id_opt
            .as_ref()
            .is_some_and(|pid| pid.as_bytes() != &[0u8; 32]);

        if g.head.is_some() && has_nonzero_parent {
            let parent_id = parent_id_opt.unwrap();
            if let Some(parent) = g.mini_store.by_hash.get(&parent_id).cloned() {
                if kblock.num != parent.num + 1 {
                    return Err(PushError::BadNumber {
                        parent_num: parent.num,
                        block_num: kblock.num,
                    });
                }
                kblock.set_parent(&parent);
            } else {
                g.mini_unlinked_store.insert(&kblock);
                // Run pruning even on the orphan path so the orphan
                // store can't grow unbounded.
                let head_num = g.head.as_ref().map(|h| h.num).unwrap_or(0);
                let cap = g.max_capacity;
                g.mini_unlinked_store.prune_below(head_num.saturating_sub(cap as i64));
                return Err(PushError::Unlinked);
            }
        }

        g.mini_store.insert(&kblock);

        // Promote head if this block extends the longest fork. Java
        // uses a strict `>` here: ties don't change the head, which
        // means the first-arriving block at a given height wins. We
        // mirror that.
        let promote = match &g.head {
            None => true,
            Some(h) => kblock.num > h.num,
        };
        if promote {
            g.head = Some(kblock.clone());
        }

        // LRU prune both stores against the new head's number.
        let head_num = g.head.as_ref().map(|h| h.num).unwrap_or(0);
        let cap = g.max_capacity;
        let threshold = head_num.saturating_sub(cap as i64);
        g.mini_store.prune_below(threshold);
        g.mini_unlinked_store.prune_below(threshold);

        Ok(g.head.clone().unwrap())
    }

    /// Pop the current head: head = head.parent. Returns `true` if the
    /// head moved; `false` if head is unset or has no parent (genesis,
    /// or parent was pruned).
    pub fn pop(&self) -> bool {
        let mut g = self.inner.lock().unwrap();
        let Some(h) = g.head.clone() else { return false };
        let Some(p) = h.parent() else { return false };
        g.head = Some(p);
        true
    }

    /// Force the head to a specific block. Used by the reorg
    /// recovery path when a fork-switch fails mid-apply.
    pub fn set_head(&self, block: Arc<KhaosBlock>) {
        let mut g = self.inner.lock().unwrap();
        g.head = Some(block);
    }

    /// Remove a block from either store (linked first, then orphan).
    /// Also re-elects the head as the highest-num block remaining in
    /// the linked store. Returns `true` if a block was removed.
    pub fn remove(&self, id: &BlockId) -> bool {
        let mut g = self.inner.lock().unwrap();
        let removed = g.mini_store.remove(id) || g.mini_unlinked_store.remove(id);
        if removed {
            // Re-elect head from highest-num remaining linked block.
            g.head = g
                .mini_store
                .by_num
                .iter()
                .max_by_key(|(n, _)| *n)
                .and_then(|(_, list)| list.first().cloned());
        }
        removed
    }

    /// Find the most-recent common ancestor of `id1` and `id2` and
    /// return the two paths from each input back to (but not
    /// including) that ancestor.
    ///
    /// java-tron equivalent: `getBranch(Sha256Hash, Sha256Hash)`.
    ///
    /// The first list is the path from `id1` walking parent-ward; the
    /// second is the path from `id2`. Both lists are in
    /// child-to-parent order, so the head of each list is the input
    /// block and the tail is the block whose parent IS the common
    /// ancestor. The common ancestor itself is NOT included.
    ///
    /// Used by the reorg path:
    /// * `branch.0` — blocks on the *current* head's chain that must
    ///   be rolled back.
    /// * `branch.1` — blocks on the *new* head's chain that must be
    ///   applied, in **reverse order** (oldest first).
    pub fn get_branch(
        &self,
        id1: &BlockId,
        id2: &BlockId,
    ) -> Result<(VecDeque<Arc<KhaosBlock>>, VecDeque<Arc<KhaosBlock>>), NonCommonBlockError> {
        let g = self.inner.lock().unwrap();
        let mut list1 = VecDeque::new();
        let mut list2 = VecDeque::new();

        let mut b1 = g.mini_store.by_hash.get(id1).cloned().ok_or(NonCommonBlockError)?;
        let mut b2 = g.mini_store.by_hash.get(id2).cloned().ok_or(NonCommonBlockError)?;

        // Equalize block numbers — drag the higher one down.
        while b1.num > b2.num {
            list1.push_back(b1.clone());
            b1 = b1.parent().ok_or(NonCommonBlockError)?;
            // Defensive lookup mirroring java-tron (a parent that
            // hasn't been pruned must also still be in the map).
            if !g.mini_store.by_hash.contains_key(&b1.id) {
                return Err(NonCommonBlockError);
            }
        }
        while b2.num > b1.num {
            list2.push_back(b2.clone());
            b2 = b2.parent().ok_or(NonCommonBlockError)?;
            if !g.mini_store.by_hash.contains_key(&b2.id) {
                return Err(NonCommonBlockError);
            }
        }

        // Walk together until ids match.
        while b1.id != b2.id {
            list1.push_back(b1.clone());
            list2.push_back(b2.clone());
            b1 = b1.parent().ok_or(NonCommonBlockError)?;
            b2 = b2.parent().ok_or(NonCommonBlockError)?;
            if !g.mini_store.by_hash.contains_key(&b1.id)
                || !g.mini_store.by_hash.contains_key(&b2.id)
            {
                return Err(NonCommonBlockError);
            }
        }
        Ok((list1, list2))
    }

    /// Number of blocks in the linked store. Useful for tests + the
    /// `dump-state` snapshot.
    pub fn linked_size(&self) -> usize {
        self.inner.lock().unwrap().mini_store.by_hash.len()
    }

    /// Number of orphans (unlinked blocks) currently buffered.
    pub fn unlinked_size(&self) -> usize {
        self.inner.lock().unwrap().mini_unlinked_store.by_hash.len()
    }
}

impl Default for KhaosDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Returned by [`KhaosDb::get_branch`] when the two inputs share no
/// reachable common ancestor in the linked store. Mirrors java-tron's
/// `NonCommonBlockException` — typically means the fork diverged
/// deeper than `max_capacity` blocks ago.
#[derive(Debug, thiserror::Error)]
#[error("no common ancestor in linked store (fork deeper than max_capacity, or one input absent)")]
pub struct NonCommonBlockError;

/// One of the two internal stores. Java-tron's `KhaosStore` inner
/// class.
#[derive(Default)]
struct KhaosStore {
    by_hash: HashMap<BlockId, Arc<KhaosBlock>>,
    by_num: HashMap<i64, Vec<Arc<KhaosBlock>>>,
}

impl KhaosStore {
    fn insert(&mut self, block: &Arc<KhaosBlock>) {
        self.by_hash.insert(block.id.clone(), block.clone());
        self.by_num
            .entry(block.num)
            .or_insert_with(Vec::new)
            .push(block.clone());
    }

    fn remove(&mut self, id: &BlockId) -> bool {
        let Some(block) = self.by_hash.remove(id) else {
            return false;
        };
        if let Some(list) = self.by_num.get_mut(&block.num) {
            list.retain(|b| b.id != block.id);
            if list.is_empty() {
                self.by_num.remove(&block.num);
            }
        }
        true
    }

    /// Drop every block with `num < threshold`. Called after each
    /// insert with `threshold = head.num - max_capacity`.
    fn prune_below(&mut self, threshold: i64) {
        if threshold <= 0 {
            return;
        }
        let to_remove: Vec<i64> = self
            .by_num
            .keys()
            .filter(|n| **n < threshold)
            .copied()
            .collect();
        for n in to_remove {
            if let Some(list) = self.by_num.remove(&n) {
                for b in list {
                    self.by_hash.remove(&b.id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_proto::{block_header::Raw as BlockHeaderRaw, Block, BlockHeader};

    /// Build a block with a given `(num, parent_hash, witness_tag)` so
    /// tests can construct sibling forks without colliding on the
    /// block hash (witness_tag perturbs the header so `block_id`
    /// differs even at the same num+parent).
    fn mk_block(num: i64, parent_hash: [u8; 32], witness_tag: u8) -> Block {
        Block {
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: num,
                    parent_hash: parent_hash.to_vec(),
                    timestamp: 1_700_000_000_000 + num,
                    witness_address: {
                        let mut a = vec![0x41u8; 21];
                        a[20] = witness_tag;
                        a
                    },
                    ..Default::default()
                }),
                ..Default::default()
            }),
            transactions: Vec::new(),
        }
    }

    fn id_of(b: &Block) -> BlockId {
        block_id_from_block(b).unwrap()
    }

    #[test]
    fn empty_db_has_no_head() {
        let db = KhaosDb::new();
        assert!(db.head().is_none());
        assert_eq!(db.linked_size(), 0);
        assert_eq!(db.unlinked_size(), 0);
    }

    #[test]
    fn start_seeds_the_head() {
        let db = KhaosDb::new();
        let b = mk_block(100, [0u8; 32], 0);
        let id = id_of(&b);
        db.start(b).expect("start");
        let head = db.head().expect("head set");
        assert_eq!(head.id, id);
        assert_eq!(head.num, 100);
        assert_eq!(db.linked_size(), 1);
    }

    #[test]
    fn push_extends_head_when_parent_matches() {
        let db = KhaosDb::new();
        let b1 = mk_block(1, [0u8; 32], 0);
        let id1 = id_of(&b1);
        db.start(b1).unwrap();

        let mut parent_bytes = [0u8; 32];
        parent_bytes.copy_from_slice(&id1.as_bytes()[..]);
        let b2 = mk_block(2, parent_bytes, 0);
        let id2 = id_of(&b2);
        let head = db.push(b2).unwrap();
        assert_eq!(head.id, id2);
        assert_eq!(db.linked_size(), 2);

        // Walking back from the new head must find the genesis as
        // parent — verifies the weak-ref linkage.
        let parent = head.parent().expect("parent set");
        assert_eq!(parent.id, id1);
    }

    #[test]
    fn push_with_unknown_parent_is_stashed_as_orphan() {
        let db = KhaosDb::new();
        let b1 = mk_block(1, [0u8; 32], 0);
        db.start(b1).unwrap();

        let stranger_parent = [0x99u8; 32];
        let b3 = mk_block(3, stranger_parent, 0);
        let err = db.push(b3).unwrap_err();
        assert!(matches!(err, PushError::Unlinked));
        assert_eq!(db.linked_size(), 1);
        assert_eq!(db.unlinked_size(), 1);
    }

    #[test]
    fn push_with_wrong_num_is_rejected() {
        let db = KhaosDb::new();
        let b1 = mk_block(1, [0u8; 32], 0);
        let id1 = id_of(&b1);
        db.start(b1).unwrap();

        let mut parent_bytes = [0u8; 32];
        parent_bytes.copy_from_slice(&id1.as_bytes()[..]);
        // Block claims num=5 but parent is num=1 → BadNumber.
        let b5 = mk_block(5, parent_bytes, 0);
        let err = db.push(b5).unwrap_err();
        assert!(matches!(err, PushError::BadNumber { parent_num: 1, block_num: 5 }));
    }

    #[test]
    fn push_dedups_already_seen_blocks() {
        let db = KhaosDb::new();
        let b1 = mk_block(1, [0u8; 32], 0);
        db.start(b1.clone()).unwrap();
        // Re-pushing genesis must NOT throw — java-tron's containBlock
        // dedup short-circuits cleanly.
        let head = db.push(b1).unwrap();
        assert_eq!(head.num, 1);
        assert_eq!(db.linked_size(), 1);
    }

    #[test]
    fn competing_forks_keep_first_seen_head_on_ties() {
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_id_bytes = [0u8; 32];
        g_id_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();

        // Two siblings extending genesis with different witness tags.
        let a = mk_block(2, g_id_bytes, 1);
        let b = mk_block(2, g_id_bytes, 2);
        let id_a = id_of(&a);
        let _id_b = id_of(&b);
        db.push(a).unwrap();
        let head = db.push(b).unwrap();
        // Tie at num=2 → head stays at the first-seen (A).
        assert_eq!(head.id, id_a);
        // Both blocks are in the linked store.
        assert_eq!(db.linked_size(), 3);
    }

    #[test]
    fn longer_fork_takes_over_head() {
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_id_bytes = [0u8; 32];
        g_id_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();

        let a2 = mk_block(2, g_id_bytes, 1);
        let mut a2_bytes = [0u8; 32];
        a2_bytes.copy_from_slice(&id_of(&a2).as_bytes()[..]);
        db.push(a2).unwrap();

        // Sibling at num=2 doesn't promote ...
        let b2 = mk_block(2, g_id_bytes, 2);
        let mut b2_bytes = [0u8; 32];
        b2_bytes.copy_from_slice(&id_of(&b2).as_bytes()[..]);
        db.push(b2).unwrap();

        // ... but a child of b2 at num=3 does (longer fork wins).
        let b3 = mk_block(3, b2_bytes, 2);
        let id_b3 = id_of(&b3);
        let head = db.push(b3).unwrap();
        assert_eq!(head.id, id_b3, "longer fork (b-chain) becomes head");
    }

    #[test]
    fn get_branch_finds_common_ancestor() {
        // Build:        g(1) → a2 → a3
        //                    ↘ b2 → b3
        // get_branch(a3, b3) must return ([a3, a2], [b3, b2]) — both
        // lists in child-to-parent order, common ancestor = g.
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let g_id = id_of(&g);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&g_id.as_bytes()[..]);
        db.start(g).unwrap();

        let a2 = mk_block(2, g_bytes, 1);
        let a2_id = id_of(&a2);
        let mut a2_bytes = [0u8; 32];
        a2_bytes.copy_from_slice(&a2_id.as_bytes()[..]);
        db.push(a2).unwrap();
        let a3 = mk_block(3, a2_bytes, 1);
        let a3_id = id_of(&a3);
        db.push(a3).unwrap();

        let b2 = mk_block(2, g_bytes, 2);
        let b2_id = id_of(&b2);
        let mut b2_bytes = [0u8; 32];
        b2_bytes.copy_from_slice(&b2_id.as_bytes()[..]);
        db.push(b2).unwrap();
        let b3 = mk_block(3, b2_bytes, 2);
        let b3_id = id_of(&b3);
        db.push(b3).unwrap();

        let (path_a, path_b) = db.get_branch(&a3_id, &b3_id).unwrap();
        assert_eq!(path_a.len(), 2);
        assert_eq!(path_b.len(), 2);
        assert_eq!(path_a[0].id, a3_id);
        assert_eq!(path_a[1].id, a2_id);
        assert_eq!(path_b[0].id, b3_id);
        assert_eq!(path_b[1].id, b2_id);
        // Common ancestor (g) is NOT in either path — matches java
        // semantics.
        assert!(path_a.iter().all(|b| b.id != g_id));
        assert!(path_b.iter().all(|b| b.id != g_id));
    }

    #[test]
    fn get_branch_equal_heights_walks_lockstep() {
        // Same shape as before but call get_branch on equal-num inputs
        // directly — exercises the "while !=" loop without the
        // pre-equalization preamble.
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();
        let a = mk_block(2, g_bytes, 1);
        let b = mk_block(2, g_bytes, 2);
        let ida = id_of(&a);
        let idb = id_of(&b);
        db.push(a).unwrap();
        db.push(b).unwrap();
        let (la, lb) = db.get_branch(&ida, &idb).unwrap();
        assert_eq!(la.len(), 1);
        assert_eq!(lb.len(), 1);
        assert_eq!(la[0].id, ida);
        assert_eq!(lb[0].id, idb);
    }

    #[test]
    fn get_branch_same_input_returns_empty_lists() {
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let id = id_of(&g);
        db.start(g).unwrap();
        let (la, lb) = db.get_branch(&id, &id).unwrap();
        assert!(la.is_empty());
        assert!(lb.is_empty());
    }

    #[test]
    fn pop_walks_head_back_to_parent() {
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let g_id = id_of(&g);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&g_id.as_bytes()[..]);
        db.start(g).unwrap();
        let two = mk_block(2, g_bytes, 0);
        db.push(two).unwrap();
        assert_eq!(db.head().unwrap().num, 2);
        assert!(db.pop());
        assert_eq!(db.head().unwrap().id, g_id);
        // Genesis has no parent in the store → pop is a no-op.
        assert!(!db.pop());
    }

    #[test]
    fn remove_drops_block_and_reelects_head() {
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let g_id = id_of(&g);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&g_id.as_bytes()[..]);
        db.start(g).unwrap();
        let two = mk_block(2, g_bytes, 0);
        let two_id = id_of(&two);
        db.push(two).unwrap();
        assert_eq!(db.head().unwrap().num, 2);
        assert!(db.remove(&two_id));
        // Head was reelected to genesis (the only remaining block).
        assert_eq!(db.head().unwrap().id, g_id);
        assert_eq!(db.linked_size(), 1);
    }

    #[test]
    fn lru_pruning_drops_blocks_below_threshold() {
        let db = KhaosDb::new();
        db.set_max_size(5);
        // Build a single chain g(1) → 2 → 3 → ... → 20.
        let mut parent_bytes = [0u8; 32];
        let g = mk_block(1, parent_bytes, 0);
        parent_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();
        for n in 2..=20 {
            let b = mk_block(n, parent_bytes, 0);
            parent_bytes.copy_from_slice(&id_of(&b).as_bytes()[..]);
            db.push(b).unwrap();
        }
        assert_eq!(db.head().unwrap().num, 20);
        // head=20, max=5 → only blocks with num ≥ 15 should survive.
        // That's 6 blocks (15, 16, 17, 18, 19, 20).
        assert_eq!(
            db.linked_size(),
            6,
            "expected blocks 15..=20 to survive, got linked={}",
            db.linked_size()
        );
    }

    #[test]
    fn pruned_parent_appears_as_none_via_weak_ref() {
        let db = KhaosDb::new();
        db.set_max_size(2);
        let mut parent_bytes = [0u8; 32];
        let g = mk_block(1, parent_bytes, 0);
        parent_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();
        for n in 2..=5 {
            let b = mk_block(n, parent_bytes, 0);
            parent_bytes.copy_from_slice(&id_of(&b).as_bytes()[..]);
            db.push(b).unwrap();
        }
        // head=5, cap=2 → keep blocks 3, 4, 5. The 3's parent (2) is
        // pruned; 3.parent() must return None.
        let head = db.head().unwrap();
        assert_eq!(head.num, 5);
        let p4 = head.parent().expect("4 still linked");
        let p3 = p4.parent().expect("3 still linked");
        assert!(
            p3.parent().is_none(),
            "block 2 was pruned; block 3's weak parent ref must fail to upgrade"
        );
    }

    #[test]
    fn get_branch_errors_on_missing_input() {
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let g_id = id_of(&g);
        db.start(g).unwrap();
        let stranger = BlockId::from_hash_and_num(&[0xfeu8; 32], 5);
        assert!(matches!(
            db.get_branch(&g_id, &stranger),
            Err(NonCommonBlockError)
        ));
    }
}
