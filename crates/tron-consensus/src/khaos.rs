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

/// Classification of a successful [`KhaosDb::push`] (H-1).
///
/// Every variant carries the resulting head, so a caller that only needs
/// "the head after this push" can use [`PushOutcome::into_head`]. The
/// `Reorg` variant additionally signals that the head jumped to a
/// *different* fork — the caller must roll back the old chain and re-apply
/// the new one (derive the exact branches via [`KhaosDb::get_branch`]).
#[derive(Debug, Clone)]
pub enum PushOutcome {
    /// The head advanced linearly: the new block (or a promoted-orphan
    /// chain it unblocked) extends the previous head.
    Extended { head: Arc<KhaosBlock> },
    /// The head moved to a different fork. `from` is the previous head,
    /// `to` the new one; their common ancestor + the rollback/reapply
    /// branches come from [`KhaosDb::get_branch`].
    Reorg {
        from: Arc<KhaosBlock>,
        to: Arc<KhaosBlock>,
    },
    /// The block was added to the tree but did NOT become the head — a
    /// side/sibling fork at lower-or-equal height. `head` is unchanged.
    Sibling { head: Arc<KhaosBlock> },
}

impl PushOutcome {
    /// The head after this push, regardless of variant.
    pub fn head(&self) -> &Arc<KhaosBlock> {
        match self {
            PushOutcome::Extended { head } | PushOutcome::Sibling { head } => head,
            PushOutcome::Reorg { to, .. } => to,
        }
    }

    /// Consume the outcome, returning the head after this push.
    pub fn into_head(self) -> Arc<KhaosBlock> {
        match self {
            PushOutcome::Extended { head } | PushOutcome::Sibling { head } => head,
            PushOutcome::Reorg { to, .. } => to,
        }
    }

    /// `true` if the head jumped to a different fork (rollback needed).
    pub fn is_reorg(&self) -> bool {
        matches!(self, PushOutcome::Reorg { .. })
    }
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
    /// Orphan index: maps a not-yet-seen parent id → the ids of unlinked
    /// blocks waiting on it. Popped by [`KhaosDb::take_orphans_waiting_on`]
    /// the moment that parent links, so the caller can re-accept each waiter
    /// through its FULL acceptance path (java-tron leaves orphan recovery to
    /// the caller; we do not link them silently in-tree).
    by_parent: HashMap<BlockId, Vec<BlockId>>,
    /// Original wire bytes for stashed orphans, keyed by block id and kept
    /// in lockstep with `mini_unlinked_store`, so a later re-acceptance can
    /// validate txTrieRoot and size bandwidth against the ORIGINAL encoding
    /// rather than a prost re-encode.
    orphan_raw: HashMap<BlockId, Vec<u8>>,
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
                by_parent: HashMap::new(),
                orphan_raw: HashMap::new(),
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

    /// Push a block into the fork tree. On success returns a
    /// [`PushOutcome`] classifying how the head changed: `Extended` on the
    /// best fork, `Reorg` when the head jumps to a different fork, or
    /// `Sibling` when the block is added but doesn't move the head. A block
    /// whose parent isn't linked yet is STASHED and `Err(Unlinked)` returned;
    /// it is NOT linked automatically when the parent later arrives
    /// (java-tron parity — `KhaosDatabase.push` has no orphan promotion).
    /// After a successful push the caller drains
    /// [`KhaosDb::take_orphans_waiting_on`] and re-feeds each returned block
    /// through its full acceptance path.
    pub fn push(&self, block: Block) -> Result<PushOutcome, PushError> {
        self.push_with_raw(block, None)
    }

    /// [`KhaosDb::push`], carrying the block's original wire bytes; they are
    /// retained ONLY if the block is stashed as an orphan (no copy on the
    /// common linked path) and handed back by
    /// [`KhaosDb::take_orphans_waiting_on`] for a byte-exact re-acceptance.
    pub fn push_with_raw(
        &self,
        block: Block,
        raw: Option<&[u8]>,
    ) -> Result<PushOutcome, PushError> {
        let kblock = KhaosBlock::new(block).ok_or(PushError::Malformed)?;
        let mut g = self.inner.lock().unwrap();

        // Dedup on the LINKED store only (java `containBlockInMiniStore`): a
        // block sitting in the ORPHAN store must stay re-pushable so a
        // re-delivery arriving after its parent has linked can still enter the
        // tree — a both-store check would swallow exactly that re-delivery as
        // a `Sibling` and strand the orphan forever.
        if g.mini_store.by_hash.contains_key(&kblock.id) {
            let head = g.head.clone().unwrap_or_else(|| kblock.clone());
            return Ok(PushOutcome::Sibling { head });
        }

        let prev_head = g.head.clone();

        // Validate parent linkage. Genesis-like pushes (parent_hash all
        // zero) skip this, matching java-tron's `parent_hash != ZERO_HASH`
        // short-circuit.
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
                // Orphan: stash it idempotently (a re-delivery while the
                // parent is still unknown must not duplicate the by_parent
                // entry) and remember which parent it waits on, retaining the
                // original wire bytes. When that parent links,
                // `take_orphans_waiting_on` hands this block back to the
                // caller, which re-accepts it through the FULL path
                // (validation + block_store persistence + fork-choice gate +
                // execution) — never linking it in-tree without persisting it.
                if !g.mini_unlinked_store.by_hash.contains_key(&kblock.id) {
                    g.mini_unlinked_store.insert(&kblock);
                    g.by_parent
                        .entry(parent_id)
                        .or_default()
                        .push(kblock.id.clone());
                }
                if let Some(raw) = raw {
                    g.orphan_raw.insert(kblock.id.clone(), raw.to_vec());
                }
                let head_num = g.head.as_ref().map(|h| h.num).unwrap_or(0);
                let cap = g.max_capacity;
                g.mini_unlinked_store
                    .prune_below(head_num.saturating_sub(cap as i64));
                prune_orphan_raw(&mut g);
                return Err(PushError::Unlinked);
            }
        }

        // Link it and advance the head if it tops the tree (strict `>`, so a
        // tie keeps the first-arrived head — java-tron parity). Orphans
        // waiting on it are NOT linked here: the caller re-feeds them via
        // `take_orphans_waiting_on` so every linked block first passes through
        // the acceptance path that persists it to block_store (the invariant
        // the solidified-containment gate's block_store walk relies on).
        g.mini_store.insert(&kblock);
        promote_head_if_higher(&mut g, &kblock);

        // Classify BEFORE pruning so the ancestor walk sees intact parents.
        let head = g.head.clone().unwrap();
        let outcome = classify_outcome(prev_head, head);

        // LRU prune both stores, then drop fully-evicted orphan-index keys.
        let head_num = g.head.as_ref().map(|h| h.num).unwrap_or(0);
        let cap = g.max_capacity;
        let threshold = head_num.saturating_sub(cap as i64);
        g.mini_store.prune_below(threshold);
        g.mini_unlinked_store.prune_below(threshold);
        let dead: Vec<BlockId> = g
            .by_parent
            .iter()
            .filter(|(_, kids)| {
                kids.iter()
                    .all(|c| !g.mini_unlinked_store.by_hash.contains_key(c))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            g.by_parent.remove(&k);
        }
        prune_orphan_raw(&mut g);

        Ok(outcome)
    }

    /// Pop every stashed orphan that was waiting on `parent`, each with the
    /// original wire bytes it arrived with. The caller re-feeds each returned
    /// block through its FULL acceptance path — validation, block_store
    /// persistence, the fork-choice gate, execution — exactly as if the
    /// network had re-delivered it after its parent landed (java-tron's
    /// recovery model for `UnLinkedBlockException`). Routing promotion through
    /// the caller preserves the invariant that every LINKED block was
    /// persisted by the acceptance path: linking an orphan in-tree here
    /// (the old `promote_orphans`) left it walkable in the fork tree yet
    /// absent from block_store, which the solidified-containment gate walks
    /// by parent hash — the tip-fork wedge that froze the head.
    ///
    /// Only DIRECT waiters are returned; a stashed descendant cascades
    /// naturally once its own parent is re-accepted and links, at which point
    /// a further `take_orphans_waiting_on` yields it. Waiters violating
    /// `num == parent.num + 1` are dropped. Empty when `parent` isn't linked.
    pub fn take_orphans_waiting_on(&self, parent: &BlockId) -> Vec<(Block, Option<Vec<u8>>)> {
        let mut g = self.inner.lock().unwrap();
        let Some(parent_kb) = g.mini_store.by_hash.get(parent).cloned() else {
            return Vec::new();
        };
        let waiting = g.by_parent.remove(parent).unwrap_or_default();
        let mut out = Vec::new();
        for child_id in waiting {
            let Some(child) = g.mini_unlinked_store.by_hash.get(&child_id).cloned() else {
                continue; // already pruned/removed
            };
            g.mini_unlinked_store.remove(&child_id);
            let raw = g.orphan_raw.remove(&child_id);
            if child.num != parent_kb.num + 1 {
                continue; // malformed orphan — never re-feed a bad chain
            }
            out.push((child.block.clone(), raw));
        }
        out
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

    /// Like [`get_branch`], but falls back to `fetch` (typically a
    /// `BlockStore` lookup) for any block not in the in-memory linked
    /// store (H-2). [`get_branch`] errors `NonCommonBlockError` the moment
    /// a fork diverges past the LRU-eviction boundary — `get_branch_deep`
    /// keeps walking onto disk. It walks by the header `parent_hash` (not
    /// the in-memory weak parent pointers, which don't exist for
    /// disk-loaded blocks). Returns the same child-to-parent branch pair,
    /// common ancestor excluded.
    pub fn get_branch_deep<F>(
        &self,
        id1: &BlockId,
        id2: &BlockId,
        mut fetch: F,
    ) -> Result<(VecDeque<Arc<KhaosBlock>>, VecDeque<Arc<KhaosBlock>>), NonCommonBlockError>
    where
        F: FnMut(&BlockId) -> Option<Block>,
    {
        let g = self.inner.lock().unwrap();
        // Resolve a block by id: in-memory linked store first, else disk.
        let resolve = |id: &BlockId, fetch: &mut F| -> Option<Arc<KhaosBlock>> {
            g.mini_store
                .by_hash
                .get(id)
                .cloned()
                .or_else(|| fetch(id).and_then(KhaosBlock::new))
        };

        let mut list1 = VecDeque::new();
        let mut list2 = VecDeque::new();
        let mut b1 = resolve(id1, &mut fetch).ok_or(NonCommonBlockError)?;
        let mut b2 = resolve(id2, &mut fetch).ok_or(NonCommonBlockError)?;

        // Equalize heights (each step strictly lowers num, so bounded).
        while b1.num > b2.num {
            list1.push_back(b1.clone());
            let pid = b1.parent_id().ok_or(NonCommonBlockError)?;
            b1 = resolve(&pid, &mut fetch).ok_or(NonCommonBlockError)?;
        }
        while b2.num > b1.num {
            list2.push_back(b2.clone());
            let pid = b2.parent_id().ok_or(NonCommonBlockError)?;
            b2 = resolve(&pid, &mut fetch).ok_or(NonCommonBlockError)?;
        }
        // Walk together until they meet.
        while b1.id != b2.id {
            list1.push_back(b1.clone());
            list2.push_back(b2.clone());
            let p1 = b1.parent_id().ok_or(NonCommonBlockError)?;
            let p2 = b2.parent_id().ok_or(NonCommonBlockError)?;
            b1 = resolve(&p1, &mut fetch).ok_or(NonCommonBlockError)?;
            b2 = resolve(&p2, &mut fetch).ok_or(NonCommonBlockError)?;
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

/// Promote `block` to head if it's strictly higher than the current head
/// (or there's no head). Strict `>` keeps the first-arrived block at a
/// given height — java-tron parity.
fn promote_head_if_higher(inner: &mut Inner, block: &Arc<KhaosBlock>) {
    let higher = match &inner.head {
        None => true,
        Some(h) => block.num > h.num,
    };
    if higher {
        inner.head = Some(block.clone());
    }
}

/// Drop retained wire bytes for any orphan no longer in the unlinked store,
/// keeping `orphan_raw` in lockstep with `mini_unlinked_store` (which is
/// pruned by its own LRU). Orphans recover by caller re-acceptance via
/// [`KhaosDb::take_orphans_waiting_on`], never by silent in-tree promotion —
/// that promotion left a block linked-but-unpersisted and wedged the head.
fn prune_orphan_raw(inner: &mut Inner) {
    let Inner {
        mini_unlinked_store,
        orphan_raw,
        ..
    } = inner;
    orphan_raw.retain(|id, _| mini_unlinked_store.by_hash.contains_key(id));
}

/// Classify a head transition for [`PushOutcome`]. `Extended` when the
/// previous head is an ancestor of the new head (or there was none);
/// `Sibling` when the head didn't move; `Reorg` otherwise.
fn classify_outcome(prev_head: Option<Arc<KhaosBlock>>, head: Arc<KhaosBlock>) -> PushOutcome {
    let Some(prev) = prev_head else {
        return PushOutcome::Extended { head };
    };
    if prev.id == head.id {
        return PushOutcome::Sibling { head };
    }
    if is_ancestor(&prev.id, &head) {
        PushOutcome::Extended { head }
    } else {
        PushOutcome::Reorg { from: prev, to: head }
    }
}

/// Walk `descendant`'s parent chain looking for `ancestor_id`. `false` if
/// the chain ends (genesis or pruned parent) before reaching it — for a
/// head change that means the new head sits on a different fork.
fn is_ancestor(ancestor_id: &BlockId, descendant: &Arc<KhaosBlock>) -> bool {
    let mut cur = descendant.clone();
    loop {
        if cur.id == *ancestor_id {
            return true;
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => return false,
        }
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
        let head = db.push(b2).unwrap().into_head();
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
        let head = db.push(b1).unwrap().into_head();
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
        let head = db.push(b).unwrap().into_head();
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
        let head = db.push(b3).unwrap().into_head();
        assert_eq!(head.id, id_b3, "longer fork (b-chain) becomes head");
    }

    #[test]
    fn out_of_order_orphan_is_handed_back_for_repush_not_auto_linked() {
        // Block 3 arrives before block 2. When 2 links, 3 must NOT be linked
        // in-tree automatically — that (the old promote_orphans) left it
        // linked-but-unpersisted and wedged the head at the solidified gate.
        // Instead `take_orphans_waiting_on` hands 3 back so the caller
        // re-accepts it through the full path. java-tron parity.
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();

        let b2 = mk_block(2, g_bytes, 0);
        let id_b2 = id_of(&b2);
        let mut b2_bytes = [0u8; 32];
        b2_bytes.copy_from_slice(&id_b2.as_bytes()[..]);
        let b3 = mk_block(3, b2_bytes, 0);
        let id_b3 = id_of(&b3);

        // b3 first → orphaned, head stays at genesis.
        assert!(matches!(db.push(b3).unwrap_err(), PushError::Unlinked));
        assert_eq!(db.unlinked_size(), 1);
        assert_eq!(db.head().unwrap().num, 1);

        // b2 links → head advances to 2 ONLY; b3 is NOT auto-linked.
        let outcome = db.push(b2).unwrap();
        assert!(matches!(outcome, PushOutcome::Extended { .. }));
        assert_eq!(db.head().unwrap().num, 2, "head advances to 2, not the orphan");
        assert!(!db.contains_in_linked(&id_b3), "orphan must NOT be auto-linked");
        assert_eq!(db.unlinked_size(), 1, "orphan still stashed");

        // The caller drains the now-linkable orphan and re-accepts it.
        let ready = db.take_orphans_waiting_on(&id_b2);
        assert_eq!(ready.len(), 1);
        assert_eq!(id_of(&ready[0].0), id_b3);
        assert_eq!(db.unlinked_size(), 0, "orphan removed from stash on take");

        // Re-push (the caller's re-acceptance) links it, head advances to 3.
        assert!(matches!(
            db.push(ready[0].0.clone()).unwrap(),
            PushOutcome::Extended { .. }
        ));
        assert_eq!(db.head().unwrap().id, id_b3);
        assert!(db.contains_in_linked(&id_b3));
    }

    #[test]
    fn orphan_raw_bytes_round_trip_through_take() {
        // push_with_raw retains the wire bytes for a stashed orphan and hands
        // them back on take (so a re-acceptance validates txTrieRoot + sizes
        // bandwidth against the ORIGINAL encoding, not a prost re-encode).
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();

        let b2 = mk_block(2, g_bytes, 0);
        let id_b2 = id_of(&b2);
        let mut b2_bytes = [0u8; 32];
        b2_bytes.copy_from_slice(&id_b2.as_bytes()[..]);
        let b3 = mk_block(3, b2_bytes, 0);

        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(matches!(
            db.push_with_raw(b3, Some(&raw[..])).unwrap_err(),
            PushError::Unlinked
        ));
        db.push(b2).unwrap();
        let ready = db.take_orphans_waiting_on(&id_b2);
        assert_eq!(ready.len(), 1);
        assert_eq!(
            ready[0].1.as_deref(),
            Some(raw.as_slice()),
            "original wire bytes must round-trip through take"
        );
    }

    #[test]
    fn redelivered_stashed_orphan_links_directly_after_parent_arrives() {
        // Linked-only dedup: a re-delivery of a still-stashed orphan arriving
        // after its parent linked must be able to link (the old both-store
        // dedup swallowed it as Sibling and stranded it).
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();

        let b2 = mk_block(2, g_bytes, 0);
        let mut b2_bytes = [0u8; 32];
        b2_bytes.copy_from_slice(&id_of(&b2).as_bytes()[..]);
        let b3 = mk_block(3, b2_bytes, 0);
        let id_b3 = id_of(&b3);

        assert!(matches!(db.push(b3.clone()).unwrap_err(), PushError::Unlinked));
        db.push(b2).unwrap(); // parent links; orphan still stashed
        // Direct re-delivery (NOT via take) must link, not dedup as Sibling.
        assert!(matches!(db.push(b3).unwrap(), PushOutcome::Extended { .. }));
        assert!(db.contains_in_linked(&id_b3));
    }

    #[test]
    fn head_jump_to_sibling_fork_is_classified_as_reorg() {
        // H-1: g → a2 → a3 (head). A longer b-chain (b2,b3,b4) overtakes,
        // so the head jumps forks → PushOutcome::Reorg{from:a3, to:b4}.
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&id_of(&g).as_bytes()[..]);
        db.start(g).unwrap();

        let a2 = mk_block(2, g_bytes, 1);
        let mut a2_bytes = [0u8; 32];
        a2_bytes.copy_from_slice(&id_of(&a2).as_bytes()[..]);
        assert!(matches!(db.push(a2).unwrap(), PushOutcome::Extended { .. }));
        let a3 = mk_block(3, a2_bytes, 1);
        let id_a3 = id_of(&a3);
        assert!(matches!(db.push(a3).unwrap(), PushOutcome::Extended { .. }));

        let b2 = mk_block(2, g_bytes, 2);
        let mut b2_bytes = [0u8; 32];
        b2_bytes.copy_from_slice(&id_of(&b2).as_bytes()[..]);
        assert!(matches!(db.push(b2).unwrap(), PushOutcome::Sibling { .. }));
        let b3 = mk_block(3, b2_bytes, 2);
        let mut b3_bytes = [0u8; 32];
        b3_bytes.copy_from_slice(&id_of(&b3).as_bytes()[..]);
        assert!(matches!(db.push(b3).unwrap(), PushOutcome::Sibling { .. }));
        let b4 = mk_block(4, b3_bytes, 2);
        let id_b4 = id_of(&b4);
        match db.push(b4).unwrap() {
            PushOutcome::Reorg { from, to } => {
                assert_eq!(from.id, id_a3, "reorg from old head a3");
                assert_eq!(to.id, id_b4, "reorg to new head b4");
            }
            other => panic!("expected Reorg, got {other:?}"),
        }
    }

    #[test]
    fn get_branch_deep_falls_back_to_disk_for_evicted_blocks() {
        // H-2: g→a2→a3 and g→b2→b3 live only "on disk" (a HashMap fetch);
        // the in-memory KhaosDb is empty. plain get_branch fails, but
        // get_branch_deep finds the common ancestor g via the fallback.
        use std::collections::HashMap;
        let g = mk_block(1, [0u8; 32], 0);
        let mut g_b = [0u8; 32];
        g_b.copy_from_slice(&id_of(&g).as_bytes()[..]);
        let a2 = mk_block(2, g_b, 1);
        let mut a2_b = [0u8; 32];
        a2_b.copy_from_slice(&id_of(&a2).as_bytes()[..]);
        let a3 = mk_block(3, a2_b, 1);
        let id_a3 = id_of(&a3);
        let b2 = mk_block(2, g_b, 2);
        let mut b2_b = [0u8; 32];
        b2_b.copy_from_slice(&id_of(&b2).as_bytes()[..]);
        let b3 = mk_block(3, b2_b, 2);
        let id_b3 = id_of(&b3);

        let mut disk: HashMap<BlockId, Block> = HashMap::new();
        for blk in [&g, &a2, &a3, &b2, &b3] {
            disk.insert(id_of(blk), blk.clone());
        }

        let db = KhaosDb::new(); // empty in-memory store
        assert!(
            db.get_branch(&id_a3, &id_b3).is_err(),
            "plain get_branch can't see disk-only blocks"
        );
        let (l1, l2) = db
            .get_branch_deep(&id_a3, &id_b3, |id| disk.get(id).cloned())
            .expect("deep branch resolves via disk");
        assert_eq!(l1.len(), 2);
        assert_eq!(l2.len(), 2);
        assert_eq!(l1.front().unwrap().id, id_a3);
        assert_eq!(l2.front().unwrap().id, id_b3);
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

    /// Pins the fork-tree contract the sync layer's `removeBlk`-on-failed-switch
    /// fix relies on: when a fork switch aborts and the old chain is restored,
    /// the driver removes the ENTIRE new branch from the tree and repoints the
    /// head at the restored old tip. That is what lets a later re-delivery of
    /// the branch be re-attempted — `accept_block` dedups on
    /// `contains_in_linked`, so a branch left linked after a failed switch would
    /// be swallowed as `AlreadyKnown` forever (the tip-fork wedge). Mirrors
    /// java-tron `Manager.switchFork`: `first.forEach(removeBlk)` then
    /// `setHead(binaryTree.getValue().peekFirst())`.
    #[test]
    fn remove_branch_and_set_head_restores_old_tip() {
        let db = KhaosDb::new();
        let g = mk_block(1, [0u8; 32], 0);
        let g_id = id_of(&g);
        let mut g_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&g_id.as_bytes()[..]);
        db.start(g).unwrap();

        // Old (executed) tip: A(2), the first-arrived sibling at height 2.
        let a = mk_block(2, g_bytes, 0);
        let a_id = id_of(&a);
        db.push(a).unwrap();
        assert_eq!(db.head().unwrap().id, a_id, "A heads after arriving first");

        // Competing branch B(2)→C(3): longer, so khaos promotes C as the
        // switch candidate (the reorg the driver would attempt and — in the
        // wedge scenario — fail to apply).
        let b = mk_block(2, g_bytes, 1);
        let b_id = id_of(&b);
        let mut b_bytes = [0u8; 32];
        b_bytes.copy_from_slice(&b_id.as_bytes()[..]);
        db.push(b).unwrap();
        let c = mk_block(3, b_bytes, 1);
        let c_id = id_of(&c);
        db.push(c).unwrap();
        assert_eq!(db.head().unwrap().id, c_id, "C wins the longest-chain race");

        // Simulate the aborted switch (Fix A1b): remove the whole new branch,
        // then pin the head back at the restored executed tip A.
        assert!(db.remove(&c_id));
        assert!(db.remove(&b_id));
        let a_kb = db.get(&a_id).expect("old tip A must still be linked");
        db.set_head(a_kb);

        // Head restored, and the removed branch is GONE from the linked store —
        // so a re-delivery of B/C is no longer AlreadyKnown and is retryable.
        assert_eq!(db.head().unwrap().id, a_id, "head restored to old tip A");
        assert!(db.contains_in_linked(&a_id), "A stays linked");
        assert!(!db.contains_in_linked(&b_id), "B removed → re-deliverable");
        assert!(!db.contains_in_linked(&c_id), "C removed → re-deliverable");

        // Re-pushing the branch re-links it (the switch is retryable, not wedged).
        db.push(mk_block(2, g_bytes, 1)).unwrap();
        assert!(db.contains_in_linked(&b_id), "B re-links on re-delivery");
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
