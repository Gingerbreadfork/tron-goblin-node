//! Tests for the `IncrementalMerkleVoucher` witness logic + the
//! voucher-helper methods on `IncrementalMerkleTree`. The witness
//! algorithm tracks the merkle path of a single targeted leaf as
//! later leaves are appended — the same code path java-tron uses to
//! build `getMerkleTreeVoucherInfo` responses.

use tron_tvm::shielded::{
    IncrementalMerkleTree, IncrementalMerkleVoucher, MerklePath, PathFiller, MERKLE_TREE_DEPTH,
};

fn cm(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Build a tree containing `leaves.len()` sequentially-appended
/// leaves.
fn tree_with(leaves: &[[u8; 32]]) -> IncrementalMerkleTree {
    let mut t = IncrementalMerkleTree::default();
    for cm in leaves {
        t.append(*cm).unwrap();
    }
    t
}

// ============================================================
// PathFiller
// ============================================================

#[test]
fn path_filler_empty_returns_empty_subtree_root_at_depth() {
    let mut filler = PathFiller::empty();
    let at_0 = filler.next(0);
    let at_5 = filler.next(5);
    let at_31 = filler.next(31);
    // All three should be canonical empty-root constants — distinct
    // because each level's empty root is a different hash.
    assert_ne!(at_0, at_5);
    assert_ne!(at_5, at_31);
    // Repeat calls at the same depth produce the same value (it's
    // the deterministic empty-tree constant).
    assert_eq!(filler.next(5), at_5);
}

#[test]
fn path_filler_from_queue_consumes_in_order_then_falls_back_to_empties() {
    let mut q = std::collections::VecDeque::new();
    q.push_back(cm(0xaa));
    q.push_back(cm(0xbb));
    let mut filler = PathFiller::from_queue(q);
    assert_eq!(filler.next(0), cm(0xaa));
    assert_eq!(filler.next(0), cm(0xbb));
    // Now empty → falls back to depth-keyed empty roots.
    let empty_at_0 = filler.next(0);
    let other_empty_0 = PathFiller::empty().next(0);
    assert_eq!(empty_at_0, other_empty_0);
}

// ============================================================
// IncrementalMerkleTree extensions
// ============================================================

#[test]
fn last_leaf_returns_most_recent_append() {
    let mut t = IncrementalMerkleTree::default();
    assert!(t.last_leaf().is_none());
    t.append(cm(0x11)).unwrap();
    assert_eq!(t.last_leaf(), Some(cm(0x11)));
    t.append(cm(0x22)).unwrap();
    assert_eq!(t.last_leaf(), Some(cm(0x22)));
    t.append(cm(0x33)).unwrap();
    // Three leaves → left=0x33, right=None, parent[0] holds combine(0x11,0x22).
    assert_eq!(t.last_leaf(), Some(cm(0x33)));
}

#[test]
fn is_complete_at_returns_true_only_when_filled_to_target_depth() {
    let mut t = IncrementalMerkleTree::default();
    // Empty tree → never complete.
    assert!(!t.is_complete_at(1));
    t.append(cm(0x01)).unwrap();
    assert!(!t.is_complete_at(1)); // right not yet filled
    t.append(cm(0x02)).unwrap();
    assert!(t.is_complete_at(1)); // depth-1 = 2 leaves
    // Need a parent at depth 1 to be "complete at depth 2".
    t.append(cm(0x03)).unwrap();
    assert!(!t.is_complete_at(2));
    t.append(cm(0x04)).unwrap();
    assert!(t.is_complete_at(2)); // depth-2 = 4 leaves
}

#[test]
fn next_depth_zero_when_a_leaf_cell_is_free() {
    let mut t = IncrementalMerkleTree::default();
    // Empty → first slot is the left leaf → depth 0.
    assert_eq!(t.next_depth(0), 0);
    t.append(cm(1)).unwrap();
    // Left filled, right free → depth 0.
    assert_eq!(t.next_depth(0), 0);
    t.append(cm(2)).unwrap();
    // Both filled → next append goes to a parent slot at depth 1.
    assert_eq!(t.next_depth(0), 1);
}

#[test]
fn next_depth_with_skip_walks_past_filled_slots() {
    // A 2-leaf tree. skip=1 means "ignore the first hole" — which is
    // the right leaf (still free). So next_depth(1) should report the
    // NEXT hole, which is parent[0] at depth 1.
    let t = tree_with(&[cm(1)]);
    assert_eq!(t.next_depth(0), 0); // right is free
    assert_eq!(t.next_depth(1), 1); // skip right → first parent
}

#[test]
fn root_with_filler_uses_queue_first_then_empties() {
    let t = IncrementalMerkleTree::default(); // empty tree
    // Empty queue → root collapses to depth-32 empty root.
    let mut empties = PathFiller::empty();
    let r_empty = t.root_with_filler(MERKLE_TREE_DEPTH, &mut empties);
    // Same as the tree's built-in `root()` for an empty tree.
    assert_eq!(r_empty, t.root());

    // With a populated queue, the root differs (one of the filler
    // siblings replaced the empty-leaf).
    let mut q = std::collections::VecDeque::new();
    q.push_back(cm(0x77));
    let mut filler = PathFiller::from_queue(q);
    let r_filled = t.root_with_filler(MERKLE_TREE_DEPTH, &mut filler);
    assert_ne!(r_filled, r_empty);
}

#[test]
fn merkle_path_is_none_for_empty_tree() {
    let t = IncrementalMerkleTree::default();
    let mut filler = PathFiller::empty();
    assert!(t.merkle_path(&mut filler).is_none());
}

#[test]
fn merkle_path_has_one_entry_per_depth() {
    let mut t = IncrementalMerkleTree::default();
    t.append(cm(1)).unwrap();
    let mut filler = PathFiller::empty();
    let path = t.merkle_path(&mut filler).unwrap();
    assert_eq!(path.siblings.len(), MERKLE_TREE_DEPTH);
    assert_eq!(path.index.len(), MERKLE_TREE_DEPTH);
}

// ============================================================
// MerklePath wire format
// ============================================================

#[test]
fn merkle_path_encode_layout_matches_compact_size_format() {
    let path = MerklePath {
        siblings: vec![cm(0x11), cm(0x22)],
        index: vec![false, true],
    };
    let encoded = path.encode();
    // Layout: <1 byte count=2> [<1 byte len=32><32 bytes>]x2 <8 bytes index>.
    assert_eq!(encoded.len(), 1 + 2 * 33 + 8);
    assert_eq!(encoded[0], 2); // compact size of sibling count
    assert_eq!(encoded[1], 32); // first sibling len
    assert_eq!(&encoded[2..34], &[0x11u8; 32]);
    assert_eq!(encoded[34], 32); // second sibling len
    assert_eq!(&encoded[35..67], &[0x22u8; 32]);
    // Index: bool list = [false, true], len=2.
    // Bit position (2-1-i): i=0 → bit 1 set if false (no). i=1 → bit 0 set if true (yes).
    // So index_long = 0b01 = 1.
    let mut idx_le = [0u8; 8];
    idx_le.copy_from_slice(&encoded[67..75]);
    let idx_long = u64::from_le_bytes(idx_le);
    assert_eq!(idx_long, 1);
}

#[test]
fn merkle_path_encode_is_deterministic() {
    let path = MerklePath {
        siblings: (0..32u8).map(cm).collect(),
        index: (0..32).map(|i| i % 2 == 0).collect(),
    };
    let a = path.encode();
    let b = path.encode();
    assert_eq!(a, b);
}

// ============================================================
// IncrementalMerkleVoucher
// ============================================================

#[test]
fn voucher_from_empty_tree_is_default() {
    let v = IncrementalMerkleVoucher::default();
    assert_eq!(v.tree, IncrementalMerkleTree::default());
    assert!(v.filled.is_empty());
    assert_eq!(v.cursor, IncrementalMerkleTree::default());
    assert_eq!(v.cursor_depth, 0);
    assert!(v.element().is_none());
}

#[test]
fn voucher_position_is_size_minus_one() {
    let v = IncrementalMerkleVoucher::from_tree(tree_with(&[cm(1)]));
    assert_eq!(v.position(), 0);
    let v3 = IncrementalMerkleVoucher::from_tree(tree_with(&[cm(1), cm(2), cm(3)]));
    assert_eq!(v3.position(), 2);
}

#[test]
fn voucher_path_for_single_leaf_at_position_zero() {
    // Target leaf at position 0. The merkle path is to the root of a
    // tree containing only that leaf.
    let v = IncrementalMerkleVoucher::from_tree(tree_with(&[cm(0xaa)]));
    let path = v.path().expect("path for non-empty tree");
    assert_eq!(path.siblings.len(), MERKLE_TREE_DEPTH);
    assert_eq!(path.index.len(), MERKLE_TREE_DEPTH);
    // The leaf at position 0 is the LEFT child at every level, so all
    // index bits should be `false`.
    assert!(path.index.iter().all(|b| !b), "leaf at pos 0 → all-left path");
}

#[test]
fn voucher_root_equals_tree_root_when_no_followups() {
    // A voucher with no appended commitments has the same root as
    // its underlying tree.
    let t = tree_with(&[cm(1), cm(2), cm(3)]);
    let direct_root = t.root();
    let v = IncrementalMerkleVoucher::from_tree(t);
    assert_eq!(v.root(), direct_root);
}

#[test]
fn voucher_append_extends_witness_and_position_remains_stable() {
    // The voucher's POSITION (leaf index) never changes — it tracks
    // the target's slot in the global tree, fixed at snapshot time.
    // The ROOT, however, DOES evolve to match the current global
    // tree root as new commitments arrive.
    let snapshot = tree_with(&[cm(1)]);
    let mut v = IncrementalMerkleVoucher::from_tree(snapshot);
    assert_eq!(v.position(), 0);
    v.append(cm(2)).unwrap();
    // Position is still 0 — the appended leaf is AFTER the target.
    assert_eq!(v.position(), 0);
    // The filled list now has one entry (the sibling at depth 0).
    assert_eq!(v.filled.len(), 1);
    assert_eq!(v.filled[0], cm(2));
    // The witness root now equals what a 2-leaf tree built directly
    // would produce.
    let direct = tree_with(&[cm(1), cm(2)]);
    assert_eq!(v.root(), direct.root());
}

#[test]
fn voucher_append_routes_to_cursor_at_depth_above_zero() {
    // Target at position 1 in a 2-leaf tree. Now appending a third
    // commitment doesn't slot into `filled` at depth 0 — both leaf
    // slots are full — so it should start a cursor subtree.
    let snapshot = tree_with(&[cm(1), cm(2)]);
    let mut v = IncrementalMerkleVoucher::from_tree(snapshot);
    assert_eq!(v.position(), 1);
    v.append(cm(3)).unwrap();
    // next_depth from a complete depth-1 tree with 0 filled = 1,
    // so the cursor starts at depth 1 with one leaf.
    assert_eq!(v.cursor_depth, 1);
    assert_eq!(v.cursor.size(), 1);
    assert!(v.filled.is_empty());
}

#[test]
fn voucher_append_promotes_complete_cursor_into_filled() {
    // Target at position 1. Two more commitments fill the cursor
    // subtree at depth 1, which then promotes into `filled`.
    let snapshot = tree_with(&[cm(1), cm(2)]);
    let mut v = IncrementalMerkleVoucher::from_tree(snapshot);
    v.append(cm(3)).unwrap();
    v.append(cm(4)).unwrap();
    // Cursor at depth 1 needed 2 leaves to complete. After 2 appends,
    // it should be promoted to `filled` and reset.
    assert_eq!(v.cursor, IncrementalMerkleTree::default());
    assert_eq!(v.cursor_depth, 0);
    assert_eq!(v.filled.len(), 1);
}

#[test]
fn voucher_root_tracks_global_tree_root_after_each_append() {
    // After each append, the voucher's root must equal the root of
    // a tree built directly with the same leaves. This is the
    // central invariant: the witness's "current root" is a stand-in
    // for the global root post-N-commitments, and the inclusion
    // proof verifies against it.
    let leaves: Vec<[u8; 32]> = (0x10u8..0x19u8).map(cm).collect();
    let snapshot = tree_with(&leaves[..1]); // single leaf
    let mut v = IncrementalMerkleVoucher::from_tree(snapshot);
    // After each append, root(voucher) == root(direct tree with the
    // same prefix of leaves).
    for n in 2..=leaves.len() {
        v.append(leaves[n - 1]).unwrap();
        let direct = tree_with(&leaves[..n]);
        assert_eq!(
            v.root(),
            direct.root(),
            "after appending {} leaves total, witness root must equal global root",
            n
        );
    }
    // Position never moves.
    assert_eq!(v.position(), 0);
}

#[test]
fn voucher_proto_round_trip_preserves_state() {
    let snapshot = tree_with(&[cm(0xab), cm(0xcd), cm(0xef)]);
    let mut v = IncrementalMerkleVoucher::from_tree(snapshot);
    v.append(cm(0x11)).unwrap();
    v.append(cm(0x22)).unwrap();
    let proto = v.to_proto();
    let back = IncrementalMerkleVoucher::from_proto(&proto);
    assert_eq!(back.tree, v.tree);
    assert_eq!(back.filled, v.filled);
    assert_eq!(back.cursor, v.cursor);
    assert_eq!(back.cursor_depth, v.cursor_depth);
    assert_eq!(back.root(), v.root());
    assert_eq!(back.position(), v.position());
}

#[test]
fn voucher_position_in_proto_resolves_to_same_value() {
    // The position helper in `tron-grpc/src/service.rs` (`voucher_position`)
    // computes leaf position from `voucher.tree.size() - 1` via the
    // proto representation. Verify the round-trip is consistent.
    let snapshot = tree_with(&[cm(1), cm(2), cm(3)]);
    let v = IncrementalMerkleVoucher::from_tree(snapshot);
    let proto = v.to_proto();
    // size = 3 → position should be 2.
    assert_eq!(v.position(), 2);
    // The proto tree's filled-cells encoding must round-trip:
    let back = IncrementalMerkleVoucher::from_proto(&proto);
    assert_eq!(back.position(), 2);
}
