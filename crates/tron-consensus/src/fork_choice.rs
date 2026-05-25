//! Fork-choice rule.
//!
//! TRON's full rule is "longest chain containing the last solidified
//! block". The solidified block is the most recent one with ≥70%
//! agreement from the active SR list (`SOLIDIFIED_THRESHOLD_PCT`).
//!
//! Two entry points:
//!
//! * [`best_head`] — fast comparison that ignores solidified-containment.
//!   Sound when every candidate is known to extend the same solidified
//!   history (e.g. the only live fork point is unsolidified blocks).
//!   Used in unit tests + scenarios with no fork ambiguity.
//!
//! * [`best_head_with_solidified`] — full rule. Caller passes a closure
//!   that resolves `parent_of(id) -> Option<BlockId>` (typically a
//!   `BlockStore::get(id).parent_hash` lookup) and the id of the
//!   latest solidified block. Each candidate is walked back via
//!   `parent_of` until either:
//!     * it reaches `latest_solidified` → candidate is eligible
//!     * it reaches a block with number ≤ `latest_solidified.num` that
//!       isn't `latest_solidified` → candidate diverges, rejected
//!     * parent lookup fails → candidate rejected (orphan branch)
//!   Among the eligible candidates, the same number/lex tiebreak as
//!   [`best_head`] picks the winner.

use tron_types::BlockId;

/// Pure-data view of a chain head for the fork-choice rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkChoice {
    pub head: BlockId,
    /// The block number this head is at. Convenient cache; could be
    /// derived from `head.num()` but having it explicit lets callers
    /// supply a separately-verified value.
    pub number: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ForkChoiceError {
    #[error("no candidate heads to compare")]
    NoCandidates,
    #[error("no candidate contains the latest solidified block")]
    AllCandidatesDivergeFromSolidified,
}

/// Pick the best head from a non-empty set of candidates.
///
/// Rules, in order:
/// 1. Higher `number` wins.
/// 2. On tie, smaller `head` bytes (lex order) wins.
///
/// Returns `Err(NoCandidates)` if `candidates` is empty.
pub fn best_head<'a>(candidates: &'a [ForkChoice]) -> Result<&'a ForkChoice, ForkChoiceError> {
    candidates
        .iter()
        .max_by(|a, b| {
            a.number
                .cmp(&b.number)
                .then_with(|| b.head.as_bytes().cmp(a.head.as_bytes()))
        })
        .ok_or(ForkChoiceError::NoCandidates)
}

/// Pick the best head, enforcing TRON's full rule: only candidates
/// whose chain reaches `latest_solidified` are eligible. Among those,
/// apply the same number/lex tiebreak as [`best_head`].
///
/// `parent_of` walks one step back through the chain — given a block
/// id, return its parent. Callers in production wire this to
/// `BlockStore::get(id).block_header.raw_data.parent_hash`. Returning
/// `None` from `parent_of` (because the block isn't in the store yet,
/// or the walk has fallen off the orphan branch) rejects that
/// candidate.
///
/// Walk depth is bounded by `head.number - latest_solidified.number +
/// 1`: a healthy fork is rarely more than a few blocks ahead of the
/// solidified head, and we hard-cap at 1024 (KhaosDb horizon) to
/// avoid pathological lookups on malicious peers feeding bogus
/// `head.number`s.
pub fn best_head_with_solidified<'a, F>(
    candidates: &'a [ForkChoice],
    latest_solidified: BlockId,
    mut parent_of: F,
) -> Result<&'a ForkChoice, ForkChoiceError>
where
    F: FnMut(&BlockId) -> Option<BlockId>,
{
    if candidates.is_empty() {
        return Err(ForkChoiceError::NoCandidates);
    }
    const WALK_HORIZON: usize = 1024;
    let solid_num = latest_solidified.num() as i64;

    let eligible: Vec<&ForkChoice> = candidates
        .iter()
        .filter(|cand| {
            // A candidate AT or BELOW the solidified height must BE
            // the solidified block to be eligible — anything older
            // can't extend a chain containing it.
            if cand.number < solid_num {
                return false;
            }
            if cand.number == solid_num {
                return cand.head == latest_solidified;
            }
            // Walk back, step by step. Stop at solidified (eligible),
            // at any block of the solidified height that isn't it
            // (diverges), or after the depth cap (reject).
            let mut cur = cand.head;
            for _ in 0..WALK_HORIZON {
                if cur == latest_solidified {
                    return true;
                }
                if (cur.num() as i64) <= solid_num {
                    // Same height as solidified or below, but not the
                    // solidified block itself → this chain forked off
                    // before the solidified head.
                    return false;
                }
                let Some(parent) = parent_of(&cur) else {
                    // Missing parent — chain is incomplete from our
                    // perspective; reject to stay safe.
                    return false;
                };
                cur = parent;
            }
            // Walked the full horizon without finding the solidified
            // block — treat as a divergent fork.
            false
        })
        .collect();

    if eligible.is_empty() {
        return Err(ForkChoiceError::AllCandidatesDivergeFromSolidified);
    }
    // `eligible` is non-empty by the early return, so the inner
    // unreachable is genuinely unreachable.
    eligible
        .into_iter()
        .max_by(|a, b| {
            a.number
                .cmp(&b.number)
                .then_with(|| b.head.as_bytes().cmp(a.head.as_bytes()))
        })
        .ok_or(ForkChoiceError::NoCandidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn bid(num: u64, marker: u8) -> BlockId {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&num.to_be_bytes());
        raw[31] = marker;
        BlockId::from_raw(raw)
    }

    fn fc(num: u64, marker: u8) -> ForkChoice {
        ForkChoice {
            head: bid(num, marker),
            number: num as i64,
        }
    }

    /// Helper: build a parent_of callback from a `[(child, parent)]`
    /// list. Returns None for anything not in the map.
    fn parent_of_from(edges: Vec<(BlockId, BlockId)>) -> impl FnMut(&BlockId) -> Option<BlockId> {
        let map: HashMap<BlockId, BlockId> = edges.into_iter().collect();
        move |id| map.get(id).copied()
    }

    #[test]
    fn best_head_with_solidified_rejects_candidate_that_diverges() {
        // Solidified at 100. Two candidates at 102:
        // * A: 100 → 101a → 102a (extends solidified — eligible)
        // * B: 100' → 101b → 102b (diverges before solid — rejected)
        let solid = bid(100, 0x01);
        let head_a = bid(102, 0xaa);
        let parent_a = bid(101, 0xaa);
        let head_b = bid(102, 0xbb);
        let parent_b = bid(101, 0xbb);
        let fake_solid = bid(100, 0x02); // different marker

        let parent_of = parent_of_from(vec![
            (head_a, parent_a),
            (parent_a, solid),
            (head_b, parent_b),
            (parent_b, fake_solid),
            // fake_solid has no parent in our edge map; walk stops here
        ]);

        let candidates = vec![fc(102, 0xaa), fc(102, 0xbb)];
        let best = best_head_with_solidified(&candidates, solid, parent_of).unwrap();
        assert_eq!(best.head, head_a, "B diverges from solidified, must be filtered");
    }

    #[test]
    fn best_head_with_solidified_falls_back_when_all_diverge() {
        let solid = bid(100, 0x01);
        let head = bid(102, 0xaa);
        let parent = bid(101, 0xaa);
        let bogus_solid = bid(100, 0x02);
        let parent_of = parent_of_from(vec![(head, parent), (parent, bogus_solid)]);
        let candidates = [fc(102, 0xaa)];
        let result = best_head_with_solidified(&candidates, solid, parent_of);
        assert_eq!(result.unwrap_err(), ForkChoiceError::AllCandidatesDivergeFromSolidified);
    }

    #[test]
    fn best_head_with_solidified_accepts_candidate_equal_to_solidified() {
        // Candidate IS the solidified head itself — degenerate case
        // but the rule must accept it.
        let solid = bid(100, 0x05);
        let candidates = vec![ForkChoice { head: solid, number: 100 }];
        // No parent walk needed; parent_of must never be called.
        let parent_of = |_: &BlockId| -> Option<BlockId> {
            panic!("parent_of must not be called for head == solidified")
        };
        let best =
            best_head_with_solidified(&candidates, solid, parent_of).unwrap();
        assert_eq!(best.head, solid);
    }

    #[test]
    fn best_head_with_solidified_rejects_candidate_below_solidified_height() {
        // Solidified at 100, candidate at 99 — can't possibly extend it.
        let solid = bid(100, 0x01);
        let parent_of = |_: &BlockId| -> Option<BlockId> { None };
        let candidates = vec![fc(99, 0xaa)];
        let result = best_head_with_solidified(&candidates, solid, parent_of);
        assert_eq!(result.unwrap_err(), ForkChoiceError::AllCandidatesDivergeFromSolidified);
    }

    #[test]
    fn best_head_with_solidified_rejects_when_parent_lookup_fails_mid_walk() {
        // Walk falls off before reaching solidified — incomplete chain.
        let solid = bid(100, 0x01);
        let head = bid(105, 0xaa);
        let parent = bid(104, 0xaa);
        // edges: head -> parent, but parent has no entry → walk stops
        let parent_of = parent_of_from(vec![(head, parent)]);
        let candidates = vec![fc(105, 0xaa)];
        let result = best_head_with_solidified(&candidates, solid, parent_of);
        assert_eq!(result.unwrap_err(), ForkChoiceError::AllCandidatesDivergeFromSolidified);
    }

    #[test]
    fn best_head_with_solidified_picks_higher_among_eligible() {
        // Three eligible candidates extending the solidified chain.
        // Pick the tallest.
        let solid = bid(100, 0x01);
        let p101 = bid(101, 0xab);
        let p102 = bid(102, 0xab);
        let head_a = bid(103, 0xa1);
        let head_b = bid(105, 0xb1);
        let head_c = bid(104, 0xc1);
        let parent_of = parent_of_from(vec![
            (head_a, p102),
            (head_b, bid(104, 0xb0)),
            (bid(104, 0xb0), bid(103, 0xb0)),
            (bid(103, 0xb0), p102),
            (head_c, bid(103, 0xc0)),
            (bid(103, 0xc0), p102),
            (p102, p101),
            (p101, solid),
        ]);
        let candidates = vec![fc(103, 0xa1), fc(105, 0xb1), fc(104, 0xc1)];
        let best = best_head_with_solidified(&candidates, solid, parent_of).unwrap();
        assert_eq!(best.head, head_b, "highest-numbered eligible wins");
    }

    #[test]
    fn best_head_with_solidified_empty_candidates_returns_no_candidates() {
        let solid = bid(100, 0x01);
        let parent_of = |_: &BlockId| -> Option<BlockId> { None };
        let result = best_head_with_solidified(&[], solid, parent_of);
        assert_eq!(result.unwrap_err(), ForkChoiceError::NoCandidates);
    }
}
