//! Log-filter matching, pinned against java-tron's `LogMatchExactlyTest`.
//!
//! java's `LogFilter.matchesExactly(Log)`
//! (`framework/.../services/jsonrpc/filters/LogFilter.java`) defines the
//! `eth_getLogs` / `eth_subscribe("logs")` contract clients rely on:
//!
//!   * an empty address list matches any log; a non-empty one is an OR set;
//!   * `topics` is POSITIONAL — entry `i` constrains log topic `i`;
//!   * a null/empty entry at position `i` is a wildcard;
//!   * a list at position `i` is an OR set;
//!   * a filter longer than the log's topic list never matches
//!     (`if (i >= logTopics.size()) return false`);
//!   * a filter shorter than the log's topic list leaves the trailing topics
//!     unconstrained.
//!
//! The cases below are the ones java's own test file asserts, translated onto
//! `log_matches_filter` — the shared predicate behind the WebSocket `logs`
//! subscription.

use serde_json::json;
use tron_rpc::pubsub::log_matches_filter;
use tron_rpc::LogFilter;

// The exact fixtures from java's `LogMatchExactlyTest`.
const ADDRESS: &str = "d4048be096f969f51fd5642a9c744ec2a7eb89fe";
const TOPIC1: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const TOPIC2: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TOPIC3: &str = "00000000000000000000000098ff8c0e1effbc70b23de702f415ec1e5ed76d42";
const TOPIC4: &str = "0000000000000000000000000000000000000000000000000000000000000783";

fn bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap()
}

/// java's fixture log: one address, four topics in the order 1,2,3,4.
fn log() -> serde_json::Value {
    json!({
        "address": format!("0x{ADDRESS}"),
        "topics": [
            format!("0x{TOPIC1}"),
            format!("0x{TOPIC2}"),
            format!("0x{TOPIC3}"),
            format!("0x{TOPIC4}"),
        ],
        "data": "0x",
    })
}

fn filter(addresses: Vec<&str>, topics: Vec<Vec<&str>>) -> LogFilter {
    LogFilter {
        from_block: 0,
        to_block: i64::MAX,
        addresses: addresses.into_iter().map(bytes).collect(),
        topics: topics
            .into_iter()
            .map(|alts| alts.into_iter().map(bytes).collect())
            .collect(),
    }
}

/// java `testMatchOneAddress1` / `testMatchOneAddress2`.
#[test]
fn single_matching_address_matches() {
    assert!(log_matches_filter(&log(), &filter(vec![ADDRESS], vec![])));
}

/// java `testMatchOneAddress3`.
#[test]
fn single_non_matching_address_does_not_match() {
    assert!(!log_matches_filter(
        &log(),
        &filter(vec!["1111111111111111111111111111111111111111"], vec![])
    ));
}

/// java `testMatchMultiAddress` — the address list is an OR set.
#[test]
fn address_list_is_an_or_set() {
    assert!(log_matches_filter(
        &log(),
        &filter(
            vec![ADDRESS, "0000000000000000000000000000000000000000"],
            vec![]
        )
    ));
}

/// java `matchesContractAddress` returns true when the list is empty.
#[test]
fn empty_address_list_matches_any_address() {
    assert!(log_matches_filter(&log(), &filter(vec![], vec![])));
}

/// java `testMatchOneTopic1` — position 0 constrains topic 0.
#[test]
fn first_topic_match() {
    assert!(log_matches_filter(&log(), &filter(vec![], vec![vec![TOPIC1]])));
}

/// java `testMatchOneTopic2` — topic 2 is at position 1, not position 0, so a
/// filter naming it at position 0 must NOT match. This is what makes the filter
/// positional rather than a set membership test.
#[test]
fn topic_filter_is_positional_not_set_membership() {
    assert!(!log_matches_filter(&log(), &filter(vec![], vec![vec![TOPIC2]])));
}

/// java `testMatchMultiTopic1` — a list at a position is an OR set.
#[test]
fn topic_position_is_an_or_set() {
    assert!(log_matches_filter(
        &log(),
        &filter(vec![], vec![vec![TOPIC1, TOPIC2]])
    ));
}

/// java `testMatchMultiTopic2` — `[null, [t1, t3, t4]]`: position 1 of the log
/// is TOPIC2, which is in none of the alternatives, so no match.
#[test]
fn wildcard_then_non_matching_or_set_does_not_match() {
    assert!(!log_matches_filter(
        &log(),
        &filter(vec![], vec![vec![], vec![TOPIC1, TOPIC3, TOPIC4]])
    ));
}

/// java `testMatchMultiTopic3` — `[[t1, t2], null, [t3, t4]]`: position 0 hits
/// TOPIC1, position 1 is a wildcard, position 2 hits TOPIC3. The log's fourth
/// topic is left unconstrained.
#[test]
fn or_sets_around_a_wildcard_match_with_a_trailing_topic_unconstrained() {
    assert!(log_matches_filter(
        &log(),
        &filter(
            vec![],
            vec![vec![TOPIC1, TOPIC2], vec![], vec![TOPIC3, TOPIC4]]
        )
    ));
}

/// java `testMatchAddressMultiTopic`, all three assertions.
#[test]
fn address_and_positional_topics_combined() {
    let addrs = vec![ADDRESS, "0000000000000000000000000000000000000000"];
    // [t1, null, [t3, t4]] → true
    assert!(log_matches_filter(
        &log(),
        &filter(
            addrs.clone(),
            vec![vec![TOPIC1], vec![], vec![TOPIC3, TOPIC4]]
        )
    ));
    // [t1, null, t4] → false: position 2 of the log is TOPIC3, not TOPIC4.
    assert!(!log_matches_filter(
        &log(),
        &filter(addrs.clone(), vec![vec![TOPIC1], vec![], vec![TOPIC4]])
    ));
    // [t2, null, [t3, t4]] → false: position 0 of the log is TOPIC1.
    assert!(!log_matches_filter(
        &log(),
        &filter(addrs, vec![vec![TOPIC2], vec![], vec![TOPIC3, TOPIC4]])
    ));
}

/// java: `if (i >= logTopics.size()) return false`. A filter with more
/// positions than the log has topics never matches, even when every position it
/// shares with the log agrees.
#[test]
fn filter_longer_than_the_logs_topics_never_matches() {
    let one_topic_log = json!({
        "address": format!("0x{ADDRESS}"),
        "topics": [format!("0x{TOPIC1}")],
        "data": "0x",
    });
    assert!(log_matches_filter(
        &one_topic_log,
        &filter(vec![], vec![vec![TOPIC1]])
    ));
    assert!(!log_matches_filter(
        &one_topic_log,
        &filter(vec![], vec![vec![TOPIC1], vec![TOPIC2]])
    ));
    // A wildcard at the overflowing position does not rescue it: java's index
    // bound is checked before the per-position OR set.
    assert!(!log_matches_filter(
        &one_topic_log,
        &filter(vec![], vec![vec![TOPIC1], vec![]])
    ));
}

/// An anonymous event carries no topics, so any positional constraint fails
/// while a topic-free filter still matches on address alone.
#[test]
fn log_with_no_topics_matches_only_a_topic_free_filter() {
    let bare = json!({
        "address": format!("0x{ADDRESS}"),
        "topics": [],
        "data": "0x",
    });
    assert!(log_matches_filter(&bare, &filter(vec![ADDRESS], vec![])));
    assert!(!log_matches_filter(&bare, &filter(vec![ADDRESS], vec![vec![TOPIC1]])));
}
