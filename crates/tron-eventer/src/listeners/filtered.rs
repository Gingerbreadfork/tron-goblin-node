//! Filter wrapper — java-tron `EventPluginLoader.matchFilter`.
//!
//! Wraps any [`EventListener`] and drops contract triggers that fall
//! outside the configured `event.subscribe.filter` block range /
//! contract-address list / topic list. Block, transaction and
//! solidified triggers pass through unfiltered (java only filters the
//! contract families).

use crate::listener::EventListener;
use crate::trigger::{
    BlockEvent, ContractEvent, ContractLogEvent, SolidifiedBlockEvent, TransactionEvent,
};
use std::sync::Arc;

/// Resolved `event.subscribe.filter` values.
///
/// * `from_block` / `to_block`: inclusive block-number range;
///   `to_block < 0` means "no upper bound" (java `LATEST_BLOCK_NUM`).
/// * `contract_addresses`: base58check strings; empty = no filtering.
/// * `contract_topics`: 32-byte log topics as lowercase hex (no 0x);
///   empty = no filtering.
#[derive(Debug, Clone)]
pub struct TriggerFilter {
    pub from_block: i64,
    pub to_block: i64,
    pub contract_addresses: Vec<String>,
    pub contract_topics: Vec<String>,
}

impl Default for TriggerFilter {
    fn default() -> Self {
        Self {
            from_block: 0,
            // -1 = "latest" / no upper bound (java LATEST_BLOCK_NUM).
            to_block: -1,
            contract_addresses: Vec::new(),
            contract_topics: Vec::new(),
        }
    }
}

impl TriggerFilter {
    /// `true` when nothing is configured — the wrapper short-circuits.
    pub fn is_empty(&self) -> bool {
        self.from_block <= 0
            && self.to_block < 0
            && self.contract_addresses.is_empty()
            && self.contract_topics.is_empty()
    }

    fn block_ok(&self, block_number: i64) -> bool {
        if self.from_block > 0 && block_number < self.from_block {
            return false;
        }
        if self.to_block >= 0 && block_number > self.to_block {
            return false;
        }
        true
    }

    fn address_ok(&self, contract_address: &str) -> bool {
        self.contract_addresses.is_empty()
            || self
                .contract_addresses
                .iter()
                .any(|a| a == contract_address)
    }

    fn topics_ok<'a>(&self, mut topics: impl Iterator<Item = &'a str>) -> bool {
        self.contract_topics.is_empty()
            || topics.any(|t| {
                let t = t.trim_start_matches("0x");
                self.contract_topics.iter().any(|f| f.eq_ignore_ascii_case(t))
            })
    }
}

/// The wrapping listener. Build via [`FilteredListener::wrap`]; when
/// the filter is empty the inner listener is returned unwrapped (zero
/// per-event cost).
pub struct FilteredListener {
    inner: Arc<dyn EventListener>,
    filter: TriggerFilter,
}

impl FilteredListener {
    pub fn wrap(inner: Arc<dyn EventListener>, filter: TriggerFilter) -> Arc<dyn EventListener> {
        if filter.is_empty() {
            return inner;
        }
        Arc::new(Self { inner, filter })
    }
}

impl EventListener for FilteredListener {
    fn on_block(&self, event: &BlockEvent) {
        self.inner.on_block(event);
    }

    fn on_transaction(&self, event: &TransactionEvent) {
        self.inner.on_transaction(event);
    }

    fn on_contract_log(&self, event: &ContractLogEvent) {
        if !self.filter.block_ok(event.block_number)
            || !self.filter.address_ok(&event.contract_address)
            || !self
                .filter
                .topics_ok(event.topic_list.iter().map(|s| s.as_str()))
        {
            return;
        }
        self.inner.on_contract_log(event);
    }

    fn on_contract_event(&self, event: &ContractEvent) {
        // java matches the RAW topics; the decoded event keeps the
        // signature hash + decoded topic values — match against both.
        let topics = std::iter::once(event.event_signature.as_str())
            .chain(event.topic_map.values().map(|s| s.as_str()));
        if !self.filter.block_ok(event.block_number)
            || !self.filter.address_ok(&event.contract_address)
            || !self.filter.topics_ok(topics)
        {
            return;
        }
        self.inner.on_contract_event(event);
    }

    fn on_solidified_block(&self, event: &SolidifiedBlockEvent) {
        self.inner.on_solidified_block(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listeners::{ChannelListener, TriggerMessage};

    fn log_event(block: i64, addr: &str, topic: &str) -> ContractLogEvent {
        ContractLogEvent {
            block_number: block,
            contract_address: addr.to_string(),
            topic_list: vec![topic.to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn empty_filter_returns_inner_unwrapped_and_passes_everything() {
        let (listener, mut rx) = ChannelListener::pair(8);
        let wrapped = FilteredListener::wrap(Arc::new(listener), TriggerFilter::default());
        wrapped.on_contract_log(&log_event(5, "Txyz", "aa"));
        assert!(matches!(rx.try_recv(), Ok(TriggerMessage::ContractLog(_))));
    }

    #[test]
    fn block_range_and_address_and_topic_filters_apply() {
        let (listener, mut rx) = ChannelListener::pair(8);
        let filter = TriggerFilter {
            from_block: 10,
            to_block: 20,
            contract_addresses: vec!["Tgood".to_string()],
            contract_topics: vec!["aa".to_string()],
        };
        let wrapped = FilteredListener::wrap(Arc::new(listener), filter);

        wrapped.on_contract_log(&log_event(5, "Tgood", "aa")); // below range
        wrapped.on_contract_log(&log_event(15, "Tbad", "aa")); // wrong address
        wrapped.on_contract_log(&log_event(15, "Tgood", "bb")); // wrong topic
        assert!(rx.try_recv().is_err(), "all three filtered out");

        wrapped.on_contract_log(&log_event(15, "Tgood", "aa"));
        assert!(matches!(rx.try_recv(), Ok(TriggerMessage::ContractLog(_))));
    }
}
