//! [`TracingListener`] — emits every trigger as a `tracing::info!`
//! event. Useful for debugging and for nodes that want a one-liner per
//! trigger in their logs without standing up a real plugin.

use crate::listener::EventListener;
use crate::trigger::{
    BlockEvent, ContractEvent, ContractLogEvent, SolidifiedBlockEvent, TransactionEvent,
};

#[derive(Default, Debug)]
pub struct TracingListener;

impl EventListener for TracingListener {
    fn on_block(&self, ev: &BlockEvent) {
        tracing::info!(
            target: "tron_eventer",
            number = ev.block_number,
            hash = %&ev.block_hash[..16.min(ev.block_hash.len())],
            txs = ev.transaction_size,
            "block trigger"
        );
    }

    fn on_transaction(&self, ev: &TransactionEvent) {
        tracing::info!(
            target: "tron_eventer",
            tx_id = %&ev.transaction_id[..16.min(ev.transaction_id.len())],
            block = ev.block_number,
            kind = %ev.contract_type,
            "transaction trigger"
        );
    }

    fn on_contract_log(&self, ev: &ContractLogEvent) {
        tracing::info!(
            target: "tron_eventer",
            tx_id = %&ev.transaction_id[..16.min(ev.transaction_id.len())],
            topics = ev.topic_list.len(),
            "contract log"
        );
    }

    fn on_contract_event(&self, ev: &ContractEvent) {
        tracing::info!(
            target: "tron_eventer",
            tx_id = %&ev.transaction_id[..16.min(ev.transaction_id.len())],
            event = %ev.event_name,
            "contract event"
        );
    }

    fn on_solidified_block(&self, ev: &SolidifiedBlockEvent) {
        tracing::info!(
            target: "tron_eventer",
            solid = ev.latest_solidified_block_number,
            "solidified-block trigger"
        );
    }
}
