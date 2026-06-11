//! Kafka sink for [`tron_eventer`] — java-tron `eventplugin`
//! kafka-plugin parity.
//!
//! Registered in the node's [`tron_eventer::PluginRegistry`] under the
//! id `"kafka"`, so a java-tron `config.conf` like
//!
//! ```conf
//! event.subscribe = {
//!   path = "plugin-kafka-1.0.0.zip"     # id resolved from the stem
//!   server = "127.0.0.1:9092"           # bootstrap servers
//!   topics = [
//!     { triggerName = "block",         enable = true, topic = "block" },
//!     { triggerName = "transaction",   enable = true, topic = "transaction" },
//!     { triggerName = "contractevent", enable = true, topic = "contractevent" },
//!     { triggerName = "contractlog",   enable = true, topic = "contractlog" },
//!     { triggerName = "solidity",      enable = true, topic = "solidity" },
//!   ]
//! }
//! ```
//!
//! works unchanged. Each trigger serialises to the same camelCase JSON
//! java's plugin posts (the shapes live in [`tron_eventer::trigger`]).
//!
//! ## Threading
//!
//! Listener callbacks fire on the block-apply path, which must never
//! block on a broker. Each `on_*` therefore only serialises the
//! trigger and `try_send`s it onto a bounded channel
//! (`event.subscribe.send_queue_length`, default 1000); a dedicated
//! `kafka-event-sink` thread owns the producer and drains the channel.
//! Queue-full / delivery errors are logged (throttled) and dropped —
//! fire-and-forget, like java's plugin.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use kafka::producer::{Producer, Record, RequiredAcks};
use tron_eventer::listener::EventListener;
use tron_eventer::plugin::{PluginError, PluginFactory, PluginParams};
use tron_eventer::trigger::{
    BlockEvent, ContractEvent, ContractLogEvent, SolidifiedBlockEvent, TransactionEvent,
};

/// java-tron trigger names (`EventPluginConfig.*_TRIGGER_NAME`).
const BLOCK: &str = "block";
const TRANSACTION: &str = "transaction";
const CONTRACT_EVENT: &str = "contractevent";
const CONTRACT_LOG: &str = "contractlog";
const SOLIDITY: &str = "solidity";

/// Default bounded-queue depth when `send_queue_length` is 0/unset.
const DEFAULT_QUEUE: usize = 1000;

/// Factory registered under `"kafka"`.
#[derive(Default)]
pub struct KafkaPluginFactory;

impl PluginFactory for KafkaPluginFactory {
    fn id(&self) -> &str {
        "kafka"
    }

    fn build(&self, params: &PluginParams) -> Result<Arc<dyn EventListener>, PluginError> {
        if params.server.trim().is_empty() {
            return Err(PluginError::InvalidConfig {
                id: "kafka".into(),
                reason: "event.subscribe.server (bootstrap servers) is required".into(),
            });
        }
        let hosts: Vec<String> = params
            .server
            .split(',')
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .collect();
        let producer = Producer::from_hosts(hosts.clone())
            .with_ack_timeout(Duration::from_secs(5))
            .with_required_acks(RequiredAcks::One)
            .create()
            .map_err(|e| PluginError::InitFailed {
                id: "kafka".into(),
                reason: format!("producer create ({hosts:?}): {e}"),
            })?;

        let topic_for = |name: &str| -> Option<String> {
            if !params.is_trigger_enabled(name) {
                return None;
            }
            let configured = params.topic_for(name);
            Some(if configured.is_empty() {
                name.to_string()
            } else {
                configured.to_string()
            })
        };
        let queue = if params.send_queue_length > 0 {
            params.send_queue_length
        } else {
            DEFAULT_QUEUE
        };

        tracing::info!(
            server = %params.server,
            queue,
            "event plugin: kafka sink up (block={:?} transaction={:?} contractevent={:?} \
             contractlog={:?} solidity={:?})",
            topic_for(BLOCK),
            topic_for(TRANSACTION),
            topic_for(CONTRACT_EVENT),
            topic_for(CONTRACT_LOG),
            topic_for(SOLIDITY),
        );

        let (tx, rx) = sync_channel::<(String, String)>(queue);
        std::thread::Builder::new()
            .name("kafka-event-sink".into())
            .spawn(move || {
                let mut producer = producer;
                let mut errors: u64 = 0;
                while let Ok((topic, json)) = rx.recv() {
                    if let Err(e) = producer.send(&Record::from_value(&topic, json.as_bytes())) {
                        errors += 1;
                        if errors == 1 || errors % 1000 == 0 {
                            tracing::warn!(
                                topic = %topic,
                                error = %e,
                                errors_so_far = errors,
                                "kafka sink: send failed (record dropped)"
                            );
                        }
                    }
                }
            })
            .map_err(|e| PluginError::InitFailed {
                id: "kafka".into(),
                reason: format!("sink thread spawn: {e}"),
            })?;

        Ok(Arc::new(KafkaListener {
            tx,
            block_topic: topic_for(BLOCK),
            transaction_topic: topic_for(TRANSACTION),
            contract_event_topic: topic_for(CONTRACT_EVENT),
            contract_log_topic: topic_for(CONTRACT_LOG),
            solidity_topic: topic_for(SOLIDITY),
            dropped: AtomicU64::new(0),
        }))
    }
}

/// The queueing listener — `on_*` never blocks.
struct KafkaListener {
    tx: SyncSender<(String, String)>,
    block_topic: Option<String>,
    transaction_topic: Option<String>,
    contract_event_topic: Option<String>,
    contract_log_topic: Option<String>,
    solidity_topic: Option<String>,
    /// Records dropped on queue-full — logged once per 1000.
    dropped: AtomicU64,
}

impl KafkaListener {
    fn publish<T: serde::Serialize>(&self, topic: &Option<String>, payload: &T) {
        let Some(topic) = topic else {
            return;
        };
        let json = match serde_json::to_string(payload) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "kafka sink: trigger serialisation failed");
                return;
            }
        };
        match self.tx.try_send((topic.clone(), json)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed);
                if n % 1000 == 0 {
                    tracing::warn!(
                        topic = %topic,
                        dropped_so_far = n + 1,
                        "kafka sink: queue full/closed — record dropped (fire-and-forget)"
                    );
                }
            }
        }
    }
}

impl EventListener for KafkaListener {
    fn on_block(&self, event: &BlockEvent) {
        self.publish(&self.block_topic, event);
    }

    fn on_transaction(&self, event: &TransactionEvent) {
        self.publish(&self.transaction_topic, event);
    }

    fn on_contract_log(&self, event: &ContractLogEvent) {
        self.publish(&self.contract_log_topic, event);
    }

    fn on_contract_event(&self, event: &ContractEvent) {
        self.publish(&self.contract_event_topic, event);
    }

    fn on_solidified_block(&self, event: &SolidifiedBlockEvent) {
        self.publish(&self.solidity_topic, event);
    }
}
