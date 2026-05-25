//! [`ChannelListener`] — forwards every trigger as a [`TriggerMessage`]
//! enum value over a tokio `mpsc` channel. The reference path for
//! in-process consumers (a metrics worker, an indexer co-located in
//! the same binary, an integration test).
//!
//! When the consumer falls behind, `try_send` returns Full and the
//! event is dropped after a `warn!` — the executor must never stall
//! waiting on a slow consumer.

use tokio::sync::mpsc;
use tracing::warn;

use crate::listener::EventListener;
use crate::trigger::{
    BlockEvent, ContractEvent, ContractLogEvent, SolidifiedBlockEvent, TransactionEvent,
};

/// Boxed trigger value, used to send heterogeneous trigger types over
/// a single channel.
#[derive(Debug, Clone)]
pub enum TriggerMessage {
    Block(BlockEvent),
    Transaction(TransactionEvent),
    ContractLog(ContractLogEvent),
    ContractEvent(ContractEvent),
    SolidifiedBlock(SolidifiedBlockEvent),
}

pub struct ChannelListener {
    tx: mpsc::Sender<TriggerMessage>,
}

impl ChannelListener {
    /// Build a listener + its receiver. The caller spawns a task that
    /// drains the receiver — anything it wants to do (forward to Kafka,
    /// log to a file, push to a counter) happens off the executor's
    /// thread.
    pub fn pair(buffer: usize) -> (Self, mpsc::Receiver<TriggerMessage>) {
        let (tx, rx) = mpsc::channel(buffer.max(1));
        (Self { tx }, rx)
    }

    fn try_emit(&self, msg: TriggerMessage) {
        if let Err(e) = self.tx.try_send(msg) {
            // `Full` is recoverable — we drop the event but the
            // consumer can catch up. `Closed` means the consumer task
            // exited; nothing to do.
            warn!(?e, "tron-eventer channel listener dropped a trigger");
        }
    }
}

impl EventListener for ChannelListener {
    fn on_block(&self, ev: &BlockEvent) {
        self.try_emit(TriggerMessage::Block(ev.clone()));
    }
    fn on_transaction(&self, ev: &TransactionEvent) {
        self.try_emit(TriggerMessage::Transaction(ev.clone()));
    }
    fn on_contract_log(&self, ev: &ContractLogEvent) {
        self.try_emit(TriggerMessage::ContractLog(ev.clone()));
    }
    fn on_contract_event(&self, ev: &ContractEvent) {
        self.try_emit(TriggerMessage::ContractEvent(ev.clone()));
    }
    fn on_solidified_block(&self, ev: &SolidifiedBlockEvent) {
        self.try_emit(TriggerMessage::SolidifiedBlock(ev.clone()));
    }
}
