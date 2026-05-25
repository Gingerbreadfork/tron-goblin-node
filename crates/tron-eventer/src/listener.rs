//! `EventListener` trait — implementors are plugins that receive
//! triggers. java-tron's equivalent is `IPluginEventListener`.
//!
//! Listeners must be `Send + Sync` because the executor calls them from
//! the block-application path which can run on any tokio worker.
//! Default methods are no-ops so a listener can opt into just the
//! trigger types it cares about (a Kafka block-topic plugin doesn't
//! need to handle contract-log triggers).
//!
//! All methods take `&self` (not `&mut self`) so the bus can fan out
//! without holding a write-lock — listeners that need internal state
//! should use interior mutability (Mutex, atomics).

use crate::trigger::{
    BlockEvent, ContractEvent, ContractLogEvent, SolidifiedBlockEvent, TransactionEvent,
};

pub trait EventListener: Send + Sync {
    fn on_block(&self, _event: &BlockEvent) {}
    fn on_transaction(&self, _event: &TransactionEvent) {}
    fn on_contract_log(&self, _event: &ContractLogEvent) {}
    fn on_contract_event(&self, _event: &ContractEvent) {}
    fn on_solidified_block(&self, _event: &SolidifiedBlockEvent) {}
}
