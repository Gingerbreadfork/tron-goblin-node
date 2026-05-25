//! Fan-out for trigger events.
//!
//! [`EventBus`] holds a vector of registered listeners and dispatches
//! each emitted trigger to every one. The bus itself is cheap to clone
//! (Arc'd internally) so callers can hand it to the executor, the
//! solidifier, and the VM tracer without thinking about lifetimes.
//!
//! Errors raised by listeners are absorbed — a misbehaving plugin
//! shouldn't be able to stall block application. Listeners that need
//! backpressure should buffer internally (mpsc::channel etc.).

use std::sync::Arc;

use crate::listener::EventListener;
use crate::trigger::{
    BlockEvent, ContractEvent, ContractLogEvent, SolidifiedBlockEvent, TransactionEvent,
};

#[derive(Clone, Default)]
pub struct EventBus {
    listeners: Arc<Vec<Arc<dyn EventListener>>>,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("listener_count", &self.listeners.len())
            .finish()
    }
}

impl EventBus {
    /// Build a bus over the given listeners. Listener order is
    /// preserved (each trigger is delivered in registration order).
    pub fn new(listeners: Vec<Arc<dyn EventListener>>) -> Self {
        Self {
            listeners: Arc::new(listeners),
        }
    }

    /// Builder-style: start with no listeners, add one at a time.
    pub fn builder() -> EventBusBuilder {
        EventBusBuilder::default()
    }

    /// Number of registered listeners. Mostly used in tests to verify
    /// wire-up; a healthy production bus has 1+.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Returns `true` when no listeners are registered. The executor
    /// uses this as a fast-path to skip building trigger payloads on
    /// nodes that don't subscribe to events.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }

    pub fn emit_block(&self, event: &BlockEvent) {
        for l in self.listeners.iter() {
            l.on_block(event);
        }
    }

    pub fn emit_transaction(&self, event: &TransactionEvent) {
        for l in self.listeners.iter() {
            l.on_transaction(event);
        }
    }

    pub fn emit_contract_log(&self, event: &ContractLogEvent) {
        for l in self.listeners.iter() {
            l.on_contract_log(event);
        }
    }

    pub fn emit_contract_event(&self, event: &ContractEvent) {
        for l in self.listeners.iter() {
            l.on_contract_event(event);
        }
    }

    pub fn emit_solidified_block(&self, event: &SolidifiedBlockEvent) {
        for l in self.listeners.iter() {
            l.on_solidified_block(event);
        }
    }
}

#[derive(Default)]
pub struct EventBusBuilder {
    listeners: Vec<Arc<dyn EventListener>>,
}

impl EventBusBuilder {
    pub fn add<L: EventListener + 'static>(mut self, listener: L) -> Self {
        self.listeners.push(Arc::new(listener));
        self
    }

    pub fn add_arc(mut self, listener: Arc<dyn EventListener>) -> Self {
        self.listeners.push(listener);
        self
    }

    pub fn build(self) -> EventBus {
        EventBus::new(self.listeners)
    }
}
