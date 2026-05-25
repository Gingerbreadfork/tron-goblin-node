//! Event subscribe / logsfilter.
//!
//! Mirrors java-tron's `org.tron.common.logsfilter` subsystem. Pure
//! plumbing: define the trigger shapes, a listener trait, a fan-out
//! bus, two reference listeners. Concrete backends (Kafka, MongoDB,
//! external HTTP, on-disk log files) implement [`EventListener`] in
//! their own crates and register with an [`EventBus`].
//!
//! ## Integration
//!
//! The executor takes an `Option<EventBus>` and calls
//! [`EventBus::emit_block`] / `emit_transaction` after each block
//! applies. The bus checks `is_empty()` first so unconfigured nodes
//! skip the payload-construction cost.
//!
//! ## Wire compatibility
//!
//! Every trigger struct serializes to the exact JSON shape java-tron's
//! Kafka plugin produces (camelCase field names, same field set, same
//! types). A TronGrid worker pointed at our event stream sees the same
//! bytes it would from java-tron — no consumer-side translation.
//!
//! ## What this crate does NOT do
//!
//! * Plugin discovery from config (no `event.subscribe.*` parser yet —
//!   listeners are wired in code).
//! * Decoding events against the contract ABI to populate
//!   [`ContractEvent::topic_map`] / `data_map`. The hooks accept
//!   already-decoded triggers; ABI decoding lives in `tron-rpc::abi`
//!   and will plug in when the executor emit-path is built out.

pub mod bus;
pub mod emit;
pub mod listener;
pub mod listeners;
pub mod plugin;
pub mod trigger;

pub use bus::{EventBus, EventBusBuilder};
pub use emit::{emit_block_and_transactions, TxOutcomeSlice};
pub use listener::EventListener;
pub use plugin::{PluginError, PluginFactory, PluginParams, PluginRegistry, TopicEnable};
pub use trigger::{
    BlockEvent, ContractEvent, ContractLogEvent, SolidifiedBlockEvent, TransactionEvent,
};
