//! Plugin loader. Maps a configured plugin name to an
//! [`EventListener`] implementation provided by a
//! [`PluginFactory`].
//!
//! ## How the loader fits into the config flow
//!
//! ```text
//!   config.conf event.subscribe.path = "/opt/tron/plugins/kafka.zip"
//!     ↓ (tron-node parses TOML → EventSubscribeConfig)
//!   tron-node builds PluginParams + picks plugin-id from path stem
//!     ↓
//!   PluginRegistry.build_bus(params, "kafka")
//!     ↓
//!   KafkaPluginFactory.build(&params) → Arc<dyn EventListener>
//!     ↓
//!   EventBus over the single listener
//! ```
//!
//! Plugin authors implement [`PluginFactory`] and register an
//! instance at startup. The registry doesn't actually load `.zip` /
//! `.so` files — that's a Java-only mechanism and out of scope.
//! Rust consumers compile their listener into the binary or expose
//! it as a separate crate and register the factory in
//! `tron-node`'s `main`.

use std::sync::Arc;

use crate::bus::EventBus;
use crate::listener::EventListener;

/// Knobs passed from the operator's `event.subscribe.*` config to
/// each plugin factory. Mirrors java-tron's `EventPluginConfig`
/// 1:1 except `topics` is the resolved per-trigger enable table
/// (java-tron derives the same set internally).
#[derive(Debug, Clone, Default)]
pub struct PluginParams {
    /// Filesystem path to the plugin (`.zip` on JVM, `.so` / `.dylib`
    /// on native).
    pub path: String,
    /// Remote sink endpoint (Kafka brokers, NATS, etc.).
    pub server: String,
    /// Plugin-specific DB connection string (MongoDB URI, etc.).
    pub db_config: String,
    /// Bounded queue length; `0` means "unbounded" (matches
    /// java-tron's `sendQueueLength` default).
    pub send_queue_length: usize,
    /// Use the in-process ZeroMQ socket instead of the .zip pipeline.
    pub use_native_queue: bool,
    /// Bind port for the native-queue socket. Ignored when
    /// `use_native_queue = false`.
    pub bind_port: u16,
    /// Block number to begin replaying triggers from. `0` = "from
    /// current tip".
    pub start_sync_block_num: i64,
    /// Run the ABI decoder on contract logs before posting.
    pub contract_parse: bool,
    /// Per-trigger enable table.
    pub topics: Vec<TopicEnable>,
    /// Resolved `event.subscribe.filter` values — applied by wrapping
    /// the built listener in a
    /// [`FilteredListener`](crate::listeners::FilteredListener)
    /// inside [`PluginRegistry::build_bus`].
    pub filter: crate::listeners::TriggerFilter,
}

/// One row from `event.subscribe.topics[]`, resolved to a
/// trigger-name-keyed bool. Plugin factories use this to decide
/// whether to call back into the bus for a given trigger type.
#[derive(Debug, Clone, Default)]
pub struct TopicEnable {
    pub trigger_name: String,
    pub enabled: bool,
    pub topic: String,
    pub redundancy: bool,
    pub eth_compatible: bool,
    pub solidified: bool,
}

impl PluginParams {
    /// `true` when the named trigger has at least one enabled topic
    /// entry. Plugin factories can short-circuit on this to skip
    /// building expensive subscribers (a Kafka plugin that only sees
    /// `block` enabled doesn't need to subscribe to `contractevent`).
    pub fn is_trigger_enabled(&self, trigger_name: &str) -> bool {
        self.topics
            .iter()
            .any(|t| t.enabled && t.trigger_name.eq_ignore_ascii_case(trigger_name))
    }

    /// Find the resolved topic name for `trigger_name`, returning
    /// `""` when missing (matches java-tron's default).
    pub fn topic_for(&self, trigger_name: &str) -> &str {
        self.topics
            .iter()
            .find(|t| t.trigger_name.eq_ignore_ascii_case(trigger_name))
            .map(|t| t.topic.as_str())
            .unwrap_or("")
    }
}

/// Plugin-loader errors. Surfaced from
/// [`PluginRegistry::build_bus`] and the host `tron-node`
/// loader.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("no plugin factory registered for id {0:?}")]
    UnknownPlugin(String),
    #[error("plugin {id} rejected config: {reason}")]
    InvalidConfig { id: String, reason: String },
    #[error("plugin {id} init failed: {reason}")]
    InitFailed { id: String, reason: String },
}

/// Factory trait that plugin authors implement.
///
/// `id` is the discriminator name the config's `path` is reduced to
/// (e.g. `event.subscribe.path = "/opt/kafka.zip"` → id = `"kafka"`).
/// `build` is called once at node startup to produce the listener
/// instance. The factory may return [`PluginError::InvalidConfig`]
/// when required fields (e.g. `server` for a Kafka plugin) are
/// missing.
pub trait PluginFactory: Send + Sync {
    fn id(&self) -> &str;
    fn build(&self, params: &PluginParams) -> Result<Arc<dyn EventListener>, PluginError>;
}

/// Plugin registry. Cheap to clone — the inner Vec is shared.
#[derive(Default, Clone)]
pub struct PluginRegistry {
    factories: Vec<Arc<dyn PluginFactory>>,
}

impl PluginRegistry {
    /// Empty registry. Add factories via [`register`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a factory. Later registrations of the same `id`
    /// shadow earlier ones, so test setups can override production
    /// plugins.
    pub fn register<F: PluginFactory + 'static>(&mut self, f: F) -> &mut Self {
        self.factories.push(Arc::new(f));
        self
    }

    /// Same as [`register`] but takes an Arc — useful when the
    /// caller already has a shared instance.
    pub fn register_arc(&mut self, f: Arc<dyn PluginFactory>) -> &mut Self {
        self.factories.push(f);
        self
    }

    /// Number of registered factories.
    pub fn len(&self) -> usize {
        self.factories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }

    /// Resolve a config `path` file stem to a registered factory id:
    /// exact match first, then "stem CONTAINS id" (java plugin zips are
    /// named `plugin-kafka-1.0.0.zip` — the stem embeds the id).
    pub fn resolve_id(&self, stem: &str) -> Option<String> {
        let lower = stem.to_lowercase();
        if let Some(f) = self
            .factories
            .iter()
            .rev()
            .find(|f| f.id().eq_ignore_ascii_case(stem))
        {
            return Some(f.id().to_string());
        }
        self.factories
            .iter()
            .rev()
            .find(|f| lower.contains(&f.id().to_lowercase()))
            .map(|f| f.id().to_string())
    }

    /// Build a single-listener [`EventBus`] using the factory
    /// matching `plugin_id`. The most-recently-registered factory
    /// wins on duplicate ids.
    pub fn build_bus(
        &self,
        params: &PluginParams,
        plugin_id: &str,
    ) -> Result<EventBus, PluginError> {
        let factory = self
            .factories
            .iter()
            .rev()
            .find(|f| f.id().eq_ignore_ascii_case(plugin_id))
            .ok_or_else(|| PluginError::UnknownPlugin(plugin_id.to_string()))?;
        let listener = factory.build(params)?;
        let listener =
            crate::listeners::FilteredListener::wrap(listener, params.filter.clone());
        Ok(EventBus::new(vec![listener]))
    }

    /// Build a fan-out [`EventBus`] over **every** registered
    /// factory. Used when the operator wants every loaded plugin to
    /// see every trigger (java-tron doesn't support this — its
    /// loader picks exactly one plugin — but it's useful for tests
    /// and Rust consumers that compile in multiple listeners).
    pub fn build_fanout_bus(&self, params: &PluginParams) -> Result<EventBus, PluginError> {
        let mut listeners = Vec::with_capacity(self.factories.len());
        for f in &self.factories {
            listeners.push(f.build(params)?);
        }
        Ok(EventBus::new(listeners))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingFactory {
        id: &'static str,
        invocations: Arc<AtomicUsize>,
    }
    impl PluginFactory for CountingFactory {
        fn id(&self) -> &str {
            self.id
        }
        fn build(&self, _params: &PluginParams) -> Result<Arc<dyn EventListener>, PluginError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(NoopListener))
        }
    }

    struct NoopListener;
    impl EventListener for NoopListener {}

    struct RejectingFactory;
    impl PluginFactory for RejectingFactory {
        fn id(&self) -> &str {
            "needs-server"
        }
        fn build(&self, params: &PluginParams) -> Result<Arc<dyn EventListener>, PluginError> {
            if params.server.is_empty() {
                return Err(PluginError::InvalidConfig {
                    id: self.id().to_string(),
                    reason: "server endpoint required".into(),
                });
            }
            Ok(Arc::new(NoopListener))
        }
    }

    #[test]
    fn registry_finds_by_id_case_insensitive() {
        let mut reg = PluginRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        reg.register(CountingFactory {
            id: "kafka",
            invocations: calls.clone(),
        });
        let bus = reg
            .build_bus(&PluginParams::default(), "KAFKA")
            .expect("build");
        assert_eq!(bus.listener_count(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn registry_missing_plugin_errors() {
        let reg = PluginRegistry::new();
        let err = reg
            .build_bus(&PluginParams::default(), "anything")
            .unwrap_err();
        assert!(matches!(err, PluginError::UnknownPlugin(_)));
    }

    #[test]
    fn registry_later_registration_shadows_earlier() {
        let mut reg = PluginRegistry::new();
        let v1 = Arc::new(AtomicUsize::new(0));
        let v2 = Arc::new(AtomicUsize::new(0));
        reg.register(CountingFactory {
            id: "kafka",
            invocations: v1.clone(),
        });
        reg.register(CountingFactory {
            id: "kafka",
            invocations: v2.clone(),
        });
        reg.build_bus(&PluginParams::default(), "kafka").unwrap();
        assert_eq!(v1.load(Ordering::SeqCst), 0);
        assert_eq!(v2.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn factory_invalid_config_propagates() {
        let mut reg = PluginRegistry::new();
        reg.register(RejectingFactory);
        let err = reg
            .build_bus(&PluginParams::default(), "needs-server")
            .unwrap_err();
        assert!(matches!(err, PluginError::InvalidConfig { .. }));
    }

    #[test]
    fn fanout_bus_includes_every_listener() {
        let mut reg = PluginRegistry::new();
        let v1 = Arc::new(AtomicUsize::new(0));
        let v2 = Arc::new(AtomicUsize::new(0));
        reg.register(CountingFactory {
            id: "a",
            invocations: v1.clone(),
        });
        reg.register(CountingFactory {
            id: "b",
            invocations: v2.clone(),
        });
        let bus = reg.build_fanout_bus(&PluginParams::default()).unwrap();
        assert_eq!(bus.listener_count(), 2);
    }

    #[test]
    fn params_trigger_enabled_check() {
        let p = PluginParams {
            topics: vec![
                TopicEnable {
                    trigger_name: "block".into(),
                    enabled: true,
                    topic: "blocks".into(),
                    ..Default::default()
                },
                TopicEnable {
                    trigger_name: "transaction".into(),
                    enabled: false,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(p.is_trigger_enabled("block"));
        assert!(p.is_trigger_enabled("BLOCK")); // case-insensitive
        assert!(!p.is_trigger_enabled("transaction"));
        assert!(!p.is_trigger_enabled("nope"));
        assert_eq!(p.topic_for("block"), "blocks");
        assert_eq!(p.topic_for("nope"), "");
    }
}
