//! Bridge between the parsed `[event]` config section and
//! [`tron_eventer`]'s plugin registry.
//!
//! Where each side lives:
//!
//! * [`crate::config::EventSubscribeConfig`] — the TOML schema. Pure
//!   data, no plugin knowledge.
//! * [`tron_eventer::PluginRegistry`] — knows how to instantiate a
//!   named plugin into an [`EventBus`].
//! * [`build_event_bus`] — the glue in this module. Translates
//!   `EventSubscribeConfig` → `PluginParams` → `PluginRegistry` →
//!   `EventBus`.
//!
//! The runtime calls this once at startup. When `cfg.enable == false`
//! an **empty** `EventBus` is returned so the executor's
//! `bus.is_empty()` fast-path takes over and no triggers are built.

use tron_eventer::{EventBus, PluginParams, PluginRegistry, TopicEnable};

use crate::config::{EventSubscribeConfig, EventTopicConfig};

/// Errors from the event-bus loader.
#[derive(Debug, thiserror::Error)]
pub enum EventLoaderError {
    #[error(
        "event.subscribe.path is required when event.subscribe.enable = true (got empty string)"
    )]
    MissingPath,
    #[error(
        "event.subscribe.path {0:?} has no file stem (java-tron uses the file stem as the plugin id)"
    )]
    UnstemmablePath(String),
    #[error("plugin loader failed: {0}")]
    Plugin(#[from] tron_eventer::PluginError),
}

/// Build an [`EventBus`] from the parsed `[event]` config section
/// against the supplied plugin registry.
///
/// Behavior matrix:
/// * `cfg == None` → empty bus (no listeners, no payload cost).
/// * `cfg.enable == false` → empty bus (same fast-path).
/// * `cfg.enable == true` + missing `path` → [`EventLoaderError::MissingPath`].
/// * Otherwise: pick plugin by the path's file stem (java-tron's
///   convention) and delegate to [`PluginRegistry::build_bus`].
pub fn build_event_bus(
    cfg: Option<&EventSubscribeConfig>,
    registry: &PluginRegistry,
) -> Result<EventBus, EventLoaderError> {
    let Some(cfg) = cfg else {
        return Ok(EventBus::default());
    };
    if !cfg.enable {
        return Ok(EventBus::default());
    }
    if cfg.path.trim().is_empty() {
        return Err(EventLoaderError::MissingPath);
    }
    let plugin_id = std::path::Path::new(&cfg.path)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| EventLoaderError::UnstemmablePath(cfg.path.clone()))?
        .to_string();

    let params = PluginParams {
        path: cfg.path.clone(),
        server: cfg.server.clone(),
        db_config: cfg.db_config.clone(),
        send_queue_length: cfg.send_queue_length,
        use_native_queue: cfg.use_native_queue,
        bind_port: cfg.bind_port,
        start_sync_block_num: cfg.start_sync_block_num,
        contract_parse: cfg.contract_parse,
        topics: cfg.topics.iter().map(topic_to_enable).collect(),
    };

    let bus = registry.build_bus(&params, &plugin_id)?;
    Ok(bus)
}

fn topic_to_enable(t: &EventTopicConfig) -> TopicEnable {
    TopicEnable {
        trigger_name: t.trigger_name.clone(),
        enabled: t.enable,
        topic: t.topic.clone(),
        redundancy: t.redundancy,
        eth_compatible: t.eth_compatible,
        solidified: t.solidified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tron_eventer::{EventListener, PluginError, PluginFactory};

    struct AlwaysOk;
    impl PluginFactory for AlwaysOk {
        fn id(&self) -> &str {
            "kafka"
        }
        fn build(
            &self,
            _params: &PluginParams,
        ) -> Result<Arc<dyn EventListener>, PluginError> {
            Ok(Arc::new(Sink))
        }
    }
    struct Sink;
    impl EventListener for Sink {}

    fn enabled_cfg(path: &str) -> EventSubscribeConfig {
        EventSubscribeConfig {
            enable: true,
            path: path.into(),
            server: "127.0.0.1:9092".into(),
            ..Default::default()
        }
    }

    #[test]
    fn none_cfg_yields_empty_bus() {
        let reg = PluginRegistry::new();
        let bus = build_event_bus(None, &reg).expect("empty");
        assert!(bus.is_empty());
    }

    #[test]
    fn disabled_cfg_yields_empty_bus() {
        let reg = PluginRegistry::new();
        let cfg = EventSubscribeConfig::default(); // enable = false
        let bus = build_event_bus(Some(&cfg), &reg).expect("empty");
        assert!(bus.is_empty());
    }

    #[test]
    fn enabled_with_blank_path_errors() {
        let mut reg = PluginRegistry::new();
        reg.register(AlwaysOk);
        let cfg = EventSubscribeConfig {
            enable: true,
            ..Default::default()
        };
        let err = build_event_bus(Some(&cfg), &reg).unwrap_err();
        assert!(matches!(err, EventLoaderError::MissingPath));
    }

    #[test]
    fn enabled_with_unknown_plugin_errors() {
        let reg = PluginRegistry::new();
        let cfg = enabled_cfg("/opt/tron/plugins/mongodb.zip");
        let err = build_event_bus(Some(&cfg), &reg).unwrap_err();
        assert!(matches!(err, EventLoaderError::Plugin(PluginError::UnknownPlugin(_))));
    }

    #[test]
    fn enabled_with_registered_plugin_produces_one_listener() {
        let mut reg = PluginRegistry::new();
        reg.register(AlwaysOk);
        let cfg = enabled_cfg("/opt/tron/plugins/kafka.zip");
        let bus = build_event_bus(Some(&cfg), &reg).expect("ok");
        assert_eq!(bus.listener_count(), 1);
    }

    #[test]
    fn plugin_id_uses_path_file_stem() {
        // Tests that "/opt/tron/plugins/kafka.zip" → id "kafka" and
        // matches the registered factory id case-insensitively.
        struct UppercaseKafka;
        impl PluginFactory for UppercaseKafka {
            fn id(&self) -> &str {
                "KAFKA"
            }
            fn build(
                &self,
                _params: &PluginParams,
            ) -> Result<Arc<dyn EventListener>, PluginError> {
                Ok(Arc::new(Sink))
            }
        }
        let mut reg = PluginRegistry::new();
        reg.register(UppercaseKafka);
        let cfg = enabled_cfg("/opt/tron/plugins/kafka.zip"); // lowercase stem
        let bus = build_event_bus(Some(&cfg), &reg).expect("ok");
        assert_eq!(bus.listener_count(), 1);
    }

    #[test]
    fn topics_pass_through_intact() {
        struct EchoTopics(Arc<std::sync::Mutex<PluginParams>>);
        impl PluginFactory for EchoTopics {
            fn id(&self) -> &str {
                "echo"
            }
            fn build(
                &self,
                params: &PluginParams,
            ) -> Result<Arc<dyn EventListener>, PluginError> {
                *self.0.lock().unwrap() = params.clone();
                Ok(Arc::new(Sink))
            }
        }
        let captured = Arc::new(std::sync::Mutex::new(PluginParams::default()));
        let mut reg = PluginRegistry::new();
        reg.register(EchoTopics(captured.clone()));
        let mut cfg = enabled_cfg("/opt/tron/plugins/echo.zip");
        cfg.contract_parse = true;
        cfg.use_native_queue = true;
        cfg.bind_port = 7777;
        cfg.topics = vec![crate::config::EventTopicConfig {
            trigger_name: "block".into(),
            enable: true,
            topic: "blocks".into(),
            redundancy: true,
            eth_compatible: false,
            solidified: false,
        }];
        let _ = build_event_bus(Some(&cfg), &reg).expect("ok");
        let got = captured.lock().unwrap();
        assert_eq!(got.path, "/opt/tron/plugins/echo.zip");
        assert!(got.contract_parse);
        assert!(got.use_native_queue);
        assert_eq!(got.bind_port, 7777);
        assert_eq!(got.topics.len(), 1);
        assert_eq!(got.topics[0].trigger_name, "block");
        assert!(got.topics[0].redundancy);
        assert!(got.is_trigger_enabled("BLOCK"));
    }
}
