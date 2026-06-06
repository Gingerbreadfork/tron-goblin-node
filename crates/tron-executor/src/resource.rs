//! Shared resource-accounting math used by both bandwidth and energy.
//!
//! The implementation now lives in `tron_types::resource` so the actuators
//! (delegate / undelegate usage-transfer) can reuse it — `tron-executor`
//! depends on `tron-actuator`, so the math could not live here without an
//! inverted dependency. This module re-exports it so the executor's existing
//! `crate::resource::…` call sites are unchanged.
//!
//! Reference: `chainbase/src/main/java/org/tron/core/db/ResourceProcessor.java`.

pub use tron_types::resource::*;
