//! Boot-time seeding of java-tron's block-version fork statistics
//! (`tron_chainbase::fork`) for data directories written before the node
//! recorded them. A converted java snapshot already carries `FORK_VERSION_*`
//! and `VERSION_NUMBER`, so this is a no-op there.

use std::collections::HashMap;

use tracing::{info, warn};
use tron_chainbase::{
    BlockIndexStore, BlockStore, DynamicPropertiesStore, WitnessScheduleStore,
};
use tron_crypto::address::Address;

use crate::storage::OpenedStores;

/// Two rounds of the 27-witness schedule: enough recent headers to see every
/// active witness's latest block version.
const HEADER_WINDOW: i64 = 60;

/// Seed the fork statistics from the most recent headers when the store has
/// none. Returns the latest passed version when seeding ran.
pub fn backfill_if_missing(stores: &OpenedStores) -> Option<i32> {
    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
    if dp.latest_fork_version() != 0
        || dp.fork_stats(tron_chainbase::fork::VERSION_4_8_2).is_some()
    {
        return None;
    }
    let head = dp.latest_block_header_number().unwrap_or(0);
    if head <= 0 {
        return None;
    }
    let active = match WitnessScheduleStore::new(stores.witness_schedule.clone()).load_active() {
        Ok(Some(active)) if !active.is_empty() => active,
        _ => return None,
    };
    let index = BlockIndexStore::new(stores.block_index.clone());
    let blocks = BlockStore::new(stores.blocks.clone());
    let mut latest_per_witness: HashMap<Address, i32> = HashMap::new();
    let lowest = (head - HEADER_WINDOW + 1).max(1);
    for num in (lowest..=head).rev() {
        let Ok(id) = index.get(num) else { continue };
        let Ok(block) = blocks.get(&id) else { continue };
        let Some(raw) = block.block_header.as_ref().and_then(|h| h.raw_data.as_ref()) else {
            continue;
        };
        if raw.witness_address.len() != 21 {
            continue;
        }
        let mut producer = [0u8; 21];
        producer.copy_from_slice(&raw.witness_address);
        latest_per_witness
            .entry(Address::from_raw(producer))
            .or_insert(raw.version);
    }
    if latest_per_witness.is_empty() {
        warn!(head, "fork statistics missing and no recent headers to seed them from");
        return None;
    }
    let seeded = tron_chainbase::backfill_fork_stats(&dp, &active, &latest_per_witness);
    if let Some(latest) = seeded {
        info!(
            head,
            latest_passed_version = latest,
            witnesses_seen = latest_per_witness.len(),
            "seeded block-version fork statistics from recent headers"
        );
    }
    seeded
}
