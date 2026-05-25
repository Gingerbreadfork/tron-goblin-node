//! `tron-node dump-state` — emit a snapshot of consensus-critical
//! chain state in a diff-friendly JSON format.
//!
//! Designed for the first-mainnet-sync debugging loop: run the node
//! until it diverges, then dump our state and compare against a
//! reference java-tron node's equivalent via JSON-RPC.
//!
//! What's included:
//!
//! * Head pointer trio (`latest_block_header_number`, `_timestamp`,
//!   `_hash`).
//! * `LATEST_SOLIDIFIED_BLOCK_NUM`.
//! * Chain-wide resource state: `TOTAL_NET_WEIGHT`, `TOTAL_NET_LIMIT`,
//!   `TOTAL_ENERGY_WEIGHT`, `TOTAL_ENERGY_CURRENT_LIMIT`,
//!   `PUBLIC_NET_USAGE`, `BLOCK_ENERGY_USAGE`.
//! * Fee accumulators: `TOTAL_TRANSACTION_COST`, `BURN_TRX_AMOUNT`,
//!   `TOTAL_CREATE_ACCOUNT_COST`.
//! * Active proposal numbers.
//! * Witness-set summary (active count, top witness's `total_produced`).
//!
//! What's deliberately NOT dumped (would be too large for a CLI dump,
//! and is recoverable via the RPC layer): full account list, all asset
//! issues, all delegations, all witness vote counts.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tron_chainbase::{DynamicPropertiesStore, KvBackend, WitnessStore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub head: HeadSnapshot,
    pub resources: ResourceSnapshot,
    pub fees: FeeSnapshot,
    pub witnesses: WitnessSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadSnapshot {
    pub latest_block_number: i64,
    pub latest_block_timestamp: i64,
    pub latest_block_hash_hex: String,
    pub latest_solidified_block_num: i64,
    pub next_maintenance_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub total_net_weight: i64,
    pub total_net_limit: i64,
    pub public_net_usage: i64,
    pub public_net_limit: i64,
    pub total_energy_weight: i64,
    pub total_energy_limit: i64,
    pub total_energy_current_limit: i64,
    pub total_energy_average_usage: i64,
    pub block_energy_usage: i64,
    pub allow_adaptive_energy: i64,
    pub energy_fee: i64,
    pub transaction_fee: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSnapshot {
    pub total_transaction_cost: i64,
    pub total_create_account_cost: i64,
    pub burn_trx_amount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSnapshot {
    /// Total number of witnesses on file (active + standby + retired).
    pub total_count: usize,
    /// Sum of `total_produced` across every witness — useful for
    /// cross-checking against block count divergences (each block
    /// bumps exactly one witness's counter).
    pub total_produced_sum: i64,
}

/// Read the snapshot from open store handles. Returns a `StateSnapshot`
/// suitable for JSON-serialising and diffing against a reference node.
pub fn snapshot(
    dyn_props_be: Arc<dyn KvBackend>,
    witnesses_be: Arc<dyn KvBackend>,
) -> StateSnapshot {
    let dp = DynamicPropertiesStore::new(dyn_props_be);
    let head_hash = dp
        .latest_block_header_hash()
        .ok()
        .flatten()
        .map(|h| hex::encode(h))
        .unwrap_or_default();

    let head = HeadSnapshot {
        latest_block_number: dp.latest_block_header_number().unwrap_or(0),
        latest_block_timestamp: dp.latest_block_header_timestamp().unwrap_or(0),
        latest_block_hash_hex: head_hash,
        latest_solidified_block_num: dp.latest_solidified_block_num().unwrap_or(0),
        next_maintenance_time: dp.next_maintenance_time().unwrap_or(0),
    };

    let resources = ResourceSnapshot {
        total_net_weight: dp.total_net_weight(),
        total_net_limit: dp.total_net_limit(),
        public_net_usage: dp.public_net_usage(),
        public_net_limit: dp.public_net_limit(),
        total_energy_weight: dp.total_energy_weight(),
        total_energy_limit: dp.total_energy_limit(),
        total_energy_current_limit: dp.total_energy_current_limit(),
        total_energy_average_usage: dp.total_energy_average_usage(),
        block_energy_usage: dp.block_energy_usage(),
        allow_adaptive_energy: dp.allow_adaptive_energy(),
        energy_fee: dp.energy_fee(),
        transaction_fee: dp.transaction_fee(),
    };

    let fees = FeeSnapshot {
        total_transaction_cost: dp.total_transaction_cost(),
        total_create_account_cost: dp.total_create_account_cost(),
        burn_trx_amount: dp.burn_trx_amount(),
    };

    let ws = WitnessStore::new(witnesses_be);
    let (total_count, total_produced_sum) = match ws.all() {
        Ok(all) => (
            all.len(),
            all.iter().map(|(_, w)| w.total_produced).sum::<i64>(),
        ),
        Err(_) => (0, 0),
    };
    let witnesses = WitnessSnapshot {
        total_count,
        total_produced_sum,
    };

    StateSnapshot {
        head,
        resources,
        fees,
        witnesses,
    }
}

/// Serialize to pretty-printed JSON for the CLI dump path.
pub fn snapshot_to_json(snapshot: &StateSnapshot) -> String {
    serde_json::to_string_pretty(snapshot)
        .expect("StateSnapshot has no non-serializable fields")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::MemBackend;
    use tron_proto::Witness;
    use tron_crypto::address::Address;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    #[test]
    fn empty_snapshot_has_all_defaults() {
        let snap = snapshot(mem(), mem());
        assert_eq!(snap.head.latest_block_number, 0);
        assert_eq!(snap.head.latest_block_hash_hex, "");
        assert_eq!(snap.resources.total_net_weight, 0);
        assert_eq!(snap.resources.total_net_limit, 43_200_000_000);
        assert_eq!(snap.resources.allow_adaptive_energy, 0);
        assert_eq!(snap.witnesses.total_count, 0);
    }

    #[test]
    fn snapshot_reflects_writes() {
        let dp_be = mem();
        let ws_be = mem();
        let dp = DynamicPropertiesStore::new(dp_be.clone());
        dp.save_latest_block_header_number(12_345);
        dp.save_latest_block_header_timestamp(1_700_000_000_000);
        dp.save_latest_block_header_hash(&[0xab; 32]);
        dp.save_total_net_weight(7_777);
        dp.save_total_energy_weight(8_888);
        dp.save_block_energy_usage(999);
        dp.put_long(b"BURN_TRX_AMOUNT", 12_345_678);

        let ws = WitnessStore::new(ws_be.clone());
        let mut addr = [0u8; 21];
        addr[0] = 0x41;
        addr[20] = 0xff;
        ws.put(
            &Address::from_raw(addr),
            &Witness {
                address: addr.to_vec(),
                total_produced: 1_000,
                ..Default::default()
            },
        );

        let snap = snapshot(dp_be, ws_be);
        assert_eq!(snap.head.latest_block_number, 12_345);
        assert_eq!(snap.head.latest_block_timestamp, 1_700_000_000_000);
        assert_eq!(snap.head.latest_block_hash_hex, "ab".repeat(32));
        assert_eq!(snap.resources.total_net_weight, 7_777);
        assert_eq!(snap.resources.total_energy_weight, 8_888);
        assert_eq!(snap.resources.block_energy_usage, 999);
        assert_eq!(snap.fees.burn_trx_amount, 12_345_678);
        assert_eq!(snap.witnesses.total_count, 1);
        assert_eq!(snap.witnesses.total_produced_sum, 1_000);

        let json = snapshot_to_json(&snap);
        assert!(json.contains("12345"));
        assert!(json.contains("ababab"));
    }
}
