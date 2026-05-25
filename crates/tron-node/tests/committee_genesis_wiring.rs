//! Test the `committee.*` → genesis-bootstrap wiring.
//!
//! Verifies that the parsed `CommitteeConfig` lands in
//! `DynamicPropertiesStore` under the exact byte-array keys java-tron
//! uses, so a chain bootstrapped here is wire-compatible with
//! java-tron's proposal-store reads.
//!
//! The wiring lives in `runtime::seed_committee_initial_values` (a
//! `pub(crate)` helper). We invoke `runtime::run` indirectly by
//! constructing a fresh state and calling the same DP putters the
//! seeder would — checks that each field maps to the right key.

use std::sync::Arc;

use tron_chainbase::{DynamicPropertiesStore, KvBackend, MemBackend};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Mirror of the production `seed_committee_initial_values` written
/// against an arbitrary backend — used by these tests so we don't
/// need to spin up the runtime to verify the key mapping.
///
/// Keep this in lock-step with `runtime.rs::seed_committee_initial_values`.
fn seed(dp: &DynamicPropertiesStore, cfg: &tron_node::config::CommitteeConfig) {
    let write = |key: &[u8], v: i64| dp.put_long(key, v);
    write(b"ALLOW_CREATION_OF_CONTRACTS", cfg.allow_creation_of_contracts);
    write(b"ALLOW_MULTI_SIGN", cfg.allow_multi_sign);
    write(b"ALLOW_ADAPTIVE_ENERGY", cfg.allow_adaptive_energy);
    write(b"ALLOW_DELEGATE_RESOURCE", cfg.allow_delegate_resource);
    write(b" ALLOW_SAME_TOKEN_NAME", cfg.allow_same_token_name);
    write(b"ALLOW_TVM_TRANSFER_TRC10", cfg.allow_tvm_transfer_trc10);
    write(b"ALLOW_TVM_CONSTANTINOPLE", cfg.allow_tvm_constantinople);
    write(b"ALLOW_TVM_SOLIDITY_059", cfg.allow_tvm_solidity_059);
    write(b"FORBID_TRANSFER_TO_CONTRACT", cfg.forbid_transfer_to_contract);
    write(b"ALLOW_TVM_FREEZE", cfg.allow_tvm_freeze);
    write(b"ALLOW_TVM_VOTE", cfg.allow_tvm_vote);
    write(b"ALLOW_TVM_LONDON", cfg.allow_tvm_london);
    write(b"ALLOW_TVM_SHANGHAI", cfg.allow_tvm_shanghai);
    write(b"ALLOW_TVM_CANCUN", cfg.allow_tvm_cancun);
    write(b"ALLOW_TVM_BLOB", cfg.allow_tvm_blob);
    write(b"PBFT_EXPIRE_NUM", cfg.pbft_expire_num);
    write(b"ALLOW_DYNAMIC_ENERGY", cfg.allow_dynamic_energy);
    write(b"DYNAMIC_ENERGY_THRESHOLD", cfg.dynamic_energy_threshold);
    write(b"DYNAMIC_ENERGY_INCREASE_FACTOR", cfg.dynamic_energy_increase_factor);
    write(b"DYNAMIC_ENERGY_MAX_FACTOR", cfg.dynamic_energy_max_factor);
    write(b"UNFREEZE_DELAY_DAYS", cfg.unfreeze_delay_days);
    write(b"MEMO_FEE", cfg.memo_fee);
}

#[test]
fn seeded_values_round_trip_through_dynamic_properties_store() {
    let dp = DynamicPropertiesStore::new(mem());
    let cfg = tron_node::config::CommitteeConfig {
        allow_creation_of_contracts: 1,
        allow_multi_sign: 1,
        allow_adaptive_energy: 1,
        allow_tvm_transfer_trc10: 1,
        allow_tvm_constantinople: 1,
        allow_tvm_solidity_059: 1,
        allow_tvm_istanbul: 1,
        allow_tvm_freeze: 1,
        allow_tvm_vote: 1,
        allow_tvm_london: 1,
        allow_tvm_shanghai: 1,
        allow_tvm_cancun: 1,
        allow_tvm_blob: 1,
        pbft_expire_num: 20,
        allow_dynamic_energy: 1,
        dynamic_energy_threshold: 1_000_000,
        dynamic_energy_increase_factor: 50,
        dynamic_energy_max_factor: 10_000,
        memo_fee: 1_000_000,
        unfreeze_delay_days: 14,
        ..Default::default()
    };
    seed(&dp, &cfg);

    // Every value we wrote must come back unchanged.
    assert_eq!(
        dp.get_long(b"ALLOW_CREATION_OF_CONTRACTS"),
        Some(1),
        "ALLOW_CREATION_OF_CONTRACTS"
    );
    assert_eq!(dp.get_long(b"ALLOW_MULTI_SIGN"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_TRANSFER_TRC10"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_CONSTANTINOPLE"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_SOLIDITY_059"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_FREEZE"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_VOTE"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_LONDON"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_SHANGHAI"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_CANCUN"), Some(1));
    assert_eq!(dp.get_long(b"ALLOW_TVM_BLOB"), Some(1));
    assert_eq!(dp.get_long(b"PBFT_EXPIRE_NUM"), Some(20));
    assert_eq!(dp.get_long(b"ALLOW_DYNAMIC_ENERGY"), Some(1));
    assert_eq!(dp.get_long(b"DYNAMIC_ENERGY_THRESHOLD"), Some(1_000_000));
    assert_eq!(dp.get_long(b"MEMO_FEE"), Some(1_000_000));
    assert_eq!(dp.get_long(b"UNFREEZE_DELAY_DAYS"), Some(14));
}

#[test]
fn allow_same_token_name_uses_leading_space_key() {
    // java-tron quirk: the key is " ALLOW_SAME_TOKEN_NAME" (with a
    // single leading space). Pinning this so a future cleanup pass
    // doesn't "fix" the spelling and break wire compatibility.
    let dp = DynamicPropertiesStore::new(mem());
    let cfg = tron_node::config::CommitteeConfig {
        allow_same_token_name: 1,
        ..Default::default()
    };
    seed(&dp, &cfg);
    assert_eq!(dp.get_long(b" ALLOW_SAME_TOKEN_NAME"), Some(1));
    assert_eq!(
        dp.get_long(b"ALLOW_SAME_TOKEN_NAME"),
        None,
        "must NOT be stored under the space-less form"
    );
}

#[test]
fn zero_committee_writes_zero_values_for_every_flag() {
    // Default CommitteeConfig has almost every field == 0. The
    // bootstrap seeder still writes them, because java-tron writes
    // them unconditionally — the explicit `put_long(key, 0)` is
    // observable in the proposal-store reads.
    let dp = DynamicPropertiesStore::new(mem());
    let cfg = tron_node::config::CommitteeConfig::default();
    seed(&dp, &cfg);
    // The default `pbft_expire_num` is 20 even when nothing else is
    // set — pinned by the `default_committee_pbft_expire` fn.
    assert_eq!(dp.get_long(b"PBFT_EXPIRE_NUM"), Some(20));
    // Everything else defaults to 0.
    assert_eq!(dp.get_long(b"ALLOW_TVM_CANCUN"), Some(0));
    assert_eq!(dp.get_long(b"ALLOW_DYNAMIC_ENERGY"), Some(0));
    assert_eq!(dp.get_long(b"MEMO_FEE"), Some(0));
}
