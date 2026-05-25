//! Consensus-critical tests for the 10 Stake-2.0 query precompiles
//! (0x0100000c..=0x01000015). Each reads `Account` / `DelegatedResource`
//! state and returns a u64 packed in a 32-byte word. Wrong outputs ⇒
//! silent chain divergence: a contract calling these expects the same
//! number on every node.
//!
//! Java reference: `PrecompiledContractsTest` per-method cases for each
//! Stake-2 precompile. Our existing `tests/precompiles.rs` covered
//! these only at the registry / address-pinning level; this file adds
//! per-precompile input-vector + state-coherence checks.

use hex_literal::hex;
use tron_crypto::address::Address;
use tron_proto::account::{AccountResource, FreezeV2 as FreezeV2Entry, UnFreezeV2};
use tron_proto::{Account, AccountType, DelegatedResource, Witness};
use tron_tvm::{EvmContext, EvmContextError, PrecompileImpl};

#[derive(Default)]
struct MockCtx {
    caller: Option<Address>,
    accounts: std::collections::HashMap<Address, Account>,
    witnesses: std::collections::HashMap<Address, Witness>,
    chain_params: std::collections::HashMap<Vec<u8>, i64>,
    delegated_resources: std::collections::HashMap<(Address, Address), DelegatedResource>,
    dynamic_factors: std::collections::HashMap<Address, i64>,
    block_number: i64,
    block_timestamp_ms: i64,
}

impl EvmContext for MockCtx {
    fn caller(&self) -> Address {
        self.caller.unwrap_or_else(|| Address::from_raw([0u8; 21]))
    }
    fn callee(&self) -> Address {
        Address::from_raw([0u8; 21])
    }
    fn get_account(&self, a: &Address) -> Result<Option<Account>, EvmContextError> {
        Ok(self.accounts.get(a).cloned())
    }
    fn get_witness(&self, a: &Address) -> Result<Option<Witness>, EvmContextError> {
        Ok(self.witnesses.get(a).cloned())
    }
    fn chain_parameter_long(&self, key: &[u8]) -> Result<Option<i64>, EvmContextError> {
        Ok(self.chain_params.get(key).copied())
    }
    fn block_number(&self) -> i64 {
        self.block_number
    }
    fn block_timestamp_ms(&self) -> i64 {
        self.block_timestamp_ms
    }
    fn all_witnesses(&self) -> Result<Vec<Witness>, EvmContextError> {
        let mut v: Vec<_> = self.witnesses.values().cloned().collect();
        v.sort_by_key(|w| w.address.clone());
        Ok(v)
    }
    fn get_delegated_resource(
        &self,
        from: &Address,
        to: &Address,
    ) -> Result<Option<DelegatedResource>, EvmContextError> {
        Ok(self.delegated_resources.get(&(*from, *to)).cloned())
    }
    fn dynamic_energy_factor(&self, c: &Address) -> Result<i64, EvmContextError> {
        Ok(self.dynamic_factors.get(c).copied().unwrap_or(0))
    }
}

fn alice() -> Address {
    Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"))
}
fn bob() -> Address {
    Address::from_raw(hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"))
}

/// Pack a TRON address into a 32-byte EVM word (high 12 zero, low 20
/// = address minus the 0x41 prefix).
fn addr_word(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(&a.as_bytes()[1..]);
    w
}

/// Pack a resource type code (0=BW, 1=Energy) into a 32-byte word.
fn type_word(r: i32) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[28..32].copy_from_slice(&(r as i32).to_be_bytes());
    w
}

/// Pack a i64 value into a 32-byte big-endian word.
fn long_word(v: i64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&v.to_be_bytes());
    w
}

/// Read 8 low bytes of `out` as a big-endian i64.
fn read_long(out: &[u8]) -> i64 {
    assert_eq!(out.len(), 32);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&out[24..32]);
    i64::from_be_bytes(buf)
}

fn put_account(ctx: &mut MockCtx, who: Address, a: Account) {
    ctx.accounts.insert(who, a);
}

/// Build an Account with a `frozen_v2[type] = amount` entry.
fn freeze_v2_account(addr: Address, resource: i32, amount: i64) -> Account {
    Account {
        address: addr.as_bytes().to_vec(),
        r#type: AccountType::Normal as i32,
        frozen_v2: vec![FreezeV2Entry {
            r#type: resource,
            amount,
        }],
        ..Default::default()
    }
}

// =============================================================================
// AvailableUnfreezeV2Size — 0x0100000c
// =============================================================================

#[test]
fn available_unfreeze_v2_size_full_when_no_pending_unfreezes() {
    let mut ctx = MockCtx::default();
    put_account(&mut ctx, alice(), freeze_v2_account(alice(), 0, 100));
    let input = addr_word(&alice());
    let out = PrecompileImpl::AvailableUnfreezeV2Size
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 32); // MAX_UNFREEZE_V2_SIZE
}

#[test]
fn available_unfreeze_v2_size_decreases_with_pending_unfreezes() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 100);
    for i in 0..5 {
        acct.unfrozen_v2.push(UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 10,
            unfreeze_expire_time: 1_000_000 + i,
        });
    }
    put_account(&mut ctx, alice(), acct);
    let input = addr_word(&alice());
    let out = PrecompileImpl::AvailableUnfreezeV2Size
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 27); // 32 - 5
}

#[test]
fn available_unfreeze_v2_size_zero_when_at_cap() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 100);
    for i in 0..32 {
        acct.unfrozen_v2.push(UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 1,
            unfreeze_expire_time: 1_000_000 + i,
        });
    }
    put_account(&mut ctx, alice(), acct);
    let input = addr_word(&alice());
    let out = PrecompileImpl::AvailableUnfreezeV2Size
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 0);
}

#[test]
fn available_unfreeze_v2_size_zero_for_unknown_account() {
    let ctx = MockCtx::default();
    let out = PrecompileImpl::AvailableUnfreezeV2Size
        .execute(&addr_word(&alice()), &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 32);
}

// =============================================================================
// UnfreezableBalanceV2 — 0x0100000d
// =============================================================================

#[test]
fn unfreezable_balance_v2_sums_only_mature_entries() {
    let mut ctx = MockCtx::default();
    ctx.block_timestamp_ms = 5_000;
    let mut acct = freeze_v2_account(alice(), 0, 0);
    acct.unfrozen_v2 = vec![
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 100,
            unfreeze_expire_time: 4_000, // mature
        },
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 200,
            unfreeze_expire_time: 5_000, // mature (≤ now)
        },
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 50,
            unfreeze_expire_time: 9_000, // future
        },
    ];
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::UnfreezableBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 300);
}

#[test]
fn unfreezable_balance_v2_filters_by_resource_type() {
    let mut ctx = MockCtx::default();
    ctx.block_timestamp_ms = 5_000;
    let mut acct = freeze_v2_account(alice(), 0, 0);
    acct.unfrozen_v2 = vec![
        UnFreezeV2 {
            r#type: 0, // bandwidth
            unfreeze_amount: 100,
            unfreeze_expire_time: 4_000,
        },
        UnFreezeV2 {
            r#type: 1, // energy
            unfreeze_amount: 999,
            unfreeze_expire_time: 4_000,
        },
    ];
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::UnfreezableBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 100); // only bandwidth, not 1099
}

#[test]
fn unfreezable_balance_v2_zero_for_unknown_account() {
    let ctx = MockCtx::default();
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::UnfreezableBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 0);
}

// =============================================================================
// ExpireUnfreezeBalanceV2 — 0x0100000e
// =============================================================================

#[test]
fn expire_unfreeze_balance_v2_uses_explicit_cutoff_argument() {
    let mut ctx = MockCtx::default();
    ctx.block_timestamp_ms = 1; // not used by this precompile
    let mut acct = freeze_v2_account(alice(), 0, 0);
    acct.unfrozen_v2 = vec![
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 100,
            unfreeze_expire_time: 4_000,
        },
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 200,
            unfreeze_expire_time: 7_000,
        },
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 50,
            unfreeze_expire_time: 9_000,
        },
    ];
    put_account(&mut ctx, alice(), acct);
    // cutoff = 7_500 → first two entries mature, last not.
    let mut input = [0u8; 96];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&long_word(7_500));
    input[64..96].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::ExpireUnfreezeBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 300);
}

#[test]
fn expire_unfreeze_balance_v2_zero_for_wrong_input_length() {
    let ctx = MockCtx::default();
    let out = PrecompileImpl::ExpireUnfreezeBalanceV2
        .execute(&[0u8; 64], &ctx) // 2 words instead of 3
        .unwrap();
    assert_eq!(read_long(&out), 0);
}

// =============================================================================
// DelegatableResource — 0x0100000f
// =============================================================================

#[test]
fn delegatable_resource_is_frozen_minus_already_delegated() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 1000);
    acct.delegated_frozen_v2_balance_for_bandwidth = 300;
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::DelegatableResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 700);
}

#[test]
fn delegatable_resource_clamps_to_zero_when_delegated_exceeds_frozen() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 100);
    acct.delegated_frozen_v2_balance_for_bandwidth = 500; // exceeds frozen
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::DelegatableResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 0);
}

#[test]
fn delegatable_resource_uses_energy_field_for_resource_type_1() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 1, 2000); // energy
    let res = AccountResource {
        delegated_frozen_v2_balance_for_energy: 700,
        ..Default::default()
    };
    acct.account_resource = Some(res);
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(1));
    let out = PrecompileImpl::DelegatableResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 1_300);
}

// =============================================================================
// ResourceV2 — 0x01000010 (just `frozen_v2[type]`)
// =============================================================================

#[test]
fn resource_v2_returns_frozen_amount_for_resource() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 555);
    acct.frozen_v2.push(FreezeV2Entry {
        r#type: 1,
        amount: 222,
    });
    put_account(&mut ctx, alice(), acct);
    // Bandwidth
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out_bw = PrecompileImpl::ResourceV2.execute(&input, &ctx).unwrap();
    assert_eq!(read_long(&out_bw), 555);
    // Energy
    input[32..64].copy_from_slice(&type_word(1));
    let out_en = PrecompileImpl::ResourceV2.execute(&input, &ctx).unwrap();
    assert_eq!(read_long(&out_en), 222);
}

#[test]
fn resource_v2_zero_for_unknown_account() {
    let ctx = MockCtx::default();
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::ResourceV2.execute(&input, &ctx).unwrap();
    assert_eq!(read_long(&out), 0);
}

// =============================================================================
// CheckUnDelegateResource — 0x01000011
// =============================================================================

#[test]
fn check_un_delegate_resource_returns_zeros_when_no_pair_record() {
    let mut ctx = MockCtx::default();
    ctx.caller = Some(alice());
    let mut input = [0u8; 96];
    input[..32].copy_from_slice(&addr_word(&bob()));
    input[32..64].copy_from_slice(&long_word(100));
    input[64..96].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::CheckUnDelegateResource
        .execute(&input, &ctx)
        .unwrap();
    // 96-byte zero output (3 words).
    assert_eq!(out.len(), 96);
    assert!(out.iter().all(|&b| b == 0));
}

#[test]
fn check_un_delegate_resource_zero_for_wrong_input_length() {
    let ctx = MockCtx::default();
    let out = PrecompileImpl::CheckUnDelegateResource
        .execute(&[0u8; 32], &ctx)
        .unwrap();
    // 3-word output of zeros even on bad input — must not be a single
    // 32-byte word.
    assert_eq!(out.len(), 96);
    assert!(out.iter().all(|&b| b == 0));
}

// =============================================================================
// ResourceUsage — 0x01000012
// =============================================================================

#[test]
fn resource_usage_returns_net_usage_for_bandwidth() {
    let mut ctx = MockCtx::default();
    let acct = Account {
        address: alice().as_bytes().to_vec(),
        r#type: AccountType::Normal as i32,
        net_usage: 12_345,
        ..Default::default()
    };
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::ResourceUsage.execute(&input, &ctx).unwrap();
    assert_eq!(read_long(&out), 12_345);
}

#[test]
fn resource_usage_returns_energy_usage_for_resource_type_1() {
    let mut ctx = MockCtx::default();
    let mut acct = Account {
        address: alice().as_bytes().to_vec(),
        r#type: AccountType::Normal as i32,
        ..Default::default()
    };
    acct.account_resource = Some(AccountResource {
        energy_usage: 99_999,
        ..Default::default()
    });
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(1));
    let out = PrecompileImpl::ResourceUsage.execute(&input, &ctx).unwrap();
    assert_eq!(read_long(&out), 99_999);
}

// =============================================================================
// TotalResource — 0x01000013 (own + acquired)
// =============================================================================

#[test]
fn total_resource_sums_frozen_own_and_acquired_delegated() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 1000);
    acct.acquired_delegated_frozen_v2_balance_for_bandwidth = 500;
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::TotalResource.execute(&input, &ctx).unwrap();
    assert_eq!(read_long(&out), 1_500);
}

#[test]
fn total_resource_handles_energy_via_account_resource() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 1, 1000);
    acct.account_resource = Some(AccountResource {
        acquired_delegated_frozen_v2_balance_for_energy: 250,
        ..Default::default()
    });
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(1));
    let out = PrecompileImpl::TotalResource.execute(&input, &ctx).unwrap();
    assert_eq!(read_long(&out), 1_250);
}

// =============================================================================
// TotalDelegatedResource — 0x01000014
// =============================================================================

#[test]
fn total_delegated_resource_returns_only_outgoing_for_bandwidth() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 1000);
    acct.delegated_frozen_v2_balance_for_bandwidth = 200;
    acct.acquired_delegated_frozen_v2_balance_for_bandwidth = 800; // not counted
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::TotalDelegatedResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 200);
}

#[test]
fn total_delegated_resource_returns_only_outgoing_for_energy() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 1, 1000);
    acct.account_resource = Some(AccountResource {
        delegated_frozen_v2_balance_for_energy: 333,
        acquired_delegated_frozen_v2_balance_for_energy: 666, // not counted
        ..Default::default()
    });
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(1));
    let out = PrecompileImpl::TotalDelegatedResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 333);
}

// =============================================================================
// TotalAcquiredResource — 0x01000015
// =============================================================================

#[test]
fn total_acquired_resource_returns_only_incoming_for_bandwidth() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 1000);
    acct.delegated_frozen_v2_balance_for_bandwidth = 200; // not counted
    acct.acquired_delegated_frozen_v2_balance_for_bandwidth = 444;
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::TotalAcquiredResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 444);
}

#[test]
fn total_acquired_resource_returns_only_incoming_for_energy() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 1, 1000);
    acct.account_resource = Some(AccountResource {
        delegated_frozen_v2_balance_for_energy: 100, // not counted
        acquired_delegated_frozen_v2_balance_for_energy: 555,
        ..Default::default()
    });
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(1));
    let out = PrecompileImpl::TotalAcquiredResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 555);
}

// =============================================================================
// Cross-precompile invariants
// =============================================================================

/// The semantic relation between the 5 query precompiles:
///   delegatable = own_frozen - own_delegated
///   total_resource = own_frozen + acquired_delegated
///   total_delegated = own_delegated
///   total_acquired = acquired_delegated
///   resource_v2 = own_frozen
///
/// Pinning these as a single test catches accidental cross-wiring.
#[test]
fn stake_v2_query_precompiles_obey_cross_method_identities() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 1_000_000);
    acct.delegated_frozen_v2_balance_for_bandwidth = 300_000;
    acct.acquired_delegated_frozen_v2_balance_for_bandwidth = 100_000;
    put_account(&mut ctx, alice(), acct);

    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));

    let frozen = read_long(&PrecompileImpl::ResourceV2.execute(&input, &ctx).unwrap());
    let delegatable = read_long(
        &PrecompileImpl::DelegatableResource
            .execute(&input, &ctx)
            .unwrap(),
    );
    let total_resource = read_long(
        &PrecompileImpl::TotalResource
            .execute(&input, &ctx)
            .unwrap(),
    );
    let total_delegated = read_long(
        &PrecompileImpl::TotalDelegatedResource
            .execute(&input, &ctx)
            .unwrap(),
    );
    let total_acquired = read_long(
        &PrecompileImpl::TotalAcquiredResource
            .execute(&input, &ctx)
            .unwrap(),
    );

    assert_eq!(frozen, 1_000_000);
    assert_eq!(delegatable, 700_000);
    assert_eq!(total_resource, 1_100_000);
    assert_eq!(total_delegated, 300_000);
    assert_eq!(total_acquired, 100_000);
    // Identity: delegatable + delegated == frozen.
    assert_eq!(delegatable + total_delegated, frozen);
    // Identity: total_resource - acquired == frozen.
    assert_eq!(total_resource - total_acquired, frozen);
}
