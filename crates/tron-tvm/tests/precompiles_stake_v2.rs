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

/// A resource-type word built from raw bytes, so a test can set the high 24
/// bytes or the low word's sign bit — the inputs `type_word` cannot express.
fn raw_type_word(bytes: [u8; 32]) -> [u8; 32] {
    bytes
}

/// A resource-type word whose low 8 bytes are `lo` and whose byte at index
/// `hi_idx` (0..24) is `hi`. `hi_idx = None` leaves the high bytes clear.
fn wide_type_word(hi_idx: Option<usize>, hi: u8, lo: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&lo.to_be_bytes());
    if let Some(i) = hi_idx {
        w[i] = hi;
    }
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
    // java `queryAvailableUnfreezeV2Size` returns 0 when the account is absent.
    let ctx = MockCtx::default();
    let out = PrecompileImpl::AvailableUnfreezeV2Size
        .execute(&addr_word(&alice()), &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 0);
}

// =============================================================================
// UnfreezableBalanceV2 — 0x0100000d
// =============================================================================

#[test]
fn unfreezable_balance_v2_returns_frozen_v2_balance() {
    // java `queryUnfreezableBalanceV2` = the currently-frozen v2 balance for
    // the resource (eligible to be unfrozen), NOT the already-unfrozen amount.
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 700);
    // Pending unfreezes are irrelevant to this precompile.
    acct.unfrozen_v2 = vec![UnFreezeV2 {
        r#type: 0,
        unfreeze_amount: 999,
        unfreeze_expire_time: 1,
    }];
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::UnfreezableBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 700);
}

#[test]
fn unfreezable_balance_v2_filters_by_resource_type() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 100); // bandwidth frozen-v2
    acct.frozen_v2.push(FreezeV2Entry {
        r#type: 1,
        amount: 999,
    }); // energy frozen-v2
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    let out = PrecompileImpl::UnfreezableBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 100); // bandwidth only, not 999 energy
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
    // Expiry is in ms; the `time` arg is in SECONDS (×1000). No type filter.
    acct.unfrozen_v2 = vec![
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 100,
            unfreeze_expire_time: 4_000_000,
        },
        UnFreezeV2 {
            r#type: 1, // different type — still counted
            unfreeze_amount: 200,
            unfreeze_expire_time: 7_000_000,
        },
        UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 50,
            unfreeze_expire_time: 9_000_000,
        },
    ];
    put_account(&mut ctx, alice(), acct);
    // time = 7_500 s → 7_500_000 ms; first two entries mature, last not.
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&long_word(7_500));
    let out = PrecompileImpl::ExpireUnfreezeBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 300);
}

#[test]
fn expire_unfreeze_balance_v2_zero_for_wrong_input_length() {
    let ctx = MockCtx::default();
    let out = PrecompileImpl::ExpireUnfreezeBalanceV2
        .execute(&[0u8; 96], &ctx) // 3 words — java wants exactly 2
        .unwrap();
    assert_eq!(read_long(&out), 0);
}

// =============================================================================
// DelegatableResource — 0x0100000f
// =============================================================================

#[test]
fn delegatable_resource_is_full_frozen_when_no_usage() {
    // java `queryDelegatableResource` = frozenV2 - v2Usage. With no current
    // usage the whole frozen-v2 balance is delegatable (delegated-out is NOT
    // subtracted — that was the old placeholder's formula).
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
    assert_eq!(read_long(&out), 1000);
}

#[test]
fn delegatable_resource_subtracts_v2_usage() {
    // frozenV2=5_000, usageBalance=1_000, no v1/acquired → v2Usage=1_000;
    // delegatable = 5_000 - 1_000 = 4_000.
    let mut ctx = MockCtx::default();
    ctx.block_timestamp_ms = 3_000_000; // now_slot 1_000
    ctx.chain_params.insert(b"TOTAL_ENERGY_WEIGHT".to_vec(), 1_000);
    ctx.chain_params
        .insert(b"TOTAL_ENERGY_CURRENT_LIMIT".to_vec(), 28_800_000_000);
    let mut acct = freeze_v2_account(alice(), 1, 5_000);
    acct.account_resource = Some(AccountResource {
        energy_usage: 28_800,
        latest_consume_time_for_energy: 1_000,
        energy_window_size: 0,
        ..Default::default()
    });
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(1));
    let out = PrecompileImpl::DelegatableResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 4_000);
}

// =============================================================================
// ResourceV2 — 0x01000010 (just `frozen_v2[type]`)
// =============================================================================

/// 3-word `(target, from, type)` ResourceV2 input.
fn resource_v2_input(target: &Address, from: &Address, rtype: i32) -> [u8; 96] {
    let mut input = [0u8; 96];
    input[..32].copy_from_slice(&addr_word(target));
    input[32..64].copy_from_slice(&addr_word(from));
    input[64..96].copy_from_slice(&type_word(rtype));
    input
}

#[test]
fn resource_v2_self_returns_frozen_amount_for_resource() {
    let mut ctx = MockCtx::default();
    let mut acct = freeze_v2_account(alice(), 0, 555);
    acct.frozen_v2.push(FreezeV2Entry {
        r#type: 1,
        amount: 222,
    });
    put_account(&mut ctx, alice(), acct);
    // from == target → own frozen-v2 balance per type.
    let out_bw = PrecompileImpl::ResourceV2
        .execute(&resource_v2_input(&alice(), &alice(), 0), &ctx)
        .unwrap();
    assert_eq!(read_long(&out_bw), 555);
    let out_en = PrecompileImpl::ResourceV2
        .execute(&resource_v2_input(&alice(), &alice(), 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&out_en), 222);
}

#[test]
fn resource_v2_cross_returns_delegated_amount() {
    let mut ctx = MockCtx::default();
    ctx.delegated_resources.insert(
        (alice(), bob()),
        DelegatedResource {
            from: alice().as_bytes().to_vec(),
            to: bob().as_bytes().to_vec(),
            frozen_balance_for_bandwidth: 321,
            ..Default::default()
        },
    );
    let out = PrecompileImpl::ResourceV2
        .execute(&resource_v2_input(&bob(), &alice(), 0), &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 321);
}

#[test]
fn resource_v2_zero_for_unknown_account() {
    let ctx = MockCtx::default();
    // from == target, missing account → 0.
    let out = PrecompileImpl::ResourceV2
        .execute(&resource_v2_input(&alice(), &alice(), 0), &ctx)
        .unwrap();
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
fn resource_usage_returns_balance_restore_pair() {
    // java ResourceUsage = the two-word (usageBalanceInSun, restoreSeconds)
    // pair — NOT the raw usage counter. Same math as CheckUnDelegateResource.
    let mut ctx = MockCtx::default();
    ctx.block_timestamp_ms = 3_000_000; // now_slot 1_000
    ctx.chain_params.insert(b"TOTAL_ENERGY_WEIGHT".to_vec(), 1_000);
    ctx.chain_params
        .insert(b"TOTAL_ENERGY_CURRENT_LIMIT".to_vec(), 28_800_000_000);
    let mut acct = Account {
        address: alice().as_bytes().to_vec(),
        r#type: AccountType::Normal as i32,
        ..Default::default()
    };
    acct.account_resource = Some(AccountResource {
        energy_usage: 28_800,
        latest_consume_time_for_energy: 1_000,
        energy_window_size: 0,
        ..Default::default()
    });
    put_account(&mut ctx, alice(), acct);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(1));
    let out = PrecompileImpl::ResourceUsage.execute(&input, &ctx).unwrap();
    assert_eq!(out.len(), 64);
    assert_eq!(read_long(&out[0..32]), 1_000, "usage balance");
    assert_eq!(read_long(&out[32..64]), 86_400, "restore seconds");
}

#[test]
fn resource_usage_zero_pair_for_fully_recovered_account() {
    // now far past the usage window → (0, 0).
    let mut ctx = MockCtx::default();
    ctx.block_timestamp_ms = 200_000_000;
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
    assert_eq!(read_long(&out[0..32]), 0);
    assert_eq!(read_long(&out[32..64]), 0);
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

/// The semantic relation between the 5 query precompiles (java semantics):
///   resource_v2(self)   = own_frozen_v2
///   delegatable         = own_frozen_v2 - v2_usage  (== own_frozen_v2 at zero usage)
///   total_resource      = own_frozen_v2 + acquired_delegated  (+ v1 sources)
///   total_delegated     = own_delegated (v1 + v2)
///   total_acquired      = acquired_delegated (v1 + v2)
///
/// Pinning these as a single test catches accidental cross-wiring. (No usage
/// is set, so `delegatable == frozen`.)
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

    let frozen = read_long(
        &PrecompileImpl::ResourceV2
            .execute(&resource_v2_input(&alice(), &alice(), 0), &ctx)
            .unwrap(),
    );
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
    assert_eq!(delegatable, 1_000_000); // no usage → full frozen is delegatable
    assert_eq!(total_resource, 1_100_000);
    assert_eq!(total_delegated, 300_000);
    assert_eq!(total_acquired, 100_000);
    // Identity: total_resource - acquired == frozen.
    assert_eq!(total_resource - total_acquired, frozen);
}

// =============================================================================
// Resource-type word decode — java `DataWord.longValueSafe()`
// =============================================================================
//
// Every type-taking FreezeV2 precompile reads its type word with
// `longValueSafe()`: 64-bit, saturating to `Long.MAX_VALUE` when the word
// occupies more than eight bytes or when its low eight bytes read as a
// negative `long`. The comparison against 0 / 1 / 2 is then on the full
// `long`, so any word that is not numerically 0, 1 or 2 selects no resource
// and yields that precompile's zero-shaped result. Ungated: java has decoded
// these words this way since the precompiles were introduced.

/// An account with distinct non-zero balances for every resource, so a
/// wrongly-decoded type word produces a loudly non-zero answer.
fn well_funded() -> Account {
    let mut acct = freeze_v2_account(alice(), 0, 700);
    acct.frozen_v2.push(FreezeV2Entry {
        r#type: 1,
        amount: 900,
    });
    acct.frozen_v2.push(FreezeV2Entry {
        r#type: 2,
        amount: 1_300,
    });
    acct.delegated_frozen_v2_balance_for_bandwidth = 300;
    acct.acquired_delegated_frozen_v2_balance_for_bandwidth = 100;
    acct.account_resource = Some(AccountResource {
        delegated_frozen_v2_balance_for_energy: 500,
        acquired_delegated_frozen_v2_balance_for_energy: 200,
        ..Default::default()
    });
    acct
}

/// Assert that `type_word` selects no resource at every type-taking
/// precompile: each must return its zero-shaped result.
fn assert_type_word_selects_nothing(label: &str, tw: [u8; 32]) {
    let mut ctx = MockCtx::default();
    put_account(&mut ctx, alice(), well_funded());
    // A delegation row so ResourceV2's cross branch has something to return.
    ctx.delegated_resources.insert(
        (bob(), alice()),
        DelegatedResource {
            from: bob().as_bytes().to_vec(),
            to: alice().as_bytes().to_vec(),
            frozen_balance_for_bandwidth: 4_000,
            frozen_balance_for_energy: 5_000,
            ..Default::default()
        },
    );
    put_account(&mut ctx, bob(), well_funded());

    let mut two_word = [0u8; 64];
    two_word[..32].copy_from_slice(&addr_word(&alice()));
    two_word[32..64].copy_from_slice(&tw);

    for p in [
        PrecompileImpl::UnfreezableBalanceV2,
        PrecompileImpl::DelegatableResource,
        PrecompileImpl::TotalResource,
        PrecompileImpl::TotalDelegatedResource,
        PrecompileImpl::TotalAcquiredResource,
    ] {
        let out = p.execute(&two_word, &ctx).unwrap();
        assert_eq!(out, vec![0u8; 32], "{label}: {p:?} must select no resource");
    }
    // ResourceUsage returns two words.
    let out = PrecompileImpl::ResourceUsage.execute(&two_word, &ctx).unwrap();
    assert_eq!(out, vec![0u8; 64], "{label}: ResourceUsage must be two zeros");

    // ResourceV2: both the self branch and the cross-delegation branch.
    let mut self_input = [0u8; 96];
    self_input[..32].copy_from_slice(&addr_word(&alice()));
    self_input[32..64].copy_from_slice(&addr_word(&alice()));
    self_input[64..96].copy_from_slice(&tw);
    assert_eq!(
        PrecompileImpl::ResourceV2.execute(&self_input, &ctx).unwrap(),
        vec![0u8; 32],
        "{label}: ResourceV2 self branch must select no resource"
    );
    let mut cross_input = [0u8; 96];
    cross_input[..32].copy_from_slice(&addr_word(&alice()));
    cross_input[32..64].copy_from_slice(&addr_word(&bob()));
    cross_input[64..96].copy_from_slice(&tw);
    assert_eq!(
        PrecompileImpl::ResourceV2.execute(&cross_input, &ctx).unwrap(),
        vec![0u8; 32],
        "{label}: ResourceV2 cross branch must select no resource"
    );

    // CheckUnDelegateResource: three words (target, amount, type) with a
    // positive amount, so a mis-decode yields a non-zero triple.
    let mut check_input = [0u8; 96];
    check_input[..32].copy_from_slice(&addr_word(&alice()));
    check_input[32..64].copy_from_slice(&long_word(100));
    check_input[64..96].copy_from_slice(&tw);
    assert_eq!(
        PrecompileImpl::CheckUnDelegateResource
            .execute(&check_input, &ctx)
            .unwrap(),
        vec![0u8; 96],
        "{label}: CheckUnDelegateResource must return three zero words"
    );
}

#[test]
fn wide_type_word_selects_no_resource() {
    // byte[23] = 0x01, everything else zero → numeric value 2^64;
    // `bytesOccupied() == 9 > 8` → Long.MAX_VALUE → matches no arm.
    assert_type_word_selects_nothing("2^64", wide_type_word(Some(23), 0x01, 0));
}

#[test]
fn negative_low_word_type_selects_no_resource() {
    // Low 8 bytes = 0x8000_0000_0000_0000 (i64::MIN) → `longValue() < 0` →
    // Long.MAX_VALUE.
    assert_type_word_selects_nothing("i64::MIN", wide_type_word(None, 0, 1u64 << 63));
}

#[test]
fn type_word_above_u32_range_selects_no_resource() {
    // Values that a 32-bit narrowing would fold onto 0 and 1 respectively.
    assert_type_word_selects_nothing("2^32", wide_type_word(None, 0, 1u64 << 32));
    assert_type_word_selects_nothing("2^32 + 1", wide_type_word(None, 0, (1u64 << 32) + 1));
}

#[test]
fn type_word_i64_max_selects_no_resource() {
    // Exactly `Long.MAX_VALUE`, the value `longValueSafe` synthesises on
    // overflow. Guards the `i64::MAX as i32 == -1` coincidence that used to
    // save ResourceV2/CheckUnDelegateResource from the narrowing bug.
    assert_type_word_selects_nothing("i64::MAX", wide_type_word(None, 0, i64::MAX as u64));
    // And the all-ones word, which saturates for both reasons at once.
    assert_type_word_selects_nothing("all ones", raw_type_word([0xffu8; 32]));
}

#[test]
fn type_word_three_selects_no_resource() {
    // An in-range but unknown type. Passes before and after the decode fix;
    // guards against the new match arms accidentally widening the set.
    assert_type_word_selects_nothing("3", wide_type_word(None, 0, 3));
}

#[test]
fn tron_power_type_still_returns_frozen_v2_power() {
    // java routes type 2 through `queryUnfreezableBalanceV2`, whose POWER arm
    // is `AccountCapsule.getTronPowerFrozenV2Balance()`. Only
    // UnfreezableBalanceV2 and ResourceV2's self branch have that arm; the
    // rest return zero for type 2. A careless "narrow to 0/1" fix regresses
    // this.
    let mut ctx = MockCtx::default();
    put_account(&mut ctx, alice(), well_funded());

    let tw = wide_type_word(None, 0, 2);
    let mut two_word = [0u8; 64];
    two_word[..32].copy_from_slice(&addr_word(&alice()));
    two_word[32..64].copy_from_slice(&tw);

    assert_eq!(
        read_long(&PrecompileImpl::UnfreezableBalanceV2.execute(&two_word, &ctx).unwrap()),
        1_300,
        "type 2 is the account's TRON_POWER frozen-v2 balance"
    );

    let mut self_input = [0u8; 96];
    self_input[..32].copy_from_slice(&addr_word(&alice()));
    self_input[32..64].copy_from_slice(&addr_word(&alice()));
    self_input[64..96].copy_from_slice(&tw);
    assert_eq!(
        read_long(&PrecompileImpl::ResourceV2.execute(&self_input, &ctx).unwrap()),
        1_300,
        "ResourceV2's self branch routes through queryUnfreezableBalanceV2"
    );

    // No type-2 arm anywhere else.
    for p in [
        PrecompileImpl::DelegatableResource,
        PrecompileImpl::TotalResource,
        PrecompileImpl::TotalDelegatedResource,
        PrecompileImpl::TotalAcquiredResource,
    ] {
        assert_eq!(
            p.execute(&two_word, &ctx).unwrap(),
            vec![0u8; 32],
            "{p:?} has no type-2 arm in java"
        );
    }
    assert_eq!(
        PrecompileImpl::ResourceUsage.execute(&two_word, &ctx).unwrap(),
        vec![0u8; 64],
        "queryFrozenBalanceUsage has no type-2 arm"
    );
    let mut check_input = [0u8; 96];
    check_input[..32].copy_from_slice(&addr_word(&alice()));
    check_input[32..64].copy_from_slice(&long_word(100));
    check_input[64..96].copy_from_slice(&tw);
    assert_eq!(
        PrecompileImpl::CheckUnDelegateResource
            .execute(&check_input, &ctx)
            .unwrap(),
        vec![0u8; 96],
        "checkUndelegateResource has no type-2 arm"
    );
}

#[test]
fn types_zero_and_one_are_unchanged_by_the_decode() {
    // The canonical in-range words must keep returning their real values.
    let mut ctx = MockCtx::default();
    put_account(&mut ctx, alice(), well_funded());
    for (rtype, frozen) in [(0i32, 700i64), (1, 900)] {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&addr_word(&alice()));
        input[32..64].copy_from_slice(&type_word(rtype));
        assert_eq!(
            read_long(&PrecompileImpl::UnfreezableBalanceV2.execute(&input, &ctx).unwrap()),
            frozen
        );
    }
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..64].copy_from_slice(&type_word(0));
    assert_eq!(
        read_long(&PrecompileImpl::TotalDelegatedResource.execute(&input, &ctx).unwrap()),
        300
    );
    assert_eq!(
        read_long(&PrecompileImpl::TotalAcquiredResource.execute(&input, &ctx).unwrap()),
        100
    );
    input[32..64].copy_from_slice(&type_word(1));
    assert_eq!(
        read_long(&PrecompileImpl::TotalDelegatedResource.execute(&input, &ctx).unwrap()),
        500
    );
    assert_eq!(
        read_long(&PrecompileImpl::TotalAcquiredResource.execute(&input, &ctx).unwrap()),
        200
    );
}

#[test]
fn check_un_delegate_resource_amount_word_still_clamps() {
    // The `amount` word keeps its unnarrowed `longValueSafe` decode: a word
    // with non-zero high bytes saturates to Long.MAX_VALUE and then clamps
    // via `min(amount, resourceLimit)`, exactly as java does. Untouched by
    // the type-word fix.
    let mut ctx = MockCtx::default();
    put_account(&mut ctx, alice(), well_funded());

    let mut saturating = [0u8; 96];
    saturating[..32].copy_from_slice(&addr_word(&alice()));
    saturating[32..64].copy_from_slice(&raw_type_word([0xffu8; 32])); // amount
    saturating[64..96].copy_from_slice(&type_word(0));
    let sat_out = PrecompileImpl::CheckUnDelegateResource
        .execute(&saturating, &ctx)
        .unwrap();

    // The same call with `amount` already at the clamp point.
    let limit = read_long(&{
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&addr_word(&alice()));
        input[32..64].copy_from_slice(&type_word(0));
        PrecompileImpl::TotalResource.execute(&input, &ctx).unwrap()
    });
    let mut clamped = [0u8; 96];
    clamped[..32].copy_from_slice(&addr_word(&alice()));
    clamped[32..64].copy_from_slice(&long_word(limit));
    clamped[64..96].copy_from_slice(&type_word(0));
    let clamped_out = PrecompileImpl::CheckUnDelegateResource
        .execute(&clamped, &ctx)
        .unwrap();

    assert_eq!(sat_out, clamped_out, "amount must clamp to the resource limit");
}
