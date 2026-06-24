//! Fee-disposal helpers shared by the actuators and the executor.

use tron_crypto::address::Address;

use crate::{AccountStore, DynamicPropertiesStore, StoreError};

/// Dispose a fee the way java-tron does once it has been debited from the payer
/// (`WitnessCreateActuator.java:143-147`, `ReceiptCapsule.payEnergyBill:345-350`,
/// the `BandwidthProcessor` fee paths, etc.):
///
/// * `ALLOW_BLACKHOLE_OPTIMIZATION` (proposal #39/#49, mainnet ~block 33M)
///   ACTIVE → `burnTrx(fee)`, which bumps the `BURN_TRX_AMOUNT` counter and
///   leaves the blackhole account untouched.
/// * before it → credit the fee to the blackhole ACCOUNT's balance
///   (`Commons.adjustBalance(blackhole, +fee)`), with no counter bump.
///
/// Collapsing both arms to a burn (the prior approximation) diverges BOTH the
/// blackhole-account balance and `BURN_TRX_AMOUNT` on a from-genesis replay,
/// where the optimization is inactive for the first ~33M blocks. On the 83M
/// snapshot the optimization is long-active, so this reduces to `burn_trx`,
/// byte-identical to before.
pub fn dispose_fee_to_blackhole(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    fee: i64,
) -> Result<(), StoreError> {
    // java `Commons.adjustBalance` short-circuits a zero amount; the burn path is
    // likewise a no-op for 0, so nothing to do.
    if fee == 0 {
        return Ok(());
    }
    if dyn_props.support_blackhole_optimization() {
        dyn_props.burn_trx(fee);
    } else {
        // java `AccountStore.getBlackhole()` resolves the configured
        // `ACCOUNT_BLACKHOLE` address; on mainnet that is `MAINNET_ASSETS[2]`,
        // seeded at genesis (so the row is always present on a real chain).
        let blackhole = Address::from_raw(tron_types::MAINNET_ASSETS[2].address);
        if let Some(mut acct) = accounts.get(&blackhole)? {
            // `Commons.adjustBalance(.., +fee)`: a positive amount never takes the
            // insufficient-balance branch and never overflows for real fee sizes
            // (blackhole balance starts at i64::MIN and only climbs).
            acct.balance = acct.balance.wrapping_add(fee);
            accounts.put(&blackhole, &acct)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tron_proto::Account;

    use super::*;
    use crate::MemBackend;

    fn stores() -> (AccountStore, DynamicPropertiesStore) {
        (
            AccountStore::new(Arc::new(MemBackend::new())),
            DynamicPropertiesStore::new(Arc::new(MemBackend::new())),
        )
    }

    fn seed_blackhole(accounts: &AccountStore) -> Address {
        let bh = Address::from_raw(tron_types::MAINNET_ASSETS[2].address);
        accounts
            .put(
                &bh,
                &Account {
                    address: bh.as_bytes().to_vec(),
                    balance: i64::MIN, // genesis blackhole balance
                    ..Default::default()
                },
            )
            .unwrap();
        bh
    }

    #[test]
    fn pre_optimization_credits_the_blackhole_account() {
        let (accounts, dp) = stores();
        let bh = seed_blackhole(&accounts);
        // ALLOW_BLACKHOLE_OPTIMIZATION defaults to 0 (off).
        dispose_fee_to_blackhole(&accounts, &dp, 1_000).unwrap();
        assert_eq!(
            accounts.get(&bh).unwrap().unwrap().balance,
            i64::MIN + 1_000,
            "blackhole account credited"
        );
        assert_eq!(dp.burn_trx_amount(), 0, "no BURN_TRX_AMOUNT bump pre-optimization");
    }

    #[test]
    fn post_optimization_burns_and_leaves_account_untouched() {
        let (accounts, dp) = stores();
        let bh = seed_blackhole(&accounts);
        dp.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
        dispose_fee_to_blackhole(&accounts, &dp, 1_000).unwrap();
        assert_eq!(dp.burn_trx_amount(), 1_000, "burned post-optimization");
        assert_eq!(
            accounts.get(&bh).unwrap().unwrap().balance,
            i64::MIN,
            "blackhole account untouched once burning"
        );
    }

    #[test]
    fn zero_fee_is_a_noop() {
        let (accounts, dp) = stores();
        let bh = seed_blackhole(&accounts);
        dispose_fee_to_blackhole(&accounts, &dp, 0).unwrap();
        assert_eq!(dp.burn_trx_amount(), 0);
        assert_eq!(accounts.get(&bh).unwrap().unwrap().balance, i64::MIN);
    }
}
