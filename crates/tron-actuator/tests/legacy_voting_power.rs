use std::sync::Arc;
use tron_actuator::freeze_v2::{execute_freeze_balance_v2, validate_freeze_balance_v2};
use tron_chainbase::{AccountStore, DynamicPropertiesStore, MemBackend};
use tron_crypto::address::Address;
use tron_proto::account::FreezeV2;
use tron_proto::{Account, FreezeBalanceV2Contract};

#[test]
fn native_first_v2_stake_preserves_only_existing_legacy_power() {
    for (new_model, legacy, expected_old) in [(1, 0, -1), (1, 7_000_000, 7_000_000), (0, 0, 0)] {
        let accounts = AccountStore::new(Arc::new(MemBackend::new()));
        let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()));
        dp.put_long(b"ALLOW_NEW_RESOURCE_MODEL", new_model);
        dp.put_long(b"UNFREEZE_DELAY_DAYS", 1);
        let mut bytes = [0x44; 21];
        bytes[0] = 0x41;
        let owner = Address::from_raw(bytes);
        accounts
            .put(
                &owner,
                &Account {
                    address: bytes.to_vec(),
                    balance: 1_000_000_000,
                    frozen_v2: if legacy == 0 {
                        vec![]
                    } else {
                        vec![FreezeV2 {
                            r#type: 1,
                            amount: legacy,
                        }]
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        for _ in 0..2 {
            let stake = FreezeBalanceV2Contract {
                owner_address: bytes.to_vec(),
                frozen_balance: 2_000_000,
                resource: 1,
            };
            validate_freeze_balance_v2(&accounts, &dp, &stake).unwrap();
            execute_freeze_balance_v2(&accounts, &dp, &stake).unwrap();
            let account = accounts.get(&owner).unwrap().unwrap();
            assert_eq!(account.old_tron_power, expected_old);
            if new_model == 1 {
                assert_eq!(tron_tvm::votes::all_tron_power(&account), legacy);
            }
        }
        if new_model == 1 {
            let stake = FreezeBalanceV2Contract {
                owner_address: bytes.to_vec(),
                frozen_balance: 500_000_000,
                resource: 2,
            };
            validate_freeze_balance_v2(&accounts, &dp, &stake).unwrap();
            execute_freeze_balance_v2(&accounts, &dp, &stake).unwrap();
            let account = accounts.get(&owner).unwrap().unwrap();
            assert_eq!(account.old_tron_power, expected_old);
            assert_eq!(
                tron_tvm::votes::all_tron_power(&account),
                legacy + 500_000_000
            );
        }
    }
}
