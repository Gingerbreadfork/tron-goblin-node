//! TIP-2935: historical block hashes served from state.
//!
//! When `ALLOW_TVM_PRAGUE` activates, the `BlockHashHistory` contract is
//! installed by direct store writes (no VM execution). From then on every
//! block writes its parent hash into the contract's storage before the
//! transaction loop, at slot `(num - 1) % HISTORY_SERVE_WINDOW`; contracts
//! read it back through a normal STATICCALL into the deployed bytecode.
//!
//! Source: java-tron `HistoryBlockHashUtil`.

use tron_chainbase::{
    AccountStore, CodeStore, ContractStore, DynamicPropertiesStore, StorageRowStore, StoreError,
};
use tron_crypto::address::Address;
use tron_proto::{Account, AccountType, SmartContract};

pub const HISTORY_SERVE_WINDOW: i64 = 8191;

/// EIP-2935's `0x0000F90827F1C53a10cb7A02335B175320002935` in TRON 21-byte form.
pub const HISTORY_STORAGE_ADDRESS: [u8; 21] = [
    0x41, 0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b,
    0x17, 0x53, 0x20, 0x00, 0x29, 0x35,
];

/// Recovered sender of EIP-2935's presigned deploy transaction, in TRON
/// 21-byte form; recorded as the contract's `origin_address`.
pub const HISTORY_DEPLOYER_ADDRESS: [u8; 21] = [
    0x41, 0x34, 0x62, 0x41, 0x3a, 0xf4, 0x60, 0x90, 0x98, 0xe1, 0xe2, 0x7a, 0x49, 0x0f, 0x55,
    0x4f, 0x26, 0x02, 0x13, 0xd6, 0x85,
];

/// EIP-2935 runtime bytecode (no constructor prefix).
pub const HISTORY_STORAGE_CODE: [u8; 83] = [
    0x33, 0x73, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x14, 0x60, 0x46, 0x57, 0x60, 0x20, 0x36, 0x03,
    0x60, 0x42, 0x57, 0x5f, 0x35, 0x60, 0x01, 0x43, 0x03, 0x81, 0x11, 0x60, 0x42, 0x57, 0x61,
    0x1f, 0xff, 0x81, 0x43, 0x03, 0x11, 0x60, 0x42, 0x57, 0x61, 0x1f, 0xff, 0x90, 0x06, 0x54,
    0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3, 0x5b, 0x5f, 0x5f, 0xfd, 0x5b, 0x5f, 0x35, 0x61, 0x1f,
    0xff, 0x60, 0x01, 0x43, 0x03, 0x06, 0x55, 0x00,
];

pub const HISTORY_STORAGE_NAME: &str = "BlockHashHistory";

pub fn history_storage_address() -> Address {
    Address::from_raw(HISTORY_STORAGE_ADDRESS)
}

/// Install `BlockHashHistory` at [`HISTORY_STORAGE_ADDRESS`]. Skips (returning
/// `false`) when foreign code or contract metadata already sits there; a
/// pre-existing plain account is upgraded to `Contract` in place, keeping its
/// balance and asset state, like the CREATE2 collision path.
pub fn deploy(
    code: &CodeStore,
    contracts: &ContractStore,
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
) -> Result<bool, StoreError> {
    let address = history_storage_address();
    if code.contains(address.as_bytes())? || contracts.contains(&address)? {
        return Ok(false);
    }

    code.put(address.as_bytes(), &HISTORY_STORAGE_CODE)?;
    contracts.put(
        &address,
        &SmartContract {
            name: HISTORY_STORAGE_NAME.to_string(),
            contract_address: HISTORY_STORAGE_ADDRESS.to_vec(),
            origin_address: HISTORY_DEPLOYER_ADDRESS.to_vec(),
            consume_user_resource_percent: 100,
            ..Default::default()
        },
    )?;

    let account = match accounts.get(&address)? {
        Some(mut existing) => {
            existing.r#type = AccountType::Contract as i32;
            let mut resource = existing.account_resource.take().unwrap_or_default();
            resource.acquired_delegated_frozen_balance_for_energy = 0;
            resource.acquired_delegated_frozen_v2_balance_for_energy = 0;
            existing.account_resource = Some(resource);
            existing.acquired_delegated_frozen_balance_for_bandwidth = 0;
            existing.acquired_delegated_frozen_v2_balance_for_bandwidth = 0;
            existing
        }
        None => Account {
            r#type: AccountType::Contract as i32,
            address: HISTORY_STORAGE_ADDRESS.to_vec(),
            ..Default::default()
        },
    };
    accounts.put(&address, &account)?;

    dyn_props.save_block_hash_history_installed(1);
    Ok(true)
}

/// Storage slot word for block `block_num`'s parent hash.
pub fn slot_for_block(block_num: i64) -> [u8; 32] {
    let slot = (block_num - 1) % HISTORY_SERVE_WINDOW;
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&slot.to_be_bytes());
    word
}

/// Write `parent_hash` for block `block_num` into the contract's storage.
/// No-op (returning `false`) for genesis or while the contract is not
/// installed.
pub fn write_parent_hash(
    storage: &StorageRowStore,
    dyn_props: &DynamicPropertiesStore,
    block_num: i64,
    parent_hash: &[u8],
) -> Result<bool, StoreError> {
    if block_num <= 0 || !dyn_props.is_block_hash_history_installed() {
        return Ok(false);
    }
    let mut value = [0u8; 32];
    let src = if parent_hash.len() > 32 {
        &parent_hash[parent_hash.len() - 32..]
    } else {
        parent_hash
    };
    value[32 - src.len()..].copy_from_slice(src);

    let key = StorageRowStore::compose_key(&history_storage_address(), &slot_for_block(block_num));
    storage.put(&key, &value)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tron_chainbase::MemBackend;

    fn stores() -> (CodeStore, ContractStore, AccountStore, DynamicPropertiesStore, StorageRowStore)
    {
        (
            CodeStore::new(Arc::new(MemBackend::new())),
            ContractStore::new(Arc::new(MemBackend::new())),
            AccountStore::new(Arc::new(MemBackend::new())),
            DynamicPropertiesStore::new(Arc::new(MemBackend::new())),
            StorageRowStore::new(Arc::new(MemBackend::new())),
        )
    }

    #[test]
    fn constants_match_java() {
        assert_eq!(
            hex::encode(HISTORY_STORAGE_ADDRESS),
            "410000f90827f1c53a10cb7a02335b175320002935"
        );
        assert_eq!(
            hex::encode(HISTORY_DEPLOYER_ADDRESS),
            "413462413af4609098e1e27a490f554f260213d685"
        );
        assert_eq!(
            hex::encode(HISTORY_STORAGE_CODE),
            "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500"
        );
    }

    #[test]
    fn deploy_installs_code_contract_account_and_marker() {
        let (code, contracts, accounts, dp, _) = stores();
        assert!(deploy(&code, &contracts, &accounts, &dp).unwrap());
        let address = history_storage_address();
        assert_eq!(code.get(address.as_bytes()).unwrap().unwrap(), HISTORY_STORAGE_CODE);
        let contract = contracts.get(&address).unwrap().unwrap();
        assert_eq!(contract.name, HISTORY_STORAGE_NAME);
        assert_eq!(contract.contract_address, HISTORY_STORAGE_ADDRESS);
        assert_eq!(contract.origin_address, HISTORY_DEPLOYER_ADDRESS);
        assert_eq!(contract.consume_user_resource_percent, 100);
        assert!(contract.trx_hash.is_empty());
        assert_eq!(contract.version, 0);
        let account = accounts.get(&address).unwrap().unwrap();
        assert_eq!(account.r#type, AccountType::Contract as i32);
        assert_eq!(account.address, HISTORY_STORAGE_ADDRESS);
        assert!(account.account_resource.is_none());
        assert!(dp.is_block_hash_history_installed());
    }

    #[test]
    fn deploy_upgrades_existing_account_in_place() {
        let (code, contracts, accounts, dp, _) = stores();
        let address = history_storage_address();
        let mut existing = Account {
            address: HISTORY_STORAGE_ADDRESS.to_vec(),
            balance: 1_000_000,
            acquired_delegated_frozen_v2_balance_for_bandwidth: 7,
            ..Default::default()
        };
        existing.account_resource = Some(tron_proto::account::AccountResource {
            energy_usage: 5,
            acquired_delegated_frozen_v2_balance_for_energy: 9,
            ..Default::default()
        });
        accounts.put(&address, &existing).unwrap();

        assert!(deploy(&code, &contracts, &accounts, &dp).unwrap());
        let account = accounts.get(&address).unwrap().unwrap();
        assert_eq!(account.r#type, AccountType::Contract as i32);
        assert_eq!(account.balance, 1_000_000);
        assert_eq!(account.acquired_delegated_frozen_v2_balance_for_bandwidth, 0);
        let resource = account.account_resource.unwrap();
        assert_eq!(resource.energy_usage, 5);
        assert_eq!(resource.acquired_delegated_frozen_v2_balance_for_energy, 0);
    }

    #[test]
    fn deploy_skips_foreign_state() {
        let (code, contracts, accounts, dp, _) = stores();
        let address = history_storage_address();
        code.put(address.as_bytes(), &[0x00]).unwrap();
        assert!(!deploy(&code, &contracts, &accounts, &dp).unwrap());
        assert!(!dp.is_block_hash_history_installed());
        assert!(contracts.get(&address).unwrap().is_none());
    }

    #[test]
    fn write_is_gated_on_install_marker_and_genesis() {
        let (_, _, _, dp, storage) = stores();
        let hash = [0xabu8; 32];
        assert!(!write_parent_hash(&storage, &dp, 5, &hash).unwrap());
        dp.save_block_hash_history_installed(1);
        assert!(!write_parent_hash(&storage, &dp, 0, &hash).unwrap());
        assert!(write_parent_hash(&storage, &dp, 5, &hash).unwrap());
        let key = StorageRowStore::compose_key(&history_storage_address(), &slot_for_block(5));
        assert_eq!(storage.get(&key).unwrap().unwrap(), hash);
    }

    #[test]
    fn slot_wraps_at_the_serve_window() {
        let mut expected = [0u8; 32];
        expected[31] = 4;
        assert_eq!(slot_for_block(5), expected);
        assert_eq!(slot_for_block(1), [0u8; 32]);
        assert_eq!(slot_for_block(HISTORY_SERVE_WINDOW + 1), [0u8; 32]);
        let mut last = [0u8; 32];
        last[30] = 0x1f;
        last[31] = 0xfe;
        assert_eq!(slot_for_block(HISTORY_SERVE_WINDOW), last);
    }
}
