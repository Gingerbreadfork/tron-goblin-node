//! Admission-time precondition validation for the two VM-bound contract
//! types — `TriggerSmartContract` and `CreateSmartContract`.
//!
//! *Execution* of these contracts runs the TVM and needs the EVM-side
//! stores (`code`, `storage_row`, `contract_state`, `block_index`) plus a
//! write session; that lives in `tron_executor::execute_vm_tx` and is the
//! path the block executor takes (it routes around `dispatch_execute`).
//!
//! What lives HERE is only the cheap precondition gate java-tron runs in
//! `TriggerSmartContractActuator.validate` / `CreateSmartContractActuator
//! .validate` — owner/contract existence and value-range checks, no VM.
//! It's what the mempool needs to *admit* a valid contract tx instead of
//! rejecting every one (the old `deferred::validate_vm` stub). A tx that
//! passes here can still revert at execution time; that's expected and
//! handled at block apply.

use prost::Message;
use prost_types::Any;
use tron_chainbase::{AccountStore, ContractStore};
use tron_proto::transaction::contract::ContractType;
use tron_proto::{CreateSmartContract, TriggerSmartContract};

use crate::helpers::{decode_address, require_owner};
use crate::ActuatorError;

/// java-tron caps a deployed contract's name at 32 bytes
/// (`CreateSmartContractActuator.validate`).
const MAX_CONTRACT_NAME_LEN: usize = 32;

/// Precondition gate for `TriggerSmartContract` / `CreateSmartContract`,
/// mirroring java-tron's actuator `validate()`. Does NOT execute the VM —
/// it only proves the tx is structurally admissible (owner exists, callee
/// is a real contract, value fields in range) so the mempool can relay it.
pub fn validate_vm(
    accounts: &AccountStore,
    contracts: &ContractStore,
    ty: ContractType,
    parameter: &Any,
) -> Result<(), ActuatorError> {
    match ty {
        ContractType::TriggerSmartContract => {
            let c = decode::<TriggerSmartContract>(parameter)?;
            let owner = require_owner(&c.owner_address)?;
            if accounts.get(&owner)?.is_none() {
                return Err(ActuatorError::OwnerAccountMissing);
            }
            let target =
                decode_address(&c.contract_address).ok_or(ActuatorError::InvalidAddress)?;
            // The callee must be a deployed smart contract — java-tron's
            // "No contract or not a smart contract".
            if contracts.get(&target)?.is_none() {
                return Err(ActuatorError::ContractMissing);
            }
            if c.call_value < 0 {
                return Err(ActuatorError::Validate("callValue must be >= 0"));
            }
            if c.call_token_value < 0 {
                return Err(ActuatorError::Validate("callTokenValue must be >= 0"));
            }
            Ok(())
        }
        ContractType::CreateSmartContract => {
            let c = decode::<CreateSmartContract>(parameter)?;
            let owner = require_owner(&c.owner_address)?;
            if accounts.get(&owner)?.is_none() {
                return Err(ActuatorError::OwnerAccountMissing);
            }
            let new_contract = c
                .new_contract
                .as_ref()
                .ok_or(ActuatorError::Validate("CreateSmartContract has no newContract"))?;
            // ownerAddress must equal the new contract's originAddress.
            if new_contract.origin_address != owner.as_bytes() {
                return Err(ActuatorError::Validate(
                    "CreateSmartContract owner address must equal origin address",
                ));
            }
            if new_contract.name.len() > MAX_CONTRACT_NAME_LEN {
                return Err(ActuatorError::Validate(
                    "contract name length must be <= 32 bytes",
                ));
            }
            if !(0..=100).contains(&new_contract.consume_user_resource_percent) {
                return Err(ActuatorError::PercentOutOfRange);
            }
            if new_contract.origin_energy_limit < 0 {
                return Err(ActuatorError::Validate(
                    "origin_energy_limit must be >= 0",
                ));
            }
            if new_contract.call_value < 0 {
                return Err(ActuatorError::Validate("callValue must be >= 0"));
            }
            if c.call_token_value < 0 {
                return Err(ActuatorError::Validate("callTokenValue must be >= 0"));
            }
            Ok(())
        }
        other => Err(ActuatorError::Store(format!(
            "validate_vm called on non-VM contract type {other:?}"
        ))),
    }
}

fn decode<T: Message + Default>(any: &Any) -> Result<T, ActuatorError> {
    T::decode(any.value.as_slice()).map_err(|e| {
        ActuatorError::Store(format!("failed to decode VM contract parameter: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tron_chainbase::{KvBackend, MemBackend};
    use tron_crypto::address::Address;
    use tron_proto::{Account, SmartContract};

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn addr(b: u8) -> Address {
        let mut raw = [0u8; 21];
        raw[0] = 0x41;
        raw[20] = b;
        Address::from_raw(raw)
    }

    fn any_of<T: Message>(c: &T) -> Any {
        Any {
            type_url: String::new(),
            value: c.encode_to_vec(),
        }
    }

    fn stores() -> (AccountStore, ContractStore) {
        (AccountStore::new(mem()), ContractStore::new(mem()))
    }

    #[test]
    fn trigger_ok_when_owner_and_contract_exist() {
        let (accounts, contracts) = stores();
        let owner = addr(1);
        let target = addr(2);
        accounts
            .put(&owner, &Account { address: owner.as_bytes().to_vec(), ..Default::default() })
            .unwrap();
        contracts
            .put(
                &target,
                &SmartContract {
                    contract_address: target.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
        let c = TriggerSmartContract {
            owner_address: owner.as_bytes().to_vec(),
            contract_address: target.as_bytes().to_vec(),
            data: vec![0xab, 0xcd],
            ..Default::default()
        };
        validate_vm(
            &accounts,
            &contracts,
            ContractType::TriggerSmartContract,
            &any_of(&c),
        )
        .expect("a real-account call to a real contract is admissible");
    }

    #[test]
    fn trigger_rejects_unknown_contract() {
        let (accounts, contracts) = stores();
        let owner = addr(1);
        accounts
            .put(&owner, &Account { address: owner.as_bytes().to_vec(), ..Default::default() })
            .unwrap();
        let c = TriggerSmartContract {
            owner_address: owner.as_bytes().to_vec(),
            contract_address: addr(9).as_bytes().to_vec(), // never deployed
            ..Default::default()
        };
        let e = validate_vm(
            &accounts,
            &contracts,
            ContractType::TriggerSmartContract,
            &any_of(&c),
        )
        .unwrap_err();
        assert!(matches!(e, ActuatorError::ContractMissing), "got {e:?}");
    }

    #[test]
    fn trigger_rejects_missing_owner() {
        let (accounts, contracts) = stores();
        let target = addr(2);
        contracts
            .put(
                &target,
                &SmartContract {
                    contract_address: target.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
        let c = TriggerSmartContract {
            owner_address: addr(1).as_bytes().to_vec(), // no account
            contract_address: target.as_bytes().to_vec(),
            ..Default::default()
        };
        let e = validate_vm(
            &accounts,
            &contracts,
            ContractType::TriggerSmartContract,
            &any_of(&c),
        )
        .unwrap_err();
        assert!(matches!(e, ActuatorError::OwnerAccountMissing), "got {e:?}");
    }

    #[test]
    fn create_rejects_percent_out_of_range() {
        let (accounts, contracts) = stores();
        let owner = addr(1);
        accounts
            .put(&owner, &Account { address: owner.as_bytes().to_vec(), ..Default::default() })
            .unwrap();
        let c = CreateSmartContract {
            owner_address: owner.as_bytes().to_vec(),
            new_contract: Some(SmartContract {
                origin_address: owner.as_bytes().to_vec(),
                consume_user_resource_percent: 250, // invalid
                ..Default::default()
            }),
            ..Default::default()
        };
        let e = validate_vm(
            &accounts,
            &contracts,
            ContractType::CreateSmartContract,
            &any_of(&c),
        )
        .unwrap_err();
        assert!(matches!(e, ActuatorError::PercentOutOfRange), "got {e:?}");
    }

    #[test]
    fn create_rejects_owner_origin_mismatch() {
        let (accounts, contracts) = stores();
        let owner = addr(1);
        accounts
            .put(&owner, &Account { address: owner.as_bytes().to_vec(), ..Default::default() })
            .unwrap();
        let c = CreateSmartContract {
            owner_address: owner.as_bytes().to_vec(),
            new_contract: Some(SmartContract {
                origin_address: addr(7).as_bytes().to_vec(), // != owner
                consume_user_resource_percent: 100,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_vm(
            &accounts,
            &contracts,
            ContractType::CreateSmartContract,
            &any_of(&c),
        )
        .is_err());
    }

    #[test]
    fn create_ok_for_well_formed_deploy() {
        let (accounts, contracts) = stores();
        let owner = addr(1);
        accounts
            .put(&owner, &Account { address: owner.as_bytes().to_vec(), ..Default::default() })
            .unwrap();
        let c = CreateSmartContract {
            owner_address: owner.as_bytes().to_vec(),
            new_contract: Some(SmartContract {
                origin_address: owner.as_bytes().to_vec(),
                consume_user_resource_percent: 100,
                origin_energy_limit: 10_000_000,
                bytecode: vec![0x60, 0x80, 0x60, 0x40],
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm(
            &accounts,
            &contracts,
            ContractType::CreateSmartContract,
            &any_of(&c),
        )
        .expect("a well-formed deploy from a real account is admissible");
    }
}
