//! Default account-permission construction shared by the actuators and the
//! VM commit path.
//!
//! java-tron attaches a default `owner` + `active[id=2]` permission to *every*
//! account it creates when `ALLOW_MULTI_SIGN == 1` (active on mainnet for
//! years). The relevant constructors live in `AccountCapsule`
//! (`createDefaultOwnerPermission` / `createDefaultActivePermission`) and are
//! invoked from `TransferActuator`, `TransferAssetActuator`,
//! `CreateAccountActuator`, `ShieldedTransferActuator` and
//! `RepositoryImpl.createNormalAccount` with
//! `withDefaultPermission = getAllowMultiSign() == 1`.
//!
//! Without these, an account our node creates during sync cannot resolve
//! `permission_id 2`, so any later multi-sig transaction from it diverges
//! ("permission_id 2 not found") from java, which created the same account
//! *with* the default permission.

use tron_proto::permission::PermissionType;
use tron_proto::{Account, Key, Permission};

use crate::DynamicPropertiesStore;

/// Mainnet `ACTIVE_DEFAULT_OPERATIONS` bitmap (32 bytes), used only as a
/// fallback when the proposal-mutable dynamic property is missing from the
/// store. Matches the value java exposes on every default active permission
/// (`7fff1fc0033ec30f` followed by zeros).
fn default_active_operations() -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[..8].copy_from_slice(&[0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x3e, 0xc3, 0x0f]);
    v
}

/// Build the default `owner` + `active[id=2]` permission pair java attaches to
/// a newly-created account when `ALLOW_MULTI_SIGN == 1`. Returns `None` when
/// multisig is disabled (pre-activation / non-mainnet) — java's
/// `withDefaultPermission == false` branch leaves the account permission-less.
///
/// `account_address` is the new account's own 21-byte address; the permission
/// keys point back at it (single key, weight 1, threshold 1). The active
/// permission's `operations` bitmap is the proposal-mutable
/// `ACTIVE_DEFAULT_OPERATIONS` dynamic property (java
/// `getActiveDefaultOperations`), read from the store with the mainnet bitmap
/// as a fallback.
pub fn default_account_permissions(
    account_address: &[u8],
    dyn_props: &DynamicPropertiesStore,
) -> Option<(Permission, Vec<Permission>)> {
    if dyn_props.get_long(b"ALLOW_MULTI_SIGN").unwrap_or(0) != 1 {
        return None;
    }
    let key = Key {
        address: account_address.to_vec(),
        weight: 1,
    };
    let owner_perm = Permission {
        r#type: PermissionType::Owner as i32,
        id: 0,
        permission_name: "owner".to_string(),
        threshold: 1,
        parent_id: 0,
        operations: Vec::new(),
        keys: vec![key.clone()],
    };
    let active_perm = Permission {
        r#type: PermissionType::Active as i32,
        id: 2,
        permission_name: "active".to_string(),
        threshold: 1,
        parent_id: 0,
        operations: dyn_props
            .get_bytes(b"ACTIVE_DEFAULT_OPERATIONS")
            .unwrap_or_else(default_active_operations),
        keys: vec![key],
    };
    Some((owner_perm, vec![active_perm]))
}

/// Apply the default permission pair (see [`default_account_permissions`]) to a
/// freshly-built account in place. No-op when multisig is disabled. The
/// account's `address` must already be set.
pub fn apply_default_account_permissions(account: &mut Account, dyn_props: &DynamicPropertiesStore) {
    if let Some((owner, actives)) = default_account_permissions(&account.address, dyn_props) {
        account.owner_permission = Some(owner);
        account.active_permission = actives;
    }
}
