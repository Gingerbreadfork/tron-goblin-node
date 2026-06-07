//! Adapter that exposes TRON's state stores as a revm
//! [`Database`](revm::Database) + [`DatabaseCommit`](revm::DatabaseCommit).
//!
//! The cross-format conversions live here so the rest of the interpreter
//! plumbing in [`crate::evm`] doesn't have to think about them:
//!
//! | EVM concept           | TRON concept                                |
//! |-----------------------|---------------------------------------------|
//! | 20-byte `Address`     | 21-byte address (`0x41` prefix + 20 bytes)  |
//! | `U256` `balance` (wei)| `i64` `balance` (sun)                       |
//! | `nonce: u64`          | (no nonce per-account; we always report 0)  |
//! | `code` + `code_hash`  | `Account.code` (raw) + `Account.code_hash`  |
//! |                       | with the bytecode mirrored in `CodeStore`   |
//! | storage slot lookup   | `StorageRowStore::compose_key` (v2 layout)  |
//! | `BLOCKHASH(n)`        | (returns zero for now — Phase 2 follow-up)  |
//!
//! ### Why no nonce
//!
//! TRON transactions are replay-protected by `ref_block_hash` +
//! `ref_block_bytes` + `expiration`, not by a per-account nonce.
//! revm carries a nonce on `AccountInfo`, but for execution purposes
//! it only matters for `CREATE` address derivation. Since TRON's
//! `CreateSmartContract` provides the contract address explicitly
//! (`new_contract.contract_address`), we don't need a real nonce. We
//! always report `nonce = 0` on read and let revm bump it as it likes
//! during execution; the bumped value gets discarded on commit.
//!
//! ### Why v2 storage layout
//!
//! Pre-`ALLOW_TVM_VOTE` contracts (v1) hash the slot before composing
//! the key. Post-vote contracts (v2) compose it directly. For Phase 2,
//! we apply v2 unconditionally — v1 contract storage parity is a
//! follow-up (java-tron reads `ContractCapsule.version` and switches).

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use revm::primitives::{Address as EvmAddress, AddressMap, StorageKey, StorageValue, B256, U256};
use revm::state::{Account, AccountInfo, Bytecode};
use revm::{Database, DatabaseCommit, DatabaseRef};
use tron_chainbase::{
    AccountStore, BlockIndexStore, CodeStore, ContractStore, StorageRowStore,
};
use tron_crypto::address::{Address as TronAddress, ADDRESS_LENGTH};
use tron_crypto::hash::keccak256;

/// Reader/writer wrapping the stores revm needs to see.
///
/// `block_index` is optional because `BLOCKHASH(n)` is rarely used; many
/// callers (e.g. unit tests) can leave it unset and accept the zero
/// fallback. When set, `BLOCKHASH(n)` returns the real block id for `n`
/// within the EVM's 256-block lookback window.
pub struct TronDatabase {
    pub accounts: Arc<AccountStore>,
    pub code: Arc<CodeStore>,
    pub storage: Arc<StorageRowStore>,
    pub block_index: Option<Arc<BlockIndexStore>>,
    /// Optional ContractStore handle. When attached, storage key
    /// composition reads each contract's `version` field and switches
    /// between v1 (`compose_key_v1`, slot pre-hashed) and v2
    /// (`compose_key`, slot raw). When absent, defaults to v2 — the
    /// safe choice for modern contracts.
    pub contracts: Option<Arc<ContractStore>>,
    // ---- Stores the state-mutating opcode bridges need ----
    //
    // Each opcode (FREEZE / UNFREEZE / VOTEWITNESS / ...) calls the
    // matching actuator primitive, which takes typed-store
    // references. Optional so read-only setups (eth_call,
    // debug_traceCall, unit tests that don't exercise mutations)
    // can omit them — the opcode-bridge methods then fall back to
    // returning 0 (matches the upstream Host default).
    pub dyn_props: Option<Arc<tron_chainbase::DynamicPropertiesStore>>,
    pub votes: Option<Arc<tron_chainbase::VotesStore>>,
    pub delegated_resources: Option<Arc<tron_chainbase::DelegatedResourceStore>>,
    pub delegation: Option<Arc<tron_chainbase::DelegationStore>>,
    /// Side-channel: each state-mutating `tron_*` bridge sets this
    /// to `(target_addr, signed_delta)` describing the EVM-side
    /// balance change that should be journaled. `Host for Context`
    /// drains it via `tron_take_last_balance_delta` immediately
    /// after the bridge returns and applies the delta via
    /// `journaled_state.balance_incr/decr`. Without this channel the
    /// chainbase commit would clobber the staking-side fields with
    /// a stale account.
    pub last_balance_delta: Option<(EvmAddress, i64)>,
    /// Per-`TronDatabase` (i.e. per-tx) memo of each contract's immutable
    /// `version` field (`true` ⇒ v1 storage layout). Avoids re-reading and
    /// decoding the same contract row on every storage slot a call touches.
    /// `true`/`false` are cached only for contracts that exist; a missing
    /// row is left uncached so a contract created earlier in the same tx is
    /// still observed.
    version_cache: RefCell<HashMap<TronAddress, bool>>,
}

impl TronDatabase {
    pub fn new(
        accounts: Arc<AccountStore>,
        code: Arc<CodeStore>,
        storage: Arc<StorageRowStore>,
    ) -> Self {
        Self {
            accounts,
            code,
            storage,
            block_index: None,
            contracts: None,
            dyn_props: None,
            votes: None,
            delegated_resources: None,
            delegation: None,
            last_balance_delta: None,
            version_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Attach a [`BlockIndexStore`] so `BLOCKHASH(n)` returns real hashes.
    pub fn with_block_index(mut self, block_index: Arc<BlockIndexStore>) -> Self {
        self.block_index = Some(block_index);
        self
    }

    /// Attach a [`ContractStore`] so storage-key composition uses the
    /// right layout for v1 vs v2 contracts.
    pub fn with_contracts(mut self, contracts: Arc<ContractStore>) -> Self {
        self.contracts = Some(contracts);
        self
    }

    /// Attach the stores the state-mutating Stake 1.0/2.0 opcode
    /// bridges need (FREEZE / UNFREEZE / VOTEWITNESS /
    /// WITHDRAWREWARD / FREEZEBALANCEV2 / UNFREEZEBALANCEV2 /
    /// CANCELALLUNFREEZEV2 / WITHDRAWEXPIREUNFREEZE /
    /// DELEGATERESOURCE / UNDELEGATERESOURCE). Without these, every
    /// state-mutating opcode pushes 0 (matches the upstream Host
    /// default).
    pub fn with_staking_stores(
        mut self,
        dyn_props: Arc<tron_chainbase::DynamicPropertiesStore>,
        votes: Option<Arc<tron_chainbase::VotesStore>>,
        delegated_resources: Arc<tron_chainbase::DelegatedResourceStore>,
        delegation: Arc<tron_chainbase::DelegationStore>,
    ) -> Self {
        self.dyn_props = Some(dyn_props);
        self.votes = votes;
        self.delegated_resources = Some(delegated_resources);
        self.delegation = Some(delegation);
        self
    }

    /// Compose a storage-row key for the given contract address +
    /// slot, switching on the contract's `version` field. v1 contracts
    /// (pre-`ALLOW_TVM_VOTE`) hash the slot before composition;
    /// everything else uses the slot raw.
    fn compose_storage_key(&self, addr: &TronAddress, slot: &[u8; 32]) -> [u8; 32] {
        if let Some(contracts) = &self.contracts {
            // `version` is immutable post-deploy, so memoize it per-tx —
            // identical v1/v2 decision as a fresh read, but skips re-reading
            // and re-decoding the contract row for every slot of a
            // storage-heavy call.
            let cached = self.version_cache.borrow().get(addr).copied();
            let is_v1 = match cached {
                Some(v) => v,
                None => match contracts.get(addr) {
                    Ok(Some(c)) => {
                        let v = c.version == 1;
                        self.version_cache.borrow_mut().insert(*addr, v);
                        v
                    }
                    // Not found / read error → v2, and don't cache (a
                    // contract created later in this tx must still be seen).
                    _ => false,
                },
            };
            if is_v1 {
                return StorageRowStore::compose_key_v1(addr, slot);
            }
        }
        // v2 layout: matches every contract deployed after the
        // ALLOW_TVM_VOTE proposal landed (most of mainnet).
        StorageRowStore::compose_key(addr, slot)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TronDbError {
    #[error("chainbase store: {0}")]
    Store(#[from] tron_chainbase::StoreError),
}

impl revm::database_interface::DBErrorMarker for TronDbError {}

// =============================================================================
// Address conversion
// =============================================================================

/// 20-byte EVM address → 21-byte TRON address (prepends 0x41).
pub fn evm_to_tron_address(addr: &EvmAddress) -> TronAddress {
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf[0] = 0x41;
    buf[1..].copy_from_slice(addr.as_slice());
    TronAddress::from_raw(buf)
}

/// 21-byte TRON address → 20-byte EVM address (strips 0x41 prefix).
pub fn tron_to_evm_address(addr: &TronAddress) -> EvmAddress {
    EvmAddress::from_slice(&addr.as_bytes()[1..])
}

// =============================================================================
// DatabaseRef (reads, &self) — and Database via blanket impl
// =============================================================================

impl DatabaseRef for TronDatabase {
    type Error = TronDbError;

    fn basic_ref(&self, address: EvmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let tron_addr = evm_to_tron_address(&address);
        let Some(account) = self.accounts.get(&tron_addr)? else {
            return Ok(None);
        };

        // TRON balance is in sun (i64); revm uses U256. The i64 → U256 cast
        // is lossless because i64 is always non-negative for valid accounts.
        let balance = U256::from(account.balance.max(0) as u64);

        // java-tron stores contract RUNTIME code in the `code` store keyed by
        // the contract ADDRESS (`RepositoryImpl.getCode`/`saveCode`), NOT by
        // code_hash. Load it by address and return it inline so revm uses it
        // directly — this is what lets java snapshot contracts execute, since
        // their `Account.code_hash` is frequently empty (the VM would otherwise
        // resolve KECCAK_EMPTY → no code → empty execution).
        let code_bytes = self.code.get(tron_addr.as_bytes())?.unwrap_or_default();
        let (code, code_hash) = if code_bytes.is_empty() {
            // No address-keyed code. Fall back to the account's code_hash so
            // revm's `code_by_hash` can still resolve code this node wrote
            // under the legacy hash key (pre-address-keying deploys); empty
            // hash ⇒ a plain account.
            let h = if account.code_hash.len() == 32 {
                B256::from_slice(&account.code_hash)
            } else {
                revm::primitives::KECCAK_EMPTY
            };
            (None, h)
        } else {
            let h = code_hash(&code_bytes);
            (Some(Bytecode::new_raw(code_bytes.into())), h)
        };

        Ok(Some(AccountInfo {
            balance,
            nonce: 0,
            code_hash,
            code,
            account_id: None,
        }))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == revm::primitives::KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        let bytes = self.code.get(code_hash.as_slice())?.unwrap_or_default();
        Ok(Bytecode::new_raw(bytes.into()))
    }

    fn storage_ref(
        &self,
        address: EvmAddress,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        let tron_addr = evm_to_tron_address(&address);
        let key_bytes: [u8; 32] = index.to_be_bytes();
        let composite = self.compose_storage_key(&tron_addr, &key_bytes);
        let raw = self.storage.get(&composite)?.unwrap_or_default();
        if raw.is_empty() {
            return Ok(StorageValue::ZERO);
        }
        // Storage values are stored as 32 BE bytes. Pad/truncate to be safe.
        let mut padded = [0u8; 32];
        let n = raw.len().min(32);
        padded[32 - n..].copy_from_slice(&raw[raw.len() - n..]);
        Ok(U256::from_be_bytes(padded))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // EVM `BLOCKHASH(n)` semantics: returns 0 for n >= current
        // block, n < current - 256, or when no index is attached.
        let Some(index) = &self.block_index else {
            return Ok(B256::ZERO);
        };
        let signed: i64 = match number.try_into() {
            Ok(n) => n,
            Err(_) => return Ok(B256::ZERO),
        };
        // Just read whatever's stored — the caller (revm interpreter)
        // already enforces the 256-block window. If the store has no
        // entry, return zero rather than propagating NotFound.
        match index.get(signed) {
            Ok(id) => Ok(B256::from_slice(id.as_bytes())),
            Err(_) => Ok(B256::ZERO),
        }
    }
}

impl Database for TronDatabase {
    type Error = TronDbError;

    fn basic(&mut self, address: EvmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }
    fn storage(
        &mut self,
        address: EvmAddress,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        self.storage_ref(address, index)
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

// =============================================================================
// DatabaseCommit (writes)
// =============================================================================

impl DatabaseCommit for TronDatabase {
    fn commit(&mut self, changes: AddressMap<Account>) {
        for (address, account) in changes {
            let tron_addr = evm_to_tron_address(&address);

            // Self-destructed accounts disappear from the AccountStore;
            // their storage rows are intentionally left in place (matches
            // java-tron's behavior — historical state isn't garbage-
            // collected on selfdestruct).
            if account.is_selfdestructed() {
                self.accounts
                    .delete(&tron_addr)
                    .expect("db error in DatabaseCommit::commit deleting selfdestructed account");
                continue;
            }

            // Skip accounts that revm loaded but never touched; nothing
            // changed for them.
            if !account.is_touched() {
                continue;
            }

            // Read existing account (if any) so we preserve TRON-only
            // fields (votes, frozen, asset map, …) across the EVM commit.
            let mut tron_account = self
                .accounts
                .get(&tron_addr)
                .ok()
                .flatten()
                .unwrap_or_else(|| tron_proto::Account {
                    address: tron_addr.as_bytes().to_vec(),
                    ..Default::default()
                });

            // Balance round-trip: revm balance is U256 in sun. We saturate
            // at i64::MAX which is ~9.2 × 10^18 sun ≈ 9.2 × 10^12 TRX,
            // far above any plausible single-account holding.
            let balance_u128 = account.info.balance.try_into().unwrap_or(u128::MAX);
            tron_account.balance = balance_u128.min(i64::MAX as u128) as i64;

            // Write code if this account has new code attached (CREATE).
            // Use `original_byte_slice` — revm pads bytecode with a
            // trailing STOP for jumpdest-analysis safety, but we want
            // to store the original (un-padded) bytes so the code-hash
            // round-trip matches java-tron and the CodeStore contents
            // are bit-identical.
            if let Some(code) = &account.info.code {
                let raw = code.original_byte_slice();
                if !raw.is_empty() {
                    // Key the runtime code by ADDRESS, matching java-tron's
                    // `RepositoryImpl.saveCode(address, ...)` so a later
                    // `getCode(address)` (and our address-keyed `basic_ref`)
                    // resolves it. (Was keyed by code_hash, which diverged
                    // from java and made snapshot contracts unreadable.)
                    self.code
                        .put(tron_addr.as_bytes(), raw)
                        .expect("db error in DatabaseCommit::commit writing code");
                    tron_account.code_hash = account.info.code_hash.to_vec();
                    tron_account.code = raw.to_vec();
                }
            }

            self.accounts
                .put(&tron_addr, &tron_account)
                .expect("db error in DatabaseCommit::commit writing account");

            // Apply storage diffs.
            for (slot_key, slot) in &account.storage {
                if slot.present_value == slot.original_value {
                    continue;
                }
                let slot_bytes: [u8; 32] = slot_key.to_be_bytes();
                let composite = self.compose_storage_key(&tron_addr, &slot_bytes);
                let value_bytes: [u8; 32] = slot.present_value.to_be_bytes();
                self.storage
                    .put(&composite, &value_bytes)
                    .expect("db error in DatabaseCommit::commit writing storage slot");
            }
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Compute the keccak-256 code hash for a piece of bytecode. The result is
/// what gets written to `Account.code_hash` and what
/// [`TronDatabase::code_by_hash`] keys against.
pub fn code_hash(code: &[u8]) -> B256 {
    if code.is_empty() {
        revm::primitives::KECCAK_EMPTY
    } else {
        B256::from(keccak256(code))
    }
}
