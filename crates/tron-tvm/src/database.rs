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
    AccountStore, BlockIndexStore, CodeStore, ContractStore, StorageRowStore, WitnessStore,
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
    /// Witness registry, consulted by the VOTEWITNESS bridge to reject
    /// votes for addresses that are not SR candidates (java-tron's
    /// `VoteWitnessProcessor.execute` → `repo.getWitness(addr) == null`).
    /// Optional like the other staking stores; when absent the bridge
    /// returns 0 (matches the upstream Host default).
    pub witnesses: Option<Arc<WitnessStore>>,
    pub delegated_resources: Option<Arc<tron_chainbase::DelegatedResourceStore>>,
    pub delegation: Option<Arc<tron_chainbase::DelegationStore>>,
    /// `reward-vi` store backing the `ALLOW_OLD_REWARD_OPT` legacy-reward
    /// fast path inside `withdraw_reward` (VOTEWITNESS / WITHDRAWREWARD /
    /// UNFREEZE bridges settle rewards first). Optional like the other
    /// staking stores; `None` only matters for voters whose reward window
    /// predates the new reward algorithm.
    pub reward_vi: Option<Arc<tron_chainbase::RewardViStore>>,
    /// ABI store -- only consulted by the SELFDESTRUCT commit path
    /// (java-tron `TransactionTrace.deleteContract` removes the
    /// account, code, contract AND abi rows for destroyed contracts).
    pub abi: Option<Arc<tron_chainbase::AbiStore>>,
    /// Multi-delta sibling of `last_balance_delta`: the suicide bridge
    /// can move several balances at once (allowance fold, frozen
    /// transfer, expired-unfreeze credit). Drained by
    /// `tron_take_balance_deltas` after each bridge call.
    pub pending_balance_deltas: Vec<(EvmAddress, i64)>,
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
    /// Memoized per contract: `(is_v1_storage_layout, addr_hash)`. `addr_hash`
    /// is java's storage-key prefix source — `sha3(address)` normally, or
    /// `sha3(address ++ trxHash)` for CREATE2 contracts (see
    /// [`StorageRowStore::addr_hash`]). Both inputs (`version`, `trxHash`) are
    /// immutable post-deploy, so caching avoids re-reading the contract row for
    /// every slot of a storage-heavy call.
    version_cache: RefCell<HashMap<TronAddress, (bool, [u8; 32])>>,
    /// Root transaction id (`sha256(raw_data)`) of the tx executing on this
    /// `TronDatabase`. Feeds nested-CREATE address derivation
    /// (`0x41 || sha3omit12(rootTxId || nonce_be8)`). Zero on read-only setups
    /// that never deploy (eth_call), where it is unused.
    pub(crate) root_tx_id: [u8; 32],
    /// java-tron's per-tx internal-transaction nonce counter
    /// (`Program.nonce`). Starts at 0; the frame layer post-increments it on
    /// every nested CALL (non-precompile) / CREATE / CREATE2 (and, via the
    /// opcode bridges, SELFDESTRUCT + staking ops). A nested CREATE's address
    /// uses the value BEFORE its own bump. One `TronDatabase` per tx ⇒ one
    /// counter per tx.
    pub(crate) create_nonce: u64,
    /// Nested CREATE/CREATE2 deploys recorded by the frame layer, keyed by the
    /// EVM contract address → (creator EVM address, is_create2). `commit`
    /// drains this to write each survivor's `SmartContract` row +
    /// `CreatedByContract` / `AccountType::Contract` account fields (java-tron
    /// `Program.createContractImpl`). A create that reverts never reaches
    /// commit, so its entry — though still present here — is simply ignored
    /// (commit only acts on addresses that show up in the committed change set).
    pub(crate) pending_created_contracts: HashMap<EvmAddress, (EvmAddress, bool)>,
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
            witnesses: None,
            delegated_resources: None,
            delegation: None,
            reward_vi: None,
            abi: None,
            pending_balance_deltas: Vec::new(),
            last_balance_delta: None,
            version_cache: RefCell::new(HashMap::new()),
            root_tx_id: [0u8; 32],
            create_nonce: 0,
            pending_created_contracts: HashMap::new(),
        }
    }

    /// Set the root transaction id used for nested-CREATE address derivation.
    /// Must be the same `sha256(raw_data)` tx id the executor computes for the
    /// transaction whose VM call this `TronDatabase` backs.
    pub fn with_root_tx_id(mut self, tx_id: [u8; 32]) -> Self {
        self.root_tx_id = tx_id;
        self
    }

    /// Advance the per-tx internal-transaction nonce counter by one — call once
    /// per java-tron `Program.increaseNonce`. Used by the staking / SELFDESTRUCT
    /// opcode bridges, which each create one (or, when they auto-withdraw an
    /// expired unfreeze, two) internal transactions java assigns nonces to. The
    /// frame layer bumps for nested CALL/CREATE separately. Only the cumulative
    /// count matters (a later nested CREATE's address reads it); ordering within
    /// a single opcode is irrelevant since no CREATE interleaves.
    pub(crate) fn note_internal_tx_nonce(&mut self) {
        self.create_nonce += 1;
    }

    /// Attach the ABI store (SELFDESTRUCT contract-row cleanup).
    pub fn with_abi(mut self, abi: Arc<tron_chainbase::AbiStore>) -> Self {
        self.abi = Some(abi);
        self
    }

    /// Attach the `reward-vi` store (legacy-reward `ALLOW_OLD_REWARD_OPT`
    /// fast path inside reward settlement).
    pub fn with_reward_vi(mut self, reward_vi: Arc<tron_chainbase::RewardViStore>) -> Self {
        self.reward_vi = Some(reward_vi);
        self
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

    /// Attach the witness registry so the VOTEWITNESS bridge can reject
    /// votes for non-SR-candidate addresses (java-tron's
    /// `VoteWitnessProcessor.execute` witness-existence check).
    pub fn with_witnesses(mut self, witnesses: Arc<WitnessStore>) -> Self {
        self.witnesses = Some(witnesses);
        self
    }

    /// Compose a storage-row key for the given contract address + slot,
    /// matching java-tron's `Storage`/`RepositoryImpl.getStorage` exactly:
    /// the 16-byte key prefix is `sha3(address)` normally but
    /// `sha3(address ++ trxHash)` for a CREATE2-deployed contract (one whose
    /// `SmartContract.trxHash` is set), and the slot is hashed first only for
    /// v1 (`version == 1`, pre-`ALLOW_TVM_VOTE`) contracts. Missing the trxHash
    /// prefix points every CREATE2 contract's storage (e.g. all DEX pairs) at
    /// the wrong key, so reads come back zero — invisible on self-synced state
    /// (we wrote AND read at the wrong prefix) but fatal against a real
    /// java-tron snapshot.
    fn compose_storage_key(&self, addr: &TronAddress, slot: &[u8; 32]) -> [u8; 32] {
        // A contract CREATE2-deployed earlier in THIS tx isn't in the
        // ContractStore until commit, but java's in-memory deposit already
        // addresses its storage with the trxHash (= this tx's root id) prefix.
        let evm = tron_to_evm_address(addr);
        if let Some((_creator, is_create2)) = self.pending_created_contracts.get(&evm) {
            let trx_hash: &[u8] = if *is_create2 { &self.root_tx_id } else { &[] };
            let ah = StorageRowStore::addr_hash(addr, trx_hash);
            // Nested creates are version 0 → v2 (raw slot).
            return StorageRowStore::compose_key_with_addr_hash(&ah, slot, false);
        }
        if let Some(contracts) = &self.contracts {
            let cached = self.version_cache.borrow().get(addr).copied();
            let (is_v1, ah) = match cached {
                Some(v) => v,
                None => match contracts.get(addr) {
                    Ok(Some(c)) => {
                        let v1 = c.version == 1;
                        let ah = StorageRowStore::addr_hash(addr, &c.trx_hash);
                        self.version_cache.borrow_mut().insert(*addr, (v1, ah));
                        (v1, ah)
                    }
                    // Not found / read error → plain prefix + v2, and don't
                    // cache (a contract created later in this tx must still be
                    // observed once its row lands).
                    _ => (false, StorageRowStore::addr_hash(addr, &[])),
                },
            };
            return StorageRowStore::compose_key_with_addr_hash(&ah, slot, is_v1);
        }
        // No ContractStore attached (read-only / test setups): plain v2.
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
                // java-tron `TransactionTrace.deleteContract`: a destroyed
                // contract loses its account, code, SmartContract AND abi
                // rows (storage rows stay -- never GC'd, see above). Without
                // this, a CREATE2 redeploy at the same address would
                // resurrect the old code.
                self.accounts
                    .delete(&tron_addr)
                    .expect("db error in DatabaseCommit::commit deleting selfdestructed account");
                self.code
                    .delete(tron_addr.as_bytes())
                    .expect("db error in DatabaseCommit::commit deleting selfdestructed code");
                if let Some(contracts) = &self.contracts {
                    contracts
                        .delete(&tron_addr)
                        .expect("db error in DatabaseCommit::commit deleting selfdestructed contract");
                }
                if let Some(abi) = &self.abi {
                    abi.delete(&tron_addr)
                        .expect("db error in DatabaseCommit::commit deleting selfdestructed abi");
                }
                continue;
            }

            // Skip accounts that revm loaded but never touched; nothing
            // changed for them.
            if !account.is_touched() {
                continue;
            }

            // Read existing account (if any) so we preserve TRON-only
            // fields (votes, frozen, asset map, …) across the EVM commit.
            let existing = self.accounts.get(&tron_addr).ok().flatten();
            // Whether the VM is creating this account from nothing — used below
            // to mirror java's `createNormalAccount`, which attaches the
            // default owner+active[id=2] permission to a freshly-created
            // *normal* (non-contract) account when multisig is enabled.
            let is_new_account = existing.is_none();
            let mut tron_account = existing.unwrap_or_else(|| tron_proto::Account {
                address: tron_addr.as_bytes().to_vec(),
                ..Default::default()
            });

            // TRON fork: if a nested CREATE/CREATE2 deployed this address (and
            // it survived to commit), mark the account `CreatedByContract` /
            // `AccountType::Contract` — java-tron `Program.createContractImpl`
            // → `deposit.createAccount(addr, "CreatedByContract", Contract)`.
            // type=Contract is consensus-relevant (TransferActuator rejects
            // plain TRX transfers to Contract-type accounts).
            let created_contract = self.pending_created_contracts.get(&address).copied();
            if created_contract.is_some() {
                tron_account.r#type = tron_proto::AccountType::Contract as i32;
                if tron_account.account_name.is_empty() {
                    tron_account.account_name = b"CreatedByContract".to_vec();
                }
            }

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

            // java's `RepositoryImpl.createNormalAccount` attaches the default
            // owner+active[id=2] permission (when ALLOW_MULTI_SIGN is on) to a
            // freshly-created *normal* account — i.e. a plain EOA the VM
            // brought into existence by transferring value to it. Deployed
            // contracts (in `pending_created_contracts`, or anything that now
            // carries code) get no default permission, matching java.
            if is_new_account && created_contract.is_none() && tron_account.code.is_empty() {
                if let Some(dyn_props) = &self.dyn_props {
                    tron_chainbase::apply_default_account_permissions(&mut tron_account, dyn_props);
                }
            }

            self.accounts
                .put(&tron_addr, &tron_account)
                .expect("db error in DatabaseCommit::commit writing account");

            // TRON fork: write the `SmartContract` row for a surviving nested
            // deploy. java-tron `createContractImpl` builds
            // `SmartContract{ contractAddress, consumeUserResourcePercent=100,
            // originAddress=creator, trxHash=rootTxId iff CREATE2, version=1 }`
            // (no ABI/name/bytecode/originEnergyLimit — those stay default; the
            // ABI lives in `AbiStore`, which a nested deploy never populates).
            // `code_hash` is left empty, matching java's lazy fill on first
            // EXTCODEHASH. Needs the `ContractStore`; read-only setups omit it.
            if let (Some((creator, is_create2)), Some(contracts)) =
                (created_contract, &self.contracts)
            {
                let creator_tron = evm_to_tron_address(&creator);
                let smart_contract = tron_proto::SmartContract {
                    origin_address: creator_tron.as_bytes().to_vec(),
                    contract_address: tron_addr.as_bytes().to_vec(),
                    consume_user_resource_percent: 100,
                    trx_hash: if is_create2 {
                        self.root_tx_id.to_vec()
                    } else {
                        Vec::new()
                    },
                    // version stays 0: java-tron only sets it (to
                    // `getContractVersion`) when ALLOW_TVM_COMPATIBLE_EVM is
                    // active, which is currently OFF on mainnet (verified:
                    // getAllowTvmCompatibleEvm == 0, and live contracts read
                    // back version 0). version 0 also selects the v2 (raw-slot)
                    // storage layout in `compose_storage_key`, which is correct
                    // for every post-ALLOW_TVM_VOTE contract — writing 1 here
                    // would wrongly switch the contract to the v1 pre-hashed
                    // slot layout and corrupt all its storage access.
                    ..Default::default()
                };
                contracts
                    .put(&tron_addr, &smart_contract)
                    .expect("db error in DatabaseCommit::commit writing contract row");
            }

            // Apply storage diffs.
            // TEMP DIAGNOSTIC (TRON_SSTORE_TRACE=<evm-addr-hex>): log every committed
            // storage write to a target contract (slot, old→new, root tx) so a silent
            // storage-VALUE divergence vs java can be pinned to the exact tx + op.
            let sstore_trace: Option<[u8; 20]> =
                std::env::var("TRON_SSTORE_TRACE").ok().and_then(|h| {
                    let h = h.trim_start_matches("0x");
                    if h.len() != 40 {
                        return None;
                    }
                    let mut out = [0u8; 20];
                    for i in 0..20 {
                        out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?;
                    }
                    Some(out)
                });
            let hx = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
            for (slot_key, slot) in &account.storage {
                if slot.present_value == slot.original_value {
                    continue;
                }
                let slot_bytes: [u8; 32] = slot_key.to_be_bytes();
                let composite = self.compose_storage_key(&tron_addr, &slot_bytes);
                let value_bytes: [u8; 32] = slot.present_value.to_be_bytes();
                if sstore_trace == Some(address.into_array()) {
                    let tx = hx(&self.root_tx_id);
                    eprintln!(
                        "SSTRACE tx={} slot={} old={} new={}",
                        &tx[..16.min(tx.len())],
                        hx(&slot_bytes),
                        hx(&slot.original_value.to_be_bytes::<32>()),
                        hx(&value_bytes),
                    );
                }
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
