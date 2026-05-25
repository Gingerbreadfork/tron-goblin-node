//! DynamicPropertiesStore — directory name `properties`.
//!
//! A heterogeneous KV store whose keys are short UTF-8 strings and whose
//! values are encoded with the bytes-per-type convention of
//! `org.tron.common.utils.ByteArray`:
//!
//! * `long` → 8-byte big-endian signed integer (`Longs.toByteArray`)
//! * `int`  → 4-byte big-endian signed integer
//! * `bytes`/`hash` → raw bytes, length defined per-key
//! * `bool` → 1 byte (`0` = false, anything else = true; java-tron writes
//!   `[1]` and `[0]`, but reads accept any non-empty byte slice)
//!
//! **Critical**: the key names are inconsistent (some uppercase, some
//! lowercase, one with a *leading space*). They are part of the consensus
//! contract — anything that "normalises" them on read or write produces a
//! divergent state root. We expose every consensus-touching key as an
//! explicit `pub const` so there is no opportunity to spell them
//! programmatically.
//!
//! Source: `org.tron.core.store.DynamicPropertiesStore` (3117 lines of
//! per-property accessors). Only the consensus-critical and most-read keys
//! are exposed as typed methods here; arbitrary keys can be reached via
//! [`DynamicPropertiesStore::get_long`] / [`get_bytes`] etc.

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "properties";

/// Canonical key bytes. Constants are exposed so consumers can never
/// mis-spell them in code. Each constant's literal value is the *exact*
/// byte sequence java-tron writes to disk.
pub mod keys {
    // --- Latest chain head pointers (lowercase, set on every block) ---
    pub const LATEST_BLOCK_HEADER_TIMESTAMP: &[u8] = b"latest_block_header_timestamp";
    pub const LATEST_BLOCK_HEADER_NUMBER: &[u8] = b"latest_block_header_number";
    pub const LATEST_BLOCK_HEADER_HASH: &[u8] = b"latest_block_header_hash";
    pub const STATE_FLAG: &[u8] = b"state_flag";

    // --- Uppercase keys (set at genesis or by governance) -------------
    pub const LATEST_SOLIDIFIED_BLOCK_NUM: &[u8] = b"LATEST_SOLIDIFIED_BLOCK_NUM";
    pub const LATEST_PROPOSAL_NUM: &[u8] = b"LATEST_PROPOSAL_NUM";
    pub const LATEST_EXCHANGE_NUM: &[u8] = b"LATEST_EXCHANGE_NUM";
    pub const NEXT_MAINTENANCE_TIME: &[u8] = b"NEXT_MAINTENANCE_TIME";
    pub const MAINTENANCE_TIME_INTERVAL: &[u8] = b"MAINTENANCE_TIME_INTERVAL";
    pub const WITNESS_PAY_PER_BLOCK: &[u8] = b"WITNESS_PAY_PER_BLOCK";
    pub const WITNESS_127_PAY_PER_BLOCK: &[u8] = b"WITNESS_127_PAY_PER_BLOCK";
    pub const WITNESS_STANDBY_ALLOWANCE: &[u8] = b"WITNESS_STANDBY_ALLOWANCE";
    pub const CURRENT_CYCLE_NUMBER: &[u8] = b"CURRENT_CYCLE_NUMBER";
    pub const ALLOW_CHANGE_DELEGATION: &[u8] = b"ALLOW_CHANGE_DELEGATION";
    pub const TOTAL_SHIELDED_POOL_VALUE: &[u8] = b"TOTAL_SHIELDED_POOL_VALUE";
    /// Genesis block timestamp (millis). Saved once at genesis init so
    /// runtime slot-attribution (`total_missed`) can compute absolute
    /// slot indices without re-reading block 0 from disk on every
    /// block. Mainnet's genesis is at timestamp 0 — testnets vary.
    pub const GENESIS_BLOCK_TIMESTAMP: &[u8] = b"GENESIS_BLOCK_TIMESTAMP";

    // --- Fork-gate flags (set by SR proposals) -------------------------
    pub const ALLOW_DELEGATE_RESOURCE: &[u8] = b"ALLOW_DELEGATE_RESOURCE";
    pub const ALLOW_ADAPTIVE_ENERGY: &[u8] = b"ALLOW_ADAPTIVE_ENERGY";
    pub const ALLOW_CREATION_OF_CONTRACTS: &[u8] = b"ALLOW_CREATION_OF_CONTRACTS";
    pub const ALLOW_UPDATE_ACCOUNT_NAME: &[u8] = b"ALLOW_UPDATE_ACCOUNT_NAME";
    pub const ALLOW_NEW_REWARD: &[u8] = b"ALLOW_NEW_REWARD";
    pub const ALLOW_HARDEN_RESOURCE_CALCULATION: &[u8] = b"ALLOW_HARDEN_RESOURCE_CALCULATION";
    pub const ALLOW_TVM_FREEZE: &[u8] = b"ALLOW_TVM_FREEZE";
    pub const ALLOW_BLACKHOLE_OPTIMIZATION: &[u8] = b"ALLOW_BLACKHOLE_OPTIMIZATION";
    /// `getUnfreezeDelayDays() > 0` ⇒ `supportUnfreezeDelay()`.
    pub const UNFREEZE_DELAY_DAYS: &[u8] = b"UNFREEZE_DELAY_DAYS";

    // --- Resource quota / pricing -------------------------------------
    pub const ENERGY_FEE: &[u8] = b"ENERGY_FEE";
    pub const TRANSACTION_FEE: &[u8] = b"TRANSACTION_FEE";
    pub const FREE_NET_LIMIT: &[u8] = b"FREE_NET_LIMIT";
    pub const CREATE_ACCOUNT_FEE: &[u8] = b"CREATE_ACCOUNT_FEE";
    pub const CREATE_NEW_ACCOUNT_BANDWIDTH_RATE: &[u8] = b"CREATE_NEW_ACCOUNT_BANDWIDTH_RATE";

    // --- Bandwidth global state ---------------------------------------
    pub const TOTAL_NET_WEIGHT: &[u8] = b"TOTAL_NET_WEIGHT";
    pub const TOTAL_NET_LIMIT: &[u8] = b"TOTAL_NET_LIMIT";
    pub const PUBLIC_NET_USAGE: &[u8] = b"PUBLIC_NET_USAGE";
    pub const PUBLIC_NET_LIMIT: &[u8] = b"PUBLIC_NET_LIMIT";
    pub const PUBLIC_NET_TIME: &[u8] = b"PUBLIC_NET_TIME";

    // --- Energy global / adaptive state --------------------------------
    pub const TOTAL_ENERGY_LIMIT: &[u8] = b"TOTAL_ENERGY_LIMIT";
    pub const TOTAL_ENERGY_CURRENT_LIMIT: &[u8] = b"TOTAL_ENERGY_CURRENT_LIMIT";
    pub const TOTAL_ENERGY_TARGET_LIMIT: &[u8] = b"TOTAL_ENERGY_TARGET_LIMIT";
    pub const TOTAL_ENERGY_AVERAGE_USAGE: &[u8] = b"TOTAL_ENERGY_AVERAGE_USAGE";
    pub const TOTAL_ENERGY_AVERAGE_TIME: &[u8] = b"TOTAL_ENERGY_AVERAGE_TIME";
    pub const TOTAL_ENERGY_WEIGHT: &[u8] = b"TOTAL_ENERGY_WEIGHT";
    pub const BLOCK_ENERGY_USAGE: &[u8] = b"BLOCK_ENERGY_USAGE";
    pub const ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER: &[u8] = b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER";
    pub const ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO: &[u8] = b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO";

    // --- Fee accounting -----------------------------------------------
    pub const TOTAL_TRANSACTION_COST: &[u8] = b"TOTAL_TRANSACTION_COST";
    pub const TOTAL_CREATE_ACCOUNT_COST: &[u8] = b"TOTAL_CREATE_ACCOUNT_COST";
    pub const BURN_TRX_AMOUNT: &[u8] = b"BURN_TRX_AMOUNT";
    pub const TRANSACTION_FEE_POOL: &[u8] = b"TRANSACTION_FEE_POOL";
    pub const MAX_CREATE_ACCOUNT_TX_SIZE: &[u8] = b"MAX_CREATE_ACCOUNT_TX_SIZE";

    /// **Quirk**: java-tron stores this key with a single leading space —
    /// almost certainly a typo that became canonical because changing it
    /// would break every existing chain database. The leading byte
    /// `0x20` is now part of the wire/disk format forever.
    ///
    /// Source: `DynamicPropertiesStore.java:120`:
    /// `byte[] ALLOW_SAME_TOKEN_NAME = " ALLOW_SAME_TOKEN_NAME".getBytes();`
    pub const ALLOW_SAME_TOKEN_NAME: &[u8] = b" ALLOW_SAME_TOKEN_NAME";

    pub const TOTAL_SIGN_NUM: &[u8] = b"TOTAL_SIGN_NUM";
    pub const VERSION_NUMBER: &[u8] = b"VERSION_NUMBER";
}

pub struct DynamicPropertiesStore {
    backend: Arc<dyn KvBackend>,
}

impl DynamicPropertiesStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    // -------------------- Generic accessors ---------------------------

    /// Read a key as 8-byte big-endian signed long.
    ///
    /// java-tron's `ByteArray.toLong` is *permissive*: it accepts any
    /// non-empty byte slice and parses it as an unsigned BigInteger
    /// truncated to 64 bits. We match that to avoid silent disagreement
    /// on edge cases (which in practice never happen — every write is
    /// canonical 8 bytes — but a hand-crafted DB entry could trip us).
    pub fn get_long(&self, key: &[u8]) -> Option<i64> {
        let bytes = self.backend.get(key)?;
        Some(parse_long_permissive(&bytes))
    }

    /// Write a key as 8-byte big-endian signed long.
    pub fn put_long(&self, key: &[u8], value: i64) {
        self.backend.put(key, &value.to_be_bytes());
    }

    /// Read raw bytes for a key (no length validation).
    pub fn get_bytes(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.backend.get(key)
    }

    pub fn put_bytes(&self, key: &[u8], value: &[u8]) {
        self.backend.put(key, value);
    }

    /// Read a key as a 32-byte hash.
    pub fn get_hash(&self, key: &[u8]) -> Result<Option<[u8; 32]>, StoreError> {
        let Some(bytes) = self.backend.get(key) else {
            return Ok(None);
        };
        if bytes.len() != 32 {
            return Err(StoreError::InvalidValueLength {
                got: bytes.len(),
                expected: 32,
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    pub fn put_hash(&self, key: &[u8], hash: &[u8; 32]) {
        self.backend.put(key, hash);
    }

    /// Read a boolean. java-tron writes `[1]` for true and `[0]` for false
    /// but reads via `ByteArray.toLong` and treats `!= 0` as true.
    pub fn get_bool(&self, key: &[u8]) -> Option<bool> {
        Some(self.get_long(key)? != 0)
    }

    pub fn put_bool(&self, key: &[u8], value: bool) {
        self.put_long(key, if value { 1 } else { 0 });
    }

    // -------------------- Typed accessors for hot keys ----------------
    //
    // These wrap the most-read keys in their canonical types. New keys
    // can be added as needed; the generic accessors above are always
    // available for one-off use.

    pub fn latest_block_header_number(&self) -> Option<i64> {
        self.get_long(keys::LATEST_BLOCK_HEADER_NUMBER)
    }
    pub fn save_latest_block_header_number(&self, n: i64) {
        self.put_long(keys::LATEST_BLOCK_HEADER_NUMBER, n);
    }

    pub fn latest_block_header_timestamp(&self) -> Option<i64> {
        self.get_long(keys::LATEST_BLOCK_HEADER_TIMESTAMP)
    }
    pub fn save_latest_block_header_timestamp(&self, t: i64) {
        self.put_long(keys::LATEST_BLOCK_HEADER_TIMESTAMP, t);
    }

    /// Genesis block's timestamp in millis. Saved once at genesis init;
    /// callers that read it from a fresh state get `None` and should
    /// fall back to 0 (mainnet convention). Used by per-block
    /// slot-attribution (`total_missed`).
    pub fn genesis_block_timestamp(&self) -> Option<i64> {
        self.get_long(keys::GENESIS_BLOCK_TIMESTAMP)
    }
    pub fn save_genesis_block_timestamp(&self, t: i64) {
        self.put_long(keys::GENESIS_BLOCK_TIMESTAMP, t);
    }

    pub fn latest_block_header_hash(&self) -> Result<Option<[u8; 32]>, StoreError> {
        self.get_hash(keys::LATEST_BLOCK_HEADER_HASH)
    }
    pub fn save_latest_block_header_hash(&self, hash: &[u8; 32]) {
        self.put_hash(keys::LATEST_BLOCK_HEADER_HASH, hash);
    }

    pub fn latest_solidified_block_num(&self) -> Option<i64> {
        self.get_long(keys::LATEST_SOLIDIFIED_BLOCK_NUM)
    }
    pub fn save_latest_solidified_block_num(&self, n: i64) {
        self.put_long(keys::LATEST_SOLIDIFIED_BLOCK_NUM, n);
    }

    pub fn next_maintenance_time(&self) -> Option<i64> {
        self.get_long(keys::NEXT_MAINTENANCE_TIME)
    }
    pub fn save_next_maintenance_time(&self, t: i64) {
        self.put_long(keys::NEXT_MAINTENANCE_TIME, t);
    }

    pub fn maintenance_time_interval(&self) -> Option<i64> {
        self.get_long(keys::MAINTENANCE_TIME_INTERVAL)
    }
    pub fn save_maintenance_time_interval(&self, v: i64) {
        self.put_long(keys::MAINTENANCE_TIME_INTERVAL, v);
    }

    // -------------------- Reward parameters ----------------------------
    //
    // Default values mirror java-tron `DynamicPropertiesStore`:
    //  * WITNESS_PAY_PER_BLOCK        = 32_000_000 sun (32 TRX)
    //  * WITNESS_127_PAY_PER_BLOCK    = 16_000_000 sun (16 TRX)
    //  * WITNESS_STANDBY_ALLOWANCE    = 115_200_000_000 sun (legacy)
    //
    // The getter returns the stored value if present, else the java-tron
    // default; the setter writes the value. Java-tron initializes these
    // at genesis, but we treat them as soft defaults so unit tests can
    // run without seeding every governance row.

    pub fn witness_pay_per_block(&self) -> i64 {
        self.get_long(keys::WITNESS_PAY_PER_BLOCK).unwrap_or(32_000_000)
    }
    pub fn save_witness_pay_per_block(&self, v: i64) {
        self.put_long(keys::WITNESS_PAY_PER_BLOCK, v);
    }

    pub fn witness_127_pay_per_block(&self) -> i64 {
        self.get_long(keys::WITNESS_127_PAY_PER_BLOCK).unwrap_or(16_000_000)
    }
    pub fn save_witness_127_pay_per_block(&self, v: i64) {
        self.put_long(keys::WITNESS_127_PAY_PER_BLOCK, v);
    }

    pub fn witness_standby_allowance(&self) -> i64 {
        self.get_long(keys::WITNESS_STANDBY_ALLOWANCE).unwrap_or(115_200_000_000)
    }
    pub fn save_witness_standby_allowance(&self, v: i64) {
        self.put_long(keys::WITNESS_STANDBY_ALLOWANCE, v);
    }

    pub fn current_cycle_number(&self) -> i64 {
        self.get_long(keys::CURRENT_CYCLE_NUMBER).unwrap_or(0)
    }
    pub fn save_current_cycle_number(&self, v: i64) {
        self.put_long(keys::CURRENT_CYCLE_NUMBER, v);
    }

    pub fn allow_change_delegation(&self) -> bool {
        self.get_long(keys::ALLOW_CHANGE_DELEGATION).unwrap_or(0) == 1
    }
    pub fn save_allow_change_delegation(&self, v: i64) {
        self.put_long(keys::ALLOW_CHANGE_DELEGATION, v);
    }

    /// See [`keys::ALLOW_SAME_TOKEN_NAME`] for the leading-space quirk.
    pub fn allow_same_token_name(&self) -> Option<i64> {
        self.get_long(keys::ALLOW_SAME_TOKEN_NAME)
    }
    pub fn save_allow_same_token_name(&self, v: i64) {
        self.put_long(keys::ALLOW_SAME_TOKEN_NAME, v);
    }

    // -------------------- Resource defaults ---------------------------
    //
    // Mirrors of java-tron's `DynamicPropertiesStore.DEFAULT_*` constants
    // and `init()` seeds. Values here are what `getX()` returns when the
    // proposal hasn't customised the key — important for unit tests that
    // build a node with an empty `properties` directory.

    /// java-tron `DEFAULT_ENERGY_FEE = 100L` (sun per energy).
    pub const DEFAULT_ENERGY_FEE: i64 = 100;
    /// `DynamicPropertiesStore.init()` seeds `TOTAL_NET_LIMIT = 43_200_000_000`.
    pub const DEFAULT_TOTAL_NET_LIMIT: i64 = 43_200_000_000;
    /// java-tron `FREE_NET_LIMIT` default is 5000 bytes/account/day.
    pub const DEFAULT_FREE_NET_LIMIT: i64 = 5_000;
    /// java-tron `PUBLIC_NET_LIMIT` default (per `DynamicPropertiesStore.init()`).
    pub const DEFAULT_PUBLIC_NET_LIMIT: i64 = 14_400_000_000;
    /// java-tron `TRANSACTION_FEE` default (sun per byte) — note this is
    /// distinct from `ChainConstant.TRANSFER_FEE` (which is 0).
    pub const DEFAULT_TRANSACTION_FEE: i64 = 10;
    /// java-tron `CREATE_NEW_ACCOUNT_BANDWIDTH_RATE` default.
    pub const DEFAULT_CREATE_NEW_ACCOUNT_BANDWIDTH_RATE: i64 = 1;
    /// java-tron `CREATE_ACCOUNT_FEE` default (sun).
    pub const DEFAULT_CREATE_ACCOUNT_FEE: i64 = 100_000;
    /// java-tron `MAX_CREATE_ACCOUNT_TX_SIZE` default (bytes).
    pub const DEFAULT_MAX_CREATE_ACCOUNT_TX_SIZE: i64 = 1_000;
    /// java-tron `ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER` default.
    pub const DEFAULT_ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER: i64 = 1_000;
    /// java-tron `ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO` default.
    pub const DEFAULT_ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO: i64 = 10;

    // -------------------- Resource pricing accessors -------------------

    /// `ENERGY_FEE` — sun-per-unit-energy. Java-tron sets this at genesis
    /// to `DEFAULT_ENERGY_FEE`; we fall back to the same default if the
    /// key is missing so a freshly-bootstrapped node behaves consistently.
    pub fn energy_fee(&self) -> i64 {
        self.get_long(keys::ENERGY_FEE).unwrap_or(Self::DEFAULT_ENERGY_FEE)
    }
    pub fn save_energy_fee(&self, v: i64) {
        self.put_long(keys::ENERGY_FEE, v);
    }

    pub fn transaction_fee(&self) -> i64 {
        self.get_long(keys::TRANSACTION_FEE).unwrap_or(Self::DEFAULT_TRANSACTION_FEE)
    }
    pub fn save_transaction_fee(&self, v: i64) {
        self.put_long(keys::TRANSACTION_FEE, v);
    }

    pub fn free_net_limit(&self) -> i64 {
        self.get_long(keys::FREE_NET_LIMIT).unwrap_or(Self::DEFAULT_FREE_NET_LIMIT)
    }
    pub fn save_free_net_limit(&self, v: i64) {
        self.put_long(keys::FREE_NET_LIMIT, v);
    }

    pub fn create_account_fee(&self) -> i64 {
        self.get_long(keys::CREATE_ACCOUNT_FEE).unwrap_or(Self::DEFAULT_CREATE_ACCOUNT_FEE)
    }
    pub fn create_new_account_bandwidth_rate(&self) -> i64 {
        self.get_long(keys::CREATE_NEW_ACCOUNT_BANDWIDTH_RATE)
            .unwrap_or(Self::DEFAULT_CREATE_NEW_ACCOUNT_BANDWIDTH_RATE)
    }
    pub fn max_create_account_tx_size(&self) -> i64 {
        self.get_long(keys::MAX_CREATE_ACCOUNT_TX_SIZE)
            .unwrap_or(Self::DEFAULT_MAX_CREATE_ACCOUNT_TX_SIZE)
    }

    // -------------------- Bandwidth global state -----------------------

    pub fn total_net_weight(&self) -> i64 {
        self.get_long(keys::TOTAL_NET_WEIGHT).unwrap_or(0)
    }
    pub fn save_total_net_weight(&self, v: i64) {
        self.put_long(keys::TOTAL_NET_WEIGHT, v);
    }
    /// Bump (or shrink) the chain-wide net weight by `delta`. Called
    /// from the freeze/unfreeze actuators. Mirrors java-tron's
    /// `DynamicPropertiesStore.addTotalNetWeight(long amount)`. The
    /// delta is added with saturating arithmetic to avoid wrap.
    pub fn add_total_net_weight(&self, delta: i64) {
        let cur = self.total_net_weight();
        self.save_total_net_weight(cur.saturating_add(delta));
    }

    /// `TOTAL_NET_LIMIT` — global per-block byte cap distributed across
    /// frozen-bandwidth holders. Defaults to `43_200_000_000`
    /// (java-tron's `init()` seed).
    pub fn total_net_limit(&self) -> i64 {
        self.get_long(keys::TOTAL_NET_LIMIT).unwrap_or(Self::DEFAULT_TOTAL_NET_LIMIT)
    }
    pub fn save_total_net_limit(&self, v: i64) {
        self.put_long(keys::TOTAL_NET_LIMIT, v);
    }

    pub fn public_net_usage(&self) -> i64 {
        self.get_long(keys::PUBLIC_NET_USAGE).unwrap_or(0)
    }
    pub fn save_public_net_usage(&self, v: i64) {
        self.put_long(keys::PUBLIC_NET_USAGE, v);
    }

    pub fn public_net_limit(&self) -> i64 {
        self.get_long(keys::PUBLIC_NET_LIMIT).unwrap_or(Self::DEFAULT_PUBLIC_NET_LIMIT)
    }
    pub fn save_public_net_limit(&self, v: i64) {
        self.put_long(keys::PUBLIC_NET_LIMIT, v);
    }

    pub fn public_net_time(&self) -> i64 {
        self.get_long(keys::PUBLIC_NET_TIME).unwrap_or(0)
    }
    pub fn save_public_net_time(&self, v: i64) {
        self.put_long(keys::PUBLIC_NET_TIME, v);
    }

    // -------------------- Energy global / adaptive state ---------------

    pub fn total_energy_limit(&self) -> i64 {
        self.get_long(keys::TOTAL_ENERGY_LIMIT).unwrap_or(0)
    }
    pub fn save_total_energy_limit(&self, v: i64) {
        self.put_long(keys::TOTAL_ENERGY_LIMIT, v);
    }

    /// `TOTAL_ENERGY_CURRENT_LIMIT` — the *adaptive* cap. Falls back to
    /// `TOTAL_ENERGY_LIMIT` when the key is unset (matches java-tron's
    /// `init()`: `saveTotalEnergyCurrentLimit(getTotalEnergyLimit())`).
    pub fn total_energy_current_limit(&self) -> i64 {
        self.get_long(keys::TOTAL_ENERGY_CURRENT_LIMIT)
            .unwrap_or_else(|| self.total_energy_limit())
    }
    pub fn save_total_energy_current_limit(&self, v: i64) {
        self.put_long(keys::TOTAL_ENERGY_CURRENT_LIMIT, v);
    }

    pub fn total_energy_target_limit(&self) -> i64 {
        self.get_long(keys::TOTAL_ENERGY_TARGET_LIMIT)
            .unwrap_or_else(|| self.total_energy_limit() / 14_400)
    }
    pub fn save_total_energy_target_limit(&self, v: i64) {
        self.put_long(keys::TOTAL_ENERGY_TARGET_LIMIT, v);
    }

    pub fn total_energy_average_usage(&self) -> i64 {
        self.get_long(keys::TOTAL_ENERGY_AVERAGE_USAGE).unwrap_or(0)
    }
    pub fn save_total_energy_average_usage(&self, v: i64) {
        self.put_long(keys::TOTAL_ENERGY_AVERAGE_USAGE, v);
    }

    pub fn total_energy_average_time(&self) -> i64 {
        self.get_long(keys::TOTAL_ENERGY_AVERAGE_TIME).unwrap_or(0)
    }
    pub fn save_total_energy_average_time(&self, v: i64) {
        self.put_long(keys::TOTAL_ENERGY_AVERAGE_TIME, v);
    }

    pub fn total_energy_weight(&self) -> i64 {
        self.get_long(keys::TOTAL_ENERGY_WEIGHT).unwrap_or(0)
    }
    pub fn save_total_energy_weight(&self, v: i64) {
        self.put_long(keys::TOTAL_ENERGY_WEIGHT, v);
    }
    /// Bump (or shrink) the chain-wide energy weight by `delta`.
    /// Mirrors `DynamicPropertiesStore.addTotalEnergyWeight`.
    pub fn add_total_energy_weight(&self, delta: i64) {
        let cur = self.total_energy_weight();
        self.save_total_energy_weight(cur.saturating_add(delta));
    }

    pub fn block_energy_usage(&self) -> i64 {
        self.get_long(keys::BLOCK_ENERGY_USAGE).unwrap_or(0)
    }
    pub fn save_block_energy_usage(&self, v: i64) {
        self.put_long(keys::BLOCK_ENERGY_USAGE, v);
    }

    pub fn adaptive_resource_limit_multiplier(&self) -> i64 {
        self.get_long(keys::ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER)
            .unwrap_or(Self::DEFAULT_ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER)
    }
    pub fn save_adaptive_resource_limit_multiplier(&self, v: i64) {
        self.put_long(keys::ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER, v);
    }

    pub fn adaptive_resource_limit_target_ratio(&self) -> i64 {
        self.get_long(keys::ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO)
            .unwrap_or(Self::DEFAULT_ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO)
    }

    // -------------------- Fork-gate readers ----------------------------

    /// `ALLOW_ADAPTIVE_ENERGY` is `0` or `1` (java-tron treats `1` as on).
    pub fn allow_adaptive_energy(&self) -> i64 {
        self.get_long(keys::ALLOW_ADAPTIVE_ENERGY).unwrap_or(0)
    }

    pub fn allow_new_reward(&self) -> bool {
        self.get_long(keys::ALLOW_NEW_REWARD).unwrap_or(0) != 0
    }

    pub fn allow_harden_resource_calculation(&self) -> bool {
        self.get_long(keys::ALLOW_HARDEN_RESOURCE_CALCULATION).unwrap_or(0) != 0
    }

    pub fn allow_tvm_freeze(&self) -> i64 {
        self.get_long(keys::ALLOW_TVM_FREEZE).unwrap_or(0)
    }

    pub fn allow_blackhole_optimization(&self) -> i64 {
        self.get_long(keys::ALLOW_BLACKHOLE_OPTIMIZATION).unwrap_or(0)
    }

    pub fn support_blackhole_optimization(&self) -> bool {
        self.allow_blackhole_optimization() == 1
    }

    /// `getUnfreezeDelayDays()` — java-tron returns 0 when unset; the
    /// fork-gate is `> 0`.
    pub fn unfreeze_delay_days(&self) -> i64 {
        self.get_long(keys::UNFREEZE_DELAY_DAYS).unwrap_or(0)
    }
    pub fn save_unfreeze_delay_days(&self, v: i64) {
        self.put_long(keys::UNFREEZE_DELAY_DAYS, v);
    }
    pub fn support_unfreeze_delay(&self) -> bool {
        self.unfreeze_delay_days() > 0
    }

    /// `TRANSACTION_FEE_POOL` accumulator: when on, bandwidth fees flow
    /// here instead of being burned.
    pub fn support_transaction_fee_pool(&self) -> bool {
        self.get_long(keys::TRANSACTION_FEE_POOL).is_some()
    }

    pub fn add_transaction_fee_pool(&self, amount: i64) {
        let cur = self.get_long(keys::TRANSACTION_FEE_POOL).unwrap_or(0);
        self.put_long(keys::TRANSACTION_FEE_POOL, cur.saturating_add(amount));
    }

    // -------------------- Fee accumulators -----------------------------

    pub fn total_transaction_cost(&self) -> i64 {
        self.get_long(keys::TOTAL_TRANSACTION_COST).unwrap_or(0)
    }
    pub fn add_total_transaction_cost(&self, amount: i64) {
        let cur = self.total_transaction_cost();
        self.put_long(keys::TOTAL_TRANSACTION_COST, cur.saturating_add(amount));
    }

    pub fn burn_trx_amount(&self) -> i64 {
        self.get_long(keys::BURN_TRX_AMOUNT).unwrap_or(0)
    }
    /// Mirrors `DynamicPropertiesStore.burnTrx(amount)`.
    pub fn burn_trx(&self, amount: i64) {
        let cur = self.burn_trx_amount();
        self.put_long(keys::BURN_TRX_AMOUNT, cur.saturating_add(amount));
    }

    pub fn total_create_account_cost(&self) -> i64 {
        self.get_long(keys::TOTAL_CREATE_ACCOUNT_COST).unwrap_or(0)
    }
    pub fn add_total_create_account_cost(&self, amount: i64) {
        let cur = self.total_create_account_cost();
        self.put_long(keys::TOTAL_CREATE_ACCOUNT_COST, cur.saturating_add(amount));
    }
}

/// Permissive long parser matching java-tron's `ByteArray.toLong`:
/// interprets any non-empty byte slice as a big-endian unsigned integer,
/// then truncates to the low 64 bits. Empty input returns 0.
fn parse_long_permissive(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    // Take the trailing up-to-8 bytes (big-endian). For shorter inputs,
    // left-pad with zero. This is what
    //   new BigInteger(1, bytes).longValue()
    // does: parses as unsigned, then returns the low 64 bits as a signed
    // long (which is identical to a zero-padded big-endian u64 view for
    // any input <= 8 bytes long, and silently drops the high bits for
    // longer inputs).
    let len = bytes.len();
    let mut buf = [0u8; 8];
    if len >= 8 {
        buf.copy_from_slice(&bytes[len - 8..]);
    } else {
        buf[8 - len..].copy_from_slice(bytes);
    }
    i64::from_be_bytes(buf)
}
