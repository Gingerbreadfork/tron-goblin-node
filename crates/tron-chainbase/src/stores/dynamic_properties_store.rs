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
//!
//! ## Error handling
//!
//! The public API on this store deliberately keeps the **infallible**
//! shape (returning `Option<i64>` etc., not `Result<Option<i64>, _>`)
//! despite [`crate::KvBackend`] now being fallible. Reason: this store
//! is read on every block-apply by dozens of callers (executor, TVM,
//! actuator, consensus, RPC). Propagating `Result` through every one of
//! those would cascade across hundreds of call sites for a class of
//! errors that — in practice — only ever occur on disk failure.
//!
//! Instead, backend errors here **panic with rich context** naming the
//! store and the specific key. That keeps the IO-fault failure mode
//! visible (you see exactly which key on which store failed in the
//! stack trace) while not infecting every caller's signature.

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
    /// **Quirk**: java-tron's on-disk key for the change-delegation flag
    /// is `CHANGE_DELEGATION` — no `ALLOW_` prefix, unlike every sibling
    /// flag (`DynamicPropertiesStore.CHANGE_DELEGATION`). Reading
    /// `ALLOW_CHANGE_DELEGATION` (the previous value here) found NOTHING
    /// in a java-imported DB, so `allow_change_delegation()` was false on
    /// live mainnet state — silently routing maintenance into the legacy
    /// pre-Vi reward path: no Vi accumulation, no cycle advance, no
    /// brokerage/vote snapshots, and `withdraw_reward`/`query_reward`
    /// no-oping. The Rust-side name keeps the `ALLOW_` prefix for
    /// consistency with the accessor; only the BYTES follow java.
    pub const ALLOW_CHANGE_DELEGATION: &[u8] = b"CHANGE_DELEGATION";
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
    /// `getAllowCancelAllUnfreezeV2() == 1 && supportUnfreezeDelay()` ⇒
    /// `supportAllowCancelAllUnfreezeV2()` — selects the precision-scaled
    /// (V2) per-account window math in `ResourceProcessor`.
    pub const ALLOW_CANCEL_ALL_UNFREEZE_V2: &[u8] = b"ALLOW_CANCEL_ALL_UNFREEZE_V2";

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
    /// Chain-wide TRON_POWER (voting) frozen weight, in TRX units. Updated
    /// by FreezeBalanceV2/UnfreezeBalanceV2 for `resource = TRON_POWER`.
    pub const TOTAL_TRON_POWER_WEIGHT: &[u8] = b"TOTAL_TRON_POWER_WEIGHT";
    pub const BLOCK_ENERGY_USAGE: &[u8] = b"BLOCK_ENERGY_USAGE";
    pub const ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER: &[u8] = b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER";
    pub const ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO: &[u8] = b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO";

    /// Flat fee charged when a transaction carries more than one
    /// signature (java-tron `Manager.consumeMultiSignFee`).
    pub const MULTI_SIGN_FEE: &[u8] = b"MULTI_SIGN_FEE";
    /// Flat fee charged when `raw_data.data` (the memo) is non-empty
    /// (java-tron `Manager.consumeMemoFee`; 0 until the SR proposal
    /// sets it).
    pub const MEMO_FEE: &[u8] = b"MEMO_FEE";
    /// java-tron `CONSENSUS_LOGIC_OPTIMIZATION` — gates several "v2"
    /// consensus behaviors (strict-math, witness sort, the in-block
    /// max-create-account-tx-size check).
    pub const CONSENSUS_LOGIC_OPTIMIZATION: &[u8] = b"CONSENSUS_LOGIC_OPTIMIZATION";

    // --- Fee accounting -----------------------------------------------
    pub const TOTAL_TRANSACTION_COST: &[u8] = b"TOTAL_TRANSACTION_COST";
    pub const TOTAL_CREATE_ACCOUNT_COST: &[u8] = b"TOTAL_CREATE_ACCOUNT_COST";
    pub const BURN_TRX_AMOUNT: &[u8] = b"BURN_TRX_AMOUNT";
    pub const TRANSACTION_FEE_POOL: &[u8] = b"TRANSACTION_FEE_POOL";
    pub const ALLOW_TRANSACTION_FEE_POOL: &[u8] = b"ALLOW_TRANSACTION_FEE_POOL";
    /// Comma-joined `unix_ms:price` schedule of every historic price, e.g.
    /// `0:100,1542607200000:20,…`. Appended by price-change proposals.
    pub const ENERGY_PRICE_HISTORY: &[u8] = b"ENERGY_PRICE_HISTORY";
    pub const BANDWIDTH_PRICE_HISTORY: &[u8] = b"BANDWIDTH_PRICE_HISTORY";
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
    /// java-tron's own database/protocol version (e.g. `34` on current
    /// mainnet). Reserved for parity — **not** our schema stamp.
    pub const VERSION_NUMBER: &[u8] = b"VERSION_NUMBER";
    /// Goblin-private chainbase schema version (M-14). A distinct key so
    /// it never collides with java-tron's `VERSION_NUMBER` above: a real
    /// snapshot already stores its protocol version (34) there, which must
    /// not be read as — or overwritten by — our schema version.
    pub const GOBLIN_SCHEMA_VERSION: &[u8] = b"GOBLIN_SCHEMA_VERSION";
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

    /// Internal helper — perform a backend read, panicking with rich
    /// context if the backend fails. See the module-level "Error
    /// handling" doc for the rationale.
    fn read_or_panic(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.backend.get(key).unwrap_or_else(|e| {
            let name = String::from_utf8_lossy(key);
            panic!("dyn_props store: failed to read {name}: {e}")
        })
    }

    /// Internal helper — perform a backend write, panicking with rich
    /// context if the backend fails.
    fn write_or_panic(&self, key: &[u8], value: &[u8]) {
        self.backend.put(key, value).unwrap_or_else(|e| {
            let name = String::from_utf8_lossy(key);
            panic!("dyn_props store: failed to write {name}: {e}")
        });
    }

    /// Read a key as 8-byte big-endian signed long.
    ///
    /// java-tron's `ByteArray.toLong` is *permissive*: it accepts any
    /// non-empty byte slice and parses it as an unsigned BigInteger
    /// truncated to 64 bits. We match that to avoid silent disagreement
    /// on edge cases (which in practice never happen — every write is
    /// canonical 8 bytes — but a hand-crafted DB entry could trip us).
    pub fn get_long(&self, key: &[u8]) -> Option<i64> {
        let bytes = self.read_or_panic(key)?;
        Some(parse_long_permissive(&bytes))
    }

    /// Write a key as 8-byte big-endian signed long.
    pub fn put_long(&self, key: &[u8], value: i64) {
        self.write_or_panic(key, &value.to_be_bytes());
    }

    /// Read raw bytes for a key (no length validation).
    pub fn get_bytes(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.read_or_panic(key)
    }

    pub fn put_bytes(&self, key: &[u8], value: &[u8]) {
        self.write_or_panic(key, value);
    }

    // -------------------- Schema version (M-14) -----------------------

    /// Current chainbase schema version. Bump whenever a wire/disk format
    /// change makes a DB written by an older binary undecodable, so
    /// [`Self::check_or_stamp_schema_version`] refuses to open it instead
    /// of silently mis-decoding.
    pub const CURRENT_SCHEMA_VERSION: i64 = 1;

    /// The schema version stamped on this DB, or `None` if it predates
    /// schema-stamping.
    pub fn schema_version(&self) -> Option<i64> {
        self.get_long(keys::GOBLIN_SCHEMA_VERSION)
    }

    /// Stamp `version` (overwrites any existing).
    pub fn save_schema_version(&self, version: i64) {
        self.put_long(keys::GOBLIN_SCHEMA_VERSION, version);
    }

    /// Stamp [`Self::CURRENT_SCHEMA_VERSION`] on a DB with no version
    /// (fresh, or pre-versioning — grandfathered as current), or verify a
    /// stamped DB matches. `Err(found)` means the DB was written by an
    /// incompatible schema; the caller should refuse to open it rather
    /// than mis-decode. (M-14)
    pub fn check_or_stamp_schema_version(&self) -> Result<(), i64> {
        match self.schema_version() {
            None => {
                self.save_schema_version(Self::CURRENT_SCHEMA_VERSION);
                Ok(())
            }
            Some(v) if v == Self::CURRENT_SCHEMA_VERSION => Ok(()),
            Some(v) => Err(v),
        }
    }

    /// Read a key as a 32-byte hash.
    pub fn get_hash(&self, key: &[u8]) -> Result<Option<[u8; 32]>, StoreError> {
        let Some(bytes) = self.backend.get(key)? else {
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
        self.write_or_panic(key, hash);
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

    /// `state_flag`: `1` iff the LATEST applied block crossed a
    /// maintenance boundary (java's `saveStateFlag`, written by
    /// `MaintenanceManager.applyBlock` on every block). Read by the
    /// next block's slot math — `DposSlot.getTime` adds
    /// `MAINTENANCE_SKIP_SLOTS` (2) to the expected slot when the head
    /// block was a maintenance block, so the production pause around
    /// maintenance is not attributed to SRs as missed slots.
    pub fn state_flag(&self) -> i64 {
        self.get_long(keys::STATE_FLAG).unwrap_or(0)
    }
    pub fn save_state_flag(&self, flag: i64) {
        // java writes this key as a 4-byte big-endian int
        // (`ByteArray.fromInt`); match the on-disk byte format so
        // state-diff tooling sees identical bytes. Our permissive
        // reader handles either width.
        self.write_or_panic(keys::STATE_FLAG, &(flag as i32).to_be_bytes());
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

    /// `MAX_FEE_LIMIT` — the ceiling a VM transaction's `fee_limit` may not
    /// exceed (java-tron `getMaxFeeLimit`, initialized to `1_000_000_000` sun
    /// at genesis and adjustable by proposal within `[0, 10_000_000_000]`).
    /// java's `VMActuator.validate` rejects `feeLimit < 0 || feeLimit >
    /// getMaxFeeLimit()`. We fall back to the genesis default if the key is
    /// somehow absent.
    pub fn max_fee_limit(&self) -> i64 {
        self.get_long(b"MAX_FEE_LIMIT").unwrap_or(1_000_000_000)
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
    /// `DynamicPropertiesStore.addTotalNetWeight(long amount)`. Adds with
    /// `wrapping_add` to match java-tron's plain `long +=`, which wraps on
    /// i64 overflow rather than throwing — exact parity at the (in-practice
    /// impossible) overflow boundary, where saturating would have diverged
    /// to `i64::MAX` while java wraps negative (M-9). The other
    /// `add_total_*` accumulators below do the same.
    pub fn add_total_net_weight(&self, delta: i64) {
        let cur = self.total_net_weight();
        self.save_total_net_weight(cur.wrapping_add(delta));
    }

    /// Chain-wide TRON_POWER (voting) frozen weight. Mirrors java-tron's
    /// `addTotalTronPowerWeight` — bumped by FreezeBalanceV2/UnfreezeBalanceV2
    /// for `resource = TRON_POWER`. (TRON_POWER can't be delegated, so the
    /// basis is just the account's TRON_POWER frozen-V2 sum.)
    pub fn total_tron_power_weight(&self) -> i64 {
        self.get_long(keys::TOTAL_TRON_POWER_WEIGHT).unwrap_or(0)
    }
    pub fn save_total_tron_power_weight(&self, v: i64) {
        self.put_long(keys::TOTAL_TRON_POWER_WEIGHT, v);
    }
    pub fn add_total_tron_power_weight(&self, delta: i64) {
        let cur = self.total_tron_power_weight();
        self.save_total_tron_power_weight(cur.wrapping_add(delta));
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
        if delta != 0 && std::env::var("TRON_WTRACE").is_ok() {
            eprintln!("WTRACE_STORE add_total_energy_weight delta={} old={} new={}", delta, cur, cur.wrapping_add(delta));
        }
        self.save_total_energy_weight(cur.wrapping_add(delta));
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

    /// java-tron `supportVM()` = `getAllowCreationOfContracts() == 1`.
    /// Gates the VM byte-accounting branch in the bandwidth processor
    /// (clear-ret size + `MAX_RESULT_SIZE_IN_TX` padding).
    pub fn support_vm(&self) -> bool {
        self.get_long(keys::ALLOW_CREATION_OF_CONTRACTS) == Some(1)
    }

    /// java-tron `getMultiSignFee()` — initialized to 1 TRX at genesis.
    pub fn multi_sign_fee(&self) -> i64 {
        self.get_long(keys::MULTI_SIGN_FEE).unwrap_or(1_000_000)
    }

    /// java-tron `getMemoFee()` — initialized from node config (0 by
    /// default); set on mainnet by SR proposal #68.
    pub fn memo_fee(&self) -> i64 {
        self.get_long(keys::MEMO_FEE).unwrap_or(0)
    }

    /// java-tron `allowConsensusLogicOptimization()`.
    pub fn allow_consensus_logic_optimization(&self) -> bool {
        self.get_long(keys::CONSENSUS_LOGIC_OPTIMIZATION) == Some(1)
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

    /// `getAllowCancelAllUnfreezeV2()` — 0 when unset.
    pub fn allow_cancel_all_unfreeze_v2(&self) -> i64 {
        self.get_long(keys::ALLOW_CANCEL_ALL_UNFREEZE_V2).unwrap_or(0)
    }
    pub fn save_allow_cancel_all_unfreeze_v2(&self, v: i64) {
        self.put_long(keys::ALLOW_CANCEL_ALL_UNFREEZE_V2, v);
    }
    /// java-tron `supportAllowCancelAllUnfreezeV2()` — gates the
    /// precision-scaled (V2) per-account usage-window math.
    pub fn support_allow_cancel_all_unfreeze_v2(&self) -> bool {
        self.allow_cancel_all_unfreeze_v2() == 1 && self.unfreeze_delay_days() > 0
    }

    /// java-tron `getHeadSlot()` =
    /// `(latestBlockHeaderTimestamp - genesisBlockTimestamp) /
    /// BLOCK_PRODUCED_INTERVAL`. The slot unit used by the windowed-average
    /// resource math (`latest_consume_time(_for_energy)` are stored in it).
    /// Note this is **not** the block height (genesis ts is 0 on mainnet, so
    /// the slot counts from the unix epoch and far exceeds the height).
    pub fn head_slot(&self) -> i64 {
        const BLOCK_PRODUCED_INTERVAL_MS: i64 = 3_000;
        let ts = self.latest_block_header_timestamp().unwrap_or(0);
        let genesis = self.genesis_block_timestamp().unwrap_or(0);
        (ts - genesis) / BLOCK_PRODUCED_INTERVAL_MS
    }

    /// java's `supportTransactionFeePool()`: the `ALLOW_TRANSACTION_FEE_POOL`
    /// proposal flag is `1`. When on, tx fees flow into the
    /// `TRANSACTION_FEE_POOL` accumulator instead of being burned.
    ///
    /// Mainnet has NEVER activated this flag (it is 0), but every mainnet
    /// database contains the `TRANSACTION_FEE_POOL` balance key — so the
    /// previous check (`key exists`) was always-true on imported state and
    /// silently routed EVERY bandwidth/energy fee into the pool key while
    /// java burned them: `BURN_TRX_AMOUNT` froze at its snapshot value
    /// (~4.6M TRX/day of missed burn accounting) and the pool key grew a
    /// value java doesn't have. Balances were unaffected (the fee left the
    /// payer either way).
    pub fn support_transaction_fee_pool(&self) -> bool {
        self.get_long(keys::ALLOW_TRANSACTION_FEE_POOL).unwrap_or(0) == 1
    }

    pub fn add_transaction_fee_pool(&self, amount: i64) {
        let cur = self.get_long(keys::TRANSACTION_FEE_POOL).unwrap_or(0);
        self.put_long(keys::TRANSACTION_FEE_POOL, cur.wrapping_add(amount));
    }

    /// Historic energy-price schedule (`unix_ms:price` pairs, comma-joined).
    /// java's `getEnergyPriceHistory` — falls back to the
    /// `DEFAULT_ENERGY_PRICE_HISTORY` ("0:100") when the key is absent.
    pub fn energy_price_history(&self) -> String {
        self.get_bytes(keys::ENERGY_PRICE_HISTORY)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| "0:100".to_string())
    }
    pub fn save_energy_price_history(&self, history: &str) {
        self.write_or_panic(keys::ENERGY_PRICE_HISTORY, history.as_bytes());
    }

    /// Historic bandwidth-price schedule. java's
    /// `getBandwidthPriceHistory` — default "0:10"
    /// (`DEFAULT_TRANSACTION_FEE`).
    pub fn bandwidth_price_history(&self) -> String {
        self.get_bytes(keys::BANDWIDTH_PRICE_HISTORY)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| "0:10".to_string())
    }
    pub fn save_bandwidth_price_history(&self, history: &str) {
        self.write_or_panic(keys::BANDWIDTH_PRICE_HISTORY, history.as_bytes());
    }

    /// Current `TRANSACTION_FEE_POOL` balance (0 when the key is absent).
    pub fn transaction_fee_pool(&self) -> i64 {
        self.get_long(keys::TRANSACTION_FEE_POOL).unwrap_or(0)
    }

    /// Overwrite the `TRANSACTION_FEE_POOL` balance — mirrors
    /// `DynamicPropertiesStore.saveTransactionFeePool`. Used by the
    /// per-block payout to drain the pool after rewarding the producer.
    pub fn save_transaction_fee_pool(&self, amount: i64) {
        self.put_long(keys::TRANSACTION_FEE_POOL, amount);
    }

    // -------------------- Fee accumulators -----------------------------

    pub fn total_transaction_cost(&self) -> i64 {
        self.get_long(keys::TOTAL_TRANSACTION_COST).unwrap_or(0)
    }
    pub fn add_total_transaction_cost(&self, amount: i64) {
        let cur = self.total_transaction_cost();
        self.put_long(keys::TOTAL_TRANSACTION_COST, cur.wrapping_add(amount));
    }

    pub fn burn_trx_amount(&self) -> i64 {
        self.get_long(keys::BURN_TRX_AMOUNT).unwrap_or(0)
    }
    /// Mirrors `DynamicPropertiesStore.burnTrx(amount)`.
    pub fn burn_trx(&self, amount: i64) {
        let cur = self.burn_trx_amount();
        self.put_long(keys::BURN_TRX_AMOUNT, cur.wrapping_add(amount));
    }

    pub fn total_create_account_cost(&self) -> i64 {
        self.get_long(keys::TOTAL_CREATE_ACCOUNT_COST).unwrap_or(0)
    }
    pub fn add_total_create_account_cost(&self, amount: i64) {
        let cur = self.total_create_account_cost();
        self.put_long(keys::TOTAL_CREATE_ACCOUNT_COST, cur.wrapping_add(amount));
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

#[cfg(test)]
mod schema_version_tests {
    use super::*;
    use crate::MemBackend;
    use std::sync::Arc;

    #[test]
    fn java_tron_version_number_does_not_collide_with_schema_stamp() {
        // Regression: a real java-tron snapshot stores its protocol version
        // (e.g. 34) under VERSION_NUMBER. Our schema stamp uses a DISTINCT
        // key, so the gate must NOT read 34 as our version — it stamps its
        // own and opens cleanly, leaving java-tron's value untouched.
        let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
        dp.put_long(keys::VERSION_NUMBER, 34); // java-tron's value

        assert!(
            dp.check_or_stamp_schema_version().is_ok(),
            "must not read java-tron's VERSION_NUMBER as our schema version"
        );
        assert_eq!(
            dp.schema_version(),
            Some(DynamicPropertiesStore::CURRENT_SCHEMA_VERSION)
        );
        // java-tron's VERSION_NUMBER is left exactly as it was.
        assert_eq!(dp.get_long(keys::VERSION_NUMBER), Some(34));
    }

    #[test]
    fn stamps_fresh_db_then_accepts_match_and_rejects_mismatch() {
        // M-14: schema-version stamp + open-time compatibility gate.
        let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
        // Fresh DB has no stamp; the check stamps CURRENT and succeeds.
        assert_eq!(dp.schema_version(), None);
        assert!(dp.check_or_stamp_schema_version().is_ok());
        assert_eq!(
            dp.schema_version(),
            Some(DynamicPropertiesStore::CURRENT_SCHEMA_VERSION)
        );
        // Re-opening a DB stamped with the matching version: ok.
        assert!(dp.check_or_stamp_schema_version().is_ok());
        // A DB stamped by an incompatible (future) schema is rejected.
        dp.save_schema_version(DynamicPropertiesStore::CURRENT_SCHEMA_VERSION + 1);
        assert_eq!(
            dp.check_or_stamp_schema_version(),
            Err(DynamicPropertiesStore::CURRENT_SCHEMA_VERSION + 1)
        );
    }
}
