//! This module contains [`Context`] struct and implements [`ContextTr`] trait for it.
use crate::{block::BlockEnv, cfg::CfgEnv, journal::Journal, tx::TxEnv, LocalContext};
use context_interface::{
    cfg::GasParams,
    context::{ContextError, ContextSetters, SStoreResult, SelfDestructResult, StateLoad},
    host::LoadError,
    journaled_state::AccountInfoLoad,
    Block, Cfg, ContextTr, Host, JournalTr, LocalContextTr, Transaction, TransactionType,
    TronDatabaseExt,
};
use database_interface::{Database, DatabaseRef, EmptyDB, WrapDatabaseRef};
use derive_where::derive_where;
use primitives::{
    hardfork::SpecId, hints_util::cold_path, Address, Log, StorageKey, StorageValue, B256, U256,
};

/// EVM context contains data that EVM needs for execution.
#[derive_where(Clone, Debug; BLOCK, CFG, CHAIN, TX, DB, JOURNAL, <DB as Database>::Error, LOCAL)]
pub struct Context<
    BLOCK = BlockEnv,
    TX = TxEnv,
    CFG = CfgEnv,
    DB: Database = EmptyDB,
    JOURNAL: JournalTr<Database = DB> = Journal<DB>,
    CHAIN = (),
    LOCAL: LocalContextTr = LocalContext,
> {
    /// Block information.
    pub block: BLOCK,
    /// Transaction information.
    pub tx: TX,
    /// Configurations.
    pub cfg: CFG,
    /// EVM State with journaling support and database.
    pub journaled_state: JOURNAL,
    /// Inner context.
    pub chain: CHAIN,
    /// Local context that is filled by execution.
    pub local: LOCAL,
    /// Error that happened during execution.
    pub error: Result<(), ContextError<DB::Error>>,
}

#[inline]
fn sync_cfg_to_journal<CFG: Cfg, JOURNAL: JournalTr>(cfg: &CFG, journal: &mut JOURNAL) {
    journal.set_spec_id(cfg.spec().into());
    journal.set_eip7708_config(
        cfg.is_eip7708_disabled(),
        cfg.is_eip7708_delayed_burn_disabled(),
    );
}

impl<
        BLOCK: Block,
        TX: Transaction,
        DB: Database + TronDatabaseExt,
        CFG: Cfg,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN,
        LOCAL: LocalContextTr,
    > ContextTr for Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
{
    type Block = BLOCK;
    type Tx = TX;
    type Cfg = CFG;
    type Db = DB;
    type Journal = JOURNAL;
    type Chain = CHAIN;
    type Local = LOCAL;

    #[inline]
    fn all(
        &self,
    ) -> (
        &Self::Block,
        &Self::Tx,
        &Self::Cfg,
        &Self::Db,
        &Self::Journal,
        &Self::Chain,
        &Self::Local,
    ) {
        let block = &self.block;
        let tx = &self.tx;
        let cfg = &self.cfg;
        let db = self.journaled_state.db();
        let journal = &self.journaled_state;
        let chain = &self.chain;
        let local = &self.local;

        (block, tx, cfg, db, journal, chain, local)
    }

    #[inline]
    fn all_mut(
        &mut self,
    ) -> (
        &Self::Block,
        &Self::Tx,
        &Self::Cfg,
        &mut Self::Journal,
        &mut Self::Chain,
        &mut Self::Local,
    ) {
        let block = &self.block;
        let tx = &self.tx;
        let cfg = &self.cfg;
        let journal = &mut self.journaled_state;
        let chain = &mut self.chain;
        let local = &mut self.local;

        (block, tx, cfg, journal, chain, local)
    }

    #[inline]
    fn error(&mut self) -> &mut Result<(), ContextError<<Self::Db as Database>::Error>> {
        &mut self.error
    }
}

impl<
        BLOCK: Block,
        TX: Transaction,
        DB: Database + TronDatabaseExt,
        CFG: Cfg,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN,
        LOCAL: LocalContextTr,
    > ContextSetters for Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
{
    fn set_tx(&mut self, tx: Self::Tx) {
        self.tx = tx;
    }

    fn set_block(&mut self, block: Self::Block) {
        self.block = block;
    }
}

impl<
        BLOCK: Block + Default,
        TX: Transaction + Default,
        DB: Database,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN: Default,
        LOCAL: LocalContextTr + Default,
        SPEC: Default + Into<SpecId> + Clone,
    > Context<BLOCK, TX, CfgEnv<SPEC>, DB, JOURNAL, CHAIN, LOCAL>
{
    /// Creates a new context with a new database type.
    ///
    /// This will create a new [`Journal`] object.
    pub fn new(db: DB, spec: SPEC) -> Self {
        let cfg = CfgEnv::new_with_spec(spec);
        let mut journaled_state = JOURNAL::new(db);
        sync_cfg_to_journal(&cfg, &mut journaled_state);
        Self {
            tx: TX::default(),
            block: BLOCK::default(),
            cfg,
            local: LOCAL::default(),
            journaled_state,
            chain: Default::default(),
            error: Ok(()),
        }
    }
}

impl<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL> Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
where
    BLOCK: Block,
    TX: Transaction,
    CFG: Cfg,
    DB: Database,
    JOURNAL: JournalTr<Database = DB>,
    LOCAL: LocalContextTr,
{
    /// Creates a new context with a new journal type. New journal needs to have the same database type.
    pub fn with_new_journal<OJOURNAL: JournalTr<Database = DB>>(
        self,
        mut journal: OJOURNAL,
    ) -> Context<BLOCK, TX, CFG, DB, OJOURNAL, CHAIN, LOCAL> {
        sync_cfg_to_journal(&self.cfg, &mut journal);
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: journal,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new database type.
    ///
    /// This will create a new [`Journal`] object.
    pub fn with_db<ODB: Database>(
        self,
        db: ODB,
    ) -> Context<BLOCK, TX, CFG, ODB, Journal<ODB>, CHAIN, LOCAL> {
        let mut journaled_state = Journal::new(db);
        sync_cfg_to_journal(&self.cfg, &mut journaled_state);
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new `DatabaseRef` type.
    pub fn with_ref_db<ODB: DatabaseRef>(
        self,
        db: ODB,
    ) -> Context<BLOCK, TX, CFG, WrapDatabaseRef<ODB>, Journal<WrapDatabaseRef<ODB>>, CHAIN, LOCAL>
    {
        let mut journaled_state = Journal::new(WrapDatabaseRef(db));
        sync_cfg_to_journal(&self.cfg, &mut journaled_state);
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new block type.
    pub fn with_block<OB: Block>(
        self,
        block: OB,
    ) -> Context<OB, TX, CFG, DB, JOURNAL, CHAIN, LOCAL> {
        Context {
            tx: self.tx,
            block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }
    /// Creates a new context with a new transaction type.
    pub fn with_tx<OTX: Transaction>(
        self,
        tx: OTX,
    ) -> Context<BLOCK, OTX, CFG, DB, JOURNAL, CHAIN, LOCAL> {
        Context {
            tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new chain type.
    pub fn with_chain<OC>(self, chain: OC) -> Context<BLOCK, TX, CFG, DB, JOURNAL, OC, LOCAL> {
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new chain type.
    pub fn with_cfg<OCFG: Cfg>(
        mut self,
        cfg: OCFG,
    ) -> Context<BLOCK, TX, OCFG, DB, JOURNAL, CHAIN, LOCAL> {
        sync_cfg_to_journal(&cfg, &mut self.journaled_state);
        Context {
            tx: self.tx,
            block: self.block,
            cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new local context type.
    pub fn with_local<OL: LocalContextTr>(
        self,
        local: OL,
    ) -> Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, OL> {
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Modifies the context configuration.
    #[must_use]
    pub fn modify_cfg_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut CFG),
    {
        f(&mut self.cfg);
        sync_cfg_to_journal(&self.cfg, &mut self.journaled_state);
        self
    }

    /// Modifies the context block.
    #[must_use]
    pub fn modify_block_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut BLOCK),
    {
        self.modify_block(f);
        self
    }

    /// Modifies the context transaction.
    #[must_use]
    pub fn modify_tx_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut TX),
    {
        self.modify_tx(f);
        self
    }

    /// Modifies the context chain.
    #[must_use]
    pub fn modify_chain_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut CHAIN),
    {
        self.modify_chain(f);
        self
    }

    /// Modifies the context database.
    #[must_use]
    pub fn modify_db_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut DB),
    {
        self.modify_db(f);
        self
    }

    /// Modifies the context journal.
    #[must_use]
    pub fn modify_journal_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut JOURNAL),
    {
        self.modify_journal(f);
        self
    }

    /// Modifies the context block.
    pub fn modify_block<F>(&mut self, f: F)
    where
        F: FnOnce(&mut BLOCK),
    {
        f(&mut self.block);
    }

    /// Modifies the context transaction.
    pub fn modify_tx<F>(&mut self, f: F)
    where
        F: FnOnce(&mut TX),
    {
        f(&mut self.tx);
    }

    /// Modifies the context configuration.
    pub fn modify_cfg<F>(&mut self, f: F)
    where
        F: FnOnce(&mut CFG),
    {
        f(&mut self.cfg);
        sync_cfg_to_journal(&self.cfg, &mut self.journaled_state);
    }

    /// Modifies the context chain.
    pub fn modify_chain<F>(&mut self, f: F)
    where
        F: FnOnce(&mut CHAIN),
    {
        f(&mut self.chain);
    }

    /// Modifies the context database.
    pub fn modify_db<F>(&mut self, f: F)
    where
        F: FnOnce(&mut DB),
    {
        f(self.journaled_state.db_mut());
    }

    /// Modifies the context journal.
    pub fn modify_journal<F>(&mut self, f: F)
    where
        F: FnOnce(&mut JOURNAL),
    {
        f(&mut self.journaled_state);
    }

    /// Modifies the local context.
    pub fn modify_local<F>(&mut self, f: F)
    where
        F: FnOnce(&mut LOCAL),
    {
        f(&mut self.local);
    }
}

// TRON fork — the additional `DB: TronDatabaseExt` bound is the
// half of the orphan-rule workaround that lets the Host impl call
// chainbase-aware methods on the database. Every Database type used
// by tron-tvm production code (TronDatabase) and every Database type
// reachable from this workspace (EmptyDB, WrapDatabaseRef, CacheDB,
// etc.) provides a TronDatabaseExt impl — see
// `revm-context-interface/src/tron_ext.rs`.
impl<
        BLOCK: Block,
        TX: Transaction,
        CFG: Cfg,
        DB: Database + TronDatabaseExt,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN,
        LOCAL: LocalContextTr,
    > Host for Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
{
    /* Block */

    fn basefee(&self) -> U256 {
        U256::from(self.block().basefee())
    }

    fn blob_gasprice(&self) -> U256 {
        U256::from(self.block().blob_gasprice().unwrap_or(0))
    }

    fn gas_limit(&self) -> U256 {
        U256::from(self.block().gas_limit())
    }

    fn difficulty(&self) -> U256 {
        self.block().difficulty()
    }

    fn prevrandao(&self) -> Option<U256> {
        self.block().prevrandao().map(|r| r.into())
    }

    #[inline]
    fn gas_params(&self) -> &GasParams {
        self.cfg().gas_params()
    }

    fn is_amsterdam_eip8037_enabled(&self) -> bool {
        self.cfg().is_amsterdam_eip8037_enabled()
    }

    #[inline]
    fn cpsb(&self) -> u64 {
        self.local().cpsb()
    }

    fn block_number(&self) -> U256 {
        self.block().number()
    }

    fn timestamp(&self) -> U256 {
        U256::from(self.block().timestamp())
    }

    fn beneficiary(&self) -> Address {
        self.block().beneficiary()
    }

    fn slot_num(&self) -> U256 {
        U256::from(self.block().slot_num())
    }

    fn chain_id(&self) -> U256 {
        U256::from(self.cfg().chain_id())
    }

    /* Transaction */

    fn effective_gas_price(&self) -> U256 {
        let basefee = self.block().basefee();
        U256::from(self.tx().effective_gas_price(basefee as u128))
    }

    fn caller(&self) -> Address {
        self.tx().caller()
    }

    fn blob_hash(&self, number: usize) -> Option<U256> {
        let tx = &self.tx();
        if tx.tx_type() != TransactionType::Eip4844 {
            return None;
        }
        tx.blob_versioned_hashes()
            .get(number)
            .map(|t| U256::from_be_bytes(t.0))
    }

    /* Config */

    fn max_initcode_size(&self) -> usize {
        self.cfg().max_initcode_size()
    }

    /* Database */

    fn block_hash(&mut self, requested_number: u64) -> Option<B256> {
        self.db_mut()
            .block_hash(requested_number)
            .map_err(|e| {
                cold_path();
                *self.error() = Err(e.into());
            })
            .ok()
    }

    /* Journal */

    /// Gets the transient storage value of `address` at `index`.
    fn tload(&mut self, address: Address, index: StorageKey) -> StorageValue {
        self.journal_mut().tload(address, index)
    }

    /// Sets the transient storage value of `address` at `index`.
    fn tstore(&mut self, address: Address, index: StorageKey, value: StorageValue) {
        self.journal_mut().tstore(address, index, value)
    }

    /// Emits a log owned by `address` with given `LogData`.
    fn log(&mut self, log: Log) {
        self.journal_mut().log(log);
    }

    /// Marks `address` to be deleted, with funds transferred to `target`.
    #[inline]
    fn selfdestruct(
        &mut self,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, LoadError> {
        self.journal_mut()
            .selfdestruct(address, target, skip_cold_load)
            .map_err(|e| {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    *self.error() = Err(err.into());
                }
                ret
            })
    }

    #[inline]
    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, LoadError> {
        self.journal_mut()
            .sstore_skip_cold_load(address, key, value, skip_cold_load)
            .map_err(|e| {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    *self.error() = Err(err.into());
                }
                ret
            })
    }

    #[inline]
    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, LoadError> {
        self.journal_mut()
            .sload_skip_cold_load(address, key, skip_cold_load)
            .map_err(|e| {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    *self.error() = Err(err.into());
                }
                ret
            })
    }

    #[inline]
    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, LoadError> {
        match self.journaled_state.load_account_info_skip_cold_load(
            address,
            load_code,
            skip_cold_load,
        ) {
            Ok(a) => Ok(a),
            Err(e) => {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    self.error = Err(err.into());
                }
                Err(ret)
            }
        }
    }

    // ====================================================================
    // TRON fork overrides — delegate to the database's TronDatabaseExt
    // impl instead of the upstream Host trait defaults (which return 0).
    //
    // The bound `DB: Database + TronDatabaseExt` on this impl ensures
    // every reachable database type has the methods available. See
    // `revm-context-interface/src/tron_ext.rs` for the trait and the
    // blanket impls covering revm-internal DBs.
    // ====================================================================

    fn tron_token_balance(&self, address: Address, token_id: i64) -> i64 {
        self.journaled_state.db().tron_token_balance(address, token_id)
    }

    fn tron_is_contract(&self, address: Address) -> bool {
        self.journaled_state.db().tron_is_contract(address)
    }

    fn tron_root_tx_id(&self) -> B256 {
        self.journaled_state.db().tron_root_tx_id()
    }

    fn tron_bump_create_nonce(&mut self) -> u64 {
        self.journaled_state.db_mut().tron_bump_create_nonce()
    }

    fn tron_record_created_contract(&mut self, address: Address, creator: Address, is_create2: bool) {
        self.journaled_state
            .db_mut()
            .tron_record_created_contract(address, creator, is_create2)
    }

    fn tron_freeze_expire_time(
        &self,
        caller_address: Address,
        target_address: Address,
        resource_type: u32,
    ) -> i64 {
        self.journaled_state.db().tron_freeze_expire_time(
            caller_address,
            target_address,
            resource_type,
        )
    }

    // ---- State-mutating bridges ----
    //
    // Each delegates to `db_mut()` so the underlying chainbase
    // stores receive the actuator-driven writes. Defaults on
    // TronDatabaseExt keep stock DBs (`EmptyDB` etc.) returning 0.

    fn tron_selfdestruct_restriction(&self) -> bool {
        self.journaled_state.tron_selfdestruct_restriction_effective()
    }

    fn tron_account_created_locally(&self, address: Address) -> bool {
        self.journaled_state.tron_account_created_locally(address)
    }

    fn tron_suicide(&mut self, owner: Address, obtainer: Address, will_destroy: bool) -> i64 {
        let result = self
            .journaled_state
            .db_mut()
            .tron_suicide(owner, obtainer, will_destroy);
        self.apply_tron_balance_deltas();
        result
    }

    fn tron_freeze(
        &mut self,
        caller: Address,
        frozen_balance: i64,
        frozen_duration: i64,
        resource_type: u32,
        receiver_address: Option<Address>,
    ) -> i64 {
        let result = self.journaled_state.db_mut().tron_freeze(
            caller,
            frozen_balance,
            frozen_duration,
            resource_type,
            receiver_address,
        );
        self.apply_tron_balance_delta();
        result
    }

    fn tron_unfreeze(
        &mut self,
        caller: Address,
        resource_type: u32,
        receiver_address: Option<Address>,
    ) -> i64 {
        let result = self
            .journaled_state
            .db_mut()
            .tron_unfreeze(caller, resource_type, receiver_address);
        self.apply_tron_balance_delta();
        result
    }

    fn tron_vote_witness(&mut self, caller: Address, witnesses: &[(Address, i64)]) -> i64 {
        let result = self.journaled_state.db_mut().tron_vote_witness(caller, witnesses);
        self.apply_tron_balance_delta();
        result
    }

    fn tron_withdraw_reward(&mut self, caller: Address) -> i64 {
        let result = self.journaled_state.db_mut().tron_withdraw_reward(caller);
        self.apply_tron_balance_delta();
        result
    }

    fn tron_freeze_balance_v2(
        &mut self,
        caller: Address,
        frozen_balance: i64,
        resource_type: u32,
    ) -> i64 {
        let result = self.journaled_state.db_mut().tron_freeze_balance_v2(
            caller,
            frozen_balance,
            resource_type,
        );
        self.apply_tron_balance_delta();
        result
    }

    fn tron_unfreeze_balance_v2(
        &mut self,
        caller: Address,
        unfreeze_balance: i64,
        resource_type: u32,
    ) -> i64 {
        let result = self.journaled_state.db_mut().tron_unfreeze_balance_v2(
            caller,
            unfreeze_balance,
            resource_type,
        );
        self.apply_tron_balance_delta();
        result
    }

    fn tron_cancel_all_unfreeze_v2(&mut self, caller: Address) -> i64 {
        let result = self.journaled_state.db_mut().tron_cancel_all_unfreeze_v2(caller);
        self.apply_tron_balance_delta();
        result
    }

    fn tron_withdraw_expire_unfreeze(&mut self, caller: Address) -> i64 {
        let result = self.journaled_state.db_mut().tron_withdraw_expire_unfreeze(caller);
        self.apply_tron_balance_delta();
        result
    }

    fn tron_delegate_resource(
        &mut self,
        caller: Address,
        balance: i64,
        receiver_address: Address,
        resource_type: u32,
        lock: bool,
        lock_period: i64,
    ) -> i64 {
        let result = self.journaled_state.db_mut().tron_delegate_resource(
            caller,
            balance,
            receiver_address,
            resource_type,
            lock,
            lock_period,
        );
        self.apply_tron_balance_delta();
        result
    }

    fn tron_undelegate_resource(
        &mut self,
        caller: Address,
        balance: i64,
        receiver_address: Address,
        resource_type: u32,
    ) -> i64 {
        let result = self.journaled_state.db_mut().tron_undelegate_resource(
            caller,
            balance,
            receiver_address,
            resource_type,
        );
        self.apply_tron_balance_delta();
        result
    }
}

impl<
        BLOCK: Block,
        TX: Transaction,
        CFG: Cfg,
        DB: Database + TronDatabaseExt,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN,
        LOCAL: LocalContextTr,
    > Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
{
    /// Helper used by every `tron_*` state-mutating bridge. Reads the
    /// side-channel delta the bridge stashed on `DB`, then applies it
    /// to the journaled balance via `balance_incr` (positive delta) or
    /// `balance_decr` (negative). On any DB error from the journal
    /// load, the delta is dropped — the bridge's chainbase write
    /// already happened, so we'd rather keep going than fail the call.
    #[inline]
    /// Multi-delta sibling of [`apply_tron_balance_delta`](Self::apply_tron_balance_delta)
    /// -- drains every pending delta (suicide moves several balances).
    fn apply_tron_balance_deltas(&mut self) {
        for (address, delta) in self.journaled_state.db_mut().tron_take_balance_deltas() {
            if delta == 0 || address == Address::ZERO {
                continue;
            }
            if delta > 0 {
                let _ = self.journaled_state.balance_incr(address, U256::from(delta as u64));
            } else {
                let abs = (-delta) as u64;
                let _ = self.journaled_state.balance_decr(address, U256::from(abs));
            }
        }
    }

    fn apply_tron_balance_delta(&mut self) {
        let (address, delta) = self.journaled_state.db_mut().tron_take_last_balance_delta();
        if delta == 0 || address == Address::ZERO {
            return;
        }
        if delta > 0 {
            let _ = self.journaled_state.balance_incr(address, U256::from(delta as u64));
        } else {
            let abs = (-delta) as u64;
            let _ = self.journaled_state.balance_decr(address, U256::from(abs));
        }
    }
}
