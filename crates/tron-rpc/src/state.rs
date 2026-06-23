//! Shared state for RPC handlers — typed references to the relevant
//! chainbase stores plus the chain-id constant. Built once at server
//! startup and cloned cheaply (interior Arcs) into each request.

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountAssetStore, AccountIdIndexStore, AccountStore, AssetIssueStore, AssetIssueV2Store,
    BalanceTraceStore, NullifierStore,
    BlockIndexStore, BlockStore, CodeStore, ContractStore, DelegatedResourceAccountIndexStore,
    DelegatedResourceStore, DelegationStore, DynamicPropertiesStore, ExchangeV2Store, KvBackend,
    MarketAccountStore, MarketOrderStore, MarketPairPriceToOrderStore, MarketPairToPriceStore,
    ProposalStore, StorageRowStore, TransactionHistoryStore, TransactionStore, WitnessStore,
};

/// Handle passed to every RPC method.
#[derive(Clone)]
pub struct RpcState {
    pub accounts: Arc<AccountStore>,
    pub blocks: Arc<BlockStore>,
    pub block_index: Arc<BlockIndexStore>,
    pub transactions: Arc<TransactionStore>,
    pub dyn_props: Arc<DynamicPropertiesStore>,
    /// Smart-contract bytecode lookup. Optional because a non-EVM
    /// configuration of the node may not stand up these stores.
    pub code: Option<Arc<CodeStore>>,
    /// Smart-contract storage-slot lookup.
    pub storage: Option<Arc<StorageRowStore>>,
    /// Optional governance/reward stores — required for the TRON-style
    /// methods (`listWitnesses`, `getReward`, `getDelegatedResource`,
    /// etc.). Absent in minimal Ethereum-compat configurations.
    pub witnesses: Option<Arc<WitnessStore>>,
    pub delegation: Option<Arc<DelegationStore>>,
    /// `reward-vi` store — legacy-reward (`ALLOW_OLD_REWARD_OPT`) fast
    /// path for `getReward` on voters whose window predates the new
    /// reward algorithm. Optional like the other governance stores.
    pub reward_vi: Option<Arc<tron_chainbase::RewardViStore>>,
    pub delegated_resources: Option<Arc<DelegatedResourceStore>>,
    pub proposals: Option<Arc<ProposalStore>>,
    pub assets_v2: Option<Arc<AssetIssueV2Store>>,
    /// Asset-issue store keyed by ASSET NAME (v1 layout). Needed by
    /// `getAssetIssueByName` / `getAssetIssueListByName`. Distinct from
    /// `assets_v2` (id-keyed) — when `ALLOW_SAME_TOKEN_NAME == 0`
    /// java-tron writes to both stores so the same row is reachable
    /// by either key.
    pub assets_v1: Option<Arc<AssetIssueStore>>,
    /// Per-account TRC10 balances split out of `Account` when
    /// `AllowAccountAssetOptimization` is active (the snapshot stores them
    /// here, with `Account.asset_v2` left empty + `asset_optimized=true`).
    /// `getAccount` merges them back (java-tron's `importAllAsset`). Absent
    /// ⇒ getAccount returns whatever inline `asset_v2` the account carries.
    pub account_assets: Option<Arc<AccountAssetStore>>,
    /// Shielded nullifier set — populated by ShieldedTransferActuator
    /// at apply-time. Needed by `is_spend` and the shielded TRC-20
    /// spent-check helpers. Absent on non-shielded configurations.
    pub nullifiers: Option<Arc<NullifierStore>>,
    pub exchanges_v2: Option<Arc<ExchangeV2Store>>,
    /// Raw backends for executing read-only EVM calls (`eth_call`).
    /// Cloned and wrapped in a `SessionBackend` per request so any
    /// state mutations are discarded on revert. `None` means
    /// `eth_call` returns `not supported`.
    pub eth_call_backends: Option<EthCallBackends>,
    /// Per-tx receipts / logs index.
    pub tx_history: Option<Arc<TransactionHistoryStore>>,
    /// Block-keyed receipts (`transactionRetStore`) — written at every
    /// apply when `[index]` is enabled, and present in archive
    /// snapshots. `gettransactioninfobyid` falls back to it (via the
    /// tx's stored block ref) when the tx-id-keyed history store has
    /// no entry, and `gettransactioninfobyblocknum` serves whole
    /// blocks from it directly.
    pub transaction_ret: Option<Arc<tron_chainbase::TransactionRetStore>>,
    /// Per-account id index — needed for `getAccountById`.
    pub account_id_index: Option<Arc<AccountIdIndexStore>>,
    /// Smart contract metadata store — needed for `getContract` /
    /// `getContractInfo`.
    pub contracts: Option<Arc<ContractStore>>,
    /// Contract ABI store — populated alongside `contracts`.
    pub abis: Option<Arc<AbiStore>>,
    /// Delegated-resource per-account index — needed for the v1/v2
    /// `getDelegatedResourceAccountIndex` family.
    pub delegated_resource_account_index: Option<Arc<DelegatedResourceAccountIndexStore>>,
    /// Raw backend behind `delegated_resource_account_index`. java's
    /// `getIndex`/`getV2Index` prefix-scan the FROM/TO slices
    /// (`0x01/0x02` for V1, `0x03/0x04` for V2) and sort by timestamp;
    /// the typed store exposes only point `get_raw`, so the prefix-scan
    /// in the RPC/gRPC handlers needs the raw `scan_prefix` here.
    pub delegated_resource_account_index_backend: Option<Arc<dyn KvBackend>>,
    /// Market (DEX) stores. All four are needed for the
    /// `getMarketOrder*` / `getMarketPair*` family; passing them
    /// independently lets a non-DEX node leave them unattached.
    pub market_orders: Option<Arc<MarketOrderStore>>,
    pub market_accounts: Option<Arc<MarketAccountStore>>,
    pub market_pair_to_price: Option<Arc<MarketPairToPriceStore>>,
    pub market_pair_price_to_order: Option<Arc<MarketPairPriceToOrderStore>>,
    /// Per-block balance-change trace. Populated by the executor when
    /// trace-recording is on; absent during read-only bringup until
    /// the executor-side write path lands.
    pub balance_trace: Option<Arc<BalanceTraceStore>>,
    /// Optional metrics sink. When attached, [`crate::server::dispatch`]
    /// records per-method request/error counters into it.
    pub metrics: Option<Arc<crate::metrics::Metrics>>,
    /// ERC-4337 bundler state (config + signing key + UserOp tracking). Present
    /// only when `[bundler] enable = true`; gates the `eth_*UserOperation`
    /// methods and `eth_supportedEntryPoints`.
    pub bundler: Option<Arc<crate::bundler::BundlerState>>,
    /// Shared filter registry for the `eth_newFilter` family. Built
    /// once at server start; each handler reads/mutates through `Arc`.
    pub filters: Arc<crate::filters::FilterRegistry>,
    /// Optional handle to a transaction mempool. When attached,
    /// `eth_sendRawTransaction` and `broadcastTransaction` accept
    /// incoming transactions; otherwise both endpoints return an
    /// "unsupported" error.
    pub mempool: Option<Arc<dyn crate::mempool::Mempool>>,
    /// Optional address-history index reader (the `/v1/accounts/...`
    /// surface). Attached by the node runtime when `[index]` is
    /// enabled; absent ⇒ the `/v1` endpoints answer with a clear
    /// "index not enabled" error.
    pub index: Option<tron_index::IndexReader>,
    /// Optional historical-state archive (the `/v1/archive/...`
    /// surface). Attached when `[index] capture_state_deltas` is on.
    pub archive: Option<crate::index_api::ArchiveApiState>,
    /// Optional verifiable state-commitment reader (the
    /// `/v1/commitment/...` surface). Attached when
    /// `[index.commitment] enabled` is on; absent ⇒ those routes answer
    /// `501 NOT_IMPLEMENTED`.
    pub commitment: Option<tron_index::CommitmentReader>,
    /// Optional firehose tail handle (the gRPC `tronfirehose.Firehose`
    /// service). Attached when `[index.firehose]` is enabled.
    pub firehose: Option<tron_index::FirehoseTailHandle>,
    pub chain_id: u64,
    /// `eth_call` / `eth_estimateGas` per-call gas cap. Defaults to
    /// 50M — the soft ceiling for heavy read-only calls (DEX
    /// simulations, big multi-hop swaps). Operators can lower this
    /// for public-facing nodes via the TOML `rpc.eth_call_gas_cap`
    /// field. Plumbed into revm's `CfgEnv::tx_gas_limit_cap` per
    /// call so anything above the cap returns `TxGasLimitGreaterThanCap`.
    pub eth_call_gas_cap: u64,
    /// `vm.supportConstant` java-tron gate. When `false`, the
    /// `triggerConstantContract` RPC returns an error rather than
    /// running. Operators that don't expose constant calls publicly
    /// keep this off (default). `eth_call` is always on — only the
    /// TRON-shape RPC consults this flag.
    pub support_constant: bool,
    /// `vm.estimateEnergy` java-tron gate. When `false`, the
    /// `estimateEnergy` RPC/gRPC throws `CONTRACT_VALIDATE_ERROR`
    /// ("this node does not support estimate energy") rather than
    /// running the binary search (java `Wallet.estimateEnergy`,
    /// `Args.estimateEnergy`). Independent of `support_constant`,
    /// though java additionally requires `support_constant` for
    /// estimate to work. Default `false`.
    pub estimate_energy: bool,
    /// `vm.estimateEnergyMaxRetry` — number of times the
    /// `estimateEnergy` binary search retries a single
    /// `cleanContextAndTriggerConstantContract` invocation on an
    /// OutOfTime (timeout) outcome before giving up. java clamps to
    /// `[0, 10]`; default `3`.
    pub estimate_energy_max_retry: u32,
    /// `vm.maxEnergyLimitForConstant` — the hard ceiling on energy a
    /// constant call (`triggerConstantContract` / `estimateEnergy`)
    /// may consume (java `CommonParameter.maxEnergyLimitForConstant`,
    /// default 100_000_000). A plain constant call (feeLimit 0)
    /// budgets exactly this; when a feeLimit is supplied the budget is
    /// `min(this, feeLimit / energyFee)` (java `VMActuator.validate`).
    /// Distinct from `eth_call_gas_cap`, which is the go-ethereum-style
    /// per-call gas cap for the `eth_call` family.
    pub constant_call_energy_limit: u64,
    /// `getEnergyFee()` (sun per energy) — needed by `estimateEnergy`
    /// to map between feeLimit (sun) and energy units during the
    /// binary search, and by the constant-call feeLimit→energy cap.
    /// java reads it from `DynamicPropertiesStore`; we cache the
    /// genesis/config default here and the live value is read from
    /// `dyn_props` at call time.
    pub energy_fee: i64,
    /// `getMaxFeeLimit()` (sun) — the upper bound `estimateEnergy`'s
    /// binary search starts from (java `dps.getMaxFeeLimit()`).
    pub max_fee_limit: i64,
    /// `vm.constantCallTimeoutMs`. Wall-clock budget (milliseconds)
    /// allowed for a single read-only EVM call (`eth_call`,
    /// `eth_estimateGas`, `triggerConstantContract`). `0` means no
    /// limit. java-tron interrupts the VM thread mid-execution; this
    /// port checks the elapsed time after the VM returns and surfaces
    /// a timeout error to the client. A separate session will install
    /// a deadline inspector to enable mid-execution preemption — until
    /// then, this gate is best-effort.
    pub constant_call_timeout_ms: i64,
    /// Optional WebSocket pubsub broker for `eth_subscribe`. When
    /// attached the WS handler is mounted on the HTTP router and
    /// the SyncDriver / SrRuntime / mempool fan events into it.
    /// When unset, WS connections are rejected with 404 — same shape
    /// as a node where the operator didn't enable subscriptions.
    pub pubsub: Option<Arc<crate::pubsub::PubSubBroker>>,
}

/// Bag of raw backends the read-only EVM call path wraps in a
/// `SessionBackend` per request. Stored alongside the typed stores so
/// the RPC handler doesn't need to invert the type erasure.
#[derive(Clone)]
pub struct EthCallBackends {
    pub accounts: Arc<dyn KvBackend>,
    pub code: Arc<dyn KvBackend>,
    pub storage: Arc<dyn KvBackend>,
    pub witnesses: Arc<dyn KvBackend>,
    pub contract_state: Arc<dyn KvBackend>,
    pub dyn_props: Arc<dyn KvBackend>,
    pub delegated_resources: Arc<dyn KvBackend>,
    pub delegation: Arc<dyn KvBackend>,
    pub contracts: Arc<dyn KvBackend>,
    pub block_index: Option<Arc<dyn KvBackend>>,
}

impl RpcState {
    /// Build from raw backends. Each store is wrapped once; the result
    /// is `Clone` for use in axum's typed-state extractor.
    pub fn new(
        accounts: Arc<dyn KvBackend>,
        blocks: Arc<dyn KvBackend>,
        block_index: Arc<dyn KvBackend>,
        transactions: Arc<dyn KvBackend>,
        dyn_props: Arc<dyn KvBackend>,
        chain_id: u64,
    ) -> Self {
        Self {
            accounts: Arc::new(AccountStore::new(accounts)),
            blocks: Arc::new(BlockStore::new(blocks)),
            block_index: Arc::new(BlockIndexStore::new(block_index)),
            transactions: Arc::new(TransactionStore::new(transactions)),
            dyn_props: Arc::new(DynamicPropertiesStore::new(dyn_props)),
            code: None,
            storage: None,
            witnesses: None,
            delegation: None,
            reward_vi: None,
            delegated_resources: None,
            proposals: None,
            assets_v2: None,
            assets_v1: None,
            account_assets: None,
            nullifiers: None,
            exchanges_v2: None,
            eth_call_backends: None,
            index: None,
            archive: None,
            commitment: None,
            firehose: None,
            tx_history: None,
            transaction_ret: None,
            account_id_index: None,
            filters: crate::filters::FilterRegistry::new(),
            mempool: None,
            chain_id,
            eth_call_gas_cap: 50_000_000,
            support_constant: false,
            estimate_energy: false,
            estimate_energy_max_retry: 3,
            constant_call_energy_limit: 100_000_000,
            energy_fee: 100,
            max_fee_limit: 15_000_000_000,
            constant_call_timeout_ms: 0,
            pubsub: None,
            contracts: None,
            abis: None,
            delegated_resource_account_index: None,
            delegated_resource_account_index_backend: None,
            market_orders: None,
            market_accounts: None,
            market_pair_to_price: None,
            market_pair_price_to_order: None,
            balance_trace: None,
            metrics: None,
            bundler: None,
        }
    }

    /// Attach the metrics sink. When set, the RPC dispatch table
    /// records per-method request and error counts into it.
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Enable the ERC-4337 bundler with resolved `[bundler]` config + signing key.
    pub fn with_bundler(mut self, bundler: Arc<crate::bundler::BundlerState>) -> Self {
        self.bundler = Some(bundler);
        self
    }

    pub fn with_mempool(mut self, mempool: Arc<dyn crate::mempool::Mempool>) -> Self {
        self.mempool = Some(mempool);
        self
    }

    pub fn with_tx_history(mut self, tx_history: Arc<dyn KvBackend>) -> Self {
        self.tx_history = Some(Arc::new(TransactionHistoryStore::new(tx_history)));
        self
    }

    /// Attach the block-keyed `transactionRetStore` (receipt fallback
    /// for the txinfo RPCs).
    pub fn with_transaction_ret(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.transaction_ret = Some(Arc::new(tron_chainbase::TransactionRetStore::new(backend)));
        self
    }

    /// Attach the address-history index reader, enabling the
    /// TronGrid-style `/v1/accounts/{address}/transactions` surface.
    pub fn with_index(mut self, reader: tron_index::IndexReader) -> Self {
        self.index = Some(reader);
        self
    }

    /// Attach the historical-state archive, enabling the
    /// `/v1/archive/...` at-height read surface.
    pub fn with_archive(mut self, archive: crate::index_api::ArchiveApiState) -> Self {
        self.archive = Some(archive);
        self
    }

    /// Attach the verifiable state-commitment reader, enabling the
    /// `/v1/commitment/...` root/status/proof surface.
    pub fn with_commitment(mut self, reader: tron_index::CommitmentReader) -> Self {
        self.commitment = Some(reader);
        self
    }

    /// Attach the firehose tail handle, enabling the gRPC
    /// server-stream sink surface.
    pub fn with_firehose(mut self, handle: tron_index::FirehoseTailHandle) -> Self {
        self.firehose = Some(handle);
        self
    }

    pub fn with_account_id_index(mut self, idx: Arc<dyn KvBackend>) -> Self {
        self.account_id_index = Some(Arc::new(AccountIdIndexStore::new(idx)));
        self
    }

    pub fn with_eth_call_backends(mut self, backends: EthCallBackends) -> Self {
        self.eth_call_backends = Some(backends);
        self
    }

    /// Attach the EVM-side stores. Required for `eth_getCode` and
    /// `eth_getStorageAt`.
    pub fn with_evm_stores(
        mut self,
        code: Arc<dyn KvBackend>,
        storage: Arc<dyn KvBackend>,
    ) -> Self {
        self.code = Some(Arc::new(CodeStore::new(code)));
        self.storage = Some(Arc::new(StorageRowStore::new(storage)));
        self
    }

    /// Attach governance/reward stores. Required for the TRON-style
    /// `listWitnesses`, `getReward`, `getDelegatedResource`,
    /// `listProposals`, `getAssetIssueById`, and `listExchanges`
    /// methods.
    pub fn with_governance_stores(
        mut self,
        witnesses: Arc<dyn KvBackend>,
        delegation: Arc<dyn KvBackend>,
        delegated_resources: Arc<dyn KvBackend>,
        proposals: Arc<dyn KvBackend>,
        assets_v2: Arc<dyn KvBackend>,
        exchanges_v2: Arc<dyn KvBackend>,
    ) -> Self {
        self.witnesses = Some(Arc::new(WitnessStore::new(witnesses)));
        self.delegation = Some(Arc::new(DelegationStore::new(delegation)));
        self.delegated_resources = Some(Arc::new(DelegatedResourceStore::new(delegated_resources)));
        self.proposals = Some(Arc::new(ProposalStore::new(proposals)));
        self.assets_v2 = Some(Arc::new(AssetIssueV2Store::new(assets_v2)));
        self.exchanges_v2 = Some(Arc::new(ExchangeV2Store::new(exchanges_v2)));
        self
    }

    /// Attach the `reward-vi` store (legacy-reward fast path for
    /// `getReward` — see the field docs).
    pub fn with_reward_vi(mut self, reward_vi: Arc<dyn KvBackend>) -> Self {
        self.reward_vi = Some(Arc::new(tron_chainbase::RewardViStore::new(reward_vi)));
        self
    }

    /// Override the `eth_call_gas_cap` from its 50M default. Set
    /// lower for public-facing nodes that want to throttle heavy
    /// read-only calls; set higher (up to whatever revm accepts) if
    /// internal-only.
    pub fn with_eth_call_gas_cap(mut self, cap: u64) -> Self {
        self.eth_call_gas_cap = cap;
        self
    }

    /// Toggle the `triggerConstantContract` RPC. When `false` the
    /// method returns an "unsupported" error matching java-tron's
    /// `Args.supportConstant=false` behavior. Independent of
    /// `eth_call`.
    pub fn with_support_constant(mut self, enabled: bool) -> Self {
        self.support_constant = enabled;
        self
    }

    /// Toggle the `estimateEnergy` RPC/gRPC. When `false` the method
    /// returns java-tron's `CONTRACT_VALIDATE_ERROR` ("this node does
    /// not support estimate energy"). java `Args.estimateEnergy`.
    pub fn with_estimate_energy(mut self, enabled: bool) -> Self {
        self.estimate_energy = enabled;
        self
    }

    /// Set the `estimateEnergy` binary-search retry budget
    /// (java-clamped to `[0, 10]` by the config layer). Used to retry a
    /// single constant-call probe on an OutOfTime outcome.
    pub fn with_estimate_energy_max_retry(mut self, retry: u32) -> Self {
        self.estimate_energy_max_retry = retry;
        self
    }

    /// Set the constant-call energy ceiling
    /// (`vm.maxEnergyLimitForConstant`, default 100M) and the
    /// `energyFee` / `maxFeeLimit` constants the constant-call and
    /// `estimateEnergy` paths use to map between feeLimit and energy.
    pub fn with_constant_call_budget(
        mut self,
        max_energy_for_constant: u64,
        energy_fee: i64,
        max_fee_limit: i64,
    ) -> Self {
        self.constant_call_energy_limit = max_energy_for_constant;
        self.energy_fee = energy_fee;
        self.max_fee_limit = max_fee_limit;
        self
    }

    /// Set the constant-call wall-clock budget. `0` (default) means no
    /// timeout. Non-zero values cause `eth_call` / `eth_estimateGas` /
    /// `triggerConstantContract` to return an error to the client when
    /// the VM run takes longer than the limit. java-tron's
    /// `vm.constantCallTimeoutMs`.
    pub fn with_constant_call_timeout_ms(mut self, ms: i64) -> Self {
        self.constant_call_timeout_ms = ms;
        self
    }

    /// Attach a WebSocket pubsub broker. With this attached, the
    /// server router exposes a `/ws` endpoint serving
    /// `eth_subscribe` over JSON-RPC. The runtime is responsible
    /// for feeding the broker — `pubsub::PubSubBroker::publish_*`
    /// from the block-apply path, mempool subscription bridge, etc.
    pub fn with_pubsub(mut self, broker: Arc<crate::pubsub::PubSubBroker>) -> Self {
        self.pubsub = Some(broker);
        self
    }

    /// Attach the contract metadata + ABI stores. Required for
    /// `getContract`, `getContractInfo`, and rich receipt formatting.
    pub fn with_contract_stores(
        mut self,
        contracts: Arc<dyn KvBackend>,
        abis: Arc<dyn KvBackend>,
    ) -> Self {
        self.contracts = Some(Arc::new(ContractStore::new(contracts)));
        self.abis = Some(Arc::new(AbiStore::new(abis)));
        self
    }

    /// Attach the per-account delegate index. Required for the
    /// `getDelegatedResourceAccountIndex` family.
    pub fn with_delegated_resource_account_index(
        mut self,
        idx: Arc<dyn KvBackend>,
    ) -> Self {
        self.delegated_resource_account_index =
            Some(Arc::new(DelegatedResourceAccountIndexStore::new(idx.clone())));
        // Retain the raw backend for the FROM/TO prefix scans java's
        // `getIndex`/`getV2Index` perform.
        self.delegated_resource_account_index_backend = Some(idx);
        self
    }

    /// Attach all four market (DEX) stores. Required for the
    /// `getMarket*` family.
    pub fn with_market_stores(
        mut self,
        market_orders: Arc<dyn KvBackend>,
        market_accounts: Arc<dyn KvBackend>,
        market_pair_to_price: Arc<dyn KvBackend>,
        market_pair_price_to_order: Arc<dyn KvBackend>,
    ) -> Self {
        self.market_orders = Some(Arc::new(MarketOrderStore::new(market_orders)));
        self.market_accounts = Some(Arc::new(MarketAccountStore::new(market_accounts)));
        self.market_pair_to_price = Some(Arc::new(MarketPairToPriceStore::new(market_pair_to_price)));
        self.market_pair_price_to_order =
            Some(Arc::new(MarketPairPriceToOrderStore::new(market_pair_price_to_order)));
        self
    }

    /// Attach the per-block balance-trace store. Required for
    /// `getBlockBalanceTrace`. When unattached the RPC method returns
    /// `Null`; when attached but empty (no executor writes), returns
    /// a zero-trace object.
    pub fn with_balance_trace(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.balance_trace = Some(Arc::new(BalanceTraceStore::new(backend)));
        self
    }

    /// Attach the asset-by-name (v1) store so
    /// `getAssetIssueByName` / `getAssetIssueListByName` can resolve.
    /// java-tron writes both v1 (name-keyed) and v2 (id-keyed) entries
    /// for every issue, so name lookups work even on
    /// `ALLOW_SAME_TOKEN_NAME == 1` chains for assets created before
    /// that proposal activated.
    pub fn with_assets_v1(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.assets_v1 = Some(Arc::new(AssetIssueStore::new(backend)));
        self
    }

    /// Attach the per-account TRC10 balance store (`account-asset`) so
    /// `getAccount` can merge optimized assets back into `asset_v2`
    /// (java-tron's `importAllAsset`).
    pub fn with_account_assets(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.account_assets = Some(Arc::new(AccountAssetStore::new(backend)));
        self
    }

    /// Attach the nullifier set so shielded `isSpend` /
    /// `isShieldedTrc20ContractNoteSpent` can resolve. The store is
    /// write-side by ShieldedTransferActuator during block apply;
    /// reads are membership checks.
    pub fn with_nullifiers(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.nullifiers = Some(Arc::new(NullifierStore::new(backend)));
        self
    }
}
