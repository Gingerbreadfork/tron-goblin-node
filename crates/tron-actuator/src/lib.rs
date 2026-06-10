//! Transaction-execution layer (the "actuator" tier in java-tron).
//!
//! For each TRON contract type (Transfer, Vote, Freeze, AssetIssue, …)
//! there's a pair of pure functions:
//!
//! * `validate_*` — read-only check that the contract is legal in the
//!   current state. Returns [`ActuatorError`] on rejection.
//! * `execute_*` — apply the state transition. Must only be called *after*
//!   a successful validate, and assumes the same state. The return value
//!   is an [`ExecutionResult`] with the energy/bandwidth consumed and
//!   any TRX burned.
//!
//! v1 scope: only `TransferContract` is wired up. The remaining 37
//! actuator types follow the same pattern (cf. the audit inventory in
//! the project's memory).

pub mod account;
pub mod asset;
pub mod contract_admin;
pub mod deferred;
pub mod delegate;
pub mod dispatch;
pub mod exchange;
pub mod freeze;
pub mod freeze_v2;
pub mod helpers;
pub mod market;
pub mod permission;
pub mod proposal;
pub mod shielded_transfer;
pub mod transfer;
pub mod vm;
pub mod vote_witness;
pub mod witness;

pub use dispatch::{dispatch_execute, dispatch_validate, ActuatorStores, ActuatorTxCtx};
pub use helpers::{check_add, check_mul, check_sub, decode_address};
pub use transfer::{execute_transfer, validate_transfer, ExecutionResult};
pub use vote_witness::{
    execute_vote_witness, tron_power_old_model, validate_vote_witness, MAX_VOTE_NUMBER,
    TRX_PRECISION,
};

/// Errors raised by validate or execute. Variants are deliberately
/// per-rule so the messages map cleanly back to java-tron's
/// `ContractValidateException` strings.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ActuatorError {
    #[error("invalid owner address")]
    InvalidOwnerAddress,
    #[error("invalid to address")]
    InvalidToAddress,
    #[error("invalid address")]
    InvalidAddress,
    #[error("cannot transfer TRX to yourself")]
    SelfTransfer,
    #[error("owner account does not exist")]
    OwnerAccountMissing,
    #[error("target account does not exist")]
    TargetAccountMissing,
    #[error("target account already exists")]
    AccountAlreadyExists,
    #[error("amount must be greater than 0")]
    NonPositiveAmount,
    #[error("insufficient balance: account has {balance}, needs {needed}")]
    InsufficientBalance { balance: i64, needed: i64 },
    #[error("arithmetic overflow")]
    Overflow,
    #[error("store error: {0}")]
    Store(String),

    // --- VoteWitness-specific -------------------------------------------
    #[error("VoteNumber must be more than 0")]
    EmptyVoteList,
    #[error("VoteNumber {got} exceeds max {max}")]
    TooManyVotes { got: usize, max: usize },
    #[error("invalid vote address")]
    InvalidVoteAddress,
    #[error("vote count must be greater than 0")]
    NonPositiveVoteCount,
    #[error("candidate account does not exist")]
    CandidateAccountMissing,
    #[error("candidate is not a registered witness")]
    CandidateWitnessMissing,
    #[error("total votes ({required}) exceed tron power ({tron_power})")]
    InsufficientTronPower { required: i64, tron_power: i64 },

    // --- Witness/governance ---------------------------------------------
    #[error("witness already exists")]
    WitnessAlreadyExists,
    #[error("witness does not exist")]
    WitnessMissing,
    #[error("invalid URL")]
    InvalidUrl,
    #[error("brokerage out of range (must be 0..=100)")]
    BrokerageOutOfRange,
    #[error("withdrawal allowance is zero")]
    NoAllowance,
    #[error("withdrawal too soon: must wait until {ready_at} (now {now})")]
    WithdrawTooSoon { ready_at: i64, now: i64 },

    // --- Account --------------------------------------------------------
    #[error("invalid account name")]
    InvalidAccountName,
    #[error("invalid account id")]
    InvalidAccountId,
    #[error("account already has a name")]
    AccountAlreadyNamed,
    #[error("account name already taken")]
    AccountNameTaken,
    #[error("account already has an id")]
    AccountAlreadyHasId,
    #[error("account id already taken")]
    AccountIdTaken,
    #[error("permission update requires allowMultiSign")]
    MultiSignNotAllowed,
    #[error("invalid permission configuration")]
    InvalidPermission,

    // --- Proposal -------------------------------------------------------
    #[error("proposal does not exist")]
    ProposalMissing,
    #[error("proposal has expired")]
    ProposalExpired,
    #[error("proposal already canceled")]
    ProposalCanceled,
    #[error("only the proposer can cancel a proposal")]
    NotProposalOwner,
    #[error("proposal already approved (or not approved) by this witness")]
    ProposalDuplicateApproval,
    #[error("proposal parameters empty")]
    EmptyProposalParameters,
    #[error("proposal parameter out of range")]
    ProposalParameterOutOfRange,

    // --- Asset ----------------------------------------------------------
    #[error("asset does not exist")]
    AssetMissing,
    #[error("asset name already taken")]
    AssetNameTaken,
    #[error("account already issued an asset")]
    AccountAlreadyIssuedAsset,
    #[error("asset issue period not started yet")]
    AssetIssueNotStarted,
    #[error("asset issue period ended")]
    AssetIssueEnded,
    #[error("insufficient asset balance: has {has}, needs {needs}")]
    InsufficientAssetBalance { has: i64, needs: i64 },
    #[error("no expired asset-supply unfreeze available")]
    NoUnfreezableAsset,

    // --- Freeze / resource ----------------------------------------------
    #[error("freeze amount below minimum (must be >= 1 TRX)")]
    FreezeTooSmall,
    #[error("invalid resource code")]
    InvalidResourceCode,
    #[error("V2 not enabled (supportUnfreezeDelay must be 1)")]
    UnfreezeDelayDisabled,
    #[error("nothing to unfreeze for this resource")]
    NothingToUnfreeze,
    #[error("unfreeze amount exceeds frozen balance")]
    UnfreezeExceedsFrozen,
    #[error("too many concurrent unfreeze entries (max {max})")]
    TooManyUnfreezes { max: usize },
    #[error("no expired unfreeze entry to withdraw")]
    NoExpiredUnfreeze,
    #[error("delegation not enabled")]
    DelegationDisabled,
    #[error("receiverAddress must not be the same as ownerAddress")]
    ReceiverSameAsOwner,
    #[error("delegated resource does not exist")]
    DelegatedResourceMissing,
    #[error("delegation receiver invalid or same as owner")]
    InvalidDelegationReceiver,
    #[error("delegation receiver is a contract")]
    DelegationToContract,
    #[error("no delegated resource to undelegate")]
    NothingToUndelegate,

    // --- Exchange / market ----------------------------------------------
    #[error("exchange does not exist")]
    ExchangeMissing,
    #[error("only the exchange creator can perform this operation")]
    NotExchangeOwner,
    #[error("token id not in this exchange's pair")]
    TokenNotInExchange,
    #[error("token quantity must be > 0")]
    NonPositiveTokenQuant,
    #[error("exchange balance limit exceeded")]
    ExchangeBalanceLimitExceeded,
    #[error("exchange output below expected amount")]
    ExchangeOutputBelowExpected,
    #[error("market not enabled")]
    MarketDisabled,
    #[error("market sell-token and buy-token must differ")]
    MarketSameTokens,
    #[error("market order does not exist")]
    MarketOrderMissing,
    #[error("market order already canceled or filled")]
    MarketOrderNotActive,

    // --- Smart contract admin -------------------------------------------
    #[error("smart contract does not exist")]
    ContractMissing,
    #[error("only the contract creator can perform this operation")]
    NotContractOwner,
    #[error("constantinople not enabled")]
    ConstantinopleDisabled,
    #[error("origin_energy_limit must be > 0")]
    NonPositiveEnergyLimit,
    #[error("consume_user_resource_percent must be in 0..=100")]
    PercentOutOfRange,

    // --- ShieldedTransferActuator ---------------------------------------
    #[error("validate error: {0}")]
    Validate(&'static str),
    #[error("execute error: {0}")]
    Execute(&'static str),
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    // --- Not yet implemented --------------------------------------------
    #[error("not implemented in this v1 port: {0}")]
    NotImplemented(&'static str),
}

impl From<tron_chainbase::StoreError> for ActuatorError {
    fn from(e: tron_chainbase::StoreError) -> Self {
        Self::Store(e.to_string())
    }
}
