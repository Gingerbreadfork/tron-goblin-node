//! Per-tx snapshot of the `ALLOW_TVM_*` chain proposals.
//!
//! Hard-fork gating in TRON is consensus-critical: each EVM feature
//! shipped at a given Ethereum hardfork is exposed through a separate
//! `ALLOW_TVM_*` chain proposal, and TVM-specific opcodes / precompiles
//! have their own proposal gates too. This module is the single place
//! that reads those flags from [`DynamicPropertiesStore`] and produces
//! the data the rest of the VM needs:
//!
//! * [`ProposalSet::resolve_spec`] returns the [`SpecId`] revm should
//!   run at — picks the highest activated standard-EVM proposal. Note
//!   TRON has no explicit Berlin proposal; activating London implies
//!   Berlin (EIP-2929/2930) the same way revm's spec ordering does.
//! * The boolean fields gate individual TRON-specific opcodes (in
//!   `evm::install_tron_opcode_stubs`) and TRON-specific precompiles
//!   (in `evm::TronPrecompiles::dispatch_tron`).
//!
//! Source for the mapping: java-tron
//! `actuator/.../vm/OperationRegistry.java` (which Operation depends on
//! which `VMConfig::allowTvm*` supplier) and
//! `actuator/.../vm/PrecompiledContracts.java` (the per-address
//! `if (VMConfig.allowXyz())` gates).

use revm::primitives::hardfork::SpecId;
use tron_chainbase::DynamicPropertiesStore;

/// Snapshot of every `ALLOW_TVM_*` and `ALLOW_*` proposal the VM cares
/// about. Constructed once per tx via [`ProposalSet::from_store`]; the
/// individual fields drive [`resolve_spec`] and the per-opcode /
/// per-precompile gates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProposalSet {
    /// `ALLOW_TVM_CONSTANTINOPLE` — SHL/SHR/SAR, CREATE2, EXTCODEHASH.
    /// Mapped to revm `PETERSBURG` (TRON skips the buggy Constantinople
    /// EIP-1283; Petersburg is Constantinople-minus-1283 in revm).
    pub allow_tvm_constantinople: bool,
    /// `ALLOW_TVM_SOLIDITY_059` — TRON-specific `ISCONTRACT` (0xd4)
    /// opcode and the `batchValidateSign` / `validateMultiSign`
    /// precompiles. Doesn't bump the standard `SpecId`.
    pub allow_tvm_solidity_059: bool,
    /// `ALLOW_TVM_ISTANBUL` — CHAINID, SELFBALANCE, EIP-1108 cheaper
    /// bn128, EIP-1884 reprice. Mapped to revm `ISTANBUL`.
    pub allow_tvm_istanbul: bool,
    /// `ALLOW_TVM_LONDON` — BASEFEE (0x48), EIP-3529 refund cap.
    /// Mapped to revm `LONDON`. Implies BERLIN (EIP-2929/2930) via
    /// revm's spec ordering.
    pub allow_tvm_london: bool,
    /// `ALLOW_TVM_SHANGHAI` — PUSH0 (0x5f), EIP-3651 warm coinbase,
    /// EIP-3860 initcode-size limit. Mapped to revm `SHANGHAI`.
    pub allow_tvm_shanghai: bool,
    /// `ALLOW_TVM_CANCUN` — TLOAD (0x5c), TSTORE (0x5d), MCOPY (0x5e),
    /// EIP-6780 SELFDESTRUCT restriction. Mapped to revm `CANCUN`.
    pub allow_tvm_cancun: bool,
    /// `ALLOW_TVM_BLOB` — BLOBHASH (0x49), BLOBBASEFEE (0x4a). In revm
    /// these come with `CANCUN`; java-tron gates them on this separate
    /// proposal. We honour the split by leaving the spec at `CANCUN`
    /// when only `allow_tvm_cancun` is set and installing
    /// `OpcodeNotFound` overrides at 0x49 / 0x4a in that case.
    pub allow_tvm_blob: bool,

    // ---- TRON-specific opcode gates (0xd0..0xdf, scattered) ----
    /// `ALLOW_TVM_TRANSFER_TRC10` — `CALLTOKEN` (0xd0), `TOKENBALANCE`
    /// (0xd1), `CALLTOKENVALUE` (0xd2), `CALLTOKENID` (0xd3).
    pub allow_tvm_transfer_trc10: bool,
    /// `ALLOW_TVM_FREEZE` — Stake-1.0 opcodes: `FREEZE` (0xd5),
    /// `UNFREEZE` (0xd6), `FREEZEEXPIRETIME` (0xd7).
    pub allow_tvm_freeze: bool,
    /// `ALLOW_TVM_VOTE` — `VOTEWITNESS` (0xd8), `WITHDRAWREWARD`
    /// (0xd9), plus the `rewardBalance`, `isSrCandidate`, `voteCount`,
    /// `usedVoteCount`, `receivedVoteCount`, `totalVoteCount`
    /// precompiles.
    pub allow_tvm_vote: bool,
    /// `ALLOW_TVM_FREEZE_V2` — Stake-2.0 opcodes: `FREEZEBALANCEV2`
    /// (0xda), `UNFREEZEBALANCEV2` (0xdb), `CANCELALLUNFREEZEV2` (0xdc),
    /// `WITHDRAWEXPIREUNFREEZE` (0xdd), `DELEGATERESOURCE` (0xde),
    /// `UNDELEGATERESOURCE` (0xdf), plus the corresponding
    /// `availableUnfreezeV2Size` / `unfreezableBalanceV2` /
    /// `expireUnfreezeBalanceV2` / `delegatableResource` /
    /// `checkUnDelegateResource` / `resourceUsage` / `totalResource` /
    /// `totalDelegatedResource` / `totalAcquiredResource` precompiles.
    pub allow_tvm_freeze_v2: bool,
    /// `ALLOW_TVM_COMPATIBLE_EVM` — gates the Ethereum-compat extras:
    /// `ethRipemd160` and `blake2F` precompiles.
    pub allow_tvm_compatible_evm: bool,
    /// `ALLOW_SHIELDED_TRC20_TRANSACTION` — gates the shielded
    /// precompiles: `verifyMintProof`, `verifyTransferProof`,
    /// `verifyBurnProof`, `merkleHash`.
    pub allow_shielded_trc20_transaction: bool,
    /// `ALLOW_TVM_SELFDESTRUCT_RESTRICTION` (proposal #94 / TIP-6780) —
    /// SELFDESTRUCT destroys only contracts created in the same tx;
    /// pre-existing contracts just transfer their balance (java's
    /// `suicide2`). Decoupled from the Cancun opcode spec: the journal
    /// gate is overridden per-tx from this flag, and the SELFDESTRUCT
    /// base energy becomes `SUICIDE_V2` (5000).
    pub allow_tvm_selfdestruct_restriction: bool,
    /// `ALLOW_TVM_PRAGUE` (proposal #95). Mapped to revm `PRAGUE`.
    pub allow_tvm_prague: bool,
    /// `ALLOW_TVM_OSAKA` (proposal #96) — P256VERIFY (TIP-7951), CLZ
    /// (TIP-7939), ModExp bounds/repricing (TIP-7883). Mapped to revm
    /// `OSAKA`.
    pub allow_tvm_osaka: bool,
}

impl ProposalSet {
    /// Read every relevant proposal flag from the chain's
    /// `DynamicPropertiesStore` once, returning an immutable snapshot
    /// suitable for the whole transaction. A missing or unset proposal
    /// counts as off (`0`), matching java-tron's `getUnchecked` ⇒
    /// `Optional.empty()` default.
    pub fn from_store(dps: &DynamicPropertiesStore) -> Self {
        let flag = |key: &[u8]| dps.get_long(key).unwrap_or(0) == 1;
        Self {
            allow_tvm_constantinople: flag(b"ALLOW_TVM_CONSTANTINOPLE"),
            allow_tvm_solidity_059: flag(b"ALLOW_TVM_SOLIDITY_059"),
            allow_tvm_istanbul: flag(b"ALLOW_TVM_ISTANBUL"),
            allow_tvm_london: flag(b"ALLOW_TVM_LONDON"),
            allow_tvm_shanghai: flag(b"ALLOW_TVM_SHANGHAI"),
            allow_tvm_cancun: flag(b"ALLOW_TVM_CANCUN"),
            allow_tvm_blob: flag(b"ALLOW_TVM_BLOB"),
            allow_tvm_transfer_trc10: flag(b"ALLOW_TVM_TRANSFER_TRC10"),
            allow_tvm_freeze: flag(b"ALLOW_TVM_FREEZE"),
            allow_tvm_vote: flag(b"ALLOW_TVM_VOTE"),
            allow_tvm_freeze_v2: flag(b"ALLOW_TVM_FREEZE_V2"),
            allow_tvm_compatible_evm: flag(b"ALLOW_TVM_COMPATIBLE_EVM"),
            allow_shielded_trc20_transaction: flag(b"ALLOW_SHIELDED_TRC20_TRANSACTION"),
            allow_tvm_selfdestruct_restriction: flag(b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION"),
            allow_tvm_prague: flag(b"ALLOW_TVM_PRAGUE"),
            allow_tvm_osaka: flag(b"ALLOW_TVM_OSAKA"),
        }
    }

    /// All-proposals-on snapshot for tests that want today's mainnet
    /// behavior (Cancun + every TRON proposal active). Production code
    /// should always go through [`from_store`] so the actual chain state
    /// drives gating.
    pub const fn all_enabled() -> Self {
        Self {
            allow_tvm_constantinople: true,
            allow_tvm_solidity_059: true,
            allow_tvm_istanbul: true,
            allow_tvm_london: true,
            allow_tvm_shanghai: true,
            allow_tvm_cancun: true,
            allow_tvm_blob: true,
            allow_tvm_transfer_trc10: true,
            allow_tvm_freeze: true,
            allow_tvm_vote: true,
            allow_tvm_freeze_v2: true,
            allow_tvm_compatible_evm: true,
            allow_shielded_trc20_transaction: true,
            // NOT enabled here: #94 changes destroy semantics and adds
            // SUICIDE_V2 base energy (test fixtures predate it), and
            // Prague/Osaka aren't activated on mainnet. Tests that
            // exercise them opt in explicitly.
            allow_tvm_selfdestruct_restriction: false,
            allow_tvm_prague: false,
            allow_tvm_osaka: false,
        }
    }

    /// Resolve the highest standard-EVM hardfork active under these
    /// proposals. The TRON proposals are cumulative: enabling Cancun
    /// without explicitly enabling London is still valid (and implies
    /// LONDON via revm's spec ordering) but in practice they ship
    /// sequentially.
    ///
    /// Default (no proposals): `BYZANTIUM` — the original TVM behavior
    /// before any of the post-Byzantium proposals shipped.
    pub fn resolve_spec(&self) -> SpecId {
        if self.allow_tvm_osaka {
            return SpecId::OSAKA;
        }
        if self.allow_tvm_prague {
            return SpecId::PRAGUE;
        }
        if self.allow_tvm_cancun {
            return SpecId::CANCUN;
        }
        if self.allow_tvm_shanghai {
            return SpecId::SHANGHAI;
        }
        if self.allow_tvm_london {
            return SpecId::LONDON;
        }
        if self.allow_tvm_istanbul {
            return SpecId::ISTANBUL;
        }
        if self.allow_tvm_constantinople {
            return SpecId::PETERSBURG;
        }
        SpecId::BYZANTIUM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_resolves_to_byzantium() {
        let p = ProposalSet::default();
        assert_eq!(p.resolve_spec(), SpecId::BYZANTIUM);
    }

    #[test]
    fn constantinople_only_resolves_to_petersburg() {
        let mut p = ProposalSet::default();
        p.allow_tvm_constantinople = true;
        assert_eq!(p.resolve_spec(), SpecId::PETERSBURG);
    }

    #[test]
    fn istanbul_only_resolves_to_istanbul() {
        let mut p = ProposalSet::default();
        p.allow_tvm_istanbul = true;
        assert_eq!(p.resolve_spec(), SpecId::ISTANBUL);
    }

    #[test]
    fn london_resolves_to_london_and_implies_berlin() {
        let mut p = ProposalSet::default();
        p.allow_tvm_london = true;
        let spec = p.resolve_spec();
        assert_eq!(spec, SpecId::LONDON);
        assert!(spec.is_enabled_in(SpecId::BERLIN));
    }

    #[test]
    fn shanghai_resolves_to_shanghai() {
        let mut p = ProposalSet::default();
        p.allow_tvm_shanghai = true;
        assert_eq!(p.resolve_spec(), SpecId::SHANGHAI);
    }

    #[test]
    fn cancun_resolves_to_cancun_and_implies_everything_below() {
        let mut p = ProposalSet::default();
        p.allow_tvm_cancun = true;
        let spec = p.resolve_spec();
        assert_eq!(spec, SpecId::CANCUN);
        for lower in [
            SpecId::BYZANTIUM,
            SpecId::PETERSBURG,
            SpecId::ISTANBUL,
            SpecId::BERLIN,
            SpecId::LONDON,
            SpecId::SHANGHAI,
        ] {
            assert!(spec.is_enabled_in(lower), "CANCUN must imply {lower:?}");
        }
    }

    #[test]
    fn highest_active_proposal_wins_when_multiple_set() {
        let mut p = ProposalSet::default();
        p.allow_tvm_constantinople = true;
        p.allow_tvm_istanbul = true;
        p.allow_tvm_cancun = true;
        // Cancun is the highest → wins. Lower flags don't downgrade the
        // resolved spec.
        assert_eq!(p.resolve_spec(), SpecId::CANCUN);
    }

    #[test]
    fn all_enabled_resolves_to_cancun() {
        assert_eq!(ProposalSet::all_enabled().resolve_spec(), SpecId::CANCUN);
    }

    #[test]
    fn from_store_reads_zero_as_disabled() {
        use std::sync::Arc;
        use tron_chainbase::{KvBackend, MemBackend};
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let dps = DynamicPropertiesStore::new(backend);
        // Nothing set → all false.
        let p = ProposalSet::from_store(&dps);
        assert_eq!(p, ProposalSet::default());

        // `0` is also disabled (matches java-tron's `== 1` check).
        dps.put_long(b"ALLOW_TVM_CANCUN", 0);
        assert!(!ProposalSet::from_store(&dps).allow_tvm_cancun);

        // Any other non-1 value is also disabled (defensive: matches
        // java-tron's `allow == 1` comparison).
        dps.put_long(b"ALLOW_TVM_CANCUN", 2);
        assert!(!ProposalSet::from_store(&dps).allow_tvm_cancun);

        dps.put_long(b"ALLOW_TVM_CANCUN", 1);
        assert!(ProposalSet::from_store(&dps).allow_tvm_cancun);
    }

    #[test]
    fn from_store_reads_all_flags() {
        use std::sync::Arc;
        use tron_chainbase::{KvBackend, MemBackend};
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let dps = DynamicPropertiesStore::new(backend);
        for key in [
            b"ALLOW_TVM_CONSTANTINOPLE".as_slice(),
            b"ALLOW_TVM_SOLIDITY_059",
            b"ALLOW_TVM_ISTANBUL",
            b"ALLOW_TVM_LONDON",
            b"ALLOW_TVM_SHANGHAI",
            b"ALLOW_TVM_CANCUN",
            b"ALLOW_TVM_BLOB",
            b"ALLOW_TVM_TRANSFER_TRC10",
            b"ALLOW_TVM_FREEZE",
            b"ALLOW_TVM_VOTE",
            b"ALLOW_TVM_FREEZE_V2",
            b"ALLOW_TVM_COMPATIBLE_EVM",
            b"ALLOW_SHIELDED_TRC20_TRANSACTION",
        ] {
            dps.put_long(key, 1);
        }
        assert_eq!(ProposalSet::from_store(&dps), ProposalSet::all_enabled());
    }
}
