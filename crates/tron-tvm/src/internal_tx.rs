//! Internal-transaction tracing — record per-frame `CALL` / `CREATE`
//! traces during EVM execution and surface them on the
//! `TransactionInfo.internal_transactions` proto field.
//!
//! Mirrors java-tron's `org.tron.common.runtime.InternalTransaction`
//! (chainbase) and `ProgramResult.addInternalTransaction` (per-call
//! accumulation in the program runtime).
//!
//! ## What we record
//!
//! For every nested `CALL` / `CALLCODE` / `DELEGATECALL` / `STATICCALL`
//! / `CALLTOKEN`, every nested `CREATE` / `CREATE2`, and every
//! `SELFDESTRUCT`, the inspector captures one [`InternalTxTrace`] entry:
//!
//! * caller / target (21-byte TRON addresses, `0x41` prefix)
//! * TRX call value (zero for STATICCALL / DELEGATECALL; the destroyed
//!   contract's balance for SELFDESTRUCT)
//! * TRC-10 token id + value (zero for non-CALLTOKEN frames)
//! * call data / init code (empty for SELFDESTRUCT)
//! * note: `"call"`, `"create"`, or `"suicide"`
//! * rejected: `true` if the frame itself or any **ancestor** frame
//!   reverted / halted (matches java-tron's `rejectInternalTransactions`
//!   semantics)
//!
//! ## What we do NOT record
//!
//! * The top-level frame — that **is** the user-facing transaction,
//!   not an internal one. Detected via "this is the first frame the
//!   inspector has seen" (depth check).
//!
//! ## How we attribute rejection
//!
//! On every frame start we push the current `internal_txs.len()` onto
//! a `frame_starts` stack. On frame end, if the frame reverted/halted,
//! every entry in `internal_txs[start..]` is marked `rejected = true`.
//! Because a parent's revert always happens **after** its children's
//! frame_ends (the EVM unwinds bottom-up), success-then-parent-revert
//! correctly flips the children's flag too.

use revm::primitives::U256;

/// One captured internal transaction. The encoding into proto happens
/// at the executor → store boundary; this struct is the VM-internal
/// representation.
#[derive(Debug, Clone)]
pub struct InternalTxTrace {
    /// 21-byte TRON address of the frame's caller.
    pub caller_address: [u8; 21],
    /// 21-byte TRON address of the frame's target (callee, or — for
    /// a CREATE — the freshly-derived contract address).
    pub transfer_to_address: [u8; 21],
    /// TRX value transferred (CALL/CREATE). `U256` to preserve full
    /// precision; the proto field is `int64` but java-tron treats it
    /// the same — overflow is a contract-author problem.
    pub call_value: U256,
    /// TRC-10 token id (non-zero only on CALLTOKEN frames).
    pub token_id: i64,
    /// TRC-10 token amount (non-zero only on CALLTOKEN frames).
    pub token_value: i64,
    /// Call data (CALL) or init code (CREATE).
    pub data: Vec<u8>,
    /// "call", "create", or "suicide" — matches the java-tron `note`
    /// field.
    pub note: &'static str,
    /// True if this frame OR any ancestor reverted/halted.
    pub rejected: bool,
}

impl InternalTxTrace {
    /// Render to the wire-format proto. Truncates `call_value` to
    /// `i64::MAX` if it overflows — matches java-tron behavior, which
    /// stores `BigInteger.longValueExact()` and accepts the resulting
    /// downcast.
    pub fn to_proto(&self, root_tx_id: &[u8; 32]) -> tron_proto::InternalTransaction {
        let trx_value = u256_to_i64_saturating(self.call_value);

        let mut call_values = Vec::new();
        if trx_value != 0 {
            call_values.push(tron_proto::internal_transaction::CallValueInfo {
                call_value: trx_value,
                token_id: String::new(),
            });
        }
        if self.token_value != 0 || self.token_id != 0 {
            call_values.push(tron_proto::internal_transaction::CallValueInfo {
                call_value: self.token_value,
                token_id: if self.token_id != 0 {
                    self.token_id.to_string()
                } else {
                    String::new()
                },
            });
        }

        tron_proto::InternalTransaction {
            hash: root_tx_id.to_vec(),
            caller_address: self.caller_address.to_vec(),
            transfer_to_address: self.transfer_to_address.to_vec(),
            call_value_info: call_values,
            note: self.note.as_bytes().to_vec(),
            rejected: self.rejected,
            extra: String::new(),
        }
    }
}

fn u256_to_i64_saturating(v: U256) -> i64 {
    // Anything that fits in u64 maps directly; we then saturate to i64.
    let bytes = v.to_be_bytes::<32>();
    // Top 24 bytes non-zero → definitely > u64::MAX, saturate.
    if bytes[..24].iter().any(|b| *b != 0) {
        return i64::MAX;
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[24..]);
    let as_u64 = u64::from_be_bytes(low);
    as_u64.min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_saturation_handles_overflow() {
        assert_eq!(u256_to_i64_saturating(U256::ZERO), 0);
        assert_eq!(u256_to_i64_saturating(U256::from(42u64)), 42);
        assert_eq!(
            u256_to_i64_saturating(U256::from(i64::MAX as u64)),
            i64::MAX
        );
        // u64::MAX > i64::MAX → saturates to i64::MAX.
        assert_eq!(u256_to_i64_saturating(U256::from(u64::MAX)), i64::MAX);
        // Anything above 2^64 saturates.
        let big = U256::from(u64::MAX) + U256::from(1u64);
        assert_eq!(u256_to_i64_saturating(big), i64::MAX);
    }

    #[test]
    fn to_proto_emits_trx_then_token_call_value_entries() {
        let trace = InternalTxTrace {
            caller_address: [0x41; 21],
            transfer_to_address: [0x42; 21],
            call_value: U256::from(100u64),
            token_id: 1000001,
            token_value: 50,
            data: vec![0xab, 0xcd],
            note: "call",
            rejected: false,
        };
        let root = [0x99u8; 32];
        let proto = trace.to_proto(&root);
        assert_eq!(proto.hash, root.to_vec());
        assert_eq!(proto.caller_address, vec![0x41; 21]);
        assert_eq!(proto.transfer_to_address, vec![0x42; 21]);
        assert_eq!(proto.note, b"call");
        assert!(!proto.rejected);
        // Two entries: TRX first, then TRC-10.
        assert_eq!(proto.call_value_info.len(), 2);
        assert_eq!(proto.call_value_info[0].call_value, 100);
        assert_eq!(proto.call_value_info[0].token_id, "");
        assert_eq!(proto.call_value_info[1].call_value, 50);
        assert_eq!(proto.call_value_info[1].token_id, "1000001");
    }

    #[test]
    fn to_proto_omits_zero_trx_entry() {
        let trace = InternalTxTrace {
            caller_address: [0x41; 21],
            transfer_to_address: [0x42; 21],
            call_value: U256::ZERO,
            token_id: 0,
            token_value: 0,
            data: vec![],
            note: "call",
            rejected: false,
        };
        let proto = trace.to_proto(&[0u8; 32]);
        assert_eq!(proto.call_value_info.len(), 0);
    }
}
