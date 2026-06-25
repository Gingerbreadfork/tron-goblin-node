//! Tests for the high-level `execute_trigger` API — the entry point
//! the block executor will call for `TriggerSmartContract` transactions.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_proto::TriggerSmartContract;
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    // Default to the post-ALLOW_TVM_TRANSFER_TRC10 (#15) mainnet era so a
    // top-level CALLTOKEN actually moves the TRC-10 amount. Pre-#15 the token
    // fields are ignored (no transfer) — that gate is verified by the dedicated
    // CALLTOKEN unit tests. Inert for calls carrying no token value/id.
    dynamic_properties.put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: None,
        reward_vi: None,
    abi: None,
    }
}

/// Pre-install a TRON contract by writing both the Account proto and the
/// CodeStore entry. The contract's 21-byte address is returned.
fn install_contract(stores: &VmStores, prefix: u8, bytecode: &[u8]) -> [u8; 21] {
    let mut tron_addr_bytes = [0u8; 21];
    tron_addr_bytes[0] = 0x41;
    tron_addr_bytes[1..].fill(prefix);
    let tron_addr = tron_crypto::address::Address::from_raw(tron_addr_bytes);
    let hash = code_hash(bytecode);
    stores.code.put(hash.as_slice(), bytecode).unwrap();
    stores.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 0,
            code_hash: hash.as_slice().to_vec(),
            code: bytecode.to_vec(),
            ..Default::default()
        },
    ).unwrap();
    tron_addr_bytes
}

fn fund_account(stores: &VmStores, prefix: u8, balance: i64) -> [u8; 21] {
    let mut tron_addr_bytes = [0u8; 21];
    tron_addr_bytes[0] = 0x41;
    tron_addr_bytes[1..].fill(prefix);
    let tron_addr = tron_crypto::address::Address::from_raw(tron_addr_bytes);
    stores.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance,
            ..Default::default()
        },
    ).unwrap();
    tron_addr_bytes
}

#[test]
fn execute_trigger_succeeds_for_simple_return_contract() {
    let stores = fresh_stores();
    // Bytecode: return 0x42 as a 32-byte word.
    let contract_addr = install_contract(
        &stores,
        0xc0,
        &[
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0
            0x52, // MSTORE
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xf3, // RETURN
        ],
    );
    let owner_addr = fund_account(&stores, 0xa0, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 100,
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
        },
        &trigger,
        100_000,
    );

    match outcome {
        VmOutcome::Success { return_data, .. } => {
            assert_eq!(return_data.len(), 32);
            assert_eq!(return_data[31], 0x42);
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

/// COINBASE (0x41) pushes the block's producing witness. java loads
/// `block.getWitnessAddress()` into the coinbase DataWord exactly like
/// ADDRESS/CALLER; we thread the 20-byte EVM-form witness through
/// `VmBlockEnv.beneficiary`, and the opcode must return it right-aligned in a
/// 32-byte word (12 leading zero bytes).
#[test]
fn coinbase_returns_block_producer_witness() {
    let stores = fresh_stores();
    //   COINBASE; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
    let contract_addr = install_contract(
        &stores,
        0xcc,
        &[
            0x41, // COINBASE
            0x60, 0x00, // PUSH1 0
            0x52, // MSTORE
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xf3, // RETURN
        ],
    );
    let owner_addr = fund_account(&stores, 0xac, 1_000_000_000);
    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let witness = [0x11u8; 20];
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 100,
            block_timestamp_ms: 1_700_000_000_000,
            beneficiary: witness,
        },
        &trigger,
        100_000,
    );
    match outcome {
        VmOutcome::Success { return_data, .. } => {
            assert_eq!(return_data.len(), 32);
            assert_eq!(&return_data[0..12], &[0u8; 12]);
            assert_eq!(&return_data[12..32], &witness);
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

/// A memory expansion past the 3 MiB cap (`EnergyCost.MEM_LIMIT`) must halt
/// with `OUT_OF_MEMORY`, NOT `OUT_OF_ENERGY`. java-tron's
/// `EnergyCost.checkMemorySize` throws `OutOfMemoryException` when
/// `newMemSize > MEM_LIMIT` (EnergyCost.java:543-547), which
/// `RuntimeImpl.setResultCode` maps to `contractResult OUT_OF_MEMORY`
/// (RuntimeImpl.java:110-112). revm surfaces the same cap breach as
/// `OutOfGasError::MemoryLimit`, distinct from an ordinary energy OOG.
#[test]
fn memory_expansion_past_3mib_halts_out_of_memory() {
    use tron_proto::transaction::result::ContractResult;

    let stores = fresh_stores();
    // MSTORE at byte offset 4 MiB (0x0040_0000) expands memory to 4 MiB + 32,
    // exceeding the 3 MiB hard cap → MemoryLimitOOG. MSTORE pops `offset`
    // (top of stack) then `value`, so push the value first and the offset on
    // top.
    //   PUSH1 0x00         // value
    //   PUSH4 0x00400000   // offset = 4 MiB (> 3 MiB cap)
    //   MSTORE
    //   STOP
    let contract_addr = install_contract(
        &stores,
        0xcb,
        &[
            0x60, 0x00, // PUSH1 0          (value)
            0x63, 0x00, 0x40, 0x00, 0x00, // PUSH4 0x00400000 (offset)
            0x52, // MSTORE
            0x00, // STOP
        ],
    );
    let owner_addr = fund_account(&stores, 0xab, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };

    // Generous energy budget — the cap check fires regardless of remaining
    // energy (revm checks `limit_reached` before recording the expansion
    // cost), so this must surface OUT_OF_MEMORY rather than OUT_OF_ENERGY.
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0, ..Default::default()
        },
        &trigger,
        100_000_000,
    );

    match outcome {
        VmOutcome::Halt { result, .. } => assert_eq!(
            result,
            ContractResult::OutOfMemory,
            "3 MiB cap breach must record OUT_OF_MEMORY, got {result:?}"
        ),
        other => panic!("expected Halt(OUT_OF_MEMORY), got {other:?}"),
    }
}

/// Regression: the `TIMESTAMP` / `NUMBER` opcodes must reflect the executing
/// block's env. They previously returned the revm BlockEnv defaults
/// (timestamp=1, number=0) because the block env was never populated, so any
/// `block.timestamp - t` underflowed (Panic 0x11) — the root cause of the
/// energy-rental / DeFi contractRet divergence cascade. TIMESTAMP is in
/// SECONDS (java `getTimestamp() / 1000`).
#[test]
fn block_timestamp_and_number_opcodes_reflect_block_env() {
    let stores = fresh_stores();
    let owner = fund_account(&stores, 0xa7, 1_000_000_000);
    let mk_trigger = |c: [u8; 21]| TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: c.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let env = || VmBlockEnv {
        block_number: 83_316_753,
        block_timestamp_ms: 1_700_000_001_000, ..Default::default()
    };
    let read_word = |o: VmOutcome| -> i64 {
        match o {
            VmOutcome::Success { return_data, .. } => {
                assert_eq!(return_data.len(), 32);
                i64::from_be_bytes(return_data[24..32].try_into().unwrap())
            }
            other => panic!("expected Success, got {other:?}"),
        }
    };

    // TIMESTAMP PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
    let ts_c = install_contract(&stores, 0x71, &[0x42, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3]);
    let ts = read_word(execute_trigger(&stores, env(), &mk_trigger(ts_c), 100_000));
    assert_eq!(ts, 1_700_000_001, "TIMESTAMP = block ts in seconds, not 1");

    // NUMBER PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
    let num_c = install_contract(&stores, 0x72, &[0x43, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3]);
    let num = read_word(execute_trigger(&stores, env(), &mk_trigger(num_c), 100_000));
    assert_eq!(num, 83_316_753, "NUMBER = block number, not 0");
}

#[test]
fn execute_trigger_top_level_calltoken_transfers_trc10_before_evm_runs() {
    use tron_crypto::address::Address;
    let stores = fresh_stores();
    let contract_addr = install_contract(&stores, 0xc1, &[0x00]); // STOP
    let owner_addr = fund_account(&stores, 0xa1, 1_000_000_000);

    // Seed sender with 1_000 of token id 1_000_001.
    let token_id: i64 = 1_000_001;
    let key = token_id.to_string();
    let mut owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    owner.asset_v2.insert(key.clone(), 1_000);
    stores.accounts.put(&Address::from_raw(owner_addr), &owner).unwrap();

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 250,
        token_id,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0, ..Default::default()
        },
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");

    // Sender: -250, Recipient: +250.
    let after_owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    assert_eq!(after_owner.asset_v2.get(&key).copied(), Some(750));
    let after_contract = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(after_contract.asset_v2.get(&key).copied(), Some(250));
}

#[test]
fn execute_trigger_top_level_calltoken_unwinds_on_revert() {
    use tron_crypto::address::Address;
    let stores = fresh_stores();
    // PUSH1 0 PUSH1 0 REVERT
    let contract_addr = install_contract(&stores, 0xc2, &[0x60, 0x00, 0x60, 0x00, 0xfd]);
    let owner_addr = fund_account(&stores, 0xa2, 1_000_000_000);
    let token_id: i64 = 1_000_002;
    let key = token_id.to_string();
    let mut owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    owner.asset_v2.insert(key.clone(), 500);
    stores.accounts.put(&Address::from_raw(owner_addr), &owner).unwrap();

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 200,
        token_id,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 0, ..Default::default()},
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::Revert { .. }));

    // After revert, sender's balance is fully restored.
    let after_owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    assert_eq!(after_owner.asset_v2.get(&key).copied(), Some(500));
    let after_contract = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap();
    // Contract may or may not exist with the asset map; either way,
    // its balance for `token_id` must be 0.
    if let Some(c) = after_contract {
        assert_eq!(c.asset_v2.get(&key).copied().unwrap_or(0), 0);
    }
}

#[test]
fn execute_trigger_top_level_calltoken_rejects_insufficient_balance() {
    let stores = fresh_stores();
    let contract_addr = install_contract(&stores, 0xc3, &[0x00]);
    let owner_addr = fund_account(&stores, 0xa3, 1_000_000_000);
    // Owner has no asset_v2 entry — balance is 0.
    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 100,
        token_id: 1_000_003,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 0, ..Default::default()},
        &trigger,
        100_000,
    );
    match outcome {
        VmOutcome::PreflightError(s) => assert!(s.contains("sender has 0")),
        other => panic!("expected PreflightError, got {other:?}"),
    }
}

#[test]
fn execute_trigger_reports_revert_for_revert_opcode() {
    let stores = fresh_stores();
    // Bytecode: REVERT immediately with no data.
    // PUSH1 0 PUSH1 0 REVERT
    let contract_addr = install_contract(&stores, 0xc2, &[0x60, 0x00, 0x60, 0x00, 0xfd]);
    let owner_addr = fund_account(&stores, 0xa2, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0, ..Default::default()
        },
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::Revert { .. }), "got {outcome:?}");
}

#[test]
fn execute_trigger_rejects_bad_address() {
    let stores = fresh_stores();
    let trigger = TriggerSmartContract {
        owner_address: vec![0x42; 20], // wrong length / prefix
        contract_address: vec![0x41; 21],
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 0,
            block_timestamp_ms: 0, ..Default::default()
        },
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::PreflightError(_)), "got {outcome:?}");
}

/// TRON has **no** SSTORE-clear energy refund, unlike Ethereum.
///
/// java-tron removed the EthereumJ refund machinery: `Program.java` has
/// `futureRefundEnergy`/`resetFutureRefund` commented out, `storageSave`
/// performs no refund, and `EnergyCost.getSstoreCost` returns a flat
/// `CLEAR_SSTORE = 5000` for clearing a slot to zero — the same as a
/// `RESET_SSTORE`, with no offsetting refund. So clearing a slot and
/// overwriting it with another non-zero value cost the *same* energy.
///
/// (A previous revision of this test asserted the opposite — that a clear
/// refunds — which was Ethereum behaviour leaking through revm's gas model;
/// that was the energy-parity bug. The TRON gas schedule pins gas decisions
/// to Frontier and zeroes the clear refund, matching java-tron.)
#[test]
fn sstore_clear_does_not_refund_matching_java_tron() {
    fn run_contract(prefix: u8, bytecode: &[u8]) -> u64 {
        let stores = fresh_stores();
        let contract_addr = install_contract(&stores, prefix, bytecode);
        let owner_addr = fund_account(&stores, prefix ^ 0xff, 1_000_000_000);
        let trigger = TriggerSmartContract {
            owner_address: owner_addr.to_vec(),
            contract_address: contract_addr.to_vec(),
            call_value: 0,
            data: vec![],
            call_token_value: 0,
            token_id: 0,
        };
        let outcome = execute_trigger(
            &stores,
            VmBlockEnv {
                block_number: 1,
                block_timestamp_ms: 0, ..Default::default()
            },
            &trigger,
            1_000_000,
        );
        match outcome {
            VmOutcome::Success { energy_used, .. } => energy_used,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    // Contract A — two SSTOREs that both leave the slot non-zero
    // (no clear ⇒ no refund).
    //   PUSH1 1 PUSH1 0 SSTORE  // slot0 := 1
    //   PUSH1 2 PUSH1 0 SSTORE  // slot0 := 2
    //   STOP
    let no_clear = run_contract(
        0xc8,
        &[
            0x60, 0x01, 0x60, 0x00, 0x55,
            0x60, 0x02, 0x60, 0x00, 0x55,
            0x00,
        ],
    );

    // Contract B — second SSTORE clears the slot (write 0 to a
    // previously non-zero slot ⇒ refund).
    //   PUSH1 1 PUSH1 0 SSTORE  // slot0 := 1
    //   PUSH1 0 PUSH1 0 SSTORE  // slot0 := 0  (refund)
    //   STOP
    let with_clear = run_contract(
        0xc9,
        &[
            0x60, 0x01, 0x60, 0x00, 0x55,
            0x60, 0x00, 0x60, 0x00, 0x55,
            0x00,
        ],
    );

    // TRON gives no SSTORE-clear refund: CLEAR_SSTORE (5000) == RESET_SSTORE
    // (5000), so the two contracts spend identical energy.
    assert_eq!(
        with_clear, no_clear,
        "TRON has no SSTORE-clear refund: with_clear={with_clear} no_clear={no_clear}"
    );
}

/// PUSH32 of a full 32-byte big-endian value.
fn push32(bytes: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(0x7f); // PUSH32
    out.extend_from_slice(&bytes);
    out
}

/// Build a contract that issues a single `CALL` to `target` with `value` as
/// the TRX call-value, then (if reached) SSTOREs slot 0 := 1 and STOPs. The
/// trailing SSTORE exists so a divergent "CALL returns 0, contract continues"
/// path (the pre-fix revm behaviour) is observable as extra consumed energy /
/// a persisted slot vs java halting at the CALL.
///
/// CALL stack (top first): `[gas, to, value, inOffset, inSize, outOffset,
/// outSize]` — pushed in reverse.
fn build_call_with_value(target: [u8; 21], value: [u8; 32]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  outSize
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  outOffset
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  inSize
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  inOffset
    bc.extend(push32(value)); //              value
    bc.push(0x73); // PUSH20 target (strip 0x41 prefix)
    bc.extend_from_slice(&target[1..]);
    bc.extend(push32({
        // gas = 50_000 forwarded
        let mut g = [0u8; 32];
        g[30] = 0xc3;
        g[31] = 0x50;
        g
    }));
    bc.push(0xf1); // CALL
    // If the contract were allowed to continue past the CALL (the pre-fix
    // path), this persists slot 0 := 1.
    bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
    bc.push(0x00); // STOP
    bc
}

/// java-tron `Program.callToAddress` evaluates `msg.getEndowment().value()
/// .longValueExact()` before the transfer; a value above `Long.MAX_VALUE`
/// throws `ArithmeticException` → `TransferException("endowment out of long
/// range")`, which surfaces `contractResult TRANSFER_FAILED`, charges only the
/// consumed energy (spend-all-exempt), and terminates the whole transaction at
/// the CALL. A balance can never reach 2^63, so upstream revm would instead let
/// the value-transfer fail with OutOfFunds, push 0, and let the contract
/// continue — recording REVERT (or even SUCCESS) and a different energy total.
#[test]
fn call_value_over_i64_max_is_transfer_failed_not_revert() {
    let stores = fresh_stores();
    // A do-nothing callee (STOP); the CALL never reaches it.
    let callee = install_contract(&stores, 0xc2, &[0x00]);
    // value = 2^63 (one above i64::MAX) — `longValueExact()` would throw.
    let mut value = [0u8; 32];
    value[24] = 0x80; // byte 24 (of 0..32) sets bit 63
    let caller = install_contract(&stores, 0xc3, &build_call_with_value(callee, value));
    let owner = fund_account(&stores, 0xa3, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: caller.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let energy_limit = 1_000_000u64;
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 100, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        energy_limit,
    );

    match outcome {
        VmOutcome::TransferFailed { energy_used } => {
            // A `TransferException` is spend-all-exempt: the energy is the
            // consumed total up to the CALL (forwarded gas refunded), NOT the
            // full limit.
            assert!(
                energy_used > 0 && energy_used < energy_limit,
                "TransferFailed energy must be consumed-only (0 < {energy_used} < {energy_limit})"
            );
        }
        other => panic!("expected TransferFailed, got {other:?}"),
    }
}

/// A CALL value that DOES fit in i64 takes the normal path (here: a plain
/// value transfer the caller can't fund → revm pushes 0, the contract
/// continues to its SSTORE+STOP and succeeds). Guards against the
/// out-of-range guard over-firing on in-range values.
#[test]
fn call_value_within_i64_is_not_transfer_failed() {
    let stores = fresh_stores();
    let callee = install_contract(&stores, 0xc4, &[0x00]); // STOP
    // value = 10 (well within i64 range); caller contract has 0 balance, so
    // the transfer fails with OutOfFunds and the CALL pushes 0 — but that is
    // NOT a TransferException, so execution continues.
    let mut value = [0u8; 32];
    value[31] = 0x0a;
    let caller = install_contract(&stores, 0xc5, &build_call_with_value(callee, value));
    let owner = fund_account(&stores, 0xa5, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: caller.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 100, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        1_000_000,
    );
    assert!(
        !matches!(outcome, VmOutcome::TransferFailed { .. }),
        "an in-range CALL value must NOT be TransferFailed, got {outcome:?}"
    );
}

/// A `TransferException` in java unwinds EVERY frame (the exception propagates
/// out of `Program.callToAddress` past `VM.play` into the parent op loop, on up
/// to `VMActuator`) — it does NOT let the parent push 0 and continue. So even a
/// DEEPLY-NESTED out-of-range CALL must fail the WHOLE transaction as
/// TRANSFER_FAILED. Guards the `frame_return_result` tx-fatal short-circuit.
#[test]
fn nested_call_value_over_i64_max_fails_whole_tx() {
    let stores = fresh_stores();
    // Leaf callee: a do-nothing STOP; never reached (the CALL into it throws).
    let leaf = install_contract(&stores, 0xc6, &[0x00]);
    // Inner contract issues the out-of-range CALL to `leaf`, then would SSTORE
    // + STOP if it were allowed to continue.
    let mut value = [0u8; 32];
    value[24] = 0x80; // 2^63, one above i64::MAX
    let inner = install_contract(&stores, 0xc7, &build_call_with_value(leaf, value));
    // Outer contract CALLs `inner` (value 0, in-range), then SSTORE 1 + STOP.
    let outer_value = [0u8; 32];
    let outer = install_contract(&stores, 0xc8, &build_call_with_value(inner, outer_value));
    let owner = fund_account(&stores, 0xa8, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: outer.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 100, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        2_000_000,
    );
    assert!(
        matches!(outcome, VmOutcome::TransferFailed { .. }),
        "a nested out-of-range CALL must fail the whole tx as TransferFailed, got {outcome:?}"
    );
}
