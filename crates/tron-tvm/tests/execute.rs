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
    // ALLOW_TVM_CONSTANTINOPLE (#26) selects the failure flavour of a failed
    // value/token transfer: `TransferException` (consumed-only energy,
    // `contractResult TRANSFER_FAILED`) from #26 on, versus the older
    // `BytecodeExecutionException` / `ArithmeticException` (all energy spent,
    // `contractResult UNKNOWN`). Pin the modern era — it is what the mainnet
    // snapshot rig runs — so these tests state one era rather than inheriting
    // whichever one an unset property happens to mean. Tests that exercise the
    // pre-#26 half build their stores with `pre_constantinople_stores()`.
    dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
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

/// COINBASE (0x41) pushes the block's producing witness. java loads the
/// 21-byte `block.getWitnessAddress()` into the coinbase DataWord, which
/// right-aligns it, and `coinBaseAction` pushes that word unmasked at every
/// height — so the prefix byte sits at index 11, ahead of the 20-byte body.
/// Contracts that fold `block.coinbase` into a hash preimage without masking
/// observe it.
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
            assert_eq!(&return_data[0..11], &[0u8; 11]);
            assert_eq!(
                return_data[11], 0x41,
                "coinbase keeps TRON's 21-byte form: prefix byte at index 11"
            );
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
    build_call_with_value_and_gas(target, value, 50_000)
}

/// `build_call_with_value` with an explicit forwarded-energy word, for tests
/// that assert on how much of the forwarded budget the caller keeps.
fn build_call_with_value_and_gas(target: [u8; 21], value: [u8; 32], gas: u64) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  outSize
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  outOffset
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  inSize
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0  inOffset
    bc.extend(push32(value)); //              value
    bc.push(0x73); // PUSH20 target (strip 0x41 prefix)
    bc.extend_from_slice(&target[1..]);
    bc.extend(push32({
        let mut g = [0u8; 32];
        g[24..32].copy_from_slice(&gas.to_be_bytes());
        g
    }));
    bc.push(0xf1); // CALL
    // Reached whenever the CALL returns to this frame at all — a failing call
    // pushes 0 and execution continues, so a persisted slot 0 := 1 marks
    // "the caller ran on past the CALL".
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

/// Post-#26 containment, the twin of
/// `pre_constantinople_nested_endowment_failure_is_contained_to_its_frame`.
/// A `TransferException` raised in a NESTED frame does not end the
/// transaction: `VM.play`'s outer catch (VM.java:114-127) rethrows only
/// `JVMStackOverFlowException` / `OutOfTimeException`, so it is recorded on
/// that frame's own result via `program.setRuntimeFailure(e)` and
/// `ProgramResult.merge` never copies a child's exception to the parent.
/// `Program.callToAddress` (Program.java:1157-1169) then does
/// `stackPushZero(); return;` and the CALLER runs on, so the outer contract's
/// post-CALL SSTORE must be observable. Only a root-frame `TransferException`
/// reaches `VMActuator` and the receipt.
#[test]
fn nested_call_value_over_i64_max_is_contained_to_its_frame() {
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
    let limit = 2_000_000u64;
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 100, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        limit,
    );
    match outcome {
        VmOutcome::Success { energy_used, .. } => {
            assert!(energy_used < limit, "the tx itself must not spend-all");
        }
        other => panic!("a nested out-of-range CALL must not kill the tx, got {other:?}"),
    }
    assert_eq!(
        slot_value(&stores, outer, 0).last(),
        Some(&1u8),
        "the caller must push 0 and run on to its SSTORE"
    );
    assert!(
        slot_value(&stores, inner, 0).iter().all(|&b| b == 0),
        "the frame that raised the failure keeps its own state unwound"
    );
}

// =============================================================================
// TRON's 21-byte address form on the stack
// =============================================================================
//
// java-tron carries addresses as 21 bytes and loads them into a `DataWord`
// with `new DataWord(byte[])`, which right-aligns a short input — so the
// prefix byte lands at word index 11. Solidity masks address-typed values to
// 160 bits, which hides it, but a contract that consumes the word raw (hash
// entropy, arithmetic) sees it. `callerAction` is the exception: java masks
// CALLER unconditionally.

/// Run `bytecode` as a contract and return its 32-byte output word.
fn run_returning_word(
    stores: &VmStores,
    prefix: u8,
    bytecode: &[u8],
    owner: [u8; 21],
) -> [u8; 32] {
    let contract_addr = install_contract(stores, prefix, bytecode);
    let trigger = TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 100,
            block_timestamp_ms: 1_700_000_000_000,
            beneficiary: [0x11u8; 20],
        },
        &trigger,
        1_000_000,
    );
    match outcome {
        VmOutcome::Success { return_data, .. } => {
            assert_eq!(return_data.len(), 32, "expected a single word");
            let mut word = [0u8; 32];
            word.copy_from_slice(&return_data);
            word
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

/// `<op>; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN`
fn return_word_of(op: u8) -> Vec<u8> {
    vec![op, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
}

/// java `addressAction` masks the address word only once ALLOW_MULTI_SIGN is
/// active; before that the 21-byte contract address reaches the stack whole.
#[test]
fn address_keeps_tron_prefix_until_multi_sign_activates() {
    let stores = fresh_stores();
    let owner = fund_account(&stores, 0xa5, 1_000_000_000);
    let word = run_returning_word(&stores, 0xc5, &return_word_of(0x30), owner);
    assert_eq!(&word[0..11], &[0u8; 11]);
    assert_eq!(word[11], 0x41, "ADDRESS keeps the prefix pre-activation");
    assert_eq!(&word[12..32], &[0xc5u8; 20]);
}

#[test]
fn address_is_masked_once_multi_sign_is_active() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    let owner = fund_account(&stores, 0xa6, 1_000_000_000);
    let word = run_returning_word(&stores, 0xc6, &return_word_of(0x30), owner);
    assert_eq!(
        &word[0..12],
        &[0u8; 12],
        "ALLOW_MULTI_SIGN masks ADDRESS back to the 20-byte form"
    );
    assert_eq!(&word[12..32], &[0xc6u8; 20]);
}

/// ORIGIN follows the same gate as ADDRESS (java `originAction`).
#[test]
fn origin_keeps_tron_prefix_until_multi_sign_activates() {
    let stores = fresh_stores();
    let owner = fund_account(&stores, 0xa7, 1_000_000_000);
    let word = run_returning_word(&stores, 0xc7, &return_word_of(0x32), owner);
    assert_eq!(word[11], 0x41, "ORIGIN keeps the prefix pre-activation");
    assert_eq!(&word[12..32], &[0xa7u8; 20]);
}

#[test]
fn origin_is_masked_once_multi_sign_is_active() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    let owner = fund_account(&stores, 0xa8, 1_000_000_000);
    let word = run_returning_word(&stores, 0xc8, &return_word_of(0x32), owner);
    assert_eq!(&word[0..12], &[0u8; 12]);
    assert_eq!(&word[12..32], &[0xa8u8; 20]);
}

/// java `callerAction` masks unconditionally — CALLER must stay clean in both
/// gate states, which is what makes it the control for the two tests above.
#[test]
fn caller_is_masked_regardless_of_multi_sign() {
    for active in [0i64, 1] {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", active);
        let owner = fund_account(&stores, 0xa9, 1_000_000_000);
        let word = run_returning_word(&stores, 0xc9, &return_word_of(0x33), owner);
        assert_eq!(
            &word[0..12],
            &[0u8; 12],
            "CALLER is masked in java at every height (ALLOW_MULTI_SIGN={active})"
        );
        assert_eq!(&word[12..32], &[0xa9u8; 20]);
    }
}

/// COINBASE is ungated — java never masks it — so ALLOW_MULTI_SIGN being
/// active must not clear the prefix the way it does for ADDRESS / ORIGIN.
#[test]
fn coinbase_keeps_tron_prefix_even_after_multi_sign() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", 1);
    let owner = fund_account(&stores, 0xaa, 1_000_000_000);
    let word = run_returning_word(&stores, 0xca, &return_word_of(0x41), owner);
    assert_eq!(word[11], 0x41, "no proposal masks COINBASE");
    assert_eq!(&word[12..32], &[0x11u8; 20]);
}

/// java pushes the new contract address with `stackPush(new DataWord(newAddress))`,
/// where `newAddress` is the 21-byte `Hash.sha3omit12` output. Nothing masks it
/// and no proposal gates it, so the success push carries the prefix at every
/// height — unlike ADDRESS / ORIGIN, ALLOW_MULTI_SIGN must not clear it.
#[test]
fn create_return_word_keeps_tron_prefix_in_both_gate_states() {
    for active in [0i64, 1] {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_MULTI_SIGN", active);
        let owner = fund_account(&stores, 0xab, 1_000_000_000);
        // CREATE pops value, offset, size — so push size, offset, value.
        //   PUSH1 0; PUSH1 0; PUSH1 0; CREATE
        //   PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
        let word = run_returning_word(
            &stores,
            0xcb,
            &[
                0x60, 0x00, // PUSH1 0  (size)
                0x60, 0x00, // PUSH1 0  (offset)
                0x60, 0x00, // PUSH1 0  (value)
                0xf0, // CREATE
                0x60, 0x00, // PUSH1 0
                0x52, // MSTORE
                0x60, 0x20, // PUSH1 32
                0x60, 0x00, // PUSH1 0
                0xf3, // RETURN
            ],
            owner,
        );
        assert_ne!(
            &word[12..32],
            &[0u8; 20],
            "the create must have succeeded (ALLOW_MULTI_SIGN={active})"
        );
        assert_eq!(&word[0..11], &[0u8; 11]);
        assert_eq!(
            word[11], 0x41,
            "CREATE's success push keeps the prefix (ALLOW_MULTI_SIGN={active})"
        );
    }
}

// =============================================================================
// Uncaught precompile throw (java `ValidateMultiSign`, 0x0a)
// =============================================================================
//
// java-tron's `ValidateMultiSign.execute` reads `words[0..3]` and parses the
// signature array BEFORE its try-block, so a malformed input throws
// `ArrayIndexOutOfBoundsException`. `Program.callToPrecompiledAddress` does
// not wrap `contract.execute`, so the throw reaches `VM.java`, whose
// `catch (RuntimeException e)` runs `program.spendAllEnergy()` on the frame
// that executed the CALL and stops it. That frame loses its ENTIRE remaining
// budget — not merely the energy it forwarded — and pushes nothing.
//
// It is NOT transaction-fatal: `VM.play`'s outer catch records a runtime
// failure and `Program.callToAddress` lets a parent push zero and continue.
// At the root frame the tx consumes its full limit and records UNKNOWN
// (`RuntimeImpl.setResultCode` has no arm for a plain AIOOBE).

/// `0x0a` — ValidateMultiSign, as a 20-byte EVM address.
const VALIDATE_MULTI_SIGN: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
];
/// `0x09` — BatchValidateSign, whose identical faults java DOES catch.
const BATCH_VALIDATE_SIGN: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
];
/// `0x01000004` — MerkleHash, which returns java's `Pair.of(false, …)`
/// rather than throwing.
const MERKLE_HASH: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x04,
];

/// `CALL(gas, target, value=0, in=(0,0), out=(0,0)); POP` — the callee gets
/// an empty input, which is malformed for every precompile used here.
fn call_op(target20: [u8; 20], gas: u64) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00]); // outSize
    bc.extend_from_slice(&[0x60, 0x00]); // outOffset
    bc.extend_from_slice(&[0x60, 0x00]); // inSize
    bc.extend_from_slice(&[0x60, 0x00]); // inOffset
    bc.extend_from_slice(&[0x60, 0x00]); // value
    bc.push(0x73); // PUSH20 target
    bc.extend_from_slice(&target20);
    bc.extend(push32({
        let mut g = [0u8; 32];
        g[24..32].copy_from_slice(&gas.to_be_bytes());
        g
    }));
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP the success flag
    bc
}

/// `PUSH1 value; PUSH1 slot; SSTORE`
fn sstore_op(slot: u8, value: u8) -> Vec<u8> {
    vec![0x60, value, 0x60, slot, 0x55]
}

fn multi_sign_stores() -> VmStores {
    let stores = fresh_stores();
    // The 0x0a precompile only dispatches under ALLOW_TVM_SOLIDITY_059 (#32).
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    stores
}

fn trigger_of(owner: [u8; 21], contract: [u8; 21]) -> TriggerSmartContract {
    TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    }
}

fn run_with_limit(stores: &VmStores, trigger: &TriggerSmartContract, limit: u64) -> VmOutcome {
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 100,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        trigger,
        limit,
    )
}

fn slot_value(stores: &VmStores, contract: [u8; 21], slot: u8) -> Vec<u8> {
    let mut key = [0u8; 32];
    key[31] = slot;
    let composed = tron_chainbase::StorageRowStore::compose_key(
        &tron_crypto::address::Address::from_raw(contract),
        &key,
    );
    stores.storage.get(&composed).unwrap().unwrap_or_default()
}

#[test]
fn root_frame_precompile_throw_burns_the_whole_energy_limit() {
    let stores = multi_sign_stores();
    let mut body = call_op(VALIDATE_MULTI_SIGN, 1_000);
    body.push(0x00); // STOP
    let c = install_contract(&stores, 0xe0, &body);
    let owner = fund_account(&stores, 0xa0, 1_000_000_000);
    let limit = 400_000u64;

    match run_with_limit(&stores, &trigger_of(owner, c), limit) {
        VmOutcome::Halt {
            result,
            energy_used,
            ..
        } => {
            assert_eq!(
                energy_used, limit,
                "spendAllEnergy must consume the root frame's entire budget"
            );
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::Unknown,
                "a plain AIOOBE has no java result code — RuntimeImpl falls through to UNKNOWN"
            );
        }
        other => panic!("expected Halt, got {other:?}"),
    }
}

#[test]
fn precompile_throw_ignores_the_forwarded_gas_bound() {
    // The discriminator: the caller forwards only 1,000 energy but has
    // 1,000,000. java burns the CALLING frame's whole remaining budget, so
    // the forwarded bound is irrelevant. A "spend the forwarded energy"
    // reading would settle at ~1,000 plus overhead.
    let stores = multi_sign_stores();
    let mut body = call_op(VALIDATE_MULTI_SIGN, 1_000);
    body.push(0x00); // STOP
    let c = install_contract(&stores, 0xe1, &body);
    let owner = fund_account(&stores, 0xa1, 1_000_000_000);
    let limit = 1_000_000u64;

    match run_with_limit(&stores, &trigger_of(owner, c), limit) {
        VmOutcome::Halt { energy_used, .. } => assert_eq!(energy_used, limit),
        other => panic!("expected Halt, got {other:?}"),
    }
}

#[test]
fn nested_precompile_throw_kills_one_frame_not_the_transaction() {
    // A calls B with a bounded 50,000; B throws inside 0x0a. java's
    // `Program.callToAddress` sees the child's exception, pushes zero and
    // returns — A keeps going, writes its marker and finishes. B's forwarded
    // 50,000 is gone (no refund), but A's own budget survives.
    let stores = multi_sign_stores();
    let mut b_body = call_op(VALIDATE_MULTI_SIGN, 40_000);
    b_body.push(0x00); // STOP
    let b = install_contract(&stores, 0xe2, &b_body);

    let mut a_body = call_op(b[1..].try_into().unwrap(), 50_000);
    a_body.extend(sstore_op(0, 1)); // marker
    a_body.push(0x00); // STOP
    let a = install_contract(&stores, 0xe3, &a_body);
    let owner = fund_account(&stores, 0xa2, 1_000_000_000);
    let limit = 1_000_000u64;

    let outcome = run_with_limit(&stores, &trigger_of(owner, a), limit);
    let energy_used = match outcome {
        VmOutcome::Success { energy_used, .. } => energy_used,
        other => panic!("a nested precompile throw must not fail the tx, got {other:?}"),
    };
    assert_eq!(
        slot_value(&stores, a, 0).last(),
        Some(&1u8),
        "the parent must continue past the failed CALL and write its marker"
    );
    assert!(
        energy_used >= 50_000,
        "the child's whole forwarded budget is burned (used={energy_used})"
    );
    assert!(
        energy_used < limit,
        "the parent's own budget must survive (used={energy_used} limit={limit})"
    );
}

#[test]
fn state_written_before_a_precompile_throw_is_discarded() {
    // B's frame is reverted along with its halt, so the SSTORE it made before
    // calling 0x0a must not persist.
    let stores = multi_sign_stores();
    let mut b_body = sstore_op(7, 0x2a);
    b_body.extend(call_op(VALIDATE_MULTI_SIGN, 40_000));
    b_body.push(0x00); // STOP
    let b = install_contract(&stores, 0xe4, &b_body);

    let mut a_body = call_op(b[1..].try_into().unwrap(), 200_000);
    a_body.extend(sstore_op(0, 1));
    a_body.push(0x00);
    let a = install_contract(&stores, 0xe5, &a_body);
    let owner = fund_account(&stores, 0xa4, 1_000_000_000);

    let outcome = run_with_limit(&stores, &trigger_of(owner, a), 1_000_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got {outcome:?}"
    );
    assert!(
        slot_value(&stores, b, 7).iter().all(|&x| x == 0),
        "the throwing frame's checkpoint must be reverted"
    );
    assert_eq!(slot_value(&stores, a, 0).last(), Some(&1u8));
}

#[test]
fn merkle_hash_failure_burns_only_the_forwarded_energy() {
    // Shared-variant guard. `MerkleHash` returns java's `Pair.of(false, …)`,
    // NOT a throw, so `Program.callToPrecompiledAddress` does `refundEnergy(0)`
    // + `stackPushZero()`: only the forwarded energy is lost and the caller
    // continues. Must not have been swept up by the PrecompileThrow change.
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_SHIELDED_TRC20_TRANSACTION", 1);
    let mut body = call_op(MERKLE_HASH, 30_000); // empty input → < 96 bytes
    body.extend(sstore_op(0, 1));
    body.push(0x00);
    let c = install_contract(&stores, 0xe6, &body);
    let owner = fund_account(&stores, 0xa6, 1_000_000_000);
    let limit = 1_000_000u64;

    let outcome = run_with_limit(&stores, &trigger_of(owner, c), limit);
    let energy_used = match outcome {
        VmOutcome::Success { energy_used, .. } => energy_used,
        other => panic!("a MerkleHash failure must not halt the caller, got {other:?}"),
    };
    assert_eq!(
        slot_value(&stores, c, 0).last(),
        Some(&1u8),
        "the caller must continue after a `Pair.of(false, …)` precompile"
    );
    assert!(
        energy_used < limit,
        "only the forwarded energy is burned (used={energy_used} limit={limit})"
    );
}

#[test]
fn batch_validate_sign_failure_lets_the_caller_continue() {
    // java wraps `BatchValidateSign.doExecute` in `catch (Throwable t)`, so
    // the same malformed shapes that kill a frame at 0x0a are an ordinary
    // success-with-zero-word at 0x09.
    let stores = multi_sign_stores();
    let mut body = call_op(BATCH_VALIDATE_SIGN, 30_000);
    body.extend(sstore_op(0, 1));
    body.push(0x00);
    let c = install_contract(&stores, 0xe7, &body);
    let owner = fund_account(&stores, 0xa7, 1_000_000_000);
    let limit = 1_000_000u64;

    let outcome = run_with_limit(&stores, &trigger_of(owner, c), limit);
    let energy_used = match outcome {
        VmOutcome::Success { energy_used, .. } => energy_used,
        other => panic!("0x09 must never halt the caller, got {other:?}"),
    };
    assert_eq!(slot_value(&stores, c, 0).last(), Some(&1u8));
    assert!(energy_used < limit);
}

// =============================================================================
// Endowment range and self-CALL bans: predicate, era and ordering
// =============================================================================
//
// java reads a call/create endowment with `msg.getEndowment().value()
// .longValueExact()` (Program.java:1034 / :821). `DataWord.value()` is
// `new BigInteger(1, data)` (DataWord.java:197-199) — UNSIGNED — so the
// accepted set is exactly `[0, Long.MAX_VALUE]` and every word from 2^63 up
// throws `ArithmeticException`. The signed `sValue()` reading, which the
// staking and token-id opcodes use, would additionally admit the
// two's-complement negative window `[2^256 - 2^63, 2^256)`.
//
// ALLOW_TVM_CONSTANTINOPLE (#26) then selects the failure flavour:
//   * active   — `TransferException`: `VM.java:100` skips `spendAllEnergy()`,
//                the forwarded energy is refunded, `contractResult
//                TRANSFER_FAILED`, energy consumed-only.
//   * inactive — the raw `ArithmeticException` (or, for a validation failure,
//                `BytecodeExecutionException`) propagates: `spendAllEnergy()`
//                runs and `RuntimeImpl.setResultCode` has no matching arm, so
//                `contractResult UNKNOWN` with the whole limit consumed.

/// Stores pinned to the era BEFORE ALLOW_TVM_CONSTANTINOPLE (#26) — the window
/// between TVM launch and that proposal, which a from-genesis sync replays.
fn pre_constantinople_stores() -> VmStores {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 0);
    stores
}

/// Give an already-installed contract a TRX balance, so java's sender-balance
/// push-0 (Program.java:1049-1055) does not pre-empt the check under test.
fn set_balance(stores: &VmStores, addr: [u8; 21], balance: i64) {
    let key = tron_crypto::address::Address::from_raw(addr);
    let acct = stores.accounts.get(&key).unwrap().unwrap();
    stores
        .accounts
        .put(&key, &tron_proto::Account { balance, ..acct })
        .unwrap();
}

/// The all-ones word is the sharpest probe of the signed-vs-unsigned reading:
/// `sValue()` reads it as -1 (in range, accepted), `value()` as 2^256-1 (out of
/// range, thrown). java uses `value()`, so it must be rejected. Before the fix
/// this word slipped past the guard entirely and the CALL fell through to an
/// ordinary `OutOfFunds` push-0.
#[test]
fn call_value_all_ones_word_is_transfer_failed() {
    let stores = fresh_stores();
    let callee = install_contract(&stores, 0xd2, &[0x00]);
    let caller = install_contract(&stores, 0xd3, &build_call_with_value(callee, [0xFF; 32]));
    let owner = fund_account(&stores, 0xb3, 1_000_000_000);

    let limit = 1_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, caller), limit) {
        VmOutcome::TransferFailed { energy_used } => {
            assert!(
                energy_used > 0 && energy_used < limit,
                "TransferException is spend-all-exempt (0 < {energy_used} < {limit})"
            );
        }
        other => panic!("expected TransferFailed, got {other:?}"),
    }
    // The contract died at the CALL, so its trailing SSTORE never ran.
    assert!(
        slot_value(&stores, caller, 0).iter().all(|&b| b == 0),
        "the frame must not have continued past the CALL"
    );
}

/// The low end of the window the unsigned reading closes: `0xFF..FF80_00…00` is
/// two's-complement `i64::MIN`, which `sValue()` accepts and `value()` rejects.
#[test]
fn call_value_min_i64_word_is_transfer_failed() {
    let stores = fresh_stores();
    let callee = install_contract(&stores, 0xd4, &[0x00]);
    // Top 192 bits all ones, then 0x8000_0000_0000_0000.
    let mut value = [0xFFu8; 32];
    value[24] = 0x80;
    value[25..].fill(0x00);
    let caller = install_contract(&stores, 0xd5, &build_call_with_value(callee, value));
    let owner = fund_account(&stores, 0xb5, 1_000_000_000);

    assert!(
        matches!(
            run_with_limit(&stores, &trigger_of(owner, caller), 1_000_000),
            VmOutcome::TransferFailed { .. }
        ),
        "the two's-complement negative window must be rejected by the unsigned reading"
    );
}

/// Top boundary: the sign bit alone (2^255) is out of range under both
/// readings. Locks the guard against a regression that only tested the low
/// limb.
#[test]
fn call_value_2_pow_255_is_transfer_failed() {
    let stores = fresh_stores();
    let callee = install_contract(&stores, 0xd6, &[0x00]);
    let mut value = [0u8; 32];
    value[0] = 0x80;
    let caller = install_contract(&stores, 0xd7, &build_call_with_value(callee, value));
    let owner = fund_account(&stores, 0xb7, 1_000_000_000);

    assert!(matches!(
        run_with_limit(&stores, &trigger_of(owner, caller), 1_000_000),
        VmOutcome::TransferFailed { .. }
    ));
}

/// Bottom boundary: `i64::MAX` itself is the largest ACCEPTED word. Guards
/// against the unsigned predicate over-firing by one.
#[test]
fn call_value_i64_max_is_accepted() {
    let stores = fresh_stores();
    let callee = install_contract(&stores, 0xd8, &[0x00]);
    let mut value = [0u8; 32];
    value[24] = 0x7F;
    value[25..].fill(0xFF);
    let caller = install_contract(&stores, 0xd9, &build_call_with_value(callee, value));
    let owner = fund_account(&stores, 0xb9, 1_000_000_000);

    // The caller holds no TRX, so the transfer fails `OutOfFunds`, the CALL
    // pushes 0, and the contract runs on to its SSTORE — java's push-zero path,
    // NOT a transfer failure.
    let outcome = run_with_limit(&stores, &trigger_of(owner, caller), 1_000_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "i64::MAX is in range and must take the ordinary push-0 path, got {outcome:?}"
    );
    assert_eq!(slot_value(&stores, caller, 0).last(), Some(&1u8));
}

/// Pre-#26 half of the endowment pair: no `TransferException` exists yet, so
/// the raw `ArithmeticException` spends the frame's whole budget and records
/// UNKNOWN — explicitly not OUT_OF_MEMORY, which is java's
/// `OutOfMemoryException` and a different fault.
#[test]
fn call_value_over_i64_max_pre_constantinople_is_spend_all_unknown() {
    let stores = pre_constantinople_stores();
    let callee = install_contract(&stores, 0xda, &[0x00]);
    let mut value = [0u8; 32];
    value[24] = 0x80; // 2^63
    let caller = install_contract(&stores, 0xdb, &build_call_with_value(callee, value));
    let owner = fund_account(&stores, 0xba, 1_000_000_000);

    let limit = 1_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, caller), limit) {
        VmOutcome::Halt {
            result,
            energy_used,
            ..
        } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::Unknown,
                "a bare ArithmeticException matches no RuntimeImpl arm"
            );
            assert_eq!(energy_used, limit, "spendAllEnergy consumes the whole limit");
        }
        other => panic!("expected a spend-all Halt/UNKNOWN, got {other:?}"),
    }
}

/// Pre-#26 containment. A spend-all halt is contained to the frame that raised
/// it: `VM.play`'s outer catch records a runtime failure
/// (`program.setRuntimeFailure`) instead of rethrowing, and
/// `Program.callToAddress` then does `stackPushZero(); return;`, so the CALLER
/// continues. Only a root-frame occurrence fails the transaction
/// (`VMActuator`). The outer contract's post-CALL SSTORE must therefore be
/// observable.
#[test]
fn pre_constantinople_nested_endowment_failure_is_contained_to_its_frame() {
    let stores = pre_constantinople_stores();
    let leaf = install_contract(&stores, 0xdc, &[0x00]);
    let mut bad = [0u8; 32];
    bad[24] = 0x80; // 2^63
    let inner = install_contract(&stores, 0xdd, &build_call_with_value(leaf, bad));
    let outer = install_contract(&stores, 0xde, &build_call_with_value(inner, [0u8; 32]));
    let owner = fund_account(&stores, 0xbe, 1_000_000_000);

    let limit = 2_000_000u64;
    let outcome = run_with_limit(&stores, &trigger_of(owner, outer), limit);
    match outcome {
        VmOutcome::Success { energy_used, .. } => {
            assert!(energy_used < limit, "the tx itself must not spend-all");
        }
        other => panic!("a nested pre-#26 endowment failure must not kill the tx, got {other:?}"),
    }
    assert_eq!(
        slot_value(&stores, outer, 0).last(),
        Some(&1u8),
        "the caller must push 0 and run on to its SSTORE"
    );
    assert!(
        slot_value(&stores, inner, 0).iter().all(|&b| b == 0),
        "the frame that raised the failure keeps its own state unwound"
    );
}

/// java bans a value-bearing CALL to one's OWN address:
/// `VMUtils.validateForSmartContract` throws `ContractValidateException`
/// ("Cannot transfer TRX to yourself", VMUtils.java:146-148), which
/// `Program.callToAddress` rethrows as a `TransferException` once #26 is
/// active.
#[test]
fn self_call_with_value_is_transfer_failed() {
    let stores = fresh_stores();
    let mut value = [0u8; 32];
    value[31] = 0x0a; // 10 sun
    // Placeholder install so the address is known, then rewrite with real code.
    let own = install_contract(&stores, 0xe0, &[0x00]);
    install_contract(&stores, 0xe0, &build_call_with_value(own, value));
    // Fund the contract so java's earlier sender-balance push-0 does NOT
    // pre-empt the self-transfer ban.
    set_balance(&stores, own, 1_000);
    let owner = fund_account(&stores, 0xb0, 1_000_000_000);

    let limit = 1_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, own), limit) {
        VmOutcome::TransferFailed { energy_used } => {
            assert!(energy_used > 0 && energy_used < limit);
        }
        other => panic!("expected TransferFailed for a funded self-CALL, got {other:?}"),
    }
}

/// Pre-#26 half of the self-CALL pair: the same `ContractValidateException` is
/// wrapped in a plain `BytecodeExecutionException`, so it spends all energy and
/// records UNKNOWN rather than TRANSFER_FAILED.
#[test]
fn self_call_with_value_pre_constantinople_is_spend_all_unknown() {
    let stores = pre_constantinople_stores();
    let mut value = [0u8; 32];
    value[31] = 0x0a;
    let own = install_contract(&stores, 0xe1, &[0x00]);
    install_contract(&stores, 0xe1, &build_call_with_value(own, value));
    set_balance(&stores, own, 1_000);
    let owner = fund_account(&stores, 0xb1, 1_000_000_000);

    let limit = 1_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, own), limit) {
        VmOutcome::Halt {
            result,
            energy_used,
            ..
        } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::Unknown
            );
            assert_eq!(energy_used, limit);
        }
        other => panic!("expected a spend-all Halt/UNKNOWN, got {other:?}"),
    }
}

/// ORDERING: java's sender-balance check (Program.java:1049-1055) runs BEFORE
/// the transfer block that contains the self-transfer ban, and answers with
/// `stackPushZero(); refundEnergy(...); return;`. So an UNDER-FUNDED self-CALL
/// pushes 0 and the contract carries on — it is not a transfer failure at all.
/// Distinguished from the ban by the trailing SSTORE being observable.
#[test]
fn self_call_with_insufficient_balance_pushes_zero_not_transfer_failed() {
    let stores = fresh_stores();
    let mut value = [0u8; 32];
    value[31] = 0x0a; // 10 sun, but the contract holds 0
    let own = install_contract(&stores, 0xe2, &[0x00]);
    install_contract(&stores, 0xe2, &build_call_with_value(own, value));
    let owner = fund_account(&stores, 0xb2, 1_000_000_000);

    let outcome = run_with_limit(&stores, &trigger_of(owner, own), 1_000_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "an under-funded self-CALL takes java's balance push-0, got {outcome:?}"
    );
    assert_eq!(
        slot_value(&stores, own, 0).last(),
        Some(&1u8),
        "the contract must run on past the CALL"
    );
}

// =============================================================================
// CREATE / CREATE2 endowment range
// =============================================================================
//
// `Program.createContractImpl` (Program.java:821) reads the endowment with a
// BARE `value.value().longValueExact()` — no try/catch, and no
// ALLOW_TVM_CONSTANTINOPLE branch. The `ArithmeticException` therefore reaches
// `VM.java:100` in EVERY era and, not being a `TransferException`, triggers
// `spendAllEnergy()`. `RuntimeImpl.setResultCode` has no arm for it, so the
// recorded code is UNKNOWN — NOT `OUT_OF_MEMORY`, which is reserved for java's
// `OutOfMemoryException` (the 3 MiB `EnergyCost.MEM_LIMIT` breach).

/// `CREATE` (or `CREATE2`) with a 32-byte endowment word, then SSTORE slot 0
/// := 1 and STOP. CREATE pops `[value, offset, length]` top-first; CREATE2
/// pops `salt` after `length`, so salt sits deepest.
fn build_create_with_value(value: [u8; 32], is_create2: bool) -> Vec<u8> {
    let mut bc = Vec::new();
    if is_create2 {
        bc.extend_from_slice(&[0x60, 0x00]); // salt = 0
    }
    bc.extend_from_slice(&[0x60, 0x00]); // length = 0
    bc.extend_from_slice(&[0x60, 0x00]); // offset = 0
    bc.extend(push32(value)); // endowment
    bc.push(if is_create2 { 0xf5 } else { 0xf0 });
    bc.push(0x50); // POP the returned address
    bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55]); // SSTORE slot0 := 1
    bc.push(0x00); // STOP
    bc
}

/// The all-ones endowment word is the CREATE half of the signed-vs-unsigned
/// correction: `sValue()` reads it as -1 and would let the CREATE proceed to an
/// ordinary insufficient-balance push-0, while java's `value()` reads 2^256-1
/// and throws. Spend-all with UNKNOWN, and the trailing SSTORE must not run.
#[test]
fn create_endowment_all_ones_word_spends_all_energy_as_unknown() {
    for is_create2 in [false, true] {
        let stores = fresh_stores();
        let caller = install_contract(
            &stores,
            if is_create2 { 0xf2 } else { 0xf1 },
            &build_create_with_value([0xFF; 32], is_create2),
        );
        let owner = fund_account(&stores, if is_create2 { 0xa2 } else { 0xa1 }, 1_000_000_000);

        let limit = 1_000_000u64;
        match run_with_limit(&stores, &trigger_of(owner, caller), limit) {
            VmOutcome::Halt {
                result,
                energy_used,
                ..
            } => {
                assert_eq!(
                    result,
                    tron_proto::transaction::result::ContractResult::Unknown,
                    "create2={is_create2}: a bare ArithmeticException records UNKNOWN, \
                     not OUT_OF_MEMORY"
                );
                assert_eq!(
                    energy_used, limit,
                    "create2={is_create2}: spendAllEnergy consumes the whole limit"
                );
            }
            other => panic!("create2={is_create2}: expected spend-all Halt/UNKNOWN, got {other:?}"),
        }
        assert!(
            slot_value(&stores, caller, 0).iter().all(|&b| b == 0),
            "create2={is_create2}: the frame must not have continued past the CREATE"
        );
    }
}

/// The CREATE endowment guard is UNGATED on ALLOW_TVM_CONSTANTINOPLE:
/// Program.java:821 has no branch on it, so the outcome is identical in the
/// pre-#26 era. Guards against the CREATE arm being "unified" with the CALL
/// arm's era fork.
#[test]
fn create_endowment_out_of_range_is_spend_all_in_both_eras() {
    let mut value = [0u8; 32];
    value[24] = 0x80; // 2^63
    for (label, stores) in [
        ("post-#26", fresh_stores()),
        ("pre-#26", pre_constantinople_stores()),
    ] {
        let caller = install_contract(&stores, 0xf3, &build_create_with_value(value, false));
        let owner = fund_account(&stores, 0xa3, 1_000_000_000);
        let limit = 1_000_000u64;
        match run_with_limit(&stores, &trigger_of(owner, caller), limit) {
            VmOutcome::Halt {
                result,
                energy_used,
                ..
            } => {
                assert_eq!(
                    result,
                    tron_proto::transaction::result::ContractResult::Unknown,
                    "{label}"
                );
                assert_eq!(energy_used, limit, "{label}");
            }
            other => panic!("{label}: expected spend-all Halt/UNKNOWN, got {other:?}"),
        }
    }
}

// =============================================================================
// Depth: java answers `getCallDeep() == MAX_DEPTH` with a push-zero, and that
// answer PRECEDES every transfer validation
// =============================================================================
//
// `Program.callToAddress` (Program.java:1002-1007) and `Program.createContract`
// (Program.java:799-802) test the depth limit at the very top and return via
// `stackPushZero()` — before the endowment read, before `checkTokenId`, and
// before the transfer block. Our depth refusal lives downstream in frame
// construction, so a transaction-fatal check raised from the opcode handler
// would otherwise fire where java had already returned.

/// Address for link `idx` of a call chain. Distinct from the single-byte-fill
/// addresses `install_contract` builds, so a long chain cannot collide with
/// the fixtures other tests install.
fn chain_addr(idx: usize) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0x5a);
    a[19] = (idx >> 8) as u8;
    a[20] = idx as u8;
    a
}

fn install_at(stores: &VmStores, addr: [u8; 21], bytecode: &[u8]) {
    let key = tron_crypto::address::Address::from_raw(addr);
    let hash = code_hash(bytecode);
    stores.code.put(hash.as_slice(), bytecode).unwrap();
    stores
        .accounts
        .put(
            &key,
            &tron_proto::Account {
                address: addr.to_vec(),
                balance: 0,
                code_hash: hash.as_slice().to_vec(),
                code: bytecode.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
}

/// Install a chain of `depth + 1` contracts where link `i` CALLs link `i + 1`
/// with zero value, and the last link runs `leaf_code`. Triggering link 0 makes
/// `leaf_code` execute at frame depth `depth`, so `depth == 64` puts the leaf
/// exactly at java's `getCallDeep() == MAX_DEPTH`. Returns link 0's address.
fn install_call_chain(stores: &VmStores, depth: usize, leaf_code: &[u8]) -> [u8; 21] {
    install_at(stores, chain_addr(depth), leaf_code);
    for i in (0..depth).rev() {
        let next = chain_addr(i + 1);
        let mut bc = Vec::new();
        // CALL [gas, to, value, inOff, inSize, outOff, outSize], pushed in
        // reverse; forward essentially everything and let the 63/64 rule cap it.
        bc.extend_from_slice(&[0x60, 0x00]); // outSize
        bc.extend_from_slice(&[0x60, 0x00]); // outOff
        bc.extend_from_slice(&[0x60, 0x00]); // inSize
        bc.extend_from_slice(&[0x60, 0x00]); // inOff
        bc.extend_from_slice(&[0x60, 0x00]); // value = 0
        bc.push(0x73); // PUSH20
        bc.extend_from_slice(&next[1..]);
        bc.extend(push32({
            let mut w = [0u8; 32];
            w[28..].copy_from_slice(&30_000_000u32.to_be_bytes());
            w
        }));
        bc.push(0xf1); // CALL
        bc.push(0x50); // POP
        bc.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55]); // SSTORE slot0 := 1
        bc.push(0x00); // STOP
        install_at(stores, chain_addr(i), &bc);
    }
    chain_addr(0)
}

/// At `getCallDeep() == MAX_DEPTH` java pushes zero and refunds BEFORE reading
/// the endowment, so an out-of-range value at the depth limit is not a transfer
/// failure at all — the caller carries on. Without the depth gate this reports
/// TRANSFER_FAILED and kills the transaction.
#[test]
fn call_value_over_i64_max_at_max_depth_pushes_zero() {
    let stores = fresh_stores();
    let sink = install_contract(&stores, 0xee, &[0x00]);
    let mut bad = [0u8; 32];
    bad[24] = 0x80; // 2^63
    let head = install_call_chain(&stores, 64, &build_call_with_value(sink, bad));
    let owner = fund_account(&stores, 0xae, 1_000_000_000);

    let limit = 50_000_000u64;
    let outcome = run_with_limit(&stores, &trigger_of(owner, head), limit);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "at MAX_DEPTH java pushes zero before the endowment read, got {outcome:?}"
    );
    // The leaf continued past its CALL, and so did its caller.
    assert_eq!(slot_value(&stores, chain_addr(64), 0).last(), Some(&1u8));
    assert_eq!(slot_value(&stores, chain_addr(0), 0).last(), Some(&1u8));
}

/// The self-CALL transfer ban is likewise pre-empted by the depth push-zero.
#[test]
fn self_call_with_value_at_max_depth_pushes_zero() {
    let stores = fresh_stores();
    let leaf_addr = chain_addr(64);
    let mut value = [0u8; 32];
    value[31] = 0x0a;
    let head = install_call_chain(&stores, 64, &build_call_with_value(leaf_addr, value));
    // Fund the leaf so the balance push-0 is not what saves it.
    set_balance(&stores, leaf_addr, 1_000);
    let owner = fund_account(&stores, 0xaf, 1_000_000_000);

    let outcome = run_with_limit(&stores, &trigger_of(owner, head), 50_000_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "at MAX_DEPTH the self-transfer ban must not fire, got {outcome:?}"
    );
    assert_eq!(slot_value(&stores, chain_addr(64), 0).last(), Some(&1u8));
}

/// CREATE's depth push-zero is ungated (Program.java:799), so an out-of-range
/// CREATE endowment at MAX_DEPTH pushes zero in every era. CREATE2 is the
/// exception and is covered separately.
#[test]
fn create_endowment_out_of_range_at_max_depth_pushes_zero() {
    let stores = fresh_stores();
    let head = install_call_chain(&stores, 64, &build_create_with_value([0xFF; 32], false));
    let owner = fund_account(&stores, 0xab, 1_000_000_000);

    let outcome = run_with_limit(&stores, &trigger_of(owner, head), 50_000_000);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "CREATE at MAX_DEPTH pushes zero before createContractImpl, got {outcome:?}"
    );
    assert_eq!(slot_value(&stores, chain_addr(64), 0).last(), Some(&1u8));
}

/// CREATE2's depth push-zero is ERA-GATED: `Program.createContract2`
/// (Program.java:1639) only returns early under `allowTvmCompatibleEvm()`.
/// Before that proposal it falls through to `createContractImpl` and DOES hit
/// the bare `longValueExact()`, so the throw still happens at MAX_DEPTH.
///
/// The leaf sits 64 frames down, and a spend-all halt is contained to its own
/// frame, so neither era fails the transaction. The observable difference is
/// whether the leaf survived its CREATE2: on the push-zero path it runs on to
/// its SSTORE, on the throw path it dies there and forfeits its whole forwarded
/// budget.
#[test]
fn create2_endowment_at_max_depth_is_era_gated() {
    let leaf_ran = |compatible_evm: bool| -> (bool, u64) {
        let stores = fresh_stores();
        if compatible_evm {
            stores
                .dynamic_properties
                .put_long(b"ALLOW_TVM_COMPATIBLE_EVM", 1);
        }
        let head = install_call_chain(&stores, 64, &build_create_with_value([0xFF; 32], true));
        let owner = fund_account(&stores, 0xac, 1_000_000_000);
        let outcome = run_with_limit(&stores, &trigger_of(owner, head), 50_000_000);
        let energy = match outcome {
            VmOutcome::Success { energy_used, .. } => energy_used,
            other => panic!("a nested halt must stay contained, got {other:?}"),
        };
        (
            slot_value(&stores, chain_addr(64), 0).last() == Some(&1u8),
            energy,
        )
    };

    let (ran_without_flag, burned_without_flag) = leaf_ran(false);
    let (ran_with_flag, burned_with_flag) = leaf_ran(true);

    assert!(
        !ran_without_flag,
        "pre-ALLOW_TVM_COMPATIBLE_EVM there is no depth push-zero for CREATE2, so the \
         bare longValueExact() still throws and the leaf frame dies"
    );
    assert!(
        ran_with_flag,
        "post-ALLOW_TVM_COMPATIBLE_EVM CREATE2 pushes zero at MAX_DEPTH and the leaf continues"
    );
    assert!(
        burned_without_flag > burned_with_flag,
        "the throwing era forfeits the leaf's whole forwarded budget \
         ({burned_without_flag} vs {burned_with_flag})"
    );
}

/// A nested `BytecodeExecutionException` must not colour a LATER, unrelated
/// root halt. java catches it per-frame (`VM.play` -> `spendAllEnergy` on that
/// program, then `Program.callToAddress` pushes zero and the caller continues),
/// so only a root-frame throw reaches the receipt as UNKNOWN. A caller that
/// runs on and then exhausts its own energy records OUT_OF_ENERGY.
///
/// Exercises the pre-#32 missing-recipient guard specifically: pre-#26 java
/// wraps `VMUtils`' "no ToAccount" validation failure in a plain
/// `BytecodeExecutionException`, distinct from the endowment-range guard.
#[test]
fn nested_bytecode_execution_failure_does_not_relabel_a_later_root_halt() {
    let stores = pre_constantinople_stores();
    // Never installed, so it has no account row. Pre-#32 java refuses to create
    // it and the inner frame dies spend-all.
    let mut absent = [0u8; 21];
    absent[0] = 0x41;
    absent[1..].fill(0xf0);

    let mut small = [0u8; 32];
    small[31] = 0x05;
    let inner = install_contract(&stores, 0xf2, &build_call_with_value(absent, small));
    set_balance(&stores, inner, 1_000);

    // Caller: CALL inner with zero value, then burn the remaining budget in a
    // self-loop so the ROOT halt is the caller's own energy exhaustion.
    let mut outer_code = Vec::new();
    outer_code.extend_from_slice(&[0x60, 0x00]); // outSize
    outer_code.extend_from_slice(&[0x60, 0x00]); // outOffset
    outer_code.extend_from_slice(&[0x60, 0x00]); // inSize
    outer_code.extend_from_slice(&[0x60, 0x00]); // inOffset
    outer_code.extend(push32([0u8; 32])); // value = 0
    outer_code.push(0x73); // PUSH20 inner
    outer_code.extend_from_slice(&inner[1..]);
    outer_code.extend(push32({
        let mut g = [0u8; 32];
        g[30] = 0xc3;
        g[31] = 0x50; // 50_000 forwarded
        g
    }));
    outer_code.push(0xf1); // CALL
    outer_code.push(0x50); // POP the success flag
    let loop_dest = outer_code.len();
    assert!(loop_dest < 256, "loop target must fit a PUSH1");
    outer_code.push(0x5b); // JUMPDEST
    outer_code.push(0x60); // PUSH1
    outer_code.push(loop_dest as u8);
    outer_code.push(0x56); // JUMP
    let outer = install_contract(&stores, 0xf3, &outer_code);
    let owner = fund_account(&stores, 0xb3, 1_000_000_000);

    let limit = 500_000u64;
    match run_with_limit(&stores, &trigger_of(owner, outer), limit) {
        VmOutcome::Halt {
            result,
            energy_used,
            ..
        } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::OutOfEnergy,
                "the root halt is the caller's own energy exhaustion; a child \
                 frame's BytecodeExecutionException must not relabel it UNKNOWN"
            );
            assert_eq!(energy_used, limit);
        }
        other => panic!("expected a root OutOfEnergy halt, got {other:?}"),
    }
}

/// A contained nested `TransferException` costs the caller the WHOLE budget it
/// forwarded, not just what the child consumed. java's
/// `Program.callToAddress` returns at :1168 for an exception child — before the
/// unspent-energy refund at :1197-1210 — so `msg.getEnergy()` is gone even
/// though the child stopped almost immediately. A child that merely REVERTED
/// falls through and does get the refund.
#[test]
fn nested_transfer_failure_forfeits_the_forwarded_energy() {
    const FORWARDED: u64 = 50_000;

    let stores = fresh_stores();
    let leaf = install_contract(&stores, 0xd0, &[0x00]);
    let mut bad = [0u8; 32];
    bad[24] = 0x80; // 2^63 — `longValueExact()` throws
    let inner = install_contract(&stores, 0xd1, &build_call_with_value(leaf, bad));
    let outer = install_contract(
        &stores,
        0xd2,
        &build_call_with_value_and_gas(inner, [0u8; 32], FORWARDED),
    );
    let owner = fund_account(&stores, 0xb8, 1_000_000_000);

    let limit = 2_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, outer), limit) {
        VmOutcome::Success { energy_used, .. } => {
            assert!(
                energy_used >= FORWARDED,
                "the caller forfeits the whole forwarded budget: {energy_used} < {FORWARDED}"
            );
            assert!(energy_used < limit, "the tx itself must not spend-all");
        }
        other => panic!("a nested transfer failure must not kill the tx, got {other:?}"),
    }
    assert_eq!(
        slot_value(&stores, outer, 0).last(),
        Some(&1u8),
        "the caller must push 0 and run on to its SSTORE"
    );
}

/// A nested `TransferException` must not colour a LATER, unrelated root
/// outcome. `RuntimeImpl.setResultCode` (RuntimeImpl.java:68, :130-133) reads
/// the exception off the ROOT `ProgramResult` alone, and `ProgramResult.merge`
/// never copies a child's exception up, so a caller that runs on and then
/// REVERTs records REVERT — and one that exhausts its own energy records
/// OUT_OF_ENERGY. The post-#26 twin of
/// `nested_bytecode_execution_failure_does_not_relabel_a_later_root_halt`.
#[test]
fn nested_transfer_failure_does_not_relabel_a_later_root_revert() {
    let mut bad = [0u8; 32];
    bad[24] = 0x80; // 2^63

    // Root REVERT after the contained child failure.
    let stores = fresh_stores();
    let leaf = install_contract(&stores, 0xd3, &[0x00]);
    let inner = install_contract(&stores, 0xd4, &build_call_with_value(leaf, bad));
    let mut outer_code = call_op(inner[1..].try_into().unwrap(), 50_000);
    outer_code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]); // PUSH1 0 PUSH1 0 REVERT
    let outer = install_contract(&stores, 0xd5, &outer_code);
    let owner = fund_account(&stores, 0xb9, 1_000_000_000);

    let limit = 500_000u64;
    match run_with_limit(&stores, &trigger_of(owner, outer), limit) {
        VmOutcome::Revert { energy_used, .. } => {
            assert!(energy_used < limit, "a REVERT is spend-all-exempt");
        }
        other => panic!(
            "the root outcome is the caller's own REVERT; a child frame's \
             TransferException must not relabel it TRANSFER_FAILED, got {other:?}"
        ),
    }

    // Root HALT after the contained child failure.
    let stores = fresh_stores();
    let leaf = install_contract(&stores, 0xd6, &[0x00]);
    let inner = install_contract(&stores, 0xd7, &build_call_with_value(leaf, bad));
    let mut outer_code = call_op(inner[1..].try_into().unwrap(), 50_000);
    let loop_dest = outer_code.len();
    assert!(loop_dest < 256, "loop target must fit a PUSH1");
    outer_code.push(0x5b); // JUMPDEST
    outer_code.push(0x60); // PUSH1
    outer_code.push(loop_dest as u8);
    outer_code.push(0x56); // JUMP
    let outer = install_contract(&stores, 0xd8, &outer_code);
    let owner = fund_account(&stores, 0xba, 1_000_000_000);

    match run_with_limit(&stores, &trigger_of(owner, outer), limit) {
        VmOutcome::Halt {
            result,
            energy_used,
            ..
        } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::OutOfEnergy,
                "the root halt is the caller's own energy exhaustion"
            );
            assert_eq!(energy_used, limit);
        }
        other => panic!("expected a root OutOfEnergy halt, got {other:?}"),
    }
}

/// The self-transfer ban — the arm most likely to be reachable from real
/// bytecode, since it needs only a funded contract rather than a 2^63 value
/// word. Nested, java contains it: `VMUtils.validateForSmartContract` throws
/// "Cannot transfer TRX to yourself", `Program.callToAddress` rethrows it as a
/// `TransferException` under #26, `VM.play` records it on that frame's own
/// result, and the caller pushes zero and continues. At the ROOT frame the
/// same failure is the transaction's outcome, TRANSFER_FAILED with
/// consumed-only energy.
#[test]
fn nested_self_call_with_value_is_contained_to_its_frame() {
    let mut value = [0u8; 32];
    value[31] = 0x0a; // 10 sun

    // Nested: the caller survives it.
    let stores = fresh_stores();
    let inner = install_contract(&stores, 0xe4, &[0x00]); // placeholder for the address
    install_contract(&stores, 0xe4, &build_call_with_value(inner, value));
    // Fund it so java's earlier sender-balance push-0 does not pre-empt the ban.
    set_balance(&stores, inner, 1_000);
    let outer = install_contract(&stores, 0xe5, &build_call_with_value(inner, [0u8; 32]));
    let owner = fund_account(&stores, 0xbb, 1_000_000_000);

    let limit = 2_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, outer), limit) {
        VmOutcome::Success { energy_used, .. } => {
            assert!(energy_used < limit, "the tx itself must not spend-all");
        }
        other => panic!("a nested self-CALL must not kill the tx, got {other:?}"),
    }
    assert_eq!(
        slot_value(&stores, outer, 0).last(),
        Some(&1u8),
        "the caller must push 0 and run on to its SSTORE"
    );
    assert!(
        slot_value(&stores, inner, 0).iter().all(|&b| b == 0),
        "the frame that raised the failure keeps its own state unwound"
    );

    // Root-frame control: the identical contract, triggered directly.
    let stores = fresh_stores();
    let own = install_contract(&stores, 0xe4, &[0x00]);
    install_contract(&stores, 0xe4, &build_call_with_value(own, value));
    set_balance(&stores, own, 1_000);
    let owner = fund_account(&stores, 0xbc, 1_000_000_000);
    match run_with_limit(&stores, &trigger_of(owner, own), limit) {
        VmOutcome::TransferFailed { energy_used } => {
            assert!(
                energy_used > 0 && energy_used < limit,
                "a TransferException is spend-all-exempt"
            );
        }
        other => panic!("expected a root-frame TransferFailed, got {other:?}"),
    }
}

/// SELFDESTRUCT is the one `TransferException` producer that is not a CALL
/// opcode. Before ALLOW_TVM_SOLIDITY_059 (#32) a dying contract with a balance
/// cannot create an absent obtainer, so `MUtil.transfer` reaches
/// `VMUtils.validateForSmartContract`, which throws "no ToAccount"; under #26
/// the catch wraps it in a `TransferException`. Nested, that halts only the
/// dying frame — the caller pushes zero and runs on, and the contract survives
/// because its state is unwound.
#[test]
fn nested_suicide_transfer_failure_is_contained_to_its_frame() {
    // `fresh_stores` is pre-#32 (ALLOW_TVM_SOLIDITY_059 unset) with #26 active.
    let stores = fresh_stores();
    let mut heir = [0u8; 21];
    heir[0] = 0x41;
    heir[1..].fill(0xe7); // never installed, so it has no account row

    let mut inner_code = Vec::new();
    inner_code.push(0x73); // PUSH20 heir
    inner_code.extend_from_slice(&heir[1..]);
    inner_code.push(0xff); // SELFDESTRUCT
    let inner = install_contract(&stores, 0xe8, &inner_code);
    set_balance(&stores, inner, 1_000); // balance > 0 selects the throwing arm

    let outer = install_contract(&stores, 0xe9, &build_call_with_value(inner, [0u8; 32]));
    let owner = fund_account(&stores, 0xbd, 1_000_000_000);

    let limit = 2_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, outer), limit) {
        VmOutcome::Success { energy_used, .. } => {
            assert!(energy_used < limit, "the tx itself must not spend-all");
        }
        other => panic!("a nested SELFDESTRUCT failure must not kill the tx, got {other:?}"),
    }
    assert_eq!(
        slot_value(&stores, outer, 0).last(),
        Some(&1u8),
        "the caller must push 0 and run on to its SSTORE"
    );
    assert!(
        stores
            .accounts
            .get(&tron_crypto::address::Address::from_raw(heir))
            .unwrap()
            .is_none(),
        "the heir must not be created before ALLOW_TVM_SOLIDITY_059"
    );
}

/// The CREATE counterpart of `nested_transfer_failure_forfeits_the_forwarded_energy`.
/// java `createContractImpl` charges the caller `energyLimit` up front
/// (Program.java:888-889), then splits the two failure kinds exactly as
/// `callToAddress` does: an init frame that raised an exception takes the early
/// `return` at Program.java:963 and never reaches `refundEnergyAfterVM`
/// (:977), so the caller forfeits the whole forwarded budget. Only an init
/// frame that merely REVERTED is refunded.
///
/// Before ALLOW_TVM_COMPATIBLE_EVM there is no 1/64 retention, so CREATE
/// forwards everything the caller had left. Forfeiting it therefore starves the
/// caller outright: it cannot reach the SSTORE after the CREATE and the root
/// halts OUT_OF_ENERGY having spent the whole limit. Refunding instead (the
/// pre-fix behaviour) lets the caller run on and the transaction SUCCEED.
#[test]
fn create_init_transfer_failure_forfeits_the_forwarded_energy() {
    let stores = fresh_stores();
    // Init code: CALL a leaf with value 2^63, which `longValueExact()` rejects.
    let leaf = install_contract(&stores, 0xe6, &[0x00]);
    let mut bad = [0u8; 32];
    bad[24] = 0x80; // 2^63
    let init = build_call_with_value(leaf, bad);

    // Caller: copy `init` into memory, CREATE from it, POP the pushed zero,
    // then SSTORE slot0 := 1 to prove whether the caller ran on.
    let mut code = Vec::new();
    for (i, b) in init.iter().enumerate() {
        code.extend_from_slice(&[0x60, *b]); // PUSH1 byte
        code.extend_from_slice(&[0x60, i as u8]); // PUSH1 offset
        code.push(0x53); // MSTORE8
    }
    code.extend_from_slice(&[0x60, init.len() as u8]); // size
    code.extend_from_slice(&[0x60, 0x00]); // offset
    code.extend_from_slice(&[0x60, 0x00]); // value
    code.push(0xf0); // CREATE
    code.push(0x50); // POP
    code.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55]); // SSTORE slot0 := 1
    code.push(0x00); // STOP

    let outer = install_contract(&stores, 0xe7, &code);
    let owner = fund_account(&stores, 0xb9, 1_000_000_000);

    let limit = 3_000_000u64;
    match run_with_limit(&stores, &trigger_of(owner, outer), limit) {
        VmOutcome::Halt {
            result,
            energy_used,
            ..
        } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::OutOfEnergy,
                "the caller forfeits the forwarded budget and starves"
            );
            assert_eq!(energy_used, limit);
        }
        other => panic!(
            "an exception init frame must forfeit the forwarded budget, not be \
             refunded into a surviving caller; got {other:?}"
        ),
    }
    assert_ne!(
        slot_value(&stores, outer, 0).last(),
        Some(&1u8),
        "the caller must not have had the energy to reach its SSTORE"
    );
}
