//! Smoke test: just verify we can build a revm EVM and run a no-op
//! transaction. This pins our minimum-viable understanding of the
//! revm 40 API surface so subsequent integration work has a known
//! starting point.
//!
//! Uses [`EmptyDB`] directly instead of `CacheDB<EmptyDB>` because the
//! TRON fork bounds `revm::Context`'s Host impl on
//! `DB: TronDatabaseExt`. `EmptyDB` has a no-op impl in
//! revm-context-interface; `CacheDB` lives in `revm-database` (higher
//! up the dep graph than our fork) so its impl can't live there.

use revm::context::TxEnv;
use revm::database_interface::EmptyDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

#[test]
fn revm_executes_an_empty_transaction_against_an_empty_db() {
    let caller = Address::from_slice(&[0x11; 20]);
    let callee = Address::from_slice(&[0x22; 20]);

    let mut evm = Context::mainnet().with_db(EmptyDB::default()).build_mainnet();

    let tx = TxEnv {
        caller,
        kind: TxKind::Call(callee),
        value: U256::ZERO,
        data: Bytes::new(),
        gas_limit: 100_000,
        gas_price: 0,
        chain_id: Some(1),
        nonce: 0,
        ..Default::default()
    };

    let res = evm.transact(tx);
    // The exact Ok variant differs by version; we just want to confirm
    // execution doesn't panic and the call to a never-existed address
    // returns a result (revm treats CALL to empty address as "no code,
    // succeeds, returns empty").
    assert!(res.is_ok(), "transact errored: {:?}", res.err());
}
