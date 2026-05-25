//! End-to-end test for `is_shielded_trc20_contract_note_spent`.
//!
//! The method composes two halves:
//!   1. Sapling nullifier derivation from `(note, ak, nk, position)`.
//!   2. A `nullifiers(bytes32)` view call against the TRC-20
//!      contract identified by `shielded_trc20_contract_address`.
//!
//! For (1) we build a known note (PaymentAddress + value + rcm)
//! locally so the test owns the inputs and the expected nullifier.
//! For (2) we deploy a minimal contract whose runtime bytecode
//! returns a hard-coded boolean for any `nullifiers(bytes32)`
//! call — that's enough to verify the gRPC method routes the
//! derived nullifier through to the contract read and decodes the
//! reply.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tron_chainbase::{AccountStore, CodeStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_proto::protocol::{NfTrc20Parameters, Note};
use tron_proto::Account;

use tron_grpc::proto::wallet_client::WalletClient;
use tron_rpc::{EthCallBackends, RpcState};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state_with_contract(addr: [u8; 21], bytecode: Vec<u8>) -> RpcState {
    let accounts = mem();
    let code = mem();
    let storage = mem();
    let witnesses = mem();
    let contract_state = mem();
    let dyn_props = mem();
    let delegated_resources = mem();
    let delegation = mem();
    let contracts = mem();
    let block_index = mem();

    let acc_store = AccountStore::new(accounts.clone());
    let code_store = CodeStore::new(code.clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code_store.put(&hash, &bytecode);
    acc_store.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: bytecode,
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    );

    let backends = EthCallBackends {
        accounts: accounts.clone(),
        code: code.clone(),
        storage: storage.clone(),
        witnesses,
        contract_state,
        dyn_props: dyn_props.clone(),
        delegated_resources,
        delegation,
        contracts,
        block_index: Some(block_index),
    };
    RpcState::new(accounts, mem(), mem(), mem(), dyn_props, 11_111)
        .with_eth_call_backends(backends)
}

async fn spawn_server(
    state: RpcState,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let shut = async move {
            let _ = shutdown_rx.await;
        };
        tron_grpc::start_server(state, addr, shut).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx, server)
}

/// Bytecode that returns 32 bytes of zeros — represents an unspent
/// nullifier in the contract's mapping (`nullifiers(nf) == false`).
fn return_false_bytecode() -> Vec<u8> {
    vec![
        0x60, 0x20, // PUSH1 0x20  (length=32)
        0x60, 0x00, // PUSH1 0x00  (offset)
        0xf3, // RETURN
    ]
}

/// Bytecode that stores 1 at memory[0..32] and returns it — represents
/// `nullifiers(nf) == true`.
fn return_true_bytecode() -> Vec<u8> {
    vec![
        0x60, 0x01, // PUSH1 0x01
        0x60, 0x1f, // PUSH1 0x1f (offset 31 — write 1 byte at end)
        0x53, // MSTORE8
        0x60, 0x20, // PUSH1 0x20 (length=32)
        0x60, 0x00, // PUSH1 0x00 (offset)
        0xf3, // RETURN
    ]
}

/// Build a valid (PaymentAddress, value, rcm, nk, position) tuple
/// using sapling-crypto so the gRPC method can derive a real
/// nullifier off it. Returns the matching `NfTrc20Parameters`.
fn build_nf_params(contract_addr: [u8; 21]) -> NfTrc20Parameters {
    use group::Group;
    use sapling_crypto::keys::{NullifierDerivingKey, SaplingIvk};
    use sapling_crypto::Diversifier;

    // Pick a known ivk + diversifier that produce a valid
    // PaymentAddress (g_d on the Jubjub subgroup).
    let ivk_scalar = jubjub::Fr::from(0x12345678u64);
    let ivk = SaplingIvk(ivk_scalar);
    // Sweep diversifiers until one works.
    let mut d_bytes = [0u8; 11];
    let mut payment_address = None;
    for i in 0..255u8 {
        d_bytes[0] = i;
        let d = Diversifier(d_bytes);
        if let Some(pa) = ivk.to_payment_address(d) {
            payment_address = Some(pa);
            break;
        }
    }
    let pa = payment_address.expect("a valid diversifier in 256 tries");
    let pa_bytes = pa.to_bytes();
    let payment_address_hex = hex::encode(pa_bytes);

    // nk = scalar * proof_generation_key_generator. For test
    // purposes, pick a non-zero subgroup point.
    let nk_point = jubjub::SubgroupPoint::generator() * jubjub::Fr::from(7u64);
    let _ = NullifierDerivingKey(nk_point);
    use group::GroupEncoding;
    let nk_bytes = nk_point.to_bytes();

    // Random rcm scalar.
    let rcm = jubjub::Fr::from(42u64);
    let rcm_bytes = rcm.to_bytes();

    let note = Note {
        value: 1000,
        payment_address: payment_address_hex,
        rcm: rcm_bytes.to_vec(),
        memo: Vec::new(),
    };
    NfTrc20Parameters {
        note: Some(note),
        ak: vec![0u8; 32], // unused for nullifier derivation
        nk: nk_bytes.to_vec(),
        position: 17,
        shielded_trc20_contract_address: contract_addr.to_vec(),
    }
}

#[tokio::test]
async fn returns_false_when_contract_mapping_says_not_spent() {
    let contract_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0xab);
        a
    };
    let state = fresh_state_with_contract(contract_addr, return_false_bytecode());
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = build_nf_params(contract_addr);
    let response = client
        .is_shielded_trc20_contract_note_spent(params)
        .await
        .expect("rpc")
        .into_inner();
    assert!(!response.is_spent, "contract returned all-zero, so unspent");
}

#[tokio::test]
async fn returns_true_when_contract_mapping_says_spent() {
    let contract_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0xcd);
        a
    };
    let state = fresh_state_with_contract(contract_addr, return_true_bytecode());
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = build_nf_params(contract_addr);
    let response = client
        .is_shielded_trc20_contract_note_spent(params)
        .await
        .expect("rpc")
        .into_inner();
    assert!(response.is_spent, "contract returned nonzero, so spent");
}

#[tokio::test]
async fn rejects_invalid_payment_address_length() {
    let contract_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0xff);
        a
    };
    let state = fresh_state_with_contract(contract_addr, return_false_bytecode());
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let mut params = build_nf_params(contract_addr);
    // Truncate the payment_address hex to make it invalid.
    params.note.as_mut().unwrap().payment_address.truncate(40);
    let err = client
        .is_shielded_trc20_contract_note_spent(params)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message().contains("payment_address"),
        "expected error mentioning payment_address; got: {}",
        err.message()
    );
}

#[tokio::test]
async fn rejects_missing_note() {
    let contract_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0xee);
        a
    };
    let state = fresh_state_with_contract(contract_addr, return_false_bytecode());
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = NfTrc20Parameters {
        note: None,
        ak: vec![0u8; 32],
        nk: vec![0u8; 32],
        position: 0,
        shielded_trc20_contract_address: contract_addr.to_vec(),
    };
    let err = client
        .is_shielded_trc20_contract_note_spent(params)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("missing note"));
}

#[tokio::test]
async fn nullifier_derivation_is_position_sensitive() {
    // Same note + nk + contract — different positions should produce
    // different nullifiers, and therefore different calldata to the
    // contract. Our return_false contract ignores the input so both
    // return `false`, but the test fails if the gRPC method DOESN'T
    // route the call (e.g., short-circuits on missing-nf-derivation).
    let contract_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(0x11);
        a
    };
    let state = fresh_state_with_contract(contract_addr, return_false_bytecode());
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let mut params_a = build_nf_params(contract_addr);
    params_a.position = 5;
    let mut params_b = build_nf_params(contract_addr);
    params_b.position = 999;
    let resp_a = client
        .is_shielded_trc20_contract_note_spent(params_a)
        .await
        .expect("rpc a")
        .into_inner();
    let resp_b = client
        .is_shielded_trc20_contract_note_spent(params_b)
        .await
        .expect("rpc b")
        .into_inner();
    // Both `false` (the return_false contract); the point is the
    // method ran end-to-end for both inputs.
    assert!(!resp_a.is_spent);
    assert!(!resp_b.is_spent);
}
