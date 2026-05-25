//! End-to-end tests for `create_shielded_contract_parameters` and
//! `_without_ask`. The two methods build a `ShieldedTrc20Parameters`
//! proto containing fully proved spend + receive descriptions plus
//! a binding signature and (with-ask) per-spend authority sigs.
//!
//! The shape rules (mirroring java-tron's `Wallet.createShieldedContractParameters`):
//!   * MINT: `fromAmount > 0`, no spends, exactly one receive whose
//!     value matches `fromAmount`, `toAmount == 0`.
//!   * TRANSFER: 1–2 spends, 1–2 receives, both amounts zero.
//!   * BURN: 1 spend, 0–1 receives, `toAmount > 0`, `transparent_to_address`
//!     set, total receive + toAmount equals spend.value.
//!
//! The heavy proving tests run Groth16 (~1–2 s release per spend or
//! output) and are gated on `#[ignore]`. Run with
//! `cargo test --test create_shielded_contract_parameters --release -- --ignored`.

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tron_chainbase::{KvBackend, MemBackend};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{
    Note as NoteProto, PrivateShieldedTrc20Parameters,
    PrivateShieldedTrc20ParametersWithoutAsk, ReceiveNote,
};
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

async fn spawn() -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
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

/// Build a ReceiveNote suitable as a destination for a synthetic
/// MINT call. Returns `(ovk, receive_note)`.
fn fresh_receive_note(value: u64) -> (Vec<u8>, ReceiveNote) {
    use sapling_crypto::keys::{Diversifier, ExpandedSpendingKey};

    let esk = ExpandedSpendingKey::from_spending_key(&[0xa5u8; 32]);
    let vk = esk.proof_generation_key().to_viewing_key();
    let ivk = vk.ivk();
    let ovk = esk.ovk.0.to_vec();
    let pa = (0u8..=255)
        .find_map(|seed| {
            let mut d = [0u8; 11];
            d[0] = seed;
            ivk.to_payment_address(Diversifier(d))
        })
        .expect("valid payment address");
    let pa_hex = hex::encode(pa.to_bytes());
    (
        ovk,
        ReceiveNote {
            note: Some(NoteProto {
                value: value as i64,
                payment_address: pa_hex,
                rcm: jubjub::Fr::from(7u64).to_bytes().to_vec(),
                memo: Vec::new(),
            }),
        },
    )
}

fn dummy_contract_addr() -> Vec<u8> {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xc0);
    a.to_vec()
}

// ============================================================
// Validation (cheap — no proving)
// ============================================================

#[tokio::test]
async fn rejects_invalid_contract_address_length() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = PrivateShieldedTrc20Parameters {
        ask: vec![0u8; 32],
        nsk: vec![0u8; 32],
        ovk: vec![0u8; 32],
        from_amount: "0".to_string(),
        shielded_spends: vec![],
        shielded_receives: vec![],
        transparent_to_address: vec![],
        to_amount: "0".to_string(),
        shielded_trc20_contract_address: vec![0u8; 16],
    };
    let err = client
        .create_shielded_contract_parameters(params)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("contract_address"));
}

#[tokio::test]
async fn rejects_unrecognised_shape() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    // Doesn't match MINT/TRANSFER/BURN: from_amount > 0 AND spends > 0.
    let params = PrivateShieldedTrc20Parameters {
        ask: vec![0u8; 32],
        nsk: vec![0u8; 32],
        ovk: vec![0u8; 32],
        from_amount: "100".to_string(),
        shielded_spends: vec![tron_proto::protocol::SpendNoteTrc20 {
            note: Some(NoteProto {
                value: 100,
                payment_address: hex::encode([0u8; 43]),
                rcm: vec![0u8; 32],
                memo: vec![],
            }),
            alpha: vec![],
            root: vec![0u8; 32],
            path: vec![0u8; 1024],
            pos: 0,
        }],
        shielded_receives: vec![],
        transparent_to_address: vec![],
        to_amount: "0".to_string(),
        shielded_trc20_contract_address: dummy_contract_addr(),
    };
    let err = client
        .create_shielded_contract_parameters(params)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("mint/transfer/burn"));
}

// ============================================================
// MINT (proving) — release-mode only.
// ============================================================

#[tokio::test]
#[ignore = "loads ~50 MB Sapling params + runs Groth16 proving"]
async fn mint_produces_shielded_trc20_parameters_with_message_hash_and_binding_sig() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (ovk, recv) = fresh_receive_note(1000);
    let params = PrivateShieldedTrc20Parameters {
        ask: vec![],
        nsk: vec![],
        ovk,
        from_amount: "1000".to_string(),
        shielded_spends: vec![],
        shielded_receives: vec![recv],
        transparent_to_address: vec![],
        to_amount: "0".to_string(),
        shielded_trc20_contract_address: dummy_contract_addr(),
    };
    let resp = client
        .create_shielded_contract_parameters(params)
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.parameter_type, "mint");
    assert!(resp.spend_description.is_empty());
    assert_eq!(resp.receive_description.len(), 1);
    let rd = &resp.receive_description[0];
    assert_eq!(rd.zkproof.len(), 192);
    assert_eq!(rd.c_enc.len(), 580);
    assert_eq!(rd.c_out.len(), 80);
    assert_eq!(resp.binding_signature.len(), 64);
    assert_eq!(resp.message_hash.len(), 32);
    // trigger_contract_input must be a non-empty hex string (the MINT
    // calldata always populates it).
    assert!(!resp.trigger_contract_input.is_empty());
    let decoded = hex::decode(&resp.trigger_contract_input).expect("hex");
    // MINT calldata layout: 32(value) + 288(receive_desc) + 64(bsig) +
    // 580+80+12 = 1056.
    assert_eq!(decoded.len(), 1056);
}

#[tokio::test]
#[ignore = "loads ~50 MB Sapling params + runs Groth16 proving"]
async fn mint_without_ask_produces_same_shape() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (ovk, recv) = fresh_receive_note(500);
    let params = PrivateShieldedTrc20ParametersWithoutAsk {
        ak: vec![],
        nsk: vec![],
        ovk,
        from_amount: "500".to_string(),
        shielded_spends: vec![],
        shielded_receives: vec![recv],
        transparent_to_address: vec![],
        to_amount: "0".to_string(),
        shielded_trc20_contract_address: dummy_contract_addr(),
    };
    let resp = client
        .create_shielded_contract_parameters_without_ask(params)
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.parameter_type, "mint");
    assert_eq!(resp.receive_description.len(), 1);
    assert_eq!(resp.binding_signature.len(), 64);
    assert_eq!(resp.message_hash.len(), 32);
    // MINT always populates trigger_contract_input even in the
    // without-ask path.
    assert!(!resp.trigger_contract_input.is_empty());
}

#[tokio::test]
async fn mint_rejects_mismatched_from_amount_and_note_value() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (ovk, recv) = fresh_receive_note(1000);
    let params = PrivateShieldedTrc20Parameters {
        ask: vec![],
        nsk: vec![],
        ovk,
        from_amount: "999".to_string(), // doesn't match note value 1000
        shielded_spends: vec![],
        shielded_receives: vec![recv],
        transparent_to_address: vec![],
        to_amount: "0".to_string(),
        shielded_trc20_contract_address: dummy_contract_addr(),
    };
    let err = client
        .create_shielded_contract_parameters(params)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
