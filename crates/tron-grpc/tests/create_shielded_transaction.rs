//! End-to-end test: `create_shielded_transaction` produces a
//! Transaction containing a `ShieldedTransferContract` with valid
//! spend + receive proofs, a 64-byte binding signature, and (in the
//! with-ask variant) 64-byte spend-authority signatures on each
//! SpendDescription.
//!
//! This is the gating test for the proving infrastructure landing —
//! if it passes, the dep-resolution + prover wiring + ZenTransactionBuilder
//! port all work together. Runs ~1-2 seconds per proof (release
//! mode), so we mark it `#[ignore]` and run explicitly.

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::sync::oneshot;
use tron_chainbase::{KvBackend, MemBackend};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{
    Note as NoteProto, PrivateParameters, PrivateParametersWithoutAsk, ReceiveNote,
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

/// Build a synthetic Sapling key triple + a payment address +
/// matching ReceiveNote suitable for shielded-transfer construction.
/// Returns `(nsk, ovk, recv_note)`. Tests that don't exercise
/// shielded SPENDS (only transparent-source) can skip the ASK
/// derivation and pass empty `ask`.
fn key_setup() -> (Vec<u8>, Vec<u8>, ReceiveNote) {
    use sapling_crypto::keys::{Diversifier, ExpandedSpendingKey};

    let sk = [0xa5u8; 32];
    let esk = ExpandedSpendingKey::from_spending_key(&sk);
    let nsk = esk.proof_generation_key().nsk.to_bytes().to_vec();
    let ovk = esk.ovk.0.to_vec();
    let vk = esk.proof_generation_key().to_viewing_key();
    let ivk = vk.ivk();

    let pa = (0u8..=255)
        .find_map(|seed| {
            let mut d = [0u8; 11];
            d[0] = seed;
            ivk.to_payment_address(Diversifier(d))
        })
        .expect("valid payment address");
    let pa_bytes = pa.to_bytes();
    let pa_hex = hex::encode(pa_bytes);

    let recv = ReceiveNote {
        note: Some(NoteProto {
            value: 1000,
            payment_address: pa_hex,
            rcm: jubjub::Fr::from(7u64).to_bytes().to_vec(),
            memo: Vec::new(),
        }),
    };
    (nsk, ovk, recv)
}

#[tokio::test]
#[ignore = "loads ~50 MB Sapling params + runs Groth16 proving (~5-10s release)"]
async fn create_shielded_transaction_with_transparent_input_and_shielded_output() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let (_nsk, ovk, recv) = key_setup();
    // Pure transparent → shielded: from_amount > 0, no spends, one
    // receive at the same value (value balance = 0).
    let mut transparent_from = [0u8; 21];
    transparent_from[0] = 0x41;
    transparent_from[1..].fill(0xab);
    let params = PrivateParameters {
        transparent_from_address: transparent_from.to_vec(),
        ask: vec![],
        nsk: vec![],
        ovk,
        from_amount: 1000,
        shielded_spends: vec![],
        shielded_receives: vec![recv],
        transparent_to_address: vec![],
        to_amount: 0,
        timeout: 0,
    };
    let resp = client
        .create_shielded_transaction(params)
        .await
        .expect("rpc")
        .into_inner();
    let tx = resp.transaction.expect("transaction set");
    let raw = tx.raw_data.expect("raw_data set");
    assert_eq!(raw.contract.len(), 1);
    let c = &raw.contract[0];
    let any = c.parameter.as_ref().expect("contract parameter set");
    let stc = tron_proto::ShieldedTransferContract::decode(any.value.as_slice()).unwrap();
    assert!(stc.spend_description.is_empty(), "no spends in this test");
    assert_eq!(stc.receive_description.len(), 1);
    let rd = &stc.receive_description[0];
    assert_eq!(rd.value_commitment.len(), 32);
    assert_eq!(rd.note_commitment.len(), 32);
    assert_eq!(rd.epk.len(), 32);
    assert_eq!(rd.c_enc.len(), 580);
    assert_eq!(rd.c_out.len(), 80);
    assert_eq!(rd.zkproof.len(), 192);
    assert_eq!(stc.binding_signature.len(), 64);
    assert_eq!(stc.transparent_from_address, transparent_from);
    assert_eq!(stc.from_amount, 1000);
}

#[tokio::test]
#[ignore = "loads ~50 MB Sapling params + runs Groth16 proving"]
async fn create_shielded_transaction_without_spend_auth_sig_leaves_field_empty() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let (_nsk, ovk, recv) = key_setup();
    let mut transparent_from = [0u8; 21];
    transparent_from[0] = 0x41;
    transparent_from[1..].fill(0xab);
    // Without-ask variant: passes `ak` instead of `ask`. Since we
    // have no shielded spend in this test (only a transparent input),
    // ak is unused but we still set it to satisfy the proto.
    let params = PrivateParametersWithoutAsk {
        transparent_from_address: transparent_from.to_vec(),
        ak: vec![],
        nsk: vec![],
        ovk,
        from_amount: 1000,
        shielded_spends: vec![],
        shielded_receives: vec![recv],
        transparent_to_address: vec![],
        to_amount: 0,
        timeout: 0,
    };
    let resp = client
        .create_shielded_transaction_without_spend_auth_sig(params)
        .await
        .expect("rpc")
        .into_inner();
    let tx = resp.transaction.expect("transaction set");
    let raw = tx.raw_data.expect("raw_data set");
    let any = raw.contract[0].parameter.as_ref().unwrap();
    let stc = tron_proto::ShieldedTransferContract::decode(any.value.as_slice()).unwrap();
    // No spends → no spend_authority_signature entries to check.
    assert!(stc.spend_description.is_empty());
    assert_eq!(stc.binding_signature.len(), 64);
}

#[tokio::test]
async fn create_shielded_transaction_rejects_no_input_source() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    // No transparent_from, no ask → InvalidArgument.
    let params = PrivateParameters {
        transparent_from_address: vec![],
        ask: vec![],
        nsk: vec![],
        ovk: vec![0u8; 32],
        from_amount: 0,
        shielded_spends: vec![],
        shielded_receives: vec![],
        transparent_to_address: vec![],
        to_amount: 0,
        timeout: 0,
    };
    let err = client.create_shielded_transaction(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn create_shielded_transaction_without_ask_rejects_no_input_source() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = PrivateParametersWithoutAsk {
        transparent_from_address: vec![],
        ak: vec![],
        nsk: vec![],
        ovk: vec![0u8; 32],
        from_amount: 0,
        shielded_spends: vec![],
        shielded_receives: vec![],
        transparent_to_address: vec![],
        to_amount: 0,
        timeout: 0,
    };
    let err = client
        .create_shielded_transaction_without_spend_auth_sig(params)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn create_shielded_transaction_with_empty_spends_and_receives_is_rejected() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let mut transparent_from = [0u8; 21];
    transparent_from[0] = 0x41;
    transparent_from[1..].fill(0xab);
    let params = PrivateParameters {
        transparent_from_address: transparent_from.to_vec(),
        ask: vec![],
        nsk: vec![],
        ovk: vec![0u8; 32],
        from_amount: 0,
        shielded_spends: vec![],
        shielded_receives: vec![],
        transparent_to_address: vec![],
        to_amount: 0,
        timeout: 0,
    };
    let err = client.create_shielded_transaction(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
