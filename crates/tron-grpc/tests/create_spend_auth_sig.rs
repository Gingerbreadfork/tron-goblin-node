//! End-to-end test for `create_spend_auth_sig` over gRPC.
//!
//! Verifies:
//!   * A valid (ask, alpha, tx_hash) triple produces a 64-byte
//!     signature.
//!   * The signature verifies against the RedJubjub verifier with the
//!     randomized verification key `rk = ak + alpha * G`.
//!   * Bad-length inputs return InvalidArgument.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tron_chainbase::{KvBackend, MemBackend};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::SpendAuthSigParameters;
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fixture() -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
}

/// Boot the gRPC server, return the bound address + shutdown handle.
async fn spawn_server() -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let state = fixture();
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
    // Wait for the bind to take effect.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx, server)
}

#[tokio::test]
async fn create_spend_auth_sig_returns_64_byte_signature_that_verifies() {
    use jubjub::Scalar;
    use rand_core::OsRng;

    let (addr, shutdown_tx, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    // Build a valid ASK and an ALPHA from random scalars.
    let ask_scalar = Scalar::from(42u64); // fixed for repeatability
    let alpha_scalar = Scalar::from(7u64);
    let tx_hash = [0xab; 32];

    // Sign through the gRPC method.
    let params = SpendAuthSigParameters {
        ask: ask_scalar.to_bytes().to_vec(),
        tx_hash: tx_hash.to_vec(),
        alpha: alpha_scalar.to_bytes().to_vec(),
    };
    let response = client
        .create_spend_auth_sig(params)
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.value.len(), 64, "signature must be 64 bytes");

    // Verify the signature: derive the randomized verification key
    // `rk = (ask + alpha) * G_SpendAuth`, where G_SpendAuth is the
    // Jubjub generator used by RedJubjub SpendAuth. Then check the
    // signature.
    let rsk_scalar = ask_scalar + alpha_scalar;
    let rsk_bytes: [u8; 32] = rsk_scalar.to_bytes();
    let signing_key: redjubjub::SigningKey<redjubjub::SpendAuth> =
        rsk_bytes.try_into().expect("rsk valid");
    let verification_key = redjubjub::VerificationKey::from(&signing_key);
    let sig_bytes: [u8; 64] = response.value.as_slice().try_into().unwrap();
    let signature: redjubjub::Signature<redjubjub::SpendAuth> = sig_bytes.into();
    verification_key
        .verify(&tx_hash, &signature)
        .expect("signature must verify against rk");

    // For good measure: a different message must NOT verify.
    let bad_msg = [0xff; 32];
    assert!(verification_key.verify(&bad_msg, &signature).is_err());

    let _ = OsRng;
    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn create_spend_auth_sig_rejects_bad_ask_length() {
    let (addr, shutdown_tx, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let params = SpendAuthSigParameters {
        ask: vec![0xab; 31], // wrong length
        tx_hash: vec![0u8; 32],
        alpha: vec![0u8; 32],
    };
    let err = client.create_spend_auth_sig(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message().contains("ask"),
        "error should mention ask: {}",
        err.message()
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn create_spend_auth_sig_rejects_bad_alpha_length() {
    let (addr, shutdown_tx, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let params = SpendAuthSigParameters {
        ask: vec![0u8; 32],
        tx_hash: vec![0u8; 32],
        alpha: vec![0xab; 31],
    };
    let err = client.create_spend_auth_sig(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    let _ = shutdown_tx.send(());
}
