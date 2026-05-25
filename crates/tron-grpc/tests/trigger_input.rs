//! Tests for `get_trigger_input_for_shielded_trc20_contract`.
//!
//! Pure byte-merging: take already-proved `ShieldedTrc20Parameters`,
//! pair with spend-auth signatures + value + transparent-to address,
//! emit the ABI-encoded calldata for the shielded-TRC-20 contract's
//! `mint(...)` / `transfer(...)` / `burn(...)` Solidity functions.
//!
//! Test strategy: synthesize parameters with known-shape bytes, call
//! the method, and assert layout properties (length, fields at the
//! right offsets). End-to-end verification against an actual deployed
//! shielded-TRC-20 contract would need a real Sapling-proved
//! transaction, which is exercised separately via the
//! `createShieldedContractParameters` method.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tron_chainbase::{KvBackend, MemBackend};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{
    BytesMessage, ReceiveDescription, ShieldedTrc20Parameters,
    ShieldedTrc20TriggerContractParameters, SpendDescription,
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

fn dummy_receive_description(prefix: u8) -> ReceiveDescription {
    ReceiveDescription {
        value_commitment: vec![prefix; 32],
        note_commitment: vec![prefix ^ 0x10; 32],
        epk: vec![prefix ^ 0x20; 32],
        c_enc: vec![prefix ^ 0x40; 580],
        c_out: vec![prefix ^ 0x50; 80],
        zkproof: vec![prefix ^ 0x60; 192],
    }
}

fn dummy_spend_description(prefix: u8) -> SpendDescription {
    SpendDescription {
        value_commitment: vec![prefix; 32],
        anchor: vec![prefix ^ 0x01; 32],
        nullifier: vec![prefix ^ 0x02; 32],
        rk: vec![prefix ^ 0x03; 32],
        zkproof: vec![prefix ^ 0x04; 192],
        spend_authority_signature: vec![],
    }
}

// ============================================================
// MINT
// ============================================================

#[tokio::test]
async fn mint_layout_starts_with_value_then_cmu_cv_epk_zkproof_bsig_cenc_cout_pad() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let rd = dummy_receive_description(0xaa);
    let p = ShieldedTrc20Parameters {
        spend_description: vec![],
        receive_description: vec![rd.clone()],
        binding_signature: vec![0xbb; 64],
        message_hash: vec![],
        trigger_contract_input: String::new(),
        parameter_type: "mint".to_string(),
    };
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: Some(p),
        spend_authority_signature: vec![],
        amount: "100".to_string(),
        transparent_to_address: vec![],
    };
    let bytes = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .expect("rpc")
        .into_inner()
        .value;
    // 32(value) + 32(cmu) + 32(cv) + 32(epk) + 192(zkproof) +
    // 64(binding sig) + 580(c_enc) + 80(c_out) + 12(zeros) = 1056.
    assert_eq!(bytes.len(), 1056);
    assert_eq!(&bytes[16..32], &100u128.to_be_bytes());
    assert_eq!(&bytes[32..64], rd.note_commitment.as_slice());
    assert_eq!(&bytes[64..96], rd.value_commitment.as_slice());
    assert_eq!(&bytes[96..128], rd.epk.as_slice());
    assert_eq!(&bytes[128..320], rd.zkproof.as_slice());
    assert_eq!(&bytes[320..384], vec![0xbb; 64].as_slice());
    assert_eq!(&bytes[384..964], rd.c_enc.as_slice());
    assert_eq!(&bytes[964..1044], rd.c_out.as_slice());
    assert_eq!(&bytes[1044..1056], &[0u8; 12]);
}

#[tokio::test]
async fn mint_rejects_zero_value() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let p = ShieldedTrc20Parameters {
        spend_description: vec![],
        receive_description: vec![dummy_receive_description(0xaa)],
        binding_signature: vec![0xbb; 64],
        message_hash: vec![],
        trigger_contract_input: String::new(),
        parameter_type: "mint".to_string(),
    };
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: Some(p),
        spend_authority_signature: vec![],
        amount: "0".to_string(),
        transparent_to_address: vec![],
    };
    let err = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("positive"));
}

// ============================================================
// TRANSFER
// ============================================================

#[tokio::test]
async fn transfer_has_correct_offsets_and_section_counts() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let sd = dummy_spend_description(0x11);
    let rd = dummy_receive_description(0x22);
    let p = ShieldedTrc20Parameters {
        spend_description: vec![sd.clone()],
        receive_description: vec![rd.clone()],
        binding_signature: vec![0xbb; 64],
        message_hash: vec![],
        trigger_contract_input: String::new(),
        parameter_type: "transfer".to_string(),
    };
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: Some(p),
        spend_authority_signature: vec![BytesMessage {
            value: vec![0xcc; 64],
        }],
        amount: "0".to_string(),
        transparent_to_address: vec![],
    };
    let bytes = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .expect("rpc")
        .into_inner()
        .value;
    // 4 x 32-byte offsets/values at the top, then 64-byte binding sig
    // at offset 96. java-tron's order: input_offset, auth_offset,
    // output_offset, binding_sig, c_offset, then sections.
    assert!(bytes.len() >= 192);
    // input_offset = 192 (5th 32-byte slot, after the 4 offsets/sig).
    // Actually the layout is: [0..32]=input_offset, [32..64]=auth_offset,
    // [64..96]=output_offset, [96..160]=binding_sig (64 bytes),
    // [160..192]=c_offset. Then sections start at 192.
    let read_u64 = |o: usize| -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&bytes[o + 24..o + 32]);
        u64::from_be_bytes(a)
    };
    let input_offset = read_u64(0);
    let auth_offset = read_u64(32);
    let output_offset = read_u64(64);
    let c_offset = read_u64(160);
    assert_eq!(input_offset, 192);
    // auth_offset = 192 + 32 + 320 * 1 = 544 (320 = spend desc len).
    assert_eq!(auth_offset, 192 + 32 + 320);
    // output_offset = auth_offset + 32 + 64 * 1 = 640.
    assert_eq!(output_offset, auth_offset + 32 + 64);
    // c_offset = output_offset + 32 + 288 * 1 = 960.
    assert_eq!(c_offset, output_offset + 32 + 288);
    // Binding signature lives at [96..160].
    assert_eq!(&bytes[96..160], vec![0xbb; 64].as_slice());
}

#[tokio::test]
async fn transfer_rejects_mismatched_spend_auth_sig_count() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let p = ShieldedTrc20Parameters {
        spend_description: vec![dummy_spend_description(0x11)],
        receive_description: vec![dummy_receive_description(0x22)],
        binding_signature: vec![0xbb; 64],
        message_hash: vec![],
        trigger_contract_input: String::new(),
        parameter_type: "transfer".to_string(),
    };
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: Some(p),
        // 0 sigs for 1 spend → mismatch.
        spend_authority_signature: vec![],
        amount: "0".to_string(),
        transparent_to_address: vec![],
    };
    let err = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ============================================================
// BURN
// ============================================================

#[tokio::test]
async fn burn_layout_includes_spend_value_payto_burncipher() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let sd = dummy_spend_description(0x33);
    let burn_cipher_bytes = vec![0xeeu8; 80];
    let p = ShieldedTrc20Parameters {
        spend_description: vec![sd.clone()],
        receive_description: vec![],
        binding_signature: vec![0xbb; 64],
        message_hash: vec![],
        trigger_contract_input: hex::encode(&burn_cipher_bytes),
        parameter_type: "burn".to_string(),
    };
    let mut transparent_to = [0u8; 21];
    transparent_to[0] = 0x41;
    transparent_to[1..].fill(0xaa);
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: Some(p),
        spend_authority_signature: vec![BytesMessage {
            value: vec![0xcc; 64],
        }],
        amount: "42".to_string(),
        transparent_to_address: transparent_to.to_vec(),
    };
    let bytes = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .expect("rpc")
        .into_inner()
        .value;
    // First 320 bytes are the spend description.
    assert_eq!(&bytes[0..32], sd.nullifier.as_slice());
    assert_eq!(&bytes[32..64], sd.anchor.as_slice());
    assert_eq!(&bytes[64..96], sd.value_commitment.as_slice());
    assert_eq!(&bytes[96..128], sd.rk.as_slice());
    assert_eq!(&bytes[128..320], sd.zkproof.as_slice());
    // Then 64-byte spend-auth-sig.
    assert_eq!(&bytes[320..384], vec![0xcc; 64].as_slice());
    // Then 32-byte value (BE, low 16 = u128 BE).
    assert_eq!(&bytes[384 + 16..384 + 32], &42u128.to_be_bytes());
    // Then 64-byte binding sig.
    assert_eq!(&bytes[416..480], vec![0xbb; 64].as_slice());
    // Then 32-byte payTo: zeros[11] + 0x41 + 20-byte tvm addr.
    assert_eq!(&bytes[480..491], &[0u8; 11]);
    assert_eq!(bytes[491], 0x41);
    assert_eq!(&bytes[492..512], &transparent_to[1..]);
    // Then 80-byte burn ciphertext + 16 zeros.
    assert_eq!(&bytes[512..592], burn_cipher_bytes.as_slice());
    assert_eq!(&bytes[592..608], &[0u8; 16]);
}

#[tokio::test]
async fn burn_rejects_empty_transparent_to() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let p = ShieldedTrc20Parameters {
        spend_description: vec![dummy_spend_description(0x33)],
        receive_description: vec![],
        binding_signature: vec![0xbb; 64],
        message_hash: vec![],
        trigger_contract_input: hex::encode(&[0xeeu8; 80]),
        parameter_type: "burn".to_string(),
    };
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: Some(p),
        spend_authority_signature: vec![BytesMessage {
            value: vec![0xcc; 64],
        }],
        amount: "42".to_string(),
        transparent_to_address: vec![],
    };
    let err = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("transparent"));
}

#[tokio::test]
async fn rejects_unknown_parameter_type() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let p = ShieldedTrc20Parameters {
        spend_description: vec![],
        receive_description: vec![],
        binding_signature: vec![],
        message_hash: vec![],
        trigger_contract_input: String::new(),
        parameter_type: "garbage".to_string(),
    };
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: Some(p),
        spend_authority_signature: vec![],
        amount: "0".to_string(),
        transparent_to_address: vec![],
    };
    let err = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("garbage"));
}

#[tokio::test]
async fn rejects_missing_parameters() {
    let (addr, _shutdown, _server) = spawn().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let req = ShieldedTrc20TriggerContractParameters {
        shielded_trc20_parameters: None,
        spend_authority_signature: vec![],
        amount: "0".to_string(),
        transparent_to_address: vec![],
    };
    let err = client
        .get_trigger_input_for_shielded_trc20_contract(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
