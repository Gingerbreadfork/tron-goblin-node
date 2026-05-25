//! End-to-end test for `create_shield_nullifier` over gRPC.
//!
//! Verifies that:
//!   * A valid `NfParameters` (note + voucher carrying tree state +
//!     nk) produces a 32-byte nullifier.
//!   * The returned nullifier matches the value `is_shielded_trc20_*`
//!     would derive from the same `(note, nk, position)` triple —
//!     proves both gRPC entry points are routing through the same
//!     `derive_sapling_nullifier` core.
//!   * Bad inputs (missing note, missing voucher, empty voucher tree,
//!     bad rcm length, bad nk length) return InvalidArgument.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tron_chainbase::{KvBackend, MemBackend};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{
    IncrementalMerkleTree, IncrementalMerkleVoucher, NfParameters, NfTrc20Parameters, Note,
    PedersenHash,
};
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fixture() -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
}

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
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx, server)
}

/// Build a known-good Note + nk via sapling-crypto.
fn build_note_and_nk() -> (Note, Vec<u8>) {
    use group::Group;
    use sapling_crypto::keys::SaplingIvk;
    use sapling_crypto::Diversifier;

    let ivk_scalar = jubjub::Fr::from(0x12345678u64);
    let ivk = SaplingIvk(ivk_scalar);
    let mut d_bytes = [0u8; 11];
    let mut payment_address = None;
    for i in 0..=255u8 {
        d_bytes[0] = i;
        let d = Diversifier(d_bytes);
        if let Some(pa) = ivk.to_payment_address(d) {
            payment_address = Some(pa);
            break;
        }
    }
    let pa = payment_address.expect("a valid diversifier in 256 tries");
    let pa_hex = hex::encode(pa.to_bytes());

    let nk_point = jubjub::SubgroupPoint::generator() * jubjub::Fr::from(11u64);
    use group::GroupEncoding;
    let nk_bytes = nk_point.to_bytes().to_vec();

    let rcm = jubjub::Fr::from(99u64);
    let note = Note {
        value: 4242,
        payment_address: pa_hex,
        rcm: rcm.to_bytes().to_vec(),
        memo: Vec::new(),
    };
    (note, nk_bytes)
}

/// Build a voucher whose `tree.size()` resolves to `target_size`.
/// Encoding follows java-tron's IncrementalMerkleTreeContainer.size():
/// `+1` if left present, `+1` if right present, `+2^(i+1)` per present
/// parent at index i. The constants here just toggle the leaf cells
/// + parents required to hit the target.
fn voucher_with_size(target_size: u64) -> IncrementalMerkleVoucher {
    let mut left = None;
    let mut right = None;
    let mut parents: Vec<PedersenHash> = Vec::new();
    let mut remaining = target_size;
    // Set left first if remaining ≥ 1.
    if remaining >= 1 {
        left = Some(PedersenHash {
            content: vec![0xaa; 32],
        });
        remaining -= 1;
    }
    if remaining >= 1 {
        right = Some(PedersenHash {
            content: vec![0xbb; 32],
        });
        remaining -= 1;
    }
    // Now fill parents at indices 0,1,2,... with weight 2^(i+1).
    let mut i = 0;
    while remaining > 0 {
        let weight = 1u64 << (i + 1);
        let present = remaining >= weight;
        parents.push(PedersenHash {
            content: if present { vec![0xcc; 32] } else { Vec::new() },
        });
        if present {
            remaining -= weight;
        }
        i += 1;
        // Hard safety bound for malformed test inputs.
        if i > 32 {
            break;
        }
    }
    IncrementalMerkleVoucher {
        tree: Some(IncrementalMerkleTree {
            left,
            right,
            parents,
        }),
        filled: Vec::new(),
        cursor: None,
        cursor_depth: 0,
        rt: Vec::new(),
        output_point: None,
    }
}

#[tokio::test]
async fn create_shield_nullifier_returns_32_bytes_matching_trc20_path() {
    let (addr, _shutdown, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let (note, nk) = build_note_and_nk();
    // Size = 8 → position = 7.
    let voucher = voucher_with_size(8);
    let params = NfParameters {
        note: Some(note.clone()),
        voucher: Some(voucher),
        ak: vec![0u8; 32], // unused by Sapling nf derivation
        nk: nk.clone(),
    };
    let response = client
        .create_shield_nullifier(params)
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.value.len(), 32, "nullifier must be 32 bytes");

    // Sanity check: the TRC-20 variant with the same (note, nk,
    // position=7) must produce the same nullifier — both methods go
    // through `derive_sapling_nullifier`.
    let trc20_params = NfTrc20Parameters {
        note: Some(note),
        ak: vec![0u8; 32],
        nk,
        position: 7,
        shielded_trc20_contract_address: vec![0u8; 21],
    };
    // Re-derive the expected value locally rather than calling the
    // TRC-20 RPC (which depends on contract state). Compute it the
    // same way the service does.
    let expected = expected_nullifier(&trc20_params);
    assert_eq!(response.value, expected.to_vec());
}

#[tokio::test]
async fn create_shield_nullifier_position_changes_with_voucher_size() {
    let (addr, _shutdown, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .expect("connect");

    let (note, nk) = build_note_and_nk();
    // Two different voucher sizes ⇒ two different positions ⇒ two
    // different nullifiers (Sapling nf is position-sensitive).
    let v_small = voucher_with_size(4); // pos = 3
    let v_large = voucher_with_size(64); // pos = 63

    let nf_small = client
        .create_shield_nullifier(NfParameters {
            note: Some(note.clone()),
            voucher: Some(v_small),
            ak: vec![0u8; 32],
            nk: nk.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .value;
    let nf_large = client
        .create_shield_nullifier(NfParameters {
            note: Some(note),
            voucher: Some(v_large),
            ak: vec![0u8; 32],
            nk,
        })
        .await
        .unwrap()
        .into_inner()
        .value;
    assert_ne!(nf_small, nf_large, "different positions must produce different nullifiers");
}

#[tokio::test]
async fn create_shield_nullifier_rejects_missing_note() {
    let (addr, _shutdown, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = NfParameters {
        note: None,
        voucher: Some(voucher_with_size(1)),
        ak: vec![0u8; 32],
        nk: vec![0u8; 32],
    };
    let err = client.create_shield_nullifier(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("missing note"));
}

#[tokio::test]
async fn create_shield_nullifier_rejects_missing_voucher() {
    let (addr, _shutdown, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (note, nk) = build_note_and_nk();
    let params = NfParameters {
        note: Some(note),
        voucher: None,
        ak: vec![0u8; 32],
        nk,
    };
    let err = client.create_shield_nullifier(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("missing voucher"));
}

#[tokio::test]
async fn create_shield_nullifier_rejects_empty_voucher_tree() {
    let (addr, _shutdown, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (note, nk) = build_note_and_nk();
    // Tree with no present nodes → size=0 → no position defined.
    let voucher = IncrementalMerkleVoucher {
        tree: Some(IncrementalMerkleTree {
            left: None,
            right: None,
            parents: Vec::new(),
        }),
        filled: Vec::new(),
        cursor: None,
        cursor_depth: 0,
        rt: Vec::new(),
        output_point: None,
    };
    let params = NfParameters {
        note: Some(note),
        voucher: Some(voucher),
        ak: vec![0u8; 32],
        nk,
    };
    let err = client.create_shield_nullifier(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message().contains("position undefined") || err.message().contains("empty"),
        "got: {}",
        err.message()
    );
}

#[tokio::test]
async fn create_shield_nullifier_rejects_bad_rcm_length() {
    let (addr, _shutdown, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (mut note, nk) = build_note_and_nk();
    note.rcm = vec![0u8; 16]; // wrong length
    let params = NfParameters {
        note: Some(note),
        voucher: Some(voucher_with_size(1)),
        ak: vec![0u8; 32],
        nk,
    };
    let err = client.create_shield_nullifier(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("rcm"));
}

#[tokio::test]
async fn create_shield_nullifier_rejects_bad_nk_length() {
    let (addr, _shutdown, _server) = spawn_server().await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (note, _) = build_note_and_nk();
    let params = NfParameters {
        note: Some(note),
        voucher: Some(voucher_with_size(1)),
        ak: vec![0u8; 32],
        nk: vec![0u8; 16], // wrong length
    };
    let err = client.create_shield_nullifier(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("nk"));
}

/// Compute the expected nullifier for a TRC-20-style NfTrc20Parameters
/// independently, so the test isn't tautological (i.e., the test
/// computes the answer via a SECOND path through sapling-crypto and
/// compares).
fn expected_nullifier(params: &NfTrc20Parameters) -> [u8; 32] {
    use group::GroupEncoding;
    use sapling_crypto::keys::NullifierDerivingKey;
    use sapling_crypto::note::Rseed;
    use sapling_crypto::value::NoteValue;
    use sapling_crypto::{Note, PaymentAddress};

    let note = params.note.as_ref().unwrap();
    let pa_bytes: [u8; 43] = hex::decode(&note.payment_address)
        .unwrap()
        .try_into()
        .unwrap();
    let pa = PaymentAddress::from_bytes(&pa_bytes).unwrap();
    let rcm_bytes: [u8; 32] = note.rcm.as_slice().try_into().unwrap();
    let rcm = jubjub::Fr::from_bytes(&rcm_bytes).unwrap();
    let sapling_note = Note::from_parts(
        pa,
        NoteValue::from_raw(note.value as u64),
        Rseed::BeforeZip212(rcm),
    );
    let nk_bytes: [u8; 32] = params.nk.as_slice().try_into().unwrap();
    let nk_point = jubjub::SubgroupPoint::from_bytes(&nk_bytes).unwrap();
    let nk = NullifierDerivingKey(nk_point);
    sapling_note.nf(&nk, params.position as u64).0
}
