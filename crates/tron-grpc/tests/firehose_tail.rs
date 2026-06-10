//! End-to-end firehose tail: a real gRPC server + the generated
//! client. Covers replay (history before the connect), live follow
//! (entries appended while the stream is open), and cursor resume.

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::sync::oneshot;
use tron_chainbase::{KvBackend, MemBackend};
use tron_grpc::firehose_proto::firehose_client::FirehoseClient;
use tron_grpc::firehose_proto::{self as fh};
use tron_index::FirehoseLogWriter;
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn tmp_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tron-fh-tail-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn apply_entry(seq: u64, height: i64) -> fh::Entry {
    fh::Entry {
        seq,
        event: Some(fh::entry::Event::Apply(fh::BlockApplied {
            height,
            block_id: vec![height as u8; 32],
            timestamp_ms: 1_700_000_000_000 + height * 3000,
            ..Default::default()
        })),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tail_replays_history_follows_live_and_resumes_by_cursor() {
    let dir = tmp_dir();
    let mut writer = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
    for h in 1..=3i64 {
        let seq = writer.next_seq();
        writer.append(&apply_entry(seq, h).encode_to_vec()).unwrap();
    }
    writer.sync().unwrap();

    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 1)
        .with_firehose(writer.tail_handle());

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let shut = async move {
            let _ = shutdown_rx.await;
        };
        tron_grpc::start_server(state, addr, shut).await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut client = FirehoseClient::connect(format!("http://{addr}")).await.expect("connect");

    // ---- replay: history present before the connect ----
    let mut stream = client
        .tail(fh::TailRequest { from_seq: 1 })
        .await
        .expect("tail")
        .into_inner();
    for expect in 1..=3u64 {
        let entry = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("timely")
            .expect("stream ok")
            .expect("entry");
        assert_eq!(entry.seq, expect);
        match entry.event {
            Some(fh::entry::Event::Apply(a)) => assert_eq!(a.height, expect as i64),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    // ---- live follow: appended while the stream is parked ----
    let seq = writer.next_seq();
    writer.append(&apply_entry(seq, 4).encode_to_vec()).unwrap();
    // Visibility follows durability: the un-fsynced append must NOT
    // reach the stream yet (a torn tail could erase it and reassign
    // its seq — consumers may only persist entries that cannot
    // vanish).
    let premature = tokio::time::timeout(Duration::from_millis(300), stream.message()).await;
    assert!(premature.is_err(), "entry visible before fsync: {premature:?}");
    writer.sync().unwrap();
    let entry = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("live entry arrives")
        .expect("stream ok")
        .expect("entry");
    assert_eq!(entry.seq, 4);

    // ---- resume: a second consumer from its own cursor ----
    let mut resumed = client
        .tail(fh::TailRequest { from_seq: 3 })
        .await
        .expect("tail resume")
        .into_inner();
    let seqs = [
        resumed.message().await.unwrap().unwrap().seq,
        resumed.message().await.unwrap().unwrap().seq,
    ];
    assert_eq!(seqs, [3, 4], "resume replays exactly from the cursor");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
}
