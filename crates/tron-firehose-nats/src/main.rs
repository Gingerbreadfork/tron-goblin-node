//! tron-firehose-nats — firehose → NATS JetStream bridge.
//!
//! Tails a tron-goblin-node's `tronfirehose.Firehose` gRPC stream and
//! republishes every entry to a JetStream stream, one message per
//! entry:
//!
//! * **Subjects**: `{prefix}.apply` for `BlockApplied` entries,
//!   `{prefix}.unwind` for `Unwind` entries (`{prefix}` defaults to
//!   `tron.firehose`). Payload = the raw protobuf `tronfirehose.Entry`
//!   bytes — downstream consumers decode with the same
//!   `firehose.proto` this crate carries.
//! * **Exactly-once into the stream**: every publish carries
//!   `Nats-Msg-Id = seq`, so JetStream's dedup window drops replays
//!   (crash between publish and nothing-else-to-commit is harmless).
//!   Downstream consumers get exactly-once the JetStream way: durable
//!   consumers + double-ack, with `seq` available for their own
//!   cursor.
//! * **Resume without local state**: the cursor IS the stream — on
//!   start the bridge reads the last message's `Entry.seq` and tails
//!   from `seq + 1`. No database, no cursor file.
//!
//! ```text
//! NATS_URL=nats://127.0.0.1:4222 \
//! TRON_FIREHOSE_URL=http://127.0.0.1:50051 \
//!     tron-firehose-nats
//! ```
//!
//! Optional: `NATS_STREAM` (default `TRON_FIREHOSE`),
//! `NATS_SUBJECT_PREFIX` (default `tron.firehose`).
//!
//! NOTE the JetStream dedup window (`duplicate_window`, default 2 min)
//! only bounds replay dedup across SHORT outages; the real idempotence
//! anchor is the resume-from-stream-tail cursor, which never re-sends
//! more than the in-flight entry.

use prost::Message as _;

pub mod fh {
    tonic::include_proto!("tronfirehose");
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let nats_url =
        std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let node_url = std::env::var("TRON_FIREHOSE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
    let stream_name =
        std::env::var("NATS_STREAM").unwrap_or_else(|_| "TRON_FIREHOSE".to_string());
    let prefix =
        std::env::var("NATS_SUBJECT_PREFIX").unwrap_or_else(|_| "tron.firehose".to_string());

    let client = async_nats::connect(&nats_url).await?;
    let js = async_nats::jetstream::new(client);
    let stream = js
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: stream_name.clone(),
            subjects: vec![format!("{prefix}.>")],
            ..Default::default()
        })
        .await?;

    // Resume point: the newest message already in the stream. Only a
    // genuinely-empty stream (NoMessageFound) starts at 0. A transport /
    // JetStream error must NOT be treated as empty: that re-tails from the
    // oldest retained entry and bulk-republishes the whole log, which
    // JetStream's short duplicate window cannot dedup — downstream would
    // double-count everything. Fail instead so the supervisor restarts and
    // retries the resume-point read.
    use async_nats::jetstream::stream::LastRawMessageErrorKind;
    let cursor: u64 = match stream
        .get_last_raw_message_by_subject(&format!("{prefix}.>"))
        .await
    {
        // The same rule applies to the payload: a last message that does
        // not decode as an Entry (foreign publisher on the subject,
        // corruption) must fail, not silently become cursor 0.
        Ok(msg) => match fh::Entry::decode(msg.payload.as_ref()) {
            Ok(entry) => entry.seq,
            Err(e) => {
                return Err(format!(
                    "the stream's last message on '{prefix}.>' does not decode as a \
                     tronfirehose.Entry: {e} — refusing to restart from seq 0; remove the \
                     foreign/corrupt message (or purge the stream) and restart the bridge"
                )
                .into())
            }
        },
        Err(e) if e.kind() == LastRawMessageErrorKind::NoMessageFound => 0, // empty stream
        Err(e) => return Err(e.into()),
    };
    tracing::info!(node = %node_url, nats = %nats_url, stream = %stream_name, cursor,
        "bridging firehose into JetStream");

    let mut grpc = fh::firehose_client::FirehoseClient::connect(node_url.clone()).await?;
    let mut tail = grpc
        .tail(fh::TailRequest { from_seq: cursor + 1 })
        .await?
        .into_inner();

    // An empty stream (cursor 0) legitimately begins at whatever the
    // node still retains — if `from_seq` predates retention the node
    // replays from the oldest retained entry, so the first seq may be
    // > 1. That is the documented start path. A non-empty stream means
    // we are RESUMING, and only then is a seq jump a true hole between
    // what is already bridged and what the node can still serve.
    let mut resuming = cursor > 0;
    let mut expected_seq = cursor + 1;
    while let Some(entry) = tail.message().await? {
        if entry.seq > expected_seq {
            if !resuming {
                // Fresh start past retention: adopt the oldest retained
                // entry as the baseline (`expected_seq` advances below).
                tracing::info!(
                    start_seq = entry.seq,
                    "starting fresh at the oldest retained firehose entry"
                );
            } else {
                // Older than the node's retention — the stream is
                // missing a range that cannot be recovered from the
                // gRPC tail.
                return Err(format!(
                    "firehose retention gap: expected seq {expected_seq}, got {} — \
                     purge the JetStream stream and re-bridge from scratch, or raise \
                     [index.firehose] retain_mb on the node",
                    entry.seq
                )
                .into());
            }
        }
        resuming = true;
        let subject = match &entry.event {
            Some(fh::entry::Event::Apply(_)) => format!("{prefix}.apply"),
            Some(fh::entry::Event::Unwind(_)) => format!("{prefix}.unwind"),
            None => format!("{prefix}.apply"),
        };
        let mut headers = async_nats::HeaderMap::new();
        // Server-side dedup id — replays of the same entry collapse.
        headers.insert("Nats-Msg-Id", entry.seq.to_string().as_str());
        // The ack ensures the message is durably in the stream before
        // the bridge advances — the bridge itself holds no state.
        js.publish_with_headers(subject, headers, entry.encode_to_vec().into())
            .await?
            .await?;
        if entry.seq % 1000 == 0 {
            tracing::info!(seq = entry.seq, "cursor");
        }
        expected_seq = entry.seq + 1;
    }
    tracing::info!("stream ended (node shutting down?)");
    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    if let Err(e) = run().await {
        tracing::error!(error = %e, "fatal");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    /// The crate-local proto copy must stay byte-identical to the
    /// node's authoritative file (same pin as tron-firehose-postgres).
    #[test]
    fn proto_copy_matches_the_nodes() {
        let local = include_str!("../proto/firehose.proto");
        let node = include_str!("../../tron-grpc/proto/firehose.proto");
        assert_eq!(
            local, node,
            "run: cp crates/tron-grpc/proto/firehose.proto crates/tron-firehose-nats/proto/"
        );
    }
}
