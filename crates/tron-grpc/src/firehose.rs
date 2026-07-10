//! The firehose `Tail` service — a resumable server-stream over the
//! durable firehose log.
//!
//! The stream is **replay-then-follow**: everything from the
//! consumer's cursor (`from_seq`) up to the current head streams
//! immediately (read off disk in bounded chunks on a blocking thread),
//! then the task parks on the writer's watch channel and forwards each
//! newly appended entry. A slow or dead consumer only backs up its own
//! bounded channel — never the apply path, never another consumer
//! (absolute sink isolation; each tail is an independent reader with
//! its own cursor).

use prost::Message as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tron_index::FirehoseTailHandle;

use crate::firehose_proto::firehose_server::Firehose;
use crate::firehose_proto::{Entry, TailRequest};

/// Entries per blocking read — bounds memory per tailer while
/// replaying deep history.
const READ_CHUNK: usize = 256;
/// Per-consumer in-flight buffer; backpressure beyond this.
const CHANNEL_DEPTH: usize = 64;

pub struct FirehoseService {
    handle: FirehoseTailHandle,
}

impl FirehoseService {
    pub fn new(handle: FirehoseTailHandle) -> Self {
        Self { handle }
    }
}

#[tonic::async_trait]
impl Firehose for FirehoseService {
    type TailStream = ReceiverStream<Result<Entry, Status>>;

    async fn tail(
        &self,
        request: Request<TailRequest>,
    ) -> Result<Response<Self::TailStream>, Status> {
        let from_seq = request.into_inner().from_seq.max(1);
        let mut handle = self.handle.clone();
        let (tx, rx) = mpsc::channel::<Result<Entry, Status>>(CHANNEL_DEPTH);

        tokio::spawn(async move {
            let mut next = from_seq;
            // Reject a cursor ahead of the durable log head. `durable + 1` is
            // allowed — a caught-up consumer legitimately waits for the next
            // entry — but anything beyond means the log was reset/recreated
            // (seqs restart lower) or the cursor is stale. Without this the
            // stream parks in `wait_past` forever: it stays open, delivers
            // nothing, and when seqs eventually catch up they name unrelated
            // blocks.
            let durable0 = handle.durable_seq();
            if from_seq > durable0 + 1 {
                let _ = tx
                    .send(Err(Status::out_of_range(format!(
                        "from_seq {from_seq} is ahead of the durable firehose head \
                         {durable0} — the log was reset or the cursor is stale; resume \
                         at {} or earlier",
                        durable0 + 1
                    ))))
                    .await;
                return;
            }
            // Offset-resumable read position: a live tail seeks to the
            // new frames instead of rescanning (and re-CRC-ing) the
            // active segment from its start on every block.
            let mut pos: Option<tron_index::ReadPos> = None;
            loop {
                // Visibility is bounded by the DURABLE mark, never the
                // appended head: an un-fsynced tail can be truncated by
                // a power loss and its seqs reassigned — a consumer
                // must never persist entries that can still vanish.
                let durable = handle.durable_seq();
                if next > durable {
                    // Caught up — park on the writer's durability
                    // wake-up. A closed channel means node shutdown.
                    if !handle.wait_past(next.saturating_sub(1)).await {
                        return;
                    }
                    continue;
                }
                let reader = handle.reader();
                let read_at = next;
                let read_pos = pos;
                let read = match tokio::task::spawn_blocking(move || {
                    reader.read_chunk(read_at, durable, READ_CHUNK, read_pos)
                })
                .await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(Status::internal(format!("firehose read: {e}")))).await;
                        return;
                    }
                    Err(join) => {
                        let _ = tx
                            .send(Err(Status::internal(format!("firehose read task: {join}"))))
                            .await;
                        return;
                    }
                };
                let (chunk, new_pos) = read;
                pos = new_pos;
                if chunk.is_empty() {
                    if !handle.wait_past(next.saturating_sub(1)).await {
                        return;
                    }
                    continue;
                }
                for (seq, payload) in chunk {
                    let entry = match Entry::decode(payload.as_slice()) {
                        Ok(e) => e,
                        Err(e) => {
                            let _ = tx
                                .send(Err(Status::internal(format!(
                                    "firehose entry {seq} undecodable: {e}"
                                ))))
                                .await;
                            return;
                        }
                    };
                    if tx.send(Ok(entry)).await.is_err() {
                        return; // consumer hung up
                    }
                    next = seq + 1;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
