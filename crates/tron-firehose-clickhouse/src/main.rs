//! tron-firehose-clickhouse — firehose → ClickHouse analytics sink.
//!
//! Tails a tron-goblin-node's `tronfirehose.Firehose` gRPC stream into
//! a ClickHouse schema shaped for analytics (per-block, per-tx, and
//! per-TRC20-transfer tables).
//!
//! ClickHouse has no multi-statement transactions, so the Postgres
//! consumer's commit-cursor-with-data trick doesn't translate. The
//! idempotence story here is the ClickHouse-native one:
//!
//! * **At-least-once + dedup**: tables are `ReplacingMergeTree` keyed
//!   by their natural primary key, so a crash between a data insert
//!   and the cursor insert replays a suffix whose rows collapse into
//!   the same key on merge (query with `FINAL` for read-time dedup).
//! * **Cursor**: `fh_cursor` accumulates `(seq)` rows; the resume
//!   point is `max(seq)`. It intentionally lags the data tables by at
//!   most one entry.
//! * **Unwinds**: an `UNWIND(to_height)` issues lightweight `DELETE`s
//!   (`DELETE FROM t WHERE height > N`) — eventually-consistent like
//!   all ClickHouse mutations, which is fine for analytics workloads;
//!   rows above the unwind height are re-inserted by the re-applied
//!   blocks that follow anyway.
//!
//! ```text
//! CLICKHOUSE_URL=http://127.0.0.1:8123 \
//! TRON_FIREHOSE_URL=http://127.0.0.1:50051 \
//!     tron-firehose-clickhouse
//! ```
//!
//! Optional: `CLICKHOUSE_DATABASE` (default `default`),
//! `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD`.

use clickhouse::Client;
use serde::Serialize;

pub mod fh {
    tonic::include_proto!("tronfirehose");
}

/// keccak256("Transfer(address,address,uint256)") — the TRC20
/// `Transfer` topic-0 (3 topics + 32-byte data; the 4-topic TRC721
/// shape is excluded, same rule as the node's embedded index).
const TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
    0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
    0xb3, 0xef,
];

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS fh_cursor (
        seq UInt64
    ) ENGINE = ReplacingMergeTree ORDER BY tuple()",
    "CREATE TABLE IF NOT EXISTS fh_blocks (
        height          Int64,
        block_id        String,
        parent_id       String,
        ts              Int64,
        witness         String,
        txinfo_missing  UInt8
    ) ENGINE = ReplacingMergeTree ORDER BY height",
    "CREATE TABLE IF NOT EXISTS fh_txs (
        height        Int64,
        tx_idx        Int32,
        txid          String,
        contract_type Int32,
        success       UInt8,
        from_addr     String,
        to_addr       String,
        amount        Int64,
        asset         String,
        vm_contract   String
    ) ENGINE = ReplacingMergeTree ORDER BY (height, tx_idx)",
    "CREATE TABLE IF NOT EXISTS fh_trc20_transfers (
        height    Int64,
        tx_idx    Int32,
        log_idx   Int32,
        txid      String,
        token     String,
        from_addr String,
        to_addr   String,
        amount    UInt256
    ) ENGINE = ReplacingMergeTree ORDER BY (height, tx_idx, log_idx)",
];

#[derive(Debug, clickhouse::Row, Serialize)]
struct CursorRow {
    seq: u64,
}

#[derive(Debug, clickhouse::Row, Serialize)]
struct BlockRow {
    height: i64,
    block_id: String,
    parent_id: String,
    ts: i64,
    witness: String,
    txinfo_missing: u8,
}

#[derive(Debug, clickhouse::Row, Serialize)]
struct TxRow {
    height: i64,
    tx_idx: i32,
    txid: String,
    contract_type: i32,
    success: u8,
    from_addr: String,
    to_addr: String,
    amount: i64,
    asset: String,
    vm_contract: String,
}

#[derive(Debug, clickhouse::Row, Serialize)]
struct Trc20Row {
    height: i64,
    tx_idx: i32,
    log_idx: i32,
    txid: String,
    token: String,
    from_addr: String,
    to_addr: String,
    amount: String, // decimal text — ClickHouse parses into UInt256
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 32-byte big-endian → decimal string (UInt256 textual form).
fn be_bytes_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = bytes.to_vec();
    let mut out = Vec::new();
    loop {
        let mut rem: u32 = 0;
        let mut all_zero = true;
        for d in digits.iter_mut() {
            let cur = (rem << 8) | *d as u32;
            *d = (cur / 10) as u8;
            rem = cur % 10;
            if *d != 0 {
                all_zero = false;
            }
        }
        out.push(b'0' + rem as u8);
        if all_zero {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).expect("ascii digits")
}

fn addr_hex(bytes: &[u8]) -> String {
    match bytes.len() {
        20 => {
            let mut a = vec![0x41];
            a.extend_from_slice(bytes);
            hex(&a)
        }
        _ => hex(bytes),
    }
}

fn trc20_rows(height: i64, tx_idx: i32, tx: &fh::Tx) -> Vec<Trc20Row> {
    tx.logs
        .iter()
        .enumerate()
        .filter_map(|(i, log)| {
            if log.topics.len() != 3
                || log.topics[0].as_slice() != TRANSFER_TOPIC
                || log.data.len() != 32
            {
                return None;
            }
            Some(Trc20Row {
                height,
                tx_idx,
                log_idx: i as i32,
                txid: hex(&tx.txid),
                token: addr_hex(&log.address),
                from_addr: addr_hex(log.topics[1].get(12..)?),
                to_addr: addr_hex(log.topics[2].get(12..)?),
                amount: be_bytes_to_decimal(&log.data),
            })
        })
        .collect()
}

/// Detect an unrepairable-gap block-height hole across firehose entries.
///
/// The firehose keeps seqs strictly contiguous, but signals a store gap it
/// could not repair by *skipping* the missing height(s): it emits
/// `APPLY(h-1)` then `APPLY(h+1)` with no seq gap, so the hole shows up only
/// as an APPLY whose height overshoots the expected next height (see
/// `working/FIREHOSE.md`). Given `expected` (the height the next APPLY should
/// carry, `None` before the first APPLY) and an entry, this returns the
/// skipped-height range `(from, to)` when the entry overshoots, plus the
/// expected-next height to carry forward. `UNWIND` re-anchors the expected
/// height at `to_height + 1`; a non-block entry leaves it unchanged.
fn height_continuity(
    expected: Option<i64>,
    entry: &fh::Entry,
) -> (Option<(i64, i64)>, Option<i64>) {
    match &entry.event {
        Some(fh::entry::Event::Apply(a)) => {
            let hole = match expected {
                Some(eh) if a.height > eh => Some((eh, a.height - 1)),
                _ => None,
            };
            (hole, Some(a.height + 1))
        }
        Some(fh::entry::Event::Unwind(u)) => (None, Some(u.to_height + 1)),
        None => (None, expected),
    }
}

async fn apply_entry(ch: &Client, entry: &fh::Entry) -> Result<(), clickhouse::error::Error> {
    match &entry.event {
        Some(fh::entry::Event::Unwind(u)) => {
            for table in ["fh_trc20_transfers", "fh_txs", "fh_blocks"] {
                ch.query(&format!("DELETE FROM {table} WHERE height > ?"))
                    .bind(u.to_height)
                    .execute()
                    .await?;
            }
            tracing::info!(to_height = u.to_height, seq = entry.seq, "unwound");
        }
        Some(fh::entry::Event::Apply(a)) => {
            let mut blocks = ch.insert("fh_blocks")?;
            blocks
                .write(&BlockRow {
                    height: a.height,
                    block_id: hex(&a.block_id),
                    parent_id: hex(&a.parent_id),
                    ts: a.timestamp_ms,
                    witness: hex(&a.witness),
                    txinfo_missing: a.txinfo_missing as u8,
                })
                .await?;
            blocks.end().await?;

            let mut txs = ch.insert("fh_txs")?;
            let mut transfers: Vec<Trc20Row> = Vec::new();
            for (idx, tx) in a.txs.iter().enumerate() {
                let idx = idx as i32;
                txs.write(&TxRow {
                    height: a.height,
                    tx_idx: idx,
                    txid: hex(&tx.txid),
                    contract_type: tx.contract_type,
                    success: tx.success as u8,
                    from_addr: hex(&tx.from),
                    to_addr: hex(&tx.to),
                    amount: tx.amount,
                    asset: tx.asset.clone(),
                    vm_contract: hex(&tx.vm_contract),
                })
                .await?;
                transfers.extend(trc20_rows(a.height, idx, tx));
            }
            txs.end().await?;

            if !transfers.is_empty() {
                let mut ins = ch.insert("fh_trc20_transfers")?;
                for row in &transfers {
                    ins.write(row).await?;
                }
                ins.end().await?;
            }
        }
        None => {}
    }
    // The cursor lands AFTER the data — a crash in between replays one
    // entry whose rows dedup on the ReplacingMergeTree keys.
    let mut cur = ch.insert("fh_cursor")?;
    cur.write(&CursorRow { seq: entry.seq }).await?;
    cur.end().await?;
    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let ch_url = std::env::var("CLICKHOUSE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8123".to_string());
    let node_url = std::env::var("TRON_FIREHOSE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
    let mut ch = Client::default()
        .with_url(&ch_url)
        .with_database(
            std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "default".to_string()),
        );
    if let Ok(user) = std::env::var("CLICKHOUSE_USER") {
        ch = ch.with_user(user);
    }
    if let Ok(pass) = std::env::var("CLICKHOUSE_PASSWORD") {
        ch = ch.with_password(pass);
    }

    for ddl in SCHEMA {
        ch.query(ddl).execute().await?;
    }
    // An empty cursor table legitimately returns 0 (ClickHouse max() over no
    // rows of a non-nullable UInt is 0). A query/transport error must fail
    // instead of silently becoming 0, which would re-tail from the oldest
    // retained entry and bulk-republish the whole log; let the supervisor
    // restart and retry the resume-point read.
    let cursor: u64 = ch
        .query("SELECT max(seq) FROM fh_cursor")
        .fetch_one::<u64>()
        .await?;
    tracing::info!(node = %node_url, clickhouse = %ch_url, cursor,
        "tailing firehose into clickhouse");

    let mut grpc = fh::firehose_client::FirehoseClient::connect(node_url.clone()).await?;
    let mut tail = grpc
        .tail(fh::TailRequest { from_seq: cursor + 1 })
        .await?
        .into_inner();

    // A fresh sink (cursor 0) legitimately begins at whatever the node
    // still retains — if `from_seq` predates retention the node replays
    // from the oldest retained entry, so the first seq may be > 1. That
    // is the documented start path. A non-empty cursor means we are
    // RESUMING, and only then is a seq jump a true retention hole
    // between what is already stored and what the node can still serve.
    let mut resuming = cursor > 0;
    let mut expected_seq = cursor + 1;
    // The block height the next APPLY should carry (`None` until the first
    // APPLY sets the baseline), used to flag a skipped-height hole the
    // firehose signals with contiguous seqs — see `height_continuity`.
    let mut expected_height: Option<i64> = None;
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
                return Err(format!(
                    "firehose retention gap: expected seq {expected_seq}, got {} — \
                     TRUNCATE the fh_* tables and re-sync, or raise [index.firehose] retain_mb \
                     on the node",
                    entry.seq
                )
                .into());
            }
        }
        let (hole, next_height) = height_continuity(expected_height, &entry);
        if let Some((from, to)) = hole {
            // Seqs stay contiguous, so the cursor/resume logic is unaffected;
            // the derived tables simply have no rows for these heights because
            // the node could not repair the store gap.
            tracing::warn!(
                from_height = from,
                to_height = to,
                seq = entry.seq,
                "firehose block-height hole: heights {from}..={to} are absent from the derived \
                 tables (the node could not repair a store gap); seqs remain contiguous"
            );
        }
        expected_height = next_height;
        resuming = true;
        apply_entry(&ch, &entry).await?;
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
    use super::*;

    /// Same proto pin as the other reference consumers.
    #[test]
    fn proto_copy_matches_the_nodes() {
        let local = include_str!("../proto/firehose.proto");
        let node = include_str!("../../tron-grpc/proto/firehose.proto");
        assert_eq!(
            local, node,
            "run: cp crates/tron-grpc/proto/firehose.proto crates/tron-firehose-clickhouse/proto/"
        );
    }

    #[test]
    fn trc20_rule_filters_and_decodes() {
        let mk_topic = |b: u8| {
            let mut t = vec![0u8; 12];
            t.extend_from_slice(&[b; 20]);
            t
        };
        let mut amount = vec![0u8; 32];
        amount[31] = 42;
        let good = fh::Log {
            address: vec![0xee; 20],
            topics: vec![TRANSFER_TOPIC.to_vec(), mk_topic(1), mk_topic(2)],
            data: amount,
        };
        let trc721 = fh::Log {
            address: vec![0xee; 20],
            topics: vec![TRANSFER_TOPIC.to_vec(), mk_topic(1), mk_topic(2), vec![0u8; 32]],
            data: vec![],
        };
        let tx = fh::Tx { txid: vec![0xab; 32], logs: vec![good, trc721], ..Default::default() };
        let got = trc20_rows(7, 0, &tx);
        assert_eq!(got.len(), 1, "the 4-topic TRC721 Transfer is excluded");
        assert_eq!(got[0].amount, "42");
        assert!(got[0].from_addr.starts_with("41"));
        assert_eq!(got[0].token.len(), 42);
    }

    #[test]
    fn decimal_conversion_matches_known_values() {
        assert_eq!(be_bytes_to_decimal(&[0u8; 32]), "0");
        assert_eq!(
            be_bytes_to_decimal(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    fn apply(height: i64, seq: u64) -> fh::Entry {
        fh::Entry {
            seq,
            event: Some(fh::entry::Event::Apply(fh::BlockApplied {
                height,
                ..Default::default()
            })),
        }
    }

    fn unwind(to_height: i64, seq: u64) -> fh::Entry {
        fh::Entry {
            seq,
            event: Some(fh::entry::Event::Unwind(fh::Unwind { to_height })),
        }
    }

    #[test]
    fn height_continuity_flags_skipped_heights_but_not_contiguous_ones() {
        // First APPLY (no baseline yet): never a hole; baseline becomes h+1.
        assert_eq!(height_continuity(None, &apply(100, 1)), (None, Some(101)));
        // Contiguous next height: no hole.
        assert_eq!(height_continuity(Some(101), &apply(101, 2)), (None, Some(102)));
        // Skipped height (APPLY(103) where 102 was expected): the hole is 102.
        assert_eq!(
            height_continuity(Some(102), &apply(103, 3)),
            (Some((102, 102)), Some(104))
        );
        // Wider hole: expected 200, got 205 → heights 200..=204 missing.
        assert_eq!(
            height_continuity(Some(200), &apply(205, 4)),
            (Some((200, 204)), Some(206))
        );
        // UNWIND re-anchors the expected height and is never itself a hole.
        assert_eq!(height_continuity(Some(300), &unwind(250, 5)), (None, Some(251)));
        // A re-apply below head (h < expected) is not flagged as a forward hole.
        assert_eq!(height_continuity(Some(251), &apply(251, 6)), (None, Some(252)));
    }
}
