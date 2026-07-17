//! tron-firehose-postgres — the reference firehose consumer.
//!
//! Tails a tron-goblin-node's `tronfirehose.Firehose` gRPC stream into
//! a Postgres explorer schema, demonstrating the documented cursor
//! protocol (`working/FIREHOSE.md`):
//!
//! * **Exactly-once**: every entry is applied in one Postgres
//!   transaction together with the cursor update (`fh_cursor.seq`).
//!   A crash replays from the last committed cursor; nothing is
//!   double-applied, nothing is skipped.
//! * **Unwinds**: an `UNWIND(to_height)` entry deletes every derived
//!   row above `to_height` — reorgs and node crash-recoveries arrive
//!   through the same protocol, so this one handler covers both.
//! * **Isolation**: this process can crash, lag, or be turned off for
//!   a week; it only grows its own lag (bounded by the node's
//!   retention budget) and never affects the node.
//!
//! ```text
//! DATABASE_URL=postgres://user:pass@host/db \
//! TRON_FIREHOSE_URL=http://127.0.0.1:50051 \
//!     tron-firehose-postgres
//! ```

use tokio_postgres::NoTls;

pub mod fh {
    tonic::include_proto!("tronfirehose");
}

/// keccak256("Transfer(address,address,uint256)") — the TRC20
/// `Transfer` topic-0 (pinned constant; same rule as the node's
/// embedded index: exactly 3 topics + 32-byte data, which excludes the
/// 4-topic TRC721 Transfer).
const TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
    0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
    0xb3, 0xef,
];

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS fh_cursor (
    id   smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    seq  bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS fh_blocks (
    height          bigint PRIMARY KEY,
    block_id        bytea NOT NULL,
    parent_id       bytea,
    ts              bigint NOT NULL,
    witness         bytea,
    txinfo_missing  boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS fh_txs (
    height        bigint NOT NULL,
    tx_idx        integer NOT NULL,
    txid          bytea NOT NULL,
    contract_type integer NOT NULL,
    success       boolean NOT NULL,
    from_addr     bytea,
    to_addr       bytea,
    amount        bigint NOT NULL DEFAULT 0,
    asset         text,
    vm_contract   bytea,
    PRIMARY KEY (height, tx_idx)
);
CREATE INDEX IF NOT EXISTS fh_txs_txid ON fh_txs (txid);
CREATE INDEX IF NOT EXISTS fh_txs_from ON fh_txs (from_addr, height DESC);
CREATE INDEX IF NOT EXISTS fh_txs_to   ON fh_txs (to_addr, height DESC);
CREATE TABLE IF NOT EXISTS fh_trc20_transfers (
    height   bigint NOT NULL,
    tx_idx   integer NOT NULL,
    log_idx  integer NOT NULL,
    txid     bytea NOT NULL,
    token    bytea NOT NULL,
    from_addr bytea NOT NULL,
    to_addr   bytea NOT NULL,
    amount    numeric NOT NULL,
    PRIMARY KEY (height, tx_idx, log_idx)
);
CREATE INDEX IF NOT EXISTS fh_trc20_from ON fh_trc20_transfers (from_addr, height DESC);
CREATE INDEX IF NOT EXISTS fh_trc20_to   ON fh_trc20_transfers (to_addr, height DESC);
CREATE TABLE IF NOT EXISTS fh_internal_txs (
    height   bigint NOT NULL,
    tx_idx   integer NOT NULL,
    itx_idx  integer NOT NULL,
    txid     bytea NOT NULL,
    caller   bytea NOT NULL,
    transfer_to bytea NOT NULL,
    call_value  bigint NOT NULL,
    token_id    text,
    rejected    boolean NOT NULL,
    PRIMARY KEY (height, tx_idx, itx_idx)
);
"#;

/// 32-byte big-endian → decimal string (Postgres `numeric` accepts the
/// textual form; TRC20 amounts overflow bigint).
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

/// A decoded TRC20 transfer pulled from a tx's logs by the standard
/// rule. Pure — unit-tested.
struct Trc20Transfer {
    log_idx: i32,
    token: Vec<u8>,
    from: Vec<u8>,
    to: Vec<u8>,
    amount_decimal: String,
}

fn trc20_transfers(tx: &fh::Tx) -> Vec<Trc20Transfer> {
    let addr21 = |bytes: &[u8]| -> Vec<u8> {
        match bytes.len() {
            20 => {
                let mut a = vec![0x41];
                a.extend_from_slice(bytes);
                a
            }
            _ => bytes.to_vec(),
        }
    };
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
            let from20 = log.topics[1].get(12..)?;
            let to20 = log.topics[2].get(12..)?;
            Some(Trc20Transfer {
                log_idx: i as i32,
                token: addr21(&log.address),
                from: addr21(from20),
                to: addr21(to20),
                amount_decimal: be_bytes_to_decimal(&log.data),
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

/// The per-connection prepared statements (see `run`).
struct Statements {
    block: tokio_postgres::Statement,
    tx: tokio_postgres::Statement,
    trc20: tokio_postgres::Statement,
    itx: tokio_postgres::Statement,
    cursor: tokio_postgres::Statement,
}

/// Apply one firehose entry inside `txn`, cursor included — the
/// exactly-once unit.
async fn apply_entry(
    txn: &tokio_postgres::Transaction<'_>,
    stmts: &Statements,
    entry: &fh::Entry,
) -> Result<(), tokio_postgres::Error> {
    match &entry.event {
        Some(fh::entry::Event::Unwind(u)) => {
            for table in ["fh_internal_txs", "fh_trc20_transfers", "fh_txs", "fh_blocks"] {
                txn.execute(&format!("DELETE FROM {table} WHERE height > $1"), &[&u.to_height])
                    .await?;
            }
            tracing::info!(to_height = u.to_height, seq = entry.seq, "unwound");
        }
        Some(fh::entry::Event::Apply(a)) => {
            txn.execute(
                &stmts.block,
                &[
                    &a.height,
                    &a.block_id,
                    &a.parent_id,
                    &a.timestamp_ms,
                    &a.witness,
                    &a.txinfo_missing,
                ],
            )
            .await?;
            for (idx, tx) in a.txs.iter().enumerate() {
                let idx = idx as i32;
                txn.execute(
                    &stmts.tx,
                    &[
                        &a.height,
                        &idx,
                        &tx.txid,
                        &tx.contract_type,
                        &tx.success,
                        &tx.from,
                        &tx.to,
                        &tx.amount,
                        &tx.asset,
                        &tx.vm_contract,
                    ],
                )
                .await?;
                for t in trc20_transfers(tx) {
                    txn.execute(
                        &stmts.trc20,
                        &[
                            &a.height,
                            &idx,
                            &t.log_idx,
                            &tx.txid,
                            &t.token,
                            &t.from,
                            &t.to,
                            &t.amount_decimal,
                        ],
                    )
                    .await?;
                }
                for (ii, itx) in tx.internal_txs.iter().enumerate() {
                    let ii = ii as i32;
                    txn.execute(
                        &stmts.itx,
                        &[
                            &a.height,
                            &idx,
                            &ii,
                            &tx.txid,
                            &itx.caller,
                            &itx.transfer_to,
                            &itx.call_value,
                            &itx.token_id,
                            &itx.rejected,
                        ],
                    )
                    .await?;
                }
            }
        }
        None => {}
    }
    // The cursor commits with the data — the exactly-once contract.
    txn.execute(&stmts.cursor, &[&(entry.seq as i64)]).await?;
    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let pg_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required (postgres://user:pass@host/db)")?;
    let node_url = std::env::var("TRON_FIREHOSE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());

    let (mut pg, connection) = tokio_postgres::connect(&pg_url, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!(error = %e, "postgres connection lost");
            std::process::exit(1);
        }
    });
    pg.batch_execute(SCHEMA).await?;
    let cursor: i64 = pg
        .query_opt("SELECT seq FROM fh_cursor WHERE id = 1", &[])
        .await?
        .map(|row| row.get(0))
        .unwrap_or(0);
    tracing::info!(node = %node_url, cursor, "tailing firehose into postgres");

    let mut client =
        fh::firehose_client::FirehoseClient::connect(node_url.clone()).await?;
    let mut stream = client
        .tail(fh::TailRequest { from_seq: cursor as u64 + 1 })
        .await?
        .into_inner();

    // Prepared once per connection — every row insert reuses these
    // instead of paying a parse+plan round trip per statement (replay
    // depth makes that egregious: a heavy block is 1000+ inserts).
    let st_block = pg
        .prepare(
            "INSERT INTO fh_blocks (height, block_id, parent_id, ts, witness, txinfo_missing) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (height) DO UPDATE SET block_id = EXCLUDED.block_id, \
               parent_id = EXCLUDED.parent_id, ts = EXCLUDED.ts, \
               witness = EXCLUDED.witness, txinfo_missing = EXCLUDED.txinfo_missing",
        )
        .await?;
    let st_tx = pg
        .prepare(
            "INSERT INTO fh_txs (height, tx_idx, txid, contract_type, success, \
               from_addr, to_addr, amount, asset, vm_contract) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
             ON CONFLICT (height, tx_idx) DO NOTHING",
        )
        .await?;
    let st_trc20 = pg
        .prepare(
            "INSERT INTO fh_trc20_transfers \
               (height, tx_idx, log_idx, txid, token, from_addr, to_addr, amount) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric) \
             ON CONFLICT (height, tx_idx, log_idx) DO NOTHING",
        )
        .await?;
    let st_itx = pg
        .prepare(
            "INSERT INTO fh_internal_txs \
               (height, tx_idx, itx_idx, txid, caller, transfer_to, call_value, \
                token_id, rejected) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT (height, tx_idx, itx_idx) DO NOTHING",
        )
        .await?;
    let st_cursor = pg
        .prepare(
            "INSERT INTO fh_cursor (id, seq) VALUES (1, $1) \
             ON CONFLICT (id) DO UPDATE SET seq = EXCLUDED.seq",
        )
        .await?;
    let stmts = Statements {
        block: st_block,
        tx: st_tx,
        trc20: st_trc20,
        itx: st_itx,
        cursor: st_cursor,
    };

    // A fresh consumer (empty cursor) legitimately begins at whatever
    // the node still retains: when its requested `from_seq` predates
    // retention the node replays from the oldest retained entry, so the
    // first seq we see may be > 1. That is the documented start path,
    // not a gap. A non-empty cursor means we are RESUMING, and only
    // then is a seq jump a true retention hole between what we already
    // stored and what the node can still serve.
    let mut resuming = cursor > 0;
    let mut expected_seq = cursor as u64 + 1;
    // The block height the next APPLY should carry (`None` until the first
    // APPLY sets the baseline), used to flag a skipped-height hole the
    // firehose signals with contiguous seqs — see `height_continuity`.
    let mut expected_height: Option<i64> = None;
    while let Some(entry) = stream.message().await? {
        if entry.seq > expected_seq {
            if !resuming {
                // Fresh start past retention: adopt the oldest retained
                // entry as the baseline and consume forward from it
                // (`expected_seq` is advanced to `entry.seq + 1` below).
                tracing::info!(
                    start_seq = entry.seq,
                    "starting fresh at the oldest retained firehose entry"
                );
            } else {
                // Older than the node's retention — the derived tables
                // are missing a range and cannot be repaired from the
                // stream.
                return Err(format!(
                    "firehose retention gap: expected seq {expected_seq}, got {} — \
                     re-sync this database from scratch (TRUNCATE the fh_* tables) or raise \
                     [index.firehose] retain_mb on the node",
                    entry.seq
                )
                .into());
            }
        }
        let (hole, next_height) = height_continuity(expected_height, &entry);
        if let Some((from, to)) = hole {
            // Seqs stay contiguous, so the exactly-once cursor logic is
            // unaffected; the derived tables simply have no rows for these
            // heights because the node could not repair the store gap.
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
        let txn = pg.transaction().await?;
        apply_entry(&txn, &stmts, &entry).await?;
        txn.commit().await?;
        if entry.seq % 1000 == 0 {
            tracing::info!(seq = entry.seq, "cursor");
        }
        expected_seq = entry.seq + 1;
    }
    tracing::info!("stream ended (node shutting down?)");
    Ok(())
}

/// This crate is out-of-process by design and depends on no tron-* crate, so
/// the version string is built here rather than pulled from tron-types. It
/// still tracks the workspace version automatically.
const CODE_VERSION: &str = concat!("tron-goblin/", env!("CARGO_PKG_VERSION"));

const USAGE: &str = "\
tron-firehose-postgres — tails a tron-goblin-node firehose into Postgres.

Usage:
  tron-firehose-postgres          Run the consumer (configured by env).
  tron-firehose-postgres --help   Show this help.
  tron-firehose-postgres --version

Environment:
  DATABASE_URL         Required. postgres://user:pass@host/db
  TRON_FIREHOSE_URL    Node firehose gRPC endpoint.
                       Default http://127.0.0.1:50051
  RUST_LOG             Log filter. Default \"info\".

The consumer is resumable and exactly-once: it commits each entry with its
cursor in one transaction, and replays from the last committed cursor after
a crash. See docs/apis-indexing-firehose.md.
";

/// Handles `--help` / `--version` before any logging or config work.
/// Returns true when the process should exit without running.
fn handle_cli_args() -> bool {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                return true;
            }
            "-V" | "--version" | "version" => {
                println!("{CODE_VERSION}");
                return true;
            }
            other => {
                eprintln!("unknown argument: {other}\n");
                eprint!("{USAGE}");
                std::process::exit(2);
            }
        }
    }
    false
}

#[tokio::main]
async fn main() {
    if handle_cli_args() {
        return;
    }
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

    /// The crate-local proto copy must stay byte-identical to the
    /// node's authoritative file — a drifted copy would silently
    /// diverge the wire format between the server and this consumer.
    /// (Runs in-workspace only; standalone checkouts build from the
    /// local copy, which is the point of having it.)
    #[test]
    fn proto_copy_matches_the_nodes() {
        let local = include_str!("../proto/firehose.proto");
        let node = include_str!("../../tron-grpc/proto/firehose.proto");
        assert_eq!(local, node, "run: cp crates/tron-grpc/proto/firehose.proto crates/tron-firehose-postgres/proto/");
    }

    /// The deliberately-duplicated topic constant pinned against the
    /// well-known value (the same hex literal the node pins in
    /// tron-index and tron-rpc).
    #[test]
    fn transfer_topic_matches_the_known_constant() {
        assert_eq!(
            TRANSFER_TOPIC.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn decimal_conversion_matches_known_values() {
        assert_eq!(be_bytes_to_decimal(&[0u8; 32]), "0");
        let mut v = [0u8; 32];
        v[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        assert_eq!(be_bytes_to_decimal(&v), "1000000000");
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
        let tx = fh::Tx { logs: vec![good, trc721], ..Default::default() };
        let got = trc20_transfers(&tx);
        assert_eq!(got.len(), 1, "the 4-topic TRC721 Transfer is excluded");
        assert_eq!(got[0].amount_decimal, "42");
        assert_eq!(got[0].from[0], 0x41);
        assert_eq!(got[0].token[0], 0x41);
        assert_eq!(got[0].token.len(), 21);
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
