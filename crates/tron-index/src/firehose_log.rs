//! The durable firehose log — append-only segments for external sinks
//! (P3).
//!
//! Unlike the embedded index (which re-reads committed stores) an
//! **external** consumer cannot re-derive from the node's stores, so
//! the log is a first-class durable artifact with its **own fsync**
//! and a documented cursor protocol. This module is the byte-level
//! half: framing, segments, rotation, retention, torn-tail recovery,
//! and the tail-wakeup handle. Payloads are opaque here — the node
//! writes prost-encoded `tronfirehose.Entry` messages (see
//! `working/FIREHOSE.md` for the documented format).
//!
//! ## On-disk format (version 1)
//!
//! ```text
//! <dir>/firehose-{first_seq:020}.fhlog
//!   [8]  magic "TRNFH001"                      (format version in the magic)
//!   then repeated frames:
//!   [4]  payload length, little-endian u32
//!   [4]  CRC32 of the payload, little-endian u32
//!   [n]  payload bytes
//! ```
//!
//! Sequence numbers are consecutive across segments: a segment's first
//! entry has the seq in its filename; entry *i* of a segment has seq
//! `first_seq + i`. A torn tail (crash mid-append) is detected by
//! length/CRC and truncated away on the next writer open — the cursor
//! protocol (consumers resume by last-applied seq) makes that loss
//! safe, and the node's writer re-derives the lost entries from its
//! stores.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::db::IndexError;

const MAGIC: &[u8; 8] = b"TRNFH001";
const FRAME_HEADER: usize = 8;
/// Rotate to a new segment once the current one crosses this size.
const SEGMENT_TARGET_BYTES: u64 = 128 * 1024 * 1024;
/// Largest payload a single frame may carry. The reader treats any framed
/// length above this as a torn/corrupt frame and stops, so the writer must
/// refuse to append one — an unreadable frame would hide every later entry
/// in the segment (and the next open would truncate it and them away).
const MAX_FRAME_PAYLOAD: usize = 64 * 1024 * 1024;

fn crc32(payload: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(payload);
    crc.sum()
}

fn segment_path(dir: &Path, first_seq: u64) -> PathBuf {
    dir.join(format!("firehose-{first_seq:020}.fhlog"))
}

/// Best-effort fsync of a directory so a freshly-created or removed segment's
/// directory entry is durable. A failure only widens the crash window (open()
/// tolerates a torn/missing newest segment), so it is not fatal.
fn fsync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// `(first_seq, path)` for every segment in `dir`, ascending.
fn list_segments(dir: &Path) -> Result<Vec<(u64, PathBuf)>, IndexError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(IndexError::Corrupt(format!("firehose dir: {e}"))),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(seq) = name
            .strip_prefix("firehose-")
            .and_then(|s| s.strip_suffix(".fhlog"))
            .and_then(|s| s.parse::<u64>().ok())
        {
            out.push((seq, entry.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// Scan a segment from `start` (a `(seq, byte_offset)` pair — pass
/// `(first_seq, 8)` for a full scan), calling `visit(seq, payload)`
/// per valid frame. Returns the `(next_seq, byte_offset)` just past
/// the last valid frame visited — the truncation point for a torn
/// tail, and the resume position for offset-based tailing. Stops at
/// the first invalid frame or when `visit` returns false.
fn scan_segment_from(
    path: &Path,
    start: (u64, u64),
    mut visit: impl FnMut(u64, Vec<u8>) -> bool,
) -> Result<(u64, u64), IndexError> {
    let mut f = File::open(path).map_err(|e| IndexError::Io(format!("open {path:?}: {e}")))?;
    let mut magic = [0u8; 8];
    if f.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return Err(IndexError::Corrupt(format!(
            "firehose segment {path:?} has a bad magic header"
        )));
    }
    let (mut seq, mut good_end) = start;
    if good_end > 8 {
        f.seek(SeekFrom::Start(good_end))
            .map_err(|e| IndexError::Io(format!("seek {path:?}: {e}")))?;
    }
    let mut header = [0u8; FRAME_HEADER];
    loop {
        match f.read_exact(&mut header) {
            Ok(()) => {}
            Err(_) => break, // clean EOF or torn header
        }
        let len = u32::from_le_bytes(header[..4].try_into().expect("4 bytes")) as usize;
        let want_crc = u32::from_le_bytes(header[4..].try_into().expect("4 bytes"));
        if len > MAX_FRAME_PAYLOAD {
            break; // absurd length ⇒ torn/corrupt frame
        }
        let mut payload = vec![0u8; len];
        if f.read_exact(&mut payload).is_err() {
            break; // torn payload
        }
        if crc32(&payload) != want_crc {
            break; // bit-rot / torn frame
        }
        good_end += (FRAME_HEADER + len) as u64;
        let keep_going = visit(seq, payload);
        seq += 1;
        if !keep_going {
            break;
        }
    }
    Ok((seq, good_end))
}

/// Resume position for [`FirehoseLogReader::read_chunk`] — the byte
/// offset just past the last frame a previous call consumed, so a
/// live tail seeks instead of rescanning the segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPos {
    next_seq: u64,
    segment_first: u64,
    offset: u64,
}

/// Read side: stateless over the directory; every call re-lists
/// segments so it sees rotation and pruning.
#[derive(Clone)]
pub struct FirehoseLogReader {
    dir: PathBuf,
}

impl FirehoseLogReader {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Oldest seq still retained, if any entries exist.
    pub fn oldest_seq(&self) -> Result<Option<u64>, IndexError> {
        Ok(list_segments(&self.dir)?.first().map(|(s, _)| *s))
    }

    /// Collect up to `limit` entries with `seq >= from_seq`, in order.
    /// A `from_seq` older than retention starts at the oldest retained
    /// entry (the consumer sees the jump in the returned seqs).
    pub fn read_from(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, IndexError> {
        let segments = list_segments(&self.dir)?;
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        // Start at the last segment whose first_seq <= from_seq (or the
        // first segment at all, when from_seq pre-dates retention).
        let start_idx = match segments.iter().rposition(|(s, _)| *s <= from_seq) {
            Some(i) => i,
            None => 0,
        };
        for (first_seq, path) in segments.into_iter().skip(start_idx) {
            if out.len() >= limit {
                break;
            }
            scan_segment_from(&path, (first_seq, 8), |seq, payload| {
                if seq >= from_seq {
                    out.push((seq, payload));
                }
                out.len() < limit
            })?;
        }
        Ok(out)
    }

    /// Offset-resumable chunked read for tail loops. Returns entries
    /// with `from_seq <= seq <= up_to` (at most `limit`) plus the
    /// position to pass back on the next call — which makes a live
    /// tail O(new data) instead of re-scanning (and re-CRC-ing) the
    /// active segment from its start on every wake-up. A stale `pos`
    /// (rotated/pruned segment, mismatched seq) silently falls back to
    /// the locate-by-seq path.
    pub fn read_chunk(
        &self,
        from_seq: u64,
        up_to: u64,
        limit: usize,
        pos: Option<ReadPos>,
    ) -> Result<(Vec<(u64, Vec<u8>)>, Option<ReadPos>), IndexError> {
        if from_seq > up_to || limit == 0 {
            return Ok((Vec::new(), pos));
        }
        let segments = list_segments(&self.dir)?;
        let start_idx = match segments.iter().rposition(|(s, _)| *s <= from_seq) {
            Some(i) => i,
            None => 0,
        };
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut next_pos: Option<ReadPos> = None;
        for (seg_idx, (first_seq, path)) in segments.iter().enumerate().skip(start_idx) {
            if out.len() >= limit {
                break;
            }
            // Resume mid-segment when the caller's position matches
            // this segment and cursor exactly; otherwise scan from the
            // segment head (skipping pre-cursor entries).
            let start = match pos {
                Some(p)
                    if p.segment_first == *first_seq
                        && p.next_seq == from_seq
                        && p.next_seq >= *first_seq =>
                {
                    (p.next_seq, p.offset)
                }
                _ => (*first_seq, 8),
            };
            let scan = scan_segment_from(path, start, |seq, payload| {
                if seq > up_to {
                    return false;
                }
                if seq >= from_seq {
                    out.push((seq, payload));
                }
                out.len() < limit
            });
            let (next_seq, end_offset) = match scan {
                Ok(t) => t,
                // Segment pruned/unreadable under us — retry without
                // the stale position.
                Err(_) if pos.is_some() => return self.read_chunk(from_seq, up_to, limit, None),
                Err(e) => return Err(e),
            };
            let is_last_listed = seg_idx == segments.len() - 1;
            if is_last_listed {
                next_pos = Some(ReadPos {
                    next_seq,
                    segment_first: *first_seq,
                    offset: end_offset,
                });
            }
        }
        Ok((out, next_pos))
    }

    /// The newest entry `(seq, payload)`, if any.
    pub fn head(&self) -> Result<Option<(u64, Vec<u8>)>, IndexError> {
        let segments = list_segments(&self.dir)?;
        for (first_seq, path) in segments.into_iter().rev() {
            let mut last: Option<(u64, Vec<u8>)> = None;
            scan_segment_from(&path, (first_seq, 8), |seq, payload| {
                last = Some((seq, payload));
                true
            })?;
            if last.is_some() {
                return Ok(last);
            }
            // Empty/torn-to-empty segment: look at the previous one.
        }
        Ok(None)
    }
}

/// Wake-up + read handle for tailers (the gRPC stream). Cheap to
/// clone. The watch channel carries the latest **durable** (fsynced)
/// seq — NOT the latest appended one. Tailers must never serve an
/// entry past it: an un-fsynced tail can be torn away by a power loss
/// and its seqs reassigned to different blocks on restart, which would
/// leave a consumer holding phantom entries that no UNWIND ever
/// retracts. Bounding visibility at the durable mark closes that hole.
#[derive(Clone)]
pub struct FirehoseTailHandle {
    dir: PathBuf,
    durable_rx: tokio::sync::watch::Receiver<u64>,
}

impl FirehoseTailHandle {
    pub fn reader(&self) -> FirehoseLogReader {
        FirehoseLogReader::new(self.dir.clone())
    }

    /// Latest durable seq — the tail-visibility bound.
    pub fn durable_seq(&self) -> u64 {
        *self.durable_rx.borrow()
    }

    /// Wait until the durable mark advances past `seen`. Returns
    /// `false` when the writer is gone (node shutting down).
    pub async fn wait_past(&mut self, seen: u64) -> bool {
        loop {
            if *self.durable_rx.borrow() > seen {
                return true;
            }
            if self.durable_rx.changed().await.is_err() {
                return false;
            }
        }
    }
}

/// Append side. Single-writer by design (the node's apply hook is
/// serialized); callers wrap it in their own lock.
pub struct FirehoseLogWriter {
    dir: PathBuf,
    file: File,
    seg_first_seq: u64,
    seg_bytes: u64,
    next_seq: u64,
    retain_bytes: u64,
    /// Latest fsynced seq — what tailers are allowed to see.
    durable_tx: tokio::sync::watch::Sender<u64>,
}

impl FirehoseLogWriter {
    /// Open (or create) the log in `dir`, validating the newest
    /// segment and truncating any torn tail.
    pub fn open(dir: impl Into<PathBuf>, retain_bytes: u64) -> Result<Self, IndexError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| IndexError::Corrupt(format!("create {dir:?}: {e}")))?;
        let segments = list_segments(&dir)?;
        let (seg_first_seq, path, existing) = match segments.last() {
            Some((first, path)) => (*first, path.clone(), true),
            None => (1, segment_path(&dir, 1), false),
        };
        let (next_seq, good_end) = if existing {
            // A crash during `rotate()` — after the segment file is created
            // but before its 8-byte magic is fully written and fsynced — can
            // leave the newest segment 0..8 bytes long. That is a torn header,
            // not corruption of committed data: the previous segment holds the
            // durable tail. Reinitialize it empty rather than refusing to open
            // (a hard `bad magic header` error here would brick node startup).
            let torn_header = std::fs::metadata(&path).map(|m| m.len() < 8).unwrap_or(false);
            if torn_header {
                tracing::warn!(
                    segment = ?path,
                    "firehose: newest segment has a torn magic header (crash mid-rotate); \
                     reinitializing it empty"
                );
                let mut f = File::create(&path)
                    .map_err(|e| IndexError::Corrupt(format!("recreate {path:?}: {e}")))?;
                f.write_all(MAGIC)
                    .map_err(|e| IndexError::Corrupt(format!("write magic: {e}")))?;
                f.sync_all().ok();
                (seg_first_seq, 8)
            } else {
                scan_segment_from(&path, (seg_first_seq, 8), |_, _| true)?
            }
        } else {
            let mut f = File::create(&path)
                .map_err(|e| IndexError::Corrupt(format!("create {path:?}: {e}")))?;
            f.write_all(MAGIC)
                .map_err(|e| IndexError::Corrupt(format!("write magic: {e}")))?;
            f.sync_all().ok();
            (1, 8)
        };
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| IndexError::Corrupt(format!("open {path:?}: {e}")))?;
        let actual_len = file
            .metadata()
            .map_err(|e| IndexError::Corrupt(format!("stat {path:?}: {e}")))?
            .len();
        if actual_len > good_end {
            tracing::warn!(
                segment = ?path,
                torn_bytes = actual_len - good_end,
                "firehose: truncating torn tail (crash mid-append; entries re-derive from stores)"
            );
            file.set_len(good_end)
                .map_err(|e| IndexError::Corrupt(format!("truncate {path:?}: {e}")))?;
        }
        file.seek(SeekFrom::End(0))
            .map_err(|e| IndexError::Io(format!("seek {path:?}: {e}")))?;
        // Everything surviving the open-time scan is on disk and
        // post-truncation — durable as far as tailers are concerned.
        let (durable_tx, _) = tokio::sync::watch::channel(next_seq.saturating_sub(1));
        Ok(Self {
            dir,
            file,
            seg_first_seq,
            seg_bytes: good_end,
            next_seq,
            retain_bytes,
            durable_tx,
        })
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn reader(&self) -> FirehoseLogReader {
        FirehoseLogReader::new(self.dir.clone())
    }

    pub fn tail_handle(&self) -> FirehoseTailHandle {
        FirehoseTailHandle { dir: self.dir.clone(), durable_rx: self.durable_tx.subscribe() }
    }

    /// Append one payload; returns its seq. Durable only after
    /// [`sync`](Self::sync) (the caller owns the fsync cadence).
    pub fn append(&mut self, payload: &[u8]) -> Result<u64, IndexError> {
        // Refuse a payload the reader could never read back: a frame past
        // the length cap is treated as torn, so appending one would hide
        // every later entry in the segment and be truncated away on the
        // next open. Reject it up front rather than persist a poison frame.
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(IndexError::Io(format!(
                "firehose append: payload {} bytes exceeds the {}-byte frame limit",
                payload.len(),
                MAX_FRAME_PAYLOAD
            )));
        }
        if self.seg_bytes >= SEGMENT_TARGET_BYTES {
            self.rotate()?;
        }
        let mut frame = Vec::with_capacity(FRAME_HEADER + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc32(payload).to_le_bytes());
        frame.extend_from_slice(payload);
        self.file
            .write_all(&frame)
            .map_err(|e| IndexError::Io(format!("firehose append: {e}")))?;
        self.seg_bytes += frame.len() as u64;
        let seq = self.next_seq;
        self.next_seq += 1;
        // Deliberately NO tailer wake-up here — visibility follows
        // durability (see `FirehoseTailHandle`).
        Ok(seq)
    }

    /// fsync the current segment — the log's own durability barrier —
    /// and only then publish the new durable mark to tailers.
    pub fn sync(&mut self) -> Result<(), IndexError> {
        self.file
            .sync_data()
            .map_err(|e| IndexError::Io(format!("firehose fsync: {e}")))?;
        // send_replace, not send: `send` refuses to store the value
        // while no receiver exists, so a tail handle subscribed later
        // would observe a stale durable mark and never serve the
        // already-durable history.
        self.durable_tx.send_replace(self.next_seq.saturating_sub(1));
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), IndexError> {
        // Propagate the old segment's final fsync. Swallowing it would let a
        // later sync() — which fsyncs only the NEW segment — publish a durable
        // mark covering the old segment's un-fsynced tail, so a power loss
        // could vanish entries tailers were already told were durable.
        self.file
            .sync_data()
            .map_err(|e| IndexError::Io(format!("firehose rotate fsync: {e}")))?;
        let path = segment_path(&self.dir, self.next_seq);
        let mut f =
            File::create(&path).map_err(|e| IndexError::Corrupt(format!("create {path:?}: {e}")))?;
        f.write_all(MAGIC)
            .map_err(|e| IndexError::Corrupt(format!("write magic: {e}")))?;
        // fsync the header before we start appending frames so a crash can't
        // leave a torn magic (open() tolerates one, but shrink the window),
        // then fsync the directory so the new segment's entry is durable too.
        f.sync_all().ok();
        fsync_dir(&self.dir);
        self.file = f;
        self.seg_first_seq = self.next_seq;
        self.seg_bytes = 8;
        self.prune()?;
        Ok(())
    }

    /// Drop the oldest segments while total size exceeds the retention
    /// budget (never the active segment). Consumers further behind
    /// than retention resume at the oldest retained seq.
    fn prune(&self) -> Result<(), IndexError> {
        let segments = list_segments(&self.dir)?;
        let mut sizes: Vec<(u64, PathBuf, u64)> = Vec::with_capacity(segments.len());
        let mut total = 0u64;
        for (seq, path) in segments {
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            total += len;
            sizes.push((seq, path, len));
        }
        for (seq, path, len) in sizes {
            if total <= self.retain_bytes || seq == self.seg_first_seq {
                break;
            }
            tracing::info!(segment = ?path, "firehose: pruning segment past retention");
            std::fs::remove_file(&path)
                .map_err(|e| IndexError::Corrupt(format!("prune {path:?}: {e}")))?;
            total = total.saturating_sub(len);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tron-fhlog-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn append_read_roundtrip_with_resume() {
        let dir = tmp_dir("roundtrip");
        let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
        for i in 1..=10u64 {
            let seq = w.append(format!("payload-{i}").as_bytes()).unwrap();
            assert_eq!(seq, i);
        }
        w.sync().unwrap();

        let r = FirehoseLogReader::new(&dir);
        let all = r.read_from(1, 100).unwrap();
        assert_eq!(all.len(), 10);
        assert_eq!(all[0], (1, b"payload-1".to_vec()));
        assert_eq!(all[9].0, 10);
        // Resume mid-stream.
        let tail = r.read_from(7, 100).unwrap();
        assert_eq!(tail.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![7, 8, 9, 10]);
        // Bounded read.
        assert_eq!(r.read_from(1, 3).unwrap().len(), 3);
        assert_eq!(r.head().unwrap().unwrap().0, 10);
        assert_eq!(r.oldest_seq().unwrap(), Some(1));
    }

    #[test]
    fn reopen_resumes_sequence_numbers() {
        let dir = tmp_dir("reopen");
        {
            let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
            w.append(b"a").unwrap();
            w.append(b"b").unwrap();
            w.sync().unwrap();
        }
        let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
        assert_eq!(w.next_seq(), 3);
        assert_eq!(w.append(b"c").unwrap(), 3);
        let r = w.reader();
        assert_eq!(r.read_from(1, 10).unwrap().len(), 3);
    }

    #[test]
    fn torn_tail_is_truncated_on_open() {
        let dir = tmp_dir("torn");
        {
            let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
            w.append(b"good-1").unwrap();
            w.append(b"good-2").unwrap();
            w.sync().unwrap();
        }
        // Simulate a crash mid-append: garbage half-frame at the tail.
        let seg = list_segments(&dir).unwrap()[0].1.clone();
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0x10, 0x00, 0x00, 0x00, 0xde, 0xad]).unwrap(); // len=16, truncated
        drop(f);

        // Reader stops at the torn frame.
        let r = FirehoseLogReader::new(&dir);
        assert_eq!(r.read_from(1, 10).unwrap().len(), 2);

        // Writer truncates and continues with the right seq.
        let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
        assert_eq!(w.next_seq(), 3);
        w.append(b"good-3").unwrap();
        w.sync().unwrap();
        let all = FirehoseLogReader::new(&dir).read_from(1, 10).unwrap();
        assert_eq!(
            all,
            vec![(1, b"good-1".to_vec()), (2, b"good-2".to_vec()), (3, b"good-3".to_vec())]
        );
    }

    #[test]
    fn torn_segment_header_recovers_on_open() {
        let dir = tmp_dir("tornhdr");
        {
            let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
            w.append(b"one").unwrap();
            w.append(b"two").unwrap();
            w.sync().unwrap();
        }
        // Simulate a crash DURING rotate(): the next segment file was created
        // and a partial (< 8 byte) magic written but not fsynced. next_seq
        // after two synced appends is 3, so the torn segment is named for 3.
        let torn = segment_path(&dir, 3);
        std::fs::write(&torn, [b'T', b'R', b'N']).unwrap(); // 3 bytes < 8

        // Open must NOT error — a hard "bad magic header" here would brick node
        // startup. It reinitializes the torn newest segment and continues.
        let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
        assert_eq!(w.next_seq(), 3, "resumes at the torn segment's first seq");
        assert_eq!(w.append(b"three").unwrap(), 3);
        w.sync().unwrap();

        // The prior segment's data survives; the new entry lands at seq 3.
        let all = FirehoseLogReader::new(&dir).read_from(1, 10).unwrap();
        assert_eq!(
            all,
            vec![(1, b"one".to_vec()), (2, b"two".to_vec()), (3, b"three".to_vec())]
        );
    }

    #[test]
    fn corrupted_crc_stops_the_scan() {
        let dir = tmp_dir("crc");
        {
            let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
            w.append(b"one").unwrap();
            w.append(b"two").unwrap();
            w.sync().unwrap();
        }
        // Flip a payload byte of the second frame.
        let seg = list_segments(&dir).unwrap()[0].1.clone();
        let mut bytes = std::fs::read(&seg).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        std::fs::write(&seg, bytes).unwrap();
        assert_eq!(FirehoseLogReader::new(&dir).read_from(1, 10).unwrap().len(), 1);
    }

    #[test]
    fn tail_handle_signals_only_durable_appends() {
        let dir = tmp_dir("tail");
        let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
        let handle = w.tail_handle();
        assert_eq!(handle.durable_seq(), 0);
        // Visibility follows durability: an un-fsynced append must NOT
        // become visible to tailers (a torn tail could erase it and
        // reassign its seq).
        w.append(b"x").unwrap();
        assert_eq!(handle.durable_seq(), 0, "append alone is not visible");
        w.sync().unwrap();
        assert_eq!(handle.durable_seq(), 1, "sync publishes the durable mark");

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let mut h = handle.clone();
            assert!(h.wait_past(0).await, "already past 0");
        });
    }

    #[test]
    fn read_chunk_resumes_by_offset_and_respects_bound() {
        let dir = tmp_dir("chunk");
        let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
        for i in 1..=6u64 {
            w.append(format!("p{i}").as_bytes()).unwrap();
        }
        w.sync().unwrap();
        let r = FirehoseLogReader::new(&dir);

        // First chunk, bounded at seq 4.
        let (chunk, pos) = r.read_chunk(1, 4, 3, None).unwrap();
        assert_eq!(chunk.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![1, 2, 3]);
        let pos = pos.expect("position for resume");

        // Resume by offset — and the bound holds.
        let (chunk, pos) = r.read_chunk(4, 4, 10, Some(pos)).unwrap();
        assert_eq!(chunk.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![4]);

        // The bound advances; new entries appended later are picked up
        // from the same position.
        w.append(b"p7").unwrap();
        w.sync().unwrap();
        let (chunk, _) = r.read_chunk(5, 7, 10, pos).unwrap();
        assert_eq!(chunk.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![5, 6, 7]);

        // A garbage position falls back to locate-by-seq.
        let bogus = ReadPos { next_seq: 3, segment_first: 999, offset: 4 };
        let (chunk, _) = r.read_chunk(3, 7, 10, Some(bogus)).unwrap();
        assert_eq!(chunk.first().map(|(s, _)| *s), Some(3));
    }

    #[test]
    fn append_rejects_oversize_payload() {
        let dir = tmp_dir("oversize");
        let mut w = FirehoseLogWriter::open(&dir, u64::MAX).unwrap();
        // One byte past the reader's frame cap: appending it would write an
        // unreadable frame that hides everything after it, so append must
        // refuse it — and must not consume a seq or leave a torn tail.
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        assert!(w.append(&big).is_err());
        // The writer stays usable and the next entry lands at seq 1.
        assert_eq!(w.append(b"ok").unwrap(), 1);
        w.sync().unwrap();
        assert_eq!(
            FirehoseLogReader::new(&dir).read_from(1, 10).unwrap(),
            vec![(1, b"ok".to_vec())]
        );
    }
}
