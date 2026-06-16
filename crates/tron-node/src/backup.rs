//! Witness HA — java-tron's `BackupManager` UDP keepalive election.
//!
//! A witness key is typically provisioned on two or more machines for
//! failover; only ONE may produce blocks at a time (a double-producing
//! key forks itself). java-tron coordinates with a tiny UDP protocol
//! on `node.backup.port` (default 10001):
//!
//! * Every `keep_alive_interval` (default 3000 ms, first send after
//!   1 s) a node that is NOT a SLAVER broadcasts
//!   `KeepAliveMessage { flag: status == MASTER, priority }` to every
//!   configured member. SLAVERs stay silent.
//! * Receiving a keepalive from a configured member refreshes the
//!   liveness clock and runs the election:
//!     - `INIT`  + (peer is master OR peer priority higher) → `SLAVER`
//!     - `MASTER` + peer claims master: higher peer priority → `SLAVER`;
//!       equal priority → lexicographically LOWER local IP yields
//!       (java `localIp.compareTo(peerIp) < 0` → SLAVER).
//! * Liveness timeout (6 × interval, 18 s): a starved `SLAVER` falls
//!   back to `INIT` (re-arming the clock); a starved `INIT` promotes
//!   itself to `MASTER`. A solo node therefore becomes MASTER ~18 s
//!   after boot — same as java.
//!
//! Wire format: one UDP datagram `[0x05][protobuf BackupMessage]`
//! (java `UdpMessageTypeEnum.BACKUP_KEEP_ALIVE`), where
//! `BackupMessage { bool flag = 1; int32 priority = 2; }`. The proto
//! is hand-coded below — two varint fields don't warrant codegen.
//!
//! The SR runtime polls [`BackupHandle::is_master`] before every
//! production attempt (java `BlockHandleImpl.getState()` returning
//! `BACKUP_IS_NOT_MASTER`).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::config::NodeBackupConfig;

/// java `UdpMessageTypeEnum.BACKUP_KEEP_ALIVE`.
const BACKUP_KEEP_ALIVE: u8 = 0x05;
/// Timeout = 6 × keepalive interval (java `keepAliveTimeout`).
const TIMEOUT_INTERVALS: u64 = 6;

const INIT: u8 = 0;
const SLAVER: u8 = 1;
const MASTER: u8 = 2;

/// Shared election-state handle. Cheap to clone; the SR runtime holds
/// one and gates production on [`is_master`](Self::is_master).
#[derive(Clone)]
pub struct BackupHandle {
    status: Arc<AtomicU8>,
}

impl BackupHandle {
    pub fn is_master(&self) -> bool {
        self.status.load(Ordering::Relaxed) == MASTER
    }

    /// Human-readable status for logs.
    pub fn status_name(&self) -> &'static str {
        match self.status.load(Ordering::Relaxed) {
            SLAVER => "SLAVER",
            MASTER => "MASTER",
            _ => "INIT",
        }
    }
}

/// Encode `[type][BackupMessage]` — proto3 skips default values, like
/// java's prost-equivalent builder output.
fn encode_keep_alive(flag: bool, priority: i32) -> Vec<u8> {
    let mut out = vec![BACKUP_KEEP_ALIVE];
    if flag {
        out.extend_from_slice(&[0x08, 0x01]); // field 1, varint, true
    }
    if priority != 0 {
        out.push(0x10); // field 2, varint
        let mut v = priority as u64;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }
    out
}

/// Tolerant decode of the datagram payload (after the type byte).
fn decode_keep_alive(mut buf: &[u8]) -> Option<(bool, i32)> {
    let mut flag = false;
    let mut priority: i64 = 0;
    while !buf.is_empty() {
        let tag = buf[0];
        buf = &buf[1..];
        let mut varint: i64 = 0;
        let mut shift = 0;
        loop {
            let (b, rest) = buf.split_first()?;
            buf = rest;
            varint |= ((b & 0x7f) as i64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
        match tag >> 3 {
            1 => flag = varint != 0,
            2 => priority = varint,
            _ => {}
        }
    }
    Some((flag, priority as i32))
}

/// Spawnable election loop. Returns the status handle immediately; the
/// future runs until `shutdown` resolves.
pub fn start(
    cfg: NodeBackupConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> (BackupHandle, impl std::future::Future<Output = ()> + Send) {
    let status = Arc::new(AtomicU8::new(INIT));
    let handle = BackupHandle {
        status: status.clone(),
    };
    let fut = run(cfg, status, shutdown);
    (handle, fut)
}

async fn run(
    cfg: NodeBackupConfig,
    status: Arc<AtomicU8>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let port = cfg.port;
    let interval_ms = cfg.keep_alive_interval.max(500);
    let timeout_ms = interval_ms * TIMEOUT_INTERVALS;
    let priority = cfg.priority;

    // Resolve members once (java also refreshes DNS in the background;
    // operators overwhelmingly configure raw IPs).
    let mut members: Vec<(String, SocketAddr)> = Vec::new();
    for m in &cfg.members {
        let hostport = if m.contains(':') {
            m.clone()
        } else {
            format!("{m}:{port}")
        };
        match tokio::net::lookup_host(hostport.clone()).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    members.push((addr.ip().to_string(), addr));
                }
            }
            Err(e) => warn!(member = %m, error = %e, "backup: member resolve failed"),
        }
    }
    if members.is_empty() {
        warn!("backup: no resolvable members; election degenerates to solo (MASTER after timeout)");
    }

    let socket = match UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(port, error = %e, "backup: UDP bind failed — production stays gated OFF");
            return;
        }
    };

    // Local IP for the equal-priority tiebreak. Detect via a connected
    // (no-traffic) UDP probe toward the first member.
    let local_ip = detect_local_ip(members.first().map(|(_, a)| *a))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    info!(
        port,
        priority,
        %local_ip,
        members = members.len(),
        "backup: keepalive election started (INIT)"
    );

    let now_ms = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    };
    let last_keep_alive = AtomicI64::new(now_ms());

    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_millis(1000),
        Duration::from_millis(interval_ms),
    );
    let mut buf = [0u8; 256];
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("backup: shutting down");
                return;
            }
            _ = ticker.tick() => {
                let st = status.load(Ordering::Relaxed);
                // Liveness check (java's scheduled task, same order).
                if st != MASTER && now_ms() - last_keep_alive.load(Ordering::Relaxed) > timeout_ms as i64 {
                    if st == SLAVER {
                        status.store(INIT, Ordering::Relaxed);
                        last_keep_alive.store(now_ms(), Ordering::Relaxed);
                        info!("backup: keepalive starved — SLAVER → INIT");
                    } else {
                        status.store(MASTER, Ordering::Relaxed);
                        info!("👑 backup: election won — INIT → MASTER (block production enabled)");
                    }
                }
                let st = status.load(Ordering::Relaxed);
                if st == SLAVER {
                    continue; // SLAVERs stay silent (java parity)
                }
                let dgram = encode_keep_alive(st == MASTER, priority);
                for (_, addr) in &members {
                    let _ = socket.send_to(&dgram, addr).await;
                }
            }
            recv = socket.recv_from(&mut buf) => {
                let Ok((n, sender)) = recv else { continue };
                if n < 1 || buf[0] != BACKUP_KEEP_ALIVE {
                    continue;
                }
                let sender_ip = sender.ip().to_string();
                if !members.iter().any(|(ip, _)| *ip == sender_ip) {
                    warn!(%sender_ip, "backup: keepalive from non-member ignored");
                    continue;
                }
                let Some((peer_flag, peer_priority)) = decode_keep_alive(&buf[1..n]) else {
                    continue;
                };
                last_keep_alive.store(now_ms(), Ordering::Relaxed);

                let st = status.load(Ordering::Relaxed);
                if st == INIT && (peer_flag || peer_priority > priority) {
                    status.store(SLAVER, Ordering::Relaxed);
                    info!(%sender_ip, peer_priority, "backup: INIT → SLAVER");
                    continue;
                }
                if st == MASTER && peer_flag {
                    if peer_priority > priority
                        || (peer_priority == priority && local_ip.as_str() < sender_ip.as_str())
                    {
                        status.store(SLAVER, Ordering::Relaxed);
                        warn!(
                            %sender_ip,
                            peer_priority,
                            "backup: yielding mastership — MASTER → SLAVER (production gated OFF)"
                        );
                    }
                }
            }
        }
    }
}

fn detect_local_ip(probe: Option<SocketAddr>) -> Option<String> {
    let probe = probe?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(probe).ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_alive_round_trips() {
        for (flag, prio) in [(false, 0), (true, 0), (false, 8), (true, 300)] {
            let enc = encode_keep_alive(flag, prio);
            assert_eq!(enc[0], BACKUP_KEEP_ALIVE);
            let (f, p) = decode_keep_alive(&enc[1..]).unwrap();
            assert_eq!((f, p), (flag, prio));
        }
    }

    #[tokio::test]
    async fn solo_node_promotes_to_master_after_timeout() {
        let cfg = NodeBackupConfig {
            priority: 8,
            port: 0, // any free port
            keep_alive_interval: 500,
            members: vec![],
        };
        let (handle, fut) = start(cfg, std::future::pending());
        tokio::spawn(fut);
        assert!(!handle.is_master(), "starts INIT");
        // 6 × 500ms timeout + slack.
        tokio::time::sleep(Duration::from_millis(4200)).await;
        assert!(handle.is_master(), "solo node self-promotes");
    }
}
