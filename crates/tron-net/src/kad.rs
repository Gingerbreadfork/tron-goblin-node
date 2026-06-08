//! Kademlia DHT peer-discovery service.
//!
//! Parity target: `org.tron.p2p.discover.protocol.kad.KadService` from
//! tronprotocol/libp2p. Owns a single UDP socket on the discovery port
//! (mainnet 18888 — same number as the TCP sync port, different protocol).
//! Maintains an in-memory routing table of live peers. Periodically runs
//! iterative `FindNode` lookups to refresh and expand the table. Exposes
//! the live set via [`KadHandle::known_peers`] so the TCP sync-driver
//! pool can dial peers it learned through DHT, not just the static seed
//! list.
//!
//! ## Why this exists
//!
//! Without DHT, a node permanently behaves like one that just finished
//! its TCP handshake on the 13 mainnet seeds and never went any further.
//! The seeds are the most-contended endpoints in the entire network —
//! every fresh node on the planet dials them first — so `TIME_BANNED`
//! and `TOO_MANY_PEERS` rejections dominate. The thousands of real
//! community peers are reachable only after a DHT bootstrap.
//!
//! ## Protocol shape
//!
//! Each UDP datagram is a single `[type_byte][protobuf payload]` packet
//! (see [`crate::discover`] for the four message types). The flow per
//! `(local, peer)`:
//!
//! 1. Outbound `KAD_PING` — peer replies `KAD_PONG`. Confirms liveness.
//! 2. Inbound `KAD_PING` — we reply `KAD_PONG`. Reciprocal liveness.
//! 3. Outbound `KAD_FIND_NODE(target_id)` — peer replies `KAD_NEIGHBORS`
//!    with up to [`BUCKET_SIZE`] endpoints "closest" to `target_id` in
//!    XOR distance. We ping each new endpoint.
//! 4. Inbound `KAD_FIND_NODE` — we reply with our own closest set from
//!    the routing table.
//!
//! The [`DISCOVER_CYCLE`] ticker triggers iterative lookups with [`ALPHA`]
//! parallel queries per round and up to [`MAX_STEPS`] rounds, matching
//! java-tron's `DiscoverTask.discover`.
//!
//! ## Distance metric
//!
//! [`distance`] mirrors `NodeEntry.distance` from java-tron exactly —
//! the unusual coarse 17-bin XOR metric (not the textbook 256-bin) that
//! TRON inherited from its libp2p fork. See the function for the bit
//! arithmetic.
//!
//! ## What's intentionally simplified vs java-tron
//!
//! * No `(DISCOVERED, ALIVE, ACTIVE, EVICTCANDIDATE)` per-node state
//!   machine. Java-tron uses it to drive its "ping the bucket LRU, evict
//!   if it doesn't pong" replacement. We use a simpler policy: when a
//!   bucket is full, drop the new node. The periodic `discover_loop`
//!   still refreshes stale entries by touching them on every inbound
//!   message.
//! * No bucket-trim threshold at 3000 nodes. Practical mainnet routing
//!   tables stabilize around 200-400 entries; the threshold is dead code
//!   in the upstream.
//! * IPv4 only. Endpoints with only an `address_ipv6` are skipped.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use prost::Message;
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::time::interval;
use tracing::{debug, info, warn};
use tron_proto::{Endpoint, FindNeighbours, Neighbours, PingMessage, PongMessage};

use crate::discover::{
    decode_packet, encode_packet, KAD_FIND_NODE, KAD_NEIGHBORS, KAD_PING, KAD_PONG,
    UDP_MAX_PACKET_BYTES,
};

/// Kademlia bucket capacity (`k` in the paper). Java-tron uses 16.
pub const BUCKET_SIZE: usize = 16;
/// Parallel-lookup factor (`α` in the paper). Java-tron uses 3.
pub const ALPHA: usize = 3;
/// Number of distance bins. Java-tron uses 17 — a coarser-than-textbook
/// metric inherited from their libp2p fork.
pub const BINS: usize = 17;
/// Max iterative-lookup rounds per `discover` cycle.
pub const MAX_STEPS: usize = 8;
/// How often the discover task picks a random target and runs a lookup.
/// Matches `KademliaOptions.DISCOVER_CYCLE = 7200` ms.
pub const DISCOVER_CYCLE: Duration = Duration::from_millis(7_200);
/// Inter-round sleep inside an iterative lookup.
pub const WAIT_TIME: Duration = Duration::from_millis(100);
/// Every Nth discover cycle, target our own id (to find peers close to
/// us). Otherwise target a random id (to scatter the table).
pub const SELF_LOOKUP_EVERY: u32 = 5;

/// XOR-distance bin per java-tron `NodeEntry.distance`. Returns a value
/// in `[0, BINS-1]` suitable as a bucket index.
///
/// Algorithm:
/// 1. Start at `BINS = 17`.
/// 2. For each byte of `XOR(owner_id, target_id)`:
///    * If zero: subtract 8 and continue.
///    * Else: subtract the number of leading zero bits in that byte and
///      stop.
/// 3. Return `max(d - 1, 0)`.
///
/// For random 64-byte node-ids the result is overwhelmingly `15-16`
/// (high bits of byte 0 nearly always differ), with the lower bins
/// populated only by IDs that happen to share prefixes.
pub(crate) fn distance(owner_id: &[u8], target_id: &[u8]) -> usize {
    let mut d: i32 = BINS as i32;
    let len = owner_id.len().min(target_id.len());
    for i in 0..len {
        let xor = owner_id[i] ^ target_id[i];
        if xor == 0 {
            d -= 8;
        } else {
            d -= xor.leading_zeros() as i32;
            break;
        }
    }
    (d - 1).max(0) as usize
}

/// A peer in the discovery network.
///
/// `id` is the 64-byte uncompressed-pubkey node-id. For a freshly-seen
/// seed it may be all-zeros until the first PONG arrives carrying the
/// peer's actual id.
#[derive(Clone, Debug)]
pub struct Node {
    pub id: Vec<u8>,
    pub addr: SocketAddr,
}

impl Node {
    /// Stable dedup key — `ip:port`. Java-tron uses `n.getHostKey()`
    /// which is the same shape.
    fn host_key(&self) -> String {
        self.addr.to_string()
    }
}

#[derive(Clone, Debug)]
struct NodeEntry {
    node: Node,
    /// When this entry was last touched (any inbound packet from the
    /// peer counts). LRU eviction sorts by this.
    modified: Instant,
}

#[derive(Default)]
struct KBucket {
    entries: Vec<NodeEntry>,
}

impl KBucket {
    /// Insert or refresh `entry`. Returns the bucket's LRU entry if the
    /// bucket is full and the candidate is new (signal to the caller
    /// that an eviction decision is needed); `None` if the entry was
    /// inserted or was already present (touched).
    fn add(&mut self, entry: NodeEntry) -> Option<NodeEntry> {
        let key = entry.node.host_key();
        for existing in self.entries.iter_mut() {
            if existing.node.host_key() == key {
                existing.modified = entry.modified;
                // Adopt the new id if the old slot was a placeholder.
                if existing.node.id.iter().all(|&b| b == 0) && !entry.node.id.is_empty() {
                    existing.node.id = entry.node.id;
                }
                return None;
            }
        }
        if self.entries.len() >= BUCKET_SIZE {
            return Some(self.lru().clone());
        }
        self.entries.push(entry);
        None
    }

    fn drop_by_key(&mut self, host_key: &str) {
        self.entries.retain(|e| e.node.host_key() != host_key);
    }

    fn touch(&mut self, host_key: &str) -> bool {
        for e in self.entries.iter_mut() {
            if e.node.host_key() == host_key {
                e.modified = Instant::now();
                return true;
            }
        }
        false
    }

    fn lru(&self) -> &NodeEntry {
        // Bucket is non-empty when this is called (only reached from `add`
        // after a length check).
        self.entries.iter().min_by_key(|e| e.modified).unwrap()
    }
}

/// Routing table — `BINS` buckets, each holding up to `BUCKET_SIZE`
/// peers. Indexed by [`distance`] from the owning node's id.
pub struct RoutingTable {
    home_id: Vec<u8>,
    buckets: Vec<KBucket>,
    by_host: HashMap<String, usize>,
}

impl RoutingTable {
    pub fn new(home_id: Vec<u8>) -> Self {
        let mut buckets = Vec::with_capacity(BINS);
        for _ in 0..BINS {
            buckets.push(KBucket::default());
        }
        Self {
            home_id,
            buckets,
            by_host: HashMap::new(),
        }
    }

    fn bucket_idx(&self, node_id: &[u8]) -> usize {
        distance(&self.home_id, node_id).min(BINS - 1)
    }

    /// Insert `node`. If the appropriate bucket is full, drop the
    /// candidate (the LRU's host_key is returned so the caller knows
    /// who *would* have been evicted under a true ping-replace policy).
    /// Returns `Some(host_key)` if the candidate was dropped due to a
    /// full bucket.
    pub fn add(&mut self, node: Node) -> Option<String> {
        let key = node.host_key();
        if key == self.home_host_key_placeholder() {
            return None;
        }
        if let Some(&idx) = self.by_host.get(&key) {
            // Already known — touch + maybe-update id.
            let entry = NodeEntry { node, modified: Instant::now() };
            self.buckets[idx].add(entry);
            return None;
        }
        let idx = self.bucket_idx(&node.id);
        let entry = NodeEntry { node: node.clone(), modified: Instant::now() };
        match self.buckets[idx].add(entry) {
            Some(_lru) => {
                // Bucket full — drop the candidate.
                Some(key)
            }
            None => {
                self.by_host.insert(key, idx);
                None
            }
        }
    }

    pub fn drop_node(&mut self, host_key: &str) {
        if let Some(idx) = self.by_host.remove(host_key) {
            self.buckets[idx].drop_by_key(host_key);
        }
    }

    pub fn touch(&mut self, host_key: &str) {
        if let Some(&idx) = self.by_host.get(host_key) {
            self.buckets[idx].touch(host_key);
        }
    }

    /// Return up to `n` nodes ordered by XOR distance to `target`.
    pub fn closest(&self, target: &[u8], n: usize) -> Vec<Node> {
        let mut all: Vec<&NodeEntry> = self.buckets.iter().flat_map(|b| b.entries.iter()).collect();
        all.sort_by_key(|e| distance(target, &e.node.id));
        all.into_iter().take(n).map(|e| e.node.clone()).collect()
    }

    pub fn all_nodes(&self) -> Vec<Node> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter().map(|e| e.node.clone()))
            .collect()
    }

    pub fn count(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    fn home_host_key_placeholder(&self) -> String {
        // We don't know our own SocketAddr inside the table, so this
        // returns a value that no real peer can match.
        String::from("0.0.0.0:0")
    }

    /// Iterate over entries older than `max_age` for refresh-pinging.
    pub fn stale_entries(&self, max_age: Duration) -> Vec<Node> {
        let now = Instant::now();
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .filter(|e| now.duration_since(e.modified) > max_age)
            .map(|e| e.node.clone())
            .collect()
    }
}

/// Long-running DHT service. Spawn [`KadService::run`] as a tokio task;
/// hand out [`KadService::handle`] clones to subsystems that want to
/// read the live peer set.
pub struct KadService {
    socket: Arc<UdpSocket>,
    home: Endpoint,
    network_id: i32,
    table: Arc<RwLock<RoutingTable>>,
    seeds: Vec<SocketAddr>,
}

/// Clone-friendly read handle. Cheap to clone (Arc-shared table).
#[derive(Clone)]
pub struct KadHandle {
    table: Arc<RwLock<RoutingTable>>,
}

impl KadHandle {
    /// Snapshot of every peer the DHT currently knows about (including
    /// seeds and any node discovered via `NEIGHBORS` responses).
    pub fn known_peers(&self) -> Vec<SocketAddr> {
        self.table
            .read()
            .expect("kad table poisoned")
            .all_nodes()
            .into_iter()
            .map(|n| n.addr)
            .collect()
    }

    /// Number of entries currently in the table.
    pub fn count(&self) -> usize {
        self.table.read().expect("kad table poisoned").count()
    }
}

impl KadService {
    /// Bind a UDP socket and prepare a routing table seeded with
    /// `home_id`. Does not yet send anything — call [`Self::run`] to
    /// start the recv + discover loops.
    pub async fn new(
        bind: SocketAddr,
        home_id: Vec<u8>,
        public_addr: SocketAddr,
        network_id: i32,
        seeds: Vec<SocketAddr>,
    ) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        let home = Endpoint {
            address: public_addr.ip().to_string().into_bytes(),
            port: public_addr.port() as i32,
            node_id: home_id.clone(),
            address_ipv6: vec![],
        };
        let table = Arc::new(RwLock::new(RoutingTable::new(home_id)));
        Ok(Self {
            socket,
            home,
            network_id,
            table,
            seeds,
        })
    }

    /// Get a clone-friendly handle for read-only access from other
    /// subsystems (e.g. the TCP sync-driver pool).
    pub fn handle(&self) -> KadHandle {
        KadHandle { table: self.table.clone() }
    }

    /// Run forever (until `shutdown` resolves). Spawns nothing — the
    /// caller is expected to `tokio::spawn` this. Drives:
    ///   * bootstrap pings to every seed,
    ///   * inbound packet dispatch (recv loop),
    ///   * periodic iterative lookups (discover loop).
    pub async fn run<F>(self, shutdown: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        // Seed the table + ping each seed to learn its real node-id.
        for seed in &self.seeds {
            let placeholder = Node { id: vec![0u8; 64], addr: *seed };
            let _ = self.table.write().expect("kad table poisoned").add(placeholder);
            self.send_ping(*seed).await;
        }
        // `unwrap_or` would EAGERLY evaluate `self.seeds[0]` even on the Ok path
        // and panic when seeds is empty (DNS/disk-only discovery, no bootstrap
        // seeds). Use a lazy, never-panicking sentinel — this is only the log's
        // bind-address display.
        let bind_disp = self
            .socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        info!(seeds = self.seeds.len(), bind = %bind_disp, "kad: bootstrap pings sent");

        let me = Arc::new(self);
        let recv_task = {
            let me = me.clone();
            tokio::spawn(async move { me.recv_loop().await })
        };
        let discover_task = {
            let me = me.clone();
            tokio::spawn(async move { me.discover_loop().await })
        };

        tokio::select! {
            _ = shutdown => {
                debug!("kad: shutdown observed");
            }
            r = recv_task => {
                warn!(?r, "kad: recv_loop exited");
            }
            r = discover_task => {
                warn!(?r, "kad: discover_loop exited");
            }
        }
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; UDP_MAX_PACKET_BYTES];
        loop {
            let (n, peer) = match self.socket.recv_from(&mut buf).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "kad: recv_from failed");
                    continue;
                }
            };
            let view = &buf[..n];
            let Some((ty, payload)) = decode_packet(view) else {
                continue;
            };
            // Copy payload because handle_packet may await + lock.
            let payload = payload.to_vec();
            self.handle_packet(ty, &payload, peer).await;
        }
    }

    async fn handle_packet(&self, ty: u8, payload: &[u8], from: SocketAddr) {
        match ty {
            KAD_PING => {
                let Ok(ping) = PingMessage::decode(payload) else {
                    debug!(from = %from, "kad: malformed PING");
                    return;
                };
                let from_id = ping.from.as_ref().map(|e| e.node_id.clone()).unwrap_or_default();
                self.touch_or_add(from, from_id);
                // Reply with PONG. `echo` carries the ping's version per
                // upstream convention.
                let pong = PongMessage {
                    from: Some(self.home.clone()),
                    echo: ping.version,
                    timestamp: now_ms(),
                };
                let bytes = encode_packet(KAD_PONG, &pong.encode_to_vec());
                let _ = self.socket.send_to(&bytes, from).await;
            }
            KAD_PONG => {
                let Ok(pong) = PongMessage::decode(payload) else {
                    return;
                };
                let from_id = pong.from.as_ref().map(|e| e.node_id.clone()).unwrap_or_default();
                self.touch_or_add(from, from_id);
            }
            KAD_FIND_NODE => {
                let Ok(find) = FindNeighbours::decode(payload) else {
                    return;
                };
                let from_id = find.from.as_ref().map(|e| e.node_id.clone()).unwrap_or_default();
                self.touch_or_add(from, from_id);
                let closest = self
                    .table
                    .read()
                    .expect("kad table poisoned")
                    .closest(&find.target_id, BUCKET_SIZE);
                let neighbours: Vec<Endpoint> = closest
                    .into_iter()
                    .map(|n| Endpoint {
                        address: n.addr.ip().to_string().into_bytes(),
                        port: n.addr.port() as i32,
                        node_id: n.id,
                        address_ipv6: vec![],
                    })
                    .collect();
                let resp = Neighbours {
                    from: Some(self.home.clone()),
                    neighbours,
                    timestamp: now_ms(),
                };
                let bytes = encode_packet(KAD_NEIGHBORS, &resp.encode_to_vec());
                let _ = self.socket.send_to(&bytes, from).await;
            }
            KAD_NEIGHBORS => {
                let Ok(resp) = Neighbours::decode(payload) else {
                    return;
                };
                let from_id = resp.from.as_ref().map(|e| e.node_id.clone()).unwrap_or_default();
                self.touch_or_add(from, from_id);
                // For each new endpoint: insert + ping to confirm liveness.
                let mut to_ping = Vec::new();
                {
                    let mut t = self.table.write().expect("kad table poisoned");
                    for ep in &resp.neighbours {
                        let Some(addr) = parse_endpoint(ep) else {
                            continue;
                        };
                        let key = addr.to_string();
                        if t.by_host.contains_key(&key) {
                            continue;
                        }
                        let node = Node { id: ep.node_id.clone(), addr };
                        if t.add(node).is_none() {
                            to_ping.push(addr);
                        }
                    }
                }
                for addr in to_ping {
                    self.send_ping(addr).await;
                }
            }
            _ => {
                // Unknown type — silently ignore (upstream behavior).
            }
        }
    }

    fn touch_or_add(&self, addr: SocketAddr, node_id: Vec<u8>) {
        let key = addr.to_string();
        let mut t = self.table.write().expect("kad table poisoned");
        if t.by_host.contains_key(&key) {
            t.touch(&key);
        } else {
            let node = Node { id: node_id, addr };
            let _ = t.add(node);
        }
    }

    async fn send_ping(&self, to: SocketAddr) {
        let ping = PingMessage {
            from: Some(self.home.clone()),
            to: Some(Endpoint {
                address: to.ip().to_string().into_bytes(),
                port: to.port() as i32,
                node_id: vec![],
                address_ipv6: vec![],
            }),
            version: self.network_id,
            timestamp: now_ms(),
        };
        let bytes = encode_packet(KAD_PING, &ping.encode_to_vec());
        let _ = self.socket.send_to(&bytes, to).await;
    }

    async fn send_find_node(&self, to: SocketAddr, target: &[u8]) {
        let find = FindNeighbours {
            from: Some(self.home.clone()),
            target_id: target.to_vec(),
            timestamp: now_ms(),
        };
        let bytes = encode_packet(KAD_FIND_NODE, &find.encode_to_vec());
        let _ = self.socket.send_to(&bytes, to).await;
    }

    async fn discover_loop(self: Arc<Self>) {
        // First tick fires immediately; skip it so we don't lookup before
        // any pongs have arrived. The seed pings sent in `run` will
        // populate the table within ~PING_TIMEOUT.
        let mut ticker = interval(DISCOVER_CYCLE);
        ticker.tick().await;
        let mut loop_num: u32 = 0;
        loop {
            ticker.tick().await;
            loop_num = loop_num.wrapping_add(1);
            let target = if loop_num % SELF_LOOKUP_EVERY == 0 {
                self.home.node_id.clone()
            } else {
                random_node_id()
            };
            self.iterative_lookup(&target).await;
            debug!(
                table_size = self.table.read().map(|t| t.count()).unwrap_or(0),
                "kad: discover cycle done"
            );
        }
    }

    async fn iterative_lookup(&self, target: &[u8]) {
        let mut tried: HashSet<SocketAddr> = HashSet::new();
        for _round in 0..MAX_STEPS {
            let candidates = self
                .table
                .read()
                .expect("kad table poisoned")
                .closest(target, ALPHA * 2);
            let mut sent_this_round = 0usize;
            for node in candidates {
                if tried.contains(&node.addr) {
                    continue;
                }
                self.send_find_node(node.addr, target).await;
                tried.insert(node.addr);
                sent_this_round += 1;
                if sent_this_round >= ALPHA {
                    break;
                }
            }
            if sent_this_round == 0 {
                break;
            }
            tokio::time::sleep(WAIT_TIME).await;
        }
    }
}

// === Helpers ===

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn random_node_id() -> Vec<u8> {
    let mut id = vec![0u8; 64];
    rand::thread_rng().fill(&mut id[..]);
    id
}

/// Parse a wire `Endpoint` into a `SocketAddr`. Returns `None` for the
/// upstream's malformed-record cases: zero / out-of-range port, address
/// not a valid ASCII-encoded IPv4 string. IPv6-only endpoints are
/// dropped (we don't dial v6 from the TCP side either).
fn parse_endpoint(ep: &Endpoint) -> Option<SocketAddr> {
    if ep.port <= 0 || ep.port > 65535 {
        return None;
    }
    let s = std::str::from_utf8(&ep.address).ok()?;
    let ip: std::net::IpAddr = s.parse().ok()?;
    Some(SocketAddr::new(ip, ep.port as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_identical_ids_clamps_to_zero() {
        let id = vec![0xAAu8; 64];
        // XOR all zero → d goes 17 - 8*64 = very negative → clamped to 0.
        assert_eq!(distance(&id, &id), 0);
    }

    #[test]
    fn distance_high_bit_diff_maxes_out() {
        let mut a = vec![0u8; 64];
        let mut b = vec![0u8; 64];
        a[0] = 0x80;
        b[0] = 0x00;
        // XOR first byte = 0x80 → leading_zeros = 0 → d = 17 → bin = 16.
        assert_eq!(distance(&a, &b), 16);
    }

    #[test]
    fn distance_low_bit_diff_gives_lower_bin_than_high_bit() {
        let mut a = vec![0u8; 64];
        let mut b = vec![0u8; 64];
        // Differ only in the LSB of the first byte.
        a[0] = 0x01;
        b[0] = 0x00;
        // leading_zeros(0x01) = 7 → d = 17 - 7 = 10 → bin = 9.
        assert_eq!(distance(&a, &b), 9);
    }

    #[test]
    fn distance_uses_first_differing_byte() {
        let mut a = vec![0u8; 64];
        let b = vec![0u8; 64];
        a[3] = 0x80; // first 3 bytes all zero on both sides
        // leading_zeros = 0 → d = 17 - 3*8 - 0 = -7 → clamped to 0.
        assert_eq!(distance(&a, &b), 0);
    }

    fn mk_node(ip_last: u8, port: u16, id_byte: u8) -> Node {
        Node {
            id: vec![id_byte; 64],
            addr: SocketAddr::from(([127, 0, 0, ip_last], port)),
        }
    }

    #[test]
    fn bucket_fills_to_capacity_then_signals_evict() {
        let mut b = KBucket::default();
        for i in 0..(BUCKET_SIZE as u8) {
            let entry = NodeEntry { node: mk_node(i, 10_000 + i as u16, 0xAA), modified: Instant::now() };
            assert!(b.add(entry).is_none(), "shouldn't evict before full at i={i}");
        }
        // 17th insert: bucket is full → returns Some(lru).
        let entry = NodeEntry { node: mk_node(99, 30_000, 0xAA), modified: Instant::now() };
        let evicted = b.add(entry);
        assert!(evicted.is_some(), "should signal eviction when full");
    }

    #[test]
    fn bucket_re_add_touches_does_not_evict() {
        let mut b = KBucket::default();
        let n = mk_node(1, 10_001, 0xAA);
        let early = Instant::now() - Duration::from_secs(60);
        b.add(NodeEntry { node: n.clone(), modified: early });
        // Same host_key again — should touch, not evict.
        let later = Instant::now();
        let res = b.add(NodeEntry { node: n.clone(), modified: later });
        assert!(res.is_none());
        assert_eq!(b.entries.len(), 1);
        assert!(b.entries[0].modified >= later);
    }

    #[test]
    fn bucket_re_add_with_real_id_replaces_placeholder() {
        let mut b = KBucket::default();
        // Insert a placeholder (all-zero id) — common for seeds before
        // pong arrives.
        let placeholder = Node { id: vec![0u8; 64], addr: SocketAddr::from(([127, 0, 0, 1], 10_001)) };
        b.add(NodeEntry { node: placeholder, modified: Instant::now() });
        // Pong arrives with the real id.
        let real = Node { id: vec![0xCC; 64], addr: SocketAddr::from(([127, 0, 0, 1], 10_001)) };
        let res = b.add(NodeEntry { node: real, modified: Instant::now() });
        assert!(res.is_none());
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.entries[0].node.id, vec![0xCC; 64]);
    }

    #[test]
    fn table_add_then_closest_returns_inserted() {
        let home = vec![0u8; 64];
        let mut t = RoutingTable::new(home);
        for i in 1..=5u8 {
            t.add(mk_node(i, 18_888, i));
        }
        let target = vec![3u8; 64];
        let closest = t.closest(&target, 3);
        assert_eq!(closest.len(), 3);
        // The closest to `target=3` is id=3 itself.
        assert_eq!(closest[0].id[0], 3);
    }

    #[test]
    fn table_dedups_by_host_key() {
        let mut t = RoutingTable::new(vec![0u8; 64]);
        let n = mk_node(1, 18_888, 1);
        assert!(t.add(n.clone()).is_none());
        // Re-add same addr — should be deduped.
        assert!(t.add(n.clone()).is_none());
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn parse_endpoint_rejects_bad_port_and_address() {
        // port = 0
        let ep = Endpoint { address: b"127.0.0.1".to_vec(), port: 0, node_id: vec![], address_ipv6: vec![] };
        assert!(parse_endpoint(&ep).is_none());
        // non-ascii-ip address
        let ep = Endpoint { address: vec![0xFF, 0xFE, 0xFD], port: 18_888, node_id: vec![], address_ipv6: vec![] };
        assert!(parse_endpoint(&ep).is_none());
        // valid
        let ep = Endpoint { address: b"10.0.0.1".to_vec(), port: 18_888, node_id: vec![], address_ipv6: vec![] };
        assert_eq!(parse_endpoint(&ep), Some(SocketAddr::from(([10, 0, 0, 1], 18_888))));
    }

    #[tokio::test]
    async fn kad_handles_inbound_ping_with_pong() {
        // Bind two sockets and have one act as the KadService while the
        // other plays a peer that pings it.
        let kad_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let kad = KadService::new(
            kad_addr,
            vec![0xAAu8; 64],
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            11_111,
            vec![],
        )
        .await
        .expect("bind kad");
        let bound = kad.socket.local_addr().unwrap();
        let me = Arc::new(kad);
        let recv = {
            let me = me.clone();
            tokio::spawn(async move { me.recv_loop().await })
        };

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ping = PingMessage {
            from: Some(Endpoint {
                address: b"127.0.0.1".to_vec(),
                port: peer.local_addr().unwrap().port() as i32,
                node_id: vec![0xCC; 64],
                address_ipv6: vec![],
            }),
            to: Some(Endpoint {
                address: b"127.0.0.1".to_vec(),
                port: bound.port() as i32,
                node_id: vec![],
                address_ipv6: vec![],
            }),
            version: 11_111,
            timestamp: now_ms(),
        };
        peer.send_to(&encode_packet(KAD_PING, &ping.encode_to_vec()), bound)
            .await
            .unwrap();

        let mut buf = vec![0u8; UDP_MAX_PACKET_BYTES];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("pong timeout")
            .unwrap();
        assert_eq!(from, bound);
        let (ty, payload) = decode_packet(&buf[..n]).unwrap();
        assert_eq!(ty, KAD_PONG);
        let pong = PongMessage::decode(payload).unwrap();
        assert_eq!(pong.echo, 11_111);

        recv.abort();
    }

    #[tokio::test]
    async fn kad_handles_find_node_with_neighbours() {
        let kad = KadService::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![0xAAu8; 64],
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            11_111,
            vec![],
        )
        .await
        .expect("bind kad");
        let bound = kad.socket.local_addr().unwrap();
        // Pre-seed table with a few nodes.
        for i in 1..=5u8 {
            kad.table.write().unwrap().add(mk_node(i, 10_000 + i as u16, i));
        }
        let me = Arc::new(kad);
        let recv = {
            let me = me.clone();
            tokio::spawn(async move { me.recv_loop().await })
        };

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let find = FindNeighbours {
            from: Some(Endpoint {
                address: b"127.0.0.1".to_vec(),
                port: peer.local_addr().unwrap().port() as i32,
                node_id: vec![0x33; 64],
                address_ipv6: vec![],
            }),
            target_id: vec![0x03; 64],
            timestamp: now_ms(),
        };
        peer.send_to(&encode_packet(KAD_FIND_NODE, &find.encode_to_vec()), bound)
            .await
            .unwrap();

        let mut buf = vec![0u8; UDP_MAX_PACKET_BYTES];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("neighbours timeout")
            .unwrap();
        let (ty, payload) = decode_packet(&buf[..n]).unwrap();
        assert_eq!(ty, KAD_NEIGHBORS);
        let resp = Neighbours::decode(payload).unwrap();
        assert!(!resp.neighbours.is_empty(), "should return some neighbours");
        // Closest to id=3 is id=3 itself.
        assert_eq!(resp.neighbours[0].node_id[0], 3);

        recv.abort();
    }
}
