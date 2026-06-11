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
//! ## Security boundary (plaintext UDP, no authentication)
//!
//! Discovery runs over **unauthenticated, unencrypted UDP** — there is no
//! TLS and no per-packet signature, exactly like java-tron's libp2p
//! discovery. A datagram's protobuf `from` field is *attacker-controlled*
//! and the source IP can be spoofed. The service therefore treats every
//! claim as a hint to be proven, not a fact:
//!
//! * **Bonding before table membership (N-9 / N-32).** A node enters the
//!   routing table *only* after it answers a `KAD_PING` we sent with a
//!   `KAD_PONG` from that same socket address. `KAD_NEIGHBORS` referrals
//!   and unsolicited `KAD_PING`s never insert directly — they trigger a
//!   verification ping, and the peer is promoted only when its `KAD_PONG`
//!   proves it is reachable at the advertised address. This defeats
//!   third-party node-id / address injection (eclipse).
//! * **Anti-amplification (N-18).** The large `KAD_NEIGHBORS` reply is
//!   sent **only to bonded peers**. A spoofed source can never bond, so
//!   the UDP reflection/amplification vector is closed; the only replies a
//!   non-bonded source can elicit (`KAD_PONG` to its `KAD_PING`) are the
//!   same size as the request.
//! * **Per-IP rate limit + temporary bans (N-18 / N-22).** Inbound packets
//!   are rate-limited per source IP; repeated malformed packets earn a
//!   temporary ban.
//! * **Subnet diversity (N-10).** A single public `/24` (v4) or `/48` (v6)
//!   may occupy only [`MAX_PER_GROUP`] table slots.
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
//! * IPv4 and IPv6 endpoints are both accepted (N-21). The TCP dial side
//!   fails an unroutable v6 address fast via its connect timeout, so a v6
//!   endpoint on a v4-only host degrades like any other dead peer rather
//!   than being silently discarded.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
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

/// Max routing-table entries that may share one public `/24` (v4) or
/// `/48` (v6). Bounds how much of the table a single subnet operator can
/// occupy (eclipse defense, N-10). Loopback / private / link-local
/// addresses are exempt (they are not eclipse-relevant and keep
/// loopback-based tests working).
pub const MAX_PER_GROUP: usize = 4;

/// How long a `KAD_PING` we sent stays "pending" while we wait for the
/// peer's `KAD_PONG` to promote it into the table. After this the
/// expectation is dropped so a never-answering address can't pin a
/// pending slot forever.
const PENDING_EXPIRY: Duration = Duration::from_secs(30);

/// Inbound-packet rate-limit window per source IP (N-18).
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Max inbound discovery packets accepted from one source IP per
/// [`RATE_WINDOW`]. Discovery is low-rate (a handful of packets per peer
/// per bootstrap / lookup round), so this is generous for honest peers
/// while still capping a flood.
const MAX_PACKETS_PER_WINDOW: u32 = 64;
/// Malformed-packet strikes from one IP within [`STRIKE_WINDOW`] that
/// trip a temporary ban (N-22).
const MAX_STRIKES: u32 = 8;
/// Rolling window over which malformed-packet strikes accumulate.
const STRIKE_WINDOW: Duration = Duration::from_secs(60);
/// How long a misbehaving IP stays banned (N-22).
const BAN_DURATION: Duration = Duration::from_secs(10 * 60);

/// Hard ceiling on the number of distinct source IPs the defense maps
/// (`rate`, `strikes`) track at once, and on retained `banned` entries.
/// The maps are pruned only once per [`DISCOVER_CYCLE`]; without a size
/// cap a spoofed-source UDP flood (millions of distinct fake source IPs
/// between prunes) would grow them without bound → memory exhaustion.
/// At the cap we stop tracking NEW ips — the packet is still admitted,
/// because amplification is blocked by the bonding gate (which a spoofed
/// source can never pass), not by the per-IP counter — so memory is
/// bounded without dropping legitimate peers. 65 536 × ~100 B ≈ 6.5 MiB.
const MAX_TRACKED_IPS: usize = 65_536;
/// Hard ceiling on outstanding (un-ponged) bonding pings. Bounds the
/// `pending` set against a flood of `KAD_NEIGHBORS` referrals naming many
/// distinct addresses (which also bounds referral-driven ping fan-out).
const MAX_PENDING: usize = 8_192;
/// Max referred endpoints we will bond-ping from a single `KAD_NEIGHBORS`,
/// so a bonded peer can't turn one referral packet into a large outbound
/// ping fan-out (reflection). A well-formed NEIGHBORS carries `<=`
/// [`BUCKET_SIZE`] anyway.
const MAX_REFERRALS_PER_NEIGHBORS: usize = BUCKET_SIZE;

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

/// Eclipse-diversity group for `ip`, or `None` if the address is exempt
/// from the per-group cap (loopback / private / link-local / unspecified —
/// not reachable on the public network, so not an eclipse lever). Public
/// v4 groups by `/24`, public v6 by `/48`.
fn diversity_group(ip: &IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
            {
                return None;
            }
            let o = v4.octets();
            Some(format!("v4:{}.{}.{}", o[0], o[1], o[2]))
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return None;
            }
            let s = v6.segments();
            Some(format!("v6:{:x}:{:x}:{:x}", s[0], s[1], s[2]))
        }
    }
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
    /// Addresses we have sent a `KAD_PING` to and are awaiting a
    /// `KAD_PONG` from. Only a peer with an entry here can be promoted
    /// into the table — proving it answered at its real source address
    /// (N-9 / N-32). Pruned by [`Self::prune_pending`].
    pending: HashMap<SocketAddr, Instant>,
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
            pending: HashMap::new(),
        }
    }

    fn bucket_idx(&self, node_id: &[u8]) -> usize {
        distance(&self.home_id, node_id).min(BINS - 1)
    }

    /// Count current entries whose address falls in eclipse-diversity
    /// `group`.
    fn count_in_group(&self, group: &str) -> usize {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .filter(|e| diversity_group(&e.node.addr.ip()).as_deref() == Some(group))
            .count()
    }

    /// Insert `node`. If the appropriate bucket is full, or the node's
    /// public `/24`/`/48` is already at [`MAX_PER_GROUP`], the candidate
    /// is dropped and its host_key returned. Returns `None` when the node
    /// was inserted or was already present (refreshed).
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
        // Subnet-diversity cap for a NEW node (N-10).
        if let Some(group) = diversity_group(&node.addr.ip()) {
            if self.count_in_group(&group) >= MAX_PER_GROUP {
                return Some(key);
            }
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

    /// True if `host_key` is a verified (bonded) table member.
    fn is_member(&self, host_key: &str) -> bool {
        self.by_host.contains_key(host_key)
    }

    /// Record that we just sent a `KAD_PING` to `addr` and expect a
    /// `KAD_PONG` back to promote it. Bounded by [`MAX_PENDING`] so a flood
    /// of referrals naming distinct addresses can't grow it without limit;
    /// an existing entry is always refreshed.
    fn note_pending(&mut self, addr: SocketAddr) {
        if !self.pending.contains_key(&addr) && self.pending.len() >= MAX_PENDING {
            return;
        }
        self.pending.insert(addr, Instant::now());
    }

    /// True if `addr` has an outstanding ping awaiting a pong.
    fn has_pending(&self, addr: &SocketAddr) -> bool {
        self.pending.contains_key(addr)
    }

    /// Consume the pending expectation for `addr` (returns whether one
    /// existed). A pong only promotes a node if we solicited it.
    fn take_pending(&mut self, addr: &SocketAddr) -> bool {
        self.pending.remove(addr).is_some()
    }

    /// Drop pending entries older than [`PENDING_EXPIRY`].
    fn prune_pending(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.pending
            .retain(|_, t| now.duration_since(*t) < max_age);
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

/// Per-source-IP fixed window for inbound-packet rate limiting (N-18).
struct RateWindow {
    start: Instant,
    count: u32,
}

/// Per-source-IP malformed-packet strike accumulator (N-22).
struct Strikes {
    count: u32,
    since: Instant,
}

/// Abuse-defense bookkeeping, keyed by source IP. Separate from the
/// routing table so the per-packet admission check never contends the
/// table lock.
#[derive(Default)]
struct DefenseState {
    rate: HashMap<IpAddr, RateWindow>,
    /// IP → instant the ban lifts.
    banned: HashMap<IpAddr, Instant>,
    strikes: HashMap<IpAddr, Strikes>,
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
    defense: Mutex<DefenseState>,
}

/// Clone-friendly read handle. Cheap to clone (Arc-shared table).
#[derive(Clone)]
pub struct KadHandle {
    table: Arc<RwLock<RoutingTable>>,
}

/// Recover a poisoned `RwLock` read guard instead of propagating the
/// panic. The routing table is advisory state — a thread that panicked
/// mid-update leaves it at worst slightly stale, never corrupt enough to
/// justify taking down all of discovery (N-13).
fn read_table(lock: &RwLock<RoutingTable>) -> RwLockReadGuard<'_, RoutingTable> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

/// Poison-recovering write guard (see [`read_table`]).
fn write_table(lock: &RwLock<RoutingTable>) -> RwLockWriteGuard<'_, RoutingTable> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

impl KadHandle {
    /// Snapshot of every peer the DHT currently knows about (including
    /// seeds and any node discovered via `NEIGHBORS` responses).
    pub fn known_peers(&self) -> Vec<SocketAddr> {
        read_table(&self.table)
            .all_nodes()
            .into_iter()
            .map(|n| n.addr)
            .collect()
    }

    /// Number of entries currently in the table.
    pub fn count(&self) -> usize {
        read_table(&self.table).count()
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
            defense: Mutex::new(DefenseState::default()),
        })
    }

    /// Get a clone-friendly handle for read-only access from other
    /// subsystems (e.g. the TCP sync-driver pool).
    pub fn handle(&self) -> KadHandle {
        KadHandle { table: self.table.clone() }
    }

    fn defense(&self) -> std::sync::MutexGuard<'_, DefenseState> {
        self.defense.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Admission check for an inbound packet from `ip`: returns `false`
    /// (drop the packet) if the IP is banned or has exceeded its per-IP
    /// rate budget for the current window (N-18 / N-22).
    fn admit(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut d = self.defense();
        if let Some(&until) = d.banned.get(&ip) {
            if now < until {
                return false;
            }
            d.banned.remove(&ip);
        }
        match d.rate.get_mut(&ip) {
            Some(w) => {
                if now.duration_since(w.start) >= RATE_WINDOW {
                    w.start = now;
                    w.count = 0;
                }
                w.count = w.count.saturating_add(1);
                // Over budget: drop, but do NOT strike — an honest peer can
                // burst briefly. Only malformed packets earn strikes.
                w.count <= MAX_PACKETS_PER_WINDOW
            }
            None => {
                // New source IP. Bound the map: under a spoofed-source flood
                // we stop tracking new ips rather than grow without limit
                // (memory DoS). Untracked ips are admitted — the bonding gate,
                // not this counter, is what blocks amplification.
                if d.rate.len() >= MAX_TRACKED_IPS {
                    return true;
                }
                d.rate.insert(ip, RateWindow { start: now, count: 1 });
                true
            }
        }
    }

    /// Record a protocol-abuse strike for `ip` (a malformed packet). On
    /// the [`MAX_STRIKES`]th strike within [`STRIKE_WINDOW`], the IP is
    /// banned for [`BAN_DURATION`] (N-22).
    fn strike(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut d = self.defense();
        // Bound the strikes map: don't let a spoofed-source flood of
        // malformed packets grow it without limit (an untracked new ip just
        // isn't strike-counted this round).
        if !d.strikes.contains_key(&ip) && d.strikes.len() >= MAX_TRACKED_IPS {
            return;
        }
        let banned = {
            let s = d.strikes.entry(ip).or_insert(Strikes { count: 0, since: now });
            if now.duration_since(s.since) >= STRIKE_WINDOW {
                s.count = 0;
                s.since = now;
            }
            s.count = s.count.saturating_add(1);
            s.count >= MAX_STRIKES
        };
        if banned {
            d.strikes.remove(&ip);
            // Cap retained bans too; if the ban map is somehow full, the worst
            // case is this abusive ip isn't banned (it's still rate-limited).
            if d.banned.len() < MAX_TRACKED_IPS {
                d.banned.insert(ip, now + BAN_DURATION);
                warn!(ip = %ip, "kad: peer banned for repeated malformed packets");
            }
        }
    }

    /// Drop expired bans / stale rate + strike entries so the defense
    /// maps don't grow without bound.
    fn prune_defense(&self) {
        let now = Instant::now();
        let mut d = self.defense();
        d.banned.retain(|_, until| *until > now);
        d.rate
            .retain(|_, w| now.duration_since(w.start) < RATE_WINDOW * 4);
        d.strikes
            .retain(|_, s| now.duration_since(s.since) < STRIKE_WINDOW);
    }

    /// True if `addr` is a bonded (PONG-verified) table member.
    fn is_bonded(&self, addr: &SocketAddr) -> bool {
        read_table(&self.table).is_member(&addr.to_string())
    }

    /// Start bonding with `addr` (ping it so its pong can promote it),
    /// unless it is already a member or already has an outstanding ping.
    async fn bond(&self, addr: SocketAddr) {
        {
            let t = read_table(&self.table);
            let key = addr.to_string();
            if t.is_member(&key) || t.has_pending(&addr) {
                return;
            }
        }
        self.send_ping(addr).await;
    }

    /// Handle a `KAD_PONG` from `addr`: promote it into the table iff we
    /// solicited the pong (had a pending ping out to it) — proving it is
    /// reachable at this exact source address (N-9 / N-32). An already
    /// bonded peer is just refreshed. An unsolicited pong from an unknown
    /// address is ignored (anti-spoof).
    fn promote(&self, addr: SocketAddr, node_id: Vec<u8>) {
        let mut t = write_table(&self.table);
        let key = addr.to_string();
        if t.take_pending(&addr) {
            t.add(Node { id: node_id, addr });
        } else if t.is_member(&key) {
            t.touch(&key);
        }
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
        // Ping each seed to learn its real node-id and bond it. Seeds are
        // NOT inserted as placeholders any more — they enter the table only
        // when they pong (N-9), exactly like any other peer.
        for seed in &self.seeds {
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
        // Per-IP admission: drop banned / rate-flooding sources before any
        // work or reply (N-18 / N-22).
        if !self.admit(from.ip()) {
            return;
        }
        match ty {
            KAD_PING => {
                let Ok(ping) = PingMessage::decode(payload) else {
                    self.strike(from.ip());
                    debug!(from = %from, "kad: malformed PING");
                    return;
                };
                // Reply with PONG. `echo` carries the ping's version per
                // upstream convention. PONG is the same size class as the
                // PING, so replying to an unbonded/spoofable source is not an
                // amplification lever.
                let pong = PongMessage {
                    from: Some(self.home.clone()),
                    echo: ping.version,
                    timestamp: now_ms(),
                };
                let bytes = encode_packet(KAD_PONG, &pong.encode_to_vec());
                let _ = self.socket.send_to(&bytes, from).await;
                // Bond before table membership: an inbound ping does NOT
                // insert the sender; we ping it back and let its pong prove
                // reachability at this address (N-9 / N-32).
                if self.is_bonded(&from) {
                    write_table(&self.table).touch(&from.to_string());
                } else {
                    self.bond(from).await;
                }
            }
            KAD_PONG => {
                let Ok(pong) = PongMessage::decode(payload) else {
                    self.strike(from.ip());
                    return;
                };
                let from_id = pong.from.as_ref().map(|e| e.node_id.clone()).unwrap_or_default();
                self.promote(from, from_id);
            }
            KAD_FIND_NODE => {
                let Ok(find) = FindNeighbours::decode(payload) else {
                    self.strike(from.ip());
                    return;
                };
                // Anti-amplification (N-18): the NEIGHBORS reply is the only
                // large response. Send it ONLY to a bonded peer — a spoofed
                // source can never bond, so the reflection vector is closed.
                if !self.is_bonded(&from) {
                    return;
                }
                write_table(&self.table).touch(&from.to_string());
                let closest = read_table(&self.table).closest(&find.target_id, BUCKET_SIZE);
                let neighbours: Vec<Endpoint> = closest
                    .into_iter()
                    .map(|n| endpoint_for(&n))
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
                    self.strike(from.ip());
                    return;
                };
                // Only accept referrals from a peer we've already bonded with —
                // otherwise an unsolicited NEIGHBORS could inject arbitrary
                // addresses for us to ping (N-9).
                if !self.is_bonded(&from) {
                    return;
                }
                write_table(&self.table).touch(&from.to_string());
                // For each referred endpoint: ping to bond — do NOT add to the
                // table on a third party's say-so. The endpoint enters only
                // when IT pongs us (N-9 / N-32).
                let mut to_bond = Vec::new();
                {
                    let t = read_table(&self.table);
                    for ep in &resp.neighbours {
                        // Cap fan-out per packet so a bonded peer can't turn one
                        // referral into a large outbound ping burst (reflection).
                        if to_bond.len() >= MAX_REFERRALS_PER_NEIGHBORS {
                            break;
                        }
                        let Some(addr) = parse_endpoint(ep) else {
                            continue;
                        };
                        if t.is_member(&addr.to_string()) || t.has_pending(&addr) {
                            continue;
                        }
                        to_bond.push(addr);
                    }
                }
                for addr in to_bond {
                    self.send_ping(addr).await;
                }
            }
            _ => {
                // Unknown type — silently ignore (upstream behavior).
            }
        }
    }

    async fn send_ping(&self, to: SocketAddr) {
        // Record the bonding expectation BEFORE the send so a fast pong
        // can't race ahead of us noting the pending entry.
        write_table(&self.table).note_pending(to);
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
            // House-keeping: expire stale pending bonds + defense entries.
            write_table(&self.table).prune_pending(PENDING_EXPIRY);
            self.prune_defense();
            loop_num = loop_num.wrapping_add(1);
            let target = if loop_num % SELF_LOOKUP_EVERY == 0 {
                self.home.node_id.clone()
            } else {
                random_node_id()
            };
            self.iterative_lookup(&target).await;
            debug!(
                table_size = read_table(&self.table).count(),
                "kad: discover cycle done"
            );
        }
    }

    async fn iterative_lookup(&self, target: &[u8]) {
        let mut tried: HashSet<SocketAddr> = HashSet::new();
        for _round in 0..MAX_STEPS {
            let candidates = read_table(&self.table).closest(target, ALPHA * 2);
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

/// Build a wire `Endpoint` for a routing-table node, placing the address
/// string in the v4 or v6 field as appropriate (N-21).
fn endpoint_for(n: &Node) -> Endpoint {
    let (address, address_ipv6) = match n.addr.ip() {
        IpAddr::V4(v4) => (v4.to_string().into_bytes(), vec![]),
        IpAddr::V6(v6) => (vec![], v6.to_string().into_bytes()),
    };
    Endpoint {
        address,
        port: n.addr.port() as i32,
        node_id: n.id.clone(),
        address_ipv6,
    }
}

/// Parse a wire `Endpoint` into a `SocketAddr`. Returns `None` for the
/// upstream's malformed-record cases: zero / out-of-range port, or an
/// address that is neither a valid ASCII-encoded IPv4 (`address`) nor
/// IPv6 (`address_ipv6`) string. IPv6 endpoints are now kept rather than
/// silently dropped (N-21).
fn parse_endpoint(ep: &Endpoint) -> Option<SocketAddr> {
    if ep.port <= 0 || ep.port > 65535 {
        return None;
    }
    let port = ep.port as u16;
    // Prefer the v4 address string; fall back to the v6 field.
    for field in [&ep.address, &ep.address_ipv6] {
        if field.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(field) {
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, port));
            }
        }
    }
    None
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
    fn public_subnet_diversity_cap_enforced() {
        // A single public /24 may occupy at most MAX_PER_GROUP slots; the
        // next same-/24 node is dropped, but a different /24 still fits.
        let mut t = RoutingTable::new(vec![0u8; 64]);
        for i in 0..(MAX_PER_GROUP as u8) {
            let n = Node { id: vec![i; 64], addr: SocketAddr::from(([203, 0, 113, i], 18_888)) };
            assert!(t.add(n).is_none(), "within cap at i={i}");
        }
        // One more in the SAME /24 → dropped.
        let over = Node { id: vec![0x99; 64], addr: SocketAddr::from(([203, 0, 113, 200], 18_888)) };
        assert!(t.add(over).is_some(), "same-/24 over cap is dropped");
        assert_eq!(t.count(), MAX_PER_GROUP);
        // A different /24 still gets in.
        let other = Node { id: vec![0x77; 64], addr: SocketAddr::from(([198, 51, 100, 1], 18_888)) };
        assert!(t.add(other).is_none(), "different /24 admitted");
        assert_eq!(t.count(), MAX_PER_GROUP + 1);
    }

    #[test]
    fn loopback_is_exempt_from_diversity_cap() {
        // Loopback (used pervasively in tests) is not eclipse-relevant and
        // must not be capped, or local multi-node tests break.
        let mut t = RoutingTable::new(vec![0u8; 64]);
        for i in 1..=(MAX_PER_GROUP as u8 + 3) {
            assert!(t.add(mk_node(i, 18_888, i)).is_none(), "loopback never capped");
        }
        assert_eq!(t.count(), MAX_PER_GROUP + 3);
    }

    #[test]
    fn pending_gate_promotes_only_solicited() {
        let mut t = RoutingTable::new(vec![0u8; 64]);
        let addr = SocketAddr::from(([198, 51, 100, 7], 18_888));
        // No pending entry → a "pong" must not promote.
        assert!(!t.take_pending(&addr));
        // After we record a ping, the pong promotes.
        t.note_pending(addr);
        assert!(t.has_pending(&addr));
        assert!(t.take_pending(&addr));
        assert!(!t.has_pending(&addr), "consumed");
    }

    #[test]
    fn parse_endpoint_rejects_bad_port_and_address() {
        // port = 0
        let ep = Endpoint { address: b"127.0.0.1".to_vec(), port: 0, node_id: vec![], address_ipv6: vec![] };
        assert!(parse_endpoint(&ep).is_none());
        // non-ascii-ip address
        let ep = Endpoint { address: vec![0xFF, 0xFE, 0xFD], port: 18_888, node_id: vec![], address_ipv6: vec![] };
        assert!(parse_endpoint(&ep).is_none());
        // valid v4
        let ep = Endpoint { address: b"10.0.0.1".to_vec(), port: 18_888, node_id: vec![], address_ipv6: vec![] };
        assert_eq!(parse_endpoint(&ep), Some(SocketAddr::from(([10, 0, 0, 1], 18_888))));
    }

    #[test]
    fn parse_endpoint_accepts_ipv6_field() {
        // IPv6-only endpoint: v4 `address` empty, `address_ipv6` carries the
        // ASCII v6 string. Previously dropped silently (N-21) — now parsed.
        let ep = Endpoint {
            address: vec![],
            port: 18_888,
            node_id: vec![],
            address_ipv6: b"2001:db8::1".to_vec(),
        };
        let got = parse_endpoint(&ep).expect("v6 endpoint parses");
        assert!(got.is_ipv6());
        assert_eq!(got.port(), 18_888);
    }

    #[test]
    fn diversity_group_exempts_private_and_loopback() {
        assert!(diversity_group(&"127.0.0.1".parse().unwrap()).is_none());
        assert!(diversity_group(&"10.1.2.3".parse().unwrap()).is_none());
        assert!(diversity_group(&"192.168.1.1".parse().unwrap()).is_none());
        // Public addresses are grouped by /24.
        assert_eq!(
            diversity_group(&"203.0.113.5".parse().unwrap()),
            diversity_group(&"203.0.113.250".parse().unwrap()),
            "same /24 → same group"
        );
        assert_ne!(
            diversity_group(&"203.0.113.5".parse().unwrap()),
            diversity_group(&"203.0.114.5".parse().unwrap()),
            "different /24 → different group"
        );
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
    async fn kad_find_node_requires_bonding_then_returns_neighbours() {
        // The NEIGHBORS reply is gated on bonding (N-18). A peer must first
        // PING (and receive our verification PONG/PING) to become bonded
        // before a FIND_NODE is answered. Drive the full bond → find_node
        // exchange and assert NEIGHBORS comes back only after bonding.
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
        // Pre-seed the table with peers to return as neighbours.
        for i in 1..=5u8 {
            write_table(&kad.table).add(mk_node(i, 10_000 + i as u16, i));
        }
        let me = Arc::new(kad);
        let recv = {
            let me = me.clone();
            tokio::spawn(async move { me.recv_loop().await })
        };

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_port = peer.local_addr().unwrap().port();
        let peer_ep = Endpoint {
            address: b"127.0.0.1".to_vec(),
            port: peer_port as i32,
            node_id: vec![0x33; 64],
            address_ipv6: vec![],
        };

        // 1) Unbonded FIND_NODE → no reply (anti-amplification gate).
        let find = FindNeighbours {
            from: Some(peer_ep.clone()),
            target_id: vec![0x03; 64],
            timestamp: now_ms(),
        };
        peer.send_to(&encode_packet(KAD_FIND_NODE, &find.encode_to_vec()), bound)
            .await
            .unwrap();
        let mut buf = vec![0u8; UDP_MAX_PACKET_BYTES];
        let early = tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf)).await;
        assert!(early.is_err(), "unbonded FIND_NODE must not be answered");

        // 2) Bond: PING the service. It replies PONG and pings us back to
        //    verify; we PONG that to complete the bond.
        let ping = PingMessage {
            from: Some(peer_ep.clone()),
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
        // Drain packets from the service until we've seen its verification
        // PING, answering it with a PONG so the bond completes.
        let bond_deadline = Duration::from_secs(2);
        loop {
            let (n, _from) = tokio::time::timeout(bond_deadline, peer.recv_from(&mut buf))
                .await
                .expect("expected a packet from service")
                .unwrap();
            let (ty, payload) = decode_packet(&buf[..n]).unwrap();
            if ty == KAD_PING {
                // Answer the verification ping → promotes us to bonded.
                let pong = PongMessage {
                    from: Some(peer_ep.clone()),
                    echo: PingMessage::decode(payload).map(|p| p.version).unwrap_or(0),
                    timestamp: now_ms(),
                };
                peer.send_to(&encode_packet(KAD_PONG, &pong.encode_to_vec()), bound)
                    .await
                    .unwrap();
                break;
            }
            // ty == KAD_PONG (reply to our ping): keep draining for the ping.
        }
        // Give the service a moment to process our bonding PONG.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(me.is_bonded(&SocketAddr::from(([127, 0, 0, 1], peer_port))), "bonded after pong");

        // 3) Bonded FIND_NODE → NEIGHBORS returned.
        peer.send_to(&encode_packet(KAD_FIND_NODE, &find.encode_to_vec()), bound)
            .await
            .unwrap();
        let resp = loop {
            let (n, _from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
                .await
                .expect("neighbours timeout")
                .unwrap();
            let (ty, payload) = decode_packet(&buf[..n]).unwrap();
            if ty == KAD_NEIGHBORS {
                break Neighbours::decode(payload).unwrap();
            }
        };
        assert!(!resp.neighbours.is_empty(), "should return some neighbours");
        // Closest to id=3 is id=3 itself.
        assert_eq!(resp.neighbours[0].node_id[0], 3);

        recv.abort();
    }

    #[tokio::test]
    async fn banned_ip_is_dropped_by_admission() {
        let kad = KadService::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![0xAAu8; 64],
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            11_111,
            vec![],
        )
        .await
        .expect("bind kad");
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        // Accumulate strikes to the ban threshold.
        for _ in 0..MAX_STRIKES {
            kad.strike(ip);
        }
        assert!(!kad.admit(ip), "ip should be banned after MAX_STRIKES");
        // A different IP is unaffected.
        assert!(kad.admit("203.0.113.10".parse().unwrap()));
    }

    #[tokio::test]
    async fn rate_limit_drops_floods() {
        let kad = KadService::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![0xAAu8; 64],
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            11_111,
            vec![],
        )
        .await
        .expect("bind kad");
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        for _ in 0..MAX_PACKETS_PER_WINDOW {
            assert!(kad.admit(ip), "within budget");
        }
        assert!(!kad.admit(ip), "over budget in the same window is dropped");
        // Flooding does not itself ban (honest bursts allowed).
        assert!(kad.defense().banned.get(&ip).is_none());
    }

    #[tokio::test]
    async fn defense_maps_are_bounded_under_distinct_source_flood() {
        // A spoofed-source flood with more distinct IPs than the cap must NOT
        // grow the rate map without bound (the memory-DoS this guards). Once at
        // the cap, new ips are admitted (the bonding gate, not this counter,
        // blocks amplification) but not tracked.
        let kad = KadService::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![0xAAu8; 64],
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            11_111,
            vec![],
        )
        .await
        .expect("bind kad");
        for i in 0..(MAX_TRACKED_IPS as u32 + 2_000) {
            let ip = IpAddr::from(i.to_be_bytes());
            assert!(kad.admit(ip), "untracked overflow ips are still admitted");
        }
        assert!(
            kad.defense().rate.len() <= MAX_TRACKED_IPS,
            "rate map must stay bounded by MAX_TRACKED_IPS"
        );
    }
}
