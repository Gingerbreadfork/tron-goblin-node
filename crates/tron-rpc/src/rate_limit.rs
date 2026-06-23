//! HTTP / RPC rate-limit middleware that consumes
//! `rate.limiter.{http,rpc}` config entries.
//!
//! Mirrors java-tron's `RateLimiterInterceptor` (HTTP) and the
//! `RateLimiterInterceptorService` it installs around the gRPC server.
//! Each `RateLimiterItem { component, strategy, params }` maps to one
//! per-component rate limiter; the middleware looks up the matching
//! component for each request and rejects with HTTP 429 (HTTP) or
//! `Unavailable` (gRPC) when the rate is exceeded.
//!
//! ## Strategies
//!
//! * `QpsRateLimiterAdapter` — global QPS bucket. Default; matches
//!   java-tron's most-common usage.
//! * `IPQPSRateLimiterAdapter` — per-source-IP QPS bucket. Used when
//!   the operator wants to throttle each client independently
//!   (e.g. one Wallet RPC method per IP).
//! * `GlobalPreemptibleAdapter` — concurrent-request count. Caps
//!   in-flight requests rather than rate. Useful for expensive
//!   operations that the server can only serve a few at a time.
//!
//! ## Component matching
//!
//! For HTTP, java-tron's interceptor matches `component` against the
//! Spring servlet name (e.g. `getaccount`); we treat the matching as
//! "last path segment, lowercased". For gRPC, java-tron matches the
//! dotted method name (e.g. `protocol.Wallet/GetAccount`); we accept
//! the same form for parity, lowercased.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// One rate-limit binding. Built from `RateLimiterItem` in the config
/// loader; the registry holds these keyed by lowercased component.
#[derive(Debug)]
pub enum RateLimit {
    Qps(QpsBucket),
    IpQps(IpQpsBuckets),
    Preemptible(PreemptibleCounter),
}

impl RateLimit {
    /// Non-blocking try-acquire. `ip` is the request's source address
    /// (used by `IpQps`); `_drop_token` returns a guard for the
    /// `Preemptible` strategy that auto-decrements on drop. Returns
    /// `(true, Some(guard))` on accept; `(false, None)` on reject.
    pub fn try_acquire(
        &self,
        ip: Option<IpAddr>,
    ) -> (bool, Option<PreemptibleGuard>) {
        match self {
            RateLimit::Qps(b) => (b.try_acquire(), None),
            RateLimit::IpQps(buckets) => {
                let ip = ip.unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
                (buckets.try_acquire(ip), None)
            }
            RateLimit::Preemptible(c) => match c.try_acquire() {
                Some(g) => (true, Some(g)),
                None => (false, None),
            },
        }
    }
}

/// QPS bucket with Guava `RateLimiter.create(qps)` semantics: permits
/// refill at `qps`/sec and can ACCUMULATE up to one second's worth
/// (`maxBurstSeconds = 1.0`), so `qps` truly concurrent requests are
/// admitted before throttling starts. (The previous one-permit burst
/// rejected the second of any two simultaneous requests regardless of
/// the configured rate — far stricter than java.)
#[derive(Debug)]
pub struct QpsBucket {
    qps: f64,
    inner: Mutex<QpsInner>,
}

#[derive(Debug)]
struct QpsInner {
    permits: f64,
    last_refill: Instant,
}

impl QpsBucket {
    pub fn new(qps: f64) -> Self {
        Self {
            qps,
            inner: Mutex::new(QpsInner {
                // Guava starts full: a fresh limiter admits a burst.
                permits: qps.max(1.0),
                last_refill: Instant::now(),
            }),
        }
    }

    pub fn try_acquire(&self) -> bool {
        let max_burst = self.qps.max(1.0); // Guava maxBurstSeconds = 1.0
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        let dt = now.saturating_duration_since(g.last_refill).as_secs_f64();
        g.permits = (g.permits + dt * self.qps).min(max_burst);
        g.last_refill = now;
        if g.permits >= 1.0 {
            g.permits -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-source-IP QPS limiter, optionally aggregating by CIDR block. Each
/// distinct key (the source IP, masked to `/prefix4` for v4 or `/prefix6` for
/// v6) gets its own bucket; the inner map is bounded — when full, an entry is
/// evicted. `prefix4 = 32` / `prefix6 = 128` is exact per-IP; shorter prefixes
/// make a whole subnet share one bucket, which stops an attacker spreading a
/// flood across many IPs in one allocation to slip under a per-IP limit.
#[derive(Debug)]
pub struct IpQpsBuckets {
    qps: f64,
    prefix4: u8,
    prefix6: u8,
    inner: Mutex<HashMap<IpAddr, QpsBucket>>,
    cap: usize,
}

impl IpQpsBuckets {
    /// Per-IP buckets (`/32`, `/128`).
    pub fn new(qps: f64) -> Self {
        Self::new_cidr(qps, 32, 128)
    }

    /// CIDR-aggregated buckets: source IPs are masked to `/prefix4` (v4) or
    /// `/prefix6` (v6) before bucketing.
    pub fn new_cidr(qps: f64, prefix4: u8, prefix6: u8) -> Self {
        Self {
            qps,
            prefix4: prefix4.min(32),
            prefix6: prefix6.min(128),
            inner: Mutex::new(HashMap::new()),
            cap: 10_000,
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let key = mask_ip(ip, self.prefix4, self.prefix6);
        let mut g = self.inner.lock().unwrap();
        // Cheap upper bound — when over cap, drop ONE entry chosen
        // arbitrarily (HashMap iteration order). Acceptable because
        // a flood from many distinct keys is the only way to hit
        // cap, and at that point every source is suspect anyway.
        if g.len() >= self.cap {
            if let Some(k) = g.keys().next().copied() {
                g.remove(&k);
            }
        }
        let bucket = g.entry(key).or_insert_with(|| QpsBucket::new(self.qps));
        bucket.try_acquire()
    }
}

/// Mask an IP to its network address for the given prefix lengths, so a whole
/// CIDR block keys to one rate-limit bucket. `prefix4 >= 32` / `prefix6 >= 128`
/// leaves the address unchanged (per-IP); `0` collapses the whole family to one
/// bucket.
fn mask_ip(ip: IpAddr, prefix4: u8, prefix6: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masked = match prefix4 {
                0 => 0,
                p if p >= 32 => bits,
                p => bits & (u32::MAX << (32 - p)),
            };
            IpAddr::V4(std::net::Ipv4Addr::from(masked))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masked = match prefix6 {
                0 => 0,
                p if p >= 128 => bits,
                p => bits & (u128::MAX << (128 - p)),
            };
            IpAddr::V6(std::net::Ipv6Addr::from(masked))
        }
    }
}

/// Concurrent-request counter. Caps in-flight calls at `permit`.
#[derive(Debug)]
pub struct PreemptibleCounter {
    permit: i64,
    in_flight: Arc<AtomicI64>,
}

impl PreemptibleCounter {
    pub fn new(permit: i64) -> Self {
        Self {
            permit,
            in_flight: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn try_acquire(&self) -> Option<PreemptibleGuard> {
        let prev = self.in_flight.fetch_add(1, Ordering::SeqCst);
        if prev >= self.permit {
            // Over capacity — back out.
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            None
        } else {
            Some(PreemptibleGuard {
                in_flight: Arc::clone(&self.in_flight),
            })
        }
    }
}

/// Guard returned by `PreemptibleCounter::try_acquire`. Drops the
/// in-flight count on drop — the request handler holds it for the
/// duration of the response.
pub struct PreemptibleGuard {
    in_flight: Arc<AtomicI64>,
}

impl Drop for PreemptibleGuard {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for PreemptibleGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreemptibleGuard").finish()
    }
}

/// Component-keyed registry. The middleware looks up the matching
/// `RateLimit` for each request's component name; missing components
/// pass through unlimited.
#[derive(Debug, Default, Clone)]
pub struct RateLimitRegistry {
    inner: Arc<HashMap<String, RateLimit>>,
}

impl RateLimitRegistry {
    pub fn new(map: HashMap<String, RateLimit>) -> Self {
        Self {
            inner: Arc::new(map),
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    /// Look up a component limit. Returns `None` when the component
    /// isn't configured (passes through unlimited).
    pub fn get(&self, component: &str) -> Option<&RateLimit> {
        self.inner.get(component)
    }

    /// True when nothing is configured. Used by the middleware to
    /// skip the per-request lookup entirely.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Parse a `key=value, key=value` param string into a map. Mirrors
/// java-tron's `Strategy.parseParam`. Whitespace around keys/values is
/// trimmed; empty input is a valid empty map.
pub fn parse_params(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in s.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        out.insert(k.trim().to_lowercase(), v.trim().to_string());
    }
    out
}

/// Build a [`RateLimit`] from a parsed config row. Unknown strategy
/// names fall back to a no-op QPS at the configured default
/// (1000 qps). Mirrors java-tron's `RateLimiterInterceptor`
/// strategy-class dispatch.
pub fn build_rate_limit(strategy: &str, params: &str) -> Option<RateLimit> {
    let map = parse_params(params);
    match strategy {
        "QpsRateLimiterAdapter" => {
            let qps = map.get("qps").and_then(|s| s.parse().ok()).unwrap_or(1000.0);
            Some(RateLimit::Qps(QpsBucket::new(qps)))
        }
        "IPQPSRateLimiterAdapter" => {
            let qps = map.get("qps").and_then(|s| s.parse().ok()).unwrap_or(1000.0);
            Some(RateLimit::IpQps(IpQpsBuckets::new(qps)))
        }
        // CIDR-aggregated per-source limiter: all IPs in the same block share a
        // bucket. Default /24 (v4) and /48 (v6) — common abuse-mitigation
        // allocations; `prefix4=32,prefix6=128` degrades to exact per-IP.
        "CIDRQPSRateLimiterAdapter" => {
            let qps = map.get("qps").and_then(|s| s.parse().ok()).unwrap_or(1000.0);
            let prefix4 = map.get("prefix4").and_then(|s| s.parse().ok()).unwrap_or(24);
            let prefix6 = map.get("prefix6").and_then(|s| s.parse().ok()).unwrap_or(48);
            Some(RateLimit::IpQps(IpQpsBuckets::new_cidr(qps, prefix4, prefix6)))
        }
        "GlobalPreemptibleAdapter" => {
            let permit = map
                .get("permit")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1_000);
            Some(RateLimit::Preemptible(PreemptibleCounter::new(permit)))
        }
        _ => None,
    }
}

/// Extract the component name a request maps to. For HTTP we use the
/// last path segment lowercased — matches java-tron's servlet-name
/// matching against the URL path.
pub fn component_for_http_path(path: &str) -> String {
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_lowercase()
}

/// Normalize a configured component name to registry-key form:
/// lowercased, with java-tron's `Servlet` class-name suffix stripped —
/// so a config.conf copied from java-tron (`component =
/// "GetAccountServlet"`) matches our path-derived key (`getaccount`).
/// gRPC method components (`protocol.Wallet/GetAccount`) only get the
/// lowercasing.
pub fn normalize_component(component: &str) -> String {
    let lower = component.to_lowercase();
    match lower.strip_suffix("servlet") {
        Some(stripped) if !stripped.is_empty() && !lower.contains('/') => stripped.to_string(),
        _ => lower,
    }
}

/// Node-wide request limits applied AFTER any per-component limit —
/// java-tron's `GlobalRateLimiter`: one global QPS bucket plus a
/// per-source-IP QPS bucket, both consulted on every HTTP servlet and
/// gRPC call. Defaults (50 000 qps global / 10 000 qps per IP) are
/// far above organic traffic; they exist to blunt floods.
///
/// Cheap to clone — both buckets are shared via `Arc`. A non-positive
/// qps disables the corresponding check.
#[derive(Debug, Clone, Default)]
pub struct GlobalRateLimiter {
    qps: Option<Arc<QpsBucket>>,
    ip_qps: Option<Arc<IpQpsBuckets>>,
}

impl GlobalRateLimiter {
    pub fn new(qps: f64, ip_qps: f64) -> Self {
        Self {
            qps: (qps > 0.0).then(|| Arc::new(QpsBucket::new(qps))),
            ip_qps: (ip_qps > 0.0).then(|| Arc::new(IpQpsBuckets::new(ip_qps))),
        }
    }

    /// A limiter that admits everything (both checks disabled).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// `true` iff the request is admitted by BOTH the global and the
    /// per-IP bucket (java rejects when either is exhausted). An
    /// unknown source IP shares one anonymous bucket.
    pub fn try_acquire(&self, ip: Option<IpAddr>) -> bool {
        if let Some(qps) = &self.qps {
            if !qps.try_acquire() {
                return false;
            }
        }
        if let Some(ip_qps) = &self.ip_qps {
            let ip = ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
            if !ip_qps.try_acquire(ip) {
                return false;
            }
        }
        true
    }

    pub fn is_disabled(&self) -> bool {
        self.qps.is_none() && self.ip_qps.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn parse_params_handles_kv_with_spaces() {
        let m = parse_params(" qps = 5 ");
        assert_eq!(m.get("qps"), Some(&"5".to_string()));
    }

    #[test]
    fn parse_params_handles_multiple_pairs() {
        let m = parse_params("qps=10,permit=2");
        assert_eq!(m.get("qps"), Some(&"10".to_string()));
        assert_eq!(m.get("permit"), Some(&"2".to_string()));
    }

    #[test]
    fn parse_params_empty_returns_empty_map() {
        assert!(parse_params("").is_empty());
        assert!(parse_params(",,,").is_empty());
    }

    #[test]
    fn qps_bucket_initial_permit_then_blocks() {
        let b = QpsBucket::new(1.0); // 1 qps
        assert!(b.try_acquire());
        assert!(!b.try_acquire());
    }

    #[test]
    fn qps_bucket_allows_guava_burst_then_blocks_then_refills() {
        // Guava semantics: a fresh limiter holds a full second of
        // permits (here 2), then refills at the configured rate.
        let b = QpsBucket::new(2.0);
        assert!(b.try_acquire(), "burst permit 1");
        assert!(b.try_acquire(), "burst permit 2");
        assert!(!b.try_acquire(), "burst exhausted");
        sleep(Duration::from_millis(600)); // ~1.2 permits refilled
        assert!(b.try_acquire());
        assert!(!b.try_acquire(), "only ~one permit refilled");
    }

    #[test]
    fn ip_qps_separates_buckets_per_ip() {
        let b = IpQpsBuckets::new(1.0);
        let a = IpAddr::V4("1.1.1.1".parse().unwrap());
        let z = IpAddr::V4("2.2.2.2".parse().unwrap());
        assert!(b.try_acquire(a));
        assert!(b.try_acquire(z));
        // Each IP has its own bucket, so the SECOND call from `a`
        // (within < 1s) fails — bucket exhausted.
        assert!(!b.try_acquire(a));
        // Re-using `z` again also fails — its bucket is also drained.
        assert!(!b.try_acquire(z));
    }

    #[test]
    fn mask_ip_masks_to_prefix() {
        let v4 = |s: &str| IpAddr::V4(s.parse().unwrap());
        assert_eq!(mask_ip(v4("1.2.3.4"), 24, 128), v4("1.2.3.0"), "/24 zeroes last octet");
        assert_eq!(mask_ip(v4("1.2.3.4"), 32, 128), v4("1.2.3.4"), "/32 is per-IP");
        assert_eq!(mask_ip(v4("1.2.3.4"), 16, 128), v4("1.2.0.0"), "/16");
        assert_eq!(mask_ip(v4("1.2.3.4"), 0, 128), v4("0.0.0.0"), "/0 collapses the family");
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        assert_eq!(
            mask_ip(v6("2001:db8:abcd:1234::1"), 32, 48),
            v6("2001:db8:abcd::"),
            "/48 keeps the first three hextets"
        );
        assert_eq!(
            mask_ip(v6("2001:db8:abcd:1234::1"), 32, 128),
            v6("2001:db8:abcd:1234::1"),
            "/128 is per-IP"
        );
    }

    #[test]
    fn cidr_qps_aggregates_a_subnet() {
        // qps=1, /24 aggregation: two DIFFERENT IPs in the same /24 share ONE
        // bucket, so the second is throttled — defeating subnet-spread evasion.
        let b = IpQpsBuckets::new_cidr(1.0, 24, 48);
        let a1 = IpAddr::V4("1.2.3.4".parse().unwrap());
        let a2 = IpAddr::V4("1.2.3.250".parse().unwrap()); // same /24 as a1
        let other = IpAddr::V4("1.2.4.1".parse().unwrap()); // different /24
        assert!(b.try_acquire(a1), "first in /24 admitted");
        assert!(!b.try_acquire(a2), "second IP in the same /24 shares the bucket -> throttled");
        assert!(b.try_acquire(other), "a different /24 has its own bucket");
    }

    #[test]
    fn build_cidr_strategy_from_config() {
        let rl = build_rate_limit("CIDRQPSRateLimiterAdapter", "qps=1,prefix4=24").unwrap();
        match rl {
            RateLimit::IpQps(b) => {
                let a1 = IpAddr::V4("9.9.9.1".parse().unwrap());
                let a2 = IpAddr::V4("9.9.9.2".parse().unwrap()); // same /24
                assert!(b.try_acquire(a1));
                assert!(!b.try_acquire(a2), "config /24 aggregation throttles the subnet");
            }
            other => panic!("expected IpQps, got {other:?}"),
        }
    }

    #[test]
    fn preemptible_counter_enforces_cap_and_drops_release() {
        let c = PreemptibleCounter::new(2);
        let g1 = c.try_acquire().expect("first acquire");
        let g2 = c.try_acquire().expect("second acquire");
        assert!(c.try_acquire().is_none(), "third acquire over cap");
        drop(g1);
        let _g3 = c.try_acquire().expect("after drop");
        drop(g2);
    }

    #[test]
    fn build_rate_limit_dispatches_strategies() {
        assert!(matches!(
            build_rate_limit("QpsRateLimiterAdapter", "qps=10"),
            Some(RateLimit::Qps(_))
        ));
        assert!(matches!(
            build_rate_limit("IPQPSRateLimiterAdapter", "qps=5"),
            Some(RateLimit::IpQps(_))
        ));
        assert!(matches!(
            build_rate_limit("GlobalPreemptibleAdapter", "permit=3"),
            Some(RateLimit::Preemptible(_))
        ));
        assert!(build_rate_limit("UnknownStrategy", "").is_none());
    }

    #[test]
    fn build_rate_limit_uses_defaults_when_param_missing() {
        match build_rate_limit("QpsRateLimiterAdapter", "") {
            Some(RateLimit::Qps(b)) => {
                // Default 1000 qps — initial burst permit then refill.
                assert!(b.try_acquire());
            }
            _ => panic!("expected default-Qps"),
        }
    }

    #[test]
    fn component_for_http_path_strips_trailing_slashes_and_lowercases() {
        assert_eq!(component_for_http_path("/wallet/getaccount"), "getaccount");
        assert_eq!(component_for_http_path("/wallet/GetAccount"), "getaccount");
        assert_eq!(component_for_http_path("/wallet/getaccount/"), "getaccount");
        assert_eq!(component_for_http_path("/"), "");
        assert_eq!(component_for_http_path(""), "");
    }

    #[test]
    fn normalize_component_strips_servlet_suffix() {
        assert_eq!(normalize_component("GetAccountServlet"), "getaccount");
        assert_eq!(normalize_component("getaccount"), "getaccount");
        // gRPC components keep the full method path (lowercased).
        assert_eq!(
            normalize_component("protocol.Wallet/GetAccount"),
            "protocol.wallet/getaccount"
        );
        // Degenerate name that IS just "servlet" stays as-is.
        assert_eq!(normalize_component("Servlet"), "servlet");
    }

    #[test]
    fn global_rate_limiter_disabled_admits_everything() {
        let g = GlobalRateLimiter::disabled();
        assert!(g.is_disabled());
        for _ in 0..1000 {
            assert!(g.try_acquire(None));
        }
    }

    #[test]
    fn global_rate_limiter_rejects_when_global_bucket_drains() {
        let g = GlobalRateLimiter::new(1.0, 0.0); // 1 qps global, ip check off
        assert!(g.try_acquire(None));
        assert!(!g.try_acquire(None));
    }

    #[test]
    fn global_rate_limiter_per_ip_buckets_are_independent() {
        let g = GlobalRateLimiter::new(0.0, 1.0); // global off, 1 qps per ip
        let a = Some(IpAddr::V4("1.1.1.1".parse().unwrap()));
        let b = Some(IpAddr::V4("2.2.2.2".parse().unwrap()));
        assert!(g.try_acquire(a));
        assert!(g.try_acquire(b));
        assert!(!g.try_acquire(a));
    }

    #[test]
    fn registry_returns_none_for_missing_component() {
        let reg = RateLimitRegistry::empty();
        assert!(reg.get("getaccount").is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_lookup_returns_configured_limit() {
        let mut map = HashMap::new();
        map.insert(
            "getaccount".to_string(),
            RateLimit::Qps(QpsBucket::new(1.0)),
        );
        let reg = RateLimitRegistry::new(map);
        assert!(reg.get("getaccount").is_some());
        assert!(reg.get("absent").is_none());
        assert!(!reg.is_empty());
    }

    #[test]
    fn try_acquire_qps_flow_returns_no_guard() {
        let lim = RateLimit::Qps(QpsBucket::new(1.0));
        let (ok, guard) = lim.try_acquire(None);
        assert!(ok);
        assert!(guard.is_none());
        // Second within budget fails.
        let (ok2, _) = lim.try_acquire(None);
        assert!(!ok2);
    }

    #[test]
    fn try_acquire_preemptible_returns_guard_that_releases_on_drop() {
        let lim = RateLimit::Preemptible(PreemptibleCounter::new(1));
        let (ok, g) = lim.try_acquire(None);
        assert!(ok);
        let g = g.expect("guard");
        // Second acquire over cap — rejected.
        let (ok2, _) = lim.try_acquire(None);
        assert!(!ok2);
        drop(g);
        // After drop, slot is free again.
        let (ok3, _) = lim.try_acquire(None);
        assert!(ok3);
    }
}
