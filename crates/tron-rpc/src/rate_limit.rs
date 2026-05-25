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

/// Global QPS bucket. One-permit burst, refill at `qps` permits/sec
/// (Guava `RateLimiter.create(qps)` stable-rate semantics).
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
                permits: 1.0,
                last_refill: Instant::now(),
            }),
        }
    }

    pub fn try_acquire(&self) -> bool {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        let dt = now.saturating_duration_since(g.last_refill).as_secs_f64();
        g.permits = (g.permits + dt * self.qps).min(1.0);
        g.last_refill = now;
        if g.permits >= 1.0 {
            g.permits -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-source-IP QPS limiter. Each IP gets its own bucket; the inner
/// map is bounded — when full, the oldest IP entry is evicted.
#[derive(Debug)]
pub struct IpQpsBuckets {
    qps: f64,
    inner: Mutex<HashMap<IpAddr, QpsBucket>>,
    cap: usize,
}

impl IpQpsBuckets {
    pub fn new(qps: f64) -> Self {
        Self {
            qps,
            inner: Mutex::new(HashMap::new()),
            cap: 10_000,
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut g = self.inner.lock().unwrap();
        // Cheap upper bound — when over cap, drop ONE entry chosen
        // arbitrarily (HashMap iteration order). Acceptable because
        // a flood from many distinct IPs is the only way to hit
        // cap, and at that point every IP is suspect anyway.
        if g.len() >= self.cap {
            if let Some(k) = g.keys().next().copied() {
                g.remove(&k);
            }
        }
        let bucket = g.entry(ip).or_insert_with(|| QpsBucket::new(self.qps));
        bucket.try_acquire()
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
    fn qps_bucket_refills_at_rate() {
        let b = QpsBucket::new(100.0);
        assert!(b.try_acquire());
        assert!(!b.try_acquire());
        sleep(Duration::from_millis(30));
        assert!(b.try_acquire());
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
