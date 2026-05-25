//! Per-frame-type rate limiter for the P2P layer.
//!
//! Mirrors java-tron's `P2pRateLimiter` (Guava `RateLimiter` wrapped
//! in a 32-entry cache keyed by message-type byte). Each message
//! type has its own token bucket; types without a registration
//! pass through unlimited.
//!
//! ## Semantics
//!
//! * **`register(byte, rate)`** — install a token bucket releasing
//!   `rate` permits per second.
//! * **`try_acquire(byte)`** — non-blocking; returns `true` when a
//!   permit is available and consumed. Frames typed with no
//!   registration always return `true`.
//! * **`acquire(byte)`** — blocking; sleeps until a permit is
//!   available. Same no-registration pass-through.
//!
//! The bucket implementation is a plain token-bucket with `rate`
//! permits added per second up to a 1-permit burst cap (matches
//! Guava's "warm-up disabled" stable rate, which is what java-tron
//! uses).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A token-bucket per message type. Cheap to clone — internally
/// guarded by a `Mutex`, so concurrent `try_acquire` calls just
/// contend on the lock briefly.
pub struct P2pRateLimiter {
    inner: Mutex<Inner>,
}

struct Inner {
    /// `Option<Bucket>` instead of just `Bucket` so unregistered
    /// types are distinguishable from rate-zero registrations.
    /// Java-tron's `getIfPresent` returns `null` for unregistered;
    /// we mirror with `None`.
    buckets: HashMap<u8, Bucket>,
}

struct Bucket {
    /// Permits per second.
    rate: f64,
    /// Fractional permits currently available, capped at `1.0`
    /// (Guava's stable-rate behavior — no burst beyond one second's
    /// worth at the configured rate).
    permits: f64,
    /// Wall-clock instant of the last `refill` call.
    last_refill: Instant,
}

impl Bucket {
    fn new(rate: f64) -> Self {
        Self {
            rate,
            permits: 1.0,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.permits = (self.permits + elapsed * self.rate).min(1.0);
            self.last_refill = now;
        }
    }

    /// Try to consume one permit. Returns `true` on success.
    fn try_take(&mut self) -> bool {
        self.refill(Instant::now());
        if self.permits >= 1.0 {
            self.permits -= 1.0;
            return true;
        }
        false
    }

    /// Time until the next full permit is available. Zero when one
    /// is already available.
    fn time_to_permit(&mut self) -> Duration {
        self.refill(Instant::now());
        if self.permits >= 1.0 {
            return Duration::ZERO;
        }
        let needed = 1.0 - self.permits;
        if self.rate <= 0.0 {
            return Duration::from_secs(u64::MAX / 2);
        }
        Duration::from_secs_f64(needed / self.rate)
    }
}

impl Default for P2pRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl P2pRateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
            }),
        }
    }

    /// Install or replace a per-type rate (permits/second). Calling
    /// with a new rate on an already-registered type starts a fresh
    /// bucket — same as java-tron's `register`.
    pub fn register(&self, ty: u8, rate: f64) {
        let mut g = self.inner.lock().unwrap();
        g.buckets.insert(ty, Bucket::new(rate));
    }

    /// Drop the registration. Subsequent `try_acquire` calls for
    /// this type pass through unlimited.
    pub fn unregister(&self, ty: u8) {
        let mut g = self.inner.lock().unwrap();
        g.buckets.remove(&ty);
    }

    /// Whether `ty` has a registration.
    pub fn is_registered(&self, ty: u8) -> bool {
        let g = self.inner.lock().unwrap();
        g.buckets.contains_key(&ty)
    }

    /// Non-blocking acquire. Returns `true` when a permit was
    /// consumed (or when no limit is configured).
    pub fn try_acquire(&self, ty: u8) -> bool {
        let mut g = self.inner.lock().unwrap();
        match g.buckets.get_mut(&ty) {
            Some(b) => b.try_take(),
            None => true, // unlimited
        }
    }

    /// Blocking acquire — sleeps until a permit is available. Should
    /// be called from non-async contexts only; tokio callers should
    /// use [`try_acquire`] in a loop with their own scheduling.
    pub fn acquire(&self, ty: u8) {
        loop {
            let wait = {
                let mut g = self.inner.lock().unwrap();
                let Some(b) = g.buckets.get_mut(&ty) else {
                    return;
                };
                if b.try_take() {
                    return;
                }
                b.time_to_permit()
            };
            std::thread::sleep(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_type_always_passes() {
        let rl = P2pRateLimiter::new();
        for _ in 0..1000 {
            assert!(rl.try_acquire(42));
        }
    }

    #[test]
    fn registered_type_runs_out_of_permits() {
        let rl = P2pRateLimiter::new();
        rl.register(7, 1.0); // 1 permit/sec
        assert!(rl.try_acquire(7)); // initial permit
        // No refill yet (called within < 1s).
        assert!(!rl.try_acquire(7));
    }

    #[test]
    fn re_register_resets_bucket() {
        let rl = P2pRateLimiter::new();
        rl.register(7, 0.0); // no permits per second
        assert!(rl.try_acquire(7));
        assert!(!rl.try_acquire(7));
        rl.register(7, 1.0); // fresh bucket → starts with 1 permit
        assert!(rl.try_acquire(7));
    }

    #[test]
    fn unregister_returns_to_unlimited() {
        let rl = P2pRateLimiter::new();
        rl.register(7, 0.0);
        assert!(rl.try_acquire(7));
        assert!(!rl.try_acquire(7));
        rl.unregister(7);
        for _ in 0..100 {
            assert!(rl.try_acquire(7));
        }
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = Bucket::new(100.0); // 100/sec
        assert!(b.try_take());
        assert!(!b.try_take()); // burst = 1, so second take fails immediately
        std::thread::sleep(Duration::from_millis(20)); // 20ms → ~2 permits worth
        assert!(b.try_take());
    }

    #[test]
    fn is_registered_reflects_state() {
        let rl = P2pRateLimiter::new();
        assert!(!rl.is_registered(5));
        rl.register(5, 10.0);
        assert!(rl.is_registered(5));
        rl.unregister(5);
        assert!(!rl.is_registered(5));
    }
}
