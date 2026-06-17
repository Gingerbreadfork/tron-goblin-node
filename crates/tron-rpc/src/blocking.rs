//! Offload synchronous, potentially-blocking store work off the async
//! worker thread.
//!
//! Every RPC handler in this crate ultimately calls into the
//! `tron-chainbase` stores, whose reads are synchronous RocksDB `get`s.
//! Under heavy block-sync load those reads can park the calling thread
//! in uninterruptible disk sleep for hundreds of milliseconds while the
//! apply path and RocksDB compaction saturate the disk. When that work
//! runs directly inside an `async fn` it pins a tokio worker for the
//! whole duration — the runtime cannot poll the accept loop or other
//! in-flight connections on that worker, so requests that land in the
//! stall window never get a response within a tight client timeout and
//! the caller observes an empty body. Retrying with a longer timeout
//! succeeds because the stall is transient.
//!
//! [`run_blocking`] wraps such work in [`tokio::task::block_in_place`],
//! which hands the worker's other tasks off to a sibling worker for the
//! duration of the closure. The accept loop and unrelated requests keep
//! making progress while one read waits on the disk.
//!
//! `block_in_place` panics on a current-thread runtime, so the helper
//! falls back to running the closure inline when no multi-threaded
//! runtime is active — covering unit tests (`#[tokio::test]` defaults to
//! a single-threaded runtime) and any non-async caller.

/// Run a synchronous closure, yielding the current tokio worker to its
/// siblings for the duration when on a multi-threaded runtime.
///
/// Returns the closure's value. Equivalent to calling `f()` directly,
/// but does not starve the runtime when `f` blocks on disk I/O.
pub fn run_blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        // Current-thread runtime (tests) or no runtime at all: there is
        // no sibling worker to hand off to, so `block_in_place` would
        // panic. Run inline — correctness is identical, only the
        // anti-starvation property is absent (and irrelevant off the
        // multi-threaded server runtime).
        _ => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::run_blocking;

    #[test]
    fn runs_inline_without_a_runtime() {
        // No tokio runtime active: must not panic, just runs the closure.
        assert_eq!(run_blocking(|| 41 + 1), 42);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runs_inline_on_current_thread_runtime() {
        // `block_in_place` would panic here; the helper must fall back.
        assert_eq!(run_blocking(|| "ok"), "ok");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offloads_on_multi_thread_runtime() {
        // On a multi-threaded runtime the closure still returns its
        // value; the offload is transparent to the caller.
        let v = run_blocking(|| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            7
        });
        assert_eq!(v, 7);
    }
}
