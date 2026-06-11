//! Per-method gRPC rate limiting — java-tron's `RateLimiterInterceptor`.
//!
//! A tower [`Layer`] wrapped around the whole tonic router (tonic's own
//! `Interceptor` never sees the method name, so this sits at the HTTP
//! layer where the URI path IS the fully-qualified method —
//! `/protocol.Wallet/GetAccount`). Each request:
//!
//! 1. Looks up the lowercased `protocol.wallet/getaccount` component in
//!    the shared [`RateLimitRegistry`] (built from `rate.limiter.rpc`
//!    config rows, same `component`/`strategy`/`params` shapes as
//!    java-tron). Missing components pass through unlimited.
//! 2. Consults the node-wide [`GlobalRateLimiter`] (java's
//!    `GlobalRateLimiter`: global qps + per-IP qps), AFTER the
//!    per-method token is taken — java's ordering.
//!
//! On overrun the call is answered with `RESOURCE_EXHAUSTED` and the
//! same message java emits ("lack of computing resources"). The
//! `GlobalPreemptibleAdapter` guard is held until the inner service
//! finishes, so in-flight caps count whole calls, not just admission.

use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tonic::body::BoxBody;
use tower::{Layer, Service};
use tron_rpc::{GlobalRateLimiter, RateLimitRegistry};

/// Layer carrying the shared limiter state. Cheap to clone.
#[derive(Clone)]
pub struct GrpcRateLimitLayer {
    registry: RateLimitRegistry,
    global: GlobalRateLimiter,
}

impl GrpcRateLimitLayer {
    pub fn new(registry: RateLimitRegistry, global: GlobalRateLimiter) -> Self {
        Self { registry, global }
    }
}

impl<S> Layer<S> for GrpcRateLimitLayer {
    type Service = GrpcRateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcRateLimit {
            inner,
            registry: self.registry.clone(),
            global: self.global.clone(),
        }
    }
}

/// The wrapped service. See the module docs for semantics.
#[derive(Clone)]
pub struct GrpcRateLimit<S> {
    inner: S,
    registry: RateLimitRegistry,
    global: GlobalRateLimiter,
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for GrpcRateLimit<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<BoxBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        // `/protocol.Wallet/GetAccount` → `protocol.wallet/getaccount`.
        let component = req.uri().path().trim_start_matches('/').to_lowercase();
        let ip = client_ip(&req);

        let mut guard = None;
        let component_ok = match self.registry.get(&component) {
            Some(limit) => {
                let (ok, g) = limit.try_acquire(ip);
                guard = g;
                ok
            }
            None => true,
        };
        if !component_ok || !self.global.try_acquire(ip) {
            let resp = tonic::Status::resource_exhausted("lack of computing resources")
                .into_http();
            return Box::pin(async move { Ok(resp) });
        }
        let fut = self.inner.call(req);
        Box::pin(async move {
            // Hold the preemptible slot (if any) for the whole call.
            let _guard = guard;
            fut.await
        })
    }
}

/// Lite-fullnode history gate — java `LiteFnQueryGrpcInterceptor`:
/// when the node runs on a lite dataset (and the operator hasn't set
/// `open_history_query_when_lite_fn`), the history-query methods close
/// with `UNAVAILABLE` and java's exact message.
#[derive(Clone)]
pub struct LiteGateLayer;

/// `LiteFnQueryGrpcInterceptor.filterMethods`, lowercased (we match the
/// lowercased URI path).
const LITE_FILTERED_METHODS: &[&str] = &[
    "protocol.wallet/getblockbyid",
    "protocol.wallet/getblockbylatestnum",
    "protocol.wallet/getblockbylatestnum2",
    "protocol.wallet/getblockbylimitnext",
    "protocol.wallet/getblockbylimitnext2",
    "protocol.wallet/getblockbynum",
    "protocol.wallet/getblockbynum2",
    "protocol.wallet/getmerkletreevoucherinfo",
    "protocol.wallet/gettransactionbyid",
    "protocol.wallet/gettransactioncountbyblocknum",
    "protocol.wallet/gettransactioninfobyid",
    "protocol.wallet/getmarketorderbyaccount",
    "protocol.wallet/getmarketorderbyid",
    "protocol.wallet/getmarketorderlistbypair",
    "protocol.wallet/getmarketpairlist",
    "protocol.wallet/getmarketpricebypair",
    "protocol.wallet/isshieldedtrc20contractnotespent",
    "protocol.wallet/isspend",
    "protocol.wallet/scanandmarknotebyivk",
    "protocol.wallet/scannotebyivk",
    "protocol.wallet/scannotebyovk",
    "protocol.wallet/scanshieldedtrc20notesbyivk",
    "protocol.wallet/scanshieldedtrc20notesbyovk",
    "protocol.wallet/totaltransaction",
    "protocol.walletsolidity/getblockbynum",
    "protocol.walletsolidity/getblockbynum2",
    "protocol.walletsolidity/getmerkletreevoucherinfo",
    "protocol.walletsolidity/gettransactionbyid",
    "protocol.walletsolidity/gettransactioncountbyblocknum",
    "protocol.walletsolidity/gettransactioninfobyid",
    "protocol.walletsolidity/getmarketorderbyaccount",
    "protocol.walletsolidity/getmarketorderbyid",
    "protocol.walletsolidity/getmarketorderlistbypair",
    "protocol.walletsolidity/getmarketpairlist",
    "protocol.walletsolidity/getmarketpricebypair",
    "protocol.walletsolidity/isshieldedtrc20contractnotespent",
    "protocol.walletsolidity/isspend",
    "protocol.walletsolidity/scanandmarknotebyivk",
    "protocol.walletsolidity/scannotebyivk",
    "protocol.walletsolidity/scannotebyovk",
    "protocol.walletsolidity/scanshieldedtrc20notesbyivk",
    "protocol.walletsolidity/scanshieldedtrc20notesbyovk",
    "protocol.database/getblockbynum",
];

impl<S> Layer<S> for LiteGateLayer {
    type Service = LiteGate<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LiteGate { inner }
    }
}

/// The wrapped service for [`LiteGateLayer`].
#[derive(Clone)]
pub struct LiteGate<S> {
    inner: S,
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for LiteGate<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<BoxBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let method = req.uri().path().trim_start_matches('/').to_lowercase();
        if LITE_FILTERED_METHODS.contains(&method.as_str()) {
            let resp = tonic::Status::unavailable(
                "this API is closed because this node is a lite fullnode",
            )
            .into_http();
            return Box::pin(async move { Ok(resp) });
        }
        Box::pin(self.inner.call(req))
    }
}

/// Source IP from tonic's connect-info extension (set by
/// `Server::serve*` for TCP transports). `None` → the limiters fall
/// back to one shared anonymous bucket.
fn client_ip<B>(req: &http::Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<tonic::transport::server::TcpConnectInfo>()
        .and_then(|info| info.remote_addr())
        .map(|addr| addr.ip())
}
