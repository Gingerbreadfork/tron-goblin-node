//! Lite-fullnode history-query gate — java-tron `LiteFnQueryHttpFilter`.
//!
//! A lite dataset (java `LiteFullNodeTool`/`dblite` split, or our
//! `admin db lite`) keeps only the most recent blocks; the history
//! query APIs would silently return wrong/empty answers, so java
//! CLOSES them unless `node.openHistoryQueryWhenLiteFN = true`. The
//! response mirrors java exactly: HTTP 200, `application/json`
//! content type, and the bare string body
//! `this API is closed because this node is a lite fullnode`.

use axum::response::IntoResponse;
use axum::Router;

/// java's message, verbatim.
pub const LITE_NODE_MSG: &str = "this API is closed because this node is a lite fullnode";

/// java `LiteFnQueryHttpFilter.filterPaths`, normalized to the path
/// tails we serve (`/wallet/...` + the solidity mirrors).
const FILTERED_TAILS: &[&str] = &[
    "getblockbyid",
    "getblockbylatestnum",
    "getblockbylimitnext",
    "getblockbynum",
    "getmerkletreevoucherinfo",
    "gettransactionbyid",
    "gettransactioncountbyblocknum",
    "gettransactioninfobyblocknum",
    "gettransactioninfobyid",
    "gettransactionreceiptbyid",
    "getmarketorderbyaccount",
    "getmarketorderbyid",
    "getmarketorderlistbypair",
    "getmarketpairlist",
    "getmarketpricebypair",
    "isshieldedtrc20contractnotespent",
    "isspend",
    "scanandmarknotebyivk",
    "scannotebyivk",
    "scannotebyovk",
    "scanshieldedtrc20notesbyivk",
    "scanshieldedtrc20notesbyovk",
    "totaltransaction",
];

/// Is this request path one of java's lite-filtered endpoints? Matches
/// the `/wallet/`, `/walletsolidity/` and `/walletpbft/` prefixes —
/// the same three context paths java registers the filter under.
pub fn is_filtered_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    let Some(rest) = lower
        .strip_prefix("/wallet/")
        .or_else(|| lower.strip_prefix("/walletsolidity/"))
        .or_else(|| lower.strip_prefix("/walletpbft/"))
    else {
        return false;
    };
    let tail = rest.trim_end_matches('/');
    FILTERED_TAILS.contains(&tail)
}

/// Wrap `router` with the gate. `enabled == false` (full node, or the
/// operator opened history queries) returns the router untouched.
pub fn layer(router: Router, enabled: bool) -> Router {
    if !enabled {
        return router;
    }
    router.layer(axum::middleware::from_fn(gate_middleware))
}

async fn gate_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if is_filtered_path(req.uri().path()) {
        return (
            [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
            LITE_NODE_MSG,
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtered_paths_match_java_list() {
        assert!(is_filtered_path("/wallet/getblockbynum"));
        assert!(is_filtered_path("/walletsolidity/gettransactionbyid"));
        assert!(is_filtered_path("/walletpbft/getblockbyid"));
        assert!(is_filtered_path("/wallet/GetBlockByNum"), "case-insensitive");
        assert!(!is_filtered_path("/wallet/getaccount"));
        assert!(!is_filtered_path("/wallet/getnowblock"));
        assert!(!is_filtered_path("/v1/accounts/x/transactions"));
    }
}
