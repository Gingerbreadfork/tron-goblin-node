//! `Monitor` gRPC service — a single RPC (`GetStatsInfo`) that returns
//! a [`MetricsInfo`] snapshot. Used by ops dashboards and TRON
//! load-balancer health probes.
//!
//! We populate the basics (head block num/hash, version string,
//! interval=0 indicating "on demand"). The fuller per-component
//! breakdown (Vm latency histograms, Net peer counts by tier) lives
//! in the Prometheus endpoint; this RPC is for clients that prefer
//! the typed proto shape.

use tonic::{Request, Response, Status};
use tron_proto::protocol::{
    metrics_info::{BlockChainInfo, NetInfo, NodeInfo as MetricsNodeInfo},
    EmptyMessage, MetricsInfo,
};

use crate::proto::monitor_server::Monitor;
use crate::service::WalletService;

#[tonic::async_trait]
impl Monitor for WalletService {
    async fn get_stats_info(
        &self,
        _request: Request<EmptyMessage>,
    ) -> Result<Response<MetricsInfo>, Status> {
        let head_num = self.state.dyn_props.latest_block_header_number().unwrap_or(0);
        let head_hash = self
            .state
            .dyn_props
            .latest_block_header_hash()
            .ok()
            .flatten()
            .map(hex::encode)
            .unwrap_or_default();

        let info = MetricsInfo {
            // `0` means "current snapshot" — java-tron uses
            // milliseconds since last reset, which we don't track.
            interval: 0,
            node: Some(MetricsNodeInfo {
                ip: String::new(),
                node_type: 0,
                version: env!("CARGO_PKG_VERSION").to_string(),
                backup_status: 0,
            }),
            blockchain: Some(BlockChainInfo {
                head_block_num: head_num,
                head_block_timestamp: 0,
                head_block_hash: head_hash,
                // The full BlockChainInfo proto carries many more
                // counters (forkCount, fail_fork_count, tps stats);
                // we leave them at default until ops tooling needs
                // them.
                ..Default::default()
            }),
            // NetInfo lives on tron-net; expose default until that
            // crate surfaces per-peer stats.
            net: Some(NetInfo::default()),
        };
        Ok(Response::new(info))
    }
}
