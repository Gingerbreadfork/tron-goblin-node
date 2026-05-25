//! `Database` gRPC service — four RPCs that wallets / SDKs hit for the
//! cheap "where's the chain right now?" loop, primarily:
//!
//! * `getBlockReference` — TAPOS reference (last solid block num + hash).
//!   Every TRON wallet calls this before building a tx to set
//!   `ref_block_bytes` / `ref_block_hash`.
//! * `GetDynamicProperties` — solidified block num.
//! * `GetNowBlock` / `GetBlockByNum` — head + by-num lookups (mirror of
//!   the Wallet service's counterparts; included here for clients that
//!   were written against this older service surface).

use tonic::{Request, Response, Status};
use tron_proto::protocol::{
    BlockReference, DynamicProperties, EmptyMessage, NumberMessage,
};
use tron_proto::Block;

use crate::proto::database_server::Database;
use crate::service::WalletService;

#[tonic::async_trait]
impl Database for WalletService {
    async fn get_block_reference(
        &self,
        _request: Request<EmptyMessage>,
    ) -> Result<Response<BlockReference>, Status> {
        // java-tron reads from the LAST SOLIDIFIED block (not the head)
        // so the resulting tx survives a one-block reorg.
        let block_num = self
            .state
            .dyn_props
            .latest_solidified_block_num()
            .unwrap_or(0);
        // Look up the hash via BlockIndexStore. If the solid block
        // hasn't propagated yet (fresh node), fall back to whichever
        // head we know.
        let id_opt = self
            .state
            .block_index
            .get(block_num)
            .ok()
            .or_else(|| {
                let head_num = self
                    .state
                    .dyn_props
                    .latest_block_header_number()
                    .unwrap_or(0);
                self.state.block_index.get(head_num).ok()
            });
        let block_hash = id_opt.map(|id| id.as_bytes().to_vec()).unwrap_or_default();
        Ok(Response::new(BlockReference {
            block_num,
            block_hash,
        }))
    }

    async fn get_dynamic_properties(
        &self,
        _request: Request<EmptyMessage>,
    ) -> Result<Response<DynamicProperties>, Status> {
        let last_solidity_block_num = self
            .state
            .dyn_props
            .latest_solidified_block_num()
            .unwrap_or(0);
        Ok(Response::new(DynamicProperties {
            last_solidity_block_num,
        }))
    }

    async fn get_now_block(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<Block>, Status> {
        // Delegate to the Wallet impl — identical semantics.
        crate::proto::wallet_server::Wallet::get_now_block(self, request).await
    }

    async fn get_block_by_num(
        &self,
        request: Request<NumberMessage>,
    ) -> Result<Response<Block>, Status> {
        crate::proto::wallet_server::Wallet::get_block_by_num(self, request).await
    }
}
