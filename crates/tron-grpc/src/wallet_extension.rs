//! `WalletExtension` gRPC service — four RPCs that paginate
//! transactions by account direction:
//!
//! * `GetTransactionsFromThis` / `GetTransactionsFromThis2` — txs
//!   where the account is the sender (offset/limit paginated).
//! * `GetTransactionsToThis` / `GetTransactionsToThis2` — txs where
//!   the account is the recipient.
//!
//! ## Current behavior
//!
//! Returns empty lists. Populating these properly needs a
//! per-account tx-id index (a new secondary store the executor would
//! write on every tx-apply); java-tron also returns empty when the
//! `--storage.transHistory.switch` flag is off, so this matches the
//! "default" upstream shape. Clients that need this surface either
//! enable the index in their own deployment OR pull via the explorer
//! API.

use tonic::{Request, Response, Status};
use tron_proto::protocol::{
    AccountPaginated, TransactionList, TransactionListExtention,
};

use crate::proto::wallet_extension_server::WalletExtension;
use crate::service::WalletService;

#[tonic::async_trait]
impl WalletExtension for WalletService {
    async fn get_transactions_from_this(
        &self,
        _request: Request<AccountPaginated>,
    ) -> Result<Response<TransactionList>, Status> {
        Ok(Response::new(TransactionList {
            transaction: Vec::new(),
        }))
    }

    async fn get_transactions_from_this2(
        &self,
        _request: Request<AccountPaginated>,
    ) -> Result<Response<TransactionListExtention>, Status> {
        Ok(Response::new(TransactionListExtention {
            transaction: Vec::new(),
        }))
    }

    async fn get_transactions_to_this(
        &self,
        _request: Request<AccountPaginated>,
    ) -> Result<Response<TransactionList>, Status> {
        Ok(Response::new(TransactionList {
            transaction: Vec::new(),
        }))
    }

    async fn get_transactions_to_this2(
        &self,
        _request: Request<AccountPaginated>,
    ) -> Result<Response<TransactionListExtention>, Status> {
        Ok(Response::new(TransactionListExtention {
            transaction: Vec::new(),
        }))
    }
}
