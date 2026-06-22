//! Minimal gRPC probe for the node's Wallet service — a sanity check of the
//! gRPC surface that the REST/JSON-RPC curl probes can't reach.
//!
//! Run against a node serving gRPC on :50051 (default):
//!   cargo run -p tron-grpc --example grpc_probe
//!   cargo run -p tron-grpc --example grpc_probe -- http://127.0.0.1:50051

use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{Account, BytesMessage, EmptyMessage};

// An address active in the early-2018 synced range.
const ADDR: [u8; 21] = [
    0x41, 0x4e, 0x52, 0x31, 0x3e, 0xdd, 0x8b, 0xf9, 0xe3, 0xa0, 0x67, 0xf4, 0xf1, 0x88, 0xe5, 0xf0,
    0x64, 0x93, 0xf4, 0x78, 0x5d,
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".to_string());
    eprintln!("Wallet gRPC probe → {endpoint}\n");
    let mut c = WalletClient::connect(endpoint).await?;
    let addr = ADDR.to_vec();

    macro_rules! probe {
        ($label:expr, $call:expr) => {
            match $call.await {
                Ok(r) => {
                    let s = format!("{:?}", r.into_inner());
                    println!("ok    {:<20} {}", $label, &s[..s.len().min(88)]);
                }
                Err(e) => println!("ERR   {:<20} {} / {}", $label, e.code(), e.message()),
            }
        };
    }

    probe!("GetNowBlock", c.get_now_block(EmptyMessage {}));
    probe!(
        "GetAccount",
        c.get_account(Account { address: addr.clone(), ..Default::default() })
    );
    probe!("ListWitnesses", c.list_witnesses(EmptyMessage {}));
    probe!("GetChainParameters", c.get_chain_parameters(EmptyMessage {}));
    probe!("TotalTransaction", c.total_transaction(EmptyMessage {}));
    probe!("GetNodeInfo", c.get_node_info(EmptyMessage {}));
    probe!("GetRewardInfo", c.get_reward_info(BytesMessage { value: addr.clone() }));
    probe!("GetBrokerageInfo", c.get_brokerage_info(BytesMessage { value: addr.clone() }));

    Ok(())
}
