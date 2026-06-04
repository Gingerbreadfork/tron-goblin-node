//! `tron-replay` — generate and validate length-delimited TRON block streams.
//!
//! Two subcommands:
//!
//! * `tron-replay gen --count N [--out PATH]` — produce a synthetic chain
//!   of `N` signed blocks starting from a synthetic genesis. Blocks are
//!   serialised as `[u32-BE length][protobuf bytes]` so the same file can
//!   be read back without out-of-band metadata.
//!
//! * `tron-replay verify PATH` — read the same format and validate each
//!   block: signature recovers to the witness address, the
//!   transactions' Merkle root matches the header, and each block's
//!   `parent_hash` equals the previous block's `BlockId`.
//!
//! This binary is a smoke test for the whole stack: any regression in
//! crypto, proto, types, or this layer fires loudly here.

use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use prost::Message;
use prost_types::Any;
use tron_crypto::address::Address;
use tron_crypto::hash::keccak256;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract, Raw as TxRaw};
use tron_proto::{Block, BlockHeader, Transaction, TransferContract};
use tron_types::{
    block_id_from_block, calc_tx_trie_root, sign_block, verify_parent_link, verify_tx_trie_root,
    verify_witness_signature, BlockId,
};

const USAGE: &str = "\
usage:
  tron-replay gen     --count N [--out PATH]
  tron-replay verify  PATH
  tron-replay execute PATH
  tron-replay dump-blocks ROCKSDB_DIR [--out PATH]
  tron-replay listen  --port N [--once]
  tron-replay sync    --peer HOST:PORT [--max-blocks N]

Commands:
  gen          synthesise N signed blocks (default 10) and write them out
  verify       read a length-delimited file and validate every block
               structurally (sig + tx-merkle + parent link)
  execute      same as verify, but additionally runs each block through
               the actuator dispatch table against a fresh in-memory
               state. Prints per-block tx success/failure counts.
  dump-blocks  open a java-tron `block/` RocksDB directory read-only and
               re-emit every stored block as length-delimited bytes —
               pipes naturally into `verify` or `execute`
  listen       open a TCP listener (default port 18888), accept incoming
               TRON P2P connections, complete the HelloMessage handshake,
               print peer info, then close. Pass --once to exit after
               one peer (default: keep accepting).
  sync         dial --peer HOST:PORT, complete the handshake, then loop:
               send SyncBlockChain with our current head, fetch the
               returned blocks, run each through the executor. --max-blocks
               caps how many blocks to apply (default: unlimited).

Each block is encoded as `[u32-BE length][protobuf bytes]` so the same
format is consumed by every subcommand and external tools.
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => match cmd_gen(&args[2..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("gen: {e}");
                ExitCode::FAILURE
            }
        },
        Some("sync") => {
            eprintln!(
                "sync: this subcommand has been removed. The legacy `run_sync_loop` did \
                 not persist blocks to BlockStore. Use the production sync surface instead:\n  \
                 tron-node start --peer HOST:PORT --data-dir DIR\n\
                 See `tron-node --help`."
            );
            ExitCode::FAILURE
        }
        Some("listen") => match cmd_listen(&args[2..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("listen: {e}");
                ExitCode::FAILURE
            }
        },
        Some("execute") => match cmd_execute(&args[2..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("execute: {e}");
                ExitCode::FAILURE
            }
        },
        Some("dump-blocks") => match cmd_dump_blocks(&args[2..]) {
            Ok(n) => {
                eprintln!("dumped {n} blocks");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("dump-blocks: {e}");
                ExitCode::FAILURE
            }
        },
        Some("verify") => match cmd_verify(&args[2..]) {
            Ok(stats) => {
                println!("{}", stats.report());
                if stats.invalid == 0 {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(e) => {
                eprintln!("verify: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprint!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

// --- gen --------------------------------------------------------------------

fn cmd_gen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut count: u32 = 10;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                i += 1;
                count = args.get(i).ok_or("--count needs a value")?.parse()?;
            }
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).ok_or("--out needs a value")?.into());
            }
            other => return Err(format!("unknown flag: {other}").into()),
        }
        i += 1;
    }

    let mut writer: Box<dyn Write> = match out_path {
        Some(p) => Box::new(BufWriter::new(File::create(p)?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };

    let chain = build_chain(count);
    for block in &chain {
        write_block(&mut *writer, block)?;
    }
    writer.flush()?;
    eprintln!("wrote {} blocks", chain.len());
    Ok(())
}

// --- dump-blocks ------------------------------------------------------------

fn cmd_dump_blocks(args: &[String]) -> Result<usize, Box<dyn std::error::Error>> {
    let mut path: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = Some(args.get(i).ok_or("--out needs a value")?.into());
            }
            other if path.is_none() => path = Some(other.into()),
            other => return Err(format!("unexpected argument: {other}").into()),
        }
        i += 1;
    }
    let path = path.ok_or("dump-blocks needs a ROCKSDB_DIR path")?;

    let backend = tron_chainbase::RocksDbBackend::open_read_only(&path)?;
    let mut writer: Box<dyn Write> = match out_path {
        Some(p) => Box::new(BufWriter::new(File::create(p)?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };

    let mut emitted = 0usize;
    let mut skipped = 0usize;
    backend
        .for_each(|_key, value| {
            match Block::decode(value) {
                Ok(block) => {
                    write_block(&mut *writer, &block)?;
                    emitted += 1;
                }
                Err(_) => {
                    // Not every value in a TRON `block/` dir is necessarily
                    // a Block proto — some implementations write metadata
                    // rows. Skip rather than abort.
                    skipped += 1;
                }
            }
            Ok(())
        })
        .map_err(|e| format!("rocksdb iteration: {e}"))?;
    writer.flush()?;
    if skipped > 0 {
        eprintln!("skipped {skipped} non-block entries");
    }
    Ok(emitted)
}

// --- listen -----------------------------------------------------------------

fn cmd_listen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::net::TcpListener;
    use tron_net::{HelloInputs, PeerConnection, MAINNET_P2P_VERSION};
    use tron_proto::Endpoint;
    use tron_types::{genesis_block_id, mainnet_inputs};

    let mut port: u16 = 18888;
    let mut once = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or("--port needs a value")?
                    .parse()
                    .map_err(|e| format!("invalid port: {e}"))?;
            }
            "--once" => once = true,
            other => return Err(format!("unknown flag: {other}").into()),
        }
        i += 1;
    }

    let genesis = genesis_block_id(&mainnet_inputs());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        eprintln!(
            "listening on 0.0.0.0:{port} (mainnet version={}, genesis={})",
            MAINNET_P2P_VERSION,
            hex::encode(genesis.as_bytes())
        );
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            eprintln!("accepted connection from {peer_addr}");
            let mut conn = PeerConnection::new(stream);
            let inputs = HelloInputs {
                from: Endpoint {
                    address: format!("0.0.0.0").into_bytes(),
                    address_ipv6: Vec::new(),
                    port: port as i32,
                    node_id: vec![0xab; 64], // placeholder; real nodes derive from witness key
                },
                version: MAINNET_P2P_VERSION,
                timestamp_ms: now_millis(),
                genesis,
                solid: genesis,
                head: genesis,
                node_type: 0,
                lowest_block_num: 0,
                code_version: b"tron-goblin/0.0.1",
            };
            match conn.handshake(inputs).await {
                Ok(outcome) => match outcome.hello() {
                    Some(hello) => {
                        eprintln!(
                            "handshake OK with {peer_addr}: version={} head_num={} code={}",
                            hello.version,
                            hello
                                .head_block_id
                                .as_ref()
                                .map(|b| b.number)
                                .unwrap_or(-1),
                            String::from_utf8_lossy(&hello.code_version),
                        );
                    }
                    None => {
                        eprintln!(
                            "handshake OK with {peer_addr}: peer accepted implicitly (no reciprocal Hello)"
                        );
                    }
                },
                Err(e) => {
                    eprintln!("handshake FAILED with {peer_addr}: {e}");
                }
            }
            if once {
                break;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}


// --- execute ----------------------------------------------------------------

fn cmd_execute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use tron_chainbase::{KvBackend, MemBackend};
    use tron_executor::{execute_block, StateBackends};

    let path = args.first().ok_or("execute needs a PATH")?;
    let mut reader = BufReader::new(File::open(path)?);

    // Fresh in-memory state per store. The executor forks a session
    // per tx automatically, so failures don't leak across tx
    // boundaries.
    let m = || -> Arc<dyn KvBackend> { Arc::new(MemBackend::new()) };
    let state = StateBackends {
        accounts: m(),
        witnesses: m(),
        votes: m(),
        delegation: m(),
        delegated_resources: m(),
        dyn_props: m(),
        proposals: m(),
        name_index: m(),
        id_index: m(),
        asset_v1: m(),
        asset_v2: m(),
        contracts: m(),
        abi: m(),
        exchange_v1: m(),
        exchange_v2: m(),
        market_orders: m(),
        nullifiers: m(),
        merkle_trees: None,
        code: Some(m()),
        storage_row: Some(m()),
        contract_state: Some(m()),
        block_index: Some(m()),
        witness_schedule: Some(m()),
    };

    let mut blocks_ok = 0usize;
    let mut blocks_failed = 0usize;
    let mut tx_ok = 0usize;
    let mut tx_failed = 0usize;
    let mut prev_id: Option<BlockId> = None;

    loop {
        match read_frame(&mut reader)? {
            Frame::Eof => break,
            Frame::Undecodable(reason) => {
                blocks_failed += 1;
                eprintln!("undecodable block: {reason}");
                continue;
            }
            Frame::Block(block) => match execute_block(&state, &block, prev_id) {
                Ok(report) => {
                    blocks_ok += 1;
                    tx_ok += report.successes();
                    tx_failed += report.failures();
                    prev_id = Some(report.block_id);
                }
                Err(e) => {
                    blocks_failed += 1;
                    eprintln!("block execution aborted: {e}");
                    // Don't advance prev_id — the chain is broken from
                    // here, subsequent blocks will fail parent_link too.
                }
            },
        }
    }

    println!("blocks_ok:     {blocks_ok}");
    println!("blocks_failed: {blocks_failed}");
    println!("tx_ok:         {tx_ok}");
    println!("tx_failed:     {tx_failed}");
    if blocks_failed > 0 {
        Err("at least one block failed execution".into())
    } else {
        Ok(())
    }
}

// --- verify -----------------------------------------------------------------

#[derive(Default)]
struct Stats {
    valid: usize,
    invalid: usize,
    first_error: Option<String>,
}

impl Stats {
    fn report(&self) -> String {
        let mut s = format!(
            "valid: {}\ninvalid: {}\ntotal: {}",
            self.valid,
            self.invalid,
            self.valid + self.invalid
        );
        if let Some(e) = &self.first_error {
            s.push_str(&format!("\nfirst error: {e}"));
        }
        s
    }
}

fn cmd_verify(args: &[String]) -> Result<Stats, Box<dyn std::error::Error>> {
    let path = args.first().ok_or("verify needs a PATH")?;
    let mut reader = BufReader::new(File::open(path)?);

    let mut stats = Stats::default();
    let mut prev_id: Option<BlockId> = None;
    loop {
        match read_frame(&mut reader)? {
            Frame::Eof => break,
            Frame::Block(block) => match validate_block(&block, prev_id) {
                Ok(id) => {
                    stats.valid += 1;
                    prev_id = Some(id);
                }
                Err(e) => {
                    stats.invalid += 1;
                    if stats.first_error.is_none() {
                        stats.first_error = Some(e);
                    }
                    // Don't advance prev_id — a bad block is treated as a
                    // gap. The next valid block must still parent to the
                    // previous valid block.
                }
            },
            Frame::Undecodable(reason) => {
                // Frame size was readable but the bytes inside don't decode
                // as a Block. The length prefix told us where the frame
                // ends, so we've already consumed it; keep going.
                stats.invalid += 1;
                if stats.first_error.is_none() {
                    stats.first_error = Some(format!("decode: {reason}"));
                }
            }
        }
    }
    Ok(stats)
}

enum Frame {
    Eof,
    Block(Block),
    Undecodable(String),
}

fn validate_block(block: &Block, expected_parent: Option<BlockId>) -> Result<BlockId, String> {
    if let Some(parent) = expected_parent {
        verify_parent_link(block, parent).map_err(|e| format!("parent link: {e}"))?;
    }
    verify_tx_trie_root(block).map_err(|e| format!("tx trie root: {e}"))?;
    verify_witness_signature(block, None).map_err(|e| format!("witness sig: {e}"))?;
    block_id_from_block(block).map_err(|e| format!("block id: {e}"))
}

// --- length-delimited framing ----------------------------------------------

fn write_block<W: Write + ?Sized>(w: &mut W, block: &Block) -> io::Result<()> {
    let bytes = block.encode_to_vec();
    let len = u32::try_from(bytes.len()).expect("block fits in u32");
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&bytes)?;
    Ok(())
}

fn read_frame<R: Read>(r: &mut R) -> io::Result<Frame> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Frame::Eof),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    match Block::decode(buf.as_slice()) {
        Ok(block) => Ok(Frame::Block(block)),
        Err(e) => Ok(Frame::Undecodable(e.to_string())),
    }
}

// --- synthetic chain builder -----------------------------------------------

/// Build a chain of `count` blocks, all signed by the same witness. Block 0
/// is a "genesis-like" block (no parent constraint); blocks 1..count link
/// via `parent_hash`.
fn build_chain(count: u32) -> Vec<Block> {
    // Deterministic witness key — the same fixture our crypto tests use.
    let priv_key: [u8; 32] =
        hex::decode("1234567890123456789012345678901234567890123456789012345678901234")
            .unwrap()
            .try_into()
            .unwrap();
    let witness_addr = derive_address(&priv_key);

    let mut blocks = Vec::with_capacity(count as usize);
    let mut prev_id = BlockId::from_raw([0u8; 32]);

    for n in 0..count as i64 {
        // Two TRX transactions per block, just to exercise the merkle root.
        let txs = vec![sample_tx(n, 1), sample_tx(n, 2)];
        let tx_root = calc_tx_trie_root(&txs).map(|h| h.to_vec()).unwrap_or_default();

        let mut block = Block {
            transactions: txs,
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    timestamp: 1_700_000_000_000 + n * 3_000,
                    tx_trie_root: tx_root,
                    parent_hash: prev_id.as_bytes().to_vec(),
                    number: n,
                    witness_id: 0,
                    witness_address: witness_addr.as_bytes().to_vec(),
                    version: 28,
                    account_state_root: Vec::new(),
                }),
                witness_signature: Vec::new(),
            }),
        };
        sign_block(&mut block, &priv_key).expect("sign");

        prev_id = block_id_from_block(&block).expect("id");
        blocks.push(block);
    }
    blocks
}

fn sample_tx(block_num: i64, index_in_block: u8) -> Transaction {
    let tc = TransferContract {
        owner_address: vec![0x41; 21],
        to_address: vec![0x41; 21],
        amount: (block_num * 100 + index_in_block as i64).max(1),
    };
    Transaction {
        raw_data: Some(TxRaw {
            ref_block_bytes: vec![block_num as u8, index_in_block],
            ref_block_num: block_num,
            ref_block_hash: vec![0u8; 8],
            expiration: 1_700_000_000_000,
            auths: Vec::new(),
            data: Vec::new(),
            contract: vec![Contract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                provider: Vec::new(),
                contract_name: Vec::new(),
                permission_id: 0,
            }],
            scripts: Vec::new(),
            timestamp: 1_700_000_000_000 + block_num,
            fee_limit: 0,
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    }
}

fn derive_address(priv_key: &[u8; 32]) -> Address {
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes(priv_key.into()).expect("priv key");
    let vk = sk.verifying_key();
    let enc = vk.to_encoded_point(false);
    let bytes = enc.as_bytes();
    // bytes is 65 bytes: [0x04, X(32), Y(32)]; strip the 0x04 and run
    // through the canonical address derivation.
    let mut prefixed = [0u8; 21];
    prefixed[0] = 0x41;
    let h = keccak256(&bytes[1..]);
    prefixed[1..].copy_from_slice(&h[12..32]);
    Address::from_raw(prefixed)
}
