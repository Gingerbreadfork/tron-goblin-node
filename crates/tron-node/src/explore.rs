//! `--explore` mode: the live TRON mainnet feed dashboard.
//!
//! The node bootstraps from a real recent tip (see `runtime`/`--explore`),
//! follows the live block tail decode-only, and feeds every block into a
//! shared [`ExploreState`]. A renderer task paints a self-updating terminal
//! dashboard from that state — real blocks landing every ~3s, real txs decoded
//! and classified, running session totals, a live feed, a block-size
//! sparkline, and milestone / whale flashes. No execution, no state, no
//! snapshot: just the real chain, streaming in seconds after launch.
//!
//! Nothing here is on the hot consensus path — it's a read-only viewer.

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use prost::Message;
use tron_proto::{
    transaction::contract::ContractType, AssetIssueContract, Block, CreateSmartContract,
    TransferContract, TriggerSmartContract,
};

/// USDT (Tether) TRC-20 contract on TRON, 21-byte (0x41-prefixed) address.
/// `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` — the single most-used contract on the
/// network, so flagging calls to it makes the live feed instantly relatable.
const USDT_ADDRESS_HEX: &str = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";
const SUN_PER_TRX: u128 = 1_000_000;
/// USDT has 6 decimals, so 1 USDT == 1_000_000 base units.
const USDT_UNITS_PER_DOLLAR: u128 = 1_000_000;
/// ERC-20/TRC-20 selectors we recognise to pull a transfer amount out of the
/// `TriggerSmartContract` calldata.
const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom(address,address,uint256)
/// Flash a whale milestone once a single USDT transfer crosses this ($).
const WHALE_USD: u128 = 100_000;
/// Cap the unique-wallet set so a viewer left running for days can't grow it
/// without bound (the count just stops climbing past this).
const MAX_WALLETS: usize = 2_000_000;

// ----- ANSI ---------------------------------------------------------------
const RST: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[38;5;203m";
const GRN: &str = "\x1b[38;5;47m";
const YEL: &str = "\x1b[38;5;221m";
const CYN: &str = "\x1b[38;5;87m";
const MAG: &str = "\x1b[38;5;213m";
const GRY: &str = "\x1b[38;5;245m";
const ORG: &str = "\x1b[38;5;215m";

/// One streamed block, summarised for the live feed.
#[derive(Clone)]
struct FeedBlock {
    num: i64,
    txs: u64,
    usdt: u64,
    usdt_units: u128,
    trx: u128, // sun
    new_contract: bool,
}

/// A celebratory one-liner shown in the milestone panel.
#[derive(Clone)]
struct Milestone {
    icon: &'static str,
    text: String,
}

struct Inner {
    cursor: i64, // highest block observed (dedup)
    // running session totals
    blocks: u64,
    txs: u64,
    trx_sun: u128,
    transfers: u64,
    calls: u64,
    usdt_transfers: u64,
    usdt_units: u128, // total USDT moved, in 6-decimal base units
    token_transfers: u64,
    contracts_created: u64,
    tokens_issued: u64,
    votes: u64,
    stakes: u64,
    wallets: HashSet<Vec<u8>>,
    // latest / extremes
    last_num: i64,
    last_ts: i64,
    biggest_txs: u64,
    biggest_num: i64,
    biggest_usdt_units: u128,
    live: bool,
    peak_tps: f64,
    // presentation
    peers: HashSet<String>,
    /// (arrival_ms, tx_count) per block, trimmed to a ~10s window, for live
    /// TPS + blocks/sec.
    arrivals: VecDeque<(i64, u64)>,
    /// Recent per-block tx counts for the sparkline (newest last).
    spark: VecDeque<u64>,
    feed: VecDeque<FeedBlock>,
    milestones: VecDeque<Milestone>,
    seen: HashSet<String>,
}

pub struct ExploreState {
    inner: Mutex<Inner>,
    start: Instant,
}

impl ExploreState {
    pub fn new(tip_at_start: i64) -> Self {
        let mut inner = Inner {
            cursor: 0,
            blocks: 0,
            txs: 0,
            trx_sun: 0,
            transfers: 0,
            calls: 0,
            usdt_transfers: 0,
            usdt_units: 0,
            token_transfers: 0,
            contracts_created: 0,
            tokens_issued: 0,
            votes: 0,
            stakes: 0,
            wallets: HashSet::new(),
            last_num: tip_at_start,
            last_ts: 0,
            biggest_txs: 0,
            biggest_num: 0,
            biggest_usdt_units: 0,
            live: false,
            peak_tps: 0.0,
            peers: HashSet::new(),
            arrivals: VecDeque::new(),
            spark: VecDeque::new(),
            feed: VecDeque::with_capacity(8),
            milestones: VecDeque::with_capacity(8),
            seen: HashSet::new(),
        };
        inner.push_milestone(
            "🌅",
            format!("Tuned into TRON mainnet at block #{}", commas(tip_at_start)),
        );
        Self {
            inner: Mutex::new(inner),
            start: Instant::now(),
        }
    }

    /// Record a peer we successfully handshook (for the live peer count).
    pub fn note_peer(&self, peer: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.peers.insert(peer.to_string());
        }
    }

    /// Fold one streamed block into the session stats. Deduped by block
    /// number, so the 24 rotation drivers can all call it safely — only
    /// forward progress past the cursor counts.
    pub fn observe_block(&self, block: &Block, block_num: i64, peer: &str, now_ms: i64) {
        let Ok(mut g) = self.inner.lock() else { return };
        if block_num <= g.cursor {
            return;
        }
        g.cursor = block_num;

        let ts = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.timestamp)
            .unwrap_or(0);

        let mut b_txs = 0u64;
        let mut b_usdt = 0u64;
        let mut b_usdt_units = 0u128;
        let mut b_trx = 0u128;
        let mut b_new_contract = false;
        let mut whale: Option<u128> = None;

        for tx in &block.transactions {
            b_txs += 1;
            let Some(raw) = tx.raw_data.as_ref() else { continue };
            let Some(contract) = raw.contract.first() else {
                continue;
            };
            let param = contract
                .parameter
                .as_ref()
                .map(|p| p.value.as_slice())
                .unwrap_or(&[]);
            match ContractType::try_from(contract.r#type).ok() {
                Some(ContractType::TransferContract) => {
                    g.transfers += 1;
                    if let Ok(c) = TransferContract::decode(param) {
                        if c.amount > 0 {
                            b_trx += c.amount as u128;
                        }
                        note_wallet(&mut g.wallets, &c.owner_address);
                    }
                }
                Some(ContractType::TransferAssetContract) => {
                    g.token_transfers += 1;
                }
                Some(ContractType::TriggerSmartContract) => {
                    g.calls += 1;
                    if let Ok(c) = TriggerSmartContract::decode(param) {
                        if c.call_value > 0 {
                            b_trx += c.call_value as u128;
                        }
                        note_wallet(&mut g.wallets, &c.owner_address);
                        if hex::encode(&c.contract_address) == USDT_ADDRESS_HEX {
                            g.usdt_transfers += 1;
                            b_usdt += 1;
                            if let Some(units) = usdt_amount(&c.data) {
                                b_usdt_units += units;
                                if units > g.biggest_usdt_units {
                                    g.biggest_usdt_units = units;
                                    if units / USDT_UNITS_PER_DOLLAR >= WHALE_USD {
                                        whale = Some(units);
                                    }
                                }
                            }
                        }
                    }
                }
                Some(ContractType::CreateSmartContract) => {
                    g.contracts_created += 1;
                    b_new_contract = true;
                    let name = CreateSmartContract::decode(param)
                        .ok()
                        .and_then(|c| c.new_contract.map(|n| n.name))
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| "unnamed".into());
                    g.push_milestone(
                        "📜",
                        format!(
                            "Smart contract \"{}\" deployed @ #{}",
                            trunc(&name, 22),
                            commas(block_num)
                        ),
                    );
                }
                Some(ContractType::AssetIssueContract) => {
                    g.tokens_issued += 1;
                    let name = AssetIssueContract::decode(param)
                        .ok()
                        .map(|c| String::from_utf8_lossy(&c.name).into_owned())
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| "?".into());
                    g.push_milestone(
                        "🪙",
                        format!("New TRC-10 token issued: \"{}\"", trunc(&name, 22)),
                    );
                }
                Some(ContractType::VoteWitnessContract) => g.votes += 1,
                Some(ContractType::FreezeBalanceV2Contract)
                | Some(ContractType::FreezeBalanceContract)
                | Some(ContractType::DelegateResourceContract) => g.stakes += 1,
                _ => {}
            }
        }

        g.blocks += 1;
        g.txs += b_txs;
        g.trx_sun += b_trx;
        g.usdt_units += b_usdt_units;
        g.arrivals.push_back((now_ms, b_txs));
        while g.arrivals.front().is_some_and(|&(t, _)| t < now_ms - 10_000) {
            g.arrivals.pop_front();
        }
        g.spark.push_back(b_txs);
        while g.spark.len() > 30 {
            g.spark.pop_front();
        }
        g.last_num = block_num;
        g.last_ts = ts;
        if b_txs > g.biggest_txs {
            g.biggest_txs = b_txs;
            g.biggest_num = block_num;
        }

        g.feed.push_front(FeedBlock {
            num: block_num,
            txs: b_txs,
            usdt: b_usdt,
            usdt_units: b_usdt_units,
            trx: b_trx,
            new_contract: b_new_contract,
        });
        while g.feed.len() > 5 {
            g.feed.pop_back();
        }

        // Milestones.
        if let Some(units) = whale {
            g.push_milestone(
                "🐋",
                format!("Whale: {} USDT in a single transfer (#{})", usd(units), commas(block_num)),
            );
        }
        let age = (now_ms - ts).max(0);
        if !g.live && ts > 0 && age <= 8_000 {
            g.live = true;
            g.push_milestone(
                "🟢",
                "Riding the live tip — new blocks the moment they're minted".into(),
            );
        }
        if b_txs >= 800 {
            g.push_milestone_once(
                "busiest",
                "🚀",
                format!("Heavy block: {} txs in 3 seconds (#{})", b_txs, commas(block_num)),
            );
        }
        for (thresh, label) in [
            (100_000u64, "100K"),
            (500_000, "500K"),
            (1_000_000, "1M"),
            (5_000_000, "5M"),
        ] {
            if g.txs >= thresh {
                g.push_milestone_once(
                    &format!("txs{thresh}"),
                    "🔄",
                    format!("{label} transactions decoded this session"),
                );
            }
        }
        for (thresh, label) in [(1u128, "$1M"), (10, "$10M"), (100, "$100M")] {
            if g.usdt_units / USDT_UNITS_PER_DOLLAR >= thresh * 1_000_000 {
                g.push_milestone_once(
                    &format!("usd{thresh}"),
                    "💸",
                    format!("{label} of USDT moved this session"),
                );
            }
        }
        let _ = peer;
    }

    /// Build a full dashboard frame for the given wall-clock time.
    pub fn render(&self, now_ms: i64) -> String {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return String::new(),
        };
        // Live TPS + blocks/sec over the trailing ~10s arrival window.
        let win_lo = now_ms - 10_000;
        let (mut win_txs, mut win_blocks) = (0u64, 0u64);
        for &(t, n) in g.arrivals.iter() {
            if t >= win_lo {
                win_txs += n;
                win_blocks += 1;
            }
        }
        let span = g
            .arrivals
            .front()
            .map(|&(f, _)| ((now_ms - f.max(win_lo)) as f64 / 1000.0).max(1.0))
            .unwrap_or(1.0);
        let tps = win_txs as f64 / span;
        let blk_per_s = win_blocks as f64 / span;
        // Only track the peak during steady live cadence (~1 block / 3s, i.e.
        // blk/s well under 1). The brief bootstrap catch-up burst processes
        // several blocks in a fraction of a second and would otherwise post a
        // wildly unrealistic TPS spike that misrepresents mainnet.
        if g.live && blk_per_s <= 1.0 && tps > g.peak_tps {
            g.peak_tps = tps;
        }
        let peak_tps = g.peak_tps;

        let w = 64;
        let mut s = String::new();
        s.push_str("\x1b[H");

        // Header
        s.push_str(&line(&format!(
            "{RED}{BOLD}🧌 TRON GOBLIN{RST}  {DIM}·{RST}  {ORG}{BOLD}MAINNET LIVE FEED{RST}"
        )));
        s.push_str(&rule(w));

        // Status: date + block + live/catching-up
        let age = (now_ms - g.last_ts).max(0);
        let when = utc(g.last_ts);
        let (status_c, status) = if g.last_ts == 0 {
            (YEL, "connecting…".to_string())
        } else if age <= 8_000 {
            (GRN, "🟢 LIVE".to_string())
        } else {
            (YEL, format!("syncing the live edge · {} behind", dur(age)))
        };
        s.push_str(&line(&format!(
            "  {CYN}📅 {when}{RST}      {BOLD}block #{}{RST}",
            commas(g.last_num)
        )));
        let peak_str = if peak_tps >= 1.0 {
            format!(" {DIM}· peak {:.0}{RST}", peak_tps)
        } else {
            String::new()
        };
        s.push_str(&line(&format!(
            "  {status_c}{status}{RST}    {MAG}⚡ {:.0} TPS{RST}{peak_str}    {GRY}📦 {:.1} blk/s · 🔗 {} peers{RST}",
            tps,
            blk_per_s,
            g.peers.len().max(1)
        )));
        // Session uptime + blocks watched.
        s.push_str(&line(&format!(
            "  {GRY}⏱ watching {} · 📦 {} blocks streamed{RST}",
            dur(self.start.elapsed().as_millis() as i64),
            commas(g.blocks as i64)
        )));
        // Block-size sparkline.
        if !g.spark.is_empty() {
            s.push_str(&line(&format!(
                "  {DIM}block sizes{RST} {GRN}{}{RST}  {GRY}(txs/block, last {}){RST}",
                sparkline(&g.spark),
                g.spark.len()
            )));
        }
        s.push_str(&blank());

        // Session totals (two columns)
        s.push_str(&section("THIS SESSION", w));
        s.push_str(&row2(
            "🔄", "transactions", &commas(g.txs as i64),
            "👛", "active wallets", &compact(g.wallets.len() as u128),
        ));
        s.push_str(&row2(
            "💵", "TRX moved", &human_trx(g.trx_sun),
            "💚", "USDT volume", &usd(g.usdt_units),
        ));
        s.push_str(&row2(
            "📜", "contract calls", &commas(g.calls as i64),
            "💸", "USDT transfers", &commas(g.usdt_transfers as i64),
        ));
        s.push_str(&row2(
            "🪙", "token transfers", &commas(g.token_transfers as i64),
            "🗳", "votes+stakes", &commas((g.votes + g.stakes) as i64),
        ));
        s.push_str(&row2(
            "🚀", "busiest block", &format!("{} txs", commas(g.biggest_txs as i64)),
            "🐋", "biggest USDT", &usd(g.biggest_usdt_units),
        ));
        s.push_str(&blank());

        // Tx-type mix — a stacked, colored bar of what this session is made of.
        s.push_str(&section("TX MIX", w));
        let trx_c = g.transfers;
        let usdt_c = g.usdt_transfers;
        let tok_c = g.token_transfers;
        // Everything else: non-USDT contract calls, votes, stakes, misc.
        let oth_c = g
            .txs
            .saturating_sub(trx_c.saturating_add(usdt_c).saturating_add(tok_c));
        let parts = [(trx_c, CYN), (usdt_c, GRN), (tok_c, YEL), (oth_c, MAG)];
        s.push_str(&line(&format!("   {}", mix_bar(&parts, 46))));
        let tot = g.txs.max(1);
        let pct = |c: u64| c.saturating_mul(100) / tot;
        s.push_str(&line(&format!(
            "   {CYN}▪ TRX {}%{RST}   {GRN}▪ USDT {}%{RST}   {YEL}▪ tokens {}%{RST}   {MAG}▪ other {}%{RST}",
            pct(trx_c), pct(usdt_c), pct(tok_c), pct(oth_c)
        )));
        s.push_str(&blank());

        // Live feed
        s.push_str(&section("BLOCK STREAM", w));
        if g.feed.is_empty() {
            s.push_str(&line(&format!("   {DIM}waiting for the next block…{RST}")));
        }
        for fb in g.feed.iter() {
            let mut extra = String::new();
            if fb.usdt > 0 {
                extra.push_str(&format!(" {GRN}· {} USDT{RST}", fb.usdt));
            }
            if fb.usdt_units >= USDT_UNITS_PER_DOLLAR {
                extra.push_str(&format!(" {GRN}{}{RST}", usd(fb.usdt_units)));
            }
            if fb.trx >= SUN_PER_TRX {
                extra.push_str(&format!(" {CYN}· {} TRX{RST}", human_trx(fb.trx)));
            }
            if fb.new_contract {
                extra.push_str(&format!(" {MAG}· 📜 new contract{RST}"));
            }
            s.push_str(&line(&format!(
                "   {GRN}▸{RST} {BOLD}#{}{RST}  {} tx{extra}",
                commas(fb.num),
                fb.txs,
            )));
        }
        s.push_str(&blank());

        // Milestones
        s.push_str(&section("MILESTONES", w));
        for m in g.milestones.iter().take(4) {
            s.push_str(&line(&format!("   {} {YEL}{}{RST}", m.icon, m.text)));
        }
        s.push_str(&blank());
        s.push_str(&line(&format!(
            "  {DIM}decode-only live view · no state, no snapshot · Ctrl-C to stop{RST}"
        )));
        s.push_str("\x1b[J");
        s
    }
}

impl Inner {
    fn push_milestone(&mut self, icon: &'static str, text: String) {
        self.milestones.push_front(Milestone { icon, text });
        while self.milestones.len() > 6 {
            self.milestones.pop_back();
        }
    }
    fn push_milestone_once(&mut self, key: &str, icon: &'static str, text: String) {
        if self.seen.insert(key.to_string()) {
            self.push_milestone(icon, text);
        }
    }
}

/// Track a unique sender address (bounded, non-empty only).
fn note_wallet(set: &mut HashSet<Vec<u8>>, addr: &[u8]) {
    if !addr.is_empty() && set.len() < MAX_WALLETS {
        set.insert(addr.to_vec());
    }
}

/// Pull the transfer amount (6-decimal base units) out of a TRC-20 call's
/// calldata for `transfer(address,uint256)` / `transferFrom(...,uint256)`.
fn usdt_amount(data: &[u8]) -> Option<u128> {
    if data.len() < 4 {
        return None;
    }
    let sel = [data[0], data[1], data[2], data[3]];
    let amount_off = if sel == SEL_TRANSFER {
        4 + 32 // selector + to
    } else if sel == SEL_TRANSFER_FROM {
        4 + 32 + 32 // selector + from + to
    } else {
        return None;
    };
    let field = data.get(amount_off..amount_off + 32)?;
    // Take the low 128 bits of the uint256 (ample for any realistic amount).
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&field[16..32]);
    Some(u128::from_be_bytes(buf))
}

// ----- rendering helpers --------------------------------------------------

fn line(content: &str) -> String {
    format!("{content}\x1b[K\r\n")
}
fn blank() -> String {
    "\x1b[K\r\n".to_string()
}
fn rule(w: usize) -> String {
    line(&format!("{GRY}{}{RST}", "━".repeat(w)))
}
fn section(title: &str, w: usize) -> String {
    let dashes = w.saturating_sub(title.len() + 6);
    line(&format!("  {BOLD}{GRY}── {title} {}{RST}", "─".repeat(dashes)))
}
fn row2(i1: &str, l1: &str, v1: &str, i2: &str, l2: &str, v2: &str) -> String {
    let left = format!("{i1} {GRY}{l1}{RST} {BOLD}{v1}{RST}");
    let right = format!("{i2} {GRY}{l2}{RST} {BOLD}{v2}{RST}");
    let pad = 32usize.saturating_sub(visible_len(&left));
    line(&format!("   {left}{}{right}", " ".repeat(pad)))
}

/// A stacked, colored proportion bar: each `(count, color)` gets a slice of
/// `width` cells sized by its share of the total. The last slice absorbs any
/// rounding remainder so the bar is always exactly `width` cells wide.
fn mix_bar(parts: &[(u64, &str)], width: usize) -> String {
    let total: u64 = parts.iter().map(|(c, _)| *c).sum();
    if total == 0 {
        return format!("{DIM}{}{RST}", "░".repeat(width));
    }
    let mut bar = String::new();
    let mut used = 0usize;
    let last = parts.len() - 1;
    for (i, (count, color)) in parts.iter().enumerate() {
        let seg = if i == last {
            width - used
        } else {
            (((*count as f64) / total as f64) * width as f64).round() as usize
        }
        .min(width - used);
        if seg > 0 {
            bar.push_str(color);
            bar.push_str(&"█".repeat(seg));
        }
        used += seg;
    }
    bar.push_str(RST);
    bar
}

/// 8-level unicode sparkline from a series of counts.
fn sparkline(vals: &VecDeque<u64>) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = vals.iter().copied().max().unwrap_or(0);
    let min = vals.iter().copied().min().unwrap_or(0);
    let span = (max.saturating_sub(min)).max(1) as f64;
    vals.iter()
        .map(|&v| {
            let lvl = (((v - min) as f64 / span) * 7.0).round() as usize;
            BARS[lvl.min(7)]
        })
        .collect()
}

/// Length of a string ignoring ANSI escapes (best-effort, for column padding).
fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c == 'm' {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            n += if c as u32 >= 0x1F000 || ('\u{2190}'..='\u{2BFF}').contains(&c) {
                2
            } else {
                1
            };
        }
    }
    n
}

fn commas(n: i64) -> String {
    let neg = n < 0;
    let mut x = n.unsigned_abs();
    if x == 0 {
        return "0".into();
    }
    let mut out = Vec::new();
    let mut c = 0;
    while x > 0 {
        if c == 3 {
            out.push(b',');
            c = 0;
        }
        out.push(b'0' + (x % 10) as u8);
        x /= 10;
        c += 1;
    }
    if neg {
        out.push(b'-');
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

/// Compact human count: 8,412 / 12.4K / 1.9M.
fn compact(n: u128) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1e6)
    } else if n >= 100_000 {
        format!("{:.0}K", n as f64 / 1e3)
    } else {
        commas(n as i64)
    }
}

/// TRX amount (from sun) as a compact human string: 12.4M, 1.92B, 8,421.
fn human_trx(sun: u128) -> String {
    compact(sun / SUN_PER_TRX)
}

/// USDT (6-decimal base units) as a dollar string: $1.24M, $850K, $1,234.
fn usd(units: u128) -> String {
    let dollars = units / USDT_UNITS_PER_DOLLAR;
    format!("${}", compact(dollars))
}

fn dur(ms: i64) -> String {
    let s = ms / 1000;
    if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{}s", s)
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

/// Format a millisecond unix timestamp as `YYYY-MM-DD HH:MM:SS UTC` without
/// pulling in chrono (Howard Hinnant's civil-from-days algorithm).
fn utc(ms: i64) -> String {
    if ms <= 0 {
        return "—".into();
    }
    let secs = ms / 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, se) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{se:02} UTC")
}

/// Spawn the dashboard renderer loop. Paints a frame ~5×/s to stdout (logs go
/// to stderr, so they never collide). Returns when `shutdown` fires; restores
/// the cursor on the way out.
pub async fn run_renderer(
    state: std::sync::Arc<ExploreState>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    {
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[2J\x1b[?25l");
        let _ = out.flush();
    }
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let frame = state.render(now_ms());
                let mut out = std::io::stdout();
                let _ = out.write_all(frame.as_bytes());
                let _ = out.flush();
            }
            _ = shutdown.recv() => break,
        }
    }
    let mut out = std::io::stdout();
    let _ = out.write_all(b"\x1b[?25h\r\n");
    let _ = out.flush();
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_proto::{Block, BlockHeader};

    fn tx(ctype: ContractType, param: Vec<u8>) -> tron_proto::Transaction {
        tron_proto::Transaction {
            raw_data: Some(tron_proto::transaction::Raw {
                contract: vec![tron_proto::transaction::Contract {
                    r#type: ctype as i32,
                    parameter: Some(prost_types::Any {
                        type_url: String::new(),
                        value: param,
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A USDT `transfer(to, amount)` calldata blob for `amount` base units.
    fn usdt_transfer_data(units: u128) -> Vec<u8> {
        let mut d = SEL_TRANSFER.to_vec();
        d.extend_from_slice(&[0u8; 32]); // to
        let mut amt = [0u8; 32];
        amt[16..32].copy_from_slice(&units.to_be_bytes());
        d.extend_from_slice(&amt);
        d
    }

    #[test]
    fn observe_block_classifies_txs_detects_usdt_volume_and_dedups() {
        let st = ExploreState::new(100);
        let transfer = TransferContract {
            amount: 5_000_000, // 5 TRX
            owner_address: vec![0x41; 21],
            ..Default::default()
        }
        .encode_to_vec();
        let usdt = TriggerSmartContract {
            contract_address: hex::decode(USDT_ADDRESS_HEX).unwrap(),
            owner_address: vec![0x42; 21],
            data: usdt_transfer_data(250_000 * USDT_UNITS_PER_DOLLAR), // $250k (whale)
            ..Default::default()
        }
        .encode_to_vec();
        let other_call = TriggerSmartContract {
            contract_address: vec![0x41; 21],
            owner_address: vec![0x42; 21], // same wallet as the USDT tx
            ..Default::default()
        }
        .encode_to_vec();
        let block = Block {
            block_header: Some(BlockHeader {
                raw_data: Some(tron_proto::block_header::Raw {
                    number: 101,
                    timestamp: 1_700_000_000_000,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            transactions: vec![
                tx(ContractType::TransferContract, transfer),
                tx(ContractType::TriggerSmartContract, usdt),
                tx(ContractType::TriggerSmartContract, other_call),
            ],
        };

        st.observe_block(&block, 101, "peer", 1_700_000_003_000);
        {
            let g = st.inner.lock().unwrap();
            assert_eq!(g.txs, 3, "all txs counted");
            assert_eq!(g.transfers, 1, "one TRX transfer");
            assert_eq!(g.calls, 2, "two contract calls");
            assert_eq!(g.usdt_transfers, 1, "exactly the USDT call detected");
            assert_eq!(g.trx_sun, 5_000_000, "5 TRX moved");
            assert_eq!(g.usdt_units, 250_000 * USDT_UNITS_PER_DOLLAR, "$250k USDT decoded");
            assert_eq!(g.wallets.len(), 2, "two unique senders (0x41.., 0x42..)");
            assert_eq!(g.last_num, 101);
            assert_eq!(g.biggest_txs, 3);
        }

        // Re-observing the same (or lower) block number is a no-op.
        st.observe_block(&block, 101, "peer", 1_700_000_003_000);
        assert_eq!(st.inner.lock().unwrap().txs, 3, "dedup by block number");
    }

    #[test]
    fn utc_formats_a_known_instant() {
        assert_eq!(utc(1_700_000_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(utc(0), "—");
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(commas(1_234_567), "1,234,567");
        assert_eq!(human_trx(5_716_000_000), "5,716"); // sun -> 5,716 TRX
        assert_eq!(human_trx(8_420_000_000_000), "8.42M");
        assert_eq!(usd(1_240_000 * USDT_UNITS_PER_DOLLAR), "$1.24M");
        assert_eq!(usd(850_000 * USDT_UNITS_PER_DOLLAR), "$850K");
    }

    #[test]
    fn usdt_amount_decodes_transfer_and_transfer_from() {
        assert_eq!(usdt_amount(&usdt_transfer_data(1_000_000)), Some(1_000_000));
        let mut tf = SEL_TRANSFER_FROM.to_vec();
        tf.extend_from_slice(&[0u8; 32]); // from
        tf.extend_from_slice(&[0u8; 32]); // to
        let mut amt = [0u8; 32];
        amt[16..32].copy_from_slice(&777u128.to_be_bytes());
        tf.extend_from_slice(&amt);
        assert_eq!(usdt_amount(&tf), Some(777));
        assert_eq!(usdt_amount(&[0u8; 8]), None, "unknown selector");
    }
}
