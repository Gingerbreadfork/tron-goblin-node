//! `--mempool` mode: the live decoded mempool feed dashboard.
//!
//! Where `--explore` shows the chain's confirmed blocks streaming in, this
//! mode shows what's *about to* land: the pending transactions peers are
//! broadcasting before any SR has mined them. The node bootstraps from a real
//! recent tip (the same path `--explore` uses), follows the live tail
//! decode-only, and every accepted pending tx the sync driver submits to the
//! shared mempool is decoded, classified (TRX / USDT / contract call), and
//! folded into a shared [`MempoolState`]. A renderer task paints a
//! self-updating terminal dashboard from that state — pending txs the instant
//! they arrive, arrival TPS, pending USDT/TRX volume, the hottest methods and
//! target contracts, DEX-swap counts, and whale alerts.
//!
//! This gives MEV / ops visibility (pending swaps, large transfers, contract
//! hotspots, time-in-mempool) that java-tron does not expose. An optional JSONL
//! feed mirrors every decoded pending tx to a file or stdout for tooling.
//!
//! Nothing here is on the hot consensus path — it's a read-only viewer. The
//! decode and render primitives are shared with [`crate::explore`] so the two
//! dashboards stay visually consistent.

use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use prost::Message;
use tron_mempool::{PendingTx, TxMempool};
use tron_proto::{
    transaction::contract::ContractType, TransferAssetContract, TransferContract, Transaction,
    TriggerSmartContract,
};

use crate::explore::{
    blank, commas, compact, dur, human_trx, line, method_name, mix_bar, now_ms, row2, rule,
    section, short_addr, sparkline, term_cols, usd, usdt_amount, visible_len, BOLD, CYN, DIM, GRN,
    GRY, MAG, ORG, RED, RST, SUN_PER_TRX, USDT_ADDRESS_HEX, USDT_UNITS_PER_DOLLAR, YEL,
};

/// Most recent decoded pending txs kept for the live feed.
const FEED_CAP: usize = 12;
/// Trailing window for the arrival-rate (pending TPS) calculation.
const TPS_WINDOW_MS: i64 = 10_000;
/// Flash a whale alert once a single USDT transfer crosses this ($).
const WHALE_USD: u128 = 100_000;
/// Flash a whale alert once a single native TRX transfer/call crosses this.
const WHALE_TRX: u128 = 1_000_000;
/// AMM/router `swap*` selectors that mark a pending tx as a DEX swap. These are
/// the same selectors [`method_name`] labels "swap"; collected here so the
/// observer can count them without string-matching the rendered name.
const SWAP_SELECTORS: [[u8; 4]; 4] = [
    [0x38, 0xed, 0x17, 0x39],
    [0x18, 0xcb, 0xaf, 0xe5],
    [0x7f, 0xf3, 0x6a, 0xb5],
    [0xfb, 0x3b, 0xdb, 0x41],
];

/// How a single pending transaction classifies for the dashboard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxKind {
    /// Native `TransferContract` — TRX moving wallet to wallet.
    Trx,
    /// `TriggerSmartContract` calling the USDT TRC-20 contract.
    Usdt,
    /// Any other `TriggerSmartContract` (DEX, dApp, generic TRC-20).
    Call,
    /// `TransferAssetContract` — a TRC-10 token transfer.
    Token,
    /// Everything else (votes, staking, contract creation, …).
    Other,
}

impl TxKind {
    /// Short, fixed tag for the feed line.
    fn tag(self) -> &'static str {
        match self {
            TxKind::Trx => "TRX",
            TxKind::Usdt => "USDT",
            TxKind::Call => "CALL",
            TxKind::Token => "TKN",
            TxKind::Other => "···",
        }
    }
    /// Display color for the tag, matching the `--explore` palette.
    fn color(self) -> &'static str {
        match self {
            TxKind::Trx => CYN,
            TxKind::Usdt => GRN,
            TxKind::Call => MAG,
            TxKind::Token => YEL,
            TxKind::Other => GRY,
        }
    }
}

/// A pending transaction decoded down to the fields the dashboard and the JSONL
/// feed care about. Produced by [`decode_tx_summary`] from a bare
/// [`Transaction`] — no chain state required.
#[derive(Clone, Debug)]
pub struct TxSummary {
    pub kind: TxKind,
    /// Destination (transfer recipient or called contract), 21 bytes, if any.
    pub to: Option<Vec<u8>>,
    /// Native value moved, in sun (`TransferContract.amount` /
    /// `TriggerSmartContract.call_value`).
    pub amount_sun: u128,
    /// USDT amount decoded from the calldata, in 6-decimal base units, when the
    /// tx is a USDT `transfer` / `transferFrom`.
    pub usdt_units: Option<u128>,
    /// Called contract address (21 bytes) for a `TriggerSmartContract`.
    pub contract: Option<Vec<u8>>,
    /// Decoded method name from the 4-byte selector, for a contract call.
    pub method: Option<String>,
    /// Raw 4-byte selector, kept so the observer can match swap selectors.
    pub selector: Option<[u8; 4]>,
}

/// Decode the first contract of a pending [`Transaction`] into a [`TxSummary`].
/// Mirrors the per-tx switch in `explore::observe_block`, but operates on a
/// standalone transaction (the mempool hands us one tx at a time, not a block).
pub fn decode_tx_summary(tx: &Transaction) -> TxSummary {
    let mut s = TxSummary {
        kind: TxKind::Other,
        to: None,
        amount_sun: 0,
        usdt_units: None,
        contract: None,
        method: None,
        selector: None,
    };
    let Some(raw) = tx.raw_data.as_ref() else {
        return s;
    };
    let Some(contract) = raw.contract.first() else {
        return s;
    };
    let param = contract
        .parameter
        .as_ref()
        .map(|p| p.value.as_slice())
        .unwrap_or(&[]);
    match ContractType::try_from(contract.r#type).ok() {
        Some(ContractType::TransferContract) => {
            s.kind = TxKind::Trx;
            if let Ok(c) = TransferContract::decode(param) {
                s.amount_sun = c.amount.max(0) as u128;
                s.to = Some(c.to_address);
            }
        }
        Some(ContractType::TransferAssetContract) => {
            s.kind = TxKind::Token;
            if let Ok(c) = TransferAssetContract::decode(param) {
                s.amount_sun = c.amount.max(0) as u128;
                s.to = Some(c.to_address);
            }
        }
        Some(ContractType::TriggerSmartContract) => {
            s.kind = TxKind::Call;
            if let Ok(c) = tron_proto::decode_lenient::<TriggerSmartContract>(param) {
                s.amount_sun = c.call_value.max(0) as u128;
                if c.data.len() >= 4 {
                    let sel = [c.data[0], c.data[1], c.data[2], c.data[3]];
                    s.selector = Some(sel);
                    s.method = Some(method_name(&sel));
                }
                if hex::encode(&c.contract_address) == USDT_ADDRESS_HEX {
                    s.kind = TxKind::Usdt;
                    s.usdt_units = usdt_amount(&c.data);
                }
                s.to = Some(c.contract_address.clone());
                s.contract = Some(c.contract_address);
            }
        }
        _ => {}
    }
    s
}

/// One pending tx as shown in the live feed (newest first).
#[derive(Clone)]
struct FeedTx {
    tx_id: [u8; 32],
    received_at_ms: i64,
    signer: Option<[u8; 21]>,
    kind: TxKind,
    amount_sun: u128,
    usdt_units: Option<u128>,
    to: Option<Vec<u8>>,
    method: Option<String>,
}

/// A whale alert one-liner shown in the alerts panel.
#[derive(Clone)]
struct Alert {
    icon: &'static str,
    text: String,
}

struct Inner {
    // running session totals
    seen: u64,
    trx_count: u64,
    usdt_count: u64,
    call_count: u64,
    token_count: u64,
    other_count: u64,
    trx_sun: u128,
    usdt_units: u128,
    swaps: u64,
    /// Pending txs the broadcast channel dropped because we couldn't keep up.
    lagged: u64,
    /// Highest single USDT transfer / TRX move observed this session.
    biggest_usdt_units: u128,
    biggest_trx_sun: u128,
    /// Contract-call methods by 4-byte selector.
    methods: HashMap<[u8; 4], u64>,
    /// Target contracts by 21-byte address.
    contracts: HashMap<Vec<u8>, u64>,
    /// (arrival_ms) per pending tx, trimmed to the TPS window.
    arrivals: VecDeque<i64>,
    /// Per-tx counts over the recent window for the sparkline (newest last).
    spark: VecDeque<u64>,
    /// Bucketed arrival counts feeding the sparkline (1s buckets).
    spark_bucket_ms: i64,
    spark_bucket_count: u64,
    feed: VecDeque<FeedTx>,
    alerts: VecDeque<Alert>,
}

pub struct MempoolState {
    inner: Mutex<Inner>,
    start: Instant,
    /// Spoofed tip height we bootstrapped at, for the header.
    tip_at_start: i64,
}

impl MempoolState {
    pub fn new(tip_at_start: i64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                seen: 0,
                trx_count: 0,
                usdt_count: 0,
                call_count: 0,
                token_count: 0,
                other_count: 0,
                trx_sun: 0,
                usdt_units: 0,
                swaps: 0,
                lagged: 0,
                biggest_usdt_units: 0,
                biggest_trx_sun: 0,
                methods: HashMap::new(),
                contracts: HashMap::new(),
                arrivals: VecDeque::new(),
                spark: VecDeque::new(),
                spark_bucket_ms: 0,
                spark_bucket_count: 0,
                feed: VecDeque::with_capacity(FEED_CAP),
                alerts: VecDeque::with_capacity(8),
            }),
            start: Instant::now(),
            tip_at_start,
        }
    }

    /// Record that the broadcast channel dropped `n` pending txs because the
    /// observer fell behind (the txs stay in the mempool — only the
    /// notification is lost). Surfaced in the header so the rates stay honest.
    pub fn note_lagged(&self, n: u64) {
        if let Ok(mut g) = self.inner.lock() {
            g.lagged = g.lagged.saturating_add(n);
        }
    }

    /// Fold one decoded pending tx into the session stats. `received_at_ms` is
    /// the mempool's accept time (when it first saw the tx).
    pub fn observe_pending(&self, p: &PendingTx, sum: &TxSummary, now_ms: i64) {
        let Ok(mut g) = self.inner.lock() else { return };
        g.seen += 1;
        match sum.kind {
            TxKind::Trx => g.trx_count += 1,
            TxKind::Usdt => {
                g.usdt_count += 1;
                g.call_count += 1;
            }
            TxKind::Call => g.call_count += 1,
            TxKind::Token => g.token_count += 1,
            TxKind::Other => g.other_count += 1,
        }
        g.trx_sun += sum.amount_sun;
        if let Some(units) = sum.usdt_units {
            g.usdt_units += units;
            if units > g.biggest_usdt_units {
                g.biggest_usdt_units = units;
            }
            if units / USDT_UNITS_PER_DOLLAR >= WHALE_USD {
                g.push_alert(
                    "!",
                    format!(
                        "Pending USDT whale: {} from {}",
                        usd(units),
                        short_addr_opt(&sum.to)
                    ),
                );
            }
        }
        if matches!(sum.kind, TxKind::Trx) && sum.amount_sun / SUN_PER_TRX >= WHALE_TRX {
            if sum.amount_sun > g.biggest_trx_sun {
                g.biggest_trx_sun = sum.amount_sun;
            }
            g.push_alert(
                "!",
                format!("Pending TRX whale: {} TRX", human_trx(sum.amount_sun)),
            );
        } else if sum.amount_sun > g.biggest_trx_sun {
            g.biggest_trx_sun = sum.amount_sun;
        }
        if let Some(sel) = sum.selector {
            *g.methods.entry(sel).or_insert(0) += 1;
            if SWAP_SELECTORS.contains(&sel) {
                g.swaps += 1;
            }
        }
        if let Some(addr) = sum.contract.as_ref() {
            if !addr.is_empty() {
                *g.contracts.entry(addr.clone()).or_insert(0) += 1;
            }
        }

        // Arrival rate window.
        g.arrivals.push_back(now_ms);
        while g.arrivals.front().is_some_and(|&t| t < now_ms - TPS_WINDOW_MS) {
            g.arrivals.pop_front();
        }
        // Sparkline: count arrivals per 1s bucket.
        let bucket = now_ms / 1000;
        if g.spark_bucket_ms == 0 {
            g.spark_bucket_ms = bucket;
        }
        if bucket == g.spark_bucket_ms {
            g.spark_bucket_count += 1;
        } else {
            let closed = g.spark_bucket_count;
            let prev_bucket = g.spark_bucket_ms;
            g.spark.push_back(closed);
            // Fill any silent seconds between buckets with zeros so the
            // sparkline timeline stays proportional.
            for _ in (prev_bucket + 1)..bucket {
                g.spark.push_back(0);
            }
            while g.spark.len() > 30 {
                g.spark.pop_front();
            }
            g.spark_bucket_ms = bucket;
            g.spark_bucket_count = 1;
        }

        let signer = p.sender;
        g.feed.push_front(FeedTx {
            tx_id: p.tx_id,
            received_at_ms: p.received_at_ms,
            signer,
            kind: sum.kind,
            amount_sun: sum.amount_sun,
            usdt_units: sum.usdt_units,
            to: sum.to.clone(),
            method: sum.method.clone(),
        });
        while g.feed.len() > FEED_CAP {
            g.feed.pop_back();
        }
    }

    /// Build a full dashboard frame for the given wall-clock time.
    pub fn render(&self, now_ms: i64) -> String {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return String::new(),
        };
        // Arrival rate over the trailing window.
        let win_lo = now_ms - TPS_WINDOW_MS;
        let in_win = g.arrivals.iter().filter(|&&t| t >= win_lo).count() as f64;
        let span = g
            .arrivals
            .front()
            .map(|&f| ((now_ms - f.max(win_lo)) as f64 / 1000.0).max(1.0))
            .unwrap_or(1.0);
        let tps = in_win / span;
        let oldest_age = g
            .feed
            .iter()
            .map(|f| f.received_at_ms)
            .filter(|&t| t > 0)
            .min()
            .map(|t| (now_ms - t).max(0))
            .unwrap_or(0);

        let w = term_cols().saturating_sub(2).clamp(64, 100);
        let colw = w.saturating_sub(3) / 2;
        let mut s = String::new();
        s.push_str("\x1b[H");

        // Header
        s.push_str(&line(&format!(
            "{RED}{BOLD}» TRON GOBLIN{RST}  {DIM}·{RST}  {ORG}{BOLD}LIVE MEMPOOL{RST}  {DIM}pending txs, decoded{RST}"
        )));
        s.push_str(&rule(w));
        let pending = g.feed.len();
        s.push_str(&line(&format!(
            "  {CYN}» streaming pending txs{RST}    {BOLD}tip #{}{RST}",
            commas(self.tip_at_start)
        )));
        s.push_str(&line(&format!(
            "  {MAG}» {:.1} tx/s arriving{RST}    {GRY}oldest in feed {} · {} in feed{RST}",
            tps,
            dur(oldest_age),
            pending
        )));
        let lag = if g.lagged > 0 {
            format!("  {RED}· {} dropped (lagged){RST}", commas(g.lagged as i64))
        } else {
            String::new()
        };
        s.push_str(&line(&format!(
            "  {GRY}⏱ {} · {} pending seen this session{lag}{RST}",
            dur(self.start.elapsed().as_millis() as i64),
            commas(g.seen as i64)
        )));
        if !g.spark.is_empty() {
            s.push_str(&line(&format!(
                "  {DIM}arrivals{RST} {GRN}{}{RST}  {GRY}(txs/sec, last {}){RST}",
                sparkline(&g.spark),
                g.spark.len()
            )));
        }
        s.push_str(&blank());

        // Session totals
        s.push_str(&section("PENDING THIS SESSION", w));
        s.push_str(&row2(
            colw,
            "▪", "TRX pending", &human_trx(g.trx_sun),
            "▪", "USDT pending", &usd(g.usdt_units),
        ));
        s.push_str(&row2(
            colw,
            "▪", "USDT transfers", &commas(g.usdt_count as i64),
            "▪", "contract calls", &commas(g.call_count as i64),
        ));
        s.push_str(&row2(
            colw,
            "▪", "DEX swaps", &commas(g.swaps as i64),
            "▪", "token transfers", &commas(g.token_count as i64),
        ));
        s.push_str(&row2(
            colw,
            "▪", "biggest USDT", &usd(g.biggest_usdt_units),
            "▪", "biggest TRX", &human_trx(g.biggest_trx_sun),
        ));
        s.push_str(&blank());

        // Pending tx-type mix.
        s.push_str(&section("PENDING MIX", w));
        let parts = [
            (g.trx_count, CYN),
            (g.usdt_count, GRN),
            (g.token_count, YEL),
            (
                g.call_count.saturating_sub(g.usdt_count).saturating_add(g.other_count),
                MAG,
            ),
        ];
        s.push_str(&line(&format!("   {}", mix_bar(&parts, w.saturating_sub(3)))));
        s.push_str(&line(&format!(
            "   {CYN}▪ TRX{RST}   {GRN}▪ USDT{RST}   {YEL}▪ tokens{RST}   {MAG}▪ other calls{RST}"
        )));
        // Top pending methods.
        if !g.methods.is_empty() {
            let mut meth: Vec<([u8; 4], u64)> =
                g.methods.iter().map(|(k, v)| (*k, *v)).collect();
            meth.sort_by(|a, b| b.1.cmp(&a.1));
            let tot = meth.iter().map(|m| m.1).sum::<u64>().max(1);
            let parts: Vec<String> = meth
                .iter()
                .take(4)
                .map(|m| {
                    format!(
                        "{CYN}{}{RST} {DIM}{}%{RST}",
                        method_name(&m.0),
                        m.1 * 100 / tot
                    )
                })
                .collect();
            if !parts.is_empty() {
                s.push_str(&line(&format!("   {DIM}* calls:{RST} {}", parts.join("   "))));
            }
        }
        s.push_str(&blank());

        // Top target contracts.
        s.push_str(&section("HOT CONTRACTS", w));
        if g.contracts.is_empty() {
            s.push_str(&line(&format!("   {DIM}waiting for pending calls…{RST}")));
        } else {
            let mut con: Vec<(Vec<u8>, u64)> =
                g.contracts.iter().map(|(k, v)| (k.clone(), *v)).collect();
            con.sort_by(|a, b| b.1.cmp(&a.1));
            let mut chips = "   ".to_string();
            let mut vis = 3;
            for (addr, n) in con.iter() {
                let chip = format!("{BOLD}{}{RST} {GRY}×{}{RST}   ", short_addr(addr), n);
                let cvis = visible_len(&chip);
                if vis + cvis > w {
                    break;
                }
                chips.push_str(&chip);
                vis += cvis;
            }
            s.push_str(&line(&chips));
        }
        s.push_str(&blank());

        // Live pending feed.
        s.push_str(&section("PENDING FEED", w));
        if g.feed.is_empty() {
            s.push_str(&line(&format!("   {DIM}waiting for the next pending tx…{RST}")));
        }
        for f in g.feed.iter() {
            let age = if f.received_at_ms > 0 {
                (now_ms - f.received_at_ms).max(0)
            } else {
                0
            };
            let tag = format!("{}{:>4}{RST}", f.kind.color(), f.kind.tag());
            let signer = match &f.signer {
                Some(a) => short_addr(a),
                None => "—".to_string(),
            };
            let mut detail = String::new();
            if let Some(units) = f.usdt_units {
                detail.push_str(&format!(" {GRN}{}{RST}", usd(units)));
            } else if f.amount_sun >= SUN_PER_TRX {
                detail.push_str(&format!(" {CYN}{} TRX{RST}", human_trx(f.amount_sun)));
            }
            if let Some(to) = &f.to {
                detail.push_str(&format!(" {GRY}→ {}{RST}", short_addr(to)));
            }
            if let Some(m) = &f.method {
                detail.push_str(&format!(" {DIM}{}{RST}", m));
            }
            s.push_str(&line(&format!(
                "   {GRY}{:>4}{RST} {tag} {signer}{detail}  {DIM}{}{RST}",
                dur(age),
                hex_short(&f.tx_id),
            )));
        }
        s.push_str(&blank());

        // Whale / large-transfer alerts.
        s.push_str(&section("ALERTS", w));
        if g.alerts.is_empty() {
            s.push_str(&line(&format!(
                "   {DIM}no whales yet · USDT ≥ ${}k or TRX ≥ {} flag here{RST}",
                WHALE_USD / 1000,
                compact(WHALE_TRX)
            )));
        }
        for a in g.alerts.iter().take(3) {
            s.push_str(&line(&format!("   {} {YEL}{}{RST}", a.icon, a.text)));
        }
        s.push_str(&blank());
        s.push_str(&line(&format!(
            "  {DIM}decode-only mempool view · no state, no snapshot · Ctrl-C to stop{RST}"
        )));
        s.push_str("\x1b[J");
        s
    }
}

impl Inner {
    fn push_alert(&mut self, icon: &'static str, text: String) {
        self.alerts.push_front(Alert { icon, text });
        while self.alerts.len() > 6 {
            self.alerts.pop_back();
        }
    }
}

/// `short_addr` over an optional address, for log/alert lines.
fn short_addr_opt(addr: &Option<Vec<u8>>) -> String {
    match addr {
        Some(a) => short_addr(a),
        None => "—".to_string(),
    }
}

/// First 4 bytes of a tx_id as hex, e.g. `a1b2c3d4` — enough to eyeball-match
/// against a block explorer without crowding the feed line.
fn hex_short(id: &[u8; 32]) -> String {
    hex::encode(&id[..4])
}

/// Where the optional JSONL feed is written.
pub enum JsonlSink {
    Stdout,
    File(std::path::PathBuf),
}

/// One JSON object per pending tx, written when `--mempool-json` is set.
fn emit_jsonl(sink: &JsonlSink, p: &PendingTx, sum: &TxSummary, ts_ms: i64) {
    let signer = p
        .sender
        .map(|a| hex::encode(a))
        .unwrap_or_default();
    let to = sum.to.as_ref().map(hex::encode).unwrap_or_default();
    let contract = sum.contract.as_ref().map(hex::encode).unwrap_or_default();
    let method = sum.method.clone().unwrap_or_default();
    let usdt = sum
        .usdt_units
        .map(|u| u.to_string())
        .unwrap_or_else(|| "null".to_string());
    let kind = sum.kind.tag();
    // Hand-built JSON keeps the dependency surface unchanged (matches the
    // dependency-light style of the rest of this module). All string fields are
    // hex / fixed enum tags, so no escaping is required.
    let json = format!(
        "{{\"txid\":\"{txid}\",\"ts\":{ts},\"signer\":\"{signer}\",\"type\":\"{kind}\",\"to\":\"{to}\",\"amount_sun\":{amount},\"usdt_units\":{usdt},\"contract\":\"{contract}\",\"method\":\"{method}\",\"expiration\":{exp}}}",
        txid = hex::encode(p.tx_id),
        ts = ts_ms,
        amount = sum.amount_sun,
        exp = p.expiration_ms,
    );
    match sink {
        JsonlSink::Stdout => {
            let mut out = std::io::stdout();
            let _ = writeln!(out, "{json}");
        }
        JsonlSink::File(path) => {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{json}");
            }
        }
    }
}

/// Subscribe to the shared mempool and fold every accepted pending tx into the
/// dashboard state (and, when configured, the JSONL feed). Returns when
/// `shutdown` fires or the mempool's broadcast sender is dropped.
pub async fn run_observer(
    state: Arc<MempoolState>,
    mempool: Arc<TxMempool>,
    jsonl: Option<Arc<JsonlSink>>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let mut rx = mempool.subscribe();
    loop {
        tokio::select! {
            res = rx.recv() => match res {
                Ok(tx_id) => {
                    let Some(pending) = mempool.get(&tx_id) else { continue };
                    let summary = decode_tx_summary(&pending.tx);
                    let ts = now_ms();
                    if let Some(sink) = &jsonl {
                        emit_jsonl(sink, &pending, &summary, ts);
                    }
                    state.observe_pending(&pending, &summary, ts);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // We fell behind the broadcast channel; the dropped txs stay
                    // in the mempool but we lost the notification. Count it so
                    // the dashboard rates stay honest.
                    state.note_lagged(n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            _ = shutdown.recv() => break,
        }
    }
}

/// Spawn the dashboard renderer loop. Paints a frame ~5×/s to stdout (logs go
/// to stderr, so they never collide). Returns when `shutdown` fires; restores
/// the cursor on the way out. Mirrors `explore::run_renderer` over a
/// [`MempoolState`].
pub async fn run_renderer(
    state: Arc<MempoolState>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(ctype: ContractType, param: Vec<u8>) -> Transaction {
        Transaction {
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
        let mut d = crate::explore::SEL_TRANSFER.to_vec();
        d.extend_from_slice(&[0u8; 32]); // to
        let mut amt = [0u8; 32];
        amt[16..32].copy_from_slice(&units.to_be_bytes());
        d.extend_from_slice(&amt);
        d
    }

    #[test]
    fn decode_tx_summary_classifies_trx_transfer() {
        let to = vec![0x41u8; 21];
        let param = TransferContract {
            amount: 5_000_000, // 5 TRX
            owner_address: vec![0x42; 21],
            to_address: to.clone(),
        }
        .encode_to_vec();
        let summary = decode_tx_summary(&tx(ContractType::TransferContract, param));
        assert_eq!(summary.kind, TxKind::Trx);
        assert_eq!(summary.amount_sun, 5_000_000);
        assert_eq!(summary.to.as_deref(), Some(to.as_slice()));
        assert!(summary.usdt_units.is_none());
        assert!(summary.method.is_none());
    }

    #[test]
    fn decode_tx_summary_classifies_usdt_transfer_with_amount_and_method() {
        let usdt_addr = hex::decode(USDT_ADDRESS_HEX).unwrap();
        let param = TriggerSmartContract {
            contract_address: usdt_addr.clone(),
            owner_address: vec![0x42; 21],
            data: usdt_transfer_data(1_234 * USDT_UNITS_PER_DOLLAR),
            ..Default::default()
        }
        .encode_to_vec();
        let summary = decode_tx_summary(&tx(ContractType::TriggerSmartContract, param));
        assert_eq!(summary.kind, TxKind::Usdt);
        assert_eq!(summary.usdt_units, Some(1_234 * USDT_UNITS_PER_DOLLAR));
        assert_eq!(summary.method.as_deref(), Some("transfer"));
        assert_eq!(summary.contract.as_deref(), Some(usdt_addr.as_slice()));
        assert_eq!(summary.selector, Some(crate::explore::SEL_TRANSFER));
    }

    #[test]
    fn decode_tx_summary_classifies_generic_call() {
        let param = TriggerSmartContract {
            contract_address: vec![0x41; 21],
            owner_address: vec![0x42; 21],
            call_value: 7_000_000, // 7 TRX attached
            data: SWAP_SELECTORS[0].to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let summary = decode_tx_summary(&tx(ContractType::TriggerSmartContract, param));
        assert_eq!(summary.kind, TxKind::Call);
        assert_eq!(summary.amount_sun, 7_000_000);
        assert_eq!(summary.method.as_deref(), Some("swap"));
        assert!(summary.usdt_units.is_none());
    }

    #[test]
    fn observe_pending_accumulates_stats_and_swaps() {
        let st = MempoolState::new(83_000_000);
        let usdt_addr = hex::decode(USDT_ADDRESS_HEX).unwrap();
        let usdt_tx = TriggerSmartContract {
            contract_address: usdt_addr,
            owner_address: vec![0x42; 21],
            data: usdt_transfer_data(250_000 * USDT_UNITS_PER_DOLLAR), // $250k (whale)
            ..Default::default()
        }
        .encode_to_vec();
        let usdt_pending_tx = tx(ContractType::TriggerSmartContract, usdt_tx);
        let pending = PendingTx {
            raw_bytes: usdt_pending_tx.encode_to_vec(),
            tx_id: [0x11; 32],
            received_at_ms: 1_700_000_000_000,
            expiration_ms: 1_700_000_060_000,
            sender: Some([0x42; 21]),
            tx: usdt_pending_tx,
            local: false,
        };
        let summary = decode_tx_summary(&pending.tx);
        st.observe_pending(&pending, &summary, 1_700_000_000_500);

        let swap_tx_inner = TriggerSmartContract {
            contract_address: vec![0x41; 21],
            owner_address: vec![0x43; 21],
            data: SWAP_SELECTORS[1].to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let swap_tx = tx(ContractType::TriggerSmartContract, swap_tx_inner);
        let swap_pending = PendingTx {
            raw_bytes: swap_tx.encode_to_vec(),
            tx_id: [0x22; 32],
            received_at_ms: 1_700_000_001_000,
            expiration_ms: 1_700_000_061_000,
            sender: Some([0x43; 21]),
            tx: swap_tx,
            local: false,
        };
        let swap_summary = decode_tx_summary(&swap_pending.tx);
        st.observe_pending(&swap_pending, &swap_summary, 1_700_000_001_500);

        let g = st.inner.lock().unwrap();
        assert_eq!(g.seen, 2);
        assert_eq!(g.usdt_count, 1, "one USDT transfer");
        assert_eq!(g.call_count, 2, "USDT + swap both count as calls");
        assert_eq!(g.swaps, 1, "one DEX swap detected");
        assert_eq!(g.usdt_units, 250_000 * USDT_UNITS_PER_DOLLAR);
        assert_eq!(g.biggest_usdt_units, 250_000 * USDT_UNITS_PER_DOLLAR);
        assert_eq!(g.feed.len(), 2);
        assert_eq!(g.alerts.len(), 1, "whale alert fired for the $250k USDT tx");
    }
}
