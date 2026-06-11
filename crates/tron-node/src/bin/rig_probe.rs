//! One-off diagnostic: open a stopped node's data dir READ-ONLY and
//! check (1) head-pointer vs block-store consistency and (2) whether
//! the stored TOTAL_*_WEIGHT counters agree with the sum of frozen
//! balances across all accounts. A large mismatch is the signature of
//! an inconsistent (live-copy) snapshot. Usage:
//!   cargo run -q --bin rig_probe -- <data_dir>
use std::sync::Arc;
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, RocksDbBackend,
};
use tron_types::resource::TRX_PRECISION;

fn open_ro(db_root: &std::path::Path, name: &str) -> Arc<dyn KvBackend> {
    Arc::new(RocksDbBackend::open_read_only(db_root.join(name)).unwrap_or_else(|e| {
        panic!("open {name} read-only: {e}");
    }))
}

fn main() {
    let data_dir = std::env::args().nth(1).expect("usage: rig_probe <data_dir>");
    let db_root = std::path::Path::new(&data_dir).join("database");
    eprintln!("probing {}", db_root.display());

    let dp = DynamicPropertiesStore::new(open_ro(&db_root, "properties"));
    let head_num = dp.latest_block_header_number().unwrap_or(0);
    let head_hash = dp.latest_block_header_hash().ok().flatten();
    println!("head pointer (properties): #{head_num}");

    // ---- (1) head vs block stores ----
    if let Some(h) = head_hash {
        let id = tron_types::BlockId::from_raw(h);
        let bi = BlockIndexStore::new(open_ro(&db_root, "block-index"));
        let bs = BlockStore::new(open_ro(&db_root, "block"));
        match bi.get(head_num) {
            Ok(indexed) if indexed == id => println!("  block-index[#{head_num}] == head hash  ✓"),
            Ok(indexed) => println!(
                "  ✗ SKEW: block-index[#{head_num}] = {} != head hash {}",
                hex::encode(&indexed.as_bytes()[..8]),
                hex::encode(&id.as_bytes()[..8])
            ),
            Err(e) => println!("  ✗ SKEW: block-index[#{head_num}] unreadable: {e}"),
        }
        match bs.get(&id) {
            Ok(_) => println!("  head block present in block store          ✓"),
            Err(e) => println!("  ✗ SKEW: head block absent from block store: {e}"),
        }
        // What height does block-index actually top out at?
        let bi_be = open_ro(&db_root, "block-index");
        let top = bi_be.scan_back_from(&[0xff; 8], 1).unwrap_or_default();
        if let Some((k, _)) = top.first() {
            if k.len() == 8 {
                let bn = i64::from_be_bytes(k.as_slice().try_into().unwrap());
                println!("  block-index max height: #{bn}  (head says #{head_num}; delta {})", bn - head_num);
            }
        }
    } else {
        println!("  no head hash in properties");
    }

    // ---- (2) weight reconstruction from account scan ----
    let stored_net = dp.total_net_weight();
    let stored_energy = dp.total_energy_weight();
    let stored_tp = dp.get_long(b"TOTAL_TRON_POWER_WEIGHT").unwrap_or(0);
    println!(
        "stored weights: net={stored_net} energy={stored_energy} tron_power={stored_tp}"
    );

    let acc_be = open_ro(&db_root, "account");
    let _ = AccountStore::new(acc_be.clone());
    use prost::Message;
    // Stored weight telescopes to Σ_account floor(basis/1e6) (V2 exact; V1 has
    // sub-TRX per-op flooring). So we accumulate the FLOORED per-account
    // contribution — matching the accumulator model exactly for V2 — and also
    // the raw sun sum for cross-checking. The right noise bound is the count of
    // CONTRIBUTING (nonzero-basis) accounts per resource, not all accounts.
    let (mut net_floor, mut energy_floor, mut tp_floor): (i128, i128, i128) = (0, 0, 0);
    let (mut net_sun, mut energy_sun, mut tp_sun): (i128, i128, i128) = (0, 0, 0);
    let (mut net_c, mut energy_c, mut tp_c): (i64, i64, i64) = (0, 0, 0);
    let tp = TRX_PRECISION as i128;
    let mut n: u64 = 0;
    let mut start: Vec<u8> = Vec::new();
    // Top-N stakers by net / energy basis, for per-account diff vs java.
    // entry: (basis_sun, addr_b58, v2, v1, deleg_v2, deleg_v1)
    const TOPN: usize = 60;
    let mut top_net: Vec<(i64, String, i64, i64, i64, i64)> = Vec::new();
    let mut top_en: Vec<(i64, String, i64, i64, i64, i64)> = Vec::new();
    let consider = |top: &mut Vec<(i64, String, i64, i64, i64, i64)>, e: (i64, String, i64, i64, i64, i64)| {
        if top.len() < TOPN {
            top.push(e);
            if top.len() == TOPN { top.sort_by_key(|x| x.0); }
        } else if e.0 > top[0].0 {
            top[0] = e;
            top.sort_by_key(|x| x.0);
        }
    };
    loop {
        let batch = acc_be.scan_from(&start, 4096).unwrap();
        if batch.is_empty() {
            break;
        }
        for (k, v) in &batch {
            if let Ok(a) = tron_proto::Account::decode(v.as_slice()) {
                // Weight contribution = OWN frozen + delegated-OUT (NOT acquired).
                let v2_bw: i64 = a.frozen_v2.iter().filter(|f| f.r#type == 0).map(|f| f.amount).sum();
                let v2_en: i64 = a.frozen_v2.iter().filter(|f| f.r#type == 1).map(|f| f.amount).sum();
                let v2_tp: i64 = a.frozen_v2.iter().filter(|f| f.r#type == 2).map(|f| f.amount).sum();
                let v1_bw: i64 = a.frozen.iter().map(|f| f.frozen_balance).sum();
                let res = a.account_resource.clone().unwrap_or_default();
                let v1_en = res.frozen_balance_for_energy.map(|f| f.frozen_balance).unwrap_or(0);
                let dlg_v2_bw = a.delegated_frozen_v2_balance_for_bandwidth;
                let dlg_v1_bw = a.delegated_frozen_balance_for_bandwidth;
                let dlg_v2_en = res.delegated_frozen_v2_balance_for_energy;
                let dlg_v1_en = res.delegated_frozen_balance_for_energy;
                let net_basis = (v2_bw + v1_bw + dlg_v2_bw + dlg_v1_bw) as i128;
                let en_basis = (v2_en + v1_en + dlg_v2_en + dlg_v1_en) as i128;
                let tp_basis = v2_tp as i128;
                if net_basis > 0 {
                    net_floor += net_basis / tp; net_sun += net_basis; net_c += 1;
                    if net_basis > 1_000_000_000 {
                        let addr = if k.len() == 21 { tron_crypto::base58check::encode_check(k) } else { hex::encode(k) };
                        consider(&mut top_net, (net_basis as i64, addr, v2_bw + v1_bw, v1_bw, dlg_v2_bw, dlg_v1_bw));
                    }
                }
                if en_basis  > 0 {
                    energy_floor += en_basis / tp; energy_sun += en_basis; energy_c += 1;
                    if en_basis > 1_000_000_000 {
                        let addr = if k.len() == 21 { tron_crypto::base58check::encode_check(k) } else { hex::encode(k) };
                        consider(&mut top_en, (en_basis as i64, addr, v2_en + v1_en, v1_en, dlg_v2_en, dlg_v1_en));
                    }
                }
                if tp_basis  > 0 { tp_floor += tp_basis / tp; tp_sun += tp_basis; tp_c += 1; }
            }
            n += 1;
        }
        start = batch.last().unwrap().0.clone();
        start.push(0); // strictly greater than last key
        if n % 2_000_000 == 0 {
            eprintln!("  scanned {n} accounts...");
        }
    }
    top_net.sort_by_key(|x| std::cmp::Reverse(x.0));
    top_en.sort_by_key(|x| std::cmp::Reverse(x.0));
    println!("--- TOP {} by NET basis (addr  net_basis_sun  held_v2+v1  v1  deleg_v2  deleg_v1) ---", top_net.len());
    for (b, addr, held, v1, dv2, dv1) in &top_net {
        println!("NET {addr} {b} {held} {v1} {dv2} {dv1}");
    }
    println!("--- TOP {} by ENERGY basis (addr  en_basis_sun  held_v2+v1  v1  deleg_v2  deleg_v1) ---", top_en.len());
    for (b, addr, held, v1, dv2, dv1) in &top_en {
        println!("EN {addr} {b} {held} {v1} {dv2} {dv1}");
    }
    println!("scanned {n} accounts");
    println!(
        "contributing accounts: net={net_c} energy={energy_c} tron_power={tp_c}"
    );
    // Per-account floored sum (matches accumulator model) and bulk sun/1e6.
    let recon_net = (net_floor) as i64;
    let recon_energy = (energy_floor) as i64;
    let recon_tp = (tp_floor) as i64;
    println!(
        "reconstructed (Σ floor(basis/1e6)): net={recon_net} energy={recon_energy} tron_power={recon_tp}"
    );
    println!(
        "reconstructed (floor(Σ basis)/1e6): net={} energy={} tron_power={}",
        (net_sun / tp) as i64, (energy_sun / tp) as i64, (tp_sun / tp) as i64
    );
    let report = |label: &str, stored: i64, recon: i64, contrib: i64| {
        let diff = stored - recon;
        // V2 telescopes exactly → 0 noise. V1 adds sub-TRX per-op error,
        // bounded by the number of contributing accounts.
        let noise = contrib.max(1);
        let verdict = if diff.abs() <= noise {
            "CONSISTENT (matches account store)"
        } else {
            "*** INCONSISTENT — counter disagrees with account store ***"
        };
        println!("  {label}: stored={stored} recon={recon} diff={diff} (noise ±{noise})  {verdict}");
    };
    report("net   ", stored_net, recon_net, net_c);
    report("energy", stored_energy, recon_energy, energy_c);
    report("tronpw", stored_tp, recon_tp, tp_c);
}
