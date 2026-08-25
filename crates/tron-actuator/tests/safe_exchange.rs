//! `SafeExchangeProcessor` (TIP-836 hardened swap) validated against vectors
//! produced by the reference JDK8 java-tron `SafeExchangeProcessor` — each line
//! is `sellBalance buyBalance quant relay out` (or `... ERR` on overflow).

use tron_actuator::exchange::safe_exchange_for_test as safe_exchange;

fn check(fixture: &str) {
    let mut n = 0usize;
    for line in fixture.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let sell: i64 = f[0].parse().unwrap();
        let buy: i64 = f[1].parse().unwrap();
        let quant: i64 = f[2].parse().unwrap();
        let got = safe_exchange(sell, buy, quant);
        if f.get(3) == Some(&"ERR") {
            assert!(got.is_err(), "line {n}: {line} — expected ERR, got {got:?}");
        } else {
            let expected: i64 = f[4].parse().unwrap();
            assert_eq!(got.ok(), Some(expected), "line {n}: {line}");
        }
        n += 1;
    }
    assert!(n > 100, "fixture looked empty ({n} lines)");
}

#[test]
fn matches_jdk8_reference_small() {
    check(include_str!("fixtures/safe_exchange_jdk8.txt"));
}

#[test]
fn matches_jdk8_reference_big() {
    check(include_str!("fixtures/safe_exchange_jdk8_big.txt"));
}
