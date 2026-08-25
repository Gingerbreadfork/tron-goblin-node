//! JDK8 `Double.toString` reproduction for the small non-negative values the
//! hardened exchange curve (`SafeExchangeProcessor`) feeds through
//! `BigDecimal.valueOf(double)` — the `pow` results land in roughly `[1, 2.01]`.
//!
//! java `BigDecimal.valueOf(double d)` is `new BigDecimal(Double.toString(d))`,
//! so the decimal digits — not the exact binary value — drive the subsequent
//! `setScale(0, DOWN)` truncation. JDK8's `sun.misc.FloatingDecimal` produces
//! the shortest decimal string that rounds back to `d`; this returns that
//! decimal as `(mantissa, scale)` with `d == mantissa * 10^-scale`.

/// Shortest decimal of a non-negative, non-huge `x` as `(mantissa, scale)`.
pub fn to_decimal(x: f64) -> (i128, u32) {
    debug_assert!(x >= 0.0 && x.is_finite());
    // Rust's `{}` formatter emits the shortest round-tripping decimal (Ryū),
    // the same value JDK8's shortest `FloatingDecimal` targets.
    parse_decimal(&format!("{x}"))
}

fn parse_decimal(s: &str) -> (i128, u32) {
    // Handle an exponent suffix defensively, though the exchange inputs never
    // produce one.
    if let Some((base, exp)) = s.split_once(['e', 'E']) {
        let (mant, scale) = parse_plain(base);
        let e: i32 = exp.parse().unwrap();
        let net = scale as i32 - e;
        if net >= 0 {
            (mant, net as u32)
        } else {
            (mant * pow10(net.unsigned_abs()), 0)
        }
    } else {
        parse_plain(s)
    }
}

fn parse_plain(s: &str) -> (i128, u32) {
    match s.split_once('.') {
        Some((int_part, frac_part)) => {
            let digits = format!("{int_part}{frac_part}");
            (digits.parse::<i128>().unwrap(), frac_part.len() as u32)
        }
        None => (s.parse::<i128>().unwrap(), 0),
    }
}

fn pow10(k: u32) -> i128 {
    let mut v: i128 = 1;
    for _ in 0..k {
        v *= 10;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_integer_forms() {
        assert_eq!(to_decimal(1.0), (1, 0));
        assert_eq!(to_decimal(2.0), (2, 0));
        assert_eq!(to_decimal(1.5), (15, 1));
        let (m, k) = to_decimal(1.0003472);
        assert_eq!(m as f64 / 10f64.powi(k as i32), 1.0003472);
    }
}
