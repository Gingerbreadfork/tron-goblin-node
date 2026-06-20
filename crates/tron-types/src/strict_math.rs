//! Bit-exact port of `java.lang.StrictMath.pow`.
//!
//! `StrictMath.pow` is specified to produce results identical to the fdlibm
//! `__ieee754_pow` routine (OpenJDK `src/java.base/share/native/libfdlibm/e_pow.c`).
//! TRON activates strict math under proposal #87 (`ALLOW_STRICT_MATH`); from that
//! point the Bancor exchange curve and the dynamic-energy decay select
//! `StrictMath.pow` over `Math.pow`. Platform `f64::powf` (glibc libm) differs
//! from fdlibm in the last ULP for non-binary bases, which after the
//! truncating `(long)` cast at those call sites can flip the integer result by
//! one unit at a boundary. This module reproduces fdlibm exactly so the strict
//! path is byte-identical to java-tron.
//!
//! The translation mirrors the C source statement-for-statement: the same
//! special-case ladder, the same `__HI`/`__LO` 32-bit word splitting (via
//! [`f64::to_bits`]/[`f64::from_bits`]), the same magic constants, and the same
//! final scaling. C `int`/`unsigned` word arithmetic is reproduced with `i32`/
//! `u32` and wrapping operations.

// fdlibm magic constants (e_pow.c).
const BP: [f64; 2] = [1.0, 1.5];
const DP_H: [f64; 2] = [0.0, 5.84962487220764160156e-01]; // 0x3FE2B803_40000000
const DP_L: [f64; 2] = [0.0, 1.35003920212974897128e-08]; // 0x3E4CFDEB_43CFD006
const ZERO: f64 = 0.0;
const ONE: f64 = 1.0;
const TWO: f64 = 2.0;
const TWO53: f64 = 9007199254740992.0; // 2^53
const HUGE: f64 = 1.0e300;
const TINY: f64 = 1.0e-300;
// poly coefs for (3/2)*(log(x)-2s-2/3*s**3
const L1: f64 = 5.99999999999994648725e-01; // 0x3FE33333_33333303
const L2: f64 = 4.28571428578550184252e-01; // 0x3FDB6DB6_DB6FABFF
const L3: f64 = 3.33333329818377432918e-01; // 0x3FD55555_518F264D
const L4: f64 = 2.72728123808534006489e-01; // 0x3FD17460_A91D4101
const L5: f64 = 2.30660745775561366331e-01; // 0x3FCD864A_93C9DB65
const L6: f64 = 2.06975017800338417784e-01; // 0x3FCA7E28_4A454EEF
const P1: f64 = 1.66666666666666019037e-01; // 0x3FC55555_5555553E
const P2: f64 = -2.77777777770155933842e-03; // 0xBF66C16C_16BEBD93
const P3: f64 = 6.61375632143793436117e-05; // 0x3F11566A_AF25DE2C
const P4: f64 = -1.65339022054652515390e-06; // 0xBEBBBD41_C5D26BF1
const P5: f64 = 4.13813679705723846039e-08; // 0x3E663769_72BEA4D0
const LG2: f64 = 6.93147180559945286227e-01; // 0x3FE62E42_FEFA39EF
const LG2_H: f64 = 6.93147182464599609375e-01; // 0x3FE62E43_00000000
const LG2_L: f64 = -1.90465429995776804525e-09; // 0xBE205C61_0CA86C39
const OVT: f64 = 8.0085662595372944372e-0017; // -(1024-log2(ovfl+.5ulp))
const CP: f64 = 9.61796693925975554329e-01; // 0x3FEEC709_DC3A03FD =2/(3ln2)
const CP_H: f64 = 9.61796700954437255859e-01; // 0x3FEEC709_E0000000 =(float)cp
const CP_L: f64 = -7.02846165095275826516e-09; // 0xBE3E2FE0_145B01F5 =tail of cp_h
const IVLN2: f64 = 1.44269504088896338700e+00; // 0x3FF71547_652B82FE =1/ln2
const IVLN2_H: f64 = 1.44269502162933349609e+00; // 0x3FF71547_60000000 =24b 1/ln2
const IVLN2_L: f64 = 1.92596299112661746887e-08; // 0x3E54AE0B_F85DDF44 =1/ln2 tail

/// High 32 bits of an `f64` (the `__HI(x)` macro in fdlibm), as a signed `i32`
/// to match the C `int` word arithmetic.
#[inline]
fn hi(x: f64) -> i32 {
    (x.to_bits() >> 32) as u32 as i32
}

/// Low 32 bits of an `f64` (the `__LO(x)` macro), as an unsigned `u32`.
#[inline]
fn lo(x: f64) -> u32 {
    x.to_bits() as u32
}

/// Rebuild an `f64` after assigning its high 32-bit word (`__HI(x)=new_hi`).
#[inline]
fn set_hi(x: f64, new_hi: i32) -> f64 {
    let lo = x.to_bits() & 0x0000_0000_ffff_ffff;
    f64::from_bits(lo | ((new_hi as u32 as u64) << 32))
}

/// Rebuild an `f64` after assigning its low 32-bit word (`__LO(x)=new_lo`).
#[inline]
fn set_lo(x: f64, new_lo: u32) -> f64 {
    let hi = x.to_bits() & 0xffff_ffff_0000_0000;
    f64::from_bits(hi | (new_lo as u64))
}

/// fdlibm `scalbn(x, n)` — `x * 2**n`, used only on the subnormal-output path.
fn scalbn(x: f64, n: i32) -> f64 {
    const TWO54: f64 = 1.80143985094819840000e+16; // 0x43500000_00000000
    const TWOM54: f64 = 5.55111512312578270212e-17; // 0x3C900000_00000000
    let mut x = x;
    let mut k = (hi(x) & 0x7ff0_0000) >> 20; // extract exponent
    if k == 0 {
        // 0 or subnormal x
        if (lo(x) | (hi(x) & 0x7fff_ffff) as u32) == 0 {
            return x; // +-0
        }
        x *= TWO54;
        k = ((hi(x) & 0x7ff0_0000) >> 20) - 54;
        if n < -50000 {
            return TINY * x; // underflow
        }
    }
    if k == 0x7ff {
        return x + x; // NaN or Inf
    }
    k += n;
    if k > 0x7fe {
        return HUGE * copysign(HUGE, x); // overflow
    }
    if k > 0 {
        // normal result
        return set_hi(x, (hi(x) & 0x800f_ffff_u32 as i32) | (k << 20));
    }
    if k <= -54 {
        if n > 50000 {
            // in case integer overflow in n+k
            return HUGE * copysign(HUGE, x); // overflow
        }
        return TINY * copysign(TINY, x); // underflow
    }
    k += 54; // subnormal result
    x = set_hi(x, (hi(x) & 0x800f_ffff_u32 as i32) | (k << 20));
    x * TWOM54
}

#[inline]
fn copysign(x: f64, y: f64) -> f64 {
    set_hi(x, (hi(x) & 0x7fff_ffff) | (hi(y) & 0x8000_0000_u32 as i32))
}

/// java-tron `Maths.pow(x, y, useStrictMath)`: selects the fdlibm
/// [`strict_pow`] when proposal #87 (`ALLOW_STRICT_MATH`) is active, otherwise
/// the platform `Math.pow` equivalent ([`f64::powf`]). The non-strict branch
/// is the pre-#87 behavior and must stay byte-unchanged.
#[inline]
pub fn pow(x: f64, y: f64, use_strict_math: bool) -> f64 {
    if use_strict_math {
        strict_pow(x, y)
    } else {
        x.powf(y)
    }
}

/// Bit-exact equivalent of `java.lang.StrictMath.pow(x, y)` (fdlibm
/// `__ieee754_pow`).
#[allow(clippy::many_single_char_names)]
pub fn strict_pow(x: f64, y: f64) -> f64 {
    let mut z: f64;
    let mut ax: f64;
    let mut p_h: f64;
    let mut p_l: f64;
    let y1: f64;
    // t1/t2 are assigned on both the |y|-huge and normal-log paths, then
    // read in the shared tail, so they live at function scope.
    let mut t1: f64;
    let t2: f64;
    let mut r: f64;
    let mut s: f64;
    let mut t: f64;
    let mut u: f64;
    let mut v: f64;
    let mut w: f64;
    let mut i: i32;
    let mut j: i32;
    let mut k: i32;
    let mut yisint: i32;
    let mut n: i32;

    let hx = hi(x);
    let lx = lo(x);
    let hy = hi(y);
    let ly = lo(y);
    let mut ix = hx & 0x7fff_ffff_u32 as i32;
    let iy = hy & 0x7fff_ffff_u32 as i32;

    // y==zero: x**0 = 1
    if (iy as u32 | ly) == 0 {
        return ONE;
    }

    // +-NaN return x+y
    if ix > 0x7ff0_0000
        || ((ix == 0x7ff0_0000) && (lx != 0))
        || iy > 0x7ff0_0000
        || ((iy == 0x7ff0_0000) && (ly != 0))
    {
        return x + y;
    }

    // determine if y is an odd int when x < 0
    // yisint = 0       ... y is not an integer
    // yisint = 1       ... y is an odd int
    // yisint = 2       ... y is an even int
    yisint = 0;
    if hx < 0 {
        if iy >= 0x4340_0000 {
            yisint = 2; // even integer y
        } else if iy >= 0x3ff0_0000 {
            k = (iy >> 20) - 0x3ff; // exponent
            if k > 20 {
                j = (ly >> (52 - k)) as i32;
                if ((j as u32) << (52 - k)) == ly {
                    yisint = 2 - (j & 1);
                }
            } else if ly == 0 {
                j = iy >> (20 - k);
                if (j << (20 - k)) == iy {
                    yisint = 2 - (j & 1);
                }
            }
        }
    }

    // special value of y
    if ly == 0 {
        if iy == 0x7ff0_0000 {
            // y is +-inf
            if ((ix - 0x3ff0_0000) as u32 | lx) == 0 {
                return y - y; // inf**+-1 is NaN
            } else if ix >= 0x3ff0_0000 {
                // (|x|>1)**+-inf = inf,0
                return if hy >= 0 { y } else { ZERO };
            } else {
                // (|x|<1)**-,+inf = inf,0
                return if hy < 0 { -y } else { ZERO };
            }
        }
        if iy == 0x3ff0_0000 {
            // y is  +-1
            if hy < 0 {
                return ONE / x;
            } else {
                return x;
            }
        }
        if hy == 0x4000_0000 {
            return x * x; // y is  2
        }
        if hy == 0x3fe0_0000 {
            // y is  0.5
            if hx >= 0 {
                // x >= +0
                return x.sqrt();
            }
        }
    }

    ax = x.abs();
    // special value of x
    if lx == 0 {
        if ix == 0x7ff0_0000 || ix == 0 || ix == 0x3ff0_0000 {
            // x is +-0,+-inf,+-1
            z = ax;
            if hy < 0 {
                z = ONE / z; // z = (1/|x|)
            }
            if hx < 0 {
                if ((ix - 0x3ff0_0000) | yisint) == 0 {
                    z = (z - z) / (z - z); // (-1)**non-int is NaN
                } else if yisint == 1 {
                    z = -z; // (x<0)**odd = -(|x|**odd)
                }
            }
            return z;
        }
    }

    n = (hx >> 31) + 1;

    // (x<0)**(non-int) is NaN
    if (n | yisint) == 0 {
        return (x - x) / (x - x);
    }

    s = ONE; // s (sign of result -ve**odd) = -1 else = 1
    if (n | (yisint - 1)) == 0 {
        s = -ONE; // (-ve)**(odd int)
    }

    // |y| is huge
    if iy > 0x4170_0000 {
        // if |y| > 2**24
        if iy > 0x4386_0000 {
            // if |y| > 2**57 then must o/uflow
            if ix <= 0x3fef_ffff {
                return if hy < 0 { HUGE * HUGE } else { TINY * TINY };
            }
            if ix >= 0x3ff0_0000 {
                return if hy > 0 { HUGE * HUGE } else { TINY * TINY };
            }
        }
        // over/underflow if x is not close to one
        if ix < 0x3fef_ffff {
            return if hy < 0 { s * HUGE * HUGE } else { s * TINY * TINY };
        }
        if ix > 0x3ff0_0000 {
            return if hy > 0 { s * HUGE * HUGE } else { s * TINY * TINY };
        }
        // now |1-x| is tiny <= 2**-20, suffice to compute
        // log(x) by x-x^2/2+x^3/3-x^4/4
        t = ax - ONE; // t has 20 trailing zeros
        w = (t * t) * (0.5 - t * (0.3333333333333333333333 - t * 0.25));
        u = IVLN2_H * t; // ivln2_h has 21 sig. bits
        v = t * IVLN2_L - w * IVLN2;
        t1 = u + v;
        t1 = set_lo(t1, 0);
        t2 = v - (t1 - u);
    } else {
        let ss: f64;
        let s2: f64;
        let s_h: f64;
        let s_l: f64;
        let mut t_h: f64;
        let mut t_l: f64;
        let z_h: f64;
        let z_l: f64;
        n = 0;
        // take care subnormal number
        if ix < 0x0010_0000 {
            ax *= TWO53;
            n -= 53;
            ix = hi(ax);
        }
        n += (ix >> 20) - 0x3ff;
        j = ix & 0x000f_ffff;
        // determine interval
        ix = j | 0x3ff0_0000; // normalize ix
        if j <= 0x3988E {
            k = 0; // |x|<sqrt(3/2)
        } else if j < 0xBB67A {
            k = 1; // |x|<sqrt(3)
        } else {
            k = 0;
            n += 1;
            ix -= 0x0010_0000;
        }
        ax = set_hi(ax, ix);

        // compute ss = s_h+s_l = (x-1)/(x+1) or (x-1.5)/(x+1.5)
        u = ax - BP[k as usize]; // bp[0]=1.0, bp[1]=1.5
        v = ONE / (ax + BP[k as usize]);
        ss = u * v;
        s_h = set_lo(ss, 0);
        // t_h=ax+bp[k] High
        t_h = set_hi(ZERO, ((ix >> 1) | 0x2000_0000) + 0x0008_0000 + (k << 18));
        t_l = ax - (t_h - BP[k as usize]);
        s_l = v * ((u - s_h * t_h) - s_h * t_l);
        // compute log(ax)
        s2 = ss * ss;
        r = s2 * s2 * (L1 + s2 * (L2 + s2 * (L3 + s2 * (L4 + s2 * (L5 + s2 * L6)))));
        r += s_l * (s_h + ss);
        let s2b = s_h * s_h;
        t_h = 3.0 + s2b + r;
        t_h = set_lo(t_h, 0);
        t_l = r - ((t_h - 3.0) - s2b);
        // u+v = ss*(1+...)
        u = s_h * t_h;
        v = s_l * t_h + t_l * ss;
        // 2/(3log2)*(ss+...)
        p_h = u + v;
        p_h = set_lo(p_h, 0);
        p_l = v - (p_h - u);
        z_h = CP_H * p_h; // cp_h+cp_l = 2/(3*log2)
        z_l = CP_L * p_h + p_l * CP + DP_L[k as usize];
        // log2(ax) = (ss+..)*2/(3*log2) = n + dp_h + z_h + z_l
        t = n as f64;
        t1 = ((z_h + z_l) + DP_H[k as usize]) + t;
        t1 = set_lo(t1, 0);
        t2 = z_l - (((t1 - t) - DP_H[k as usize]) - z_h);
    }

    // split up y into y1+y2 and compute (y1+y2)*(t1+t2)
    y1 = set_lo(y, 0);
    p_l = (y - y1) * t1 + y * t2;
    p_h = y1 * t1;
    z = p_l + p_h;
    j = hi(z);
    i = lo(z) as i32;
    if j >= 0x4090_0000 {
        // z >= 1024
        if ((j - 0x4090_0000) | i) != 0 {
            // if z > 1024
            return s * HUGE * HUGE; // overflow
        } else if p_l + OVT > z - p_h {
            return s * HUGE * HUGE; // overflow
        }
    } else if (j & 0x7fff_ffff) >= 0x4090_cc00 {
        // z <= -1075
        if ((j as u32).wrapping_sub(0xc090_cc00) | i as u32) != 0 {
            // z < -1075
            return s * TINY * TINY; // underflow
        } else if p_l <= z - p_h {
            return s * TINY * TINY; // underflow
        }
    }

    // compute 2**(p_h+p_l)
    i = j & 0x7fff_ffff_u32 as i32;
    k = (i >> 20) - 0x3ff;
    n = 0;
    if i > 0x3fe0_0000 {
        // if |z| > 0.5, set n = [z+0.5]
        n = j + (0x0010_0000 >> (k + 1));
        k = ((n & 0x7fff_ffff) >> 20) - 0x3ff; // new k for n
        t = set_hi(ZERO, n & !(0x000f_ffff >> k));
        n = ((n & 0x000f_ffff) | 0x0010_0000) >> (20 - k);
        if j < 0 {
            n = -n;
        }
        p_h -= t;
    }
    t = p_l + p_h;
    t = set_lo(t, 0);
    u = t * LG2_H;
    v = (p_l - (t - p_h)) * LG2 + t * LG2_L;
    z = u + v;
    w = v - (z - u);
    t = z * z;
    t1 = z - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
    r = (z * t1) / (t1 - TWO) - (w + z * w);
    z = ONE - (r - z);
    j = hi(z);
    j += n << 20;
    if (j >> 20) <= 0 {
        // subnormal output
        z = scalbn(z, n);
    } else {
        z = set_hi(z, j);
    }
    s * z
}

#[cfg(test)]
mod tests;
