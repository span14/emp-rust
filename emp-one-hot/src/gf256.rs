use crate::{
    BoolMatrix, OneHotContext, ShareMatrix,
    table::Table,
    unary::{half_outer_product, unary_outer_product},
};
use emp_tool::io_channel::IOChannel;
use std::{io, sync::OnceLock};

/// Multiply two bytes in GF(2^8) with the AES polynomial.
fn mul_byte(mut x: u8, mut y: u8) -> u8 {
    let mut c = 0u8;
    for _ in 0..8 {
        if y & 1 == 1 {
            c ^= x;
        }
        let carry = x & 0x80;
        x <<= 1;
        if carry != 0 {
            x ^= 0x1B;
        }
        y >>= 1;
    }
    c
}

/// Compute multiplicative inverse in GF(2^8); returns 0 for input 0.
fn invert_byte(x: u8) -> u8 {
    if x == 0 {
        0
    } else {
        // x^254
        let mut z = x;
        for _ in 0..6 {
            z = mul_byte(z, z);
            z = mul_byte(z, x);
        }
        mul_byte(z, z)
    }
}

/// Convert a byte to a little-endian boolean vector.
fn byte_to_bools(mut x: u8) -> Vec<bool> {
    let mut v = vec![false; 8];
    for i in 0..8 {
        v[i] = (x & 1) == 1;
        x >>= 1;
    }
    v
}

/// Convert a boolean vector (len 8) to a byte (little-endian).
fn bools_to_byte(bits: &[bool]) -> u8 {
    let mut x = 0u8;
    for (i, &b) in bits.iter().enumerate() {
        if b {
            x |= 1 << i;
        }
    }
    x
}

fn reduction_table() -> &'static BoolMatrix {
    static TABLE: OnceLock<BoolMatrix> = OnceLock::new();
    TABLE.get_or_init(|| {
        // Build 15x8 then transpose to 8x15 (matches the C++ reference).
        let mut t = BoolMatrix::new(15, 8);
        for i in 0..8 {
            t.set(i, i, true);
        }
        t.set(8, 0, true);
        t.set(8, 1, true);
        t.set(8, 3, true);
        t.set(8, 4, true);
        t.set(9, 1, true);
        t.set(9, 2, true);
        t.set(9, 4, true);
        t.set(9, 5, true);
        t.set(10, 2, true);
        t.set(10, 3, true);
        t.set(10, 5, true);
        t.set(10, 6, true);
        t.set(11, 3, true);
        t.set(11, 4, true);
        t.set(11, 6, true);
        t.set(11, 7, true);
        t.set(12, 0, true);
        t.set(12, 1, true);
        t.set(12, 3, true);
        t.set(12, 5, true);
        t.set(12, 7, true);
        t.set(13, 0, true);
        t.set(13, 2, true);
        t.set(13, 3, true);
        t.set(13, 6, true);
        t.set(14, 1, true);
        t.set(14, 3, true);
        t.set(14, 4, true);
        t.set(14, 7, true);
        t.transpose()
    })
}

/// Compute `(x + color(x)) * y` in GF(256).
pub fn half_mul_gf256<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), 8);
    assert_eq!(y.rows(), 8);
    assert_eq!(x.cols(), 1);
    assert_eq!(y.cols(), 1);

    let mut xy_outer = ShareMatrix::new(8, 8);
    half_outer_product(ctx, x.as_slice(), y.as_slice(), &mut xy_outer)?;

    let mut unreduced = ShareMatrix::vector(15);
    for i in 0..8 {
        for j in 0..8 {
            let idx = i + j;
            unreduced[idx] ^= xy_outer[(i, j)];
        }
    }
    Ok(ShareMatrix::mul_bool_matrix(reduction_table(), &unreduced))
}

/// Multiply `x` by `y` in GF(256).
pub fn mul_gf256<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), 8);
    assert_eq!(y.rows(), 8);
    assert_eq!(x.cols(), 1);
    assert_eq!(y.cols(), 1);

    let x_colors = x.colors();
    let y_colors = y.colors();
    let cx = bools_to_byte(x_colors.as_slice());
    let cy = bools_to_byte(y_colors.as_slice());

    let mut out = half_mul_gf256(ctx, x, y)?;
    let x_const = ShareMatrix::constant(
        ctx,
        &BoolMatrix::from_vec(8, 1, x_colors.as_slice().to_vec()),
    );
    out.xor_assign(&half_mul_gf256(ctx, y, &x_const)?);

    let const_term = ShareMatrix::constant(
        ctx,
        &BoolMatrix::from_vec(8, 1, byte_to_bools(mul_byte(cx, cy))),
    );
    out.xor_assign(&const_term);
    Ok(out)
}

struct InverseTable;

impl Table for InverseTable {
    fn row(&self, index: usize) -> usize {
        invert_byte(index as u8) as usize
    }
}

/// Compute the multiplicative inverse of `x` (input must be non-zero).
pub fn gf256_invert<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), 8);
    assert_eq!(x.cols(), 1);

    let mut y = ShareMatrix::vector(8);
    if ctx.is_generator() {
        loop {
            let candidate = ShareMatrix::uniform(ctx, 8, 1);
            if bools_to_byte(candidate.colors().as_slice()) != 0 {
                y = candidate;
                break;
            }
        }
    }

    let cx = bools_to_byte(x.colors().as_slice());
    let cy = bools_to_byte(y.colors().as_slice());
    let cols = ShareMatrix::constant(
        ctx,
        &BoolMatrix::from_vec(8, 1, byte_to_bools(mul_byte(cx, cy))),
    );

    let mut xy = half_mul_gf256(ctx, x, &y)?;
    xy.xor_assign(&cols);
    xy.reveal(ctx)?;

    let mut xy_outer = ShareMatrix::new(8, 8);
    unary_outer_product(
        ctx,
        &InverseTable,
        xy.as_slice(),
        y.as_slice(),
        &mut xy_outer,
    )?;

    let mut unreduced = ShareMatrix::vector(15);
    for i in 0..8 {
        for j in 0..8 {
            unreduced[i + j] ^= xy_outer[(i, j)];
        }
    }
    Ok(ShareMatrix::mul_bool_matrix(reduction_table(), &unreduced))
}

fn aes_linear_matrix() -> &'static BoolMatrix {
    static MAT: OnceLock<BoolMatrix> = OnceLock::new();
    MAT.get_or_init(|| {
        let mut m = BoolMatrix::new(8, 8);
        for i in 0..8 {
            m.set(i, (0 + i) % 8, true);
            m.set(i, (4 + i) % 8, true);
            m.set(i, (5 + i) % 8, true);
            m.set(i, (6 + i) % 8, true);
            m.set(i, (7 + i) % 8, true);
        }
        m
    })
}

fn aes_linear_shift() -> &'static BoolMatrix {
    static SHIFT: OnceLock<BoolMatrix> = OnceLock::new();
    SHIFT.get_or_init(|| {
        let mut m = BoolMatrix::vector(8);
        m.set(0, 0, true);
        m.set(1, 0, true);
        m.set(5, 0, true);
        m.set(6, 0, true);
        m
    })
}

/// AES S-box implemented with GF(256) inversion.
pub fn aes_sbox<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), 8);
    assert_eq!(x.cols(), 1);

    let mut zero = ctx.not(x[0]);
    for i in 1..8 {
        zero = ctx.and_gate(zero, ctx.not(x[i]))?;
    }

    let mut z = ShareMatrix::vector(8);
    z[0] = zero;

    let mut tmp = x.clone();
    tmp.xor_assign(&z);
    let mut inv = gf256_invert(ctx, &tmp)?;
    inv.xor_assign(&z);

    let mut out = ShareMatrix::mul_bool_matrix(aes_linear_matrix(), &inv);
    out.xor_assign(&ShareMatrix::constant(ctx, aes_linear_shift()));
    Ok(out)
}
