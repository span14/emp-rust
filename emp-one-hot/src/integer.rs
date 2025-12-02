use crate::{
    BoolMatrix, OneHotContext, Share, ShareMatrix, table::Table, unary::unary_outer_product,
};
use emp_tool::io_channel::IOChannel;
use std::{
    io,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Prime modulus used in the reference C++ demo.
pub const MOD_P: u32 = 65_521;

static CHUNKING_FACTOR: AtomicUsize = AtomicUsize::new(6);

/// Get the chunking factor used for exponentiation.
pub fn chunking_factor() -> usize {
    CHUNKING_FACTOR.load(Ordering::Relaxed)
}

/// Set the chunking factor used for exponentiation.
pub fn set_chunking_factor(v: usize) {
    CHUNKING_FACTOR.store(v.max(1), Ordering::Relaxed);
}

/// Convert a `u32` into a little-endian bit vector.
pub fn from_u32(x: u32) -> BoolMatrix {
    let mut out = BoolMatrix::vector(32);
    for i in 0..32 {
        out.set(i, 0, ((x >> i) & 1) == 1);
    }
    out
}

/// Convert a little-endian bit vector into `u32`.
pub fn to_u32(m: &BoolMatrix) -> u32 {
    assert_eq!(m.rows(), 32);
    let mut x = 0u32;
    for i in 0..32 {
        if m.get(i, 0) {
            x |= 1 << i;
        }
    }
    x
}

fn and_gate<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    a: Share,
    b: Share,
) -> io::Result<Share> {
    ctx.and_gate(a, b)
}

fn or_gate<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    a: Share,
    b: Share,
) -> io::Result<Share> {
    let na = ctx.not(a);
    let nb = ctx.not(b);
    let t = ctx.and_gate(na, nb)?;
    Ok(ctx.not(t))
}

fn eq_share<IO: IOChannel>(ctx: &OneHotContext<'_, IO>, a: Share, b: Share) -> Share {
    ctx.not(a ^ b)
}

/// Add two share vectors of length `bits_to_add`.
pub fn integer_add<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    bits_to_add: usize,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.cols(), 1);
    assert_eq!(y.cols(), 1);
    assert!(x.rows() >= bits_to_add);
    assert!(y.rows() >= bits_to_add);

    let mut out = ShareMatrix::vector(bits_to_add);
    let mut carry = ctx.bit(false);

    for i in 0..bits_to_add - 1 {
        let xc = x[i] ^ carry;
        out[i] = xc ^ y[i];
        let t = ctx.and_gate(xc, y[i] ^ carry)?;
        carry ^= t;
    }
    out[bits_to_add - 1] = x[bits_to_add - 1] ^ y[bits_to_add - 1] ^ carry;
    Ok(out)
}

/// Add two share vectors of equal length.
pub fn integer_add_full<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), y.rows());
    integer_add(ctx, x.rows(), x, y)
}

/// Subtract `y` from `x`.
pub fn integer_sub<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.cols(), 1);
    assert_eq!(y.cols(), 1);
    assert_eq!(x.rows(), y.rows());
    let n = x.rows();

    let mut out = ShareMatrix::vector(n);
    let mut borrow = ctx.bit(false);
    for i in 0..n - 1 {
        let xy = x[i] ^ y[i];
        let yc = y[i] ^ borrow;
        out[i] = xy ^ borrow;
        let t = and_gate(ctx, xy, yc)?;
        borrow ^= t;
    }
    out[n - 1] = x[n - 1] ^ y[n - 1] ^ borrow;
    Ok(out)
}

/// Multiply two share vectors.
pub fn integer_multiply<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.cols(), 1);
    assert_eq!(y.cols(), 1);
    assert_eq!(x.rows(), y.rows());
    let n = x.rows();

    let xy = crate::outer_product(ctx, x.as_slice(), y.as_slice())?;
    let mut sum = ShareMatrix::vector(1);
    sum[0] = xy[(n - 1, n - 1)];

    for i in 1..n {
        let mut shifted = ShareMatrix::vector(sum.rows() + 1);
        for j in 0..sum.rows() {
            shifted[j + 1] = sum[j];
        }
        sum = shifted;

        let mut row_vec = ShareMatrix::vector(i + 1);
        for j in 0..=i {
            row_vec[j] = xy[(n - i - 1, j)];
        }
        sum = integer_add(ctx, i + 1, &sum, &row_vec)?;
    }
    Ok(sum)
}

/// Naive exponentiation used for testing.
pub fn naive_exponent<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    base: u32,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(y.rows(), 32);
    assert_eq!(y.cols(), 1);
    let mut out = ShareMatrix::constant(ctx, &from_u32(base));
    for i in 0..32 {
        out[i] = ctx.and_gate(out[i], y[0])?;
    }

    for i in 1..32 {
        let mut mul = ShareMatrix::constant(ctx, &from_u32(base.wrapping_mul(1 << i)));
        for j in 0..32 {
            mul[j] = ctx.and_gate(mul[j], y[i])?;
        }
        out = integer_multiply(ctx, &out, &mul)?;
    }
    Ok(out)
}

const fn pow32(x: u32, p: u32) -> u32 {
    if p == 0 {
        1
    } else if p == 1 {
        x
    } else {
        let tmp = pow32(x, p / 2);
        if p % 2 == 0 { tmp * tmp } else { x * tmp * tmp }
    }
}

struct ExpTable {
    base: u32,
    shift: usize,
}

impl Table for ExpTable {
    fn row(&self, index: usize) -> usize {
        pow32(self.base, (index << self.shift) as u32) as usize
    }
}

/// One-hot exponentiation following the C++ reference.
pub fn exponent<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    base: u32,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(y.rows(), 32);
    assert_eq!(y.cols(), 1);

    let n_chunks = (32 + chunking_factor() - 1) / chunking_factor();

    let mask = ShareMatrix::uniform(ctx, 32, 1);
    let mut masked = integer_sub(ctx, y, &mask)?;
    masked.reveal(ctx)?;

    let mut one = ShareMatrix::vector(1);
    one[0] = ctx.bit(true);

    let mut result = ShareMatrix::vector(32);
    {
        let mut chunk = ShareMatrix::vector(chunking_factor());
        for i in 0..chunking_factor() {
            chunk[i] = masked[i];
        }
        let table = ExpTable { base, shift: 0 };
        unary_outer_product(ctx, &table, chunk.as_slice(), one.as_slice(), &mut result)?;
    }

    for i in 1..n_chunks {
        let chunk_size = std::cmp::min(32 - i * chunking_factor(), chunking_factor());
        let mut chunk = ShareMatrix::vector(chunk_size);
        for j in 0..chunk_size {
            chunk[j] = masked[j + i * chunking_factor()];
        }
        let table = ExpTable {
            base,
            shift: i * chunking_factor(),
        };
        let mut mul = ShareMatrix::vector(32);
        unary_outer_product(ctx, &table, chunk.as_slice(), one.as_slice(), &mut mul)?;
        result = integer_multiply(ctx, &result, &mul)?;
    }

    let pow_mask = ShareMatrix::constant(ctx, &from_u32(pow32(base, to_u32(&mask.colors()))));
    integer_multiply(ctx, &result, &pow_mask)
}

/// Conditional swap: return `x` if `s` is 1 else `y`.
pub fn swap<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    s: Share,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), y.rows());
    assert_eq!(x.cols(), y.cols());
    let n = x.rows();
    let m = x.cols();

    let mut diff = x.clone();
    diff.xor_assign(y);

    let mut masked = ShareMatrix::new(n, m);
    for i in 0..n {
        for j in 0..m {
            masked[(i, j)] = ctx.and_gate(diff[(i, j)], s)?;
        }
    }
    masked.xor_assign(y);
    Ok(masked)
}

/// Subtract `y` from `x` only if `x > y`.
pub fn sub_if_greater<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
    y: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), 32);
    assert_eq!(y.rows(), 32);
    assert_eq!(x.cols(), 1);
    assert_eq!(y.cols(), 1);

    let diff = integer_sub(ctx, x, y)?;
    let eq_top = eq_share(ctx, x[31], y[31]);
    let neq_top = ctx.not(eq_top);
    let msb_flip = eq_share(ctx, x[31], diff[31]);
    let left = and_gate(ctx, eq_top, ctx.not(msb_flip))?;
    let right = and_gate(ctx, neq_top, x[31])?;
    let gt = or_gate(ctx, left, right)?;
    swap(ctx, gt, x, &diff)
}

struct ModpTable {
    shift: usize,
}

impl Table for ModpTable {
    fn row(&self, index: usize) -> usize {
        (index * (1 << self.shift)) % MOD_P as usize
    }
}

/// Compute `x mod 65521` using the one-hot gadget.
pub fn mod_p<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &ShareMatrix,
) -> io::Result<ShareMatrix> {
    assert_eq!(x.rows(), 32);
    assert_eq!(x.cols(), 1);

    let mask = ShareMatrix::uniform(ctx, 32, 1);
    let mut masked = integer_sub(ctx, x, &mask)?;
    masked.reveal(ctx)?;

    let mut low = ShareMatrix::vector(32);
    let mut mid = ShareMatrix::vector(32);
    let mut high = ShareMatrix::vector(32);
    for i in 0..16 {
        low[i] = masked[i];
    }

    {
        let mut mid_chunk = ShareMatrix::vector(8);
        for i in 0..8 {
            mid_chunk[i] = masked[i + 16];
        }
        let table = ModpTable { shift: 16 };
        let mut one = ShareMatrix::vector(1);
        one[0] = ctx.bit(true);
        unary_outer_product(ctx, &table, mid_chunk.as_slice(), one.as_slice(), &mut mid)?;
    }

    {
        let mut high_chunk = ShareMatrix::vector(8);
        for i in 0..8 {
            high_chunk[i] = masked[i + 24];
        }
        let table = ModpTable { shift: 24 };
        let mut one = ShareMatrix::vector(1);
        one[0] = ctx.bit(true);
        unary_outer_product(
            ctx,
            &table,
            high_chunk.as_slice(),
            one.as_slice(),
            &mut high,
        )?;
    }

    let mut out = integer_add_full(ctx, &low, &mid)?;
    out = integer_add_full(ctx, &out, &high)?;
    let mask_const = ShareMatrix::constant(ctx, &from_u32(to_u32(&mask.colors()) % MOD_P));
    out = integer_add_full(ctx, &out, &mask_const)?;

    out = sub_if_greater(ctx, &out, &ShareMatrix::constant(ctx, &from_u32(MOD_P * 4)))?;
    out = sub_if_greater(ctx, &out, &ShareMatrix::constant(ctx, &from_u32(MOD_P * 2)))?;
    sub_if_greater(ctx, &out, &ShareMatrix::constant(ctx, &from_u32(MOD_P)))
}
