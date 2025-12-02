use crate::{BoolMatrix, IdentityTable, OneHotContext, Share, ShareMatrix, table::Table};
use emp_tool::io_channel::IOChannel;
use std::io;

fn populate_seeds<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &[Share],
) -> io::Result<(Vec<Share>, usize)> {
    let n = x.len();
    assert!(n > 0);
    assert!(n < 64);
    let leaves = 1usize << n;
    let mut seeds = vec![Share::default(); leaves];
    let mut missing: usize = 0;

    // Base layer from the last bit.
    let last = x[n - 1];
    if ctx.is_generator() {
        if last.color() {
            seeds[0] = ctx.hash_current(last);
            seeds[1] = ctx.hash_current(ctx.not(last));
        } else {
            seeds[1] = ctx.hash_current(last);
            seeds[0] = ctx.hash_current(ctx.not(last));
        }
    } else {
        seeds[(!last.color()) as usize] = ctx.hash_current(last);
    }
    missing |= last.color() as usize;
    ctx.bump_nonce(1);

    let one = ctx.bit(true);
    let zero = ctx.bit(false);

    // Walk up the tree.
    for level in 1..n {
        let bit = x[n - level - 1].color();
        let key0 = Share(x[n - level - 1].0 ^ if bit { zero.0 } else { one.0 });
        let key1 = Share(key0.0 ^ one.0);

        if ctx.is_generator() {
            let mut evens = Share::default();
            let mut odds = Share::default();
            for j in (0..(1 << (level - 1))).rev() {
                let parent = seeds[j];
                let odd = ctx.hash_with_tweak(parent, 0);
                let even = ctx.hash_with_tweak(parent, 1);
                seeds[j * 2 + 1] = odd;
                seeds[j * 2] = even;
                evens ^= even;
                odds ^= odd;
            }
            let msg0 = ctx.hash_current(key0) ^ evens;
            let msg1 = ctx.hash_current(key1) ^ odds;
            ctx.io_mut().send_block(&msg0.0)?;
            ctx.io_mut().send_block(&msg1.0)?;
            missing = (missing << 1) | (bit as usize);
        } else {
            let g_evens = Share(ctx.io_mut().recv_block()?);
            let g_odds = Share(ctx.io_mut().recv_block()?);
            let mut e_evens = Share::default();
            let mut e_odds = Share::default();
            for j in (0..(1 << (level - 1))).rev() {
                if j != missing {
                    let parent = seeds[j];
                    let odd = ctx.hash_with_tweak(parent, 0);
                    let even = ctx.hash_with_tweak(parent, 1);
                    seeds[j * 2 + 1] = odd;
                    seeds[j * 2] = even;
                    e_evens ^= even;
                    e_odds ^= odd;
                }
            }
            missing = (missing << 1) | (bit as usize);
            let sibling = if bit {
                ctx.hash_current(x[n - level - 1]) ^ g_evens ^ e_evens
            } else {
                ctx.hash_current(x[n - level - 1]) ^ g_odds ^ e_odds
            };
            seeds[missing ^ 1] = sibling;
        }
        ctx.bump_nonce(1);
    }

    Ok((seeds, missing))
}

/// One-hot unary outer product.
pub fn unary_outer_product<IO: IOChannel, T: Table>(
    ctx: &mut OneHotContext<'_, IO>,
    table: &T,
    x: &[Share],
    y: &[Share],
    out: &mut ShareMatrix,
) -> io::Result<()> {
    assert_eq!(y.len(), out.cols());
    let l = out.rows();
    let n = x.len();
    let m = y.len();
    let leaves = 1usize << n;

    let (seeds, missing) = populate_seeds(ctx, x)?;
    let base_nonce = ctx.nonce();

    if ctx.is_generator() {
        let mut messages = Vec::with_capacity(m);
        for j in 0..m {
            let mut sum = Share::default();
            for i in 0..leaves {
                let tweak = base_nonce + (leaves as u64) * (j as u64) + (i as u64);
                let s = ctx.hash_with_tweak(seeds[i], tweak);
                sum ^= s;
                let frow = table.row(i);
                for k in 0..l {
                    if (frow >> k) & 1 == 1 {
                        out.xor_cell(k, j, s);
                    }
                }
            }
            messages.push(sum ^ y[j]);
        }
        for msg in messages {
            ctx.io_mut().send_block(&msg.0)?;
        }
    } else {
        let mut messages = Vec::with_capacity(m);
        for _ in 0..m {
            messages.push(Share(ctx.io_mut().recv_block()?));
        }

        for (j, g_sum) in messages.into_iter().enumerate() {
            let mut e_sum = Share::default();
            for i in 0..leaves {
                if i == missing {
                    continue;
                }
                let tweak = base_nonce + (leaves as u64) * (j as u64) + (i as u64);
                let s = ctx.hash_with_tweak(seeds[i], tweak);
                e_sum ^= s;
                let frow = table.row(i);
                for k in 0..l {
                    if (frow >> k) & 1 == 1 {
                        out.xor_cell(k, j, s);
                    }
                }
            }
            let s = e_sum ^ g_sum ^ y[j];
            let frow = table.row(missing);
            for k in 0..l {
                if (frow >> k) & 1 == 1 {
                    out.xor_cell(k, j, s);
                }
            }
        }
    }

    ctx.set_nonce(base_nonce + (leaves as u64) * (m as u64));
    Ok(())
}

/// Compute `(x + color(x)) * y`.
pub fn half_outer_product<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &[Share],
    y: &[Share],
    out: &mut ShareMatrix,
) -> io::Result<()> {
    assert_eq!(out.rows(), x.len());
    assert_eq!(out.cols(), y.len());
    unary_outer_product(ctx, &IdentityTable, x, y, out)
}

/// Full outer product using the one-hot construction.
pub fn outer_product<IO: IOChannel>(
    ctx: &mut OneHotContext<'_, IO>,
    x: &[Share],
    y: &[Share],
) -> io::Result<ShareMatrix> {
    let mut out = ShareMatrix::new(x.len(), y.len());
    half_outer_product(ctx, x, y, &mut out)?;

    let x_colors: Vec<bool> = x.iter().map(Share::color).collect();
    let y_colors: Vec<bool> = y.iter().map(Share::color).collect();
    let x_const = ShareMatrix::constant(ctx, &BoolMatrix::from_vec(x.len(), 1, x_colors.clone()));

    let mut transposed = ShareMatrix::new(y.len(), x.len());
    half_outer_product(ctx, y, x_const.as_slice(), &mut transposed)?;
    out.xor_transpose_assign(&transposed);

    let xy_const = BoolMatrix::outer_product(&x_colors, &y_colors);
    let xy_share = ShareMatrix::constant(ctx, &xy_const);
    out.xor_assign(&xy_share);

    Ok(out)
}
