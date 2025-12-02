#![deny(missing_docs)]
//! One-hot garbling primitives built on top of `emp-tool`.
//!
//! The API mirrors the reference C++ implementation in `one-hot-garbling`.
//! A [`OneHotContext`] owns the cryptographic state (global key, delta, nonce)
//! and an [`emp_tool::io_channel::IOChannel`] transport. Operations take
//! the context and lists of [`Share`]s to produce garbled outputs.

mod context;
mod gf256;
mod integer;
mod matrix;
mod role;
mod share;
mod share_matrix;
mod table;
mod unary;

pub use context::OneHotContext;
pub use gf256::{aes_sbox, gf256_invert, half_mul_gf256, mul_gf256};
pub use integer::{
    MOD_P, chunking_factor, exponent, from_u32, integer_add, integer_add_full, integer_multiply,
    integer_sub, mod_p, naive_exponent, set_chunking_factor, sub_if_greater, swap, to_u32,
};
pub use matrix::BoolMatrix;
pub use role::Role;
pub use share::Share;
pub use share_matrix::{ShareMatrix, decode_matrix};
pub use table::{IdentityTable, Table};
pub use unary::{half_outer_product, outer_product, unary_outer_product};

#[cfg(test)]
mod tests {
    use super::*;
    use emp_tool::Block;
    use emp_tool::io_channel::NetIO;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;
    use std::thread;

    #[test]
    fn outer_product_matches_plain_bits() {
        let mut rng = ChaCha12Rng::seed_from_u64(7);

        let fixed_key = Block::from(rng.random::<u128>());
        let seed = Block::from(rng.random::<u128>());

        let n = 4usize;
        let m = 3usize;
        let x_bits: Vec<bool> = (0..n).map(|_| rng.random()).collect();
        let y_bits: Vec<bool> = (0..m).map(|_| rng.random()).collect();
        let x_bits_eval = x_bits.clone();
        let y_bits_eval = y_bits.clone();

        let addr = format!(
            "127.0.0.1:{}",
            12_345 + (rng.random::<u16>() % 1000) as usize
        );

        let x_bits_g = x_bits.clone();
        let y_bits_g = y_bits.clone();
        let addr_g = addr.clone();
        let generator = thread::spawn(move || {
            let mut io = NetIO::new(true, &addr_g).unwrap();
            let mut ctx = OneHotContext::new_generator(&mut io, fixed_key, seed);
            let x_shares: Vec<Share> = x_bits_g.iter().map(|&b| ctx.bit(b)).collect();
            let y_shares: Vec<Share> = y_bits_g.iter().map(|&b| ctx.bit(b)).collect();
            let out = outer_product(&mut ctx, &x_shares, &y_shares).unwrap();
            (out, ctx.delta())
        });

        thread::sleep(std::time::Duration::from_millis(25));

        let addr_e = addr.clone();
        let evaluator = thread::spawn(move || {
            let mut io = NetIO::new(false, &addr_e).unwrap();
            let mut ctx = OneHotContext::new_evaluator(&mut io, fixed_key, seed);
            let x_shares: Vec<Share> = x_bits_eval.iter().map(|&b| ctx.bit(b)).collect();
            let y_shares: Vec<Share> = y_bits_eval.iter().map(|&b| ctx.bit(b)).collect();
            outer_product(&mut ctx, &x_shares, &y_shares).unwrap()
        });

        let (out_g, delta) = generator.join().unwrap();
        let out_e = evaluator.join().unwrap();
        let decoded = decode_matrix(delta, &out_g, &out_e);

        for i in 0..n {
            for j in 0..m {
                assert_eq!(decoded.get(i, j), x_bits[i] & y_bits[j]);
            }
        }
    }
}
