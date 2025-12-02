//! GF(2^128) helper functions mirroring the C++ `f2k.h` utilities.

use crate::block::Block;

/// Carry-less multiply without reduction: returns the low/high limbs.
#[inline(always)]
pub fn mul128(a: Block, b: Block) -> (Block, Block) {
    a.clmul(&b)
}

/// Reduce a 256-bit product modulo x^128 + x^7 + x^2 + x + 1.
#[inline(always)]
pub fn reduce(low: Block, high: Block) -> Block {
    Block::reduce(&low, &high)
}

/// GF multiplication with standard reduction.
#[inline(always)]
pub fn gfmul(a: Block, b: Block) -> Block {
    a.gfmul(&b)
}

/// GF multiplication with “reflect” reduction (alias to standard here).
#[inline(always)]
pub fn gfmul_reflect(a: Block, b: Block) -> Block {
    gfmul(a, b)
}

/// Inner product with reduction: sum_i a[i]*b[i].
#[inline(always)]
pub fn vector_inn_prdt_sum_red(a: &[Block], b: &[Block]) -> Block {
    Block::inn_prdt_red(a, b)
}

/// Inner product without reduction: returns low/high accumulators.
#[inline(always)]
pub fn vector_inn_prdt_sum_no_red(a: &[Block], b: &[Block]) -> (Block, Block) {
    Block::inn_prdt_no_red(a, b)
}

/// Generate coefficients for an almost-universal hash (see C++ `uni_hash_coeff_gen`).
pub fn uni_hash_coeff_gen(coeff: &mut [Block], seed: Block) {
    if coeff.is_empty() {
        return;
    }
    coeff[0] = seed;
    if coeff.len() == 1 {
        return;
    }

    coeff[1] = gfmul(seed, seed);
    if coeff.len() == 2 {
        return;
    }

    coeff[2] = gfmul(coeff[1], seed);
    if coeff.len() == 3 {
        return;
    }

    let multiplier = gfmul(coeff[2], seed);
    coeff[3] = multiplier;
    if coeff.len() == 4 {
        return;
    }

    let mut i = 4;
    while i + 3 < coeff.len() {
        coeff[i] = gfmul(coeff[i - 4], multiplier);
        coeff[i + 1] = gfmul(coeff[i - 3], multiplier);
        coeff[i + 2] = gfmul(coeff[i - 2], multiplier);
        coeff[i + 3] = gfmul(coeff[i - 1], multiplier);
        i += 4;
    }

    while i < coeff.len() {
        coeff[i] = gfmul(coeff[i - 1], seed);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coeff_generation_progresses() {
        let seed = Block::from(0x1234_5678_9abc_def0_1357_9bdf_2468_acefu128);
        let mut coeff = [Block::ZERO; 8];
        uni_hash_coeff_gen(&mut coeff, seed);
        // All coefficients should be non-zero and distinct for this seed.
        for i in 0..coeff.len() {
            assert_ne!(coeff[i], Block::ZERO);
            for j in 0..i {
                assert_ne!(coeff[i], coeff[j]);
            }
        }
    }

    #[test]
    fn inner_product_matches_block_impl() {
        let a = [
            Block::from(1u128),
            Block::from(2u128),
            Block::from(3u128),
            Block::from(4u128),
        ];
        let b = [
            Block::from(5u128),
            Block::from(6u128),
            Block::from(7u128),
            Block::from(8u128),
        ];
        let (low, high) = vector_inn_prdt_sum_no_red(&a, &b);
        let reduced = reduce(low, high);
        assert_eq!(reduced, vector_inn_prdt_sum_red(&a, &b));
    }
}
