use emp_tool::Block;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

/// Generate universal hash coefficients deterministically from a key block.
pub fn uni_hash_coeff_gen(key: Block, n: usize) -> Vec<Block> {
    let mut hasher = Sha256::new();
    hasher.update(<[u8; 16]>::from(key));
    let digest = hasher.finalize();
    let mut seed_bytes = [0u8; 16];
    seed_bytes.copy_from_slice(&digest[..16]);
    let mut prg = emp_tool::prg::Prg::from_seed(Block::from(seed_bytes));
    let mut coeffs = vec![Block::ZERO; n];
    prg.random_blocks(&mut coeffs);
    coeffs
}

/// Compute inner product sum in GF(2^128) without reduction, returning (low, high) parts.
pub fn vector_inn_prdt_sum_no_red(a: &[Block], b: &[Block]) -> (Block, Block) {
    assert_eq!(a.len(), b.len());
    let mut acc_low = Block::ZERO;
    let mut acc_high = Block::ZERO;
    for (x, y) in a.iter().zip(b.iter()) {
        let (l, h) = emp_tool::block::Block::inn_prdt_no_red(&[*x], &[*y]);
        acc_low ^= l;
        acc_high ^= h;
    }
    (acc_low, acc_high)
}

/// Compute inner product sum reduced to GF(2^128).
pub fn vector_inn_prdt_sum_red(a: &[Block], b: &[Block]) -> Block {
    let (l, h) = vector_inn_prdt_sum_no_red(a, b);
    emp_tool::block::Block::inn_prdt_red(&[l], &[h])
}
