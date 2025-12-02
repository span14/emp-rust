use crate::ferret::constants::PrimalLpnParameter;
use emp_tool::{Block, aes::Aes};
use rayon::prelude::*;

/// Lightweight LPN sampler over GF(2) using an implicit matrix defined by an AES-based PRP.
///
/// For each row `i`, we derive `d` column indices via AES(seed, (i, ctr)) and XOR the selected
/// `x[j]` blocks to produce `y[i]`. This keeps memory footprint small while being reproducible
/// across parties that share `seed`, `n`, `k`, and `d`.
#[derive(Clone, Debug)]
pub struct Lpn {
    pub n: usize,
    pub k: usize,
    pub d: usize,
    seed: Block,
}

impl Lpn {
    pub fn new(n: usize, k: usize, d: usize, seed: Block) -> Self {
        assert!(d > 0, "density d must be positive");
        assert!(k > 0, "k must be positive");
        Self { n, k, d, seed }
    }

    /// Construct from a `PrimalLpnParameter` plus an explicit density `d`.
    pub fn from_params(params: PrimalLpnParameter, d: usize, seed: Block) -> Self {
        Self::new(params.n as usize, params.k as usize, d, seed)
    }

    /// Compute y = A * x over GF(2) where A is implicit; parallelized with rayon.
    pub fn apply(&self, x: &[Block]) -> Vec<Block> {
        assert_eq!(x.len(), self.k, "input vector length must equal k");
        let aes = Aes::new(self.seed);
        (0..self.n)
            .into_par_iter()
            .map(|row| eval_row(&aes, row as u64, self.k, self.d, x))
            .collect()
    }

    /// Compute y = A * x + e where e is Bernoulli noise with probability `p_noise`.
    pub fn apply_with_noise(&self, x: &[Block], p_noise: f64) -> Vec<Block> {
        let mut p = p_noise;
        if p < 0.0 {
            p = 0.0;
        } else if p > 1.0 {
            p = 1.0;
        }
        let threshold = (p * u64::MAX as f64) as u64;
        assert_eq!(x.len(), self.k, "input vector length must equal k");
        let aes = Aes::new(self.seed);
        (0..self.n)
            .into_par_iter()
            .map(|row| {
                let mut v = eval_row(&aes, row as u64, self.k, self.d, x);
                let noise = sample_noise_bit(&aes, row as u64, self.d as u64);
                if noise <= threshold {
                    v ^= Block::from(1u128); // flip LSB to represent additive 1 over GF(2)
                }
                v
            })
            .collect()
    }
}

fn eval_row(aes: &Aes, row: u64, k: usize, d: usize, x: &[Block]) -> Block {
    let mut acc = Block::ZERO;
    for ctr in 0..d {
        let input = Block::from([row, ctr as u64]);
        let prp = aes.encrypt_block(input);
        let idx = (u128::from(prp) as usize) % k;
        acc ^= x[idx];
    }
    acc
}

fn sample_noise_bit(aes: &Aes, row: u64, offset: u64) -> u64 {
    let input = Block::from([row, offset]);
    let prp = aes.encrypt_block(input);
    let words: [u64; 2] = prp.into();
    words[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let seed = Block::from(42u128);
        let lpn = Lpn::new(8, 4, 3, seed);
        let x = [
            Block::from(1u128),
            Block::from(2u128),
            Block::from(3u128),
            Block::from(4u128),
        ];
        let y1 = lpn.apply(&x);
        let y2 = lpn.apply(&x);
        assert_eq!(y1, y2);
    }

    #[test]
    fn matches_serial_eval() {
        let seed = Block::from(7u128);
        let lpn = Lpn::new(5, 3, 2, seed);
        let x = [
            Block::from(0xA_u128),
            Block::from(0xB_u128),
            Block::from(0xC_u128),
        ];
        // Serial baseline
        let aes = Aes::new(seed);
        let expected: Vec<Block> = (0..lpn.n)
            .map(|row| eval_row(&aes, row as u64, lpn.k, lpn.d, &x))
            .collect();
        let parallel = lpn.apply(&x);
        assert_eq!(parallel, expected);
    }

    #[test]
    fn noise_probability_applies_deterministically() {
        let seed = Block::from(99u128);
        let lpn = Lpn::new(4, 2, 2, seed);
        let x = [Block::from(1u128), Block::from(2u128)];
        // p_noise=1 should flip all outputs by 1 over GF(2).
        let base = lpn.apply(&x);
        let noisy = lpn.apply_with_noise(&x, 1.0);
        for (b, n) in base.iter().zip(noisy.iter()) {
            assert_eq!(*n, *b ^ Block::from(1u128));
        }
    }

    #[test]
    fn builds_from_params() {
        let seed = Block::from(123u128);
        let params = PrimalLpnParameter::new(8, 2, 4, 0, 0, 0, 0, 0);
        let lpn = Lpn::from_params(params, 3, seed);
        assert_eq!(lpn.n, 8);
        assert_eq!(lpn.k, 4);
        assert_eq!(lpn.d, 3);
        let x = vec![Block::from(1u128); 4];
        let out = lpn.apply(&x);
        assert_eq!(out.len(), 8);
    }
}
