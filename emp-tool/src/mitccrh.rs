//! Multi-instance tweakable circular correlation-robust hash (MITCCRH).
//!
//! This mirrors the C++ `mitccrh.h` API using the existing `Aes` primitive.

use crate::{block::Block, Aes};

/// MITCCRH with a configurable batch size (default 8).
#[derive(Clone)]
pub struct Mitccrh<const BATCH: usize = 8> {
    keys: [Aes; BATCH],
    key_used: usize,
    start_point: Block,
    gid: u64,
}

impl<const BATCH: usize> Mitccrh<BATCH> {
    /// Create with zero start point.
    pub fn new() -> Self {
        Self {
            keys: [Aes::new(Block::ZERO); BATCH],
            key_used: BATCH, // force renew on first use
            start_point: Block::ZERO,
            gid: 0,
        }
    }

    /// Set the seed block `S`.
    pub fn set_s(&mut self, s: Block) {
        self.start_point = s;
    }

    /// Renew key schedules using current gid.
    pub fn renew_with_gid(&mut self, gid: u64) {
        self.gid = gid;
        self.renew();
    }

    /// Renew key schedules, incrementing gid internally.
    pub fn renew(&mut self) {
        for i in 0..BATCH {
            let key = self.start_point ^ Block::from([0, self.gid + i as u64]);
            self.keys[i] = Aes::new(key);
        }
        self.gid += BATCH as u64;
        self.key_used = 0;
    }

    /// Current global identifier used for hashing.
    pub fn gid(&self) -> u64 {
        self.gid
    }

    /// Hash `K*H` blocks in place with K active keys.
    pub fn hash<const K: usize, const H: usize>(&mut self, blks: &mut [Block]) {
        assert!(K <= BATCH);
        assert_eq!(BATCH % K, 0, "Batch size must be divisible by K");
        assert_eq!(blks.len(), K * H);
        if self.key_used == BATCH {
            self.renew();
        }

        let mut tmp = blks.to_vec();
        for k in 0..K {
            let key = self.keys[self.key_used + k];
            for j in 0..H {
                let idx = k * H + j;
                tmp[idx] = key.encrypt_block(tmp[idx]);
            }
        }
        self.key_used += K;

        for i in 0..blks.len() {
            blks[i] ^= tmp[i];
        }
    }

    /// Hash with sigma pre-processing (circular correlation robust variant).
    pub fn hash_cir<const K: usize, const H: usize>(&mut self, blks: &mut [Block]) {
        for b in blks.iter_mut() {
            *b = Block::sigma(*b);
        }
        self.hash::<K, H>(blks);
    }
}

impl Default for Mitccrh {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mitccrh_produces_nontrivial_output() {
        let mut h: Mitccrh<8> = Mitccrh::new();
        h.set_s(Block::from(0x1234_5678_9abc_def0_1357_9bdf_2468_acefu128));
        h.renew_with_gid(0);

        let mut data = vec![Block::ZERO; 4];
        h.hash::<2, 2>(&mut data);
        assert!(data.iter().any(|b| *b != Block::ZERO));

        let mut data2 = vec![Block::ZERO; 4];
        h.hash_cir::<2, 2>(&mut data2);
        assert!(data2.iter().any(|b| *b != Block::ZERO));
        assert_ne!(data, data2);
    }
}
