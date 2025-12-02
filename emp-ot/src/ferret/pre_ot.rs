use crate::ferret::hash::Ccrh;
use emp_tool::Block;

/// Simple precomputed OT buffer.
///
/// This mirrors the upstream `OTPre` but omits hashing layers for now.
pub struct PreOt {
    pre_data: Vec<Block>,
    bits: Vec<bool>,
    n: usize,
    length: usize,
    count: usize,
    hasher: Ccrh,
}

impl PreOt {
    pub fn new(length: usize, times: usize) -> Self {
        let n = length * times;
        Self {
            pre_data: vec![Block::ZERO; 2 * n],
            bits: vec![false; n],
            n,
            length,
            count: 0,
            hasher: Ccrh::default(),
        }
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }

    /// Receiver side: preload `bits` and seed material.
    pub fn recv_pre(&mut self, data: &[Block]) {
        assert_eq!(data.len(), self.n);
        let hashed = self.hasher.hash_blocks(data);
        for (i, blk) in data.iter().enumerate() {
            self.bits[i] = blk.get_lsb();
        }
        self.pre_data[..self.n].copy_from_slice(&hashed);
    }

    /// Sender side: preload correlation masks.
    pub fn send_pre(&mut self, data: &[Block], delta: Block) {
        assert_eq!(data.len(), self.n);
        let hashed = self.hasher.hash_blocks(data);
        self.pre_data[..self.n].copy_from_slice(&hashed);
        for i in 0..self.n {
            self.pre_data[self.n + i] = hashed[i] ^ delta;
        }
    }

    pub fn choices_sender(&mut self) {
        self.count += self.length;
    }

    pub fn choices_receiver(&mut self, out: &mut [bool]) {
        assert_eq!(out.len(), self.length);
        out.copy_from_slice(&self.bits[self.count..self.count + self.length]);
        self.count += self.length;
    }

    /// Sender uses precomputed masks to one-time-pad outgoing pairs.
    pub fn send_window(
        &self,
        m0: &[Block],
        m1: &[Block],
        out0: &mut [Block],
        out1: &mut [Block],
        window_idx: usize,
    ) {
        assert_eq!(m0.len(), self.length);
        assert_eq!(m1.len(), self.length);
        assert_eq!(out0.len(), self.length);
        assert_eq!(out1.len(), self.length);
        let start = window_idx * self.length;
        for i in 0..self.length {
            let k = start + i;
            out0[i] = m0[i] ^ self.pre_data[k];
            out1[i] = m1[i] ^ self.pre_data[self.n + k];
        }
    }

    /// Receiver decodes using precomputed mask and choice bits.
    pub fn recv_window(&self, pads0: &[Block], pads1: &[Block], choices: &[bool]) -> Vec<Block> {
        assert_eq!(pads0.len(), self.length);
        assert_eq!(pads1.len(), self.length);
        assert_eq!(choices.len(), self.length);
        let mut out = Vec::with_capacity(self.length);
        let start = self.count - self.length;
        for i in 0..self.length {
            let k = start + i;
            let mask = self.pre_data[k];
            let chosen = if choices[i] { pads1[i] } else { pads0[i] };
            out.push(mask ^ chosen);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_ot_buffers_choices_and_masks() {
        let mut pre = PreOt::new(4, 2);
        let data: Vec<Block> = (0..8).map(|i| Block::from(i as u128)).collect();
        pre.recv_pre(&data);

        let mut choices = [false; 4];
        pre.choices_receiver(&mut choices);
        assert_eq!(choices, [false, true, false, true]); // based on LSB of 0..3
        pre.reset();
        let mut choices2 = [false; 4];
        pre.choices_receiver(&mut choices2);
        assert_eq!(choices2, [false, true, false, true]);
    }
}
