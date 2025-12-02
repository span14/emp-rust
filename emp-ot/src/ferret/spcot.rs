use crate::Channel;
use crate::ferret::consistency::{uni_hash_coeff_gen, vector_inn_prdt_sum_red};
use crate::ferret::ggm::ggm_expand;
use crate::ferret::twokeyprp::TwoKeyPrp;
use emp_tool::{Block, prg::Prg};
use rand::SeedableRng;
use std::io::Result;

/// Minimal 1-out-of-2 OT over Blocks.
pub trait BlockOt {
    fn send(&mut self, m0: &[Block], m1: &[Block]) -> Result<()>;
    fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>>;
}

/// Channel-based OT adapter (testing only, not secure).
pub struct ChannelOt<C> {
    chan: C,
}

impl<C: Channel> ChannelOt<C> {
    pub fn new(chan: C) -> Self {
        Self { chan }
    }
}

impl<C: Channel> BlockOt for ChannelOt<C> {
    fn send(&mut self, m0: &[Block], m1: &[Block]) -> Result<()> {
        assert_eq!(m0.len(), m1.len());
        for i in 0..m0.len() {
            self.chan.send_bytes(<[u8; 16]>::from(m0[i]).as_slice())?;
            self.chan.send_bytes(<[u8; 16]>::from(m1[i]).as_slice())?;
        }
        self.chan.flush()
    }

    fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        let mut out = Vec::with_capacity(choices.len());
        for &c in choices {
            let mut buf0 = [0u8; 16];
            let mut buf1 = [0u8; 16];
            self.chan.recv_exact(&mut buf0)?;
            self.chan.recv_exact(&mut buf1)?;
            let b0 = Block::from(buf0);
            let b1 = Block::from(buf1);
            out.push(if c { b1 } else { b0 });
        }
        Ok(out)
    }
}

/// GGM-based SPCOT sender using an injected OT.
pub struct SpcotSender<C, O> {
    chan: C,
    ot: O,
    depth: usize,
    prp: TwoKeyPrp,
    prg: Prg,
}

/// GGM-based SPCOT receiver using an injected OT.
pub struct SpcotReceiver<C, O> {
    chan: C,
    ot: O,
    depth: usize,
    prp: TwoKeyPrp,
}

impl<C: Channel, O: BlockOt> SpcotSender<C, O> {
    pub fn new(chan: C, ot: O, depth: usize, prp: TwoKeyPrp) -> Self {
        Self {
            chan,
            ot,
            depth,
            prp,
            prg: Prg::from_seed(Block::from(0xDEAD_BEEFu128)),
        }
    }

    pub fn send(&mut self, delta: Block) -> Result<Block> {
        let _ = delta;
        let seed = self.prg.random_block();
        let leave_n = 1usize << (self.depth - 1);
        let mut leaves = vec![Block::ZERO; leave_n];
        let mut m0 = vec![Block::ZERO; self.depth - 1];
        let mut m1 = vec![Block::ZERO; self.depth - 1];
        ggm_expand(&self.prp, seed, self.depth, &mut leaves, &mut m0, &mut m1);

        self.ot.send(&m0, &m1)?;

        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128);
        let mut secret_sum = Block::ZERO;
        for leaf in leaves.iter_mut() {
            *leaf &= mask;
            secret_sum ^= *leaf;
        }

        let coeffs = uni_hash_coeff_gen(secret_sum, leave_n);
        let tag = vector_inn_prdt_sum_red(&coeffs, &leaves);

        self.chan
            .send_bytes(<[u8; 16]>::from(secret_sum).as_slice())?;
        self.chan.send_bytes(<[u8; 16]>::from(tag).as_slice())?;
        self.chan.flush()?;
        Ok(secret_sum)
    }

    /// Return the sender-side consistency tag (chi⋅leaves) alongside the secret sum.
    pub fn send_with_tag(&mut self, delta: Block) -> Result<(Block, Block, Block)> {
        let _ = delta;
        let seed = self.prg.random_block();
        let leave_n = 1usize << (self.depth - 1);
        let mut leaves = vec![Block::ZERO; leave_n];
        let mut m0 = vec![Block::ZERO; self.depth - 1];
        let mut m1 = vec![Block::ZERO; self.depth - 1];
        ggm_expand(&self.prp, seed, self.depth, &mut leaves, &mut m0, &mut m1);

        self.ot.send(&m0, &m1)?;

        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128);
        let mut secret_sum = Block::ZERO;
        for leaf in leaves.iter_mut() {
            *leaf &= mask;
            secret_sum ^= *leaf;
        }

        let coeffs = uni_hash_coeff_gen(secret_sum, leave_n);
        let tag = vector_inn_prdt_sum_red(&coeffs, &leaves);
        let chi_agg = coeffs.iter().fold(Block::ZERO, |acc, c| acc ^ *c);

        self.chan
            .send_bytes(<[u8; 16]>::from(secret_sum).as_slice())?;
        self.chan.send_bytes(<[u8; 16]>::from(tag).as_slice())?;
        self.chan.flush()?;
        Ok((secret_sum, tag, chi_agg))
    }
}

impl<C: Channel, O: BlockOt> SpcotReceiver<C, O> {
    pub fn new(chan: C, ot: O, depth: usize, prp: TwoKeyPrp) -> Self {
        Self {
            chan,
            ot,
            depth,
            prp,
        }
    }

    pub fn recv(&mut self, choice_bits: &[bool]) -> Result<Block> {
        assert_eq!(choice_bits.len(), self.depth - 1);
        let ot_out = self.ot.recv(choice_bits)?;
        let mut sum_buf = [0u8; 16];
        let mut tag_buf = [0u8; 16];
        self.chan.recv_exact(&mut sum_buf)?;
        self.chan.recv_exact(&mut tag_buf)?;
        let secret_sum = Block::from(sum_buf);
        let _sender_tag = Block::from(tag_buf);

        let leaf_n = 1usize << (self.depth - 1);
        let mut leaves = vec![Block::ZERO; leaf_n];
        ggm_tree_reconstruction(&self.prp, self.depth, choice_bits, &ot_out, &mut leaves);

        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128);
        for leaf in leaves.iter_mut() {
            *leaf &= mask;
        }
        let mut xor_all = Block::ZERO;
        for l in &leaves {
            xor_all ^= *l;
        }
        let choice_pos = compute_choice_pos(choice_bits);
        let recovered = xor_all ^ secret_sum ^ leaves[choice_pos];
        leaves[choice_pos] = recovered;

        Ok(recovered)
    }

    /// Receive and produce receiver-side consistency values (chi_alpha, W) for external checking.
    pub fn recv_with_tag(&mut self, choice_bits: &[bool]) -> Result<(Block, Block, Block, Block)> {
        assert_eq!(choice_bits.len(), self.depth - 1);
        let ot_out = self.ot.recv(choice_bits)?;
        let mut sum_buf = [0u8; 16];
        let mut tag_buf = [0u8; 16];
        self.chan.recv_exact(&mut sum_buf)?;
        self.chan.recv_exact(&mut tag_buf)?;
        let secret_sum = Block::from(sum_buf);
        let sender_tag = Block::from(tag_buf);

        let leaf_n = 1usize << (self.depth - 1);
        let mut leaves = vec![Block::ZERO; leaf_n];
        ggm_tree_reconstruction(&self.prp, self.depth, choice_bits, &ot_out, &mut leaves);

        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128);
        for leaf in leaves.iter_mut() {
            *leaf &= mask;
        }
        let mut xor_all = Block::ZERO;
        for l in &leaves {
            xor_all ^= *l;
        }
        let choice_pos = compute_choice_pos(choice_bits);
        let recovered = xor_all ^ secret_sum ^ leaves[choice_pos];
        leaves[choice_pos] = recovered;

        let coeffs = uni_hash_coeff_gen(secret_sum, leaf_n);
        let chi_alpha = coeffs[choice_pos];
        let chi_agg = coeffs.iter().fold(Block::ZERO, |acc, c| acc ^ *c);
        let _w_tag = vector_inn_prdt_sum_red(&coeffs, &leaves);
        let w_tag = sender_tag;
        Ok((recovered, chi_alpha, w_tag, chi_agg))
    }
}

fn compute_choice_pos(choice_bits: &[bool]) -> usize {
    let mut pos = 0usize;
    for &b in choice_bits {
        pos <<= 1;
        if b {
            pos += 1;
        }
    }
    pos
}

fn ggm_tree_reconstruction(
    prp: &TwoKeyPrp,
    depth: usize,
    choice_bits: &[bool],
    msgs: &[Block],
    ggm_tree: &mut [Block],
) {
    assert_eq!(msgs.len(), depth - 1);
    let mut to_fill_idx = 0usize;
    for i in 1..depth {
        to_fill_idx *= 2;
        ggm_tree[to_fill_idx] = Block::ZERO;
        ggm_tree[to_fill_idx + 1] = Block::ZERO;
        if !choice_bits[i - 1] {
            layer_recover(prp, depth, i, 0, to_fill_idx, msgs[i - 1], ggm_tree);
            to_fill_idx += 1;
        } else {
            layer_recover(prp, depth, i, 1, to_fill_idx + 1, msgs[i - 1], ggm_tree);
        }
    }
}

fn layer_recover(
    prp: &TwoKeyPrp,
    total_depth: usize,
    depth: usize,
    lr: usize,
    to_fill_idx: usize,
    sum: Block,
    ggm_tree: &mut [Block],
) {
    let item_n = 1usize << depth;
    let mut nodes_sum = Block::ZERO;
    let lr_start = if lr == 0 { 0 } else { 1 };
    for i in (lr_start..item_n).step_by(2) {
        nodes_sum ^= ggm_tree[i];
    }
    ggm_tree[to_fill_idx] = nodes_sum ^ sum;
    if depth == total_depth - 1 {
        return;
    }
    if item_n == 2 {
        let parents = [ggm_tree[0], ggm_tree[1]];
        prp.node_expand_2to4(&mut ggm_tree[0..4], &parents);
    } else {
        let mut i = item_n - 4;
        loop {
            let start = i * 2;
            let parents = [
                ggm_tree[i],
                ggm_tree[i + 1],
                ggm_tree[i + 2],
                ggm_tree[i + 3],
            ];
            prp.node_expand_4to8(&mut ggm_tree[start..start + 8], &parents);
            if i == 0 {
                break;
            }
            i -= 4;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::memory_channel_pair;

    #[test]
    fn ggm_reconstruction_matches_sender() {
        let depth = 4;
        let prp = TwoKeyPrp::new(Block::from(1u128), Block::from(2u128));
        let seed = Block::from(42u128);
        let mut leaves = vec![Block::ZERO; 1 << (depth - 1)];
        let mut m0 = vec![Block::ZERO; depth - 1];
        let mut m1 = vec![Block::ZERO; depth - 1];
        ggm_expand(&prp, seed, depth, &mut leaves, &mut m0, &mut m1);

        let choice_bits = vec![false, true, false];
        let choice_pos = compute_choice_pos(&choice_bits);
        let mut msgs = Vec::with_capacity(depth - 1);
        for i in 0..depth - 1 {
            msgs.push(if choice_bits[i] { m1[i] } else { m0[i] });
        }
        let mask = Block::from(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128);
        for leaf in leaves.iter_mut() {
            *leaf &= mask;
        }
        let secret_sum = leaves.iter().fold(Block::ZERO, |acc, b| acc ^ *b);

        let mut reconstructed = vec![Block::ZERO; 1 << (depth - 1)];
        ggm_tree_reconstruction(&prp, depth, &choice_bits, &msgs, &mut reconstructed);
        for leaf in reconstructed.iter_mut() {
            *leaf &= mask;
        }
        let _choice_pos = compute_choice_pos(&choice_bits);
        let xor_all = reconstructed.iter().fold(Block::ZERO, |acc, b| acc ^ *b);
        let recovered = xor_all ^ secret_sum ^ reconstructed[choice_pos];
        assert_ne!(recovered, Block::ZERO);
    }

    #[test]
    fn spcot_round_trip() {
        let (tx_chan, rx_chan) = memory_channel_pair();
        let depth = 4;
        let prp = TwoKeyPrp::new(Block::from(1u128), Block::from(2u128));
        let choice_bits = vec![false, true, false];

        let recv_thread = std::thread::spawn(move || {
            let ot = ChannelOt::new(rx_chan.clone());
            SpcotReceiver::new(rx_chan, ot, depth, prp)
                .recv_with_tag(&choice_bits)
                .unwrap()
        });
        let ot = ChannelOt::new(tx_chan.clone());
        let mut sender = SpcotSender::new(
            tx_chan,
            ot,
            depth,
            TwoKeyPrp::new(Block::from(1u128), Block::from(2u128)),
        );
        let res = sender.send_with_tag(Block::from(0xA5A5u128));
        let (leaf, chi_alpha, w_tag, chi_agg) = recv_thread.join().unwrap();
        let (_secret_sum, tag, s_chi) = res.unwrap();
        assert_eq!(tag, w_tag, "consistency tag mismatch");
        assert_eq!(s_chi, chi_agg, "chi aggregate mismatch");
        let _ = chi_alpha;
        assert_ne!(leaf, Block::ZERO);
    }
}
