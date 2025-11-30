use crate::ferret::block_ot::{IknpBlockOtReceiver, IknpBlockOtSender};
use crate::ferret::spcot::{SpcotReceiver, SpcotSender};
use crate::ferret::twokeyprp::TwoKeyPrp;
use crate::{BaseOtRecv, BaseOtSend, Channel, IknpReceiver, IknpSender};
use emp_tool::{prg::Prg, Block};
use rand::SeedableRng;
use sha2::Digest;
use std::io::Result;

/// MPCOT built from multiple SPCOT_full instances.
pub struct MpcotSender<C, B> {
    sender: SpcotSender<C, IknpBlockOtSender<C, B>>,
    tree_n: usize,
    delta: Block,
    tags: Vec<Block>,
    chi_agg: Vec<Block>,
    pre_cot: Vec<Block>,
}

pub struct MpcotReceiver<C, B> {
    receiver: SpcotReceiver<C, IknpBlockOtReceiver<C, B>>,
    tree_n: usize,
    depth: usize,
    chi_alpha: Vec<Block>,
    chi_agg: Vec<Block>,
    w_tags: Vec<Block>,
    pre_cot: Vec<Block>,
}

impl<C, B> MpcotSender<C, B>
where
    C: Channel + Clone,
    B: BaseOtRecv,
{
    pub fn new_from_config(
        delta: Block,
        iknp: IknpSender<C, B>,
        config: crate::ferret::config::FerretConfig,
        prg_seed: Block,
        pre_cot: Vec<Block>,
    ) -> Self {
        let depth = (config.params.log_bin_sz as usize) + 1;
        let mut prg = Prg::from_seed(prg_seed);
        let prp = TwoKeyPrp::new(prg.random_block(), prg.random_block());
        let chan = iknp.clone_channel();
        let ot = IknpBlockOtSender::new(iknp);
        Self {
            sender: SpcotSender::new(chan, ot, depth, prp),
            tree_n: config.params.t as usize,
            delta,
            tags: Vec::with_capacity(config.params.t as usize),
            chi_agg: Vec::with_capacity(config.params.t as usize),
            pre_cot,
        }
    }

    pub fn send(&mut self) -> Result<(Vec<Block>, [u8; 32])> {
        self.tags.clear();
        self.chi_agg.clear();
        for _ in 0..self.tree_n {
            let (_secret, tag, chi) = self.sender.send_with_tag(self.delta)?;
            self.tags.push(tag);
            self.chi_agg.push(chi);
        }
        Ok((self.tags.clone(), self.consistency_hash()))
    }

    pub fn consistency_hash(&self) -> [u8; 32] {
        hash_tags(&self.pre_cot, &self.tags, &self.chi_agg)
    }
}

impl<C, B> MpcotReceiver<C, B>
where
    C: Channel + Clone,
    B: BaseOtSend,
{
    pub fn new_from_config(
        iknp: IknpReceiver<C, B>,
        config: crate::ferret::config::FerretConfig,
        prg_seed: Block,
        pre_cot: Vec<Block>,
    ) -> Self {
        let depth = (config.params.log_bin_sz as usize) + 1;
        let mut prg = Prg::from_seed(prg_seed);
        let prp = TwoKeyPrp::new(prg.random_block(), prg.random_block());
        let chan = iknp.clone_channel();
        let ot = IknpBlockOtReceiver::new(iknp);
        Self {
            receiver: SpcotReceiver::new(chan, ot, depth, prp),
            tree_n: config.params.t as usize,
            depth,
            chi_alpha: Vec::with_capacity(config.params.t as usize),
            chi_agg: Vec::with_capacity(config.params.t as usize),
            w_tags: Vec::with_capacity(config.params.t as usize),
            pre_cot,
        }
    }

    pub fn recv(
        &mut self,
        hot_positions: &[usize],
    ) -> Result<(Vec<Block>, Vec<Block>, Vec<Block>, [u8; 32])> {
        assert_eq!(hot_positions.len(), self.tree_n);
        self.chi_alpha.clear();
        self.chi_agg.clear();
        self.w_tags.clear();
        let mut outs = Vec::with_capacity(self.tree_n);
        for &pos in hot_positions {
            let bits = index_to_bits(pos, self.depth - 1);
            let (leaf, chi, w_tag, chi_agg) = self.receiver.recv_with_tag(&bits)?;
            outs.push(leaf);
            self.chi_alpha.push(chi);
            self.chi_agg.push(chi_agg);
            self.w_tags.push(w_tag);
        }
        Ok((outs, self.w_tags.clone(), self.chi_alpha.clone(), self.consistency_hash()))
    }

    pub fn consistency_hash(&self) -> [u8; 32] {
        hash_tags(&self.pre_cot, &self.w_tags, &self.chi_agg)
    }
}

fn index_to_bits(idx: usize, bits: usize) -> Vec<bool> {
    let mut out = vec![false; bits];
    for i in 0..bits {
        let bit = (idx >> (bits - 1 - i)) & 1;
        out[i] = bit == 1;
    }
    out
}

fn hash_tags(pre_cot: &[Block], tags: &[Block], chi_vec: &[Block]) -> [u8; 32] {
    let mut v = Block::ZERO;
    for t in tags {
        v ^= *t;
    }
    let mut chi = Block::ZERO;
    for c in chi_vec {
        chi ^= *c;
    }
    let mut m = Block::ZERO;
    for mask in pre_cot {
        m ^= *mask;
    }
    // Masked linear check: hash(v XOR chi XOR m)
    let masked = v ^ chi ^ m;
    let digest = sha2::Sha256::digest(<[u8; 16]>::from(masked));
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::NaorPinkasBase;
    use crate::channel::memory_channel_pair;

    #[test]
    fn mpcot_full_round_trip() {
        let (s_chan, r_chan) = memory_channel_pair();
        let base_s = NaorPinkasBase::new(s_chan.clone());
        let base_r = NaorPinkasBase::new(r_chan.clone());
        let iknp_s = IknpSender::new(s_chan, base_s);
        let iknp_r = IknpReceiver::new(r_chan, base_r);
        let config = crate::ferret::config::FerretConfig {
            params: crate::ferret::constants::PrimalLpnParameter::new(4, 2, 2, 2, 0, 0, 0, 0),
            density: 1,
        };
        let prg_seed = Block::from(0x1234u128);
        let pre_cot = vec![Block::ZERO; 128];
        let mut sender =
            MpcotSender::new_from_config(Block::from(0x55u128), iknp_s, config, prg_seed, pre_cot.clone());
        let mut receiver = MpcotReceiver::new_from_config(iknp_r, config, prg_seed, pre_cot);
        let hot_positions = vec![0, 1];
        let recv_thread = std::thread::spawn(move || receiver.recv(&hot_positions).unwrap());
        let sent = sender.send().unwrap();
        let got = recv_thread.join().unwrap();
        assert_eq!(sent.0, got.1, "W tags differ from sender tags");
        assert_eq!(sent.0.len(), got.0.len());
        assert_eq!(sent.1, got.3, "consistency digests differ");
    }
}
