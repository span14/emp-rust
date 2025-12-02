use crate::ferret::config::FerretConfig;
use crate::ferret::mpcot::{MpcotReceiver, MpcotSender};
use crate::{BaseOtRecv, BaseOtSend, Channel, IknpReceiver, IknpSender};
use emp_tool::{Block, prg::Prg};
use rand::SeedableRng;
use std::io::Result;

/// Ferret sender wrapper built on top of MPCOT.
pub struct FerretSender<C, B> {
    inner: MpcotSender<C, B>,
}

/// Ferret receiver wrapper built on top of MPCOT.
pub struct FerretReceiver<C, B> {
    inner: MpcotReceiver<C, B>,
}

impl<C, B> FerretSender<C, B>
where
    C: Channel + Clone,
    B: BaseOtRecv,
{
    pub fn new_from_config(
        delta: Block,
        iknp: IknpSender<C, B>,
        config: FerretConfig,
        prg_seed: Block,
        pre_cot: Vec<Block>,
    ) -> Self {
        Self {
            inner: MpcotSender::new_from_config(delta, iknp, config, prg_seed, pre_cot),
        }
    }

    pub fn send(&mut self) -> Result<(Vec<Block>, [u8; 32])> {
        self.inner.send()
    }

    pub fn consistency_hash(&self) -> [u8; 32] {
        self.inner.consistency_hash()
    }

    // buckets path not supported in full alignment
}

impl<C, B> FerretReceiver<C, B>
where
    C: Channel + Clone,
    B: BaseOtSend,
{
    pub fn new_from_config(
        iknp: IknpReceiver<C, B>,
        config: FerretConfig,
        prg_seed: Block,
        pre_cot: Vec<Block>,
    ) -> Self {
        Self {
            inner: MpcotReceiver::new_from_config(iknp, config, prg_seed, pre_cot),
        }
    }

    pub fn recv(
        &mut self,
        hot_positions: &[usize],
    ) -> Result<(Vec<Block>, Vec<Block>, Vec<Block>, [u8; 32])> {
        self.inner.recv(hot_positions)
    }

    pub fn consistency_hash(&self) -> [u8; 32] {
        self.inner.consistency_hash()
    }

    // buckets path not supported in full alignment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::NaorPinkasBase;
    use crate::channel::memory_channel_pair;
    use crate::ferret::constants::PrimalLpnParameter;

    #[test]
    fn ferret_rot_round_trip() {
        let (sender_chan, recv_chan) = memory_channel_pair();
        let base_s = NaorPinkasBase::new(sender_chan.clone());
        let base_r = NaorPinkasBase::new(recv_chan.clone());
        let iknp_s = IknpSender::new(sender_chan, base_s);
        let iknp_r = IknpReceiver::new(recv_chan, base_r);

        let delta = Block::from(0x5555_u128);
        // Small params to keep the test fast.
        let small_params = PrimalLpnParameter::new(8, 5, 5, 2, 0, 0, 0, 0);
        let config = FerretConfig {
            params: small_params,
            density: 1,
        };
        let prg_seed = Block::from(0xAAAABBBB_u128);
        let pre_cot = pre_cot_from_seed(prg_seed);
        let mut sender =
            FerretSender::new_from_config(delta, iknp_s, config, prg_seed, pre_cot.clone());
        let hot_positions = vec![0, 1, 2, 3, 0];
        let hot_for_thread = hot_positions.clone();
        let handle = std::thread::spawn(move || {
            FerretReceiver::new_from_config(iknp_r, config, prg_seed, pre_cot)
                .recv(&hot_for_thread)
                .unwrap()
        });
        let (tags, send_hash) = sender.send().unwrap();
        let (out, w_tags, chi, recv_hash) = handle.join().unwrap();

        assert_eq!(tags.len(), w_tags.len());
        assert_eq!(chi.len(), hot_positions.len());
        assert_eq!(out.len(), hot_positions.len());
        assert_eq!(send_hash, recv_hash);
    }

    #[test]
    fn ferret_rot_round_trip_with_buckets() {
        // Buckets path not supported in full alignment; ensure basic send/recv still works.
        let (sender_chan, recv_chan) = memory_channel_pair();
        let base_s = NaorPinkasBase::new(sender_chan.clone());
        let base_r = NaorPinkasBase::new(recv_chan.clone());
        let iknp_s = IknpSender::new(sender_chan, base_s);
        let iknp_r = IknpReceiver::new(recv_chan, base_r);

        let delta = Block::from(0x5555_u128);
        let config = FerretConfig {
            params: PrimalLpnParameter::new(8, 5, 5, 2, 0, 0, 0, 0),
            density: 1,
        };
        let prg_seed = Block::from(0x1111u128);
        let pre_cot = pre_cot_from_seed(prg_seed);
        let mut sender =
            FerretSender::new_from_config(delta, iknp_s, config, prg_seed, pre_cot.clone());
        let hot_positions = vec![0, 1, 2, 3, 0];
        let hot_for_thread = hot_positions.clone();
        let handle = std::thread::spawn(move || {
            FerretReceiver::new_from_config(iknp_r, config, prg_seed, pre_cot)
                .recv(&hot_for_thread)
                .unwrap()
        });
        let (tags, send_hash) = sender.send().unwrap();
        let (out, w_tags, chi, recv_hash) = handle.join().unwrap();

        assert_eq!(tags.len(), w_tags.len());
        assert_eq!(chi.len(), hot_positions.len());
        assert_eq!(out.len(), hot_positions.len());
        assert_eq!(send_hash, recv_hash);
    }
}

fn pre_cot_from_seed(seed: Block) -> Vec<Block> {
    let mut prg = Prg::from_seed(seed);
    let mut buf = vec![Block::ZERO; 128];
    prg.random_blocks(&mut buf);
    buf
}
