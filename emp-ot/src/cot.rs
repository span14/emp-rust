use crate::{Channel, IknpReceiver, IknpSender};
use emp_tool::{Block, prg::Prg};
use sha2::{Digest, Sha256};
use std::io::Result;

use crate::{BaseOtRecv, BaseOtSend};

/// Correlated OT sender: holds the correlation Delta.
pub struct CotSender<C, B> {
    delta: Block,
    inner: IknpSender<C, B>,
    prg: Prg,
}

/// Correlated OT receiver.
pub struct CotReceiver<C, B> {
    inner: IknpReceiver<C, B>,
}

impl<C, B> CotSender<C, B>
where
    C: Channel + Clone,
    B: BaseOtRecv,
{
    pub fn new(delta: Block, inner: IknpSender<C, B>) -> Self {
        Self {
            delta,
            inner,
            prg: Prg::new(),
        }
    }

    /// Execute correlated OT: sender inputs Delta, learns q values; receiver gets q or q^Delta.
    pub fn send(&mut self, len: usize) -> Result<Vec<Block>> {
        let mut q = vec![Block::ZERO; len];
        self.prg.random_blocks(&mut q);
        let m0 = q.clone();
        let mut m1 = Vec::with_capacity(len);
        for v in &m0 {
            m1.push(*v ^ self.delta);
        }
        self.inner.send(&m0, &m1)?;
        Ok(q)
    }

    /// Random OT derived from correlated OT seeds.
    pub fn send_rot(&mut self, len: usize) -> Result<(Vec<Block>, Vec<Block>)> {
        let q = self.send(len)?;
        let mut out0 = Vec::with_capacity(len);
        let mut out1 = Vec::with_capacity(len);
        for (i, &seed) in q.iter().enumerate() {
            out0.push(kdf_block(&seed, i as u64));
            out1.push(kdf_block(&(seed ^ self.delta), i as u64));
        }
        Ok((out0, out1))
    }
}

impl<C, B> CotReceiver<C, B>
where
    C: Channel + Clone,
    B: BaseOtSend,
{
    pub fn new(inner: IknpReceiver<C, B>) -> Self {
        Self { inner }
    }

    /// Receive correlated OT outputs for given choices.
    pub fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        self.inner.recv(choices)
    }

    /// Random OT derived from correlated OT seeds.
    pub fn recv_rot(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        let seeds = self.recv(choices)?;
        let mut out = Vec::with_capacity(seeds.len());
        for (i, seed) in seeds.into_iter().enumerate() {
            out.push(kdf_block(&seed, i as u64));
        }
        Ok(out)
    }
}

fn kdf_block(input: &Block, idx: u64) -> Block {
    let mut h = Sha256::new();
    h.update(<[u8; 16]>::from(*input));
    h.update(idx.to_le_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Block::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::NaorPinkasBase;
    use crate::channel::memory_channel_pair;

    #[test]
    fn correlated_ot_round_trip() {
        let (sender_chan, recv_chan) = memory_channel_pair();
        let base_s = NaorPinkasBase::new(sender_chan.clone());
        let base_r = NaorPinkasBase::new(recv_chan.clone());
        let iknp_s = IknpSender::new(sender_chan, base_s);
        let iknp_r = IknpReceiver::new(recv_chan, base_r);
        let delta = Block::from(rand::random::<u128>());
        let mut sender = CotSender::new(delta, iknp_s);
        let mut receiver = CotReceiver::new(iknp_r);

        let choices = vec![false, true, false, true, true];
        let choices_for_thread = choices.clone();
        let handle = std::thread::spawn(move || receiver.recv(&choices_for_thread).unwrap());
        let q = sender.send(choices.len()).unwrap();
        let out = handle.join().unwrap();

        assert_eq!(q.len(), choices.len());
        assert_eq!(out.len(), choices.len());
        for i in 0..choices.len() {
            let expected = if choices[i] { q[i] ^ delta } else { q[i] };
            assert_eq!(out[i], expected);
        }
    }

    #[test]
    fn random_ot_round_trip() {
        let (sender_chan, recv_chan) = memory_channel_pair();
        let base_s = NaorPinkasBase::new(sender_chan.clone());
        let base_r = NaorPinkasBase::new(recv_chan.clone());
        let iknp_s = IknpSender::new(sender_chan, base_s);
        let iknp_r = IknpReceiver::new(recv_chan, base_r);
        let delta = Block::from(rand::random::<u128>());
        let mut sender = CotSender::new(delta, iknp_s);
        let mut receiver = CotReceiver::new(iknp_r);

        let choices = vec![false, true, true, false];
        let choices_for_thread = choices.clone();
        let handle = std::thread::spawn(move || receiver.recv_rot(&choices_for_thread).unwrap());
        let (m0, m1) = sender.send_rot(choices.len()).unwrap();
        let out = handle.join().unwrap();

        assert_eq!(m0.len(), choices.len());
        assert_eq!(m1.len(), choices.len());
        for i in 0..choices.len() {
            let expected = if choices[i] { m1[i] } else { m0[i] };
            assert_eq!(out[i], expected);
        }
    }
}
