use crate::{base::BaseOtRecv, base::BaseOtSend, channel::Channel};
use emp_tool::{Block, prg::Prg};
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::io::{Error, ErrorKind, Result};

const K: usize = 128;

/// IKNP OT extension sender (inputs message pairs).
pub struct IknpSender<C, B> {
    chan: C,
    base: B,
    delta: [bool; K],
    seeds: [Block; K],
    prgs: [Prg; K],
    setup: bool,
}

/// IKNP OT extension receiver (inputs choice bits).
pub struct IknpReceiver<C, B> {
    chan: C,
    base: B,
    seeds0: [Block; K],
    seeds1: [Block; K],
    prg0: [Prg; K],
    prg1: [Prg; K],
    setup: bool,
}

impl<C, B> IknpSender<C, B>
where
    C: Channel + Clone,
    B: BaseOtRecv,
{
    pub fn new(chan: C, base: B) -> Self {
        Self {
            chan,
            base,
            delta: [false; K],
            seeds: [Block::ZERO; K],
            prgs: init_prg_array(),
            setup: false,
        }
    }

    pub fn clone_channel(&self) -> C {
        self.chan.clone()
    }

    fn ensure_setup(&mut self) -> Result<()> {
        if self.setup {
            return Ok(());
        }
        let mut prg = Prg::new();
        prg.random_bools(&mut self.delta);
        self.base.recv(&self.delta, &mut self.seeds)?;
        for i in 0..K {
            self.prgs[i] = Prg::from_seed(self.seeds[i]);
        }
        self.setup = true;
        Ok(())
    }

    /// Execute OTs for the sender role.
    pub fn send(&mut self, m0: &[Block], m1: &[Block]) -> Result<()> {
        if m0.len() != m1.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "m0 and m1 must have the same length",
            ));
        }
        self.ensure_setup()?;
        let n = m0.len();
        let delta_block = bools_to_block(&self.delta);

        // Receive u rows from receiver and derive q matrix rows.
        let mut q_rows: Vec<Vec<bool>> = Vec::with_capacity(K);
        let mut u_buf = vec![0u8; n];
        for i in 0..K {
            let mut t_i = vec![false; n];
            self.prgs[i].random_bools(&mut t_i);
            self.chan.recv_exact(&mut u_buf)?;
            let u_bits = bytes_to_bools(&u_buf)?;
            if u_bits.len() != n {
                return Err(Error::new(ErrorKind::InvalidData, "u length mismatch"));
            }
            let mut q = t_i;
            if self.delta[i] {
                for j in 0..n {
                    q[j] ^= u_bits[j];
                }
            }
            q_rows.push(q);
        }

        // For each column derive keys and send masked messages.
        let mut buf = [0u8; 32];
        for j in 0..n {
            let mut col = [false; K];
            for i in 0..K {
                col[i] = q_rows[i][j];
            }
            let q_block = bools_to_block(&col);
            let k0 = kdf_block(&q_block);
            let k1 = kdf_block(&(q_block ^ delta_block));
            let c0 = k0 ^ m0[j];
            let c1 = k1 ^ m1[j];
            encode_block_pair(&mut buf, c0, c1);
            self.chan.send_bytes(&buf)?;
        }
        self.chan.flush()
    }
}

impl<C, B> IknpReceiver<C, B>
where
    C: Channel + Clone,
    B: BaseOtSend,
{
    pub fn new(chan: C, base: B) -> Self {
        Self {
            chan,
            base,
            seeds0: [Block::ZERO; K],
            seeds1: [Block::ZERO; K],
            prg0: init_prg_array(),
            prg1: init_prg_array(),
            setup: false,
        }
    }

    pub fn clone_channel(&self) -> C {
        self.chan.clone()
    }

    fn ensure_setup(&mut self) -> Result<()> {
        if self.setup {
            return Ok(());
        }
        self.base.send(&mut self.seeds0, &mut self.seeds1)?;
        for i in 0..K {
            self.prg0[i] = Prg::from_seed(self.seeds0[i]);
            self.prg1[i] = Prg::from_seed(self.seeds1[i]);
        }
        self.setup = true;
        Ok(())
    }

    /// Execute OTs for the receiver role, returning the selected messages.
    pub fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        self.ensure_setup()?;
        let n = choices.len();

        let mut columns: Vec<[bool; K]> = vec![[false; K]; n];
        let mut u_buf = vec![0u8; n];
        for i in 0..K {
            let mut t0 = vec![false; n];
            let mut t1 = vec![false; n];
            self.prg0[i].random_bools(&mut t0);
            self.prg1[i].random_bools(&mut t1);
            for j in 0..n {
                columns[j][i] = if choices[j] { t1[j] } else { t0[j] };
                u_buf[j] = (t0[j] ^ t1[j] ^ choices[j]) as u8;
            }
            self.chan.send_bytes(&u_buf)?;
        }
        self.chan.flush()?;

        let mut out = Vec::with_capacity(n);
        let mut buf = [0u8; 32];
        for j in 0..n {
            self.chan.recv_exact(&mut buf)?;
            let (c0, c1) = decode_block_pair(&buf);
            let key = kdf_block(&bools_to_block(&columns[j]));
            let m = if choices[j] { c1 ^ key } else { c0 ^ key };
            out.push(m);
        }
        Ok(out)
    }
}

fn init_prg_array() -> [Prg; K] {
    let dummy = Prg::from_seed(Block::ZERO);
    std::array::from_fn(|_| dummy.clone())
}

fn bools_to_block(bits: &[bool; K]) -> Block {
    let mut acc: u128 = 0;
    for (i, &b) in bits.iter().enumerate() {
        if b {
            acc |= 1u128 << i;
        }
    }
    Block::from(acc)
}

fn bytes_to_bools(bytes: &[u8]) -> Result<Vec<bool>> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            0 => out.push(false),
            1 => out.push(true),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "boolean byte not in {0,1}",
                ));
            }
        }
    }
    Ok(out)
}

fn kdf_block(input: &Block) -> Block {
    let mut h = Sha256::new();
    h.update(<[u8; 16]>::from(*input));
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Block::from(out)
}

fn encode_block_pair(buf: &mut [u8; 32], m0: Block, m1: Block) {
    buf[..16].copy_from_slice(&<[u8; 16]>::from(m0));
    buf[16..].copy_from_slice(&<[u8; 16]>::from(m1));
}

fn decode_block_pair(buf: &[u8; 32]) -> (Block, Block) {
    let mut left = [0u8; 16];
    let mut right = [0u8; 16];
    left.copy_from_slice(&buf[..16]);
    right.copy_from_slice(&buf[16..]);
    (Block::from(left), Block::from(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::NaorPinkasBase;
    use crate::channel::memory_channel_pair;

    #[test]
    fn iknp_round_trip() {
        let (sender_chan, recv_chan) = memory_channel_pair();
        let mut sender: IknpSender<_, NaorPinkasBase<_>> =
            IknpSender::new(sender_chan.clone(), NaorPinkasBase::new(sender_chan));
        let mut receiver: IknpReceiver<_, NaorPinkasBase<_>> =
            IknpReceiver::new(recv_chan.clone(), NaorPinkasBase::new(recv_chan));

        let m0 = vec![
            Block::from(1u128),
            Block::from(2u128),
            Block::from(3u128),
            Block::from(4u128),
        ];
        let m1 = vec![
            Block::from(10u128),
            Block::from(20u128),
            Block::from(30u128),
            Block::from(40u128),
        ];
        let choices = vec![false, true, false, true];
        let choices_for_thread = choices.clone();
        let recv_thread = std::thread::spawn(move || receiver.recv(&choices_for_thread).unwrap());
        sender.send(&m0, &m1).unwrap();
        let out = recv_thread.join().unwrap();

        assert_eq!(out.len(), choices.len());
        for i in 0..choices.len() {
            let expected = if choices[i] { m1[i] } else { m0[i] };
            assert_eq!(out[i], expected);
        }
    }
}
