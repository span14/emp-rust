use crate::channel::Channel;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use emp_tool::Block;
use rand_core_06::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{Error, ErrorKind, Result};

/// Chou–Orlandi base OT over Ristretto.
pub struct ChouOrlandi<C, R = OsRng> {
    chan: C,
    rng: R,
}

impl<C> ChouOrlandi<C, OsRng> {
    pub fn new(chan: C) -> Self {
        Self { chan, rng: OsRng }
    }
}

impl<C, R> ChouOrlandi<C, R>
where
    C: Channel,
    R: CryptoRng + RngCore,
{
    /// Sender role: send pairs (m0, m1).
    pub fn send(&mut self, data0: &[Block], data1: &[Block]) -> Result<()> {
        if data0.len() != data1.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "data0 and data1 must have identical length",
            ));
        }
        let len = data0.len();

        let a = Scalar::random(&mut self.rng);
        let a_point = a * RISTRETTO_BASEPOINT_POINT;
        self.send_point(&a_point)?;

        let a_times_a = a * a_point;
        let a_times_a_inv = -a_times_a;

        let mut b_points = Vec::with_capacity(len);
        let mut ba_points = Vec::with_capacity(len);
        for _ in 0..len {
            let b = self.recv_point()?;
            let ba = a * b;
            let ba1 = ba + a_times_a_inv;
            b_points.push(ba);
            ba_points.push(ba1);
        }
        self.chan.flush()?;

        let mut buf = [0u8; 32];
        for i in 0..len {
            let m0 = kdf_block(&b_points[i], i as u64) ^ data0[i];
            let m1 = kdf_block(&ba_points[i], i as u64) ^ data1[i];
            encode_block_pair(&mut buf, m0, m1);
            self.chan.send_bytes(&buf)?;
        }
        self.chan.flush()
    }

    /// Receiver role: chooses `choices` and receives one block per pair.
    pub fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        let len = choices.len();
        let a_point = self.recv_point()?;

        let mut bb = Vec::with_capacity(len);
        let mut b_points = Vec::with_capacity(len);
        for &choice in choices {
            let r = Scalar::random(&mut self.rng);
            let mut b = r * RISTRETTO_BASEPOINT_POINT;
            if choice {
                b += a_point;
            }
            bb.push(r);
            b_points.push(b);
        }

        for b in &b_points {
            self.send_point(b)?;
        }
        self.chan.flush()?;

        let mut shared = Vec::with_capacity(len);
        for i in 0..len {
            shared.push(bb[i] * a_point);
        }

        let mut out = Vec::with_capacity(len);
        let mut buf = [0u8; 32];
        for (i, &choice) in choices.iter().enumerate() {
            self.chan.recv_exact(&mut buf)?;
            let (c0, c1) = decode_block_pair(&buf);
            let key = kdf_block(&shared[i], i as u64);
            let msg = if choice { c1 ^ key } else { c0 ^ key };
            out.push(msg);
        }
        Ok(out)
    }

    fn send_point(&mut self, p: &RistrettoPoint) -> Result<()> {
        self.chan.send_bytes(p.compress().as_bytes())
    }

    fn recv_point(&mut self) -> Result<RistrettoPoint> {
        let mut buf = [0u8; 32];
        self.chan.recv_exact(&mut buf)?;
        let compressed = CompressedRistretto::from_slice(&buf)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid compressed point bytes"))?;
        compressed
            .decompress()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid point received"))
    }
}

fn kdf_block(point: &RistrettoPoint, idx: u64) -> Block {
    let mut h = Sha256::new();
    h.update(point.compress().as_bytes());
    h.update(idx.to_le_bytes());
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
    use crate::channel::memory_channel_pair;

    #[test]
    fn chou_orlandi_round_trip() {
        let (sender_chan, recv_chan) = memory_channel_pair();
        let mut sender: ChouOrlandi<_> = ChouOrlandi::new(sender_chan.clone());
        let mut receiver: ChouOrlandi<_> = ChouOrlandi::new(recv_chan.clone());

        let m0 = vec![Block::from(1u128), Block::from(2u128), Block::from(3u128)];
        let m1 = vec![
            Block::from(10u128),
            Block::from(20u128),
            Block::from(30u128),
        ];
        let choices = vec![false, true, false];
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
