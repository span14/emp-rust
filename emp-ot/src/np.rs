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

/// Naor–Pinkas base OT over Ristretto.
pub struct NaorPinkas<C, R = OsRng> {
    chan: C,
    rng: R,
}

impl<C> NaorPinkas<C, OsRng> {
    pub fn new(chan: C) -> Self {
        Self { chan, rng: OsRng }
    }
}

impl<C, R> NaorPinkas<C, R>
where
    C: Channel,
    R: CryptoRng + RngCore,
{
    /// Sender side: sends pairs (m0, m1) and hides them behind DH keys.
    pub fn send(&mut self, data0: &[Block], data1: &[Block]) -> Result<()> {
        if data0.len() != data1.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "data0 and data1 must have identical length",
            ));
        }
        let len = data0.len();

        let d = Scalar::random(&mut self.rng);
        let c = d * RISTRETTO_BASEPOINT_POINT;
        self.send_point(&c)?;
        self.chan.flush()?;

        let mut r_scalars = Vec::with_capacity(len);
        let mut gr_points = Vec::with_capacity(len);
        let mut c_r_points = Vec::with_capacity(len);
        for _ in 0..len {
            let r = Scalar::random(&mut self.rng);
            let gr = r * RISTRETTO_BASEPOINT_POINT;
            let cr = r * c;
            r_scalars.push(r);
            gr_points.push(gr);
            c_r_points.push(cr);
        }

        // Receive pk0 values
        let mut pk0_points = Vec::with_capacity(len);
        for _ in 0..len {
            pk0_points.push(self.recv_point()?);
        }

        // Send gr points
        for gr in &gr_points {
            self.send_point(gr)?;
        }
        self.chan.flush()?;

        let mut buf = [0u8; 32];
        for i in 0..len {
            let k0 = pk0_points[i] * r_scalars[i];
            let pk1 = c_r_points[i] - k0;
            let m0 = kdf_block(&k0) ^ data0[i];
            let m1 = kdf_block(&pk1) ^ data1[i];
            encode_block_pair(&mut buf, m0, m1);
            self.chan.send_bytes(&buf)?;
        }
        self.chan.flush()
    }

    /// Receiver side: selects one block per pair based on `choices`.
    pub fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        let len = choices.len();
        let c = self.recv_point()?;
        self.chan.flush()?;

        let mut k_scalars = Vec::with_capacity(len);
        let mut pk0_points = Vec::with_capacity(len);
        for &choice in choices {
            let k = Scalar::random(&mut self.rng);
            let pk0 = if choice {
                let pk1 = k * RISTRETTO_BASEPOINT_POINT;
                c - pk1
            } else {
                k * RISTRETTO_BASEPOINT_POINT
            };
            k_scalars.push(k);
            pk0_points.push(pk0);
        }

        for pk0 in &pk0_points {
            self.send_point(pk0)?;
        }

        let mut gr_points = Vec::with_capacity(len);
        for _ in 0..len {
            gr_points.push(self.recv_point()?);
        }
        self.chan.flush()?;

        let mut out = Vec::with_capacity(len);
        let mut buf = [0u8; 32];
        for ((choice, gr), k) in choices.iter().zip(gr_points.iter()).zip(k_scalars.iter()) {
            let shared = gr * k;
            self.chan.recv_exact(&mut buf)?;
            let (m0, m1) = decode_block_pair(&buf);
            let key = kdf_block(&shared);
            let recovered = if *choice { m1 ^ key } else { m0 ^ key };
            out.push(recovered);
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

fn kdf_block(point: &RistrettoPoint) -> Block {
    let mut h = Sha256::new();
    h.update(point.compress().as_bytes());
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
    use std::thread;

    #[test]
    fn naor_pinkas_round_trip() {
        let (sender_chan, recv_chan) = memory_channel_pair();
        let mut sender = NaorPinkas::new(sender_chan.clone());
        let mut recv = NaorPinkas::new(recv_chan.clone());

        let data0 = vec![Block::from(1u128), Block::from(2u128), Block::from(3u128)];
        let data1 = vec![
            Block::from(10u128),
            Block::from(20u128),
            Block::from(30u128),
        ];
        let choices = vec![false, true, false];
        let choices_for_thread = choices.clone();

        let recv_thread = thread::spawn(move || recv.recv(&choices_for_thread).unwrap());
        sender.send(&data0, &data1).unwrap();
        let received = recv_thread.join().unwrap();

        assert_eq!(received.len(), choices.len());
        for i in 0..choices.len() {
            let expected = if choices[i] { data1[i] } else { data0[i] };
            assert_eq!(received[i], expected);
        }
    }
}
