use crate::{Channel, NaorPinkas};
use emp_tool::Block;
use std::io::Result;

/// Base OT sender role: sends pairs of seeds.
pub trait BaseOtSend {
    fn send(&mut self, k0: &mut [Block], k1: &mut [Block]) -> Result<()>;
}

/// Base OT receiver role: receives one seed per pair according to `choices`.
pub trait BaseOtRecv {
    fn recv(&mut self, choices: &[bool], out: &mut [Block]) -> Result<()>;
}

/// Adapter to use Naor–Pinkas as the base OT.
pub struct NaorPinkasBase<C> {
    inner: NaorPinkas<C>,
}

impl<C> NaorPinkasBase<C> {
    pub fn new(chan: C) -> Self {
        Self {
            inner: NaorPinkas::new(chan),
        }
    }
}

impl<C: Channel> BaseOtSend for NaorPinkasBase<C> {
    fn send(&mut self, k0: &mut [Block], k1: &mut [Block]) -> Result<()> {
        self.inner.send(k0, k1)
    }
}

impl<C: Channel> BaseOtRecv for NaorPinkasBase<C> {
    fn recv(&mut self, choices: &[bool], out: &mut [Block]) -> Result<()> {
        let vals = self.inner.recv(choices)?;
        if vals.len() != out.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "base OT recv length mismatch",
            ));
        }
        out.copy_from_slice(&vals);
        Ok(())
    }
}
