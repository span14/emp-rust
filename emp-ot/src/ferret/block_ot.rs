use crate::{Channel, IknpReceiver, IknpSender};
use crate::ferret::spcot::BlockOt;
use emp_tool::Block;
use std::io::Result;

/// IKNP-backed 1-out-of-2 OT over Blocks, suitable for spcot_full.
pub struct IknpBlockOtSender<C, B> {
    ot: IknpSender<C, B>,
}

pub struct IknpBlockOtReceiver<C, B> {
    ot: IknpReceiver<C, B>,
}

impl<C: Channel + Clone, B> IknpBlockOtSender<C, B> {
    pub fn new(ot: IknpSender<C, B>) -> Self {
        Self { ot }
    }
}

impl<C: Channel + Clone, B> IknpBlockOtReceiver<C, B> {
    pub fn new(ot: IknpReceiver<C, B>) -> Self {
        Self { ot }
    }
}

impl<C, B> BlockOt for IknpBlockOtSender<C, B>
where
    C: Channel + Clone,
    B: crate::BaseOtRecv,
{
    fn send(&mut self, m0: &[Block], m1: &[Block]) -> Result<()> {
        self.ot.send(m0, m1)
    }

    fn recv(&mut self, _choices: &[bool]) -> Result<Vec<Block>> {
        unreachable!("sender side")
    }
}

impl<C, B> BlockOt for IknpBlockOtReceiver<C, B>
where
    C: Channel + Clone,
    B: crate::BaseOtSend,
{
    fn send(&mut self, _m0: &[Block], _m1: &[Block]) -> Result<()> {
        unreachable!("receiver side")
    }

    fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        self.ot.recv(choices)
    }
}
