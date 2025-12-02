//! Input OT adapters for evaluator label delivery.

use crossbeam_channel::{Receiver, Sender};
use emp_tool::Block;
#[cfg(feature = "ot-input")]
use emp_tool::IOChannel;
use std::io::{Error, ErrorKind, Result};
#[cfg(feature = "ot-input")]
use std::sync::{Arc, Mutex};

/// Input OT abstraction: sender delivers correlated labels; receiver picks labels by choice bits.
pub trait InputOT {
    /// Sender side: send `label0` for each bit; `label1` is derived as `label0 ^ delta`.
    fn send_correlated(&mut self, labels0: &[Block], delta: Block) -> Result<()>;
    /// Receiver side: receive labels according to `choices`.
    fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>>;
}

/// Simple in-memory OT for tests.
pub struct MockInputOTSender {
    tx: Sender<(Block, Block)>,
}

/// Receiver half for the mock OT.
pub struct MockInputOTReceiver {
    rx: Receiver<(Block, Block)>,
}

impl MockInputOTSender {
    /// Build a paired sender/receiver.
    pub fn pair() -> (Self, MockInputOTReceiver) {
        let (tx, rx) = crossbeam_channel::unbounded();
        (Self { tx }, MockInputOTReceiver { rx })
    }
}

impl InputOT for MockInputOTSender {
    fn send_correlated(&mut self, labels0: &[Block], delta: Block) -> Result<()> {
        for &l0 in labels0 {
            let l1 = l0 ^ delta;
            self.tx.send((l0, l1)).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        }
        Ok(())
    }

    fn recv(&mut self, _choices: &[bool]) -> Result<Vec<Block>> {
        Err(Error::new(ErrorKind::Other, "mock sender cannot recv"))
    }
}

impl InputOT for MockInputOTReceiver {
    fn send_correlated(&mut self, _labels0: &[Block], _delta: Block) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "mock receiver cannot send"))
    }

    fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        let mut out = Vec::with_capacity(choices.len());
        for &c in choices {
            let (l0, l1) = self
                .rx
                .recv()
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            out.push(if c { l1 } else { l0 });
        }
        Ok(out)
    }
}

/// Adapter to use emp-ot's IKNP extension over an `IOChannel`.
#[cfg(feature = "ot-input")]
pub struct IknpInputOT<IO: IOChannel + Send + 'static> {
    inner: IknpRole<IO>,
}

#[cfg(feature = "ot-input")]
enum IknpRole<IO: IOChannel + Send + 'static> {
    Sender(emp_ot::iknp::IknpSender<ChannelAdapter<IO>, emp_ot::base::NaorPinkasBase<ChannelAdapter<IO>>>),
    Receiver(emp_ot::iknp::IknpReceiver<ChannelAdapter<IO>, emp_ot::base::NaorPinkasBase<ChannelAdapter<IO>>>),
}

#[cfg(feature = "ot-input")]
impl<IO: IOChannel + Send + 'static> IknpInputOT<IO> {
    /// Build a sender role (garbler side) from an IO channel.
    pub fn new_sender(io: IO) -> Self {
        let chan = ChannelAdapter::new(io);
        let base = emp_ot::base::NaorPinkasBase::new(chan.clone());
        Self {
            inner: IknpRole::Sender(emp_ot::iknp::IknpSender::new(chan, base)),
        }
    }

    /// Build a receiver role (evaluator side) from an IO channel.
    pub fn new_receiver(io: IO) -> Self {
        let chan = ChannelAdapter::new(io);
        let base = emp_ot::base::NaorPinkasBase::new(chan.clone());
        Self {
            inner: IknpRole::Receiver(emp_ot::iknp::IknpReceiver::new(chan, base)),
        }
    }
}

#[cfg(feature = "ot-input")]
impl<IO: IOChannel + Send + 'static> InputOT for IknpInputOT<IO> {
    fn send_correlated(&mut self, labels0: &[Block], delta: Block) -> Result<()> {
        match &mut self.inner {
            IknpRole::Sender(s) => {
                let mut l1 = Vec::with_capacity(labels0.len());
                for &l0 in labels0 {
                    l1.push(l0 ^ delta);
                }
                s.send(labels0, &l1)?;
                Ok(())
            }
            _ => Err(Error::new(ErrorKind::Other, "not a sender role")),
        }
    }

    fn recv(&mut self, choices: &[bool]) -> Result<Vec<Block>> {
        match &mut self.inner {
            IknpRole::Receiver(r) => r.recv(choices),
            _ => Err(Error::new(ErrorKind::Other, "not a receiver role")),
        }
    }
}

/// Wrap an `IOChannel` to satisfy `emp_ot::Channel` (adds `Clone` via Arc+Mutex).
#[cfg(feature = "ot-input")]
#[derive(Clone)]
pub struct ChannelAdapter<IO: IOChannel + Send + 'static> {
    inner: Arc<Mutex<IO>>,
}

#[cfg(feature = "ot-input")]
impl<IO: IOChannel + Send + 'static> ChannelAdapter<IO> {
    pub fn new(io: IO) -> Self {
        Self {
            inner: Arc::new(Mutex::new(io)),
        }
    }
}

#[cfg(feature = "ot-input")]
impl<IO: IOChannel + Send + 'static> emp_ot::channel::Channel for ChannelAdapter<IO> {
    fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| Error::new(ErrorKind::Other, "lock poisoned"))?
            .send_bytes(data)
    }

    fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| Error::new(ErrorKind::Other, "lock poisoned"))?
            .recv_bytes(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| Error::new(ErrorKind::Other, "lock poisoned"))?
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_ot_roundtrip() {
        let (mut s, mut r) = MockInputOTSender::pair();
        let delta = Block::from(0xdeadbeefu128);
        let labels0 = vec![Block::from(1u128), Block::from(2u128), Block::from(3u128)];
        let labels_clone = labels0.clone();
        std::thread::spawn(move || {
            s.send_correlated(&labels_clone, delta).unwrap();
        });
        let choices = vec![false, true, false];
        let out = r.recv(&choices).unwrap();
        assert_eq!(out[0], labels0[0]);
        assert_eq!(out[1], labels0[1] ^ delta);
        assert_eq!(out[2], labels0[2]);
    }
}
