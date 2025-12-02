//! Simple in-memory duplex channel for tests.

use emp_tool::IOChannel;

/// Mock IO implementing `IOChannel` using crossbeam channels.
pub struct MockIO {
    tx: crossbeam_channel::Sender<Vec<u8>>,
    rx: crossbeam_channel::Receiver<Vec<u8>>,
    stash: Vec<u8>,
}

impl MockIO {
    /// Create a paired duplex channel (garbler, evaluator).
    pub fn pair() -> (Self, Self) {
        let (a_tx, a_rx) = crossbeam_channel::unbounded::<Vec<u8>>();
        let (b_tx, b_rx) = crossbeam_channel::unbounded::<Vec<u8>>();
        (
            MockIO {
                tx: a_tx,
                rx: b_rx,
                stash: Vec::new(),
            },
            MockIO {
                tx: b_tx,
                rx: a_rx,
                stash: Vec::new(),
            },
        )
    }
}

impl IOChannel for MockIO {
    fn send_bytes(&mut self, buffer: &[u8]) -> std::io::Result<()> {
        self.tx.send(buffer.to_vec()).unwrap();
        Ok(())
    }

    fn recv_bytes(&mut self, buffer: &mut [u8]) -> std::io::Result<()> {
        while self.stash.len() < buffer.len() {
            let chunk = self.rx.recv().unwrap();
            self.stash.extend_from_slice(&chunk);
        }
        let tail = self.stash.split_off(buffer.len());
        buffer.copy_from_slice(&self.stash);
        self.stash = tail;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
