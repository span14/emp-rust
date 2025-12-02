use std::io::{Read, Result, Write};

/// Minimal synchronous channel abstraction used by the OT protocols.
pub trait Channel {
    fn send_bytes(&mut self, data: &[u8]) -> Result<()>;
    fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

impl<T: Read + Write + Clone> Channel for T {
    fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.write_all(data)
    }

    fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        Read::read_exact(self, buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.flush()
    }
}

#[cfg(test)]
pub fn memory_channel_pair() -> (MemoryEndpoint, MemoryEndpoint) {
    use std::sync::{Arc, Condvar, Mutex};

    let a_inbox = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
    let b_inbox = Arc::new((Mutex::new(Vec::new()), Condvar::new()));

    let a = MemoryEndpoint {
        inbox: a_inbox.clone(),
        outbox: b_inbox.clone(),
    };
    let b = MemoryEndpoint {
        inbox: b_inbox,
        outbox: a_inbox,
    };
    (a, b)
}

#[cfg(test)]
#[derive(Clone)]
pub struct MemoryEndpoint {
    inbox: std::sync::Arc<(std::sync::Mutex<Vec<u8>>, std::sync::Condvar)>,
    outbox: std::sync::Arc<(std::sync::Mutex<Vec<u8>>, std::sync::Condvar)>,
}

#[cfg(test)]
impl Channel for MemoryEndpoint {
    fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
        let (lock, cv) = &*self.outbox;
        let mut buf = lock
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "lock poisoned"))?;
        buf.extend_from_slice(data);
        cv.notify_all();
        Ok(())
    }

    fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let (lock, cv) = &*self.inbox;
        let mut inbox = lock
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "lock poisoned"))?;
        while inbox.len() < buf.len() {
            inbox = cv
                .wait(inbox)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "lock poisoned"))?;
        }
        let drained: Vec<u8> = inbox.drain(..buf.len()).collect();
        for (dst, src) in buf.iter_mut().zip(drained) {
            *dst = src;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
