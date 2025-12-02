use std::io::{self, Error, ErrorKind};

use crate::io_channel::IOChannel;

/// In-memory channel useful for testing or buffering transcripts.
pub struct MemIO {
    buf: Vec<u8>,
    read_pos: usize,
    bytes: usize,
}

impl MemIO {
    /// Create a new in-memory channel with an initial capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            read_pos: 0,
            bytes: 0,
        }
    }

    /// Create a new channel preloaded with the provided bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            buf: bytes,
            read_pos: 0,
            bytes: len,
        }
    }

    /// Reset read/write offsets and drop buffered data.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.read_pos = 0;
        self.bytes = 0;
    }

    /// Consume the buffer.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Total bytes written into the buffer.
    pub fn bytes_transferred(&self) -> usize {
        self.bytes
    }
}

impl Default for MemIO {
    fn default() -> Self {
        Self::with_capacity(1024 * 1024)
    }
}

impl IOChannel for MemIO {
    #[inline(always)]
    fn send_bytes(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.bytes += buffer.len();
        self.buf.extend_from_slice(buffer);
        Ok(())
    }

    #[inline(always)]
    fn recv_bytes(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        if self.read_pos + buffer.len() > self.buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "MemIO underflow"));
        }
        buffer.copy_from_slice(&self.buf[self.read_pos..self.read_pos + buffer.len()]);
        self.read_pos += buffer.len();
        Ok(())
    }

    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_io_roundtrip() {
        let mut mio = MemIO::default();
        let payload = b"hello world";
        mio.send_bytes(payload).unwrap();
        let mut buf = vec![0u8; payload.len()];
        mio.recv_bytes(&mut buf).unwrap();
        assert_eq!(buf, payload);
        assert_eq!(mio.bytes_transferred(), payload.len());
    }
}
