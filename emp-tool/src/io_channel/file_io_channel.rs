use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::constants::FILE_BUFFER_SIZE;
use crate::io_channel::IOChannel;

/// File-backed channel implementing `IOChannel`.
pub struct FileIO {
    reader: BufReader<File>,
    writer: BufWriter<File>,
    bytes: usize,
}

impl FileIO {
    /// Open a file for buffered IO. When `read_existing` is true the file is
    /// opened without truncation; otherwise it is created/truncated.
    pub fn new<P: AsRef<Path>>(path: P, read_existing: bool) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        let file = if read_existing {
            opts.open(path)?
        } else {
            opts.create(true).truncate(true).open(path)?
        };

        let reader = BufReader::with_capacity(FILE_BUFFER_SIZE, file.try_clone()?);
        let writer = BufWriter::with_capacity(FILE_BUFFER_SIZE, file);

        Ok(Self {
            reader,
            writer,
            bytes: 0,
        })
    }

    /// Seek back to the beginning of the file for subsequent reads/writes.
    pub fn reset(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.reader.seek(SeekFrom::Start(0))?;
        self.writer.get_mut().seek(SeekFrom::Start(0))?;
        Ok(())
    }

    /// Total bytes transferred through this handle.
    pub fn bytes_transferred(&self) -> usize {
        self.bytes
    }
}

impl IOChannel for FileIO {
    #[inline(always)]
    fn send_bytes(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.bytes += buffer.len();
        self.writer.write_all(buffer)
    }

    #[inline(always)]
    fn recv_bytes(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        self.reader.read_exact(buffer)
    }

    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn roundtrip_file_io() {
        let tmp_path =
            std::env::temp_dir().join(format!("emp_tool_fileio_{}.bin", rand::random::<u64>()));
        {
            let mut fio = FileIO::new(&tmp_path, false).expect("create file");
            let mut payload = [0u8; 64];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut payload);
            fio.send_bytes(&payload).unwrap();
            fio.flush().unwrap();
            fio.reset().unwrap();

            let mut readback = [0u8; 64];
            fio.recv_bytes(&mut readback).unwrap();
            assert_eq!(payload.to_vec(), readback.to_vec());
            assert_eq!(fio.bytes_transferred(), payload.len());
        }
        let _ = std::fs::remove_file(tmp_path);
    }
}
