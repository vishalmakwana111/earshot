//! An in-memory [`Source`], for tests and for holding a fully-buffered stream.

use std::io;

use super::Source;

#[derive(Debug, Clone)]
pub struct MemSource {
    bytes: Vec<u8>,
}

impl MemSource {
    pub fn new(bytes: Vec<u8>) -> Self {
        MemSource { bytes }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for MemSource {
    fn from(bytes: Vec<u8>) -> Self {
        MemSource::new(bytes)
    }
}

impl Source for MemSource {
    fn size(&mut self) -> io::Result<Option<u64>> {
        Ok(Some(self.bytes.len() as u64))
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Ok(off) = usize::try_from(off) else {
            return Ok(0);
        };
        let Some(available) = self.bytes.get(off..) else {
            return Ok(0);
        };
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}
