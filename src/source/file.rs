//! `file://` — positioned reads against a local file.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::Source;

/// A local file read by offset.
///
/// Uses seek-then-read rather than a platform positional-read API, because
/// portability is worth more here than saving one syscall: this source exists to
/// validate the [`Source`] shape and to make the splice layer testable without a
/// network.
#[derive(Debug)]
pub struct FileSource {
    file: File,
    len: u64,
    /// Where the file handle currently sits, so sequential reads skip the seek.
    cursor: u64,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(FileSource {
            file,
            len,
            cursor: 0,
        })
    }
}

impl Source for FileSource {
    fn size(&mut self) -> io::Result<Option<u64>> {
        Ok(Some(self.len))
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        if off >= self.len {
            return Ok(0);
        }
        if off != self.cursor {
            self.file.seek(SeekFrom::Start(off))?;
            self.cursor = off;
        }
        let read = self.file.read(buf)?;
        self.cursor += read as u64;
        Ok(read)
    }
}
