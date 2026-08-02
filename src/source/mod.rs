//! Byte sources, addressed by offset.
//!
//! This trait is the one structural decision the whole tool rests on, so it is
//! worth stating why it is not `io::Read`.
//!
//! Every source earshot cares about is randomly accessible. HTTP has `Range`.
//! Spotify's audio cipher is AES-128-CTR, whose keystream position *is* the
//! absolute byte offset — librespot's own `AudioDecrypt` implements `Seek` by
//! calling `cipher.seek(offset)`. A `Read`-only chain throws both away: seeking
//! to 5:00 of a track would mean fetching and discarding everything before it, on
//! every seek, and a connection that drops at 70% could not be resumed.
//!
//! Offset addressing keeps the decorator model that makes backends small — the
//! decorators just decorate `Source` instead of `Read`:
//!
//! ```text
//! Window<Decrypt<HttpRanged>>      // a Spotify track
//!   Window   read_at(o) -> inner.read_at(o + 0xa7)   strips the prepended packet
//!   Decrypt  read_at(o) -> keystream_at(o) ^ inner   exact, because CTR is seekable
//! ```
//!
//! Because `Window` is offset-preserving, granule bisection still works straight
//! through the stack, and the Ogg layer above never learns that any of it
//! happened.

use std::io;

mod file;
mod mem;

pub use file::FileSource;
pub use mem::MemSource;

/// A random-access window of bytes.
pub trait Source {
    /// Total size in bytes, if the source knows it.
    ///
    /// `None` means unbounded or not yet known — an HTTP source that has not
    /// issued its first request, for instance. Bisection needs a length; forward
    /// streaming does not.
    fn size(&mut self) -> io::Result<Option<u64>>;

    /// Read up to `buf.len()` bytes starting at absolute offset `off`.
    ///
    /// Returns the number of bytes read, which may be short for reasons other
    /// than end of stream. `Ok(0)` means end of stream. Use
    /// [`read_exact_at`] or [`read_upto_at`] rather than calling this directly.
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize>;
}

/// Fill `buf` completely, or fail.
///
/// Short reads are retried; a genuine end of stream before `buf` is full is an
/// [`io::ErrorKind::UnexpectedEof`].
pub fn read_exact_at<S: Source + ?Sized>(src: &mut S, off: u64, buf: &mut [u8]) -> io::Result<()> {
    let filled = read_upto_at(src, off, buf)?;
    if filled < buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("wanted {} bytes at {off}, got {filled}", buf.len()),
        ));
    }
    Ok(())
}

/// Read as much of `buf` as the source will give, returning how much that was.
///
/// Retries short reads so a caller cannot mistake one for end of stream — which
/// matters because a page parse treats a short buffer as a truncated page.
pub fn read_upto_at<S: Source + ?Sized>(
    src: &mut S,
    off: u64,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match src.read_at(off + filled as u64, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Resolve a URI to a source.
///
/// At M1 only `file://` and bare paths resolve. `http(s)://` and `room://` are
/// recognised so they can fail with something useful rather than being mistaken
/// for a relative path.
pub fn open(uri: &str) -> io::Result<Box<dyn Source>> {
    if let Some(rest) = uri.strip_prefix("file://") {
        return Ok(Box::new(FileSource::open(rest)?));
    }
    for scheme in ["http://", "https://", "room://"] {
        if uri.starts_with(scheme) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{scheme} sources are not implemented yet (M2/M3)"),
            ));
        }
    }
    if let Some((scheme, _)) = uri.split_once("://") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unknown URI scheme {scheme:?}"),
        ));
    }
    // A bare path is a convenience, not a scheme.
    Ok(Box::new(FileSource::open(uri)?))
}

impl<S: Source + ?Sized> Source for Box<S> {
    fn size(&mut self) -> io::Result<Option<u64>> {
        (**self).size()
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(off, buf)
    }
}

impl<S: Source + ?Sized> Source for &mut S {
    fn size(&mut self) -> io::Result<Option<u64>> {
        (**self).size()
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(off, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that deliberately returns one byte at a time, to prove the
    /// helpers do not mistake a short read for end of stream.
    struct Dribble(Vec<u8>);

    impl Source for Dribble {
        fn size(&mut self) -> io::Result<Option<u64>> {
            Ok(Some(self.0.len() as u64))
        }

        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
            let off = off as usize;
            if off >= self.0.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0[off];
            Ok(1)
        }
    }

    #[test]
    fn read_upto_at_retries_short_reads() {
        let mut src = Dribble((0..64u8).collect());
        let mut buf = [0u8; 32];
        assert_eq!(read_upto_at(&mut src, 8, &mut buf).unwrap(), 32);
        assert_eq!(buf[0], 8);
        assert_eq!(buf[31], 39);
    }

    #[test]
    fn read_upto_at_reports_a_short_tail() {
        let mut src = Dribble((0..10u8).collect());
        let mut buf = [0u8; 32];
        assert_eq!(read_upto_at(&mut src, 4, &mut buf).unwrap(), 6);
    }

    #[test]
    fn read_exact_at_fails_past_the_end() {
        let mut src = Dribble((0..10u8).collect());
        let mut buf = [0u8; 32];
        let err = read_exact_at(&mut src, 4, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn unimplemented_schemes_say_so_instead_of_looking_like_paths() {
        // `Box<dyn Source>` is not `Debug`, so inspect the error by hand rather
        // than through `unwrap_err`.
        let kind = |uri: &str| match open(uri) {
            Ok(_) => panic!("{uri} should not have opened"),
            Err(e) => e.kind(),
        };
        for uri in ["http://x/y", "https://x/y", "room://tok@host/track"] {
            assert_eq!(kind(uri), io::ErrorKind::Unsupported, "{uri}");
        }
        assert_eq!(kind("gopher://x"), io::ErrorKind::Unsupported);
    }
}
