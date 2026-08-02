//! `Window` — a fixed-offset slice of another source.
//!
//! The offset-addressed trait makes this decorator one arithmetic operation:
//! every read at `o` becomes a read at `o + start`, and the size shrinks by
//! `start`. No buffering, no state, no seek support to fake — the layer above
//! keeps addressing from zero and never learns a slice happened.
//!
//! Its concrete use is stripping the ~`0xa7`-byte normalisation packet Spotify
//! prepends to an Ogg stream (`DESIGN.md` A10) — librespot's `Subfile` does the
//! same thing with less honour — but the decorator itself is generic, which is
//! what makes it testable over bytes with a `MemSource` and no network.

use std::io;

use super::Source;

/// A view of `inner` starting at byte `start`.
///
/// `read_at(o)` reads `inner` at `o + start`; `size()` reports
/// `inner.size() - start`. Offsets are translated but never clamped: a read
/// past the end surfaces as end of stream from `inner` itself.
pub struct Window<S> {
    inner: S,
    start: u64,
}

impl<S> Window<S> {
    /// Slice `inner` from absolute byte `start`.
    pub fn new(inner: S, start: u64) -> Self {
        Window { inner, start }
    }
}

impl<S: Source> Source for Window<S> {
    fn size(&mut self) -> io::Result<Option<u64>> {
        Ok(self.inner.size()?.map(|n| n.saturating_sub(self.start)))
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(self.start.saturating_add(off), buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::mem::MemSource;
    use crate::source::{read_exact_at, read_upto_at};

    #[test]
    fn reads_are_translated_and_the_tail_is_trimmed() {
        let mut w = Window::new(MemSource::new((0..16u8).collect()), 4);
        assert_eq!(w.size().unwrap(), Some(12));
        let mut buf = [0u8; 12];
        assert_eq!(read_upto_at(&mut w, 0, &mut buf).unwrap(), 12);
        assert_eq!(buf, (4..16u8).collect::<Vec<u8>>()[..]);
    }

    #[test]
    fn a_window_past_the_end_is_empty() {
        let mut w = Window::new(MemSource::new((0..16u8).collect()), 64);
        assert_eq!(w.size().unwrap(), Some(0));
        let mut buf = [0u8; 4];
        assert_eq!(read_upto_at(&mut w, 0, &mut buf).unwrap(), 0);
    }

    #[test]
    fn reads_within_a_partial_first_page_stay_put() {
        // Random access at the *start* of the window, as granule bisection does.
        let mut w = Window::new(MemSource::new((0..16u8).collect()), 4);
        let mut one = [0u8; 1];
        read_exact_at(&mut w, 2, &mut one).unwrap();
        assert_eq!(one[0], 6);
    }
}
