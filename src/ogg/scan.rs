//! Reading pages out of a [`Source`], resynchronising, and bisecting on granule.
//!
//! Everything here is offset-driven, which is what makes `--start-ms` cheap. A
//! bisection probe costs one 282-byte header read plus one page read to confirm
//! the checksum — a handful of those, rather than streaming and discarding
//! everything before the target.
//!
//! Two details from the format make the search less obvious than a plain binary
//! search over an array:
//!
//! - A page's granule position is `-1` when no packet *finishes* on it. Such a
//!   page carries no position at all, so the search has to step over it rather
//!   than read it as position zero.
//! - `OggS` can occur inside a page body by coincidence. A candidate offset is
//!   therefore only accepted once its page parses *and* its checksum validates.

use std::io;

use super::page::{Page, PageHeader, ParseError, MAX_PAGE_LEN, MAX_SEGMENTS, MIN_HEADER_LEN};
use crate::source::{read_exact_at, read_upto_at, Source};

/// Bytes needed to be certain of a page's total length: the fixed header plus
/// the largest possible segment table.
const PROBE_LEN: usize = MIN_HEADER_LEN + MAX_SEGMENTS;

/// Window used when hunting for a capture pattern.
const RESYNC_WINDOW: usize = 64 * 1024;

#[derive(Debug)]
pub enum ScanError {
    Io(io::Error),
    Parse {
        offset: u64,
        error: ParseError,
    },
    BadChecksum {
        offset: u64,
    },
    /// Bisection needs to know where the stream ends.
    LengthUnknown,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Parse { offset, error } => write!(f, "at byte {offset}: {error}"),
            Self::BadChecksum { offset } => {
                write!(f, "at byte {offset}: page checksum does not match")
            }
            Self::LengthUnknown => write!(f, "source length unknown; cannot seek"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<io::Error> for ScanError {
    fn from(e: io::Error) -> Self {
        ScanError::Io(e)
    }
}

/// A page together with where it was found.
#[derive(Debug, Clone)]
pub struct PageAt {
    pub offset: u64,
    pub header: PageHeader,
    /// Exactly this page's bytes.
    pub bytes: Vec<u8>,
}

impl PageAt {
    /// Offset of the page that follows this one.
    pub fn next_offset(&self) -> u64 {
        self.offset + self.bytes.len() as u64
    }

    pub fn page(&self) -> Result<Page<'_>, ParseError> {
        Page::parse(&self.bytes)
    }
}

/// Page-level reader over a byte source.
pub struct Scanner<S: Source> {
    src: S,
    buf: Vec<u8>,
}

impl<S: Source> Scanner<S> {
    pub fn new(src: S) -> Self {
        Scanner {
            src,
            buf: Vec::with_capacity(PROBE_LEN),
        }
    }

    pub fn source_len(&mut self) -> Result<u64, ScanError> {
        self.src.size()?.ok_or(ScanError::LengthUnknown)
    }

    pub fn into_inner(self) -> S {
        self.src
    }

    /// Read just enough to learn a page's header and total length.
    pub fn header_at(&mut self, offset: u64) -> Result<PageHeader, ScanError> {
        self.buf.clear();
        self.buf.resize(PROBE_LEN, 0);
        let filled = read_upto_at(&mut self.src, offset, &mut self.buf)?;
        PageHeader::parse(&self.buf[..filled]).map_err(|error| ScanError::Parse { offset, error })
    }

    /// Read a whole page, verifying its checksum.
    ///
    /// Two reads at most: the header probe, then the remainder. The probe bytes
    /// are reused rather than fetched twice, which matters for a ranged source.
    pub fn page_at(&mut self, offset: u64) -> Result<PageAt, ScanError> {
        self.buf.clear();
        self.buf.resize(PROBE_LEN, 0);
        let filled = read_upto_at(&mut self.src, offset, &mut self.buf)?;
        let header = PageHeader::parse(&self.buf[..filled])
            .map_err(|error| ScanError::Parse { offset, error })?;

        let total = header.total_len();
        let mut bytes = std::mem::take(&mut self.buf);
        if total > filled {
            bytes.resize(total, 0);
            read_exact_at(
                &mut self.src,
                offset + filled as u64,
                &mut bytes[filled..total],
            )?;
        }
        bytes.truncate(total);

        let page = Page::parse(&bytes).map_err(|error| ScanError::Parse { offset, error })?;
        if !page.verify_crc() {
            return Err(ScanError::BadChecksum { offset });
        }
        Ok(PageAt {
            offset,
            header,
            bytes,
        })
    }

    /// Find the next genuine page boundary at or after `from`, below `limit`.
    ///
    /// Candidates are confirmed by parsing and checksum, so a coincidental
    /// `OggS` inside a body is skipped rather than believed.
    pub fn resync(&mut self, from: u64, limit: u64) -> Result<Option<PageAt>, ScanError> {
        let mut search = from;
        let mut window = Vec::new();
        while search < limit {
            // Read a full window even when it runs past `limit`. `limit` bounds
            // where a page may *start*, not how far we may look to recognise
            // one — clamping the read instead means a page starting one byte
            // below the limit is invisible, because four bytes of capture
            // pattern will not fit in the window.
            window.clear();
            window.resize(RESYNC_WINDOW, 0);
            let filled = read_upto_at(&mut self.src, search, &mut window)?;
            if filled == 0 {
                return Ok(None);
            }

            let mut cursor = 0usize;
            while let Some(found) = find(&window[..filled], cursor) {
                let candidate = search + found as u64;
                if candidate >= limit {
                    return Ok(None);
                }
                match self.page_at(candidate) {
                    Ok(page) => return Ok(Some(page)),
                    // Not a real page here — step one byte past this false
                    // positive and keep looking.
                    Err(ScanError::Parse { .. }) | Err(ScanError::BadChecksum { .. }) => {
                        cursor = found + 1;
                    }
                    Err(e) => return Err(e),
                }
            }

            // Overlap by three bytes so a pattern straddling two windows is
            // still found.
            if filled < 4 {
                return Ok(None);
            }
            search += (filled - 3) as u64;
        }
        Ok(None)
    }

    /// Offset of the last page at or before `target`, searching within
    /// `[lo, hi)`.
    ///
    /// `lo` must already be a page boundary whose position is at or before the
    /// target — in practice the first audio page. Returns `lo` when nothing
    /// better is found, so the caller always gets a usable page.
    pub fn seek_granule(&mut self, target: u64, lo: u64, hi: u64) -> Result<u64, ScanError> {
        let mut best = lo;
        let mut low = lo;
        let mut high = hi;

        // Phase 1: bisect until the window is about one page wide. Grinding
        // below that only re-probes the same page, so the forward walk in phase
        // two finishes the job more cheaply and — more importantly — exactly.
        while low < high && high - low > MAX_PAGE_LEN as u64 {
            let mid = low + (high - low) / 2;
            let Some(found) = self.resync(mid, high)? else {
                // Nothing parseable between here and the top: the answer is
                // below.
                high = mid;
                continue;
            };
            let page_end = found.next_offset();

            match found.header.granule() {
                Some(granule) if granule <= target => {
                    best = found.offset;
                    if page_end <= low {
                        break;
                    }
                    low = page_end;
                }
                Some(_) => {
                    if found.offset <= low {
                        break;
                    }
                    high = found.offset;
                }
                // -1: carries no position. Step past it instead of reading it
                // as zero.
                None => {
                    if page_end >= high {
                        high = found.offset;
                    } else {
                        low = page_end;
                    }
                }
            }
        }

        // Phase 2: walk forward from the best candidate for as long as pages
        // still satisfy the target. This is what makes the result exact — the
        // bisection only has to get close.
        let mut cursor = best;
        loop {
            let header = self.header_at(cursor)?;
            let next = cursor + header.total_len() as u64;
            if next >= hi {
                break;
            }
            let ahead = self.header_at(next)?;
            match ahead.granule() {
                Some(granule) if granule <= target => {
                    best = next;
                    cursor = next;
                }
                Some(_) => break,
                // Carries no position; step over it and keep looking.
                None => cursor = next,
            }
        }
        Ok(best)
    }
}

/// First occurrence of the capture pattern at or after `from`.
fn find(haystack: &[u8], from: usize) -> Option<usize> {
    const NEEDLE: &[u8; 4] = b"OggS";
    if from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(NEEDLE.len())
        .position(|w| w == NEEDLE)
        .map(|p| p + from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    /// Walk every page sequentially, the slow and obvious way, as ground truth
    /// for the bisection tests.
    fn linear(bytes: &[u8]) -> Vec<(u64, Option<u64>)> {
        let mut out = Vec::new();
        let mut scanner = Scanner::new(MemSource::new(bytes.to_vec()));
        let mut offset = 0u64;
        let end = bytes.len() as u64;
        while offset < end {
            let page = scanner.page_at(offset).expect("page");
            out.push((offset, page.header.granule()));
            offset = page.next_offset();
        }
        out
    }

    #[test]
    fn page_at_reads_and_verifies_every_page() {
        for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
            let bytes = fixture(name);
            let pages = linear(&bytes);
            assert!(pages.len() >= 7, "{name}");
            let total: u64 = {
                let mut scanner = Scanner::new(MemSource::new(bytes.clone()));
                pages
                    .iter()
                    .map(|(off, _)| scanner.page_at(*off).expect("page").bytes.len() as u64)
                    .sum()
            };
            assert_eq!(total, bytes.len() as u64, "{name}: pages tile the file");
        }
    }

    #[test]
    fn header_at_agrees_with_a_full_page_read() {
        for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
            let bytes = fixture(name);
            let mut scanner = Scanner::new(MemSource::new(bytes.clone()));
            for (offset, _) in linear(&bytes) {
                let header = scanner.header_at(offset).expect("header");
                let page = scanner.page_at(offset).expect("page");
                assert_eq!(header, page.header, "{name} at {offset}");
                assert_eq!(header.total_len(), page.bytes.len(), "{name} at {offset}");
            }
        }
    }

    /// The test that matters for bisection: it must agree with a linear scan for
    /// every reachable target, not just a few sampled ones.
    #[test]
    fn bisection_agrees_with_linear_search_everywhere() {
        for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
            let bytes = fixture(name);
            let pages = linear(&bytes);
            let end = bytes.len() as u64;

            // First page carrying a real position, which is where a caller
            // would start the search.
            let lo = pages
                .iter()
                .find(|(_, g)| g.is_some())
                .map(|(off, _)| *off)
                .expect("a positioned page");

            let max_granule = pages.iter().filter_map(|(_, g)| *g).max().unwrap();
            let mut scanner = Scanner::new(MemSource::new(bytes.clone()));

            for target in (0..=max_granule + 5_000).step_by(997) {
                let expected = pages
                    .iter()
                    .filter(|(off, g)| *off >= lo && g.map(|g| g <= target).unwrap_or(false))
                    .map(|(off, _)| *off)
                    .next_back()
                    .unwrap_or(lo);
                let got = scanner.seek_granule(target, lo, end).expect("seek");
                assert_eq!(got, expected, "{name}: target {target}");
            }
        }
    }

    #[test]
    fn resync_finds_the_first_page_from_a_mid_page_offset() {
        let bytes = fixture("vorbis_5s.ogg");
        let pages = linear(&bytes);
        let mut scanner = Scanner::new(MemSource::new(bytes.clone()));

        // Starting one byte into each page must land on the *next* page.
        for window in pages.windows(2) {
            let (this, next) = (window[0].0, window[1].0);
            let found = scanner
                .resync(this + 1, bytes.len() as u64)
                .expect("resync")
                .expect("a page");
            assert_eq!(found.offset, next, "from {}", this + 1);
        }
    }

    #[test]
    fn resync_rejects_a_coincidental_capture_pattern() {
        // Bury "OggS" inside a page body and confirm resync steps over it: the
        // bytes are not a page, so its checksum cannot validate.
        let real = fixture("vorbis_5s.ogg");
        let pages = linear(&real);
        let second = pages[1].0 as usize;

        let mut doctored = real.clone();
        let plant = second + MIN_HEADER_LEN + 40;
        doctored[plant..plant + 4].copy_from_slice(b"OggS");
        // Planting bytes broke page two's checksum, so search past it.
        let third = pages[2].0;

        let mut scanner = Scanner::new(MemSource::new(doctored.clone()));
        let found = scanner
            .resync(plant as u64, doctored.len() as u64)
            .expect("resync")
            .expect("a page");
        assert_eq!(
            found.offset, third,
            "must skip the planted pattern, not accept it",
        );
    }

    #[test]
    fn a_corrupt_page_is_reported_not_silently_accepted() {
        let mut bytes = fixture("opus_5s.opus");
        let pages = linear(&bytes);
        let target = pages[2].0 as usize;
        bytes[target + MIN_HEADER_LEN + 10] ^= 0xff;

        let mut scanner = Scanner::new(MemSource::new(bytes));
        match scanner.page_at(target as u64) {
            Err(ScanError::BadChecksum { offset }) => assert_eq!(offset, target as u64),
            other => panic!("expected a checksum error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_sources_error_rather_than_panic() {
        let bytes = fixture("vorbis_5s.ogg");
        for cut in (0..bytes.len()).step_by(101) {
            let mut scanner = Scanner::new(MemSource::new(bytes[..cut].to_vec()));
            let _ = scanner.page_at(0);
            let _ = scanner.header_at(0);
            let _ = scanner.resync(0, cut as u64);
            let _ = scanner.seek_granule(100_000, 0, cut as u64);
        }
    }
}
