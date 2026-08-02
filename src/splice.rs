//! Splice policy: emit a stream that starts near a requested millisecond.
//!
//! The output is the original header pages followed by the tail from a chosen
//! page, renumbered and re-checksummed. Three constraints from the formats decide
//! which page gets chosen:
//!
//! 1. **The page must not be a continuation.** Its first packet has to start
//!    there, or the decoder receives a fragment.
//! 2. **A decoder needs run-up.** Vorbis is a lapped transform, so the packet
//!    before the target has to be present for the overlap-add; Opus wants ~80 ms
//!    to converge after a mid-stream cut.
//! 3. **Granule positions stay absolute.** This is the deliberate choice, and it
//!    is worth spelling out — RFC 7845 offers an alternative for Opus: rewrite
//!    `OpusHead.pre_skip` to ≥3840 so the decoder trims exactly to the target,
//!    which is sample-exact. But `pre_skip` is *also* subtracted from every
//!    granule position, so raising it shifts the whole reported timeline by the
//!    difference (312 → 3840 is 73.5 ms). A consumer showing a progress bar
//!    against the original track would then be wrong for the entire stream.
//!
//! So earshot keeps granules absolute, starts slightly early, and reports
//! `actual_start_ms`. Positions stay true to the source and the consumer trims if
//! it wants exactness. The alternative remains open for a re-timed stream — see
//! `DESIGN.md` Part 8.

use std::io::{self, Write};

use crate::codec::{Codec, CodecError};
use crate::ogg::page::{self, PageHeader};
use crate::ogg::scan::{ScanError, Scanner};
use crate::ogg::ParseError;
use crate::sink::{self, Disposition, Progress};
use crate::source::Source;

/// Bound on page-stepping loops, so a pathological stream cannot spin forever.
const MAX_HOPS: usize = 64;

#[derive(Debug)]
pub enum SpliceError {
    Io(io::Error),
    Scan(ScanError),
    Codec(CodecError),
    Parse(ParseError),
    /// The first page carries no packet at all.
    NoPackets,
    /// The identification header is split across pages. Legal in Ogg, but no
    /// encoder does it, and handling it needs packet-level surgery.
    IdHeaderSpansPages,
    /// Audio begins on the same page as the last header packet. Emitting that
    /// page plus a distant tail would strand a partial packet.
    AudioSharesHeaderPage,
    /// The stream ends before its header packets do.
    HeadersIncomplete,
}

impl std::fmt::Display for SpliceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Scan(e) => write!(f, "{e}"),
            Self::Codec(e) => write!(f, "{e}"),
            Self::Parse(e) => write!(f, "{e}"),
            Self::NoPackets => write!(f, "first page contains no packet"),
            Self::IdHeaderSpansPages => {
                write!(f, "identification header spans pages; unsupported")
            }
            Self::AudioSharesHeaderPage => {
                write!(f, "audio starts on a header page; unsupported")
            }
            Self::HeadersIncomplete => write!(f, "stream ends before its headers do"),
        }
    }
}

impl std::error::Error for SpliceError {}

impl From<io::Error> for SpliceError {
    fn from(e: io::Error) -> Self {
        SpliceError::Io(e)
    }
}
impl From<ScanError> for SpliceError {
    fn from(e: ScanError) -> Self {
        SpliceError::Scan(e)
    }
}
impl From<CodecError> for SpliceError {
    fn from(e: CodecError) -> Self {
        SpliceError::Codec(e)
    }
}
impl From<ParseError> for SpliceError {
    fn from(e: ParseError) -> Self {
        SpliceError::Parse(e)
    }
}

impl SpliceError {
    /// The underlying I/O failure, wherever in the stack it surfaced.
    ///
    /// A transport failure reaching us through the scanner is still a transport
    /// failure. Matching only on [`SpliceError::Io`] classified a refused
    /// connection as a malformed stream, which tells a consumer to skip the track
    /// when it should retry.
    fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            SpliceError::Io(e) => Some(e.kind()),
            SpliceError::Scan(ScanError::Io(e)) => Some(e.kind()),
            _ => None,
        }
    }

    /// Exit code per the contract in `DESIGN.md`.
    pub fn exit_code(&self) -> u8 {
        match self.io_kind() {
            Some(io::ErrorKind::NotFound) => 3,
            Some(io::ErrorKind::Unsupported) => 1,
            Some(io::ErrorKind::PermissionDenied) => 4,
            // Any other transport failure: the bytes are not implicated, so this
            // is worth retrying rather than skipping.
            Some(_) => 2,
            // No I/O involved, so the stream itself is not what we were told.
            None => 5,
        }
    }
}

/// What the consumer needs to know before the first byte of audio.
#[derive(Debug, Clone)]
pub struct SpliceInfo {
    pub codec: &'static str,
    /// Granule timebase — 48 000 for Opus regardless of decode rate.
    pub rate: u32,
    pub channels: u8,
    pub duration_ms: Option<u64>,
    pub requested_start_ms: u64,
    /// Where the emitted audio actually begins. Never later than requested.
    pub actual_start_ms: u64,
    /// Granule of the first emitted audio page.
    pub start_granule: Option<u64>,
    /// Bytes skipped before the Ogg stream begins (non-zero only for wrapped
    /// sources such as Spotify's 167-byte prefix).
    pub container_offset: u64,
    pub header_pages: usize,
}

impl SpliceInfo {
    /// One-line JSON, for the metadata channel.
    pub fn to_json(&self) -> String {
        let mut s = String::from("{");
        s.push_str(&format!("\"codec\":\"{}\"", self.codec));
        s.push_str(&format!(",\"rate\":{}", self.rate));
        s.push_str(&format!(",\"channels\":{}", self.channels));
        match self.duration_ms {
            Some(d) => s.push_str(&format!(",\"duration_ms\":{d}")),
            None => s.push_str(",\"duration_ms\":null"),
        }
        s.push_str(&format!(
            ",\"requested_start_ms\":{}",
            self.requested_start_ms
        ));
        s.push_str(&format!(",\"actual_start_ms\":{}", self.actual_start_ms));
        match self.start_granule {
            Some(g) => s.push_str(&format!(",\"start_granule\":{g}")),
            None => s.push_str(",\"start_granule\":null"),
        }
        s.push_str(&format!(",\"container_offset\":{}", self.container_offset));
        s.push_str(&format!(",\"header_pages\":{}", self.header_pages));
        s.push('}');
        s
    }
}

/// A decided splice, ready to emit.
#[derive(Debug, Clone)]
pub struct Plan {
    pub info: SpliceInfo,
    header_offsets: Vec<u64>,
    tail_start: u64,
    source_len: u64,
}

impl Plan {
    /// Byte offset of the first audio page that will be emitted.
    pub fn tail_start(&self) -> u64 {
        self.tail_start
    }
}

/// Result of writing a plan out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Emitted {
    pub bytes: u64,
    pub pages: usize,
    /// True when the consumer closed the pipe. Not an error: it is disposal.
    pub disposed: bool,
}

/// Decide what to emit, without writing anything.
///
/// Separate from [`emit`] so the metadata line can be written before the first
/// audio byte, as the contract requires.
pub fn plan<S: Source>(scanner: &mut Scanner<S>, start_ms: u64) -> Result<Plan, SpliceError> {
    let source_len = scanner.source_len()?;

    // --- identify the codec from the first packet of the first page ---
    let first = scanner.page_at(0)?;
    let first_page = first.page()?;
    let id_span = first_page.packets().next().ok_or(SpliceError::NoPackets)?;
    if !id_span.complete {
        return Err(SpliceError::IdHeaderSpansPages);
    }
    let id_packet = first_page
        .body
        .get(id_span.start..id_span.start + id_span.len)
        .ok_or(SpliceError::NoPackets)?;
    let codec = Codec::identify(id_packet)?;

    // --- collect header pages ---
    let mut header_offsets = Vec::new();
    let mut completed = 0usize;
    let mut offset = 0u64;
    loop {
        let at = scanner.page_at(offset)?;
        let page = at.page()?;
        let spans: Vec<_> = page.packets().collect();
        let finished_here = spans.iter().filter(|s| s.complete).count();
        let trailing_partial = spans.last().map(|s| !s.complete).unwrap_or(false);

        header_offsets.push(offset);
        completed += finished_here;
        let next = at.next_offset();

        if completed >= codec.header_packets() {
            if completed > codec.header_packets() || trailing_partial {
                return Err(SpliceError::AudioSharesHeaderPage);
            }
            offset = next;
            break;
        }
        if next >= source_len {
            return Err(SpliceError::HeadersIncomplete);
        }
        offset = next;
    }
    let first_audio = offset;
    if first_audio >= source_len {
        return Err(SpliceError::HeadersIncomplete);
    }

    // --- duration, from the last page carrying a position ---
    let last_positioned = scanner.seek_granule(u64::MAX, first_audio, source_len)?;
    let duration_ms = scanner
        .header_at(last_positioned)?
        .granule()
        .map(|g| codec.granule_to_ms(g));

    // --- choose the starting page ---
    let target = codec.ms_to_granule(start_ms);
    let mut chosen = page_containing(scanner, target, first_audio, source_len)?;

    // Never begin on a continued page: its first packet started earlier, so a
    // decoder would receive a fragment.
    let mut hops = 0;
    while hops < MAX_HOPS && chosen > first_audio && scanner.header_at(chosen)?.is_continued() {
        chosen = previous_page(scanner, chosen, first_audio, source_len)?;
        hops += 1;
    }

    // A decoder needs run-up before its output is trustworthy, but that is a
    // requirement about *packets*, not pages: the packets earlier in the chosen
    // page normally supply it, since a page holds dozens of them. Only step back
    // a whole page when this one alone does not begin early enough — which
    // happens with very short pages, or when the target lands in the first page
    // of the stream.
    let preroll_ms = codec.preroll_ms();
    let mut hops = 0;
    while hops < MAX_HOPS && chosen > first_audio {
        let begins = emitted_start_ms(scanner, &codec, chosen, first_audio, source_len)?;
        if begins + preroll_ms <= start_ms {
            break;
        }
        chosen = previous_page(scanner, chosen, first_audio, source_len)?;
        hops += 1;
    }

    let actual_start_ms = emitted_start_ms(scanner, &codec, chosen, first_audio, source_len)?;

    let start_granule = scanner.header_at(chosen)?.granule();
    let header_pages = header_offsets.len();

    Ok(Plan {
        info: SpliceInfo {
            codec: codec.name(),
            rate: codec.granule_rate(),
            channels: codec.channels(),
            duration_ms,
            requested_start_ms: start_ms,
            actual_start_ms,
            start_granule,
            container_offset: 0,
            header_pages,
        },
        header_offsets,
        tail_start: chosen,
        source_len,
    })
}

/// Write a plan out, renumbering pages and fixing their checksums.
pub fn emit<S: Source, W: Write>(
    scanner: &mut Scanner<S>,
    plan: &Plan,
    out: &mut W,
) -> Result<Emitted, SpliceError> {
    emit_with_progress(scanner, plan, out, &Progress::new())
}

/// [`emit`], stamping write progress so an idle watchdog can tell a parked
/// consumer from a slow one.
pub fn emit_with_progress<S: Source, W: Write>(
    scanner: &mut Scanner<S>,
    plan: &Plan,
    out: &mut W,
    progress: &Progress,
) -> Result<Emitted, SpliceError> {
    let mut sequence = 0u32;
    let mut bytes = 0u64;
    let mut pages = 0usize;

    for &offset in &plan.header_offsets {
        match write_page(scanner, offset, sequence, out, progress)? {
            Some(n) => {
                bytes += n;
                pages += 1;
                sequence = sequence.wrapping_add(1);
            }
            None => {
                return Ok(Emitted {
                    bytes,
                    pages,
                    disposed: true,
                })
            }
        }
    }

    let mut offset = plan.tail_start;
    while offset < plan.source_len {
        let at = scanner.page_at(offset)?;
        let next = at.next_offset();
        match write_page(scanner, offset, sequence, out, progress)? {
            Some(n) => {
                bytes += n;
                pages += 1;
                sequence = sequence.wrapping_add(1);
            }
            None => {
                return Ok(Emitted {
                    bytes,
                    pages,
                    disposed: true,
                })
            }
        }
        offset = next;
    }

    if sink::flush(out)? == Disposition::Disposed {
        return Ok(Emitted {
            bytes,
            pages,
            disposed: true,
        });
    }

    Ok(Emitted {
        bytes,
        pages,
        disposed: false,
    })
}

/// Emit one page with a new sequence number. `Ok(None)` means the pipe closed.
fn write_page<S: Source, W: Write>(
    scanner: &mut Scanner<S>,
    offset: u64,
    sequence: u32,
    out: &mut W,
    progress: &Progress,
) -> Result<Option<u64>, SpliceError> {
    let mut at = scanner.page_at(offset)?;
    page::set_sequence(&mut at.bytes, sequence)?;
    page::recompute_crc_in_place(&mut at.bytes)?;
    match sink::write_all(out, &at.bytes, progress)? {
        Disposition::Complete => Ok(Some(at.bytes.len() as u64)),
        Disposition::Disposed => Ok(None),
    }
}

/// The first page whose span contains `target`.
///
/// A page's granule is the position *after* the last packet finishing on it, so
/// page P covers `(granule(P-1), granule(P)]`. The page holding a given sample is
/// therefore the first one whose granule is at or above the target — not the last
/// one at or below it, which is the page before.
fn page_containing<S: Source>(
    scanner: &mut Scanner<S>,
    target: u64,
    first_audio: u64,
    hi: u64,
) -> Result<u64, SpliceError> {
    // The target may fall inside the very first audio page, which has no
    // predecessor to bisect from.
    if let Some(granule) = scanner.header_at(first_audio)?.granule() {
        if granule >= target {
            return Ok(first_audio);
        }
    }

    let before = scanner.seek_granule(target.saturating_sub(1), first_audio, hi)?;
    let mut cursor = before;
    let mut hops = 0;
    while hops < MAX_HOPS {
        let header = scanner.header_at(cursor)?;
        let next = cursor + header.total_len() as u64;
        if next >= hi {
            // Nothing after this page; the last positioned page is the best we
            // can offer.
            return Ok(cursor);
        }
        cursor = next;
        hops += 1;
        // Step over pages carrying no position: they cannot be a start point.
        if scanner.header_at(cursor)?.granule().is_some() {
            return Ok(cursor);
        }
    }
    Ok(cursor)
}

/// Millisecond position at which the audio emitted from `chosen` begins.
///
/// Page `chosen` covers `(granule(chosen-1), granule(chosen)]`, so its audio
/// starts where the previous page ended. This is the number the consumer needs to
/// keep its clock honest, and it is never later than the requested start.
fn emitted_start_ms<S: Source>(
    scanner: &mut Scanner<S>,
    codec: &Codec,
    chosen: u64,
    first_audio: u64,
    hi: u64,
) -> Result<u64, SpliceError> {
    if chosen <= first_audio {
        // Emitted from the true start of the stream, so nothing is lost.
        return Ok(0);
    }
    let previous = previous_page(scanner, chosen, first_audio, hi)?;
    if previous >= chosen {
        return Ok(0);
    }
    let Some(granule) = scanner.header_at(previous)?.granule() else {
        return Ok(0);
    };
    // The decoder cannot reconstruct the head of a spliced stream, so the audible
    // start is later than the nominal one by a codec-specific amount.
    Ok(codec.granule_to_ms(granule + codec.splice_discard_samples()))
}

/// The page before `at`, found by bisecting for a granule one below its own.
fn previous_page<S: Source>(
    scanner: &mut Scanner<S>,
    at: u64,
    lo: u64,
    hi: u64,
) -> Result<u64, SpliceError> {
    if at <= lo {
        return Ok(lo);
    }
    let header: PageHeader = scanner.header_at(at)?;
    let Some(granule) = header.granule() else {
        return Ok(lo);
    };
    if granule == 0 {
        return Ok(lo);
    }
    let previous = scanner.seek_granule(granule - 1, lo, hi)?;
    // Guard against a search that cannot make progress.
    Ok(if previous >= at { lo } else { previous })
}
