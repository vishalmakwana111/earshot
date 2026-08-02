//! Ogg page framing: parse, walk, and re-serialise.
//!
//! This is the genuinely codec-agnostic layer. It knows about pages, segment
//! tables, packet boundaries and checksums — and deliberately nothing about
//! audio. Anything that needs to turn a granule position into a duration is a
//! *codec* concern and lives one layer up, because [RFC 3533] is explicit that
//! granule semantics are defined by the codec's media mapping, not by Ogg:
//! Vorbis counts samples at the stream rate, Opus always counts at 48 kHz and
//! carries a pre-skip to subtract. A single "generic" `ms → granule` helper
//! cannot be written here without being wrong for one of them.
//!
//! ## Header layout (RFC 3533 §6)
//!
//! ```text
//!  0..4   capture pattern "OggS"
//!  4      version (must be 0)
//!  5      header type flags     0x01 continued · 0x02 bos · 0x04 eos
//!  6..14  granule position      little-endian; -1 means "no packet finishes here"
//! 14..18  bitstream serial      little-endian
//! 18..22  page sequence number  little-endian, per serial
//! 22..26  CRC-32                little-endian, computed with this field zeroed
//! 26      page segments (n)     0..=255
//! 27..27+n segment table        lacing values
//! ```
//!
//! Every multi-byte field is little-endian, even though the checksum itself is
//! computed MSB-first. See [`super::crc`].
//!
//! ## Why serialising matters as much as parsing
//!
//! Splicing a stream means emitting the original header pages followed by a tail
//! that starts mid-file. That renumbers page sequence numbers, and it may rewrite
//! a codec's identification header (Opus pre-skip). Both edits invalidate the
//! checksum, and a stale CRC is one of the three things that make libogg report a
//! hole in the data — the others being a sequence-number gap and a
//! continuation-flag mismatch at the boundary. So the splice layer cannot be a
//! zero-copy view over the input: it has to re-serialise. Hence
//! [`Page::write_with_crc`].
//!
//! [RFC 3533]: https://www.rfc-editor.org/rfc/rfc3533.html#section-6

use super::crc;

/// The four bytes that begin every page.
pub const CAPTURE_PATTERN: [u8; 4] = *b"OggS";

/// The only stream structure version RFC 3533 defines.
pub const VERSION: u8 = 0;

/// Bytes of header that precede the segment table.
pub const MIN_HEADER_LEN: usize = 27;

/// A page carries at most 255 lacing values.
pub const MAX_SEGMENTS: usize = 255;

/// 255 segments × 255 bytes — the reason pages cap out just under 64 KiB.
pub const MAX_BODY_LEN: usize = MAX_SEGMENTS * 255;

/// Largest possible page, header included.
pub const MAX_PAGE_LEN: usize = MIN_HEADER_LEN + MAX_SEGMENTS + MAX_BODY_LEN;

/// Offset of the CRC field, which is zeroed while checksumming.
const CRC_OFFSET: usize = 22;

/// The page's first packet is continued from the previous page.
pub const FLAG_CONTINUED: u8 = 0x01;
/// Beginning of stream.
pub const FLAG_BOS: u8 = 0x02;
/// End of stream.
pub const FLAG_EOS: u8 = 0x04;

/// `-1` in two's complement: no packet *finishes* on this page.
///
/// Bisection must skip these pages rather than treat them as position 0, and a
/// rewrite must preserve the value verbatim.
pub const GRANULE_NONE: u64 = u64::MAX;

/// Why a buffer is not a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The capture pattern is absent — this is not a page boundary.
    NotAPage,
    /// Structure version is something other than 0.
    UnsupportedVersion(u8),
    /// The buffer ends before the page does.
    Truncated { need: usize, got: usize },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAPage => write!(f, "no OggS capture pattern"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported Ogg version {v}"),
            Self::Truncated { need, got } => {
                write!(f, "truncated page: need {need} bytes, have {got}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A page header, parsed without needing the body.
///
/// Exists for one reason: bisecting a remote stream for a granule position needs
/// each probe to cost as little as possible. A probe reads at most
/// `MIN_HEADER_LEN + MAX_SEGMENTS` (282) bytes, learns the granule *and* the
/// exact total page length, and stops — instead of pulling up to 64 KiB to find
/// out where the page ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageHeader {
    pub flags: u8,
    pub granule_raw: u64,
    pub serial: u32,
    pub sequence: u32,
    pub crc: u32,
    /// Number of lacing values.
    pub segment_count: usize,
    /// Sum of the lacing values.
    pub body_len: usize,
}

impl PageHeader {
    /// Parse a header from the start of `buf`.
    ///
    /// Needs only `27 + segment_count` bytes, not the whole page. Cannot panic
    /// on any input.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        // Judge the capture pattern against whatever prefix exists. A buffer that
        // *contradicts* "OggS" is definitively not a page at any length, and
        // resync wants that answer without waiting for 27 bytes. A buffer that
        // merely stops inside a matching prefix might still become one, so that
        // reports as truncated instead.
        let probe = buf.len().min(CAPTURE_PATTERN.len());
        if buf[..probe] != CAPTURE_PATTERN[..probe] {
            return Err(ParseError::NotAPage);
        }

        let head: &[u8; MIN_HEADER_LEN] = buf
            .get(..MIN_HEADER_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(ParseError::Truncated {
                need: MIN_HEADER_LEN,
                got: buf.len(),
            })?;

        if head[4] != VERSION {
            return Err(ParseError::UnsupportedVersion(head[4]));
        }

        // Spelled out byte by byte so the RFC offsets are checkable by eye, and
        // so indexing a fixed-size array keeps this provably panic-free.
        let granule_raw = u64::from_le_bytes([
            head[6], head[7], head[8], head[9], head[10], head[11], head[12], head[13],
        ]);
        let serial = u32::from_le_bytes([head[14], head[15], head[16], head[17]]);
        let sequence = u32::from_le_bytes([head[18], head[19], head[20], head[21]]);
        let crc = u32::from_le_bytes([head[22], head[23], head[24], head[25]]);
        let segment_count = head[26] as usize;

        let table_end = MIN_HEADER_LEN + segment_count;
        let segments = buf
            .get(MIN_HEADER_LEN..table_end)
            .ok_or(ParseError::Truncated {
                need: table_end,
                got: buf.len(),
            })?;

        Ok(PageHeader {
            flags: head[5],
            granule_raw,
            serial,
            sequence,
            crc,
            segment_count,
            // Bounded by 255 × 255, so this cannot overflow.
            body_len: segments.iter().map(|&v| v as usize).sum(),
        })
    }

    /// Bytes of header, segment table included.
    pub fn header_len(&self) -> usize {
        MIN_HEADER_LEN + self.segment_count
    }

    /// Total on-the-wire length of the page this header describes.
    pub fn total_len(&self) -> usize {
        self.header_len() + self.body_len
    }

    /// Granule position, or `None` for the `-1` no-packet-finishes-here case.
    pub fn granule(&self) -> Option<u64> {
        (self.granule_raw != GRANULE_NONE).then_some(self.granule_raw)
    }

    pub fn is_continued(&self) -> bool {
        self.flags & FLAG_CONTINUED != 0
    }

    pub fn is_bos(&self) -> bool {
        self.flags & FLAG_BOS != 0
    }

    pub fn is_eos(&self) -> bool {
        self.flags & FLAG_EOS != 0
    }
}

/// Overwrite a page's sequence number in place, leaving the checksum stale.
///
/// Always pair with [`recompute_crc_in_place`]; splitting the two is deliberate
/// so a caller making several edits pays for one checksum pass.
pub fn set_sequence(page: &mut [u8], sequence: u32) -> Result<(), ParseError> {
    let header = PageHeader::parse(page)?;
    if page.len() < header.total_len() {
        return Err(ParseError::Truncated {
            need: header.total_len(),
            got: page.len(),
        });
    }
    page[18..22].copy_from_slice(&sequence.to_le_bytes());
    Ok(())
}

/// Recompute a page's checksum from its current bytes and store it.
///
/// This is the step whose omission shows up much later as a decoder reporting a
/// hole in the data.
pub fn recompute_crc_in_place(page: &mut [u8]) -> Result<u32, ParseError> {
    let header = PageHeader::parse(page)?;
    let total = header.total_len();
    if page.len() < total {
        return Err(ParseError::Truncated {
            need: total,
            got: page.len(),
        });
    }
    let page = &mut page[..total];
    page[CRC_OFFSET..CRC_OFFSET + 4].fill(0);
    let checksum = crc::checksum(page);
    page[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    Ok(checksum)
}

/// A parsed page borrowing its bytes from the input.
///
/// Only [`Page::parse`] can build one — the private `raw` field is what makes
/// that so. It keeps two invariants free: `segments.len() <= 255`, and `raw` is
/// exactly this page's bytes, so [`Page::verify_crc`] checks the *input* rather
/// than our re-rendering of it. Synthesising pages from scratch is an M1
/// concern and will want a separate owned builder.
#[derive(Debug, Clone)]
pub struct Page<'a> {
    /// Header type flags; prefer the [`Page::is_continued`] family.
    pub flags: u8,
    /// Granule position exactly as stored, including [`GRANULE_NONE`].
    pub granule_raw: u64,
    /// Logical bitstream this page belongs to.
    pub serial: u32,
    /// Page sequence number, counted per `serial`.
    pub sequence: u32,
    /// Checksum as stored in the header.
    pub crc: u32,
    /// Lacing values.
    pub segments: &'a [u8],
    /// Page body, `segments.iter().sum()` bytes long.
    pub body: &'a [u8],
    raw: &'a [u8],
}

impl<'a> Page<'a> {
    /// Parse one page from the start of `buf`.
    ///
    /// Reads only as far as this page extends, so it is safe to call on a buffer
    /// holding many pages. Cannot panic on any input: every offset below is
    /// bounds-checked at compile time against a fixed-size header array, and the
    /// two variable-length regions are length-checked first.
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let header = PageHeader::parse(buf)?;
        let body_start = header.header_len();
        let page_end = header.total_len();

        // `PageHeader::parse` already proved the segment table is present, so
        // only the body can still be short.
        let segments = buf
            .get(MIN_HEADER_LEN..body_start)
            .ok_or(ParseError::Truncated {
                need: body_start,
                got: buf.len(),
            })?;
        let body = buf.get(body_start..page_end).ok_or(ParseError::Truncated {
            need: page_end,
            got: buf.len(),
        })?;

        Ok(Page {
            flags: header.flags,
            granule_raw: header.granule_raw,
            serial: header.serial,
            sequence: header.sequence,
            crc: header.crc,
            segments,
            body,
            raw: &buf[..page_end],
        })
    }

    /// This page's header, as it would be seen by a header-only probe.
    pub fn header(&self) -> PageHeader {
        PageHeader {
            flags: self.flags,
            granule_raw: self.granule_raw,
            serial: self.serial,
            sequence: self.sequence,
            crc: self.crc,
            segment_count: self.segments.len(),
            body_len: self.body.len(),
        }
    }

    /// This page's exact bytes as they appeared in the input.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Total on-the-wire length, header included.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Always false — a page has at minimum a 27-byte header. Present because
    /// clippy asks for it wherever `len` exists.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Granule position, or `None` for the `-1` no-packet-finishes-here case.
    pub fn granule(&self) -> Option<u64> {
        (self.granule_raw != GRANULE_NONE).then_some(self.granule_raw)
    }

    /// True when this page's first packet continues one from the previous page.
    ///
    /// A splice must not begin on such a page: the decoder would receive a
    /// packet fragment.
    pub fn is_continued(&self) -> bool {
        self.flags & FLAG_CONTINUED != 0
    }

    pub fn is_bos(&self) -> bool {
        self.flags & FLAG_BOS != 0
    }

    pub fn is_eos(&self) -> bool {
        self.flags & FLAG_EOS != 0
    }

    /// Walk packet spans within this page's body.
    ///
    /// A lacing value below 255 terminates a packet; a run of 255s means the
    /// packet continues, and if such a run reaches the end of the segment table
    /// the final span is reported with `complete: false` — it carries on into
    /// the next page. A lacing value of 0 legitimately terminates a zero-length
    /// packet, so empty spans are not an error.
    pub fn packets(&self) -> Packets<'a> {
        Packets {
            segments: self.segments,
            index: 0,
            offset: 0,
        }
    }

    /// Checksum recomputed from [`Page::raw`], with the CRC field taken as zero.
    pub fn computed_crc(&self) -> u32 {
        let mut hasher = crc::Crc::new();
        // `raw` is at least MIN_HEADER_LEN long, so both slices are in bounds.
        hasher.update(&self.raw[..CRC_OFFSET]);
        hasher.update(&[0u8; 4]);
        hasher.update(&self.raw[CRC_OFFSET + 4..]);
        hasher.finish()
    }

    /// Whether the stored checksum matches the bytes.
    pub fn verify_crc(&self) -> bool {
        self.computed_crc() == self.crc
    }

    /// Append this page to `out`, keeping the stored checksum.
    ///
    /// Renders from the parsed fields rather than copying [`Page::raw`], which
    /// is what makes the roundtrip test meaningful: byte-identical output proves
    /// the serialiser agrees with the parser on every field and offset.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        self.write_header(out, self.crc);
        out.extend_from_slice(self.body);
    }

    /// Append this page to `out` with a freshly computed checksum, returning it.
    ///
    /// This is the path the splice layer uses after renumbering a sequence
    /// number or rewriting a codec identification header.
    pub fn write_with_crc(&self, out: &mut Vec<u8>) -> u32 {
        let start = out.len();
        self.write_header(out, 0);
        out.extend_from_slice(self.body);
        let checksum = crc::checksum(&out[start..]);
        let field = start + CRC_OFFSET;
        out[field..field + 4].copy_from_slice(&checksum.to_le_bytes());
        checksum
    }

    fn write_header(&self, out: &mut Vec<u8>, checksum: u32) {
        out.extend_from_slice(&CAPTURE_PATTERN);
        out.push(VERSION);
        out.push(self.flags);
        out.extend_from_slice(&self.granule_raw.to_le_bytes());
        out.extend_from_slice(&self.serial.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        // Invariant from `parse`: at most 255 segments, so this cannot truncate.
        out.push(self.segments.len() as u8);
        out.extend_from_slice(self.segments);
    }
}

/// One packet, or packet fragment, within a page body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketSpan {
    /// Offset within the page *body*.
    pub start: usize,
    pub len: usize,
    /// False when the packet runs on into the following page.
    pub complete: bool,
}

/// Iterator over [`PacketSpan`]s. See [`Page::packets`].
#[derive(Debug, Clone)]
pub struct Packets<'a> {
    segments: &'a [u8],
    index: usize,
    offset: usize,
}

impl Iterator for Packets<'_> {
    type Item = PacketSpan;

    fn next(&mut self) -> Option<PacketSpan> {
        if self.index >= self.segments.len() {
            return None;
        }
        let start = self.offset;
        let mut len = 0usize;
        let mut complete = false;
        while let Some(&value) = self.segments.get(self.index) {
            self.index += 1;
            len += value as usize;
            if value < 255 {
                complete = true;
                break;
            }
        }
        self.offset = start + len;
        Some(PacketSpan {
            start,
            len,
            complete,
        })
    }
}

/// Sequential page reader over a whole buffer.
///
/// Strict on purpose: it stops at the first thing that is not a page. Resynchro-
/// nising after damage, and granule bisection over a random-access source, are
/// M1's `scan` concerns — this exists so tests and the `pages` debug command can
/// walk a well-formed file.
#[derive(Debug, Clone)]
pub struct Pages<'a> {
    buf: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> Pages<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Pages {
            buf,
            offset: 0,
            done: false,
        }
    }

    /// Byte offset of the next page to be read.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl<'a> Iterator for Pages<'a> {
    type Item = Result<Page<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.buf.len() {
            return None;
        }
        match Page::parse(&self.buf[self.offset..]) {
            Ok(page) => {
                self.offset += page.len();
                Some(Ok(page))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a page from parts, with a valid checksum. Test-only: production
    /// code only ever *reads* pages at M0.
    fn synth(flags: u8, granule_raw: u64, sequence: u32, segments: &[u8]) -> Vec<u8> {
        let body_len: usize = segments.iter().map(|&v| v as usize).sum();
        let body: Vec<u8> = (0..body_len).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        out.extend_from_slice(&CAPTURE_PATTERN);
        out.push(VERSION);
        out.push(flags);
        out.extend_from_slice(&granule_raw.to_le_bytes());
        out.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.push(segments.len() as u8);
        out.extend_from_slice(segments);
        out.extend_from_slice(&body);
        let checksum = crc::checksum(&out);
        out[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
        out
    }

    #[test]
    fn parses_a_synthetic_page() {
        let bytes = synth(FLAG_BOS, 4242, 7, &[30]);
        let page = Page::parse(&bytes).expect("parse");
        assert!(page.is_bos());
        assert!(!page.is_continued());
        assert!(!page.is_eos());
        assert_eq!(page.granule(), Some(4242));
        assert_eq!(page.sequence, 7);
        assert_eq!(page.serial, 0x1234_5678);
        assert_eq!(page.body.len(), 30);
        assert_eq!(page.len(), MIN_HEADER_LEN + 1 + 30);
        assert!(page.verify_crc());
    }

    #[test]
    fn roundtrip_is_byte_identical() {
        for segments in [
            &[0u8][..],        // nil packet
            &[30][..],         // one small packet
            &[255, 12][..],    // one packet spanning two lacing values
            &[255, 0][..],     // packet of exactly 255 bytes
            &[255; 255][..],   // maximal body, packet continues onward
            &[10, 20, 30][..], // three packets
        ] {
            let bytes = synth(0, 99, 3, segments);
            let page = Page::parse(&bytes).expect("parse");
            let mut out = Vec::new();
            page.write_to(&mut out);
            assert_eq!(out, bytes, "roundtrip for segments {segments:?}");
        }
    }

    #[test]
    fn write_with_crc_reproduces_a_valid_checksum() {
        let bytes = synth(0, 1000, 1, &[40, 50]);
        let page = Page::parse(&bytes).expect("parse");
        let mut out = Vec::new();
        let written = page.write_with_crc(&mut out);
        assert_eq!(written, page.crc, "unmodified page keeps its checksum");
        assert_eq!(out, bytes);
    }

    #[test]
    fn renumbering_changes_the_checksum_and_stays_valid() {
        let bytes = synth(0, 1000, 41, &[40, 50]);
        let original = Page::parse(&bytes).expect("parse");

        let mut renumbered = original.clone();
        renumbered.sequence = 3;

        let mut out = Vec::new();
        let new_crc = renumbered.write_with_crc(&mut out);
        assert_ne!(new_crc, original.crc, "a header edit must change the CRC");

        // The re-emitted page must parse and self-verify — this is the exact
        // step whose omission shows up as a hole in the data downstream.
        let reparsed = Page::parse(&out).expect("reparse");
        assert_eq!(reparsed.sequence, 3);
        assert!(reparsed.verify_crc());
    }

    #[test]
    fn granule_minus_one_is_preserved_not_zeroed() {
        let bytes = synth(FLAG_CONTINUED, GRANULE_NONE, 9, &[255, 255]);
        let page = Page::parse(&bytes).expect("parse");
        assert_eq!(page.granule(), None, "-1 must not read as a position");
        assert_eq!(page.granule_raw, GRANULE_NONE);

        let mut out = Vec::new();
        page.write_to(&mut out);
        assert_eq!(out, bytes, "-1 must survive a rewrite verbatim");
    }

    #[test]
    fn continuation_flag_is_reported() {
        let bytes = synth(FLAG_CONTINUED, 5, 2, &[10]);
        assert!(Page::parse(&bytes).expect("parse").is_continued());
    }

    #[test]
    fn packet_walk_handles_the_lacing_rules() {
        let cases: &[(&[u8], &[PacketSpan])] = &[
            // A single 30-byte packet.
            (
                &[30],
                &[PacketSpan {
                    start: 0,
                    len: 30,
                    complete: true,
                }],
            ),
            // 255 + 12: one packet of 267 bytes.
            (
                &[255, 12],
                &[PacketSpan {
                    start: 0,
                    len: 267,
                    complete: true,
                }],
            ),
            // A packet whose length is exactly 255 is terminated by a 0.
            (
                &[255, 0],
                &[PacketSpan {
                    start: 0,
                    len: 255,
                    complete: true,
                }],
            ),
            // A bare 0 is a legal zero-length packet, not an error.
            (
                &[0],
                &[PacketSpan {
                    start: 0,
                    len: 0,
                    complete: true,
                }],
            ),
            // Three packets back to back.
            (
                &[10, 20, 30],
                &[
                    PacketSpan {
                        start: 0,
                        len: 10,
                        complete: true,
                    },
                    PacketSpan {
                        start: 10,
                        len: 20,
                        complete: true,
                    },
                    PacketSpan {
                        start: 30,
                        len: 30,
                        complete: true,
                    },
                ],
            ),
            // Runs out mid-packet: continues into the next page.
            (
                &[255, 255],
                &[PacketSpan {
                    start: 0,
                    len: 510,
                    complete: false,
                }],
            ),
            // One complete packet, then the start of another.
            (
                &[5, 255],
                &[
                    PacketSpan {
                        start: 0,
                        len: 5,
                        complete: true,
                    },
                    PacketSpan {
                        start: 5,
                        len: 255,
                        complete: false,
                    },
                ],
            ),
        ];
        for (segments, expected) in cases {
            let bytes = synth(0, 1, 0, segments);
            let page = Page::parse(&bytes).expect("parse");
            let got: Vec<_> = page.packets().collect();
            assert_eq!(&got[..], *expected, "segments {segments:?}");
            // Spans must exactly tile the body.
            let covered: usize = got.iter().map(|p| p.len).sum();
            assert_eq!(covered, page.body.len(), "segments {segments:?}");
        }
    }

    #[test]
    fn rejects_non_pages_and_bad_versions() {
        let mut bytes = synth(0, 0, 0, &[1]);
        bytes[4] = 9;
        assert_eq!(
            Page::parse(&bytes).unwrap_err(),
            ParseError::UnsupportedVersion(9),
        );
    }

    /// "Not a page" must win over "truncated" whenever the bytes we *do* have
    /// already rule a page out — that is what lets a scanner advance instead of
    /// waiting for more input that cannot help.
    #[test]
    fn capture_pattern_is_judged_before_length() {
        for contradicts in [
            &b""[..], // nothing to contradict, but nothing to match either
            &b"X"[..],
            &b"Xgg"[..],
            &b"Ogg!"[..],
            &b"NotAnOggPageAtAllReally..."[..],
            &b"a very long buffer that never mentions the magic bytes"[..],
        ] {
            if contradicts.is_empty() {
                // An empty buffer matches the empty prefix, so it is truncated.
                assert_eq!(
                    Page::parse(contradicts).unwrap_err(),
                    ParseError::Truncated {
                        need: MIN_HEADER_LEN,
                        got: 0
                    },
                );
                continue;
            }
            assert_eq!(
                Page::parse(contradicts).unwrap_err(),
                ParseError::NotAPage,
                "input {contradicts:?}",
            );
        }

        // A buffer that stops *inside* a matching prefix could still become a
        // page, so it must report as truncated rather than rejected.
        for partial in [&b"O"[..], &b"Og"[..], &b"Ogg"[..], &b"OggS"[..]] {
            assert_eq!(
                Page::parse(partial).unwrap_err(),
                ParseError::Truncated {
                    need: MIN_HEADER_LEN,
                    got: partial.len(),
                },
                "input {partial:?}",
            );
        }
    }

    #[test]
    fn every_truncation_is_an_error_and_never_a_panic() {
        let bytes = synth(0, 500, 4, &[255, 40]);
        for cut in 0..bytes.len() {
            match Page::parse(&bytes[..cut]) {
                Err(ParseError::Truncated { .. }) => {}
                Err(other) => panic!("cut at {cut}: unexpected {other:?}"),
                Ok(_) => panic!("cut at {cut}: parsed a truncated page"),
            }
        }
        assert!(Page::parse(&bytes).is_ok(), "the whole page still parses");
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // A cheap stand-in for the real fuzz target, so the property is at least
        // exercised in CI. `fuzz/` carries the unbounded version.
        let mut state = 0x243F_6A88_85A3_08D3u64;
        for _ in 0..20_000 {
            let len = {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 40) as usize % 200
            };
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            if let Ok(page) = Page::parse(&buf) {
                // Anything that parses must also survive the accessors.
                let _ = page.granule();
                let _ = page.verify_crc();
                let _ = page.packets().count();
                let mut out = Vec::new();
                page.write_to(&mut out);
            }
        }
    }

    #[test]
    fn pages_iterator_walks_a_multi_page_buffer() {
        let mut buf = Vec::new();
        for seq in 0..5u32 {
            buf.extend_from_slice(&synth(0, seq as u64 * 1000, seq, &[20, 30]));
        }
        let pages: Vec<_> = Pages::new(&buf).map(|p| p.expect("page")).collect();
        assert_eq!(pages.len(), 5);
        for (i, page) in pages.iter().enumerate() {
            assert_eq!(page.sequence, i as u32);
            assert!(page.verify_crc());
        }
    }
}
