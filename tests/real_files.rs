//! Golden-fixture tests against real encoder output.
//!
//! These are the tests that matter most for the checksum, because ffmpeg wrote
//! those CRC fields, not us. If our table were the reflected zlib variant — the
//! single easiest way to get Ogg wrong — every assertion here would fail. Unit
//! tests can only prove our implementation is self-consistent; these prove it
//! agrees with the rest of the world.
//!
//! Both fixtures are five seconds of a 440 Hz sine, stereo. Regenerate with:
//!
//! ```sh
//! ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=44100:duration=5" -ac 2 \
//!        -c:a vorbis -strict -2 -y tests/fixtures/vorbis_5s.ogg
//! ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=5" -ac 2 \
//!        -c:a libopus -b:a 48k -y tests/fixtures/opus_5s.opus
//! ```
//!
//! Regenerating means updating the constants below; they are golden values, and
//! that is the point.

use earshot::ogg::{Page, Pages};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn parse_all(bytes: &[u8]) -> Vec<Page<'_>> {
    let mut pages = Vec::new();
    let mut iter = Pages::new(bytes);
    for result in &mut iter {
        pages.push(result.expect("well-formed page"));
    }
    let consumed: usize = pages.iter().map(|p| p.len()).sum();
    assert_eq!(consumed, bytes.len(), "pages must tile the whole file");
    pages
}

/// The external-oracle test: ffmpeg's checksums must validate against our table.
#[test]
fn every_page_checksum_validates() {
    for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
        let bytes = fixture(name);
        let pages = parse_all(&bytes);
        assert!(!pages.is_empty(), "{name}: no pages");
        for (i, page) in pages.iter().enumerate() {
            assert!(
                page.verify_crc(),
                "{name}: page {i} at seq {} — stored {:#010x}, computed {:#010x}",
                page.sequence,
                page.crc,
                page.computed_crc(),
            );
        }
    }
}

/// Parse then re-render every page from its fields; the file must come back
/// byte for byte. This is what proves the serialiser and parser agree on all
/// eight header fields and both variable-length regions.
#[test]
fn whole_file_roundtrip_is_byte_identical() {
    for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
        let bytes = fixture(name);
        let mut out = Vec::with_capacity(bytes.len());
        for page in parse_all(&bytes) {
            page.write_to(&mut out);
        }
        assert_eq!(out.len(), bytes.len(), "{name}: length");
        assert!(out == bytes, "{name}: bytes differ after roundtrip");
    }
}

/// Re-emitting with a recomputed checksum must reproduce the original file
/// exactly — no page was modified, so no checksum may change.
#[test]
fn recomputing_checksums_reproduces_the_file() {
    for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
        let bytes = fixture(name);
        let mut out = Vec::with_capacity(bytes.len());
        for page in parse_all(&bytes) {
            let stored = page.crc;
            let written = page.write_with_crc(&mut out);
            assert_eq!(written, stored, "{name}: seq {}", page.sequence);
        }
        assert!(out == bytes, "{name}: bytes differ");
    }
}

/// Page sequence numbers are per-serial and must be gapless in encoder output.
/// A splice breaks this, which is why the splice layer renumbers.
#[test]
fn sequence_numbers_are_gapless_per_serial() {
    for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
        let bytes = fixture(name);
        let pages = parse_all(&bytes);
        let serial = pages[0].serial;
        for (expected, page) in pages.iter().enumerate() {
            assert_eq!(page.serial, serial, "{name}: single logical stream");
            assert_eq!(page.sequence, expected as u32, "{name}: sequence gap");
        }
    }
}

#[test]
fn stream_boundaries_are_marked_once_each() {
    for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
        let bytes = fixture(name);
        let pages = parse_all(&bytes);
        assert!(pages[0].is_bos(), "{name}: first page must be bos");
        assert!(pages.last().unwrap().is_eos(), "{name}: last must be eos");
        assert_eq!(pages.iter().filter(|p| p.is_bos()).count(), 1, "{name}");
        assert_eq!(pages.iter().filter(|p| p.is_eos()).count(), 1, "{name}");
    }
}

/// Packet spans must exactly tile each page body, with continuation reported
/// consistently against the next page's flag.
#[test]
fn packet_spans_tile_bodies_and_agree_with_continuation_flags() {
    for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
        let bytes = fixture(name);
        let pages = parse_all(&bytes);
        for (i, page) in pages.iter().enumerate() {
            let spans: Vec<_> = page.packets().collect();
            let covered: usize = spans.iter().map(|s| s.len).sum();
            assert_eq!(covered, page.body.len(), "{name}: page {i} body coverage");

            let runs_on = spans.last().map(|s| !s.complete).unwrap_or(false);
            if let Some(next) = pages.get(i + 1) {
                assert_eq!(
                    runs_on,
                    next.is_continued(),
                    "{name}: page {i} runs on but page {} disagrees",
                    i + 1,
                );
            }
        }
    }
}

#[test]
fn vorbis_fixture_matches_its_golden_shape() {
    let bytes = fixture("vorbis_5s.ogg");
    assert_eq!(bytes.len(), 20_917);
    let pages = parse_all(&bytes);
    assert_eq!(pages.len(), 7);

    // Vorbis has three header packets; the identification header is alone on the
    // first page and starts with packet type 1 followed by "vorbis".
    assert_eq!(&pages[0].body[..7], b"\x01vorbis");

    // Vorbis granule counts samples at the *stream* rate, so this is directly
    // convertible: 5 s at 44 100 Hz is 220 500, and the encoder padded to a
    // block boundary. No pre-skip mechanism exists — contrast the Opus case.
    let final_granule = pages.last().unwrap().granule().expect("final granule");
    assert_eq!(final_granule, 220_544);
    assert!(
        final_granule >= 5 * 44_100,
        "at least five seconds of samples"
    );
}

/// The fixture that pins axiom A7, and the reason `ms → granule` cannot live in
/// the generic Ogg layer.
#[test]
fn opus_granule_is_48khz_and_offset_by_pre_skip() {
    let bytes = fixture("opus_5s.opus");
    assert_eq!(bytes.len(), 41_650);
    let pages = parse_all(&bytes);
    assert_eq!(pages.len(), 8);

    // OpusHead: magic(8) version(1) channels(1) pre_skip(2 LE) rate(4) gain(2)
    // mapping(1) = 19 bytes, alone on the first page.
    let head = pages[0].body;
    assert_eq!(head.len(), 19);
    assert_eq!(&head[..8], b"OpusHead");
    let channels = head[9];
    let pre_skip = u16::from_le_bytes([head[10], head[11]]) as u64;
    assert_eq!(channels, 2);
    assert_eq!(pre_skip, 312, "libopus default pre-skip");

    // The load-bearing assertion. Opus granule always counts at 48 kHz
    // regardless of decode rate, and the true PCM position is
    // `granule - pre_skip`. Five seconds is therefore exactly 240 000 — but only
    // once pre-skip is subtracted. A codec-agnostic granule→ms helper would be
    // off by 312 samples here and by a different amount for Vorbis.
    let final_granule = pages.last().unwrap().granule().expect("final granule");
    assert_eq!(final_granule, 240_312);
    assert_eq!(final_granule - pre_skip, 5 * 48_000);
}

/// Neither fixture exercises the `-1` granule or the continuation flag, so those
/// paths are covered by hand-built pages in the unit tests. Asserting the gap
/// here keeps it from being mistaken for coverage we have.
#[test]
fn fixtures_do_not_cover_the_awkward_cases() {
    for name in ["vorbis_5s.ogg", "opus_5s.opus"] {
        let bytes = fixture(name);
        let pages = parse_all(&bytes);
        assert_eq!(
            pages.iter().filter(|p| p.granule().is_none()).count(),
            0,
            "{name}: unexpected -1 granule — update the unit-test note",
        );
        assert_eq!(
            pages.iter().filter(|p| p.is_continued()).count(),
            0,
            "{name}: unexpected continued page — update the unit-test note",
        );
    }
}

/// Truncating a real file at any byte must produce an error, never a panic.
#[test]
fn truncated_real_files_never_panic() {
    let bytes = fixture("vorbis_5s.ogg");
    for cut in (0..bytes.len()).step_by(7) {
        let mut iter = Pages::new(&bytes[..cut]);
        for page in (&mut iter).flatten() {
            let _ = page.verify_crc();
            let _ = page.packets().count();
        }
    }
}
