//! Fuzz the page parser over arbitrary bytes.
//!
//! `ogg::page` is a hand-written parser fed by whatever a remote source hands
//! over, so "never panics on hostile input" is the claim most worth verifying
//! mechanically. The unit suite has a bounded pseudo-random stand-in; this is the
//! unbounded version.
//!
//! It checks more than absence of panics. Any buffer that *parses* must
//! re-serialise to exactly its own bytes — the same roundtrip identity the
//! fixture tests assert, now over inputs nobody chose.
//!
//! Run it:
//!
//! ```sh
//! cargo +nightly fuzz run page_scan
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use earshot::ogg::page::{Page, Pages};

fuzz_target!(|data: &[u8]| {
    if let Ok(page) = Page::parse(data) {
        // Accessors must survive anything that parsed.
        let _ = page.granule();
        let _ = page.verify_crc();
        let _ = page.computed_crc();

        // Packet spans must tile the body exactly, never overrun it.
        let covered: usize = page.packets().map(|p| p.len).sum();
        assert_eq!(
            covered,
            page.body.len(),
            "packet spans do not tile the body",
        );

        // Roundtrip identity, over an input nobody chose.
        let mut out = Vec::new();
        page.write_to(&mut out);
        assert_eq!(out, page.raw(), "serialise did not reproduce the input");

        // Re-emitting with a fresh checksum must still parse and self-verify.
        let mut rewritten = Vec::new();
        page.write_with_crc(&mut rewritten);
        let reparsed = Page::parse(&rewritten).expect("rewritten page must parse");
        assert!(reparsed.verify_crc(), "rewritten page fails its own checksum");
    }

    // Walking a whole buffer must terminate and never panic. `Pages` advances by
    // at least a header length per step or stops, so a hang here would itself be
    // the bug worth finding.
    for result in Pages::new(data) {
        if let Ok(page) = result {
            let _ = page.verify_crc();
        }
    }
});
