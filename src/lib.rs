//! earshot — a streaming audio source tool.
//!
//! Turns a URI into an Ogg stream on stdout, with precise `--start-ms` splicing.
//! A building block for audio applications rather than an application itself.
//!
//! ## Layers
//!
//! ```text
//! source   offset-addressed bytes         file:// today; http:// and room:// next
//!   │      Source { len, read_at }        transforms are Source→Source decorators
//!   ▼
//! ogg      page framing + checksums       genuinely codec-agnostic
//!   │      parse · serialise · scan · bisect
//!   ▼
//! codec    granule semantics              Vorbis vs Opus disagree; this is the seam
//!   │      ms ↔ granule · pre-roll policy
//!   ▼
//! splice   which page to start from       renumber, re-checksum, report actual_start_ms
//!   │
//!   ▼
//! stdout   backpressure is the interface  BrokenPipe is disposal, not failure
//! ```
//!
//! Sources are addressed by **offset** rather than being `io::Read` adapters, and
//! that is the one decision everything else rests on: HTTP has `Range`, and
//! AES-CTR's keystream position *is* the byte offset, so seeking stays `O(log n)`
//! and a dropped connection can resume. `DESIGN.md` derives this and the rest
//! from verified properties of Ogg, Vorbis, Opus, HTTP and Unix pipes.

pub mod codec;
pub mod config;
pub mod ogg;
pub mod sink;
pub mod source;
pub mod splice;

use std::path::PathBuf;

/// `$XDG_CONFIG_HOME`, else `~/.config`.
pub fn config_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(dir));
    }
    home_dir().map(|h| h.join(".config"))
}

/// Cross-platform home directory.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    let var = "HOME";
    #[cfg(windows)]
    let var = "USERPROFILE";
    std::env::var_os(var).map(PathBuf::from)
}
