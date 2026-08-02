//! Ogg container framing — the codec-agnostic core.
//!
//! Deliberately narrow: pages, segment tables, packet boundaries, checksums.
//! Nothing here knows what audio is, and that is the point. Granule position is
//! defined by each codec's media mapping rather than by Ogg itself, so
//! `ms ↔ granule` lives in the codec layer above (M0 milestone note: that layer
//! is next, and `DESIGN.md` records why it cannot be folded in here).

pub mod crc;
pub mod page;
pub mod scan;

pub use page::{
    PacketSpan, Packets, Page, Pages, ParseError, FLAG_BOS, FLAG_CONTINUED, FLAG_EOS, GRANULE_NONE,
    MAX_BODY_LEN, MAX_PAGE_LEN, MAX_SEGMENTS, MIN_HEADER_LEN,
};
