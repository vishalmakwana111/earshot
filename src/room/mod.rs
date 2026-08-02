//! The `room://` backend: play a track resolved by a listening-room host.
//!
//! A listening room lets many free-account listeners share one Premium host's
//! session. The host mints the audio key and signed CDN URLs; the guest here
//! just downloads, decrypts and splices. This module is the guest half.
//!
//! The hardware store analogy: earshot is a tool shop, `room://` is one
//! branded aisle; the actual Spotify machinery lives in the host, which is an
//! M3 concern (and, in practice, the Myx room binary).
//!
//! ## How a track becomes bytes
//!
//! ```text
//! room:spotify:track:… ──► resolve via /resolve ──► key + CDN urls
//!                                                            │
//!                              Window { start: 0xa7 }  ◄─────┤
//!                                Decrypt { key }      ◄─────┤  CTR keystream
//!                                  HttpSource         ◄─────┤  ranged GETs
//! ```
//!
//! Each layer is a [`Source`] decorator from the byte core, which is why this
//! whole backend reads as a pipeline. The two Spotify-specific facts — the
//! fixed CTR IV (`A8`) and the prepended `0xa7` normalisation packet (`A10`) —
//! live in `source::decrypt` and here respectively.

pub mod client;

use crate::config::Settings;
use crate::source::{read_exact_at, Decrypt, HttpSource, OpenError, Source, Window};
use client::RoomClient;

/// Where the Ogg stream begins inside the decrypted file: after the ~`0xa7`-byte
/// normalisation packet Spotify prepends (`DESIGN.md` A10).
pub const SPOTIFY_OGG_HEADER_END: u64 = 0xa7;

/// Build the source for a room track: resolve through the configured host,
/// then layer `Window<Decrypt<HttpSource>>`, verifying along the way that the
/// decrypted stream actually is Ogg before anything reads it.
pub fn open_room(track: &str, settings: &Settings) -> Result<Box<dyn Source>, OpenError> {
    let host = settings
        .room_host
        .as_deref()
        .filter(|h| !h.trim().is_empty())
        .ok_or_else(|| {
            OpenError::Usage(
                "a room track needs a host — set room_host/room_token or \
                 EARSHOT_ROOM_HOST/EARSHOT_ROOM_TOKEN"
                    .into(),
            )
        })?;
    let token = settings
        .room_token
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| OpenError::Usage("room_token is not configured".into()))?;
    if host.contains("://") {
        return Err(OpenError::Usage(format!(
            "room_host holds a whole URL ({host:?}); give it just the host:port"
        )));
    }

    let resolved = RoomClient::new(
        crate::source::http_agent(settings),
        host.to_string(),
        token.to_string(),
        settings.room_allow_networks.clone(),
    )
    .resolve(track)?;

    let http = HttpSource::with_fallbacks(resolved.urls, settings).map_err(OpenError::Io)?;
    let mut decrypted = Decrypt::new(http, resolved.key);
    verify_ogg_magic(&mut decrypted)?;
    Ok(Box::new(Window::new(decrypted, SPOTIFY_OGG_HEADER_END)))
}

/// Confirm the stream is Ogg before it is read, so a wrong key or mislabelled
/// file fails here with a clear message instead of a confusing parse error in
/// the splice. Costs one 4-byte ranged request.
fn verify_ogg_magic(src: &mut dyn Source) -> Result<(), OpenError> {
    let mut magic = [0u8; 4];
    read_exact_at(src, SPOTIFY_OGG_HEADER_END, &mut magic).map_err(|e| {
        OpenError::Malformed(format!(
            "decrypted stream ended before the Ogg header (0xa7 + 4 bytes): {e} — \
             wrong key, or not a Spotify Ogg file"
        ))
    })?;
    if &magic != b"OggS" {
        return Err(OpenError::Malformed(format!(
            "decrypted audio starts with {magic:?}, not OggS — wrong key, or not a \
             Spotify Ogg file"
        )));
    }
    Ok(())
}
