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
//! Window<Decrypt<HttpRanged>>      // a Spotify track in a room
//!   Window   read_at(o) -> inner.read_at(o + 0xa7)   strips the prepended packet
//!   Decrypt  read_at(o) -> keystream_at(o) ^ inner   exact, because CTR is seekable
//! ```
//!
//! Because the decorators are offset-preserving, granule bisection still works
//! straight through the stack, and the Ogg layer above never learns that any of
//! it happened.

use std::io;

#[cfg(feature = "room")]
mod decrypt;
mod file;
#[cfg(feature = "http")]
mod http;
mod mem;
mod window;

#[cfg(feature = "room")]
pub use decrypt::{Decrypt, SPOTIFY_AUDIO_IV};
pub use file::FileSource;
#[cfg(feature = "http")]
pub use http::HttpSource;
pub use mem::MemSource;
pub use window::Window;

/// How a URI failed to become a source, classified for the exit-code contract.
///
/// `DESIGN.md` Part 4 fixes the consumer surface: a player needs to tell "skip
/// this track" from "retry" from "re-auth" from "you gave me junk". `io::Error`
/// carries only a kind, and there is no kind for "the token was rejected", so
/// routing through one would lose exactly the distinction the contract buys.
#[derive(Debug)]
pub enum OpenError {
    /// A wrapped `io` failure from the plain backends; mapped to exit codes the
    /// same way the CLI used to map `io::ErrorKind`.
    Io(io::Error),
    /// The URI or configuration is wrong — a room URI with no room configured,
    /// for instance.
    Usage(String),
    /// Worth retrying: the room was busy, the network hiccup'd, a transient
    /// resolve failure.
    Transient(String),
    /// Permanently not playable — wrong format, host decided the track is gone.
    Unavailable(String),
    /// Credentials were rejected: bad room token.
    Auth(String),
    /// The host (or file) handed back junk that passed no validation.
    Malformed(String),
}

impl OpenError {
    /// The exit code the CLI should report. 3 and 4 distinguish skip from re-auth,
    /// which is what lets a consumer branch without parsing messages.
    pub fn exit_code(&self) -> u8 {
        match self {
            OpenError::Io(e) => match e.kind() {
                io::ErrorKind::Unsupported => 1,
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => 3,
                _ => 2,
            },
            OpenError::Usage(_) => 1,
            OpenError::Transient(_) => 2,
            OpenError::Unavailable(_) => 3,
            OpenError::Auth(_) => 4,
            OpenError::Malformed(_) => 5,
        }
    }
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Io(e) => write!(f, "{e}"),
            OpenError::Usage(m)
            | OpenError::Transient(m)
            | OpenError::Unavailable(m)
            | OpenError::Auth(m)
            | OpenError::Malformed(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

/// A ureq agent with the network timeouts from `settings`, shared by the HTTP
/// source and the room client so both talk the same retry language.
#[cfg(feature = "http")]
pub(crate) fn http_agent(settings: &crate::config::Settings) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(settings.timeout_global))
        .timeout_connect(Some(settings.timeout_connect))
        .http_status_as_error(false)
        .build();
    config.into()
}

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
/// Recognised schemes: `file://` and bare paths, `http(s)://` (with the `http`
/// feature), and — with the `room` feature — `spotify:` and `room:` track URIs,
/// which play through the room configured in `settings`.
#[cfg_attr(not(any(feature = "http", feature = "room")), allow(unused_variables))]
pub fn open(uri: &str, settings: &crate::config::Settings) -> Result<Box<dyn Source>, OpenError> {
    if let Some(rest) = uri.strip_prefix("file://") {
        return FileSource::open(rest)
            .map(|s| Box::new(s) as Box<dyn Source>)
            .map_err(OpenError::Io);
    }

    #[cfg(feature = "http")]
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return HttpSource::with_fallbacks(vec![uri.to_string()], settings)
            .map(|s| Box::new(s) as Box<dyn Source>)
            .map_err(OpenError::Io);
    }
    #[cfg(not(feature = "http"))]
    for scheme in ["http://", "https://"] {
        if uri.starts_with(scheme) {
            return Err(OpenError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{scheme} needs the `http` feature"),
            )));
        }
    }

    #[cfg(feature = "room")]
    {
        // The 0.1-style URI put the token in the URI itself. That is a real
        // credential leak — argv, shell history, process listings — so it is
        // rejected with a pointer to the config layers instead of tolerated.
        if uri.starts_with("room://") {
            return Err(OpenError::Usage(
                "credentials do not belong in the URI — put the room's host and token \
                 in room_host/room_token (or EARSHOT_ROOM_HOST/EARSHOT_ROOM_TOKEN) and \
                 pass `room:<track>` or `spotify:<track>`"
                    .into(),
            ));
        }
        if uri == "room:" {
            return Err(OpenError::Usage("room: needs a track URI after it".into()));
        }
        if let Some(track) = uri.strip_prefix("room:") {
            return crate::room::open_room(track, settings);
        }
        // A bare `spotify:track:…` URI comes from a consumer that may not even
        // know rooms exist (myx passes the URI straight through); if a room is
        // configured, it is a room track.
        if uri.starts_with("spotify:") && uri.len() > "spotify:".len() {
            return crate::room::open_room(uri, settings);
        }
    }
    #[cfg(not(feature = "room"))]
    {
        if uri.starts_with("room:") || uri.starts_with("spotify:") {
            return Err(OpenError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{uri:?} needs the `room` feature"),
            )));
        }
    }

    if let Some((scheme, _)) = uri.split_once("://") {
        return Err(OpenError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unknown URI scheme {scheme:?}"),
        )));
    }
    // A bare path is a convenience, not a scheme.
    FileSource::open(uri)
        .map(|s| Box::new(s) as Box<dyn Source>)
        .map_err(OpenError::Io)
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
    fn known_schemes_and_the_unknown_fallback() {
        let settings = crate::config::Settings::default();
        // file:// and bare paths are the plain case.
        assert!(open("file:///does/not/exist.ogg", &settings).is_err());
        assert!(open("/does/not/exist.ogg", &settings).is_err());
        // http(s):// constructs a source without contacting it (M1 behaviour).
        #[cfg(feature = "http")]
        {
            assert!(open("http://example.invalid/a.ogg", &settings).is_ok());
            assert!(open("https://example.invalid/a.ogg", &settings).is_ok());
        }
        // Unknown schemes fail loudly instead of looking like relative paths.
        let err = match open("gopher://x", &settings) {
            Ok(_) => panic!("gopher:// should not open"),
            Err(e) => e,
        };
        assert!(
            matches!(err, OpenError::Io(ref e) if e.kind() == io::ErrorKind::Unsupported),
            "{err}"
        );

        // With the room feature, room:// with credentials in the URI is a
        // deliberate refusal — that is not the protocol's shape.
        #[cfg(not(feature = "room"))]
        {
            let err = match open("room://tok@host/track", &settings) {
                Ok(_) => panic!("room:// should not open"),
                Err(e) => e,
            };
            assert!(
                matches!(err, OpenError::Io(ref e) if e.kind() == io::ErrorKind::Unsupported),
                "{err}"
            );
        }
        // A spotify: URI with no room configured is a usage error, not a file.
        #[cfg(feature = "room")]
        {
            for bad in [
                "room://tok@host/spotify:track:x",
                "spotify:track:xyz",
                "room:",
            ] {
                let err = match open(bad, &settings) {
                    Ok(_) => panic!("{bad} should not open"),
                    Err(e) => e,
                };
                assert!(matches!(err, OpenError::Usage(_)), "{bad}: {err}");
            }
        }
    }
}
