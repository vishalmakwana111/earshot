//! `http(s)://` — a ranged reader.
//!
//! This is where the [`Source`] trait earns its shape. Every read is a `Range`
//! request at an absolute offset, so granule bisection costs a handful of small
//! requests instead of streaming and discarding everything before the target, and
//! a connection that dies mid-transfer costs one re-request rather than the file.
//!
//! ## The three quirks this exists to handle
//!
//! Verified against how Spotify's CDN actually behaves (see `DESIGN.md` A9):
//!
//! 1. **A range larger than the file returns `200`, not `206`.** So does any
//!    server that ignores `Range` outright. Either way the body starts at offset
//!    zero, and serving a read at offset *N* from it means discarding *N* bytes —
//!    treating it as a chunk would silently return the wrong region.
//! 2. **Resources rotate.** A time-limited CDN URL can start serving something
//!    else. `If-Range` with the validator makes the server answer `200` (whole
//!    body) instead of a chunk of a *different* file; combined with an `ETag`
//!    comparison that becomes a detectable error rather than a silent splice of
//!    mismatched bytes.
//! 3. **`416` carries the length.** Asking past the end answers
//!    `Content-Range: bytes */NNN`, which is how end-of-stream is learned without
//!    a separate `HEAD` — useful because some CDNs do not answer `HEAD` at all.
//!
//! ## Why it buffers
//!
//! The layers above read a page at a time — a 282-byte header probe, then a few
//! kilobytes of body. One request per read would mean hundreds of round trips for
//! a single track. Reads are served from a read-ahead window instead (see
//! [`chunk_size`]), so sequential streaming costs one request per megabyte while
//! bisection still gets its random access.

use std::io::{self, Read};

use super::Source;
use crate::config::Settings;

/// Classify an HTTP status the contract cares about.
///
/// Shared by both request paths deliberately: when only `fetch` did this, a 404
/// discovered while probing for the length came back unclassified and a consumer
/// was told to retry something permanently gone.
fn status_error(url: &str, status: u16) -> io::Error {
    let kind = match status {
        404 | 410 => io::ErrorKind::NotFound,
        401 | 403 => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{url}: HTTP {status}"))
}

/// A remote byte range, addressed by offset.
pub struct HttpSource {
    agent: ureq::Agent,
    /// Candidate URLs in preference order. A resolver may hand back several for
    /// the same content; any of them will do, so a failure moves to the next.
    urls: Vec<String>,
    /// Which URL is currently working, so the next read starts there.
    active: usize,
    /// Total length, learned from `Content-Range`, `Content-Length` or a `416`.
    len: Option<u64>,
    /// Validator for `If-Range`, so a rotated resource is detected.
    etag: Option<String>,
    /// Read-ahead window and the absolute offset of its first byte.
    buf: Vec<u8>,
    buf_start: u64,
    /// Resolved once, so every read uses the same window.
    chunk: usize,
}

impl HttpSource {
    /// A single URL, with settings from the config layers.
    pub fn new(url: impl Into<String>) -> io::Result<Self> {
        Self::with_fallbacks(vec![url.into()], &Settings::load().unwrap_or_default())
    }

    /// Several interchangeable URLs, tried in order.
    pub fn with_fallbacks(urls: Vec<String>, settings: &Settings) -> io::Result<Self> {
        if urls.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no candidate URLs",
            ));
        }
        for url in &urls {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("not an http(s) URL: {url}"),
                ));
            }
        }

        // Status codes are data here, not errors: 206 vs 200 vs 416 each mean
        // something specific, and ureq would otherwise turn 4xx/5xx into an
        // error before it could be inspected.
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(settings.timeout_global))
            .timeout_connect(Some(settings.timeout_connect))
            .http_status_as_error(false)
            .build();

        Ok(HttpSource {
            agent: config.into(),
            urls,
            active: 0,
            len: None,
            etag: None,
            buf: Vec::new(),
            buf_start: 0,
            chunk: settings.http_window,
        })
    }

    /// Serve from the read-ahead window, if `off` falls inside it.
    fn read_from_window(&self, off: u64, dst: &mut [u8]) -> Option<usize> {
        let start = usize::try_from(off.checked_sub(self.buf_start)?).ok()?;
        let available = self.buf.get(start..)?;
        if available.is_empty() {
            return None;
        }
        let n = available.len().min(dst.len());
        dst[..n].copy_from_slice(&available[..n]);
        Some(n)
    }

    /// Fetch a window starting at `off`, trying each URL until one answers.
    fn fill(&mut self, off: u64) -> io::Result<()> {
        let mut last: Option<io::Error> = None;
        for attempt in 0..self.urls.len() {
            let index = (self.active + attempt) % self.urls.len();
            match self.fetch(index, off) {
                Ok(()) => {
                    self.active = index;
                    return Ok(());
                }
                // A failure on one candidate does not mean the content is gone,
                // so keep trying — but remember the most specific failure.
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no candidate URLs")))
    }

    fn fetch(&mut self, index: usize, off: u64) -> io::Result<()> {
        let url = self.urls[index].clone();
        let end = off.saturating_add(self.chunk as u64 - 1);

        let mut request = self
            .agent
            .get(&url)
            .header("Range", &format!("bytes={off}-{end}"));
        if let Some(etag) = &self.etag {
            // Quirk 2: makes a rotated resource answer 200-whole-body rather
            // than a chunk of something else.
            request = request.header("If-Range", etag);
        }

        let mut response = request
            .call()
            .map_err(|e| io::Error::other(format!("{url}: {e}")))?;
        let status = response.status().as_u16();

        let header = |name: &str| -> Option<String> {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let content_range = header("content-range");
        let content_length = header("content-length");
        let served_etag = header("etag");

        match status {
            // Quirk 3: the only response that carries the length for free.
            416 => {
                if let Some(total) = content_range.as_deref().and_then(total_from_content_range) {
                    self.len = Some(total);
                }
                // Past the end is not a failure; it is end of stream.
                self.buf.clear();
                self.buf_start = off;
                return Ok(());
            }
            200 | 206 => {}
            other => return Err(status_error(&url, other)),
        }

        // Quirk 1: on 200 the body starts at zero, whatever we asked for.
        let body_starts_at = if status == 206 {
            if let Some(total) = content_range.as_deref().and_then(total_from_content_range) {
                self.len = Some(total);
            }
            off
        } else {
            if let Some(total) = content_length
                .as_deref()
                .and_then(|v| v.parse::<u64>().ok())
            {
                self.len = Some(total);
            }
            // Quirk 2 again: we sent a validator and got the whole body back. If
            // the validator also changed, this is a different resource — serving
            // its bytes as though they were ours would corrupt the stream
            // silently, which is the one outcome worth failing over.
            if let (Some(ours), Some(theirs)) = (&self.etag, &served_etag) {
                if ours != theirs {
                    return Err(io::Error::other(format!(
                        "{url}: resource changed mid-stream (ETag {ours} -> {theirs})"
                    )));
                }
            }
            0
        };

        if self.etag.is_none() {
            self.etag = served_etag;
        }

        // Discard down to the offset we actually want. Only reachable on the
        // 200 path, where the server sent us the file from the start.
        let mut reader = response.body_mut().as_reader();
        if body_starts_at < off {
            let skip = off - body_starts_at;
            let mut sink = io::sink();
            let copied = io::copy(&mut reader.by_ref().take(skip), &mut sink)?;
            if copied < skip {
                // The body ended before our offset: nothing here to read.
                self.buf.clear();
                self.buf_start = off;
                return Ok(());
            }
        }

        self.buf.clear();
        // A short read is normal — the range may be clipped by the file end, and
        // a dropped connection leaves a partial window. Either way the caller is
        // served what arrived and the next read re-requests from where it got to,
        // which is what makes resume cost one request rather than the file.
        reader.take(self.chunk as u64).read_to_end(&mut self.buf)?;
        self.buf_start = off;
        Ok(())
    }

    /// Learn the length with a one-byte range, since some CDNs ignore `HEAD`.
    fn probe_len(&mut self) -> io::Result<()> {
        let mut last: Option<io::Error> = None;
        for attempt in 0..self.urls.len() {
            let index = (self.active + attempt) % self.urls.len();
            let url = self.urls[index].clone();
            let response = match self.agent.get(&url).header("Range", "bytes=0-0").call() {
                Ok(r) => r,
                Err(e) => {
                    last = Some(io::Error::other(format!("{url}: {e}")));
                    continue;
                }
            };

            let header = |name: &str| -> Option<String> {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            let status = response.status().as_u16();
            let total = match status {
                206 | 416 => header("content-range")
                    .as_deref()
                    .and_then(total_from_content_range),
                // Range ignored: the whole body is here, so its length is the
                // total.
                200 => header("content-length")
                    .as_deref()
                    .and_then(|v| v.parse::<u64>().ok()),
                _ => None,
            };
            if self.etag.is_none() {
                self.etag = header("etag");
            }
            if let Some(total) = total {
                self.len = Some(total);
                self.active = index;
                return Ok(());
            }
            // Keep the status classified: a 404 here means the same thing it
            // means anywhere else.
            last = Some(match status {
                200 | 206 | 416 => {
                    io::Error::other(format!("{url}: HTTP {status} carried no usable length"))
                }
                other => status_error(&url, other),
            });
        }
        Err(last.unwrap_or_else(|| io::Error::other("could not determine content length")))
    }
}

impl Source for HttpSource {
    fn size(&mut self) -> io::Result<Option<u64>> {
        if self.len.is_none() {
            // Bisection needs a length; forward streaming does not. Report the
            // failure rather than pretending the stream is unbounded, since the
            // caller would otherwise get a confusing "cannot seek".
            self.probe_len()?;
        }
        Ok(self.len)
    }

    fn read_at(&mut self, off: u64, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if let Some(len) = self.len {
            if off >= len {
                return Ok(0);
            }
        }
        if let Some(n) = self.read_from_window(off, dst) {
            return Ok(n);
        }
        self.fill(off)?;
        Ok(self.read_from_window(off, dst).unwrap_or(0))
    }
}

/// Total size out of `Content-Range: bytes X-Y/Z` — or `bytes */Z` on a 416.
///
/// `Z` may legitimately be `*` when the server does not know the total, which is
/// not a parse failure but is unusable for seeking.
fn total_from_content_range(value: &str) -> Option<u64> {
    let (_, total) = value.rsplit_once('/')?;
    total.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_total_out_of_content_range() {
        assert_eq!(total_from_content_range("bytes 0-1023/4096"), Some(4096));
        // The 416 form, which is how end-of-stream is learned.
        assert_eq!(total_from_content_range("bytes */4096"), Some(4096));
        assert_eq!(total_from_content_range("bytes 100-199/200"), Some(200));
    }

    #[test]
    fn unknown_totals_are_not_parse_failures_but_are_unusable() {
        assert_eq!(total_from_content_range("bytes 0-1023/*"), None);
        assert_eq!(total_from_content_range("nonsense"), None);
        assert_eq!(total_from_content_range(""), None);
    }

    #[test]
    fn rejects_non_http_urls_up_front() {
        for url in ["file:///x", "room://t@h/x", "ftp://x/y", "x"] {
            let err = HttpSource::new(url).map(|_| ()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{url}");
        }
        assert!(HttpSource::new("http://example.com/a.ogg").is_ok());
        assert!(HttpSource::new("https://example.com/a.ogg").is_ok());
    }

    #[test]
    fn an_empty_candidate_list_is_rejected() {
        let err = HttpSource::with_fallbacks(Vec::new(), &Settings::default())
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn the_window_comes_from_settings() {
        let settings = Settings {
            http_window: 128 * 1024,
            ..Settings::default()
        };
        let src =
            HttpSource::with_fallbacks(vec!["http://x/y".into()], &settings).expect("construct");
        assert_eq!(src.chunk, 128 * 1024);
    }
}
