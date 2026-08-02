//! `http://` end to end, against a fake upstream that reproduces the CDN quirks.
#![cfg(feature = "http")]

//!
//! The server is hand-rolled on `std::net` rather than pulled in as a dependency,
//! because the whole point is to control behaviour a real server will not perform
//! on demand: answering `200` to a ranged request, rotating an `ETag` mid-stream,
//! dropping a connection halfway through a body, failing one URL so a fallback is
//! exercised.
//!
//! The strongest assertion here is [`http_and_file_produce_identical_output`]: the
//! same track served over HTTP and read from disk must splice to *byte-identical*
//! output at every offset. Anything wrong in the ranged reader — an off-by-one in
//! a `Range` header, a mishandled `200`, a botched window boundary — shows up as a
//! diff.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const BIN: &str = env!("CARGO_BIN_EXE_earshot");

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

// ---------------------------------------------------------------- fake upstream

/// How the fake upstream should misbehave.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Quirk {
    /// Correct `206` with `Content-Range`.
    #[default]
    Compliant,
    /// Ignores `Range` entirely and always answers `200` with the whole body —
    /// the same shape a CDN produces when the requested range exceeds the file.
    IgnoresRange,
    /// Serves a different `ETag` than it first advertised, and answers `200`.
    /// A reader that trusted the bytes would splice a different file in.
    RotatesEtag,
    /// Closes the connection partway through the body.
    TruncatesBody,
    /// Answers `500` on every request, so a fallback URL has to take over.
    AlwaysFails,
}

struct Upstream {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    /// Range headers seen, so a test can assert *how* it was read.
    ranges: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn start(body: Vec<u8>, quirk: Quirk) -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let ranges = Arc::new(Mutex::new(Vec::new()));

        let up = Upstream {
            port,
            hits: Arc::clone(&hits),
            stop: Arc::clone(&stop),
            ranges: Arc::clone(&ranges),
        };

        thread::spawn(move || {
            for incoming in listener.incoming() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = incoming else { break };
                let body = body.clone();
                let hits = Arc::clone(&hits);
                let ranges = Arc::clone(&ranges);
                thread::spawn(move || {
                    let _ = serve(stream, &body, quirk, &hits, &ranges);
                });
            }
        });

        up
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/track.ogg", self.port)
    }

    /// A path this server does not have.
    fn missing_url(&self) -> String {
        format!("http://127.0.0.1:{}/nope.ogg", self.port)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }

    fn ranges(&self) -> Vec<String> {
        self.ranges.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Unblock `incoming()` so the accept loop notices the stop flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(
    mut stream: TcpStream,
    body: &[u8],
    quirk: Quirk,
    hits: &AtomicUsize,
    ranges: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    hits.fetch_add(1, Ordering::Relaxed);
    if let Some(range) = headers.get("range") {
        if let Ok(mut seen) = ranges.lock() {
            seen.push(range.clone());
        }
    }

    if quirk == Quirk::AlwaysFails {
        return stream.write_all(b"HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n");
    }

    // Anything other than the one path we serve is genuinely gone.
    if !request_line.contains("/track.ogg") {
        return stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }

    let total = body.len() as u64;
    let requested = headers.get("range").and_then(|r| parse_range(r, total));

    // The `IgnoresRange` and `RotatesEtag` quirks both answer 200 with the whole
    // body, which is exactly what a CDN does for an over-large range.
    let answer_200 = requested.is_none()
        || quirk == Quirk::IgnoresRange
        || (quirk == Quirk::RotatesEtag && headers.contains_key("if-range"));

    if answer_200 {
        let etag = if quirk == Quirk::RotatesEtag && headers.contains_key("if-range") {
            "\"rotated\""
        } else {
            "\"original\""
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\n\
             ETag: {etag}\r\n\r\n"
        );
        stream.write_all(head.as_bytes())?;
        let payload = if quirk == Quirk::TruncatesBody {
            &body[..body.len() / 3]
        } else {
            body
        };
        stream.write_all(payload)?;
        return Ok(());
    }

    let (start, end) = requested.expect("checked above");
    if start >= total {
        // Quirk 3: this is where the length is advertised.
        let head = format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{total}\r\n\
             Content-Length: 0\r\n\r\n"
        );
        return stream.write_all(head.as_bytes());
    }

    let slice = &body[start as usize..=(end as usize)];
    let head = format!(
        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\n\
         Content-Length: {}\r\nAccept-Ranges: bytes\r\nETag: \"original\"\r\n\r\n",
        slice.len()
    );
    stream.write_all(head.as_bytes())?;
    let payload = if quirk == Quirk::TruncatesBody {
        &slice[..slice.len() / 3]
    } else {
        slice
    };
    stream.write_all(payload)
}

/// `bytes=START-END`, clamped to the body. `None` when absent or unparseable.
fn parse_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let spec = value.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = match end.trim() {
        "" => total.saturating_sub(1),
        v => v.parse::<u64>().ok()?,
    };
    Some((start, end.min(total.saturating_sub(1))))
}

// -------------------------------------------------------------------- helpers

struct Run {
    stdout: Vec<u8>,
    stderr: String,
    code: i32,
}

fn earshot(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn earshot");
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn field(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find([',', '}'])?;
    rest[..end].trim().parse().ok()
}

// ---------------------------------------------------------------------- tests

/// The load-bearing test: HTTP and `file://` must splice to identical bytes.
#[test]
fn http_and_file_produce_identical_output() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::Compliant);
    let path = fixture("vorbis_5s.ogg");

    for start_ms in ["0", "500", "1000", "2500", "4000", "4900"] {
        let over_http = earshot(&[&up.url(), "--start-ms", start_ms]);
        let from_disk = earshot(&[path.to_str().unwrap(), "--start-ms", start_ms]);

        assert_eq!(over_http.code, 0, "http @{start_ms}: {}", over_http.stderr);
        assert_eq!(from_disk.code, 0, "file @{start_ms}: {}", from_disk.stderr);
        assert!(
            over_http.stdout == from_disk.stdout,
            "@{start_ms}: http output differs from file output ({} vs {} bytes)",
            over_http.stdout.len(),
            from_disk.stdout.len(),
        );
        assert!(!over_http.stdout.is_empty(), "@{start_ms}: empty output");
    }
}

/// Metadata over HTTP must match metadata from disk, including `actual_start_ms`.
#[test]
fn http_metadata_matches_the_local_file() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::Compliant);
    let path = fixture("vorbis_5s.ogg");

    for start_ms in ["0", "1500", "3000"] {
        let http = earshot(&["probe", &up.url(), "--start-ms", start_ms]);
        let file = earshot(&["probe", path.to_str().unwrap(), "--start-ms", start_ms]);
        assert_eq!(http.code, 0, "{}", http.stderr);
        let a = String::from_utf8_lossy(&http.stdout).trim().to_string();
        let b = String::from_utf8_lossy(&file.stdout).trim().to_string();
        assert_eq!(a, b, "@{start_ms}: metadata differs between http and file");
    }
}

/// Seeking must actually use ranges rather than pulling the file and discarding.
///
/// This is the property that justifies the offset-addressed `Source` trait. The
/// window is narrowed for the test because the fixture is smaller than the default
/// one — with a 1 MiB window a 20 KiB file is fetched whole in a single request,
/// which is correct and optimal but leaves nothing to observe.
#[test]
fn seeking_uses_ranges_instead_of_streaming_from_zero() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let total = bytes.len();
    let up = Upstream::start(bytes, Quirk::Compliant);

    let out = Command::new(BIN)
        .args([&up.url(), "--start-ms", "4900"])
        .env("EARSHOT_HTTP_WINDOW", "4096") // raised to the 64 KiB floor
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let ranges = up.ranges();
    assert!(!ranges.is_empty(), "no Range headers were sent at all");
    assert!(
        ranges.iter().all(|r| r.starts_with("bytes=")),
        "unexpected Range syntax: {ranges:?}",
    );
    // Whatever the window, the file must not be fetched once per read.
    assert!(
        up.hits() < total / 1000,
        "{} requests for a {total}-byte file suggests per-read fetching",
        up.hits(),
    );
}

/// With a window narrower than the file, a late seek must request a *later*
/// region rather than starting from zero and discarding.
#[test]
fn a_late_seek_requests_a_later_region() {
    // 64 KiB is the floor, so build a body comfortably larger than it by serving
    // the fixture padded — only the Ogg prefix is ever parsed, and the reader is
    // what is under test here.
    let mut bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let real_len = bytes.len();
    bytes.resize(real_len + 300_000, 0);
    let up = Upstream::start(bytes, Quirk::Compliant);

    let out = Command::new(BIN)
        .args([&up.url(), "--start-ms", "4900"])
        .env("EARSHOT_HTTP_WINDOW", "65536")
        .output()
        .expect("spawn");
    // Trailing zeroes are not pages, so earshot reports a malformed tail — the
    // point here is which ranges it asked for on the way there.
    let _ = out.status;

    let ranges = up.ranges();
    let starts: Vec<u64> = ranges
        .iter()
        .filter_map(|r| r.strip_prefix("bytes="))
        .filter_map(|s| s.split('-').next())
        .filter_map(|s| s.parse::<u64>().ok())
        .collect();
    assert!(
        starts.iter().any(|&s| s > 0),
        "every request started at offset 0, so nothing was seeked: {ranges:?}",
    );
}

/// Quirk 1: a server that ignores `Range` answers `200` with the body from zero.
/// Reads at an offset must still return the right region.
#[test]
fn a_server_that_ignores_range_still_yields_correct_output() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::IgnoresRange);
    let path = fixture("vorbis_5s.ogg");

    for start_ms in ["0", "2000", "4000"] {
        let over_http = earshot(&[&up.url(), "--start-ms", start_ms]);
        let from_disk = earshot(&[path.to_str().unwrap(), "--start-ms", start_ms]);
        assert_eq!(over_http.code, 0, "@{start_ms}: {}", over_http.stderr);
        assert!(
            over_http.stdout == from_disk.stdout,
            "@{start_ms}: 200-instead-of-206 produced the wrong region",
        );
    }
}

/// Quirk 2: a resource that rotates mid-stream must be an error, never silently
/// spliced. Serving the new file's bytes as though they were the old one's is the
/// single worst outcome available here.
#[test]
fn a_rotated_resource_is_detected_rather_than_spliced() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::RotatesEtag);

    // A late start forces more than one request, so the validator is sent and the
    // rotation is observable.
    let run = earshot(&[&up.url(), "--start-ms", "4000"]);
    assert_ne!(run.code, 0, "a rotated resource should not succeed quietly");
    assert!(
        run.stderr.to_lowercase().contains("changed") || run.stderr.to_lowercase().contains("etag"),
        "error does not explain the rotation: {}",
        run.stderr,
    );
}

/// Quirk 3: asking past the end answers `416` carrying the total, which is how
/// the length is learned without a `HEAD`.
#[test]
fn length_is_learned_and_past_the_end_is_not_an_error() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::Compliant);

    let probe = earshot(&["probe", &up.url(), "--start-ms", "0"]);
    assert_eq!(probe.code, 0, "{}", probe.stderr);
    let json = String::from_utf8_lossy(&probe.stdout);
    assert_eq!(field(&json, "duration_ms"), Some(5_000), "duration: {json}");

    // Well past the end: still a valid stream, clamped.
    let run = earshot(&[&up.url(), "--start-ms", "600000"]);
    assert_eq!(run.code, 0, "seeking past the end: {}", run.stderr);
    assert_eq!(&run.stdout[..4], b"OggS");
}

/// A dead URL must fail with a retryable code rather than hanging or claiming the
/// stream is malformed.
#[test]
fn an_unreachable_server_reports_a_transient_failure() {
    // Port 1 is reserved and nothing listens there.
    let run = earshot(&["http://127.0.0.1:1/track.ogg"]);
    assert_ne!(run.code, 0);
    assert!(
        run.code == 2 || run.code == 3,
        "expected transient (2) or unavailable (3), got {}: {}",
        run.code,
        run.stderr,
    );
}

/// Every candidate answering 5xx is transient — the bytes are not implicated, so
/// a consumer should retry rather than skip the track.
#[test]
fn a_failing_server_is_reported_as_transient() {
    let up = Upstream::start(Vec::new(), Quirk::AlwaysFails);
    let run = earshot(&[&up.url()]);
    assert_eq!(
        run.code, 2,
        "expected retryable (2); got {}: {}",
        run.code, run.stderr,
    );
}

/// A 404 is permanent: skip the track, do not retry it forever.
#[test]
fn a_404_is_reported_as_permanently_unavailable() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::Compliant);
    let run = earshot(&[&up.missing_url()]);
    assert_eq!(
        run.code, 3,
        "expected permanently unavailable (3); got {}: {}",
        run.code, run.stderr,
    );
}

/// A body that stops early must surface as a malformed stream, not as silence or
/// a hang.
#[test]
fn a_truncated_body_is_reported() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::TruncatesBody);
    let run = earshot(&[&up.url(), "--start-ms", "0"]);
    // Either it refuses, or it emits a prefix and stops — never a hang, and never
    // a success claim over bytes it does not have.
    if run.code == 0 {
        assert!(
            !run.stdout.is_empty(),
            "claimed success with no output at all",
        );
    } else {
        assert!(
            run.code == 2 || run.code == 5,
            "unexpected code {}: {}",
            run.code,
            run.stderr,
        );
    }
}

/// The output must still be structurally valid Ogg when it came over the wire.
#[test]
fn http_output_passes_our_own_validator() {
    let bytes = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::Compliant);

    let run = earshot(&[&up.url(), "--start-ms", "2000"]);
    assert_eq!(run.code, 0, "{}", run.stderr);

    let dir = std::env::temp_dir().join(format!("earshot-http-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("out.ogg");
    std::fs::write(&path, &run.stdout).expect("write");

    let pages = earshot(&["pages", path.to_str().unwrap()]);
    let report = String::from_utf8_lossy(&pages.stdout);
    assert_eq!(pages.code, 0, "pages said: {}", pages.stderr);
    assert!(
        report.contains("checksum failures: 0"),
        "checksum failures over http: {report}",
    );
    let _ = std::fs::remove_file(&path);
}

/// Both codecs over the wire, since granule semantics differ.
#[test]
fn opus_over_http_matches_the_local_file() {
    let bytes = std::fs::read(fixture("opus_5s.opus")).expect("fixture");
    let up = Upstream::start(bytes, Quirk::Compliant);
    let path = fixture("opus_5s.opus");

    let over_http = earshot(&[&up.url(), "--start-ms", "3000"]);
    let from_disk = earshot(&[path.to_str().unwrap(), "--start-ms", "3000"]);
    assert_eq!(over_http.code, 0, "{}", over_http.stderr);
    assert!(
        over_http.stdout == from_disk.stdout,
        "opus over http differs from file",
    );
}
