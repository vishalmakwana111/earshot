//! `earshot host` end to end: the *server* half of a room, driven as a real
//! subprocess against a fake engine, and then consumed by a real `earshot`
//! guest — the full M3 loop.
//!
//! ```text
//!   earshot <track>          earshot host              fake engine
//!   (guest, room client)     (this milestone)          (stands in for Myx)
//!        │                        │                         │
//!        ├─ POST /resolve ───────►│                         │
//!        │                        ├─ POST /engine-resolve ─►│
//!        │                        │◄─ url + key_hex ────────┤
//!        │◄─ signed /audio/… ─────┤                         │
//!        ├─ GET /audio/… (Range) ►│                         │
//!        │                        ├─ ranged GET ───────────►│
//!        │◄─ 206 ─────────────────┤◄─ 206 ──────────────────┤
//! ```
//!
//! The engine serves the Spotify artifact shape (`DESIGN` A10): `0xa7` junk
//! bytes then the Ogg fixture, AES-128-CTR encrypted. Nothing in the chain
//! decrypts except the guest, so the load-bearing assertion is the same one
//! `room_e2e` makes — audio through the whole loop is **byte-identical** to the
//! fixture read straight off disk.
//!
//! The host is never given a fixed port: it binds `127.0.0.1:0` and announces
//! the chosen address on stdout, which is both the readiness signal and the
//! proof that minted CDN URLs carry the *real* port rather than the configured
//! one.

#![cfg(feature = "host")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use base64::Engine as _;
use ctr::Ctr128BE;
use earshot::source::SPOTIFY_AUDIO_IV;
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_earshot");

/// Bytes before the Ogg stream Spotify prepends (`SPOTIFY_OGG_HEADER_END`).
const PREG_END: usize = 0xa7;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const KEY: [u8; 16] = *b"0123456789abcdef";
const TRACK: &str = "spotify:track:deadbeef";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The encrypted, normalisation-padded body the engine will serve.
fn audio_body() -> Vec<u8> {
    let audio = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let mut plain = Vec::with_capacity(PREG_END + audio.len());
    plain.extend(std::iter::repeat_n(0xe5, PREG_END));
    plain.extend_from_slice(&audio);
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(&KEY, &SPOTIFY_AUDIO_IV).expect("cipher");
    cipher.apply_keystream(&mut plain);
    plain
}

// ------------------------------------------------------------- signing oracle

/// Recompute the host's CDN signature. Mirrors `room::host::sign`.
///
/// The test knows the shared token, and the signing secret is derived from it,
/// so the test can mint URLs the host will accept. That is what makes it
/// possible to prove expiry is enforced *on a genuinely valid signature* —
/// a tampered one would be refused for the wrong reason.
fn sign(token: &str, id: &str, exp: u64) -> String {
    let secret = {
        let mut h = Sha256::new();
        h.update(b"earshot/cdn/v1");
        h.update(token.as_bytes());
        h.finalize().to_vec()
    };
    let mut h = Sha256::new();
    h.update(&secret);
    h.update(id.as_bytes());
    h.update(b"|");
    h.update(exp.to_string().as_bytes());
    hex(&h.finalize())
}

fn audio_id(engine_url: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(engine_url.as_bytes())
}

// ---------------------------------------------------------------- fake engine

/// How the fake engine should answer, to exercise the host's validation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EngineMode {
    Happy,
    /// 500 — the engine is broken.
    Broken,
    /// A format the room cannot play.
    NonOgg,
    /// A key that is not 32 hex chars.
    ShortKey,
    /// A `url` that is not http(s).
    BadUrl,
    /// Happy, but states a lifetime short enough to forbid caching.
    ExpiresImmediately,
    /// Happy on resolve, but the file URL is already dead (410) — an expired
    /// CDN link, which is the case a TTL alone cannot catch.
    DeadUrl,
}

/// Holds every `/file.ogg` request until `target` of them are in flight at once.
///
/// This is how concurrency is asserted without timing: a host that serves
/// requests one at a time can never get a second request into the engine while
/// the first is still inside it, so the gate never opens and the requests fail.
struct Gate {
    target: usize,
    state: Mutex<usize>,
    open: Condvar,
}

impl Gate {
    /// Returns false if the gate never reached its target — a serialized host.
    fn arrive(&self) -> bool {
        let mut waiting = self.state.lock().expect("gate");
        *waiting += 1;
        if *waiting >= self.target {
            self.open.notify_all();
            return true;
        }
        let deadline = Duration::from_secs(5);
        let start = std::time::Instant::now();
        while *waiting < self.target {
            if start.elapsed() >= deadline {
                return false;
            }
            let (next, timeout) = self
                .open
                .wait_timeout(waiting, deadline - start.elapsed())
                .expect("gate wait");
            waiting = next;
            if timeout.timed_out() && *waiting < self.target {
                return false;
            }
        }
        true
    }
}

struct FakeEngine {
    port: u16,
    resolve_calls: Arc<AtomicUsize>,
    ranges: Arc<Mutex<Vec<String>>>,
    /// TCP connections accepted, and requests served across them. Equal iff the
    /// host never reuses a connection.
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

impl FakeEngine {
    fn start(mode: EngineMode) -> FakeEngine {
        FakeEngine::start_gated(mode, None)
    }

    /// Start an engine that holds `/file.ogg` until `concurrent` requests overlap.
    fn start_concurrent(concurrent: usize) -> FakeEngine {
        FakeEngine::start_gated(
            EngineMode::Happy,
            Some(Arc::new(Gate {
                target: concurrent,
                state: Mutex::new(0),
                open: Condvar::new(),
            })),
        )
    }

    fn start_gated(mode: EngineMode, gate: Option<Arc<Gate>>) -> FakeEngine {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind engine");
        let port = listener.local_addr().expect("addr").port();
        let resolve_arc = Arc::new(AtomicUsize::new(0));
        let range_arc = Arc::new(Mutex::new(Vec::new()));
        let conn_arc = Arc::new(AtomicUsize::new(0));
        let req_arc = Arc::new(AtomicUsize::new(0));
        let engine = FakeEngine {
            port,
            resolve_calls: Arc::clone(&resolve_arc),
            ranges: Arc::clone(&range_arc),
            connections: Arc::clone(&conn_arc),
            requests: Arc::clone(&req_arc),
        };

        let body = audio_body();
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { break };
                let body = body.clone();
                let resolve_calls = Arc::clone(&resolve_arc);
                let ranges = Arc::clone(&range_arc);
                let requests = Arc::clone(&req_arc);
                let gate = gate.clone();
                conn_arc.fetch_add(1, Ordering::Relaxed);
                thread::spawn(move || {
                    // Keep-alive capable, so a host that *did* pool would show
                    // up as more requests than connections.
                    let mut reader = match stream.try_clone() {
                        Ok(dup) => BufReader::new(dup),
                        Err(_) => return,
                    };
                    let mut stream = stream;
                    loop {
                        requests.fetch_add(1, Ordering::Relaxed);
                        match serve_engine(
                            &mut stream,
                            &mut reader,
                            mode,
                            &body,
                            port,
                            &resolve_calls,
                            &ranges,
                            gate.clone(),
                        ) {
                            Ok(true) => continue,
                            // EOF before a request line: the peer hung up, so
                            // that last increment counted a request that was
                            // never made.
                            Ok(false) | Err(_) => {
                                requests.fetch_sub(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                });
            }
        });
        engine
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn file_url(&self) -> String {
        format!("http://127.0.0.1:{}/file.ogg", self.port)
    }

    fn resolve_calls(&self) -> usize {
        self.resolve_calls.load(Ordering::Relaxed)
    }

    fn ranges(&self) -> Vec<String> {
        self.ranges.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// (connections accepted, requests served). Reuse shows up as requests > connections.
    fn reuse(&self) -> (usize, usize) {
        (
            self.connections.load(Ordering::Relaxed),
            self.requests.load(Ordering::Relaxed),
        )
    }
}

impl Drop for FakeEngine {
    fn drop(&mut self) {
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// Serve one request. `Ok(true)` means the connection may carry another.
#[allow(clippy::too_many_arguments)]
fn serve_engine(
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    mode: EngineMode,
    body: &[u8],
    port: u16,
    resolve_calls: &AtomicUsize,
    ranges: &Mutex<Vec<String>>,
    gate: Option<Arc<Gate>>,
) -> std::io::Result<bool> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(false);
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

    if request_line.contains("/engine-resolve") {
        resolve_calls.fetch_add(1, Ordering::Relaxed);
        let url = format!("http://127.0.0.1:{port}/file.ogg");
        let (status, payload): (u16, String) = match mode {
            EngineMode::Broken => (500, r#"{"error":"engine exploded"}"#.into()),
            EngineMode::NonOgg => (
                200,
                format!(
                    r#"{{"uri":"{TRACK}","format":"AAC_128","key_hex":"{}","url":"{url}"}}"#,
                    hex(&KEY)
                ),
            ),
            EngineMode::ShortKey => (
                200,
                format!(
                    r#"{{"uri":"{TRACK}","format":"OGG_VORBIS_320","key_hex":"abc","url":"{url}"}}"#
                ),
            ),
            EngineMode::BadUrl => (
                200,
                format!(
                    r#"{{"uri":"{TRACK}","format":"OGG_VORBIS_320","key_hex":"{}","url":"file:///etc/passwd"}}"#,
                    hex(&KEY)
                ),
            ),
            EngineMode::ExpiresImmediately => (
                200,
                format!(
                    r#"{{"uri":"{TRACK}","format":"OGG_VORBIS_320","key_hex":"{}","url":"{url}","expires_in":0}}"#,
                    hex(&KEY)
                ),
            ),
            EngineMode::Happy | EngineMode::DeadUrl => (
                200,
                format!(
                    r#"{{"uri":"{TRACK}","format":"OGG_VORBIS_320","key_hex":"{}","url":"{url}"}}"#,
                    hex(&KEY)
                ),
            ),
        };
        stream.write_all(
            format!(
                "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{payload}",
                if status == 200 { "OK" } else { "Error" },
                payload.len()
            )
            .as_bytes(),
        )?;
        return Ok(true);
    }

    if !request_line.contains("/file.ogg") {
        stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )?;
        return Ok(true);
    }
    if let Some(range) = headers.get("range") {
        if let Ok(mut seen) = ranges.lock() {
            seen.push(range.clone());
        }
    }

    // An expired CDN link: resolvable, but gone by the time it is fetched.
    if mode == EngineMode::DeadUrl {
        stream.write_all(
            b"HTTP/1.1 410 Gone\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )?;
        return Ok(true);
    }

    // Hold here until enough requests overlap, when the test asks for it.
    if let Some(gate) = &gate {
        if !gate.arrive() {
            stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            )?;
            return Ok(true);
        }
    }

    let total = body.len() as u64;
    let requested = headers.get("range").and_then(|r| parse_range(r, total));

    if let Some((start, end)) = requested {
        if start >= total {
            stream.write_all(
                format!(
                    "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{total}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )?;
            return Ok(true);
        }
        let slice = &body[start as usize..=end as usize];
        stream.write_all(
            format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n",
                slice.len()
            )
            .as_bytes(),
        )?;
        stream.write_all(slice)?;
        return Ok(true);
    }

    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nConnection: keep-alive\r\n\r\n"
        )
        .as_bytes(),
    )?;
    stream.write_all(body)?;
    Ok(true)
}

/// `bytes=START-END`, clamped. `None` when absent or unparseable.
fn parse_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let spec = value.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = match end.trim() {
        "" => total.saturating_sub(1),
        v => {
            let end: u64 = v.parse().ok()?;
            end.min(total.saturating_sub(1))
        }
    };
    Some((start, end))
}

// ------------------------------------------------------------- the host itself

/// A running `earshot host` subprocess.
struct Host {
    child: Child,
    addr: String,
    stderr: Arc<Mutex<String>>,
}

impl Host {
    /// Start the host against `engine`. `token` of `None` exercises minting.
    fn start(engine: &FakeEngine, token: Option<&str>) -> Host {
        let mut command = Command::new(BIN);
        command
            .arg("host")
            // Port 0: the OS picks. Nothing in the test may assume a port, and
            // the host must advertise the one it actually got.
            .env("EARSHOT_HOST_BIND", "127.0.0.1:0")
            .env("EARSHOT_HOST_ENGINE", engine.base())
            .env_remove("EARSHOT_CONFIG")
            .env_remove("EARSHOT_ROOM_TOKEN")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(token) = token {
            command.env("EARSHOT_ROOM_TOKEN", token);
        }
        let mut child = command.spawn().expect("spawn earshot host");

        // Drain stderr for the child's whole life on its own thread: the same
        // obligation myx has toward earshot, and it keeps the startup banner
        // readable without ever blocking the host on a full pipe.
        let log = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&log);
        let err = child.stderr.take().expect("stderr");
        thread::spawn(move || {
            let mut reader = BufReader::new(err);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                if let Ok(mut buf) = sink.lock() {
                    buf.push_str(&line);
                }
                line.clear();
            }
        });

        // The readiness signal: one line on stdout naming the real address.
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        let read = out.read_line(&mut line).unwrap_or(0);
        assert!(
            read > 0,
            "host exited before announcing a port; stderr:\n{}",
            log.lock().map(|l| l.clone()).unwrap_or_default(),
        );
        // "earshot-host: listening <scheme>://<addr>" — one token, so the
        // obvious parse cannot go wrong.
        let announced = line
            .trim()
            .strip_prefix("earshot-host: listening ")
            .unwrap_or_else(|| panic!("unexpected readiness line {line:?}"));
        assert!(
            !announced.contains(' '),
            "the readiness line must be one token a consumer can use as-is: {line:?}"
        );
        let addr = announced
            .strip_prefix("http://")
            .unwrap_or_else(|| panic!("this host was not configured for TLS: {line:?}"))
            .to_string();
        assert!(
            !addr.ends_with(":0"),
            "the host advertised the configured port, not the bound one: {addr}"
        );

        Host {
            child,
            addr,
            stderr: log,
        }
    }

    fn log(&self) -> String {
        self.stderr.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Wait for a line of the banner to show up.
    ///
    /// stdout and stderr are separate pipes drained by separate threads, so the
    /// readiness line arriving says nothing about whether the stderr drain has
    /// been scheduled yet — even though the child wrote stderr first. Poll
    /// rather than assume.
    fn wait_log(&self, prefix: &str) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let log = self.log();
            if let Some(found) = log.lines().find_map(|l| l.strip_prefix(prefix)) {
                return found.trim().to_string();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {prefix:?} in the host log:\n{log}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// --------------------------------------------------------------- tiny HTTP client

struct Reply {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One request, `Connection: close`, read to EOF — no keep-alive bookkeeping.
fn request(addr: &str, raw_head: &str, body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("connect to host");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(raw_head.as_bytes()).expect("write head");
    if !body.is_empty() {
        stream.write_all(body).expect("write body");
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read reply");

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator in reply");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw[split + 4..].to_vec();

    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .expect("status line");
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Reply {
        status,
        headers,
        body,
    }
}

fn post_json(addr: &str, path: &str, body: &str) -> Reply {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    request(addr, &head, body.as_bytes())
}

fn get(addr: &str, path: &str, range: Option<&str>) -> Reply {
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(range) = range {
        head.push_str(&format!("Range: {range}\r\n"));
    }
    head.push_str("\r\n");
    request(addr, &head, b"")
}

/// Pull a string field out of a small JSON reply without a parser.
fn field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ------------------------------------------------------------------ the guest

struct Run {
    stdout: Vec<u8>,
    stderr: String,
    code: i32,
}

/// Drive a real `earshot` guest against the running host.
fn guest(host: &Host, token: &str, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("EARSHOT_ROOM_HOST", &host.addr)
        .env("EARSHOT_ROOM_TOKEN", token)
        // The host is on loopback, which the guest's SSRF guard refuses by
        // default — named explicitly rather than opening every private range.
        .env("EARSHOT_ROOM_ALLOW_NETWORKS", "127.0.0.0/8")
        .env_remove("EARSHOT_CONFIG")
        .env_remove("EARSHOT_HTTP_WINDOW")
        .env_remove("EARSHOT_MAX_IDLE")
        .output()
        .expect("spawn earshot guest");
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// The same binary reading the fixture straight off disk — the reference.
fn from_disk(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env_remove("EARSHOT_CONFIG")
        .env_remove("EARSHOT_ROOM_HOST")
        .env_remove("EARSHOT_ROOM_TOKEN")
        .env_remove("EARSHOT_HTTP_WINDOW")
        .env_remove("EARSHOT_MAX_IDLE")
        .output()
        .expect("spawn earshot");
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

// ---------------------------------------------------------------------- tests

/// The whole M3 loop, and the load-bearing assertion: audio fetched through
/// engine → host → guest is byte-identical to the fixture on disk, at every
/// start offset.
#[test]
fn a_guest_plays_through_the_host_byte_for_byte() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));
    let path = fixture("vorbis_5s.ogg");

    for start_ms in ["0", "500", "1000", "2500", "4000", "4900"] {
        let via_host = guest(&host, TOKEN, &[TRACK, "--start-ms", start_ms]);
        let direct = from_disk(&[path.to_str().unwrap(), "--start-ms", start_ms]);

        assert_eq!(via_host.code, 0, "host @{start_ms}: {}", via_host.stderr);
        assert_eq!(direct.code, 0, "disk @{start_ms}: {}", direct.stderr);
        assert!(
            via_host.stdout == direct.stdout,
            "@{start_ms}: through-the-host output differs from disk ({} vs {} bytes)",
            via_host.stdout.len(),
            direct.stdout.len(),
        );
        assert!(!via_host.stdout.is_empty(), "@{start_ms}: empty output");
        assert!(
            via_host.stdout.starts_with(b"OggS"),
            "@{start_ms}: not an Ogg stream"
        );
    }

    // The engine was actually consulted, and the CDN was read with ranges —
    // the host proxied them rather than buffering the file.
    assert!(engine.resolve_calls() >= 1, "the engine was never asked");
    let ranges = engine.ranges();
    assert!(!ranges.is_empty(), "the host sent no Range to the engine");
    assert!(
        ranges.iter().all(|r| r.starts_with("bytes=")),
        "unexpected Range syntax reaching the engine: {ranges:?}",
    );
}

/// `/resolve` is the protocol surface the room client depends on: it must echo
/// the track, carry the key, and hand back URLs pointing at the *host*.
#[test]
fn resolve_returns_the_room_reply_pointing_at_the_host() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));

    let reply = post_json(
        &host.addr,
        "/resolve",
        &format!(r#"{{"token":"{TOKEN}","uri":"{TRACK}"}}"#),
    );
    assert_eq!(reply.status, 200, "{}", reply.text());
    let body = reply.text();

    assert_eq!(field(&body, "track").as_deref(), Some(TRACK));
    assert_eq!(field(&body, "format").as_deref(), Some("OGG_VORBIS_320"));
    assert_eq!(field(&body, "key_hex").as_deref(), Some(hex(&KEY).as_str()));

    // The engine's address must never reach a guest.
    let url = body
        .split("\"urls\":[\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("a CDN url");
    assert!(
        url.starts_with(&format!("http://{}/audio/", host.addr)),
        "CDN url does not point at the host: {url}"
    );
    assert!(
        !body.contains(&format!("127.0.0.1:{}", engine.port)),
        "the reply leaks the engine address: {body}"
    );
}

/// The token is the guest's credential on every endpoint that costs something.
#[test]
fn a_bad_token_is_refused_on_join_and_resolve() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));

    let joined = post_json(&host.addr, "/join", &format!(r#"{{"token":"{TOKEN}"}}"#));
    assert_eq!(
        joined.status,
        200,
        "a good token should join: {}",
        joined.text()
    );

    for (path, body) in [
        ("/join", r#"{"token":"nope"}"#.to_string()),
        ("/resolve", format!(r#"{{"token":"nope","uri":"{TRACK}"}}"#)),
        ("/join", r#"{}"#.to_string()),
        ("/resolve", format!(r#"{{"uri":"{TRACK}"}}"#)),
    ] {
        let reply = post_json(&host.addr, path, &body);
        assert_eq!(
            reply.status,
            403,
            "{path} with {body} should be 403, got {}: {}",
            reply.status,
            reply.text()
        );
    }

    // And a rejected token must never have reached the engine.
    assert_eq!(
        engine.resolve_calls(),
        0,
        "the host consulted the engine for an unauthenticated resolve"
    );
}

/// A CDN link is only good with a correct, unexpired signature. The expired
/// case uses a *genuinely valid* HMAC, so it proves expiry is checked rather
/// than the signature merely failing.
#[test]
fn the_cdn_refuses_forged_and_expired_signatures() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));
    let id = audio_id(&engine.file_url());

    let future = now_secs() + 600;
    let good = format!("/audio/{id}?exp={future}&sig={}", sign(TOKEN, &id, future));
    let ok = get(&host.addr, &good, Some("bytes=0-15"));
    assert_eq!(
        ok.status,
        206,
        "a valid signature should serve: {}",
        ok.text()
    );

    let past = now_secs() - 1;
    let cases = [
        (
            format!("/audio/{id}?exp={past}&sig={}", sign(TOKEN, &id, past)),
            "an expired but correctly signed url",
        ),
        (
            format!(
                "/audio/{id}?exp={future}&sig={}",
                sign("wrong-token", &id, future)
            ),
            "a signature from the wrong secret",
        ),
        (
            format!("/audio/{id}?exp={future}&sig=deadbeef"),
            "a junk signature",
        ),
        (format!("/audio/{id}?exp={future}"), "no signature at all"),
        (format!("/audio/{id}"), "no query at all"),
        (
            // Same expiry, different id: the signature must cover the id.
            format!(
                "/audio/{}?exp={future}&sig={}",
                audio_id("http://127.0.0.1:1/other.ogg"),
                sign(TOKEN, &id, future)
            ),
            "a signature lifted from another file",
        ),
    ];
    for (path, what) in cases {
        let reply = get(&host.addr, &path, None);
        assert_eq!(
            reply.status,
            403,
            "{what} should be 403, got {}: {}",
            reply.status,
            reply.text()
        );
        assert!(
            reply.body.len() < 512,
            "{what} returned a body that looks like audio ({} bytes)",
            reply.body.len()
        );
    }
}

/// The CDN is a pass-through, not a buffer: a guest's `Range` must reach the
/// engine and the `206`/`Content-Range` must come back intact.
#[test]
fn ranges_pass_through_to_the_engine() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));
    let id = audio_id(&engine.file_url());
    let exp = now_secs() + 600;
    let path = format!("/audio/{id}?exp={exp}&sig={}", sign(TOKEN, &id, exp));
    let body = audio_body();

    for (start, end) in [
        (0u64, 15u64),
        (100, 199),
        (PREG_END as u64, PREG_END as u64 + 3),
    ] {
        let reply = get(&host.addr, &path, Some(&format!("bytes={start}-{end}")));
        assert_eq!(reply.status, 206, "bytes={start}-{end}: {}", reply.text());
        assert_eq!(
            reply.body,
            &body[start as usize..=end as usize],
            "bytes={start}-{end}: wrong slice"
        );
        assert_eq!(
            reply.headers.get("content-range").map(String::as_str),
            Some(format!("bytes {start}-{end}/{}", body.len()).as_str()),
            "bytes={start}-{end}: content-range not forwarded"
        );
    }

    // Proof it really went to the engine rather than a cache in the host.
    let seen = engine.ranges();
    assert!(
        seen.contains(&"bytes=100-199".to_string()),
        "the guest range never reached the engine: {seen:?}"
    );
}

/// A host with no configured token mints one and prints it exactly once, so a
/// room can be started without committing a credential anywhere.
#[test]
fn a_host_without_a_token_mints_one_and_announces_it() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, None);

    let minted = host.wait_log("earshot-host: token (generated): ");
    assert_eq!(minted.len(), 32, "minted token is not 32 hex: {minted:?}");
    assert!(
        minted.bytes().all(|b| b.is_ascii_hexdigit()),
        "minted token is not hex: {minted:?}"
    );

    // It is the real credential: it works, and the usual one does not.
    let good = post_json(&host.addr, "/join", &format!(r#"{{"token":"{minted}"}}"#));
    assert_eq!(
        good.status,
        200,
        "the minted token was refused: {}",
        good.text()
    );
    let bad = post_json(&host.addr, "/join", &format!(r#"{{"token":"{TOKEN}"}}"#));
    assert_eq!(bad.status, 403, "a stale token was accepted");

    // And a guest can actually play with it.
    let run = guest(&host, &minted, &[TRACK]);
    assert_eq!(run.code, 0, "guest with the minted token: {}", run.stderr);
    assert!(run.stdout.starts_with(b"OggS"));
}

/// A hostile or broken engine is the same threat as a hostile room host: the
/// host validates its answer instead of forwarding it to guests.
#[test]
fn a_bad_engine_answer_is_refused_rather_than_forwarded() {
    for (mode, expect) in [
        (EngineMode::Broken, "engine said HTTP 500"),
        (EngineMode::NonOgg, "Ogg only"),
        (EngineMode::ShortKey, "key_hex"),
        (EngineMode::BadUrl, "not http"),
    ] {
        let engine = FakeEngine::start(mode);
        let host = Host::start(&engine, Some(TOKEN));
        let reply = post_json(
            &host.addr,
            "/resolve",
            &format!(r#"{{"token":"{TOKEN}","uri":"{TRACK}"}}"#),
        );
        assert_eq!(reply.status, 400, "expected a refusal: {}", reply.text());
        let text = reply.text();
        assert!(
            text.contains(expect),
            "the error should explain {expect:?}, got {text}"
        );
        // Nothing playable escaped.
        assert!(
            !text.contains("urls"),
            "a bad engine answer produced URLs: {text}"
        );
    }
}

/// A guest hitting a host whose engine is broken gets a real exit code, not a
/// hang or a truncated stream.
#[test]
fn a_broken_engine_surfaces_to_the_guest() {
    let engine = FakeEngine::start(EngineMode::Broken);
    let host = Host::start(&engine, Some(TOKEN));
    let run = guest(&host, TOKEN, &[TRACK]);
    assert_ne!(run.code, 0, "a broken engine must not look like success");
    assert!(run.stdout.is_empty(), "audio was written despite no track");
}

/// A room exists to serve *many* listeners from one session, so the host must
/// overlap requests rather than queue them behind each other's engine fetch.
///
/// Asserted structurally, not by timing: the engine refuses to answer until
/// `CONCURRENT` requests are inside it simultaneously. A host that handled
/// requests one at a time could never put a second one there, so this cannot
/// pass by being merely fast.
#[test]
fn many_listeners_are_served_concurrently() {
    const CONCURRENT: usize = 4;

    let engine = FakeEngine::start_concurrent(CONCURRENT);
    let host = Host::start(&engine, Some(TOKEN));
    let id = audio_id(&engine.file_url());
    let exp = now_secs() + 600;
    let path = format!("/audio/{id}?exp={exp}&sig={}", sign(TOKEN, &id, exp));

    let mut listeners = Vec::with_capacity(CONCURRENT);
    for n in 0..CONCURRENT {
        let addr = host.addr.clone();
        let path = path.clone();
        listeners.push(thread::spawn(move || {
            let start = n * 32;
            let reply = get(&addr, &path, Some(&format!("bytes={start}-{}", start + 31)));
            (n, reply.status, reply.body)
        }));
    }

    let body = audio_body();
    for listener in listeners {
        let (n, status, bytes) = listener.join().expect("listener thread");
        assert_eq!(
            status, 206,
            "listener {n} got {status}: the host served requests one at a time, \
             so the engine's concurrency gate never opened"
        );
        let start = n * 32;
        assert_eq!(bytes, &body[start..start + 32], "listener {n}: wrong slice");
    }
}

/// The host must not reuse a connection to the engine.
///
/// Regression test for a bug found by driving the real binaries: with the
/// agent's idle pool on, an engine that closes per response leaves the pool
/// full of dead sockets, and the close is only discovered when the *next*
/// request goes out on one. That surfaced at the guest as `exit 5 — not a
/// Spotify Ogg file`, i.e. as a key problem that did not exist, at roughly
/// 7 failures per 40 concurrent plays. Retrying does not converge, because
/// when every pooled connection is stale each attempt draws another corpse.
///
/// Asserted on the engine side, where reuse is observable: this fake speaks
/// keep-alive, so a pooling host would serve more requests than it opened
/// connections.
#[test]
fn the_host_does_not_reuse_engine_connections() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));
    let id = audio_id(&engine.file_url());
    let exp = now_secs() + 600;
    let path = format!("/audio/{id}?exp={exp}&sig={}", sign(TOKEN, &id, exp));

    // Enough sequential fetches that a pool would certainly be exercised.
    for n in 0..8 {
        let start = n * 16;
        let reply = get(
            &host.addr,
            &path,
            Some(&format!("bytes={start}-{}", start + 15)),
        );
        assert_eq!(reply.status, 206, "fetch {n}: {}", reply.text());
    }

    let (connections, requests) = engine.reuse();
    assert!(requests >= 8, "the engine saw only {requests} requests");
    assert_eq!(
        connections, requests,
        "the host reused engine connections ({requests} requests over {connections} \
         connections); an engine that closes one would strand the next listener"
    );
}

/// One engine call per *track*, not per listener.
///
/// This is the point of a room: many people share one session. Without it, a
/// hundred listeners starting the same song is a hundred round trips into the
/// single component holding a Spotify account.
#[test]
fn many_listeners_cost_the_engine_one_resolve() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));

    for _ in 0..10 {
        let reply = post_json(
            &host.addr,
            "/resolve",
            &format!(r#"{{"token":"{TOKEN}","uri":"{TRACK}"}}"#),
        );
        assert_eq!(reply.status, 200, "{}", reply.text());
        assert!(reply.text().contains("key_hex"), "{}", reply.text());
    }
    assert_eq!(
        engine.resolve_calls(),
        1,
        "10 listeners on one track cost {} engine calls",
        engine.resolve_calls()
    );

    // A different track is a different entry, not a stale hit.
    let other = post_json(
        &host.addr,
        "/resolve",
        &format!(r#"{{"token":"{TOKEN}","uri":"spotify:track:other"}}"#),
    );
    assert_eq!(other.status, 200, "{}", other.text());
    assert_eq!(engine.resolve_calls(), 2, "a second track must be resolved");
    assert_eq!(
        field(&other.text(), "track").as_deref(),
        Some("spotify:track:other"),
        "the cache served the wrong track"
    );
}

/// An engine that states a short lifetime is obeyed over the default.
#[test]
fn an_engine_stated_lifetime_overrides_the_default() {
    let engine = FakeEngine::start(EngineMode::ExpiresImmediately);
    let host = Host::start(&engine, Some(TOKEN));

    for _ in 0..3 {
        let reply = post_json(
            &host.addr,
            "/resolve",
            &format!(r#"{{"token":"{TOKEN}","uri":"{TRACK}"}}"#),
        );
        assert_eq!(reply.status, 200, "{}", reply.text());
    }
    assert_eq!(
        engine.resolve_calls(),
        3,
        "`expires_in: 0` must forbid reuse, but the host cached anyway"
    );
}

/// A cached URL the engine has since disowned must not be sticky.
///
/// No TTL predicts expiry perfectly, so the proxy watching for the engine's
/// refusal is what makes caching safe rather than merely bounded: the entry is
/// dropped and the next listener resolves afresh.
#[test]
fn a_url_the_engine_disowns_is_dropped_from_the_cache() {
    let engine = FakeEngine::start(EngineMode::DeadUrl);
    let host = Host::start(&engine, Some(TOKEN));

    let first = post_json(
        &host.addr,
        "/resolve",
        &format!(r#"{{"token":"{TOKEN}","uri":"{TRACK}"}}"#),
    );
    assert_eq!(first.status, 200, "{}", first.text());
    assert_eq!(engine.resolve_calls(), 1);

    // Cached: a second resolve costs nothing.
    post_json(
        &host.addr,
        "/resolve",
        &format!(r#"{{"token":"{TOKEN}","uri":"{TRACK}"}}"#),
    );
    assert_eq!(
        engine.resolve_calls(),
        1,
        "the entry should still be cached"
    );

    // Now fetch it. The engine says 410, which must evict the entry.
    let id = audio_id(&engine.file_url());
    let exp = now_secs() + 600;
    let fetched = get(
        &host.addr,
        &format!("/audio/{id}?exp={exp}&sig={}", sign(TOKEN, &id, exp)),
        Some("bytes=0-15"),
    );
    assert_eq!(
        fetched.status, 410,
        "the engine's refusal should pass through"
    );

    post_json(
        &host.addr,
        "/resolve",
        &format!(r#"{{"token":"{TOKEN}","uri":"{TRACK}"}}"#),
    );
    assert_eq!(
        engine.resolve_calls(),
        2,
        "a disowned URL stayed cached; listeners would inherit a dead link \
         until the TTL happened to lapse"
    );
}

/// Unknown paths and methods are answered, not left to hang.
#[test]
fn unknown_routes_are_answered() {
    let engine = FakeEngine::start(EngineMode::Happy);
    let host = Host::start(&engine, Some(TOKEN));

    assert_eq!(get(&host.addr, "/", None).status, 404);
    assert_eq!(get(&host.addr, "/nope", None).status, 404);
    assert_eq!(post_json(&host.addr, "/nope", "{}").status, 404);
    // `/audio/` with no id is a miss, not a panic.
    assert_eq!(get(&host.addr, "/audio/", None).status, 403);
}

/// The host refuses to start rather than mint URLs nothing can fetch.
#[test]
fn a_misconfigured_host_refuses_to_start() {
    let engine = FakeEngine::start(EngineMode::Happy);

    let cases: [(&str, &str, &str); 4] = [
        ("", &engine.base(), "host_bind"),
        ("127.0.0.1:0", "", "host_engine"),
        ("127.0.0.1:0", "127.0.0.1:9090", "http(s)"),
        // A wildcard bind cannot produce a fetchable CDN URL.
        ("0.0.0.0:0", &engine.base(), "wildcard"),
    ];
    for (bind, engine_base, expect) in cases {
        let out = Command::new(BIN)
            .arg("host")
            .env("EARSHOT_HOST_BIND", bind)
            .env("EARSHOT_HOST_ENGINE", engine_base)
            .env_remove("EARSHOT_CONFIG")
            .output()
            .expect("spawn");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "bind={bind:?} engine={engine_base:?} should be a usage error: {stderr}"
        );
        assert!(
            stderr.contains(expect),
            "the error should name {expect:?}: {stderr}"
        );
    }
}

/// `host` takes no positional arguments, and says so.
#[test]
fn host_rejects_stray_arguments() {
    let out = Command::new(BIN)
        .args(["host", "extra"])
        .env_remove("EARSHOT_CONFIG")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("host takes no arguments"),
        "unexpected error: {stderr}"
    );
}
