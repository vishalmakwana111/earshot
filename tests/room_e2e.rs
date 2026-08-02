//! `room://` end to end: the guest half of the room protocol against a fake
//! `127.0.0.1` host that mints the key and CDN URLs exactly as the real one does.
//!
//! The fake is two roles on one listener:
//!
//! * `POST /resolve` — the protocol. It validates the token, echoes `uri`, and
//!   answers with `format`/`key_hex`/`urls`, the URLs pointing back at itself.
//! * `GET /file.ogg` — the signed CDN behind those URLs: correct `206` ranged
//!   responses for the *encrypted* body.
//!
//! The body models the Spotify artifact (`DESIGN` A10): `0xa7` junk bytes (the
//! normalisation packet) followed by the real Ogg fixture, the whole thing
//! AES-128-CTR-encrypted with the fixed audio IV. The room open path decrypts,
//! strips `0xa7`, and splices — so the load-bearing assertion is that the audio
//! is **byte-identical** to the same fixture read from disk, at every offset.
//!
//! The room client refuses loopback CDN URLs unless a network covering them is
//! named, which is exactly what an e2e against a local fake needs; these tests
//! pass `127.0.0.0/8` through `EARSHOT_ROOM_ALLOW_NETWORKS`.

#![cfg(feature = "room")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use ctr::Ctr128BE;
use earshot::source::SPOTIFY_AUDIO_IV;

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

/// The encrypted, normalisation-padded body the CDN will serve.
fn audio_body() -> Vec<u8> {
    let audio = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let mut plain = Vec::with_capacity(PREG_END + audio.len());
    plain.extend(std::iter::repeat_n(0xe5, PREG_END));
    plain.extend_from_slice(&audio);
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(&KEY, &SPOTIFY_AUDIO_IV).expect("cipher");
    cipher.apply_keystream(&mut plain);
    plain
}

/// How the fake room should misbehave, to exercise the guest's failure paths.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RoomMode {
    Happy,
    BadToken,
    MissingTrack,
    WrongFormat,
    WrongKey,
}

struct FakeRoom {
    port: u16,
    resolve_calls: Arc<AtomicUsize>,
    cdn_ranges: Arc<Mutex<Vec<String>>>,
}

impl FakeRoom {
    fn start(mode: RoomMode) -> FakeRoom {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let resolve_arc = Arc::new(AtomicUsize::new(0));
        let range_arc = Arc::new(Mutex::new(Vec::new()));
        let room = FakeRoom {
            port,
            resolve_calls: Arc::clone(&resolve_arc),
            cdn_ranges: Arc::clone(&range_arc),
        };

        let body = audio_body();
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { break };
                let body = body.clone();
                let resolve_calls = Arc::clone(&resolve_arc);
                let cdn_ranges = Arc::clone(&range_arc);
                thread::spawn(move || {
                    let _ = serve(stream, mode, &body, port, &resolve_calls, &cdn_ranges);
                });
            }
        });
        room
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn resolve_calls(&self) -> usize {
        self.resolve_calls.load(Ordering::Relaxed)
    }

    fn ranges(&self) -> Vec<String> {
        self.cdn_ranges
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default()
    }
}

impl Drop for FakeRoom {
    fn drop(&mut self) {
        // Wake the accept loop so it notices we are done.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(
    mut stream: TcpStream,
    mode: RoomMode,
    body: &[u8],
    port: u16,
    resolve_calls: &AtomicUsize,
    cdn_ranges: &Mutex<Vec<String>>,
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

    if request_line.contains("/resolve") {
        resolve_calls.fetch_add(1, Ordering::Relaxed);
        let (status, body): (u16, String) = match mode {
            RoomMode::BadToken => (403, r#"{"error":"bad token"}"#.into()),
            RoomMode::MissingTrack => (404, r#"{"error":"no such track"}"#.into()),
            RoomMode::WrongFormat => (
                200,
                format!(
                    r#"{{"track":"{TRACK}","format":"AAC_128","key_hex":"{}","urls":["http://127.0.0.1:{port}/file.ogg"]}}"#,
                    hex(&KEY)
                ),
            ),
            RoomMode::WrongKey => (
                200,
                format!(
                    r#"{{"track":"{TRACK}","format":"OGG_VORBIS_320","key_hex":"{}","urls":["http://127.0.0.1:{port}/file.ogg"]}}"#,
                    hex(&[0x00; 16])
                ),
            ),
            RoomMode::Happy => (
                200,
                format!(
                    r#"{{"track":"{TRACK}","format":"OGG_VORBIS_320","key_hex":"{}","urls":["http://127.0.0.1:{port}/file.ogg"]}}"#,
                    hex(&KEY)
                ),
            ),
        };
        return stream.write_all(
            format!(
                "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                if status == 200 { "OK" } else { "Error" },
                body.len()
            )
            .as_bytes(),
        );
    }

    // The CDN: only our one signed path exists.
    if !request_line.contains("/file.ogg") {
        return stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }
    if let Some(range) = headers.get("range") {
        if let Ok(mut seen) = cdn_ranges.lock() {
            seen.push(range.clone());
        }
    }

    let total = body.len() as u64;
    let requested = headers.get("range").and_then(|r| parse_range(r, total));

    if let Some((start, end)) = requested {
        if start >= total {
            return stream.write_all(
                format!(
                    "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{total}\r\nContent-Length: 0\r\n\r\n"
                )
                .as_bytes(),
            );
        }
        let slice = &body[start as usize..=end as usize];
        stream.write_all(
            format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nETag: \"file\"\r\n\r\n",
                slice.len()
            )
            .as_bytes(),
        )?;
        return stream.write_all(slice);
    }

    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nETag: \"file\"\r\n\r\n"
        )
        .as_bytes(),
    )?;
    stream.write_all(body)
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

struct Run {
    stdout: Vec<u8>,
    stderr: String,
    code: i32,
}

/// Drive earshot against the fake room, room configured via env vars so a
/// developer's config file stays out of the way.
fn earshot(room: &FakeRoom, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("EARSHOT_ROOM_HOST", room.host())
        .env("EARSHOT_ROOM_TOKEN", TOKEN)
        .env("EARSHOT_ROOM_ALLOW_NETWORKS", "127.0.0.0/8")
        .env_remove("EARSHOT_CONFIG")
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

/// Run without any room environment: proves the credential contract.
fn earshot_bare(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env_remove("EARSHOT_ROOM_HOST")
        .env_remove("EARSHOT_ROOM_TOKEN")
        .env_remove("EARSHOT_ROOM_ALLOW_NETWORKS")
        .output()
        .expect("spawn earshot");
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

// ---------------------------------------------------------------------- tests

/// The load-bearing test: room-decrypted output must be byte-identical to the
/// fixture read from disk at every offset (the CDN body is the fixture behind
/// 0xa7 junk bytes, encrypted).
#[test]
fn room_output_matches_the_fixture_byte_for_byte() {
    let room = FakeRoom::start(RoomMode::Happy);
    let path = fixture("vorbis_5s.ogg");

    for start_ms in ["0", "500", "1000", "2500", "4000", "4900"] {
        let via_room = earshot(&room, &[TRACK, "--start-ms", start_ms]);
        let from_disk = earshot(&room, &[path.to_str().unwrap(), "--start-ms", start_ms]);

        assert_eq!(via_room.code, 0, "room @{start_ms}: {}", via_room.stderr);
        assert_eq!(from_disk.code, 0, "file @{start_ms}: {}", from_disk.stderr);
        assert!(
            via_room.stdout == from_disk.stdout,
            "@{start_ms}: room output differs from disk output ({} vs {} bytes)",
            via_room.stdout.len(),
            from_disk.stdout.len(),
        );
        assert!(!via_room.stdout.is_empty(), "@{start_ms}: empty output");
        assert!(
            via_room.stdout.starts_with(b"OggS"),
            "@{start_ms}: not an Ogg stream"
        );
    }
}

/// The protocol actually ran: the resolve endpoint saw traffic, and the CDN was
/// read with ranges (which is the whole point of the offset-addressed reader).
#[test]
fn the_room_host_is_reached_and_the_cdn_is_read_with_ranges() {
    let room = FakeRoom::start(RoomMode::Happy);
    let run = earshot(&room, &[TRACK]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        room.resolve_calls() >= 1,
        "the /resolve endpoint was never hit"
    );
    let ranges = room.ranges();
    assert!(!ranges.is_empty(), "no Range headers were sent to the CDN");
    assert!(
        ranges.iter().all(|r| r.starts_with("bytes=")),
        "unexpected Range syntax: {ranges:?}",
    );
}

/// The normalisation packet is real: decrypting the served body must land `OggS`
/// exactly at offset 0xa7.
#[test]
fn the_decrypted_body_starts_ogg_at_0xa7() {
    let mut body = audio_body();
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(&KEY, &SPOTIFY_AUDIO_IV).expect("cipher");
    cipher.apply_keystream(&mut body);
    assert_eq!(&body[PREG_END..PREG_END + 4], b"OggS");
}

/// A wrong key must fail loudly — the OggS guard at 0xa7 is what catches it —
/// never stream plausible-looking garbage.
#[test]
fn a_wrong_key_is_refused_rather_than_played() {
    let room = FakeRoom::start(RoomMode::WrongKey);
    let run = earshot(&room, &[TRACK]);
    assert_eq!(
        run.code, 5,
        "expected malformed (5); got {}: {}",
        run.code, run.stderr
    );
    assert!(
        run.stderr.contains("OggS") || run.stderr.contains("Ogg"),
        "the wrong-key error should name Ogg: {}",
        run.stderr,
    );
}

/// A rejected token is auth: exit 4, never a play attempt or a malformed claim.
#[test]
fn a_bad_token_is_auth() {
    let room = FakeRoom::start(RoomMode::BadToken);
    let out = Command::new(BIN)
        .args([TRACK])
        .env("EARSHOT_ROOM_HOST", room.host())
        .env("EARSHOT_ROOM_TOKEN", "not-the-token")
        .env("EARSHOT_ROOM_ALLOW_NETWORKS", "127.0.0.0/8")
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(4),
        "expected auth (4); got {}: {}",
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// A missing track is transient (exit 2): the track may exist moments later, so
/// a consumer should retry rather than skip it forever.
#[test]
fn a_missing_track_is_transient() {
    let room = FakeRoom::start(RoomMode::MissingTrack);
    let run = earshot(&room, &["spotify:track:mystery"]);
    assert_eq!(
        run.code, 2,
        "expected transient (2); got {}: {}",
        run.code, run.stderr
    );
}

/// A non-Ogg format advertised by the room is a dead end worth skipping (exit 3):
/// retrying will never make an AAC track a Vorbis one.
#[test]
fn a_non_ogg_format_is_permanently_unavailable() {
    let room = FakeRoom::start(RoomMode::WrongFormat);
    let run = earshot(&room, &[TRACK]);
    assert_eq!(
        run.code, 3,
        "expected unavailable (3); got {}: {}",
        run.code, run.stderr
    );
}

/// Without a configured room, a room track is a usage error — the credential
/// interface must not be skippable.
#[test]
fn a_room_track_requires_credentials() {
    let run = earshot_bare(&[TRACK]);
    assert_eq!(run.code, 1, "expected usage (1): {}", run.stderr);
    assert!(
        run.stderr.contains("room_host") || run.stderr.contains("token"),
        "the error should name the missing setting: {}",
        run.stderr,
    );
}
