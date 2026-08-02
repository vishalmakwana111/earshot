//! The room's control channel over TLS, end to end.
//!
//! Without this, `/join` and `/resolve` carry the shared token and the audio key
//! in the clear. The Spotify *session* never crosses that wire — it stays in the
//! engine — so this is not about the account, but a room reachable on anything
//! wider than a trusted LAN should not be handing out decryption keys to anyone
//! listening.
//!
//! A room has no publicly-signed name, so the guest is pointed at the
//! certificate to trust (`room_ca_cert`) rather than given a switch that turns
//! verification off. The load-bearing pair of tests is therefore:
//!
//! * with the CA, a guest plays and the bytes match the fixture exactly;
//! * without it, the guest **fails** — proving the trust is real and not a
//!   decoration over an unverified channel.
//!
//! Certificates are minted here at test time. A checked-in fixture cert would
//! be a test that starts failing on a date nobody chose.

#![cfg(feature = "tls")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use ctr::Ctr128BE;
use earshot::source::SPOTIFY_AUDIO_IV;

const BIN: &str = env!("CARGO_BIN_EXE_earshot");
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

fn audio_body() -> Vec<u8> {
    let audio = std::fs::read(fixture("vorbis_5s.ogg")).expect("fixture");
    let mut plain = Vec::with_capacity(PREG_END + audio.len());
    plain.extend(std::iter::repeat_n(0xe5, PREG_END));
    plain.extend_from_slice(&audio);
    let mut cipher = Ctr128BE::<Aes128>::new_from_slices(&KEY, &SPOTIFY_AUDIO_IV).expect("cipher");
    cipher.apply_keystream(&mut plain);
    plain
}

// ------------------------------------------------------------------ certificates

/// A freshly minted CA and a leaf for `127.0.0.1`, written to `dir`.
///
/// A real CA signing a real leaf, rather than one self-signed certificate doing
/// both jobs: that is the shape an operator actually deploys, and it is the one
/// where "trust this CA" means something separate from "serve this cert".
struct Certs {
    ca_pem: PathBuf,
    cert_pem: PathBuf,
    key_pem: PathBuf,
    /// A second, unrelated CA — trusting it must not admit the room.
    other_ca_pem: PathBuf,
}

fn mint_certs(dir: &Path) -> Certs {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };

    let make_ca = |name: &str| {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, name.to_string());
        let key = KeyPair::generate().expect("ca key");
        let cert = params.self_signed(&key).expect("ca cert");
        (cert, key)
    };

    let (ca, ca_key) = make_ca("earshot test room CA");
    let (other_ca, _) = make_ca("an unrelated CA");

    // The leaf, valid for the loopback address the host binds.
    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = vec![
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::DnsName("localhost".try_into().expect("dns name")),
    ];
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "earshot room".to_string());
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf cert");

    let certs = Certs {
        ca_pem: dir.join("ca.pem"),
        cert_pem: dir.join("room.crt"),
        key_pem: dir.join("room.key"),
        other_ca_pem: dir.join("other-ca.pem"),
    };
    std::fs::write(&certs.ca_pem, ca.pem()).expect("write ca");
    std::fs::write(&certs.other_ca_pem, other_ca.pem()).expect("write other ca");
    // The chain the host serves: leaf then issuer.
    std::fs::write(&certs.cert_pem, format!("{}{}", leaf.pem(), ca.pem())).expect("write cert");
    std::fs::write(&certs.key_pem, leaf_key.serialize_pem()).expect("write key");
    certs
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("earshot-tls-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

// ---------------------------------------------------------------- fake engine

/// Plain-HTTP engine. The host↔engine hop is deliberately not the subject here:
/// it is the guest↔host channel that carries the token and the key.
struct FakeEngine {
    port: u16,
}

impl FakeEngine {
    fn start() -> FakeEngine {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind engine");
        let port = listener.local_addr().expect("addr").port();
        let body = audio_body();
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { break };
                let body = body.clone();
                thread::spawn(move || {
                    let _ = serve_engine(stream, &body, port);
                });
            }
        });
        FakeEngine { port }
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

fn serve_engine(mut stream: TcpStream, body: &[u8], port: u16) -> std::io::Result<()> {
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

    if request_line.contains("/engine-resolve") {
        let payload = format!(
            r#"{{"uri":"{TRACK}","format":"OGG_VORBIS_320","key_hex":"{}","url":"http://127.0.0.1:{port}/file.ogg"}}"#,
            hex(&KEY)
        );
        return stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
            .as_bytes(),
        );
    }

    let total = body.len() as u64;
    let requested = headers
        .get("range")
        .and_then(|r| r.trim().strip_prefix("bytes=").map(str::to_string))
        .and_then(|spec| {
            let (a, b) = spec.split_once('-')?;
            let start: u64 = a.trim().parse().ok()?;
            let end = match b.trim() {
                "" => total.saturating_sub(1),
                v => v.parse::<u64>().ok()?.min(total.saturating_sub(1)),
            };
            Some((start, end))
        });

    if let Some((start, end)) = requested {
        if start >= total {
            return stream.write_all(
                format!("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{total}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
        }
        let slice = &body[start as usize..=end as usize];
        stream.write_all(
            format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{total}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                slice.len()
            )
            .as_bytes(),
        )?;
        return stream.write_all(slice);
    }

    stream.write_all(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )?;
    stream.write_all(body)
}

// ------------------------------------------------------------------- the host

struct Host {
    child: Child,
    addr: String,
    scheme: String,
    stderr: Arc<Mutex<String>>,
}

impl Host {
    fn start(engine: &FakeEngine, certs: Option<&Certs>) -> Host {
        let mut command = Command::new(BIN);
        command
            .arg("host")
            .env("EARSHOT_HOST_BIND", "127.0.0.1:0")
            .env("EARSHOT_HOST_ENGINE", engine.base())
            .env("EARSHOT_ROOM_TOKEN", TOKEN)
            .env_remove("EARSHOT_CONFIG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(certs) = certs {
            command
                .env("EARSHOT_HOST_TLS_CERT", &certs.cert_pem)
                .env("EARSHOT_HOST_TLS_KEY", &certs.key_pem);
        }
        let mut child = command.spawn().expect("spawn earshot host");

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

        let mut out = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        let read = out.read_line(&mut line).unwrap_or(0);
        assert!(
            read > 0,
            "host exited before announcing a port; stderr:\n{}",
            log.lock().map(|l| l.clone()).unwrap_or_default(),
        );
        // "earshot-host: listening <scheme>://<addr>"
        let announced = line
            .trim()
            .strip_prefix("earshot-host: listening ")
            .unwrap_or_else(|| panic!("unexpected readiness line {line:?}"));
        assert!(
            !announced.contains(' '),
            "the readiness line must be one usable token: {line:?}"
        );
        let (scheme, addr) = announced
            .split_once("://")
            .unwrap_or_else(|| panic!("readiness line is not a URL: {line:?}"));

        Host {
            child,
            addr: addr.to_string(),
            scheme: scheme.to_string(),
            stderr: log,
        }
    }

    fn log(&self) -> String {
        self.stderr.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Run {
    stdout: Vec<u8>,
    stderr: String,
    code: i32,
}

/// A guest over TLS. `ca` of `None` means "trust only the public roots", which
/// is what must fail against a privately-signed room.
fn guest(host: &Host, ca: Option<&Path>, args: &[&str]) -> Run {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env("EARSHOT_ROOM_HOST", &host.addr)
        .env("EARSHOT_ROOM_TOKEN", TOKEN)
        .env("EARSHOT_ROOM_TLS", "true")
        .env("EARSHOT_ROOM_ALLOW_NETWORKS", "127.0.0.0/8")
        .env_remove("EARSHOT_CONFIG")
        .env_remove("EARSHOT_ROOM_CA_CERT");
    if let Some(ca) = ca {
        command.env("EARSHOT_ROOM_CA_CERT", ca);
    }
    let out = command.output().expect("spawn guest");
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn from_disk(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env_remove("EARSHOT_CONFIG")
        .env_remove("EARSHOT_ROOM_HOST")
        .env_remove("EARSHOT_ROOM_TOKEN")
        .output()
        .expect("spawn earshot");
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

// ---------------------------------------------------------------------- tests

/// The whole loop over TLS: same byte-identical property, encrypted channel.
#[test]
fn a_guest_plays_over_tls_byte_for_byte() {
    let dir = scratch("plays");
    let certs = mint_certs(&dir);
    let engine = FakeEngine::start();
    let host = Host::start(&engine, Some(&certs));

    assert_eq!(
        host.scheme,
        "https",
        "the host did not serve TLS: {}",
        host.log()
    );
    let path = fixture("vorbis_5s.ogg");

    for start_ms in ["0", "1000", "4000"] {
        let over_tls = guest(&host, Some(&certs.ca_pem), &[TRACK, "--start-ms", start_ms]);
        let direct = from_disk(&[path.to_str().unwrap(), "--start-ms", start_ms]);
        assert_eq!(over_tls.code, 0, "tls @{start_ms}: {}", over_tls.stderr);
        assert_eq!(
            over_tls.stdout, direct.stdout,
            "@{start_ms}: audio over TLS differs from disk"
        );
        assert!(over_tls.stdout.starts_with(b"OggS"));
    }
}

/// The trust is real: without the CA the guest must refuse, or `room_ca_cert`
/// would be decoration over a channel nobody is actually verifying.
#[test]
fn a_guest_without_the_ca_refuses_to_connect() {
    let dir = scratch("noca");
    let certs = mint_certs(&dir);
    let engine = FakeEngine::start();
    let host = Host::start(&engine, Some(&certs));

    let bare = guest(&host, None, &[TRACK]);
    assert_ne!(bare.code, 0, "an untrusted room certificate was accepted");
    assert!(
        bare.stdout.is_empty(),
        "audio was written over an unverified channel"
    );

    // And trusting *some other* CA is not enough either.
    let wrong = guest(&host, Some(&certs.other_ca_pem), &[TRACK]);
    assert_ne!(wrong.code, 0, "an unrelated CA admitted the room");
    assert!(wrong.stdout.is_empty());
}

/// Half a TLS identity is a mistake, not a quiet downgrade to plain HTTP.
#[test]
fn half_a_tls_identity_refuses_to_start() {
    let dir = scratch("half");
    let certs = mint_certs(&dir);
    let engine = FakeEngine::start();

    for (cert, key, expect) in [
        (Some(&certs.cert_pem), None, "host_tls_key"),
        (None, Some(&certs.key_pem), "host_tls_cert"),
    ] {
        let mut command = Command::new(BIN);
        command
            .arg("host")
            .env("EARSHOT_HOST_BIND", "127.0.0.1:0")
            .env("EARSHOT_HOST_ENGINE", engine.base())
            .env_remove("EARSHOT_CONFIG");
        if let Some(cert) = cert {
            command.env("EARSHOT_HOST_TLS_CERT", cert);
        }
        if let Some(key) = key {
            command.env("EARSHOT_HOST_TLS_KEY", key);
        }
        let out = command.output().expect("spawn");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "should be a usage error: {stderr}"
        );
        assert!(stderr.contains(expect), "should name {expect}: {stderr}");
        assert!(
            stderr.contains("refusing"),
            "should say it refused rather than downgraded: {stderr}"
        );
    }
}

/// A plain-HTTP room says so, so nobody assumes a room is private when it isn't.
#[test]
fn a_plaintext_room_warns() {
    let engine = FakeEngine::start();
    let host = Host::start(&engine, None);
    assert_eq!(host.scheme, "http");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let log = host.log();
        if log.contains("readable on the network") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a plaintext room did not warn:\n{log}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// An unreadable `room_ca_cert` narrows nothing rather than crashing — and the
/// room is still refused, because the public roots do not vouch for it.
#[test]
fn a_broken_ca_file_falls_back_to_public_roots() {
    let dir = scratch("brokenca");
    let certs = mint_certs(&dir);
    let engine = FakeEngine::start();
    let host = Host::start(&engine, Some(&certs));

    let junk = dir.join("not-a-cert.pem");
    std::fs::write(&junk, b"this is not a certificate").expect("write junk");

    let run = guest(&host, Some(&junk), &[TRACK]);
    assert_ne!(run.code, 0, "a junk CA file must not admit the room");
    assert!(
        run.stderr.contains("room_ca_cert"),
        "the guest should say the CA file was unusable: {}",
        run.stderr
    );
}
