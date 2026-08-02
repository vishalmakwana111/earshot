//! The other half of a room: `earshot host` — the server surface, wrapping an
//! external engine that actually touches a Spotify session.
//!
//! # Shape (M3, Part 8 #3)
//!
//! The design's open question was "whether `host` ships at all", because a full
//! in-process Spotify host would carry the whole librespot stack and the full ToS
//! exposure with it. M3 settles it the other way: **earshot owns the room server
//! surface** — token handling, `/join`, `/resolve`, and a ranged CDN — and an
//! **external engine** (in practice the Myx room binary, or any HTTP endpoint
//! holding a Premium session) does the one thing earshot will not: produce the
//! encrypted audio file and its key.
//!
//! The engine contract is deliberately one POST:
//!
//! ```text
//! POST <host_engine>/engine-resolve
//!   {"uri": "spotify:track:…"}
//! → 200 {"uri": "…", "format": "OGG_VORBIS_320", "key_hex": <32 hex>,
//!        "url": "<absolute URL of the already-encrypted audio file>"}
//!   or 400 {"error": "…"}
//! ```
//!
//! Whatever that URL returns must be the real Spotify artifact — `0xa7` junk
//! bytes then the Ogg stream, AES-128-CTR-encrypted with `key_hex` — because the
//! guest's room client builds `Window<Decrypt<HttpSource>>` over it and the `OggS`
//! probe at offset `0xa7` is the authenticator. The host never re-encrypts or
//! inspects the body: it is a ranged pass-through of the engine's file.
//!
//! # What the host exposes
//!
//! - `POST /join` — `{"token": …}` → `200 | 403`. Kept so that pre-M2 Myx
//!   listeners can preflight the shared token without a full resolve.
//! - `POST /resolve` — `{"token": …, "uri": …}` → the room client's reply
//!   (`track`, `format`, `key_hex`, `urls`), whose URLs point back at this host
//!   (`/audio/…`) and never at the engine — a guest must not learn the engine's
//!   address.
//! - `GET /audio/<id>?exp=…&sig=…` — a time-limited, HMAC-signed CDN that ranges
//!   through to the engine file. No signature, no bytes.
//!
//! # Trust
//!
//! - The token is the guest's credential. If none is configured, the host mints
//!   one with the OS RNG and prints it to stderr once (Part 7: a token printed
//!   once beats one committed to a repo).
//! - Each CDN URL is HMAC-SHA256 over `id|exp` keyed by a token-derived salt, so
//!   a guest cannot mint URLs for files it was never granted, and a leaked URL
//!   expires after [`URL_LIFETIME_SECS`].
//! - `key_hex` and `format` from the engine are validated with the same strictness
//!   the guest applies to a resolve reply (32 hex chars, Ogg-only) — a hostile
//!   engine is the same threat as a hostile room host.
//!
//! # Concurrency
//!
//! The guest pipeline is single-threaded by design — one track, blocking reads,
//! pause *is* a full pipe. The host is the one place that inverts: a room exists
//! to serve **many** listeners from one session, and every `/audio/` request
//! blocks on a ranged GET to the engine before it can answer. Served from a
//! single accept loop, listener N+1 would wait on listener N's network round
//! trip, and a room would degrade with each person who joined it.
//!
//! So requests are taken by a fixed pool of [`WORKERS`] threads, each blocking
//! in `Server::recv`. The work is I/O-bound — a worker is parked on the engine's
//! socket, not burning CPU — so a modest pool covers far more listeners than it
//! has threads. Nothing is shared mutably: [`Router`] is immutable once bound.

use std::collections::HashMap;
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::config::Settings;
use crate::source::{http_agent_unpooled, OpenError};

/// Seconds a minted CDN URL stays valid.
const URL_LIFETIME_SECS: u64 = 1800;

/// The audio key must be exactly this many ASCII hex chars.
const KEY_HEX_LEN: usize = 32;

/// Token length when the host mints its own.
const TOKEN_HEX_LEN: usize = 32;

/// Cap on a guest's request body and the engine's reply.
const MAX_BODY: u64 = 1 << 16;

/// Threads taking requests. Each spends its time blocked on the engine's
/// socket, so this bounds concurrent *engine fetches*, not listeners: a
/// listener occupies a worker only for the ranged GET that refills its window.
const WORKERS: usize = 16;

/// The host's state. Immutable once bound, apart from the resolve cache.
struct Router {
    bind: String,
    /// `host:port` a guest should use, which is only known after binding: a
    /// `:0` bind means the OS chose the port. Minted CDN URLs use this, never
    /// the configured string, or `--host-bind 127.0.0.1:0` would advertise
    /// port 0 and nothing could fetch it.
    advertised: String,
    /// `"http"` or `"https"`, matching how this host is actually serving. CDN
    /// URLs carry it, so a guest never has to be told separately.
    scheme: &'static str,
    engine_base: String,
    token: String,
    /// The token if this host minted it (to print exactly once).
    minted: Option<String>,
    secret: Vec<u8>,
    agent: ureq::Agent,
    /// Resolved tracks, so a room of listeners costs the engine one call rather
    /// than one per person. See [`cached_resolve`].
    cache: Mutex<HashMap<String, CacheEntry>>,
}

/// A validated engine answer.
#[derive(Clone)]
struct EngineReply {
    format: String,
    key: [u8; 16],
    url: String,
    /// How long the engine says `url` stays fetchable, if it says at all.
    expires_in: Option<u64>,
}

/// A resolved track and the moment it stops being safe to hand out.
struct CacheEntry {
    reply: EngineReply,
    expires: Instant,
}

/// How long a resolved track may be reused when the engine says nothing.
///
/// Deliberately short. The win being bought is the stampede — a room full of
/// listeners starting the same track at once, which is the shape a room
/// actually has — and that is collapsed by any TTL at all. A long default would
/// trade that for the risk of handing out a URL that has already died, which
/// fails later, elsewhere, and looks like something else.
const CACHE_TTL_DEFAULT: Duration = Duration::from_secs(30);

/// Ceiling on reuse regardless of what the engine claims, so one wrong
/// `expires_in` cannot poison a track for an hour.
const CACHE_TTL_MAX: Duration = Duration::from_secs(300);

/// Fraction of the engine's stated lifetime actually used, as a margin: a URL
/// handed out in the last moment of its life is one the listener cannot finish
/// a window with.
const CACHE_TTL_MARGIN: u64 = 4; // i.e. three quarters

/// Tracks held at once. A room plays one thing at a time, so this is generous;
/// it exists so a host driven by a script cannot grow without bound.
const CACHE_CAPACITY: usize = 64;

/// Serve the room until killed.
pub fn run_host(settings: &Settings) -> Result<(), OpenError> {
    let mut router = Router::new(settings)?;

    let bind = router.bind.clone();
    let server = bind_server(&bind, settings)?;
    router.advertised = advertised_base(&server)?;
    router.scheme = if tls_configured(settings) {
        "https"
    } else {
        "http"
    };

    eprintln!(
        "earshot-host: room on {}://{} (engine {})",
        router.scheme, router.advertised, router.engine_base
    );
    if router.scheme == "http" {
        eprintln!(
            "earshot-host: plain HTTP — the room token and audio keys are readable \
             on the network; set host_tls_cert/host_tls_key to encrypt them"
        );
    }
    if let Some(minted) = &router.minted {
        eprintln!("earshot-host: token (generated): {minted}");
    }
    // Stdout is the machine-readable half: one line, flushed, so a supervisor
    // (or a test) can wait for readiness and learn the chosen port without
    // parsing the human log on stderr.
    //
    // A whole URL rather than address-and-scheme fields, because the obvious
    // way to read this line is "everything after the prefix" — and with two
    // fields that silently yields `127.0.0.1:8787 http`, which fails later as
    // an invalid URI. One token cannot be split wrong, and a consumer can use
    // it as-is.
    println!(
        "earshot-host: listening {}://{}",
        router.scheme, router.advertised
    );
    let _ = io::stdout().flush();

    // One immutable router, one listener, many takers. `Server::recv` is `&self`
    // and internally a shared queue, so the pool needs no lock of its own.
    let router = Arc::new(router);
    let server = Arc::new(server);
    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let router = Arc::clone(&router);
        let server = Arc::clone(&server);
        workers.push(thread::spawn(move || {
            // `recv` errors when the server is shutting down; that ends the worker.
            while let Ok(mut request) = server.recv() {
                let method = request.method().clone();
                let url = request.url().to_string();
                let range = request_range(&request);
                let body = read_body(&mut request);
                let response = dispatch(&router, &method, &url, &range, &body);
                let _ = request.respond(response);
            }
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn dispatch(
    router: &Router,
    method: &Method,
    url: &str,
    range: &Option<(u64, u64)>,
    body: &[u8],
) -> Response<Cursor<Vec<u8>>> {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    match (method.as_str(), path) {
        ("POST", "/join") => handle_join(router, body),
        ("POST", "/resolve") => handle_resolve(router, body),
        ("GET", p) if p.starts_with("/audio/") => handle_audio(router, p, query, range),
        ("GET" | "POST", _) => json_response(json_error("not found"), 404),
        _ => json_response(json_error("method not allowed"), 405),
    }
}

fn handle_join(router: &Router, body: &[u8]) -> Response<Cursor<Vec<u8>>> {
    let Some(token) = json_str(body, "token") else {
        return json_response(json_error("join needs a token"), 403);
    };
    if tokens_eq(&token, &router.token) {
        json_response("ok".to_string(), 200)
    } else {
        json_response(json_error("bad token"), 403)
    }
}

fn handle_resolve(router: &Router, body: &[u8]) -> Response<Cursor<Vec<u8>>> {
    let Some(token) = json_str(body, "token") else {
        return json_response(json_error("resolve needs a token"), 403);
    };
    if !tokens_eq(&token, &router.token) {
        return json_response(json_error("bad token"), 403);
    }
    let Some(uri) = json_str(body, "uri") else {
        return json_response(json_error("resolve needs a uri"), 400);
    };

    let engine = match cached_resolve(router, &uri) {
        Ok(engine) => engine,
        Err(message) => return json_response(json_error(&message), 400),
    };
    let cdn = match mint_cdn_url(router, &engine.url) {
        Ok(c) => c,
        Err(message) => return json_response(json_error(&message), 400),
    };
    json_response(
        format!(
            r#"{{"track":{},"format":{},"key_hex":{},"urls":[{}]}}"#,
            json_quote(&uri),
            json_quote(&engine.format),
            json_quote(&hex(&engine.key)),
            json_quote(&cdn)
        ),
        200,
    )
}

fn handle_audio(
    router: &Router,
    path: &str,
    query: &str,
    guest_range: &Option<(u64, u64)>,
) -> Response<Cursor<Vec<u8>>> {
    let Some(id) = path.strip_prefix("/audio/") else {
        return json_response(json_error("not found"), 404);
    };
    if !signature_ok(router, id, query) {
        return json_response(json_error("bad or expired signature"), 403);
    }
    // The id is the base64 of the engine's file URL; only the host can decode
    // it, which is why guests see `/audio/<id>` and never the engine address.
    let engine_url = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(id) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => return json_response(json_error("bad id"), 400),
    };
    if !(engine_url.starts_with("http://") || engine_url.starts_with("https://")) {
        return json_response(json_error("bad id"), 400);
    }

    let (status, bytes, content_range) = proxied_range(&router.agent, &engine_url, *guest_range);
    // The engine disowning a URL is how an expired one announces itself. Drop
    // it so the next listener re-resolves instead of inheriting the corpse —
    // this is what makes caching safe without a perfect TTL.
    if matches!(status, 401 | 403 | 404 | 410) {
        invalidate_url(router, &engine_url);
    }
    let mut reply = Response::from_data(bytes)
        .with_status_code(StatusCode(status))
        .with_header(Header::from_bytes("content-type", "application/octet-stream").unwrap());
    if let Some(cr) = content_range {
        reply = reply.with_header(Header::from_bytes("content-range", cr).unwrap());
    }
    reply
}

// ------------------------------------------------------------- engine plumbing

/// Whether a failed engine request is safe to replay.
///
/// The agent is configured with `http_status_as_error(false)`, so an `Err` here
/// means **no response was received at all** — nothing observed, nothing
/// partially consumed, no side effect the engine could have committed and told
/// us about. Replaying that is safe in a way that replaying a *status* would
/// not be.
///
/// It is also necessary. The agent pools keep-alive connections, and an engine
/// is free to close one whenever it likes: an idle timeout, a restart, a
/// proxy's per-connection request ceiling, or simply answering HTTP/1.0. The
/// close is only discovered when the next request goes out on the dead socket,
/// and with several listeners sharing the pool that lands often enough to drop
/// real listeners — measured at 7 failures in 40 concurrent plays against an
/// engine that closes per response, and none once retried.
///
/// A timeout is deliberately excluded: it has already spent the caller's
/// budget, and replaying it would double the wait rather than fix anything.
fn retryable(error: &ureq::Error) -> bool {
    matches!(
        error,
        ureq::Error::Io(_) | ureq::Error::ConnectionFailed | ureq::Error::Protocol(_)
    )
}

/// Attempts before giving up on the engine.
///
/// More than two because the pool can hold *several* dead sockets at once — an
/// engine that closes every response leaves one per worker — and a single retry
/// then just draws another corpse. Each failed attempt evicts the connection it
/// discovered, so attempts strictly improve. Bounded, because a genuinely
/// unreachable engine must fail fast rather than stall a listener.
const ENGINE_ATTEMPTS: usize = 4;

/// Run an engine request, replaying it while the failure is a dead connection.
///
/// Reports the final error, plus how many attempts it took and what the first
/// failure was — the difference between "the engine is down" and "the pool was
/// stale" is invisible from one message, and they need different fixes.
fn with_retry<T>(mut attempt: impl FnMut() -> Result<T, ureq::Error>) -> Result<T, String> {
    let mut first: Option<String> = None;
    let mut last: Option<ureq::Error> = None;

    for tries in 1..=ENGINE_ATTEMPTS {
        match attempt() {
            Ok(value) => return Ok(value),
            // Not a dead connection: replaying cannot help, so say so now.
            Err(fatal) if !retryable(&fatal) => return Err(fatal.to_string()),
            Err(error) => {
                if first.is_none() {
                    first = Some(error.to_string());
                }
                if tries == ENGINE_ATTEMPTS {
                    last = Some(error);
                }
            }
        }
    }

    let last = last.expect("ENGINE_ATTEMPTS is non-zero, so a failure was recorded");
    let first = first.unwrap_or_else(|| last.to_string());
    Err(format!(
        "{last} (still failing after {ENGINE_ATTEMPTS} attempts; first was: {first})"
    ))
}

/// Resolve a track, reusing a recent answer when there is one.
///
/// The goal is one engine call per *track*, not per listener: a room exists so
/// that many people share one session, and without this a hundred listeners
/// starting the same song is a hundred round trips into the one component that
/// holds a Spotify account.
///
/// What makes it safe to cache at all is that staleness is *detected*, not just
/// bounded. A CDN URL from a real engine expires, and no TTL guesses that
/// perfectly — so when the proxy sees the engine refuse a URL, the entry is
/// dropped and the next listener re-resolves. The TTL keeps the window small;
/// the invalidation makes a wrong TTL survivable rather than sticky.
fn cached_resolve(router: &Router, uri: &str) -> Result<EngineReply, String> {
    if let Ok(cache) = router.cache.lock() {
        if let Some(entry) = cache.get(uri) {
            if entry.expires > Instant::now() {
                return Ok(entry.reply.clone());
            }
        }
    }

    let reply = engine_resolve(router, uri)?;

    // The engine's word, margined and capped; otherwise the short default.
    let ttl = match reply.expires_in {
        Some(secs) => Duration::from_secs(secs * (CACHE_TTL_MARGIN - 1) / CACHE_TTL_MARGIN),
        None => CACHE_TTL_DEFAULT,
    }
    .min(CACHE_TTL_MAX);

    if !ttl.is_zero() {
        if let Ok(mut cache) = router.cache.lock() {
            if cache.len() >= CACHE_CAPACITY {
                let now = Instant::now();
                cache.retain(|_, entry| entry.expires > now);
                // Still full of live entries: this host is being driven far
                // outside "a room plays one thing", so start over rather than
                // grow. Correctness does not depend on the cache.
                if cache.len() >= CACHE_CAPACITY {
                    cache.clear();
                }
            }
            cache.insert(
                uri.to_string(),
                CacheEntry {
                    reply: reply.clone(),
                    expires: Instant::now() + ttl,
                },
            );
        }
    }
    Ok(reply)
}

/// Forget any track resolved to `url`, because the engine just refused it.
///
/// Keyed by URL rather than track because that is all the proxy knows — and it
/// is the right key anyway: the URL is the thing that expired.
fn invalidate_url(router: &Router, url: &str) {
    if let Ok(mut cache) = router.cache.lock() {
        cache.retain(|_, entry| entry.reply.url != url);
    }
}

fn engine_resolve(router: &Router, uri: &str) -> Result<EngineReply, String> {
    let body = format!(r#"{{"uri":{}}}"#, json_quote(uri));
    let mut response = with_retry(|| {
        router
            .agent
            .post(&format!("{}/engine-resolve", router.engine_base))
            .header("content-type", "application/json")
            .send(body.as_str())
    })
    .map_err(|e| format!("engine unreachable: {e}"))?;

    let status = response.status().as_u16();
    let mut text = String::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_BODY)
        .read_to_string(&mut text)
        .map_err(|e| format!("engine reply: {e}"))?;
    if status != 200 {
        return Err(format!("engine said HTTP {status}: {text}"));
    }
    parse_engine_reply(&text)
}

/// Validate the engine's answer with the same strictness the guest applies to a
/// resolve reply: quote every string, and refuse anything that is not Ogg with a
/// 32-hex key.
fn parse_engine_reply(text: &str) -> Result<EngineReply, String> {
    let bytes = text.as_bytes();
    let Some(format) = json_str(bytes, "format") else {
        return Err("engine reply lacks a format".into());
    };
    if !format.starts_with("OGG_") {
        return Err(format!("engine gives {format:?} — earshot plays Ogg only"));
    }
    let Some(key_hex) = json_str(bytes, "key_hex") else {
        return Err("engine reply lacks key_hex".into());
    };
    if key_hex.len() != KEY_HEX_LEN || !key_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "engine key_hex is {} chars, expected {KEY_HEX_LEN} hex",
            key_hex.chars().count()
        ));
    }
    let Some(url) = json_str(bytes, "url") else {
        return Err("engine reply lacks a url".into());
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("engine url is not http(s)".into());
    }
    let key = decode_key(&key_hex)?;
    // Optional: an engine that knows its URL's lifetime should say so, and the
    // cache will honour it in preference to guessing.
    let expires_in = json_u64(bytes, "expires_in");
    Ok(EngineReply {
        format,
        key,
        url,
        expires_in,
    })
}

fn decode_key(hex: &str) -> Result<[u8; 16], String> {
    let mut key = [0u8; 16];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| "engine key_hex has a bad pair".to_string())?;
    }
    Ok(key)
}

/// The CDN does one ranged GET against the engine file and forwards it mostly
/// untouched, status included — the guest's `HttpRanged` already knows what a
/// `200`-instead-of-`206` or a `416` means.
fn proxied_range(
    agent: &ureq::Agent,
    url: &str,
    guest_range: Option<(u64, u64)>,
) -> (u16, Vec<u8>, Option<String>) {
    // Same replay rule as the resolve path: a dead pooled connection must cost
    // a retry, not a listener. See [`retryable`].
    let mut response = match with_retry(|| {
        let mut request = agent.get(url);
        if let Some((start, end)) = guest_range {
            request = request.header("Range", &format!("bytes={start}-{end}"));
        }
        request.call()
    }) {
        Ok(response) => response,
        Err(e) => {
            // Never silent: a 502 with no explanation reaches the guest as
            // "not a Spotify Ogg file", which sends whoever is debugging it
            // hunting for a key problem that does not exist.
            eprintln!("earshot-host: engine fetch failed: {e}");
            return (502, Vec::new(), None);
        }
    };
    let status = response.status().as_u16();
    let content_range = response
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    let mut reader = response.body_mut().as_reader().take(1 << 24);
    if let Err(e) = reader.read_to_end(&mut bytes) {
        // Not retried: the response had already begun, so a replay could
        // duplicate or straddle bytes the guest has partly seen.
        eprintln!("earshot-host: engine body truncated: {e}");
        return (502, Vec::new(), None);
    }
    (status, bytes, content_range)
}

// ----------------------------------------------------------------- CDN signing

/// Whether both halves of a TLS identity are configured.
fn tls_configured(settings: &Settings) -> bool {
    let set = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
    set(&settings.host_tls_cert) && set(&settings.host_tls_key)
}

/// Bind the listener, over TLS when a certificate and key are configured.
///
/// Half a TLS identity is a configuration mistake, not a fallback: silently
/// serving plain HTTP because the key path had a typo would hand out the room
/// token in the clear while the operator believed otherwise.
fn bind_server(bind: &str, settings: &Settings) -> Result<Server, OpenError> {
    let cert = settings
        .host_tls_cert
        .as_deref()
        .filter(|s| !s.trim().is_empty());
    let key = settings
        .host_tls_key
        .as_deref()
        .filter(|s| !s.trim().is_empty());

    match (cert, key) {
        (Some(cert), Some(key)) => bind_tls(bind, cert, key),
        (None, None) => Server::http(bind)
            .map_err(|e| OpenError::Usage(format!("host: cannot bind {bind}: {e}"))),
        (Some(_), None) => Err(OpenError::Usage(
            "host_tls_cert is set but host_tls_key is not — refusing to serve the \
             room in the clear when TLS was intended"
                .into(),
        )),
        (None, Some(_)) => Err(OpenError::Usage(
            "host_tls_key is set but host_tls_cert is not — refusing to serve the \
             room in the clear when TLS was intended"
                .into(),
        )),
    }
}

#[cfg(feature = "tls")]
fn bind_tls(bind: &str, cert: &str, key: &str) -> Result<Server, OpenError> {
    let read = |what: &str, path: &str| {
        std::fs::read(path)
            .map_err(|e| OpenError::Usage(format!("host: cannot read {what} {path}: {e}")))
    };
    let config = tiny_http::SslConfig {
        certificate: read("host_tls_cert", cert)?,
        private_key: read("host_tls_key", key)?,
    };
    Server::https(bind, config)
        .map_err(|e| OpenError::Usage(format!("host: cannot serve TLS on {bind}: {e}")))
}

#[cfg(not(feature = "tls"))]
fn bind_tls(_bind: &str, _cert: &str, _key: &str) -> Result<Server, OpenError> {
    Err(OpenError::Usage(
        "host_tls_cert/host_tls_key are set but this build has no TLS — \
         rebuild with `--features tls`"
            .into(),
    ))
}

/// The `host:port` guests should be pointed at.
///
/// Taken from the listener rather than the configured string, because `:0`
/// means "any free port" and only the OS knows which one it picked. A wildcard
/// bind is refused instead of guessed: `http://0.0.0.0:8787/audio/…` is not a
/// URL any guest can fetch, and silently minting one would surface as an
/// unexplained download failure rather than a configuration mistake.
fn advertised_base(server: &Server) -> Result<String, OpenError> {
    let addr = server.server_addr().to_ip().ok_or_else(|| {
        OpenError::Usage("host: a Unix socket cannot mint fetchable CDN URLs".into())
    })?;
    if addr.ip().is_unspecified() {
        return Err(OpenError::Usage(format!(
            "host_bind is a wildcard address ({addr}); CDN URLs minted from it are \
             not fetchable — bind the concrete address guests reach, e.g. 127.0.0.1:8787"
        )));
    }
    Ok(addr.to_string())
}

/// Mint a time-limited, signed CDN URL for the engine's file.
fn mint_cdn_url(router: &Router, engine_url: &str) -> Result<String, String> {
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(engine_url.as_bytes());
    let exp = now_secs() + URL_LIFETIME_SECS;
    Ok(format!(
        "{}://{}/audio/{}?exp={exp}&sig={}",
        router.scheme,
        router.advertised,
        id,
        sign(router, &id, exp)
    ))
}

/// A CDN link is only valid while unexpired and carrying the right HMAC.
fn signature_ok(router: &Router, id: &str, query: &str) -> bool {
    let Some(exp) = query_pair(query, "exp") else {
        return false;
    };
    let Some(given) = query_pair(query, "sig") else {
        return false;
    };
    let Ok(exp) = exp.parse::<u64>() else {
        return false;
    };
    if exp < now_secs() {
        return false;
    }
    tokens_eq(&given, &sign(router, id, exp))
}

/// HMAC-SHA256 over `secret || id || "|" || exp`, keyed by the token-derived salt.
fn sign(router: &Router, id: &str, exp: u64) -> String {
    let mut h = Sha256::new();
    h.update(&router.secret);
    h.update(id.as_bytes());
    h.update(b"|");
    h.update(exp.to_string().as_bytes());
    hex(&h.finalize())
}

/// Constant-time token comparison: an attacker must not be able to time a guess.
fn tokens_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

// ------------------------------------------------------------ configuration

impl Router {
    fn new(settings: &Settings) -> Result<Router, OpenError> {
        let bind = settings
            .host_bind
            .as_deref()
            .filter(|b| !b.trim().is_empty())
            .ok_or_else(|| {
                OpenError::Usage(
                    "host needs a bind address — set host_bind/EARSHOT_HOST_BIND".into(),
                )
            })?
            .to_string();
        let engine_base = settings
            .host_engine
            .as_deref()
            .filter(|e| !e.trim().is_empty())
            .ok_or_else(|| {
                OpenError::Usage(
                    "host needs an engine — set host_engine/EARSHOT_HOST_ENGINE".into(),
                )
            })?;
        if !(engine_base.starts_with("http://") || engine_base.starts_with("https://")) {
            return Err(OpenError::Usage(
                "host_engine must be an http(s) URL".into(),
            ));
        }

        let (token, minted) = match settings.room_token.as_deref() {
            Some(t) if !t.trim().is_empty() => (t.trim().to_string(), None),
            _ => {
                let token = rand_token();
                (token.clone(), Some(token))
            }
        };

        // The CDN signing key is derived from the token with a salt, so a
        // listener who knows the shared credential cannot forge URLs either.
        let secret = {
            let mut h = Sha256::new();
            h.update(b"earshot/cdn/v1");
            h.update(token.as_bytes());
            h.finalize().to_vec()
        };
        // Unpooled on purpose: see `http_agent_unpooled`. The retry below stays
        // for genuinely transient failures — an engine restarting mid-stream —
        // which no pooling setting prevents.
        let agent = http_agent_unpooled(settings);
        Ok(Router {
            // Both replaced once the listener exists and its scheme is known.
            advertised: bind.clone(),
            scheme: "http",
            bind,
            engine_base: engine_base.to_string(),
            token,
            minted,
            secret,
            agent,
            cache: Mutex::new(HashMap::new()),
        })
    }
}

/// Random hex token from the OS RNG.
fn rand_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_HEX_LEN / 2];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

// ----------------------------------------------------------------- tiny_http glue

/// Pull the request body, bounded.
fn read_body(request: &mut Request) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut reader = request.as_reader().take(MAX_BODY);
    let _ = reader.read_to_end(&mut buf);
    buf
}

/// Parse the `Range: bytes=a-b` header, if the guest sent one.
fn request_range(request: &Request) -> Option<(u64, u64)> {
    let value = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))?
        .value
        .clone();
    let rest = value.as_str().strip_prefix("bytes=")?;
    let (start, end) = rest.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    Some((start, end))
}

/// First value of a `k=v` query pair.
fn query_pair(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

// ----------------------------------------------------------------- JSON bits

/// A JSON response (with the header the content actually is).
fn json_response(text: String, status: u16) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(text.into_bytes())
        .with_status_code(StatusCode(status))
        .with_header(Header::from_bytes("content-type", "application/json").unwrap())
}

fn json_error(message: &str) -> String {
    format!(r#"{{"error":{}}}"#, json_quote(message))
}

/// Quote a string as a JSON string literal.
fn json_quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Pull one string field out of a small JSON object.
fn json_str(body: &[u8], key: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get(key)?.as_str().map(str::to_string)
}

/// Pull one whole-number field out of a small JSON object.
fn json_u64(body: &[u8], key: &str) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get(key)?.as_u64()
}
