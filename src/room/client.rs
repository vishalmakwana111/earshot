//! The guest's side of a listening room: resolve a track through the host.
//!
//! This is an HTTP client for a **protocol**, not a conversation partner — the
//! host is remote and possibly hostile, so every byte it sends is untrusted
//! input, validated at the trust boundary. Treatment:
//!
//! 1. **Strict schema.** [`ResolveReply`] uses `deny_unknown_fields`: the guest
//!    pins today's protocol, so a host that grows new fields stops loudly rather
//!    than having a guest silently ignore something security-relevant.
//! 2. **Bounded.** The reply body is capped ([`MAX_RESOLVE_BODY`]) and the URL
//!    list is capped ([`MAX_URLS`]), so a malicious host cannot make a guest
//!    allocate unbounded memory.
//! 3. **Validated values.** The key must be exactly 32 hex chars, the format
//!    must be Ogg, and every URL must be `http(s)://` with no userinfo.
//! 4. **SSRF-guarded.** A compromised room host must not turn every guest into
//!    an internal-network prober, so URLs are DNS-resolved and rejected unless
//!    every address is public (`DESIGN.md` Part 7), or inside a network the
//!    operator named in `room_allow_networks` — which is how a Tailscale room
//!    (`100.64.0.0/10`) or a LAN one is permitted without also unblocking the
//!    link-local range cloud metadata services answer on.
//!
//! The `join` handshake from the original Myx protocol is deliberately *not*
//! called: `/resolve` already authenticates with the token, so an extra request
//! per track would only buy a host-side counter nothing here depends on.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use serde::Deserialize;
use url::Url;

use crate::config::Cidr;
use crate::source::OpenError;

/// Cap on the resolve reply. 64 KiB is enormous for (urls × ~256 chars) and
/// keeps a chatty host's cost to the guest small.
const MAX_RESOLVE_BODY: u64 = 1 << 16;
/// Cap on the number of candidate download URLs a resolve may hand back.
const MAX_URLS: usize = 8;

/// The reply to `/resolve`, pinned to exactly this shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveReply {
    /// The host echoes the URI we asked for; a different string means the host
    /// is resolving *something else*, which must not play. Pinned here rather
    /// than ignored, because ignoring it would make the mismatch silent.
    track: String,
    format: String,
    key_hex: String,
    urls: Vec<String>,
}

/// A validated, playable track: the parts of the reply the source needs.
pub struct ResolvedTrack {
    pub format: String,
    pub key: [u8; 16],
    pub urls: Vec<String>,
}

/// One-shot guest path. Stateless: each resolve round-trips the host, which is
/// right for a tool that resolves once per invoked track (a player does its own
/// caching above this layer).
pub struct RoomClient {
    agent: ureq::Agent,
    host: String,
    token: String,
    /// Networks permitted on top of the public internet — empty by default.
    /// See `Settings::room_allow_networks`.
    allow: Vec<Cidr>,
    /// `"http"` or `"https"`, from `Settings::room_tls`. The control channel
    /// carries the token and the audio key, so this is the one that matters;
    /// CDN URLs arrive with their own scheme already on them.
    scheme: &'static str,
}

impl RoomClient {
    pub fn new(agent: ureq::Agent, host: String, token: String, allow: Vec<Cidr>) -> Self {
        RoomClient::with_scheme(agent, host, token, allow, false)
    }

    pub fn with_scheme(
        agent: ureq::Agent,
        host: String,
        token: String,
        allow: Vec<Cidr>,
        tls: bool,
    ) -> Self {
        RoomClient {
            agent,
            host,
            token,
            allow,
            scheme: if tls { "https" } else { "http" },
        }
    }

    /// Ask the host to resolve `uri` (e.g. `spotify:track:…`), validate the
    /// answer as documented at the top of this module, and hand back what the
    /// guest needs to build a source.
    pub fn resolve(&self, uri: &str) -> Result<ResolvedTrack, OpenError> {
        if uri.is_empty() {
            return Err(OpenError::Usage("empty track URI".into()));
        }

        let body = serde_json::json!({ "token": self.token, "uri": uri }).to_string();
        let mut response = self
            .agent
            .post(&format!("{}://{}/resolve", self.scheme, self.host))
            .header("content-type", "application/json")
            .send(body)
            .map_err(transport_error)?;

        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_RESOLVE_BODY)
            .read_to_string()
            .map_err(|e| OpenError::Malformed(format!("resolve reply: {e}")))?;

        if status != 200 {
            return Err(classify_status(status, &text, &self.host));
        }

        let reply: ResolveReply = serde_json::from_str(&text)
            .map_err(|e| OpenError::Malformed(format!("bad resolve reply: {e}")))?;
        if reply.track != uri {
            return Err(OpenError::Malformed(format!(
                "host resolved {uri:?} but answered back as {reply:?} — refusing the mismatch"
            )));
        }
        let key = decode_key(&reply.key_hex)?;
        let urls = validate_url_list(&reply.urls, &self.allow)?;
        if !reply.format.starts_with("OGG_") {
            return Err(OpenError::Unavailable(format!(
                "track comes back as {:?} — earshot plays Ogg only",
                reply.format
            )));
        }
        Ok(ResolvedTrack {
            format: reply.format,
            key,
            urls,
        })
    }
}

/// Classify a non-200 status into something the exit-code contract can act on.
///
/// The distinctions that matter: 401/403 is *auth* (bad token, exit 4);
/// over-resource statuses like 429 are *transient* (exit 2, retry); everything
/// else around resolving a specific track is demote to transient too — an
/// audio-key error upstream is flaky, and calling a possibly-fine track
/// unplayable (exit 3, skip) would silently disappear it.
fn classify_status(status: u16, text: &str, host: &str) -> OpenError {
    let detail = if text.trim().is_empty() {
        String::new()
    } else {
        format!(": {}", text.trim())
    };
    match status {
        401 | 403 => OpenError::Auth(format!(
            "{host} rejected the room token (HTTP {status}){detail}"
        )),
        408 | 429 => OpenError::Transient(format!(
            "{host} is busy or throttling us (HTTP {status}){detail}"
        )),
        400..=499 => OpenError::Transient(format!(
            "{host} could not resolve the track (HTTP {status}){detail}"
        )),
        _ => OpenError::Transient(format!("{host} trouble (HTTP {status}){detail}")),
    }
}

/// Transport errors (connection, DNS, timeout) are retryable. Because the
/// agent runs with `http_status_as_error(false)`, 4xx/5xx never reach us here.
fn transport_error(e: ureq::Error) -> OpenError {
    OpenError::Transient(format!("room request failed: {e}"))
}

/// The audio key is 32 hex chars from a remote host — validated *before* it is
/// indexed, so a hostile room cannot crash the guest with multi-byte utf-8
/// (the same mistake the old Myx `decode_key` doc comment warns about).
fn decode_key(hex: &str) -> Result<[u8; 16], OpenError> {
    let mut key = [0u8; 16];
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OpenError::Malformed(format!(
            "key_hex is {} chars, expected 32 hex",
            hex.chars().count()
        )));
    }
    for (i, slot) in key.iter_mut().enumerate() {
        let pair = &hex[2 * i..2 * i + 2];
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| OpenError::Malformed(format!("key_hex has a bad pair {pair:?}")))?;
    }
    Ok(key)
}

/// Validate the URL list, returning it owned.
fn validate_url_list(urls: &[String], allow: &[Cidr]) -> Result<Vec<String>, OpenError> {
    if urls.is_empty() {
        return Err(OpenError::Malformed("resolve reply listed no URLs".into()));
    }
    if urls.len() > MAX_URLS {
        return Err(OpenError::Malformed(format!(
            "resolve reply holds {} URLs, the cap is {MAX_URLS}",
            urls.len()
        )));
    }
    for url in urls {
        validate_cdn_url(url, allow)?;
    }
    Ok(urls.to_vec())
}

/// Validate one CDN URL a host handed us: scheme, host, credentials, and that
/// its address is public — or inside one of the `allow` networks the operator
/// named, which is how a Tailscale or LAN room is permitted without also
/// unblocking link-local and every other private range.
pub fn validate_cdn_url(url: &str, allow: &[Cidr]) -> Result<(), OpenError> {
    let parsed = Url::parse(url)
        .map_err(|e| OpenError::Malformed(format!("unparsable URL from the host {url:?}: {e}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(OpenError::Malformed(format!(
            "host URL uses {:?} where http(s) is required",
            parsed.scheme()
        )));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(OpenError::Malformed("host URL carries credentials".into()));
    }
    if parsed.fragment().is_some() {
        return Err(OpenError::Malformed("host URL carries a fragment".into()));
    }
    // `url::Host` gives us literal IPv4/IPv6 without any DNS; only a domain
    // name needs resolving, and the SSRF danger is exactly the domain that
    // resolves to something internal.
    let host = parsed
        .host()
        .ok_or_else(|| OpenError::Malformed("host URL has no host".into()))?;
    match host {
        url::Host::Ipv4(ip) => permitted_or(IpAddr::V4(ip), allow),
        url::Host::Ipv6(ip) => permitted_or(IpAddr::V6(ip), allow),
        url::Host::Domain(name) => {
            let port = parsed
                .port_or_known_default()
                .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
            let addresses: Vec<SocketAddr> = (name, port)
                .to_socket_addrs()
                .map_err(|e| {
                    OpenError::Malformed(format!("host URL {name:?} does not resolve: {e}"))
                })?
                .collect();
            if addresses.iter().any(|a| !permitted(&a.ip(), allow)) {
                return Err(OpenError::Malformed(format!(
                    "host URL {name:?} resolves to a non-public address"
                )));
            }
            Ok(())
        }
    }
}

/// Public, or inside a network the operator explicitly allowed.
pub fn permitted(ip: &IpAddr, allow: &[Cidr]) -> bool {
    is_public(ip) || allow.iter().any(|net| net.contains(ip))
}

fn permitted_or(ip: IpAddr, allow: &[Cidr]) -> Result<(), OpenError> {
    if permitted(&ip, allow) {
        Ok(())
    } else {
        Err(OpenError::Malformed(format!(
            "host URL {ip} is not a public address, and no room_allow_networks entry covers it"
        )))
    }
}

/// Whether an address is reachable only from a private or specially-reserved
/// network — the exact SSRF case (`DESIGN.md` Part 7): a compromised room host
/// handing guests `169.254.*`, RFC1918, loopback, etc. must not make them probe
/// the inside of whatever network they happen to be on.
///
/// Kept as *manual* range math rather than `std::net`'s classifier methods,
/// because several of those (`is_link_local`, `is_documentation` for IPv6)
/// are unstable and the blocklist is a security decision that should not
/// silently change between compilers.
pub fn is_public(ip: &IpAddr) -> bool {
    // IPv4-in-IPv6 (`::ffff:1.2.3.4`) is judged as the embedded IPv4.
    match ip {
        IpAddr::V4(v4) => is_public_v4(*v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(*v6),
        },
    }
}

fn is_public_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    match a {
        // 0.0.0.0/8 — "this network"; never routable.
        0 => false,
        // 10.0.0.0/8 — RFC 1918.
        10 => false,
        // 100.64.0.0/10 — CG-NAT (RFC 6598).
        100 => !(64..=127).contains(&b),
        // 127.0.0.0/8 — loopback.
        127 => false,
        // 169.254.0.0/16 — link-local.
        169 => !matches!(b, 254),
        // 172.16.0.0/12 — RFC 1918.
        172 => !(16..=31).contains(&b),
        // 192.168.0.0/16 — RFC 1918.
        192 if b == 168 => false,
        // Documentation ranges (TEST-NET): 192.0.2.0/24, 198.51.100.0/24,
        // 203.0.113.0/24 — reserved, block them too.
        192 if b == 0 && c == 2 => false,
        198 if b == 51 && c == 100 => false,
        203 if b == 0 && c == 113 => false,
        // 224.0.0.0/4 — multicast.
        224..=239 => false,
        // 240.0.0.0/4 — reserved.
        240..=255 => false,
        _ => true,
    }
}

fn is_public_v6(ip: std::net::Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    // The checks are top-bit comparisons on the 128-bit address.
    let top8 = (bits >> 120) as u8;
    let top10 = (bits >> 118) & 0x3ff;
    let top32 = (bits >> 96) as u32;
    match bits {
        // :: and ::1
        0 | 1 => false,
        _ => {
            top8 != 0xff // ff00::/8 multicast
                && top10 != 0x3fa // fe80::/10 link-local
                && ((bits >> 121) & 0x7f) != 0x7e // fc00::/7 unique-local
                && top10 != 0x3fb // fec0::/10 site-local (deprecated)
                && top32 != 0x2001_0db8 // 2001:db8::/32 documentation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_key_decodes() {
        assert_eq!(
            decode_key("0123456789abcdef0123456789abcdef").unwrap(),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef
            ]
        );
    }

    #[test]
    fn a_bad_key_is_a_malformed_reply() {
        for bad in [
            "",
            "00",
            "0123456789abcdef0123456789abcde",
            "zz3456789abcdef0123456789abcdef",
        ] {
            let err = decode_key(bad).unwrap_err();
            assert!(matches!(err, OpenError::Malformed(_)), "{bad:?}: {err}");
        }
    }

    #[test]
    fn url_lists_are_bounded() {
        let many: Vec<String> = (0..=(MAX_URLS as u32))
            .map(|i| format!("http://93.184.216.34/{i}"))
            .collect();
        let err = validate_url_list(&many, &[]).unwrap_err();
        assert!(matches!(err, OpenError::Malformed(_)));
        assert!(validate_url_list(&[], &[]).is_err());
        assert!(validate_url_list(&["https://93.184.216.34/a".into()], &[]).is_ok());
    }

    #[test]
    fn cdn_urls_stick_to_http_without_credentials() {
        let err = validate_cdn_url("ftp://93.184.216.34/a", &[]).unwrap_err();
        assert!(matches!(err, OpenError::Malformed(_)));
        let err = validate_cdn_url("http://user:pass@93.184.216.34/a", &[]).unwrap_err();
        assert!(matches!(err, OpenError::Malformed(_)));
        let err = validate_cdn_url("http://93.184.216.34/a#frag", &[]).unwrap_err();
        assert!(matches!(err, OpenError::Malformed(_)));
        assert!(validate_cdn_url("https://93.184.216.34/a?b=c", &[]).is_ok());
    }

    #[test]
    fn private_urls_are_rejected_public_ones_pass() {
        // Literal IPs need no DNS: the guard must classify them without asking
        // the resolver anything.
        for open in [
            "https://93.184.216.34/a",
            "http://8.8.8.8/x",
            "https://[2001:4860:4860::8888]/a",
        ] {
            assert!(
                validate_cdn_url(open, &[]).is_ok(),
                "should be public: {open}"
            );
        }
        // `localhost` is a domain, so it goes through the resolver → loopback.
        assert!(validate_cdn_url("http://localhost/a", &[]).is_err());
    }

    #[test]
    fn the_ssrf_blocklist_covers_the_usual_internal_ranges() {
        assert!(
            validate_cdn_url("http://127.0.0.1/a", &[]).is_err(),
            "loopback"
        );
        assert!(
            validate_cdn_url("http://169.254.169.254/a", &[]).is_err(),
            "link-local"
        );
        assert!(
            validate_cdn_url("http://10.0.0.1/a", &[]).is_err(),
            "RFC1918 /8"
        );
        assert!(
            validate_cdn_url("http://172.16.0.1/a", &[]).is_err(),
            "RFC1918 /12"
        );
        assert!(
            validate_cdn_url("http://192.168.1.1/a", &[]).is_err(),
            "RFC1918 /16"
        );
        assert!(
            validate_cdn_url("http://100.64.0.1/a", &[]).is_err(),
            "CG-NAT"
        );
        assert!(
            validate_cdn_url("http://192.0.2.1/a", &[]).is_err(),
            "documentation"
        );
        assert!(
            validate_cdn_url("http://[::1]/a", &[]).is_err(),
            "IPv6 loopback"
        );
        assert!(
            validate_cdn_url("http://[fe80::1]/a", &[]).is_err(),
            "IPv6 link-local"
        );
        assert!(
            validate_cdn_url("http://[fc00::1]/a", &[]).is_err(),
            "IPv6 unique-local"
        );
        assert!(
            validate_cdn_url("http://[2001:db8::1]/a", &[]).is_err(),
            "IPv6 doc"
        );
        assert!(
            validate_cdn_url("http://[::ffff:127.0.0.1]/a", &[]).is_err(),
            "IPv4-mapped loopback is loopback"
        );
        // Naming a network admits it, and only it.
        assert!(
            validate_cdn_url("http://127.0.0.1/a", &[Cidr::parse("127.0.0.0/8").unwrap()]).is_ok()
        );
    }

    /// The case that motivated an allowlist rather than a boolean: a Tailscale
    /// room lives in `100.64.0.0/10`, which the guard blocks as CG-NAT.
    #[test]
    fn a_named_network_is_admitted_and_nothing_else_is() {
        let tailnet = [Cidr::parse("100.64.0.0/10").expect("cidr")];

        assert!(
            validate_cdn_url("http://100.101.102.103/a.ogg", &tailnet).is_ok(),
            "a Tailscale address should be admitted when the tailnet is named"
        );

        // The whole point: the old blanket switch admitted every one of these.
        for blocked in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/a",
            "http://10.0.0.1/a",
            "http://192.168.1.1/a",
            "http://172.16.0.1/a",
        ] {
            assert!(
                validate_cdn_url(blocked, &tailnet).is_err(),
                "naming a tailnet must not admit {blocked}"
            );
        }

        // Only 100.64/10 is CG-NAT — 100.0.0.0/8 at large is public, so the
        // prefix maths must not just match the first octet.
        assert!(
            validate_cdn_url("http://100.1.2.3/a", &[]).is_ok(),
            "100.1/8 is public"
        );
        assert!(
            validate_cdn_url("http://100.64.0.1/a", &[]).is_err(),
            "100.64/10 is CG-NAT"
        );
    }

    #[test]
    fn cidr_parsing_rejects_what_it_should() {
        for bad in [
            "100.64.0.0",
            "not-an-ip/8",
            "100.64.0.0/33",
            "100.64.0.0/x",
            "",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad:?} should not parse");
        }
        assert!(Cidr::parse("::1/128").is_ok());
        assert!(Cidr::parse("fd00::/8").is_ok());
        assert!(
            Cidr::parse("  10.0.0.0/8  ").is_ok(),
            "surrounding space is fine"
        );

        // A v6 network must not swallow v4 addresses, or the reverse.
        let v6 = Cidr::parse("fd00::/8").expect("cidr");
        assert!(!v6.contains(&"10.0.0.1".parse().unwrap()));
        let v4 = Cidr::parse("10.0.0.0/8").expect("cidr");
        assert!(!v4.contains(&"fd00::1".parse().unwrap()));
        // But a v4-mapped v6 is judged as its v4, matching `is_public`.
        assert!(v4.contains(&"::ffff:10.1.2.3".parse().unwrap()));
    }
}
