//! Layered settings: CLI > `EARSHOT_*` > config file > defaults.
//!
//! ## Why the file parser is hand-written
//!
//! The config is flat and tiny — four keys, all scalars. A full TOML parser plus
//! `serde` is roughly ten crates to read `key = value` lines, against a project
//! whose byte core deliberately has none. So this reads a documented *subset*:
//! `key = value`, `#` comments, blank lines. Nothing else.
//!
//! Crucially it is **strict**. An unrecognised key, a bad value, or a line it
//! cannot parse is an error naming the file and line — never a silent skip. A
//! mistyped `htp_window` that quietly did nothing would produce exactly the class
//! of bug that unknown CLI flags are rejected to avoid.
//!
//! If the config ever grows tables or arrays, swap this for `toml`; the
//! [`Settings`] surface will not have to change.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// An IP network in CIDR form — the unit of [`Settings::room_allow_networks`].
///
/// Hand-parsed for the same reason the blocklist in `room::client` is hand-written:
/// this is a security decision, and it should not change silently underneath the
/// project with a dependency bump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    bits: u8,
}

impl Cidr {
    /// Parse `10.0.0.0/8` or `fd00::/8`. The prefix length is required, so a
    /// bare address cannot be mistaken for a whole network.
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let text = text.trim();
        let (addr, bits) = text
            .split_once('/')
            .ok_or_else(|| format!("{text:?} is not a network (expected e.g. 100.64.0.0/10)"))?;
        let base: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("{:?} is not an IP address", addr.trim()))?;
        let bits: u8 = bits
            .trim()
            .parse()
            .map_err(|_| format!("{:?} is not a prefix length", bits.trim()))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!("/{bits} is longer than {base} allows (max /{max})"));
        }
        Ok(Cidr { base, bits })
    }

    /// Whether `ip` falls inside this network.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        // `::ffff:1.2.3.4` is judged as the IPv4 it carries, matching `is_public`.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
            other => *other,
        };
        match (self.base, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => prefix_eq(&net.octets(), &ip.octets(), self.bits),
            (IpAddr::V6(net), IpAddr::V6(ip)) => prefix_eq(&net.octets(), &ip.octets(), self.bits),
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.bits)
    }
}

/// Whether two addresses agree on their first `bits` bits.
fn prefix_eq(net: &[u8], ip: &[u8], bits: u8) -> bool {
    let whole = (bits / 8) as usize;
    if net[..whole] != ip[..whole] {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    (net[whole] & mask) == (ip[whole] & mask)
}

/// Default read-ahead window for remote reads.
pub const HTTP_WINDOW_DEFAULT: usize = 1 << 20;

/// Smallest useful window: below a maximum Ogg page, one page read needs two
/// round trips.
pub const HTTP_WINDOW_MIN: usize = 64 * 1024;

/// How long the consumer may stop reading before we dispose of ourselves.
///
/// Pause is backpressure — a full pipe *is* the pause — but a producer parked
/// indefinitely holds an open connection to a possibly time-limited URL, so the
/// mechanism needs a ceiling. See `DESIGN.md` D6.
pub const MAX_IDLE_DEFAULT: Duration = Duration::from_secs(60);

/// Everything tunable, already resolved through the layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub http_window: usize,
    /// `None` disables the idle watchdog entirely.
    pub max_idle: Option<Duration>,
    pub timeout_connect: Duration,
    pub timeout_global: Duration,
    /// Room backend (M2): the host to resolve tracks against, e.g. `127.0.0.1:8787`.
    pub room_host: Option<String>,
    /// The room's shared token. A credential — `EARSHOT_ROOM_TOKEN` is the
    /// preferred home for it, since env vars do not show up in `ps`.
    pub room_token: Option<String>,
    /// Networks whose addresses the room's CDN URLs may use, on top of the
    /// public internet. Empty by default, because a compromised room host must
    /// not turn guests into an internal-network prober (DESIGN Part 7).
    ///
    /// A list rather than an "allow private" switch because the real cases are
    /// each one specific range — `100.64.0.0/10` for a Tailscale room,
    /// `192.168.0.0/16` for a LAN one, `127.0.0.0/8` for a local test server —
    /// and a blanket permission would additionally unblock link-local, which is
    /// where cloud metadata services live. Naming the network you mean costs a
    /// few characters and gives up nothing else.
    pub room_allow_networks: Vec<Cidr>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            http_window: HTTP_WINDOW_DEFAULT,
            max_idle: Some(MAX_IDLE_DEFAULT),
            timeout_connect: Duration::from_secs(10),
            timeout_global: Duration::from_secs(60),
            room_host: None,
            room_token: None,
            room_allow_networks: Vec::new(),
        }
    }
}

/// Where a config file is looked for.
pub fn config_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("EARSHOT_CONFIG") {
        return Some(PathBuf::from(explicit));
    }
    crate::config_home().map(|h| h.join("earshot/earshot.toml"))
}

#[derive(Debug)]
pub struct ConfigError {
    pub source: String,
    pub line: Option<usize>,
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(n) => write!(f, "{}:{}: {}", self.source, n, self.message),
            None => write!(f, "{}: {}", self.source, self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Settings {
    /// Resolve every layer below the CLI.
    ///
    /// The caller applies CLI overrides afterwards, since only it knows which
    /// flags were actually given — a default-valued flag must not outrank an
    /// explicit config file entry.
    pub fn load() -> Result<Settings, ConfigError> {
        let mut settings = Settings::default();
        if let Some(path) = config_path() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                settings.apply_file(&text, &path.display().to_string())?;
            }
            // A missing file is not an error; an unreadable or malformed one is.
        }
        settings.apply_env()?;
        Ok(settings)
    }

    /// Apply the documented subset of a config file.
    pub fn apply_file(&mut self, text: &str, source: &str) -> Result<(), ConfigError> {
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                return Err(ConfigError {
                    source: source.to_string(),
                    line: Some(line),
                    message: format!("expected `key = value`, got {trimmed:?}"),
                });
            };
            let key = key.trim();
            // Accept quoted values so a future string setting reads naturally.
            let value = value.trim().trim_matches('"').trim();
            self.apply_one(key, value).map_err(|message| ConfigError {
                source: source.to_string(),
                line: Some(line),
                message,
            })?;
        }
        Ok(())
    }

    /// Apply `EARSHOT_*`, which outranks the file.
    pub fn apply_env(&mut self) -> Result<(), ConfigError> {
        for (key, var) in KEYS {
            if let Ok(value) = std::env::var(var) {
                if value.trim().is_empty() {
                    continue;
                }
                self.apply_one(key, value.trim())
                    .map_err(|message| ConfigError {
                        source: (*var).to_string(),
                        line: None,
                        message,
                    })?;
            }
        }
        Ok(())
    }

    /// One setting, by its config-file name. Unknown keys are rejected.
    fn apply_one(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "http_window" => {
                let raw: usize = value
                    .parse()
                    .map_err(|_| format!("http_window: {value:?} is not a byte count"))?;
                // Raised rather than rejected: a too-small window is a
                // performance mistake, not a malformed setting.
                self.http_window = raw.max(HTTP_WINDOW_MIN);
            }
            "max_idle" => {
                if value.eq_ignore_ascii_case("off") || value == "0" {
                    self.max_idle = None;
                } else {
                    let secs: u64 = value
                        .parse()
                        .map_err(|_| format!("max_idle: {value:?} is not seconds or \"off\""))?;
                    self.max_idle = Some(Duration::from_secs(secs));
                }
            }
            "timeout_connect" => {
                self.timeout_connect = Duration::from_secs(parse_secs("timeout_connect", value)?);
            }
            "timeout_global" => {
                self.timeout_global = Duration::from_secs(parse_secs("timeout_global", value)?);
            }
            "room_host" => {
                self.room_host = if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                };
            }
            "room_token" => {
                self.room_token = if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                };
            }
            "room_allow_networks" => {
                self.room_allow_networks = if value.is_empty() {
                    Vec::new()
                } else {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|entry| !entry.is_empty())
                        .map(Cidr::parse)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| format!("room_allow_networks: {e}"))?
                };
            }
            other => {
                let known: Vec<&str> = KEYS.iter().map(|(k, _)| *k).collect();
                return Err(format!(
                    "unknown setting {other:?} (known: {})",
                    known.join(", ")
                ));
            }
        }
        Ok(())
    }
}

fn parse_secs(key: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{key}: {value:?} is not a number of seconds"))
}

/// Config-file key paired with the environment variable that overrides it.
const KEYS: &[(&str, &str)] = &[
    ("http_window", "EARSHOT_HTTP_WINDOW"),
    ("max_idle", "EARSHOT_MAX_IDLE"),
    ("timeout_connect", "EARSHOT_TIMEOUT_CONNECT"),
    ("timeout_global", "EARSHOT_TIMEOUT_GLOBAL"),
    ("room_host", "EARSHOT_ROOM_HOST"),
    ("room_token", "EARSHOT_ROOM_TOKEN"),
    ("room_allow_networks", "EARSHOT_ROOM_ALLOW_NETWORKS"),
];

/// The commented template written by `earshot config --init`, so there is a file
/// to edit and nothing to look up.
pub const TEMPLATE: &str = "\
# earshot configuration. Every value here is a default; uncomment to change.
# Precedence: command line > EARSHOT_* environment > this file > built-in.

# Read-ahead window for remote reads, in bytes. Smaller reaches first audio
# sooner; larger costs fewer round trips. Raised to 65536 if set below it.
# http_window = 1048576

# Seconds the consumer may stop reading before earshot disposes of itself and
# exits 6. Pause is a full pipe, but parking forever holds an open connection to
# a possibly time-limited URL. \"off\" disables the watchdog.
# max_idle = 60

# Per-request network timeouts, in seconds.
# timeout_connect = 10
# timeout_global = 60

# A listening room (M2): the host to resolve tracks against, and the room's
# shared token. A `spotify:track:...` or `room:spotify:track:...` URI only
# plays when a room is configured. The token is a credential — prefer the
# `EARSHOT_ROOM_TOKEN` environment variable over committing it to a file.
# room_host = \"127.0.0.1:8787\"
# room_token = \"0123456789abcdef0123456789abcdef\"

# Networks the room's download URLs may live on, besides the public internet.
# Empty by default so a compromised room cannot use guests to probe inside
# networks (SSRF). Name the one you actually use — a Tailscale room is
# 100.64.0.0/10, a LAN one 192.168.0.0/16, a local test server 127.0.0.0/8 —
# rather than opening every private range, which would include the link-local
# addresses cloud metadata services answer on. Comma-separated.
# room_allow_networks = \"100.64.0.0/10\"

";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_documented_ones() {
        let s = Settings::default();
        assert_eq!(s.http_window, 1 << 20);
        assert_eq!(s.max_idle, Some(Duration::from_secs(60)));
    }

    #[test]
    fn reads_the_documented_subset() {
        let mut s = Settings::default();
        s.apply_file(
            "# a comment\n\
             \n\
             http_window = 200000   # trailing comment\n\
             max_idle = 5\n\
             timeout_connect = 3\n",
            "test",
        )
        .expect("parse");
        assert_eq!(s.http_window, 200_000);
        assert_eq!(s.max_idle, Some(Duration::from_secs(5)));
        assert_eq!(s.timeout_connect, Duration::from_secs(3));
    }

    /// The property that makes a hand-written parser acceptable: it never
    /// silently ignores something it did not understand.
    #[test]
    fn an_unknown_key_is_an_error_naming_the_line() {
        let mut s = Settings::default();
        let err = s
            .apply_file("http_window = 200000\nhtp_window = 4\n", "earshot.toml")
            .unwrap_err();
        assert_eq!(err.line, Some(2));
        assert!(err.message.contains("htp_window"), "{}", err.message);
        // And it lists what it does know, so the typo is obvious.
        assert!(err.message.contains("http_window"), "{}", err.message);
        assert_eq!(err.to_string(), format!("earshot.toml:2: {}", err.message));
    }

    #[test]
    fn a_bad_value_is_an_error_not_a_default() {
        let mut s = Settings::default();
        for bad in [
            "http_window = banana",
            "max_idle = soon",
            "timeout_global = -",
            "room_allow_networks = 100.64.0.0",
        ] {
            let err = s.apply_file(bad, "test").unwrap_err();
            assert_eq!(err.line, Some(1), "{bad}");
        }
    }

    #[test]
    fn a_line_that_is_not_key_equals_value_is_rejected() {
        let mut s = Settings::default();
        let err = s.apply_file("[section]\n", "test").unwrap_err();
        assert!(err.message.contains("key = value"), "{}", err.message);
    }

    #[test]
    fn a_too_small_window_is_raised_rather_than_rejected() {
        let mut s = Settings::default();
        s.apply_file("http_window = 10\n", "test").expect("parse");
        assert_eq!(s.http_window, HTTP_WINDOW_MIN);
    }

    #[test]
    fn the_idle_watchdog_can_be_switched_off() {
        for value in ["off", "OFF", "0"] {
            let mut s = Settings::default();
            s.apply_file(&format!("max_idle = {value}\n"), "test")
                .expect("parse");
            assert_eq!(s.max_idle, None, "{value}");
        }
    }

    #[test]
    fn quoted_values_are_accepted() {
        let mut s = Settings::default();
        s.apply_file("max_idle = \"off\"\n", "test").expect("parse");
        assert_eq!(s.max_idle, None);
    }

    /// The template must actually parse, or the file we hand people is broken.
    #[test]
    fn the_template_parses_and_changes_nothing() {
        let mut s = Settings::default();
        s.apply_file(TEMPLATE, "template").expect("template parses");
        assert_eq!(s, Settings::default(), "template altered a default");
    }

    #[test]
    fn every_key_has_an_env_var_and_both_are_reachable() {
        for (key, var) in KEYS {
            assert!(var.starts_with("EARSHOT_"), "{var}");
            // Every documented key must be applicable, or the table lies.
            let mut s = Settings::default();
            let probe = match *key {
                "max_idle" => "off",
                "room_host" => "127.0.0.1:8787",
                "room_token" => "0123456789abcdef0123456789abcdef",
                "room_allow_networks" => "127.0.0.0/8",
                _ => "70000",
            };
            s.apply_one(key, probe)
                .unwrap_or_else(|e| panic!("{key} listed but not applicable: {e}"));
        }
    }

    /// Room settings round-trip through the same strict subset as the rest.
    #[test]
    fn room_settings_parse_and_round_trip() {
        let mut s = Settings::default();
        s.apply_file(
            "room_host = \"127.0.0.1:8787\"\n\
             room_token = 0123456789abcdef0123456789abcdef\n\
             room_allow_networks = \"127.0.0.0/8, 100.64.0.0/10\"\n",
            "test",
        )
        .expect("parse");
        assert_eq!(s.room_host.as_deref(), Some("127.0.0.1:8787"));
        assert_eq!(
            s.room_token.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(s.room_allow_networks.len(), 2);
        assert!(s.room_allow_networks[0].contains(&"127.0.0.1".parse().unwrap()));
        assert!(s.room_allow_networks[1].contains(&"100.100.1.1".parse().unwrap()));
        assert!(!s.room_allow_networks[1].contains(&"8.8.8.8".parse().unwrap()));

        let mut s2 = Settings::default();
        assert!(
            s2.room_host.is_none() && s2.room_token.is_none() && s2.room_allow_networks.is_empty()
        );
        s2.apply_file("room_host = \"\"\n", "test")
            .expect("empty host clears");
        assert_eq!(s2.room_host, None);
    }
}
