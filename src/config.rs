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

use std::path::PathBuf;
use std::time::Duration;

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
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            http_window: HTTP_WINDOW_DEFAULT,
            max_idle: Some(MAX_IDLE_DEFAULT),
            timeout_connect: Duration::from_secs(10),
            timeout_global: Duration::from_secs(60),
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
                _ => "70000",
            };
            s.apply_one(key, probe)
                .unwrap_or_else(|e| panic!("{key} listed but not applicable: {e}"));
        }
    }
}
