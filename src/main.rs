//! earshot CLI.
//!
//! ```text
//! earshot <uri> [--start-ms N] [--max-idle SECS|off]
//! earshot probe <uri> [--start-ms N]   metadata JSON on stdout, no audio
//! earshot pages <file>                 page structure and checksum validation
//! earshot config --init                write a commented config file
//! ```
//!
//! Settings layer as `DESIGN.md` Part 4 specifies: command line > `EARSHOT_*` >
//! `~/.config/earshot/earshot.toml` > built-in defaults.
//!
//! stdout is sacred: on the streaming path it carries Ogg bytes and nothing else.
//! The metadata line goes to stderr prefixed `earshot-meta:` and is written
//! before the first audio byte. (`DESIGN.md` reserves fd 3 for it; stderr is the
//! M1 stand-in, since fd 3 needs platform-specific probing to detect whether it
//! is even open.)

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use earshot::config::{self, Settings};
use earshot::ogg::scan::Scanner;
use earshot::ogg::{page::Pages, GRANULE_NONE};
use earshot::sink::{self, Progress};
use earshot::source;
use earshot::splice;

// Exit codes are contract, not decoration: a consumer decides retry vs. skip vs.
// re-auth from them. See DESIGN.md Part 4.
const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_UNAVAILABLE: u8 = 3;
const EXIT_MALFORMED: u8 = 5;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, settings) = match Command::parse(&args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("earshot: {message}");
            eprintln!("try `earshot --help`");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match command {
        Command::Help => {
            print_help(&mut io::stdout());
            ExitCode::from(EXIT_OK)
        }
        Command::Version => {
            println!("earshot {}", env!("CARGO_PKG_VERSION"));
            ExitCode::from(EXIT_OK)
        }
        Command::Stream {
            uri,
            start_ms,
            max_idle,
        } => cmd_stream(&uri, start_ms, true, max_idle, &settings),
        Command::Probe { uri, start_ms } => cmd_stream(&uri, start_ms, false, None, &settings),
        Command::Pages { path } => cmd_pages(&path),
        Command::ConfigInit => cmd_config_init(),
        #[cfg(feature = "host")]
        Command::Host => cmd_host(&settings),
    }
}

enum Command {
    Stream {
        uri: String,
        start_ms: u64,
        max_idle: Option<Duration>,
    },
    Probe {
        uri: String,
        start_ms: u64,
    },
    Pages {
        path: String,
    },
    /// Write a commented config template, so there is a file to edit.
    ConfigInit,
    /// (host feature) serve a listening room, M3 — see `earshot --help`.
    #[cfg(feature = "host")]
    Host,
    Help,
    Version,
}

impl Command {
    /// Parse arguments, rejecting anything unrecognised.
    ///
    /// Deliberately strict: a silently-ignored `--strat-ms` would produce a
    /// stream that starts in the wrong place and look like a bug in the splice.
    fn parse(args: &[String]) -> Result<(Command, Settings), String> {
        let mut positional: Vec<&str> = Vec::new();
        let mut start_ms: Option<u64> = None;
        // Only set when the flag is actually given, so a default does not
        // outrank an explicit config-file entry.
        let mut max_idle_flag: Option<Option<Duration>> = None;
        let mut init = false;
        let mut index = 0;

        while index < args.len() {
            let arg = args[index].as_str();
            match arg {
                "-h" | "--help" => return Ok((Command::Help, Settings::default())),
                "-V" | "--version" => return Ok((Command::Version, Settings::default())),
                "--start-ms" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--start-ms needs a value".to_string())?;
                    start_ms = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| format!("--start-ms: {value:?} is not a whole number"))?,
                    );
                    index += 2;
                }
                "--init" => {
                    init = true;
                    index += 1;
                }
                "--max-idle" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--max-idle needs seconds or \"off\"".to_string())?;
                    max_idle_flag = Some(parse_max_idle(value)?);
                    index += 2;
                }
                _ if arg.starts_with("--max-idle=") => {
                    max_idle_flag = Some(parse_max_idle(&arg["--max-idle=".len()..])?);
                    index += 1;
                }
                _ if arg.starts_with("--start-ms=") => {
                    let value = &arg["--start-ms=".len()..];
                    start_ms = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| format!("--start-ms: {value:?} is not a whole number"))?,
                    );
                    index += 1;
                }
                // A bare "-" is not a flag, but anything else starting with a
                // dash is, and an unknown one is an error rather than a URI.
                _ if arg.starts_with('-') && arg.len() > 1 => {
                    return Err(format!("unknown option {arg:?}"));
                }
                _ => {
                    positional.push(arg);
                    index += 1;
                }
            }
        }

        let start_ms = start_ms.unwrap_or(0);
        // Layers below the CLI, then the flag if it was given.
        let settings = Settings::load().map_err(|e| e.to_string())?;
        let max_idle = max_idle_flag.unwrap_or(settings.max_idle);

        match positional.as_slice() {
            ["config", "init"] => Ok((Command::ConfigInit, settings)),
            ["config"] if init => Ok((Command::ConfigInit, settings)),
            ["config"] => Err("config needs --init".to_string()),
            _ if init => Err("--init is only valid for `earshot config`".to_string()),
            [] => Ok((Command::Help, settings)),
            ["pages", path] => Ok((
                Command::Pages {
                    path: (*path).to_string(),
                },
                settings,
            )),
            ["pages"] => Err("pages needs a file path".to_string()),
            ["probe", uri] => Ok((
                Command::Probe {
                    uri: (*uri).to_string(),
                    start_ms,
                },
                settings,
            )),
            ["probe"] => Err("probe needs a URI".to_string()),
            #[cfg(feature = "host")]
            ["host"] => Ok((Command::Host, settings)),
            #[cfg(feature = "host")]
            ["host", ..] => Err("host takes no arguments (see settings)".to_string()),
            [uri] => Ok((
                Command::Stream {
                    uri: (*uri).to_string(),
                    start_ms,
                    max_idle,
                },
                settings,
            )),
            _ => Err(format!(
                "expected one URI, got {}: {}",
                positional.len(),
                positional.join(" ")
            )),
        }
    }
}

fn print_help(out: &mut impl Write) {
    let _ = writeln!(
        out,
        "earshot {} — a streaming audio source tool

USAGE:
    earshot <uri> [--start-ms N]        Ogg on stdout, metadata on stderr
    earshot probe <uri> [--start-ms N]  metadata JSON on stdout, no audio
    earshot pages <file>                page structure and checksum validation
    earshot config --init               write a commented config file
    earshot host                        serve a listening room (host_bind/host_engine)

OPTIONS:
    --start-ms N                        where to start
    --max-idle SECS|off                 dispose after the consumer stops reading

URIs:
    file://path, a bare path, http(s):// supported
    room:<track>  or  spotify:<track>      play through a listening room
                                          (set room_host/room_token to use one)

EXIT CODES:
    0 clean (including a closed pipe)   4 auth rejected
    1 usage                             5 malformed stream
    2 transient failure — retry         6 idle: consumer stopped reading
    3 permanently unavailable

Settings layer: command line > EARSHOT_* > ~/.config/earshot/earshot.toml",
        env!("CARGO_PKG_VERSION"),
    );
}

/// The streaming path. `write_audio` false means probe: metadata only.
/// `off`/`0` disables the watchdog; anything else is seconds.
fn parse_max_idle(value: &str) -> Result<Option<Duration>, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") || value == "0" {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(|s| Some(Duration::from_secs(s)))
        .map_err(|_| format!("--max-idle: {value:?} is not seconds or \"off\""))
}

fn cmd_config_init() -> ExitCode {
    let Some(path) = config::config_path() else {
        eprintln!("earshot: no config directory (set HOME or EARSHOT_CONFIG)");
        return ExitCode::from(EXIT_USAGE);
    };
    if path.exists() {
        // Never clobber an edited config.
        println!("{} already exists; leaving it alone", path.display());
        return ExitCode::from(EXIT_OK);
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("earshot: {}: {e}", dir.display());
            return ExitCode::from(EXIT_USAGE);
        }
    }
    match std::fs::write(&path, config::TEMPLATE) {
        Ok(()) => {
            println!("wrote {}", path.display());
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            eprintln!("earshot: {}: {e}", path.display());
            ExitCode::from(EXIT_USAGE)
        }
    }
}

#[cfg(feature = "host")]
fn cmd_host(settings: &Settings) -> ExitCode {
    match earshot::room::host::run_host(settings) {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!("earshot: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn cmd_stream(
    uri: &str,
    start_ms: u64,
    write_audio: bool,
    max_idle: Option<Duration>,
    settings: &Settings,
) -> ExitCode {
    let src = match source::open(uri, settings) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("earshot: {uri}: {e}");
            return ExitCode::from(e.exit_code());
        }
    };

    let mut scanner = Scanner::new(src);
    let plan = match splice::plan(&mut scanner, start_ms) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("earshot: {uri}: {e}");
            return ExitCode::from(e.exit_code());
        }
    };

    if !write_audio {
        println!("{}", plan.info.to_json());
        return ExitCode::from(EXIT_OK);
    }

    // Metadata before the first audio byte, so a consumer can set its clock
    // before it starts decoding.
    eprintln!("earshot-meta: {}", plan.info.to_json());

    // Pause is a full pipe, but a producer parked forever holds an open
    // connection to a possibly time-limited URL. See DESIGN.md D6.
    let progress = Progress::new();
    sink::spawn_idle_watchdog(progress.clone(), max_idle);

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    match splice::emit_with_progress(&mut scanner, &plan, &mut out, &progress) {
        // A closed pipe is the consumer disposing of us, which is a clean end.
        Ok(_) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!("earshot: {uri}: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn cmd_pages(path: &str) -> ExitCode {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("earshot: {path}: {e}");
            return ExitCode::from(match e.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => EXIT_UNAVAILABLE,
                _ => EXIT_USAGE,
            });
        }
    };

    println!(
        "{:>8}  {:>5}  {:>4}  {:>12}  {:>5}  {:>6}  {:>10}  flags",
        "offset", "seq", "segs", "granule", "body", "total", "crc"
    );

    let mut offset = 0usize;
    let mut count = 0usize;
    let mut bad_crc = 0usize;
    let mut continued = 0usize;
    let mut no_granule = 0usize;
    let mut last_granule = None;

    let mut pages = Pages::new(&bytes);
    for result in &mut pages {
        let page = match result {
            Ok(p) => p,
            Err(e) => {
                eprintln!("earshot: malformed page at byte {offset}: {e}");
                return ExitCode::from(EXIT_MALFORMED);
            }
        };

        let ok = page.verify_crc();
        if !ok {
            bad_crc += 1;
        }
        if page.is_continued() {
            continued += 1;
        }
        match page.granule() {
            Some(g) => last_granule = Some(g),
            None => no_granule += 1,
        }

        let mut flags = String::new();
        if page.is_bos() {
            flags.push_str("bos ");
        }
        if page.is_eos() {
            flags.push_str("eos ");
        }
        if page.is_continued() {
            flags.push_str("cont ");
        }
        if !ok {
            flags.push_str("BAD-CRC ");
        }

        let granule = if page.granule_raw == GRANULE_NONE {
            "-1".to_string()
        } else {
            page.granule_raw.to_string()
        };

        println!(
            "{:>8}  {:>5}  {:>4}  {:>12}  {:>5}  {:>6}  {:#010x}  {}",
            offset,
            page.sequence,
            page.segments.len(),
            granule,
            page.body.len(),
            page.len(),
            page.crc,
            flags.trim_end(),
        );

        offset += page.len();
        count += 1;
    }

    let trailing = bytes.len() - offset;
    println!();
    println!("{count} pages, {} bytes", bytes.len());
    println!("  checksum failures: {bad_crc}");
    println!("  continued pages:   {continued}");
    println!("  granule -1 pages:  {no_granule}");
    if let Some(g) = last_granule {
        println!("  final granule:     {g}  (codec decides what this means in ms)");
    }
    if trailing > 0 {
        println!("  trailing bytes:    {trailing}  (not a page)");
    }

    if bad_crc > 0 || trailing > 0 {
        ExitCode::from(EXIT_MALFORMED)
    } else {
        ExitCode::from(EXIT_OK)
    }
}
