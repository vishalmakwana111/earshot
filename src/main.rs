//! earshot CLI.
//!
//! ```text
//! earshot <uri> [--start-ms N]     Ogg on stdout, metadata line on stderr
//! earshot probe <uri> [--start-ms N]   metadata JSON on stdout, no audio
//! earshot pages <file>             page structure and checksum validation
//! ```
//!
//! stdout is sacred: on the streaming path it carries Ogg bytes and nothing else.
//! The metadata line goes to stderr prefixed `earshot-meta:` and is written
//! before the first audio byte. (`DESIGN.md` reserves fd 3 for it; stderr is the
//! M1 stand-in, since fd 3 needs platform-specific probing to detect whether it
//! is even open.)

use std::io::{self, Write};
use std::process::ExitCode;

use earshot::ogg::scan::Scanner;
use earshot::ogg::{page::Pages, GRANULE_NONE};
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
    match Command::parse(&args) {
        Ok(Command::Help) => {
            print_help(&mut io::stdout());
            ExitCode::from(EXIT_OK)
        }
        Ok(Command::Version) => {
            println!("earshot {}", env!("CARGO_PKG_VERSION"));
            ExitCode::from(EXIT_OK)
        }
        Ok(Command::Stream { uri, start_ms }) => cmd_stream(&uri, start_ms, true),
        Ok(Command::Probe { uri, start_ms }) => cmd_stream(&uri, start_ms, false),
        Ok(Command::Pages { path }) => cmd_pages(&path),
        Err(message) => {
            eprintln!("earshot: {message}");
            eprintln!("try `earshot --help`");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

enum Command {
    Stream { uri: String, start_ms: u64 },
    Probe { uri: String, start_ms: u64 },
    Pages { path: String },
    Help,
    Version,
}

impl Command {
    /// Parse arguments, rejecting anything unrecognised.
    ///
    /// Deliberately strict: a silently-ignored `--strat-ms` would produce a
    /// stream that starts in the wrong place and look like a bug in the splice.
    fn parse(args: &[String]) -> Result<Command, String> {
        let mut positional: Vec<&str> = Vec::new();
        let mut start_ms: Option<u64> = None;
        let mut index = 0;

        while index < args.len() {
            let arg = args[index].as_str();
            match arg {
                "-h" | "--help" => return Ok(Command::Help),
                "-V" | "--version" => return Ok(Command::Version),
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
        match positional.as_slice() {
            [] => Ok(Command::Help),
            ["pages", path] => Ok(Command::Pages {
                path: (*path).to_string(),
            }),
            ["pages"] => Err("pages needs a file path".to_string()),
            ["probe", uri] => Ok(Command::Probe {
                uri: (*uri).to_string(),
                start_ms,
            }),
            ["probe"] => Err("probe needs a URI".to_string()),
            [uri] => Ok(Command::Stream {
                uri: (*uri).to_string(),
                start_ms,
            }),
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

URIs:
    file://path, or a bare path         supported
    http(s)://, room://                 not implemented yet

EXIT CODES:
    0 clean (including a closed pipe)   3 permanently unavailable
    1 usage                             4 auth rejected
    2 transient failure — retry         5 malformed stream",
        env!("CARGO_PKG_VERSION"),
    );
}

/// The streaming path. `write_audio` false means probe: metadata only.
fn cmd_stream(uri: &str, start_ms: u64, write_audio: bool) -> ExitCode {
    let src = match source::open(uri) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("earshot: {uri}: {e}");
            return ExitCode::from(match e.kind() {
                io::ErrorKind::Unsupported => EXIT_USAGE,
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => EXIT_UNAVAILABLE,
                _ => 2,
            });
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

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    match splice::emit(&mut scanner, &plan, &mut out) {
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
