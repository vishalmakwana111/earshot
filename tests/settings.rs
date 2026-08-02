//! Configuration layering and the idle ceiling, driven through the real binary.
//!
//! Both are things whose failure modes are silent, which is why they get their own
//! suite: a config key that quietly does nothing, or a producer that parks forever
//! holding a connection, look like working software until much later.
//!
//! The idle tests need a fixture **larger than a pipe buffer** (64 KiB on Linux).
//! With a smaller file earshot writes everything into the buffer and exits before
//! the consumer's silence matters, so a watchdog test against the 20 KiB fixture
//! would pass without ever exercising the watchdog.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_earshot");

/// Larger than a 64 KiB pipe buffer, so a non-reading consumer really does block
/// the writer.
const OVER_BUFFER: &str = "vorbis_30s.ogg";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A scratch config path unique to this call — these tests run as parallel
/// threads of one process, so a shared path would have them clobbering each other.
fn scratch_config(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("earshot-cfg-{}-{tag}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join("earshot.toml")
}

struct Run {
    stdout: Vec<u8>,
    stderr: String,
    code: i32,
}

/// Run with an explicit config path, so the developer's own config cannot leak in.
fn earshot_with_config(config: &Path, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("EARSHOT_CONFIG", config)
        // Clear the inherited overrides, or a shell that exported one would
        // silently change what these tests measure.
        .env_remove("EARSHOT_MAX_IDLE")
        .env_remove("EARSHOT_HTTP_WINDOW")
        .output()
        .expect("spawn earshot");
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Wait for a child, giving up after `limit`. `None` means it was still running.
fn wait_for_exit(child: &mut Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        match child.try_wait().expect("try_wait") {
            Some(status) => return Some(status.code().unwrap_or(-1)),
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    None
}

// ------------------------------------------------------------------- config

#[test]
fn config_init_writes_a_template_that_parses() {
    let config = scratch_config("init");
    let run = earshot_with_config(&config, &["config", "--init"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(config.is_file(), "no file written");

    let text = std::fs::read_to_string(&config).expect("read");
    assert!(text.contains("http_window"), "template lacks the settings");
    assert!(text.contains("max_idle"), "template lacks the settings");

    // The file we hand people must not break the next invocation.
    let path = fixture("vorbis_5s.ogg");
    let stream = earshot_with_config(&config, &[path.to_str().unwrap(), "--start-ms", "0"]);
    assert_eq!(
        stream.code, 0,
        "template broke streaming: {}",
        stream.stderr
    );
    assert_eq!(&stream.stdout[..4], b"OggS");
}

/// An edited config must never be overwritten by a second `--init`.
#[test]
fn config_init_does_not_clobber_an_existing_file() {
    let config = scratch_config("noclobber");
    std::fs::write(&config, "max_idle = 11\n").expect("write");
    let run = earshot_with_config(&config, &["config", "--init"]);
    assert_eq!(run.code, 0);
    assert_eq!(
        std::fs::read_to_string(&config).expect("read"),
        "max_idle = 11\n",
        "an existing config was overwritten",
    );
}

/// The property that justifies a hand-written parser: a typo is loud.
#[test]
fn a_mistyped_config_key_is_an_error_naming_the_line() {
    let config = scratch_config("typo");
    std::fs::write(&config, "# fine\nhtp_window = 200000\n").expect("write");
    let path = fixture("vorbis_5s.ogg");
    let run = earshot_with_config(&config, &[path.to_str().unwrap()]);

    assert_eq!(run.code, 1, "a bad config is a usage error: {}", run.stderr);
    assert!(run.stderr.contains(":2:"), "no line number: {}", run.stderr);
    assert!(run.stderr.contains("htp_window"), "{}", run.stderr);
    // And it says what it does know, so the fix is obvious.
    assert!(run.stderr.contains("http_window"), "{}", run.stderr);
    assert!(run.stdout.is_empty(), "emitted audio despite a bad config");
}

#[test]
fn a_bad_config_value_is_an_error_not_a_silent_default() {
    let config = scratch_config("badvalue");
    std::fs::write(&config, "max_idle = soon\n").expect("write");
    let path = fixture("vorbis_5s.ogg");
    let run = earshot_with_config(&config, &[path.to_str().unwrap()]);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(run.stderr.contains("max_idle"), "{}", run.stderr);
}

#[test]
fn a_line_that_is_not_key_equals_value_is_rejected() {
    let config = scratch_config("section");
    std::fs::write(&config, "[network]\nhttp_window = 200000\n").expect("write");
    let path = fixture("vorbis_5s.ogg");
    let run = earshot_with_config(&config, &[path.to_str().unwrap()]);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(run.stderr.contains("key = value"), "{}", run.stderr);
}

/// A missing config file is normal, not an error.
#[test]
fn a_missing_config_file_is_fine() {
    let config = scratch_config("absent");
    let path = fixture("vorbis_5s.ogg");
    let run = earshot_with_config(&config, &[path.to_str().unwrap(), "--start-ms", "0"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
}

// --------------------------------------------------------------- idle ceiling

/// The D6 ceiling: a consumer that stops reading must not park the producer
/// forever holding an open connection.
///
/// The pipe is opened and then never read, which is exactly what a paused consumer
/// looks like from here.
#[test]
fn a_consumer_that_stops_reading_is_disposed_with_exit_6() {
    let path = fixture(OVER_BUFFER);
    let mut child = Command::new(BIN)
        .args([path.to_str().unwrap(), "--max-idle", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("EARSHOT_MAX_IDLE")
        .spawn()
        .expect("spawn");

    // Hold the read end open without reading, so the buffer fills and stays full.
    let _held = child.stdout.take().expect("stdout");

    let code = wait_for_exit(&mut child, Duration::from_secs(15));
    let code = code.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("earshot never disposed itself; it is still parked on a full pipe");
    });
    assert_eq!(code, 6, "expected the idle exit code");

    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut stderr);
    }
    assert!(
        stderr.contains("read nothing") || stderr.contains("disposing"),
        "no explanation of why it exited: {stderr}",
    );
}

/// `--max-idle off` must genuinely disable the ceiling, since a consumer that
/// pauses deliberately for a long time is a legitimate use.
#[test]
fn the_ceiling_can_be_switched_off() {
    let path = fixture(OVER_BUFFER);
    let mut child = Command::new(BIN)
        .args([path.to_str().unwrap(), "--max-idle", "off"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("EARSHOT_MAX_IDLE")
        .spawn()
        .expect("spawn");
    let _held = child.stdout.take().expect("stdout");

    // Well past what a 1s ceiling would allow.
    let code = wait_for_exit(&mut child, Duration::from_secs(4));
    let still_running = code.is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        still_running,
        "exited with {code:?} despite the ceiling being off",
    );
}

/// A consumer that *is* reading must never be disposed, however small the ceiling.
/// This is the false-positive case, and it is the one that would break playback.
#[test]
fn a_reading_consumer_is_never_disposed() {
    let path = fixture(OVER_BUFFER);
    let mut child = Command::new(BIN)
        .args([path.to_str().unwrap(), "--max-idle", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("EARSHOT_MAX_IDLE")
        .spawn()
        .expect("spawn");

    // Read slowly but continuously — slower than the stream, so the pipe is often
    // full, yet progress never stops for a whole second.
    let mut stdout = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut total = 0usize;
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
        total
    });

    let code = wait_for_exit(&mut child, Duration::from_secs(60)).unwrap_or_else(|| {
        let _ = child.kill();
        panic!("never finished");
    });
    let total = reader.join().expect("reader");

    assert_eq!(code, 0, "a reading consumer was disposed (exit {code})");
    assert!(
        total > 65_536,
        "only {total} bytes moved, so the pipe never filled and the case was not tested",
    );
}

/// The command line must outrank the config file, or an explicit flag is a lie.
#[test]
fn the_command_line_outranks_the_config_file() {
    let config = scratch_config("precedence");
    // The file says never dispose; the flag says dispose after a second.
    std::fs::write(&config, "max_idle = off\n").expect("write");
    let path = fixture(OVER_BUFFER);

    let mut child = Command::new(BIN)
        .args([path.to_str().unwrap(), "--max-idle", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("EARSHOT_CONFIG", &config)
        .env_remove("EARSHOT_MAX_IDLE")
        .spawn()
        .expect("spawn");
    let _held = child.stdout.take().expect("stdout");

    let code = wait_for_exit(&mut child, Duration::from_secs(15));
    if code.is_none() {
        let _ = child.kill();
    }
    assert_eq!(code, Some(6), "the config file overrode an explicit flag");
}

/// The environment must outrank the config file, and be outranked by the flag.
#[test]
fn the_environment_outranks_the_config_file() {
    let config = scratch_config("env");
    std::fs::write(&config, "max_idle = off\n").expect("write");
    let path = fixture(OVER_BUFFER);

    let mut child = Command::new(BIN)
        .args([path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("EARSHOT_CONFIG", &config)
        .env("EARSHOT_MAX_IDLE", "1")
        .spawn()
        .expect("spawn");
    let _held = child.stdout.take().expect("stdout");

    let code = wait_for_exit(&mut child, Duration::from_secs(15));
    if code.is_none() {
        let _ = child.kill();
    }
    assert_eq!(code, Some(6), "the config file overrode EARSHOT_MAX_IDLE");
}

/// A bad value in the environment must be as loud as one in the file.
#[test]
fn a_bad_environment_value_is_rejected() {
    let config = scratch_config("badenv");
    let path = fixture("vorbis_5s.ogg");
    let out = Command::new(BIN)
        .args([path.to_str().unwrap()])
        .env("EARSHOT_CONFIG", &config)
        .env("EARSHOT_MAX_IDLE", "whenever")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("EARSHOT_MAX_IDLE"), "{stderr}");
}

#[test]
fn init_is_rejected_outside_the_config_command() {
    let config = scratch_config("misuse");
    let path = fixture("vorbis_5s.ogg");
    let run = earshot_with_config(&config, &["--init", path.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    assert!(run.stderr.contains("--init"), "{}", run.stderr);
}
