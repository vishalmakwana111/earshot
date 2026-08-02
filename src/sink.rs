//! stdout, and the two ways writing to it can end.
//!
//! ## Disposal
//!
//! A closed pipe is the consumer disposing of us, not a failure. Rust sets
//! `SIGPIPE` to `SIG_IGN` before `main`, so the write returns `EPIPE` and this is
//! ordinary error handling rather than a signal handler (`DESIGN.md` A11).
//!
//! ## The idle ceiling
//!
//! Pause is backpressure: the consumer stops reading, the kernel pipe fills, and
//! the next write blocks. That is the whole pause mechanism and it needs no state.
//! But a Linux pipe holds only 64 KiB — about 1.6 s at 320 kbps — so a paused
//! producer parks almost immediately, and it parks *holding an open connection to
//! a possibly time-limited URL*. Twenty minutes later the resume fails.
//!
//! So the mechanism gets a ceiling (`DESIGN.md` D6). A blocking write cannot be
//! given a deadline portably, so a watchdog thread does it instead: the writer
//! stamps its progress, and if no progress happens within `max_idle` the watchdog
//! ends the process with [`EXIT_IDLE`]. The consumer sees a distinct code and
//! respawns if it still wants audio — which costs one invocation, against holding
//! a dead connection indefinitely.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The consumer stopped reading for longer than `max_idle`. Not a failure: it
/// means "respawn me if you still want this".
pub const EXIT_IDLE: u8 = 6;

/// How the write loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Everything was written.
    Complete,
    /// The consumer closed the pipe. A clean end.
    Disposed,
}

/// Tracks write progress so a watchdog can tell parked from progressing.
///
/// Milliseconds since the process-relative epoch, because an `Instant` is not an
/// atomic-friendly value.
#[derive(Clone)]
pub struct Progress {
    millis: Arc<AtomicU64>,
    epoch: Instant,
}

impl Progress {
    pub fn new() -> Self {
        Progress {
            millis: Arc::new(AtomicU64::new(0)),
            epoch: Instant::now(),
        }
    }

    /// Record that bytes moved.
    pub fn touch(&self) {
        let elapsed = self.epoch.elapsed().as_millis() as u64;
        self.millis.store(elapsed, Ordering::Relaxed);
    }

    /// How long since the last [`Progress::touch`].
    pub fn idle_for(&self) -> Duration {
        let last = self.millis.load(Ordering::Relaxed);
        let now = self.epoch.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(last))
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the idle watchdog. Returns without doing anything when disabled.
///
/// Ends the process rather than signalling the writer, because the writer is
/// blocked inside a `write` syscall and cannot be asked to notice anything.
pub fn spawn_idle_watchdog(progress: Progress, max_idle: Option<Duration>) {
    let Some(limit) = max_idle else {
        return;
    };
    // Touch once so a slow start is not mistaken for a parked consumer.
    progress.touch();
    std::thread::Builder::new()
        .name("earshot-idle-watchdog".to_string())
        .spawn(move || {
            // Poll at a fraction of the limit: fine enough to be prompt, coarse
            // enough to cost nothing.
            let tick = (limit / 10).max(Duration::from_millis(250));
            loop {
                std::thread::sleep(tick);
                if progress.idle_for() >= limit {
                    // stderr, because stdout is the audio stream.
                    eprintln!(
                        "earshot: consumer read nothing for {}s; disposing (exit {EXIT_IDLE})",
                        limit.as_secs()
                    );
                    std::process::exit(EXIT_IDLE as i32);
                }
            }
        })
        .expect("spawn idle watchdog");
}

/// Write everything, treating a closed pipe as disposal.
///
/// Stamps [`Progress`] on success so the watchdog can distinguish a parked
/// consumer from a slow one.
pub fn write_all<W: Write>(
    out: &mut W,
    bytes: &[u8],
    progress: &Progress,
) -> io::Result<Disposition> {
    match out.write_all(bytes) {
        Ok(()) => {
            progress.touch();
            Ok(Disposition::Complete)
        }
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(Disposition::Disposed),
        Err(e) => Err(e),
    }
}

/// Flush, treating a closed pipe as disposal.
pub fn flush<W: Write>(out: &mut W) -> io::Result<Disposition> {
    match out.flush() {
        Ok(()) => Ok(Disposition::Complete),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(Disposition::Disposed),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that reports a closed pipe, as a disposed consumer would.
    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
    }

    struct Failing;

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk on fire"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_pipe_is_disposal_not_an_error() {
        let progress = Progress::new();
        let got = write_all(&mut ClosedPipe, b"pages", &progress).expect("not an error");
        assert_eq!(got, Disposition::Disposed);
        assert_eq!(
            flush(&mut ClosedPipe).expect("not an error"),
            Disposition::Disposed
        );
    }

    /// Disposal must not swallow genuine write failures.
    #[test]
    fn other_write_failures_still_propagate() {
        let progress = Progress::new();
        let err = write_all(&mut Failing, b"pages", &progress).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_successful_write_records_progress() {
        let progress = Progress::new();
        std::thread::sleep(Duration::from_millis(60));
        let before = progress.idle_for();
        assert!(before >= Duration::from_millis(50), "{before:?}");

        let mut out: Vec<u8> = Vec::new();
        write_all(&mut out, b"pages", &progress).expect("write");
        assert!(
            progress.idle_for() < before,
            "progress was not recorded: {:?}",
            progress.idle_for(),
        );
        assert_eq!(out, b"pages");
    }

    #[test]
    fn idle_grows_while_nothing_is_written() {
        let progress = Progress::new();
        progress.touch();
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            progress.idle_for() >= Duration::from_millis(100),
            "idle did not grow: {:?}",
            progress.idle_for(),
        );
    }

    /// Disabling the watchdog must not spawn a thread that later exits the
    /// process — a test binary would die with it.
    #[test]
    fn a_disabled_watchdog_does_nothing() {
        spawn_idle_watchdog(Progress::new(), None);
        std::thread::sleep(Duration::from_millis(50));
        // Reaching here at all is the assertion.
    }
}
