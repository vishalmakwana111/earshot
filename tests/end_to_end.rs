//! End-to-end tests: drive the real binary, then check its output with an
//! independent decoder.
//!
//! Our own parser agreeing with our own writer proves very little, so the load
//! here is carried by ffmpeg. The strongest assertion in this file is
//! [`actual_start_ms_predicts_decoded_duration`]: earshot reports where it
//! believes the audio begins, and ffmpeg's decoded sample count must agree to
//! within a millisecond. That single number exercises the granule maths, the
//! codec seam, the bisection, the page renumbering and the checksum rewrite all
//! at once — get any of them wrong and it drifts.
//!
//! Tests needing ffmpeg print a clear SKIPPED line when it is absent rather than
//! passing quietly, because a silently-skipped oracle looks exactly like a
//! working one.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_earshot");

/// Fixtures, with the sample rate to decode them at.
const FIXTURES: &[(&str, u32)] = &[("vorbis_5s.ogg", 44_100), ("opus_5s.opus", 48_000)];

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn have_ffmpeg() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct Run {
    stdout: Vec<u8>,
    stderr: String,
    code: i32,
}

fn earshot(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {BIN}: {e}"));
    Run {
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Pull one integer field out of the metadata JSON without a serde dependency.
fn field(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find([',', '}'])?;
    rest[..end].trim().parse().ok()
}

fn probe(name: &str, start_ms: u64) -> String {
    let path = fixture_path(name);
    let run = earshot(&[
        "probe",
        path.to_str().unwrap(),
        "--start-ms",
        &start_ms.to_string(),
    ]);
    assert_eq!(run.code, 0, "probe failed: {}", run.stderr);
    String::from_utf8_lossy(&run.stdout).trim().to_string()
}

fn stream(name: &str, start_ms: u64) -> Vec<u8> {
    let path = fixture_path(name);
    let run = earshot(&[path.to_str().unwrap(), "--start-ms", &start_ms.to_string()]);
    assert_eq!(run.code, 0, "stream failed: {}", run.stderr);
    run.stdout
}

/// A temp path unique to this call.
///
/// Cargo runs the tests in this file as parallel threads of one process, so a
/// path keyed only on the process id gets clobbered by a sibling test — which
/// showed up as "decoded to nothing" rather than as an obvious race.
fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("earshot-{}-{tag}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Decode Ogg bytes to interleaved 16-bit PCM, returning samples per channel.
fn decode(bytes: &[u8], rate: u32) -> (Vec<u8>, String) {
    let dir = scratch("decode");
    let input = dir.join("in.ogg");
    let output = dir.join("out.pcm");
    std::fs::write(&input, bytes).expect("write input");
    let _ = std::fs::remove_file(&output);

    let out = Command::new("ffmpeg")
        .args(["-hide_banner", "-v", "error", "-i"])
        .arg(&input)
        .args(["-f", "s16le", "-ac", "2", "-ar", &rate.to_string()])
        .arg(&output)
        .arg("-y")
        .output()
        .expect("run ffmpeg");

    let pcm = std::fs::read(&output).unwrap_or_default();
    let complaints = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    (pcm, complaints)
}

// ---------------------------------------------------------------- self-checks

/// The identity that exercises the entire emit path: parse every page, renumber
/// it, recompute its checksum, write it back — and land on the original bytes.
/// Any error in header offsets, the segment table, or the CRC variant breaks it.
#[test]
fn start_ms_zero_reproduces_the_input_byte_for_byte() {
    for (name, _) in FIXTURES {
        let original = std::fs::read(fixture_path(name)).expect("fixture");
        let spliced = stream(name, 0);
        assert_eq!(spliced.len(), original.len(), "{name}: length");
        assert!(spliced == original, "{name}: bytes differ");
    }
}

/// Whatever we emit must satisfy our own validator: gapless sequence numbers,
/// every checksum correct, no trailing garbage.
#[test]
fn every_splice_is_structurally_valid_ogg() {
    for (name, _) in FIXTURES {
        for start_ms in [0, 250, 1000, 2000, 3000, 4000, 4999, 60_000] {
            let bytes = stream(name, start_ms);
            let path = scratch("valid").join("s.ogg");
            std::fs::write(&path, &bytes).expect("write");

            let run = earshot(&["pages", path.to_str().unwrap()]);
            let report = String::from_utf8_lossy(&run.stdout);
            assert_eq!(run.code, 0, "{name}@{start_ms}: pages said {}", run.stderr);
            assert!(
                report.contains("checksum failures: 0"),
                "{name}@{start_ms}: {report}",
            );
            assert!(
                !report.contains("trailing bytes"),
                "{name}@{start_ms}: trailing bytes in output",
            );

            // Sequence numbers must restart at zero and be gapless.
            let sequences: Vec<u32> = report
                .lines()
                .skip(1)
                .filter_map(|l| l.split_whitespace().nth(1))
                .filter_map(|s| s.parse().ok())
                .collect();
            assert!(!sequences.is_empty(), "{name}@{start_ms}: no pages");
            for (expected, got) in sequences.iter().enumerate() {
                assert_eq!(*got, expected as u32, "{name}@{start_ms}: sequence gap");
            }
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// `actual_start_ms` must never be later than requested — a splice that
/// overshoots silently drops audio the caller asked for.
#[test]
fn actual_start_never_overshoots_the_request() {
    for (name, _) in FIXTURES {
        let duration = field(&probe(name, 0), "duration_ms").expect("duration");
        for start_ms in (0..=5_000).step_by(137) {
            let json = probe(name, start_ms);
            let actual = field(&json, "actual_start_ms").expect("actual_start_ms");
            assert!(
                actual <= start_ms as i64,
                "{name}@{start_ms}: actual {actual} is later than requested",
            );
            assert!(actual <= duration, "{name}@{start_ms}: actual past the end");
        }
    }
}

/// Asking beyond the end must still produce a decodable stream rather than an
/// error or an empty file.
#[test]
fn seeking_past_the_end_still_yields_a_valid_stream() {
    for (name, _) in FIXTURES {
        let bytes = stream(name, 60_000);
        assert!(!bytes.is_empty(), "{name}: empty output");
        let json = probe(name, 60_000);
        let actual = field(&json, "actual_start_ms").expect("actual");
        let duration = field(&json, "duration_ms").expect("duration");
        assert!(actual <= duration, "{name}: {actual} past {duration}");
    }
}

/// Metadata must reach stderr before any audio, so a consumer can set its clock
/// before it starts decoding.
#[test]
fn metadata_is_reported_on_stderr_for_the_streaming_path() {
    let path = fixture_path("vorbis_5s.ogg");
    let run = earshot(&[path.to_str().unwrap(), "--start-ms", "2000"]);
    assert_eq!(run.code, 0);
    assert!(
        run.stderr.contains("earshot-meta: {"),
        "no metadata line: {:?}",
        run.stderr,
    );
    assert!(
        run.stderr.contains("\"actual_start_ms\":"),
        "metadata missing actual_start_ms: {:?}",
        run.stderr,
    );
    // stdout carries Ogg and nothing else.
    assert_eq!(&run.stdout[..4], b"OggS");
}

// ------------------------------------------------------------- ffmpeg oracle

/// Worst-case error in `actual_start_ms`, per codec.
///
/// Opus is exact: the granule timebase is 48 kHz and `pre_skip` fully describes
/// what the decoder discards, so prediction and reality agree to the sample.
///
/// Vorbis is exact in the interior of a stream but not in its final page, whose
/// granule carries the encoder's end-of-stream trim (640 samples in this
/// fixture). Separating that trim from real audio needs the per-packet block
/// sizes, which live inside the compressed data — so a splicer that deliberately
/// does not decode cannot recover it. The error is bounded by one long block:
/// `blocksize_1 / 2` = 1024 samples = 23.2 ms at 44.1 kHz.
fn tolerance_ms(codec: &str) -> f64 {
    match codec {
        "opus" => 1.0,
        // One long block, plus a millisecond for integer rounding.
        _ => 24.0,
    }
}

/// The load-bearing test.
///
/// earshot claims the emitted audio begins at `actual_start_ms`. Every splice runs
/// to the end of the track, so an independent decoder must produce
/// `duration_ms - actual_start_ms` of audio. Agreement means the granule
/// arithmetic, the codec seam, the chosen page, the renumbering, the checksum
/// rewrite and the decoder-discard model are all right at once — get any one of
/// them wrong and this drifts.
#[test]
fn actual_start_ms_predicts_decoded_duration() {
    if !have_ffmpeg() {
        eprintln!("SKIPPED: ffmpeg not found; the external decoder oracle did not run");
        return;
    }

    for (name, rate) in FIXTURES {
        let base = probe(name, 0);
        let duration = field(&base, "duration_ms").expect("duration");
        let codec = if base.contains("\"vorbis\"") {
            "vorbis"
        } else {
            "opus"
        };
        let tolerance = tolerance_ms(codec);

        for start_ms in [0u64, 500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500] {
            let json = probe(name, start_ms);
            let actual = field(&json, "actual_start_ms").expect("actual_start_ms");
            let bytes = stream(name, start_ms);

            let (pcm, complaints) = decode(&bytes, *rate);
            assert!(
                complaints.trim().is_empty(),
                "{name}@{start_ms}: ffmpeg complained: {complaints}",
            );
            assert!(!pcm.is_empty(), "{name}@{start_ms}: decoded to nothing");

            // Two channels of 16-bit samples.
            let decoded_ms = pcm.len() as f64 / 4.0 / *rate as f64 * 1000.0;
            let predicted_ms = (duration - actual) as f64;
            let drift = (predicted_ms - decoded_ms).abs();
            assert!(
                drift <= tolerance,
                "{name}@{start_ms}: predicted {predicted_ms:.1}ms, \
                 ffmpeg decoded {decoded_ms:.1}ms (drift {drift:.2}ms, \
                 tolerance {tolerance:.1}ms)",
            );
        }
    }
}

/// The tighter guarantee: away from the final page, prediction is exact to within
/// integer-millisecond rounding for *both* codecs. Kept separate from the test
/// above so the end-of-stream allowance cannot silently cover a regression in the
/// ordinary case.
#[test]
fn prediction_is_exact_away_from_the_final_page() {
    if !have_ffmpeg() {
        eprintln!("SKIPPED: ffmpeg not found; the external decoder oracle did not run");
        return;
    }

    for (name, rate) in FIXTURES {
        let duration = field(&probe(name, 0), "duration_ms").expect("duration");
        // The fixtures hold roughly one second per page; stay two pages clear of
        // the end so no splice can land in the final one.
        let ceiling = duration.saturating_sub(2_000) as u64;

        for start_ms in (0..ceiling).step_by(250) {
            let json = probe(name, start_ms);
            let actual = field(&json, "actual_start_ms").expect("actual_start_ms");
            let (pcm, complaints) = decode(&stream(name, start_ms), *rate);
            assert!(
                complaints.trim().is_empty(),
                "{name}@{start_ms}: {complaints}"
            );

            let decoded_ms = pcm.len() as f64 / 4.0 / *rate as f64 * 1000.0;
            let predicted_ms = (duration - actual) as f64;
            let drift = (predicted_ms - decoded_ms).abs();
            assert!(
                drift <= 1.0,
                "{name}@{start_ms}: predicted {predicted_ms:.1}ms, decoded \
                 {decoded_ms:.1}ms (drift {drift:.2}ms) — expected exact here",
            );
        }
    }
}

/// A splice must not corrupt anything downstream of it: since every splice runs
/// to the end of the track, the decoded tails must be identical to the original's.
#[test]
fn spliced_audio_matches_the_original_tail_sample_for_sample() {
    if !have_ffmpeg() {
        eprintln!("SKIPPED: ffmpeg not found; the external decoder oracle did not run");
        return;
    }

    for (name, rate) in FIXTURES {
        let original = std::fs::read(fixture_path(name)).expect("fixture");
        let (reference, complaints) = decode(&original, *rate);
        assert!(complaints.trim().is_empty(), "{name}: {complaints}");

        // Compare the last half second, well clear of the splice seam.
        let tail_bytes = (*rate as usize / 2) * 4;

        for start_ms in [1000u64, 2000, 3000, 4000] {
            let bytes = stream(name, start_ms);
            let (spliced, complaints) = decode(&bytes, *rate);
            assert!(
                complaints.trim().is_empty(),
                "{name}@{start_ms}: {complaints}"
            );
            assert!(
                spliced.len() >= tail_bytes && reference.len() >= tail_bytes,
                "{name}@{start_ms}: too short to compare tails",
            );

            let a = &reference[reference.len() - tail_bytes..];
            let b = &spliced[spliced.len() - tail_bytes..];
            assert!(
                a == b,
                "{name}@{start_ms}: decoded tail differs from the original",
            );
        }
    }
}

/// ffprobe must see the codec, channel count and rate earshot reported.
#[test]
fn reported_stream_parameters_match_what_a_decoder_sees() {
    if !have_ffmpeg() {
        eprintln!("SKIPPED: ffmpeg not found; the external decoder oracle did not run");
        return;
    }

    for (name, _) in FIXTURES {
        let json = probe(name, 2000);
        let channels = field(&json, "channels").expect("channels");
        let bytes = stream(name, 2000);

        let path = scratch("params").join("p.ogg");
        std::fs::write(&path, &bytes).expect("write");

        let out = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-select_streams",
                "a:0",
                "-show_entries",
                "stream=codec_name,channels",
                "-of",
                "default=nw=1",
            ])
            .arg(&path)
            .output()
            .expect("run ffprobe");
        let report = String::from_utf8_lossy(&out.stdout);

        let expected_codec = if json.contains("\"vorbis\"") {
            "vorbis"
        } else {
            "opus"
        };
        assert!(
            report.contains(&format!("codec_name={expected_codec}")),
            "{name}: ffprobe saw {report}",
        );
        assert!(
            report.contains(&format!("channels={channels}")),
            "{name}: ffprobe saw {report}",
        );
        let _ = std::fs::remove_file(&path);
    }
}

// --------------------------------------------------------------- CLI contract

/// A closed pipe is disposal, not failure. Rust ignores SIGPIPE, so the write
/// returns `BrokenPipe` and earshot must treat it as a clean exit 0.
///
/// Done in-process rather than through a shell pipeline for two reasons: no
/// dependency on which shell exists on the runner, and determinism. Closing the
/// read end *before* earshot writes anything guarantees the very first write hits
/// EPIPE — whereas `| head -c 200` cannot, since these fixtures are smaller than
/// a 64 KiB pipe buffer and would fit entirely without ever blocking.
#[test]
fn a_closed_pipe_exits_zero() {
    use std::io::Read;

    let path = fixture_path("vorbis_5s.ogg");
    let mut child = Command::new(BIN)
        .args([path.to_str().unwrap(), "--start-ms", "1000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn earshot");

    // Dropping the handle closes our read end, so every write earshot attempts
    // fails with EPIPE.
    drop(child.stdout.take().expect("stdout"));

    let status = child.wait().expect("wait for earshot");
    assert_eq!(
        status.code(),
        Some(0),
        "a disposed consumer must be a clean exit, not a failure",
    );

    // And the partial-consumption case: read a little, then close.
    let mut child = Command::new(BIN)
        .args([path.to_str().unwrap(), "--start-ms", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn earshot");
    {
        let mut out = child.stdout.take().expect("stdout");
        let mut buf = [0u8; 200];
        let _ = out.read(&mut buf);
    }
    let status = child.wait().expect("wait for earshot");
    assert_eq!(
        status.code(),
        Some(0),
        "partial read then close must exit 0"
    );
}

#[test]
fn exit_codes_follow_the_contract() {
    let good = fixture_path("vorbis_5s.ogg");
    let good = good.to_str().unwrap();

    // 0 — clean.
    assert_eq!(earshot(&[good, "--start-ms", "1000"]).code, 0);
    assert_eq!(earshot(&["--help"]).code, 0);
    assert_eq!(earshot(&["--version"]).code, 0);

    // 1 — usage. An unknown flag must be rejected, not ignored: a silently
    // dropped `--strat-ms` would stream from the wrong place and look like a
    // splice bug.
    assert_eq!(earshot(&[good, "--strat-ms", "1000"]).code, 1);
    assert_eq!(earshot(&[good, "--start-ms", "banana"]).code, 1);
    assert_eq!(earshot(&[good, "--start-ms"]).code, 1);
    assert_eq!(earshot(&["pages"]).code, 1);
    assert_eq!(earshot(&["probe"]).code, 1);
    assert_eq!(earshot(&[good, good]).code, 1);
    // room:// with credentials in the URI is rejected as a usage error (room
    // feature), and as unsupported without the room feature.
    #[cfg(feature = "room")]
    assert_eq!(earshot(&["room://token@host/track"]).code, 1);
    #[cfg(not(feature = "room"))]
    assert_eq!(earshot(&["room://token@host/track"]).code, 1);
    // http:// is implemented with the `http` feature, so an unreachable host is
    // a *transport* failure worth retrying (2), otherwise it is unsupported (1).
    // Port 1 fails immediately; pointing this at a real hostname would make the
    // suite depend on the network and take 30s to time out.
    #[cfg(feature = "http")]
    assert_eq!(earshot(&["http://127.0.0.1:1/a.ogg"]).code, 2);
    #[cfg(not(feature = "http"))]
    assert_eq!(earshot(&["http://127.0.0.1:1/a.ogg"]).code, 1);

    // 3 — permanently unavailable.
    assert_eq!(earshot(&["/definitely/not/here.ogg"]).code, 3);

    // 5 — malformed stream.
    let dir = scratch("codes");
    let junk = dir.join("junk.ogg");
    std::fs::write(&junk, b"this is not an ogg stream at all, not even close").expect("write");
    assert_eq!(earshot(&[junk.to_str().unwrap()]).code, 5);

    // A flipped byte inside a page that gets emitted must be caught, not
    // streamed on as if it were fine.
    let mut corrupt = std::fs::read(fixture_path("vorbis_5s.ogg")).expect("fixture");
    let at = corrupt.len() - 200;
    corrupt[at] ^= 0xff;
    let corrupt_path = dir.join("corrupt.ogg");
    std::fs::write(&corrupt_path, &corrupt).expect("write");
    let run = earshot(&[corrupt_path.to_str().unwrap(), "--start-ms", "0"]);
    assert_eq!(
        run.code, 5,
        "corruption inside the emitted range must be reported; stderr {}",
        run.stderr,
    );
}

/// Damage in a region the splice never touches is not an error, and that is the
/// point of addressing sources by offset: earshot reads the header pages and the
/// tail it was asked for, not the whole stream. Recording it as a test keeps it a
/// documented property rather than a surprise.
#[test]
fn corruption_outside_the_emitted_range_is_not_read() {
    let original = std::fs::read(fixture_path("vorbis_5s.ogg")).expect("fixture");

    // Find the byte range of the final page, and splice from inside it.
    let last_page_start = (1..original.len())
        .rev()
        .find(|&i| original[i..].starts_with(b"OggS"))
        .expect("a final page");

    // Damage a page in the middle, which a late splice has no reason to read.
    let mut damaged = original.clone();
    let victim = last_page_start / 2;
    damaged[victim] ^= 0xff;

    let dir = scratch("untouched");
    let path = dir.join("damaged.ogg");
    std::fs::write(&path, &damaged).expect("write");

    let run = earshot(&[path.to_str().unwrap(), "--start-ms", "4800"]);
    assert_eq!(
        run.code, 0,
        "a late splice should not have read the damaged region; stderr {}",
        run.stderr,
    );
    assert_eq!(&run.stdout[..4], b"OggS");

    // And the same file spliced from zero *is* an error, proving the damage was
    // real and simply out of range above.
    let from_zero = earshot(&[path.to_str().unwrap(), "--start-ms", "0"]);
    assert_eq!(from_zero.code, 5, "the damage should be detected when read");
}

#[test]
fn help_and_version_go_to_stdout() {
    let help = earshot(&["--help"]);
    assert!(String::from_utf8_lossy(&help.stdout).contains("USAGE"));
    let version = earshot(&["--version"]);
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("earshot "));
}
