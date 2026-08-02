# earshot

Turns a URI into an Ogg stream on stdout, with precise `--start-ms` splicing.

```
earshot <uri> [--start-ms N]   →  Ogg on stdout · logs on stderr · meaningful exit codes
```

Stateless per invocation — **kill = dispose, seek = respawn**. A building block for
audio applications, not an application.

```console
$ earshot track.ogg --start-ms 90000 | mpv -
earshot-meta: {"codec":"vorbis","rate":44100,"channels":2,"duration_ms":214533,
               "requested_start_ms":90000,"actual_start_ms":89020, ...}
```

Two things `ffmpeg -ss N -c copy -f ogg -` won't give you:

- **It tells you where it actually landed.** Splices hit page boundaries and decoders
  discard the head of a spliced stream, so `--start-ms 90000` may really begin at
  89 020 ms. `actual_start_ms` is reported, and verified against a real decoder.
- **A dispose contract.** A full pipe is the consumer's pause; a closed pipe is
  disposal and exits 0. Backpressure is the interface, not an accident.

## Install

No toolchain, no clone:

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/vishalmakwana111/earshot/releases/latest/download/earshot-installer.sh | sh
```

Prebuilt for Linux (`x86_64`, `aarch64`), macOS (Apple Silicon, Intel) and Windows
(`x86_64`). The installer verifies checksums and refuses on a mismatch;
`EARSHOT_BIN_DIR` overrides where it lands. Or from source:

```bash
cargo install --git https://github.com/vishalmakwana111/earshot
```

> Not on crates.io: that name belongs to an unrelated voice-activity-detection
> crate, so **don't** run `cargo install earshot`.

## Guide

```bash
earshot <uri> [--start-ms N]        # Ogg on stdout, metadata on stderr
earshot probe <uri> [--start-ms N]  # metadata JSON on stdout, no audio
earshot pages <file>                # page structure + checksum validation
earshot config --init               # write a commented config file
```

Settings layer, highest first: **command line > `EARSHOT_*` >
`~/.config/earshot/earshot.toml` > defaults.** An unknown key or a bad value is an
error naming the file and line — never a silent skip, for the same reason unknown
flags are rejected.

`<uri>` is `file://path`, a bare path, or `http(s)://…`. `room://` is recognised and
rejected with a clear message rather than mistaken for a filename.

Remote reads are ranged, so a late `--start-ms` costs a handful of small requests
rather than downloading and discarding everything before it. `http_window` tunes the
read-ahead window (default 1 MiB, floor 64 KiB): smaller reaches first audio sooner,
larger costs fewer round trips.

`--max-idle SECS|off` (default 60) bounds the pause. A full pipe *is* the pause, but
a producer parked indefinitely holds an open connection to a possibly time-limited
URL — so past the ceiling earshot disposes of itself with exit 6 and the consumer
respawns if it still wants audio.

Unknown flags are **errors**, not ignored — a silently dropped `--strat-ms` would
stream from the wrong place and look like a splice bug.

### Exit codes

The consumer's whole decision surface, so deliberately finer than pass/fail:

| | Meaning | What a consumer should do |
|---|---|---|
| 0 | Clean, including a closed pipe | nothing |
| 1 | Usage / bad URI | fix the invocation |
| 2 | Transient source failure | retry |
| 3 | Permanently unavailable | skip the track |
| 4 | Auth rejected | re-authenticate |
| 5 | Malformed stream | skip and report |
| 6 | Idle: the consumer stopped reading | respawn if still wanted |

### Using it from your program

It's a byte pipe, so consuming it needs no library dependency — spawn it, read the
metadata line from stderr, decode stdout. Two obligations:

- **Drain stderr.** A full stderr pipe blocks earshot's writer, which surfaces as
  audio stalling and looks exactly like a decode bug.
- **Trust `actual_start_ms`, not your request**, or your playhead drifts by up to a
  page.

Transport maps onto the process: pause by **stopping reading** (the pipe fills and
earshot blocks in `write`), seek by **respawning** with a new `--start-ms`, stop by
**killing**. [myx](https://github.com/HaseebKhalid1507/Myx) does exactly this.

#### Accuracy of `actual_start_ms`

Measured against ffmpeg, not asserted. Never *later* than requested — overshooting
would silently drop audio the caller asked for.

| Codec | Mid-stream | Final page |
|---|---|---|
| Opus | exact | exact |
| Vorbis | exact to ms rounding | within one long block (23.2 ms) |

The final-page caveat is inherent: that page's granule carries the encoder's
end-of-stream trim, and separating it needs per-packet block sizes that live inside
the compressed data. A splicer that deliberately never decodes cannot recover them.

> Granule positions stay **absolute**, so container duration still describes the
> original track — a stream spliced at 3 s reports `duration=5.0065` to `ffprobe`
> while carrying 2 s of audio. That is the point: seek to 90 s and you see 90 s. Use
> `duration_ms − actual_start_ms` for the emitted length.

## Architecture

Five layers, each testable over bytes — no audio device and no Spotify session
anywhere in the test suite. The only network is loopback, against a fake upstream the
tests start themselves.

| Layer | Job |
|---|---|
| `source` | `trait Source { size, read_at }` — `file://` ✅, `http(s)://` ✅, `room://` planned |
| `ogg` | page parse · serialise · packet walk · CRC · resync · granule bisection |
| `codec` | granule semantics: Vorbis vs Opus. **The seam that cannot live in `ogg`** |
| `splice` | pick the start page, renumber, re-checksum, report `actual_start_ms` |
| stdout | `BrokenPipe` is disposal, not failure |

Three decisions worth knowing; [DESIGN.md](DESIGN.md) derives them from primary
sources:

- **Sources are addressed by offset, not `io::Read`.** HTTP has `Range` and AES-CTR's
  keystream position *is* the byte offset, so seeking stays `O(log n)` and a dropped
  connection can resume. Transforms stay decorators — they just decorate `Source`.
- **The Ogg core is codec-agnostic; the seek is not.** Ogg has no concept of time.
  Vorbis counts granules at the stream rate; Opus always at 48 kHz with `pre_skip`
  subtracted. A single "generic" `ms → granule` would be wrong for one of them.
- **Splicing rewrites pages.** Renumbering sequence numbers invalidates Ogg's
  checksum, and a stale checksum is one of three things that make a decoder report a
  hole in the data. So it re-serialises rather than viewing.

## Status

| Milestone | State |
|---|---|
| **M0** byte core — page framing, checksums | ✅ |
| **M1** the tool — `Source`, codec, splice, sink, config | ✅ |
| **M2** `room://` — ranged HTTP + AES-CTR decrypt | ⬜ |
| **M3** `host` — server side, PKCE login | ⬜ |

Working today: `file://`, a bare path, or `http(s)://`; Ogg Vorbis and Ogg Opus;
`--start-ms` seeking by granule bisection; layered config; the bounded idle ceiling;
metadata; and the full exit-code contract.
Remote reads handle the CDN quirks in `DESIGN.md` A9 — a range larger than the file
answering `200`, resources rotating mid-stream, and `416` carrying the length.

## Testing

105 tests. The ones that can actually falsify something:

- **`--start-ms 0` reproduces its input byte for byte** — exercises the whole emit
  path: parse every page, renumber, recompute checksums, write back.
- **ffmpeg's decoded sample count matches `duration_ms − actual_start_ms`** — one
  number covering the granule maths, codec seam, chosen page, renumbering and
  checksum rewrite at once.
- **Decoded tails match the original's, sample for sample** — the splice corrupts
  nothing downstream.
- **Bisection agrees with a linear scan at every target**, not a sampled few.
- **HTTP and `file://` splice to byte-identical output** at every offset, against a
  fake upstream that answers `200` to ranged requests, rotates its `ETag`, truncates
  bodies and fails over — an off-by-one in a `Range` header shows up as a diff.
- **A consumer that stops reading is disposed with exit 6, and one that keeps reading
  never is** — against a fixture larger than a pipe buffer, since with a smaller file
  earshot finishes before the consumer's silence could matter.
- **A mistyped config key fails with its line number**, so a setting cannot quietly
  do nothing.
- **`table[0x80] != 0xEDB88320`** — proves we did not build the reflected CRC-32.
  Ogg's is non-reflected, init 0, no final XOR; an off-the-shelf `crc32` is silently
  wrong.

```bash
cargo test                           # everything
cargo test --lib --no-default-features   # byte core: zero dependencies
cargo +nightly fuzz run page_scan    # local; asserts roundtrip identity too
```

CI additionally fails if ffmpeg is missing (a skipped oracle looks exactly like a
working one), asserts the dependency tree is **empty**, and installs from a packaged
release including the paths that must refuse.

Regenerate fixtures:

```bash
ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=44100:duration=5" -ac 2 \
       -c:a vorbis -strict -2 -y tests/fixtures/vorbis_5s.ogg
ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=5" -ac 2 \
       -c:a libopus -b:a 48k -y tests/fixtures/opus_5s.opus
```

## Credits

Understanding of Spotify's audio path — AES-128-CTR keyed by absolute byte offset,
the 167-byte prepended metadata packet, the CDN range protocol — comes from reading
[librespot](https://github.com/librespot-org/librespot) and
[myx](https://github.com/HaseebKhalid1507/Myx), both MIT. No code copied; both are
credited for the reverse engineering they made legible.

Format work follows [RFC 3533](https://www.rfc-editor.org/rfc/rfc3533.html),
the [Vorbis I spec](https://xiph.org/vorbis/doc/Vorbis_I_spec.html), and
[RFC 7845](https://datatracker.ietf.org/doc/html/rfc7845).

## License

MIT — see [LICENSE](LICENSE).
