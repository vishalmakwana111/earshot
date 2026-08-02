# earshot

A streaming audio source tool. Turns a URI into an Ogg stream on stdout, with
precise `--start-ms` splicing.

```
earshot <uri> [--start-ms N]     →  Ogg on stdout, logs on stderr, meaningful exit codes
```

Stateless per invocation: kill = dispose, seek = respawn. A building block for
audio applications rather than an application itself.

```console
$ earshot track.ogg --start-ms 90000 | mpv -
earshot-meta: {"codec":"vorbis","rate":44100,"channels":2,"duration_ms":214533,
               "requested_start_ms":90000,"actual_start_ms":89020,
               "start_granule":3925504,"container_offset":0,"header_pages":2}
```

Two things it gives you that `ffmpeg -ss N -c copy -f ogg -` does not:

- **It tells you where it actually landed.** A splice lands on a page boundary
  and a decoder discards the head of a spliced stream, so `--start-ms 90000` may
  really begin at 89 020 ms. earshot reports `actual_start_ms`, verified against
  a real decoder, so the consumer's clock stays honest.
- **A first-class dispose contract.** A full pipe is the consumer's pause; a
  closed pipe is disposal and exits 0. Backpressure is the interface, not an
  accident.

---

## Status

| Milestone | State | What it covers |
|---|---|---|
| **M0** — byte core | ✅ done | Ogg page parse/serialise, checksums, packet walk |
| **M1** — the tool | 🟡 `file://` working | Source trait, codec seam, splice, stdout sink, exit codes |
| **M2** — `room://` | ⬜ planned | Ranged HTTP + AES-CTR decrypt decorators |
| **M3** — `host` | ⬜ planned | Server side, PKCE login |

Working today: `file://` (or a bare path), both Ogg Vorbis and Ogg Opus,
`--start-ms` seeking by granule bisection, metadata reporting, and the full exit
code contract. `http://` and `room://` are recognised and rejected with a clear
message rather than mistaken for filenames.

---

## Architecture

Five layers. Each one is testable over bytes — no audio device, no network, no
Spotify session anywhere in the test suite.

```
uri
 │
 ▼
┌─ source ────────────────────────────────────────────────────────────┐
│  trait Source { size(), read_at(offset, buf) }                      │
│                                                                     │
│    file://     positioned reads                          ✅         │
│    http(s)://  ranged reader: If-Range, resume, fallback  ⬜ M2     │
│    room://     ranged HTTP + remote resolver              ⬜ M2     │
│                  └─ Decrypt<S>   keystream at absolute offset       │
│                       └─ Window<S>  start = 0xa7                    │
└─────────────────────────────────────────────────────────────────────┘
 │
 ▼
┌─ ogg ───────────────────────────────────────────────────────────────┐
│  page framing, genuinely codec-agnostic                             │
│    crc.rs   Ogg's CRC-32 — not the one in your dependency tree      │
│    page.rs  parse · serialise · packet walk · in-place patchers     │
│    scan.rs  read at offset · resync · granule bisection             │
└─────────────────────────────────────────────────────────────────────┘
 │
 ▼
┌─ codec ─────────────────────────────────────────────────────────────┐
│  granule semantics — the seam that cannot live in `ogg`             │
│    Vorbis: granule at stream rate, blocksizes, no pre-skip          │
│    Opus:   granule always at 48 kHz, pre_skip subtracted            │
└─────────────────────────────────────────────────────────────────────┘
 │
 ▼
┌─ splice ────────────────────────────────────────────────────────────┐
│  which page to start from, and what to tell the consumer            │
│    header pages + tail from the chosen page                         │
│    renumber sequence · recompute checksums · report actual_start_ms │
└─────────────────────────────────────────────────────────────────────┘
 │
 ▼
   stdout — BrokenPipe is disposal, not failure
```

### Why sources are addressed by offset

This is the one decision everything else rests on, and it is the reason the
`Source` trait is not `io::Read`.

Every source earshot cares about is randomly accessible. HTTP has `Range`.
Spotify's audio cipher is AES-128-CTR, whose keystream position *is* the absolute
byte offset — librespot's own `AudioDecrypt` implements `Seek` by calling
`cipher.seek(offset)`. A `Read`-only chain throws both away: seeking to 5:00 of a
track would mean fetching and discarding everything before it, on every seek, and
a connection dropping at 70% could not be resumed.

Offset addressing keeps the decorator model that makes backends small — the
decorators just decorate `Source` instead of `Read`. Because `Window` is
offset-preserving, granule bisection works straight through the stack, and the
Ogg layer never learns any of it happened.

### Why the Ogg core is codec-agnostic but the seek is not

Ogg has no concept of time. A granule position is a unitless marker whose meaning
each codec defines:

| | Vorbis | Opus |
|---|---|---|
| granule timebase | the stream's sample rate | **always 48 kHz** |
| start trim | none | `pre_skip`, subtracted from granule |
| header packets | 3 | 2 |
| usable output needs | two consecutive packets | ~80 ms to converge |

So page framing is genuinely reusable machinery and `ms → granule` genuinely is
not. A single "generic" helper would be off by `pre_skip` for Opus and by a
different amount for Vorbis. They are separate layers for that reason, and
`tests/real_files.rs` pins it with a real file: the Opus fixture's final granule
is 240 312, its pre-skip is 312, and 240 312 − 312 is exactly five seconds at
48 kHz.

### Why splicing has to rewrite pages

Emitting header pages followed by a distant tail renumbers page sequence numbers.
Ogg's checksum covers the whole page, so any header edit invalidates it — and a
stale checksum is one of the three things that make a decoder report a hole in the
data, alongside a sequence gap and a continuation-flag mismatch at the seam. The
splice layer therefore cannot be a zero-copy view; it re-serialises.

---

## Accuracy of `actual_start_ms`

Measured against ffmpeg, not asserted:

| Codec | Interior of the stream | Final page |
|---|---|---|
| **Opus** | exact | exact |
| **Vorbis** | exact to integer-millisecond rounding | within one long block (23.2 ms at 44.1 kHz) |

The final-page caveat is inherent rather than a defect. That page's granule
carries the encoder's end-of-stream trim, and separating the trim from real audio
needs the per-packet block sizes — which live inside the compressed data. A
splicer that deliberately does not decode cannot recover them. `earshot` states
the bound instead of claiming precision it cannot deliver.

What it *does* guarantee unconditionally: `actual_start_ms` is **never later than
requested**. A splice that overshot would silently drop audio the caller asked
for.

### One consequence to know about

Because granule positions stay absolute, container-level duration metadata still
describes the *original* track. A stream spliced at 3 s reports `duration=5.0065`
to `ffprobe` even though it carries two seconds of audio — the timeline genuinely
ends where the source ended.

That is the point: positions stay true to the source, so a consumer that seeks to
90 s sees 90 s. Use `duration_ms - actual_start_ms` for the emitted length, not the
container's duration field.

---

## Testing

59 tests. The interesting ones are the ones an independent tool can falsify.

```sh
cargo test          # everything
cargo test --lib    # byte core only: no fixtures, no ffmpeg
```

- **`ogg::crc`** — the table is cross-checked three ways: hand-computed entries, a
  bitwise implementation derived from the definition, and real encoder output. One
  test asserts the reflected variant's signature `0xEDB88320` never appears in the
  table; that single line catches the most likely bug in the project.
- **Roundtrip identity** — `--start-ms 0` must reproduce the input byte for byte.
  This exercises the entire emit path: parse every page, renumber it, recompute
  its checksum, write it back. Any error in header offsets, the segment table, or
  the CRC variant breaks it.
- **Bisection vs. linear** — granule bisection must agree with a naive forward
  scan for *every* reachable target, not a sampled few.
- **The load-bearing test** — earshot claims audio begins at `actual_start_ms`, so
  ffmpeg's decoded sample count must agree. That one number exercises the granule
  arithmetic, the codec seam, the chosen page, the renumbering, the checksum
  rewrite and the decoder-discard model at once.
- **Tail comparison** — decoded output must match the original's decoded tail
  sample for sample, proving the splice corrupts nothing downstream.
- **Never panics** — page parsing is fuzzed over pseudo-random input, and every
  truncation of a real file must produce an error rather than a panic.

Tests needing ffmpeg print an explicit `SKIPPED` line when it is absent, because a
silently-skipped oracle looks exactly like a working one.

### Regenerating fixtures

```sh
ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=44100:duration=5" -ac 2 \
       -c:a vorbis -strict -2 -y tests/fixtures/vorbis_5s.ogg
ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=5" -ac 2 \
       -c:a libopus -b:a 48k -y tests/fixtures/opus_5s.opus
```

The golden constants in `tests/real_files.rs` are tied to these files and would
need updating.

---

## CLI

```
earshot <uri> [--start-ms N]        Ogg on stdout, metadata on stderr
earshot probe <uri> [--start-ms N]  metadata JSON on stdout, no audio
earshot pages <file>                page structure and checksum validation
```

Unknown flags are **rejected**, not ignored: a silently dropped `--strat-ms`
would stream from the wrong place and look like a splice bug.

### Exit codes

The consumer's entire decision surface, so they are deliberately finer than
success/failure:

| Code | Meaning | Consumer action |
|---|---|---|
| 0 | Clean, including a closed pipe | none |
| 1 | Usage / bad URI | fix invocation |
| 2 | Transient source failure | retry |
| 3 | Permanently unavailable | skip track |
| 4 | Auth rejected | re-authenticate |
| 5 | Malformed stream | skip and report |

### `pages`

A debug aid, and a second opinion on whether something really is valid Ogg:

```console
$ earshot pages tests/fixtures/opus_5s.opus
  offset    seq  segs       granule   body   total         crc  flags
       0      0     1             0     19      47  0x15987e48  bos
      47      1     1             0     62      90  0x516ebae9
     137      2    50         48000   7930    8007  0x1225db74
     ...
   41392      7     1        240312    230     258  0x83b4eee6  eos

8 pages, 41650 bytes
  checksum failures: 0
  continued pages:   0
  granule -1 pages:  0
  final granule:     240312  (codec decides what this means in ms)
```

---

## Design notes

[DESIGN.md](DESIGN.md) derives the architecture from verified properties of Ogg,
Vorbis, Opus, HTTP Range and Unix pipes — each with a primary source — and records
what is still an open decision. Two worth knowing about here:

**Granule positions stay absolute.** RFC 7845 offers an alternative for Opus:
rewrite `OpusHead.pre_skip` to ≥3840 so the decoder trims exactly to the target,
which is sample-exact. But `pre_skip` is *also* subtracted from every granule
position, so raising it shifts the whole reported timeline by the difference
(312 → 3840 is 73.5 ms). A consumer drawing a progress bar against the original
track would then be wrong for the entire stream. earshot keeps granules absolute,
starts slightly early, and reports where.

**Pause is bounded.** A Linux pipe holds 64 KiB — about 1.6 s at 320 kbps — so a
paused producer parks almost immediately while holding an open connection to a
possibly time-limited URL. Backpressure is the mechanism; a ceiling on it is the
policy, and it belongs in the contract rather than being discovered in production.

---

## Credits

Understanding of Spotify's audio path — the AES-128-CTR keystream indexed by
absolute byte offset, the 167-byte prepended metadata packet, the CDN range
protocol — comes from reading [librespot](https://github.com/librespot-org/librespot)
(MIT) and [myx](https://github.com/HaseebKhalid1507/Myx) (MIT). No code is copied;
both are credited for the reverse engineering they made legible.

Format work follows [RFC 3533](https://www.rfc-editor.org/rfc/rfc3533.html) (Ogg),
the [Vorbis I specification](https://xiph.org/vorbis/doc/Vorbis_I_spec.html), and
[RFC 7845](https://datatracker.ietf.org/doc/html/rfc7845) (Ogg Opus).

## License

MIT — see [LICENSE](LICENSE).
