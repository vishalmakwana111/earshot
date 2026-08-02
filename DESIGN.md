# earshot — design

A small CLI that turns a URI into an Ogg stream on stdout with precise
`--start-ms` splicing. A building block for audio applications; `myx`'s external
source is one consumer, not the reason for existing.

**Contract.** `earshot <uri> [--start-ms N]` → Ogg on stdout, logs on stderr,
meaningful exit codes. Stateless per invocation: kill = dispose, seek = respawn.

This document is written bottom-up. Part 1 records facts about the formats and
the OS that were verified against primary sources; Part 2 derives the
architecture from them. Where the two disagree, Part 1 wins — and if a fact in
Part 1 turns out to be wrong, the derivation that depends on it should be redone
rather than patched.

---

## Part 1 — Verified axioms

| # | Fact | Consequence |
|---|---|---|
| **A1** | Granule position's meaning is **codec-defined**; Ogg has no concept of time, only unitless increasing markers | A generic Ogg layer cannot do `ms → granule` |
| **A2** | Granule counts samples of packets **finishing** on a page; pages where none finish carry **−1** | Bisection must skip −1; a rewrite must preserve it verbatim |
| **A3** | `header_type` bit `0x01` marks a first packet **continued** from the previous page | The splice target must have this bit clear |
| **A4** | CRC covers the whole page with its CRC field zeroed: poly `0x04c11db7`, **non-reflected, init 0, no final XOR** | Any header edit ⇒ recompute. An off-the-shelf `crc32` is silently wrong |
| **A5** | `page_sequence_number` is **per-serial**, and gaps are visible to decoders | Splicing needs renumbering |
| **A6** | Vorbis is a lapped transform: **two consecutive packets** are needed before any PCM is usable. Its own trim mechanism requires the first audio page to hold *exactly two* packets | An exact Vorbis splice at arbitrary ms is impossible without pre-roll |
| **A7** | Opus granule is **always at 48 kHz**; `pre_skip` is both an output trim and a granule offset (`pcm_pos = granule − pre_skip`); RFC 7845 **recommends ≥3840 samples (80 ms)** of pre-skip when cropping the start of an existing stream | Opus splice has a spec-blessed, sample-exact recipe |
| **A8** | librespot's `AudioDecrypt` is AES-128-CTR (`Ctr128BE`) with fixed IV `72e067fb…630d93`, and implements `Seek` by calling `cipher.seek(absolute_byte_offset)` | The keystream is indexed by **absolute file offset** — random access is free *if the offset is known* |
| **A9** | Spotify serves audio from its CDN over **Range** requests; a range larger than the file returns **200, not 206**; `ETag` + `If-Range` makes a rotated resource return 200 rather than a mismatched chunk | The HTTP reader must handle both quirks |
| **A10** | `SPOTIFY_OGG_HEADER_END = 0xa7` (167 bytes) is a **malformed Ogg packet Spotify prepends** carrying normalisation metadata, and applies to `OGG_VORBIS` only — not their AAC or FLAC | This is Spotify-specific, **not** generic Ogg work |
| **A11** | Rust's std sets `SIGPIPE` to `SIG_IGN` before `main`, so writes to a closed pipe return `EPIPE` → `ErrorKind::BrokenPipe`. `SIG_IGN` is inherited across `exec` | Exit-0-on-EPIPE needs **no** configuration |
| **A12** | Linux pipe capacity is **64 KiB** (16 pages). `F_SETPIPE_SZ` is Linux-only — XNU lacks it — and is capped by `/proc/sys/fs/pipe-max-size` (default 1 MiB) | The "pause" window is ~1.6 s at 320 kbps, ~3.3 s at 160 kbps, and not portably tunable |
| **A13** | A decoder handed a *spliced* stream discards its head: Vorbis loses `blocksize_1 / 2` (1024 samples = 23.2 ms at 44.1 kHz), Opus loses `pre_skip` (312 samples with libopus defaults). **Measured against ffmpeg, not derived** | `actual_start_ms` must account for it, or it is optimistic by a block |
| **A14** | A stream's **final page** carries the encoder's end-of-stream trim inside its granule (640 samples in our Vorbis fixture), and separating trim from audio needs per-packet block sizes — which live inside the compressed data | Exact prediction at the tail is impossible without decoding; state the bound instead |

**Sources.** [RFC 3533 (Ogg)](https://www.rfc-editor.org/rfc/rfc3533.html) ·
[Ogg framing](https://xiph.org/vorbis/doc/framing.html) ·
[Vorbis I spec](https://xiph.org/vorbis/doc/Vorbis_I_spec.html) ·
[stb_vorbis seek notes](http://nothings.org/stb_vorbis/ogg_seek.txt) ·
[RFC 7845 (Ogg Opus)](https://datatracker.ietf.org/doc/html/rfc7845) ·
[librespot `decrypt.rs`](https://github.com/librespot-org/librespot/blob/dev/audio/src/decrypt.rs) ·
[librespot `player.rs`](https://github.com/librespot-org/librespot/blob/dev/playback/src/player.rs) ·
[librespot `fetch/mod.rs`](https://docs.rs/librespot-audio/latest/src/librespot_audio/fetch/mod.rs.html) ·
[librespot #309 (CDN migration)](https://github.com/librespot-org/librespot/issues/309) ·
[pipe(7)](https://www.man7.org/linux/man-pages/man7/pipe.7.html) ·
[Rust `unix_sigpipe`](https://github.com/rust-lang/rust/issues/97889)

### Locally confirmed

A4, A7, A13 and A14 are not taken on trust. `tests/fixtures/` holds five seconds
of a 440 Hz sine encoded by ffmpeg as both Vorbis and Opus.

- `tests/real_files.rs` checks every page's checksum against our own table (15
  pages, two codecs) and asserts the Opus relationship directly: final granule
  240 312 − pre-skip 312 = 240 000 = exactly 5 s at 48 kHz.
- `tests/end_to_end.rs` splices at a sweep of offsets, decodes with ffmpeg, and
  requires the decoded sample count to match `duration_ms − actual_start_ms`.
  A13's two constants came out of that measurement: the Vorbis shortfall was a
  flat 23 ms (1024 samples = `blocksize_1 / 2`) and correcting for it made Opus
  land on exact millisecond boundaries.

**Resulting accuracy of `actual_start_ms`:**

| Codec | Interior | Final page |
|---|---|---|
| Opus | exact | exact |
| Vorbis | exact to integer-ms rounding | within one long block (23.2 ms) |

Unconditional guarantee either way: `actual_start_ms` is **never later than
requested**. Overshooting would silently drop audio the caller asked for.

---

## Part 2 — Derivations

**D1 (from A1, A2, A7).** `ms ↔ granule` is codec-specific, and not cosmetically
so. ⇒ Three layers, not two: `ogg` (framing) → `codec` (granule semantics) →
`splice` (policy).

**D2 (from A4, A5).** Splicing edits headers, which invalidates checksums. ⇒ The
splice layer cannot be a zero-copy view; `ogg` needs a **serialiser**, and output
is re-rendered pages.

**D3 (from A6, A7).** An exact splice at an arbitrary millisecond is impossible.
⇒ `actual_start_ms` is **load-bearing contract**, not a nicety: without it the
consumer's clock drifts by up to a page.

**D4 (from A8, A9).** Both interesting sources are randomly accessible, and CTR
is seekable by construction. ⇒ The source abstraction must be **offset-addressed**;
a `Read`-only chain degrades `--start-ms` to a linear scan and makes mid-stream
resume impossible.

**D5 (from A3).** The splice target must be a page whose continuation flag is
clear, or the decoder receives a packet fragment.

**D6 (from A12).** Pause-by-backpressure yields ~2 s, then the producer parks
holding an open connection to a time-limited URL. ⇒ Pause must be **bounded**;
past the bound, dispose and let the consumer respawn.

**D7 (from A11).** Exit-0-on-EPIPE is free, but a full **stderr** pipe deadlocks
the writer. ⇒ Logging must never block, and the consumer contract must say so.

**D8 (from A10).** The 167-byte strip belongs to the Spotify source, not the
generic core.

---

## Part 3 — Architecture

```
uri
 │
 ▼
Source  (offset-addressed: len() + read_at)
 ├─ file://    → positioned reads
 ├─ http(s):// → ranged reader: ETag/If-Range, resume-from-offset,
 │                URL fallback, the 200-instead-of-206 quirk        (A9)
 └─ room://    → ranged HTTP + remote resolver
                  └─ Decrypt<…>   keystream at absolute offset      (A8)
                       └─ Window<…>  start = 0xa7                   (A10)
 │
 ▼
ogg::framing     page scan · parse · SERIALISE · CRC                (A4, D2)
 │
 ▼
codec            Vorbis | Opus: header count, granule↔ms, pre-roll   (D1)
 │
 ▼
splice           bisect on granule (skip −1) → page with cont-flag clear
                 → rewrite ID header (Opus pre_skip) → renumber → re-CRC
 │
 ▼
sink             write; BrokenPipe → exit 0; stderr never blocks    (D7)
```

### The trait everything hangs off

```rust
/// A random-access byte window. Every source and every transform is one.
trait Source {
    fn len(&self) -> Option<u64>;                              // None = unbounded
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize>;
}
```

Transforms stay decorators — they just decorate `Source` instead of `Read`:

```rust
struct Decrypt<S> { inner: S, key: Key }   // keystream_at(off); A8 makes this exact
struct Window<S>  { inner: S, start: u64 } // read_at(o) → inner.read_at(o + start)
```

`Window { start: 0xa7 }` is librespot's `Subfile` generalised, and because it is
offset-preserving, bisection still works straight through it. A room track
composes as `Window<Decrypt<HttpRanged>>` and the Ogg layer above never knows.

This is the one place the original sketch was structurally wrong: it described
sources as `Read` adapters, which reads as a simplification but silently gives up
`O(log n)` seeking and byte-range resume — the two properties that make the tool
good at its job.

### Splice policy per codec

| | Vorbis | Opus |
|---|---|---|
| granule units | samples at stream rate | samples at 48 kHz, always |
| start trim mechanism | none | `pre_skip` |
| splice recipe | back up one page so the decoder gets its overlap partner; report the earlier `actual_start_ms` | back up ≥80 ms; rewrite `OpusHead.pre_skip` to ≥3840; re-CRC that page |
| accuracy | within one page | sample-exact |

### Module layout

Marked against what exists, because a layout diagram that describes intentions
rather than files is worse than none.

```
src/
  main.rs        ✅ dispatch: <uri> | probe | pages        (host, sources: M3)
  source/
    mod.rs       ✅ trait Source + registry by scheme
    file.rs      ✅ positioned reads
    mem.rs       ✅ in-memory, for tests
    http.rs      ⬜ M2  ranged reader: fallback, If-Range, resume, timeouts
    decrypt.rs   ⬜ M2  Decrypt<S>  — offset-indexed CTR
    window.rs    ⬜ M2  Window<S>   — offset shift
  ogg/
    crc.rs       ✅ the trap; own table, known-answer tested
    page.rs      ✅ parse + serialise + in-place patchers, roundtrip-exact
    scan.rs      ✅ read-at-offset, resync, granule bisection
  codec.rs       ✅ Vorbis + Opus granule semantics
  splice.rs      ✅ policy, plan/emit split, page rewriting
  config.rs      ⬜ M2  CLI > EARSHOT_* > ~/.config/earshot/earshot.toml
  room/
    client.rs    ⬜ M2  protocol client, strict validation
    host.rs      ⬜ M3  the `host` subcommand, isolated from the pipeline
  oauth.rs       ⬜ M3  PKCE (host only)
```

Two deviations from the original sketch, both deliberate:

- **`codec.rs` is one file, not a `codec/` directory.** At ~200 lines covering two
  codecs, a directory would be structure for its own sake. It splits when a third
  codec arrives.
- **There is no `sink.rs`.** Backpressure and `BrokenPipe` handling turned out to
  be three lines inside `splice::emit`, where the bytes already are. A module
  boundary there would separate the write from the only thing that writes.

---

## Part 4 — Consumer contract

**stdout** — Ogg bytes, nothing else, ever.

**stderr** — structured logs. *The consumer must inherit or drain stderr* (D7).
Logging drops lines rather than blocking. Key material carries a redacting
`Debug`; it must never reach a log line.

**Metadata** — one JSON line before the first stdout byte. Reserved for **fd 3**;
M1 writes it to stderr prefixed `earshot-meta:` instead, because detecting whether
fd 3 is even open needs platform-specific probing and unsafe descriptor handling
that is not worth carrying yet. `earshot probe <uri>` prints the same JSON to
stdout with no audio, which is what scripts and tests should use.

```json
{"codec":"vorbis","rate":44100,"channels":2,"duration_ms":214533,
 "requested_start_ms":300000,"actual_start_ms":299720,
 "start_granule":13217612,"container_offset":167}
```

**Exit codes** — the consumer's whole decision surface, so 0/1/2 is too coarse:

| Code | Meaning | Consumer action |
|---|---|---|
| 0 | Clean, including `BrokenPipe` | none |
| 1 | Usage / bad URI | fix invocation |
| 2 | Transient source failure | retry |
| 3 | Permanently unavailable | skip track |
| 4 | Auth / token rejected | re-authenticate |
| 5 | Malformed stream (truncated, bad CRC) | skip and report |

**Pause** — the mechanism is backpressure; the policy is bounded.
`--max-idle <dur>` (default 60 s) exists because a parked producer holds a
time-limited URL open (D6). On expiry, exit distinctly and let the consumer
respawn at the saved position.

**Also required:** connect/read/total timeouts, `SIGTERM` → clean exit, and a
truncated stream at EOF exits 5 rather than 0.

---

## Part 5 — Milestones

**M0 — the byte core. ✅ done.** `ogg::crc` and `ogg::page`: parse, serialise,
packet walk, checksum. No dependencies, no I/O. Every trap found in Part 1 lives
here, which is why it shipped before any source existed.

The CRC table is cross-checked three independent ways — hand-computed entries, a
bitwise implementation derived from the definition, and real ffmpeg output.

**M1 — the tool. 🟡 `file://` working.** Delivered: the `Source` trait with
`file://` and an in-memory backend, `ogg::scan` (read-at-offset, resync, granule
bisection), the `codec` seam for Vorbis and Opus, `splice` with plan/emit split,
the metadata line, and the full exit-code contract. 59 tests, including 13 that
drive the real binary and check its output with ffmpeg.

Still to do for M1: `http://` (ranged reader with `If-Range`, resume and URL
fallback), `--max-idle`, and layered config.

Three bugs worth recording, because each was found by a test that a weaker suite
would not have contained:

- **`resync` clamped its read to the search limit**, so a page starting one byte
  below the limit was invisible — four bytes of capture pattern would not fit. The
  bisection then silently returned a page one too early. Caught by requiring
  bisection to agree with a linear scan at *every* target rather than a sampled few.
- **The splice chose the page before the target.** A page spans
  `(granule(P-1), granule(P)]`, so the page holding a sample is the first with
  granule ≥ target, not the last with granule ≤ target.
- **`actual_start_ms` was optimistic by one block**, until A13 was measured.

**M2 — `room://`.** `Decrypt` and `Window` decorators plus a strict-validation
protocol client. Small *because* M1 gets the trait right.

**M3 — `host` + polish.** README, docs, hardening.

M1 standing alone is a real property, not a story — but note that M1 as specified
is close to `ffmpeg -ss N -i URI -c copy -f ogg -`. What actually differentiates
it is the pair ffmpeg will not hand you cleanly: a reported `actual_start_ms`, and
a first-class dispose/backpressure contract. Those should lead the README.

---

## Part 6 — Testing strategy

Byte-exact goldens alone are brittle — change page segmentation and every fixture
fails for no real reason. So, layered:

1. **CRC known-answer**, including the *negative* assertion that the reflected
   variant's signature `0xEDB88320` never appears in the table. That one line
   catches the single most likely bug in the project.
2. **Roundtrip identity** — `parse → serialise` is byte-identical on real files,
   which proves the serialiser before it is trusted to rewrite headers.
3. **Property tests** — lacing sums equal body length; packet spans tile the
   body; continuation flags agree across page boundaries; granule monotonic or −1.
4. **Fuzz the page parser.** "Never panics on hostile input" is a claim a fuzzer
   verifies; a hand-written parser over attacker-influenced bytes is where it
   would otherwise fail. `fuzz/fuzz_targets/page_scan.rs` exists and also asserts
   roundtrip identity over arbitrary input. It needs nightly, so it is local-only
   until someone has run it; CI carries a bounded pseudo-random stand-in instead.
   Wiring it into CI is deliberately deferred rather than shipped unverified.
5. **Splice invariants**, not byte goldens: first output audio page has its
   continuation flag clear, granule ≥ target, sequence numbers contiguous per
   serial, every emitted page self-verifies.
6. **Decode assertion** — pipe output through `symphonia`/`lewton` as a
   dev-dependency and assert the first decoded sample lands within one packet of
   `actual_start_ms`. This is the test that proves the whole thesis.
7. **Fake upstream** covering the three real quirks: over-large range → 200,
   `ETag` rotation mid-stream, connection drop at 70% → resume from offset.

---

## Part 7 — Risk register

**The Spotify key path is M2's dominant risk, and it is inherited rather than
created.** There are widespread reports of `audio key error 0 1` on librespot
through late 2025 including 0.8.0; PlayPlay has never been publicly reversed; the
Widevine route needs a CDM from a physical device and does not scale. Calibration:
librespot-based players do work today for many accounts, so the legacy path is
degraded rather than dead. The structural mitigation is the seam already drawn —
if `AudioKey` dies it lands entirely on `host`, and M0/M1 are untouched.

**`room://` security**, beyond strict schema / hex-key / scheme validation:

- **SSRF.** `http(s)://` does not exclude `http://169.254.169.254/` or
  `http://localhost:8080/`. Resolve DNS *then* reject loopback, link-local and
  RFC1918, or use an allowlist. Otherwise a compromised room server turns every
  guest into an internal-network prober.
- **Specify the IV.** Per A8 it is a fixed constant with the counter at the
  absolute byte offset. Write that into the protocol rather than leaving it
  implicit.
- **Token lifecycle.** A password-style token with no expiry, revocation or rate
  limit means one leak is unlimited streaming off the host's account, forever.
- **CTR gives confidentiality, not integrity.** Bit flips decrypt to garbage that
  reaches the decoder. librespot inherits this too, so it is not ours — but
  "strict validation at the trust boundary" should not imply the boundary is
  sealed.

**Terms of service.** Re-streaming one Premium account's audio to other people is
materially different from librespot's single-user case and plausibly breaches
Spotify's developer terms; the realistic downside is the host's account plus a
repo takedown. Recorded here so it stays a deliberate decision. M0–M1 are
unaffected.

---

## Part 8 — Decisions

### Settled during M1

**Granule positions stay absolute; the splice starts early and reports where.**
RFC 7845's alternative for Opus — rewrite `OpusHead.pre_skip` to ≥3840 so the
decoder trims exactly to the target — is sample-exact, but `pre_skip` is *also*
subtracted from every granule position, so raising it from 312 shifts the entire
reported timeline by 73.5 ms. A consumer drawing a progress bar against the
original track would be wrong for the whole stream. Absolute granules plus an
honest `actual_start_ms` is the better trade; the rewrite stays available for a
deliberately re-timed stream.

The visible cost: container duration metadata still describes the original track.
A stream spliced at 3 s reports `duration=5.0065` to `ffprobe` while carrying two
seconds of audio, because the granule timeline genuinely still ends where the
source ended. Consumers must use `duration_ms − actual_start_ms` for the emitted
length rather than the container's duration field — which is documented in the
README, since it is exactly the kind of thing that otherwise reads as a bug.

**Pre-roll is a packet requirement, not a page one.** The first version stepped
back a whole page, which in a file with ~1 s pages meant starting a full second
early. The packets earlier in the *chosen* page already supply Vorbis's overlap
partner, so the splice only steps back when the page alone does not reach
`preroll_ms` before the target. This is why `Codec::preroll_ms` exists and
`preroll_pages` does not.

**Unknown CLI flags are errors.** A silently ignored `--strat-ms` produces a
stream that starts in the wrong place and looks like a bug in the splice.

### Still open

1. **Whether `host` ships at all**, given Part 7.
2. **Whether to close the final-page gap.** A14 means Vorbis prediction is up to
   one block off at the tail. Closing it needs per-packet block sizes, i.e.
   partial decoding — which would cost earshot its "never decodes" property. The
   current answer is to state the bound; revisit only if a consumer needs
   sample-exact tails.
3. **`--max-idle` is specified but not implemented.** D6 says pause must be
   bounded; M1 has no timer. Needs doing before any long-lived source (M2) makes
   it matter.
