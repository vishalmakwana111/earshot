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
earshot host                        # serve a listening room (see below)
```

Settings layer, highest first: **command line > `EARSHOT_*` >
`~/.config/earshot/earshot.toml` > defaults.** An unknown key or a bad value is an
error naming the file and line — never a silent skip, for the same reason unknown
flags are rejected.

`<uri>` is `file://path`, a bare path, `http(s)://…`, or — with a room configured —
a `spotify:track:…` / `room:spotify:track:…` played through a [listening
room](#listening-rooms). The credential-bearing `room://token@host/…` form is
refused: a token in a URI leaks into `ps`, shell history and argv.

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

## Listening rooms

One account, many listeners. A **host** holds the session and hands out keys; each
**guest** is a stateless decrypt-and-splice pipe that carries no credential of its
own. A listener who can reach the host can play — there is no per-account setup,
and the whole maintenance surface is the one host box.

```text
  earshot <track>            earshot host              your engine
  (guest — no credential)    (this tool)               (holds the session)
       │                          │                         │
       ├─ POST /resolve ─────────►│                         │
       │                          ├─ POST /engine-resolve ─►│
       │                          │◄─ url + key_hex ────────┤
       │◄─ key + signed CDN url ──┤                         │
       ├─ GET /audio/… (Range) ──►├─ ranged GET ───────────►│
       │◄─ 206 ───────────────────┤◄─ 206 ──────────────────┤
       └─ decrypt · skip 0xa7 · splice · Ogg on stdout
```

### Guest

```bash
export EARSHOT_ROOM_HOST=192.168.1.10:8787
export EARSHOT_ROOM_TOKEN=…                 # prefer the env var; it stays out of `ps`
earshot spotify:track:4cOdK2wGLETKBW3PvgPWqT --start-ms 30000
```

CDN URLs on non-public addresses are refused by default, so a compromised room
cannot use guests to probe inside your network. Name the network your room
actually lives on:

```bash
export EARSHOT_ROOM_ALLOW_NETWORKS=100.64.0.0/10   # a Tailscale room
#                                  192.168.0.0/16  # a LAN room
#                                  127.0.0.0/8     # a local test server
```

A list rather than an "allow private" switch because each real case is one
specific range, while a blanket permission would also unblock `169.254.0.0/16` —
where cloud metadata services answer.

### Host

earshot serves the room; it does **not** log in to Spotify. The session lives in an
external *engine* you point it at, which is the one thing earshot will not do.

```bash
export EARSHOT_HOST_BIND=192.168.1.10:8787    # the address guests reach
export EARSHOT_HOST_ENGINE=http://127.0.0.1:9090
export EARSHOT_ROOM_TOKEN=…                   # omit and the host mints one, printed once
earshot host
```

| Setting | Env | Meaning |
|---|---|---|
| `host_bind` | `EARSHOT_HOST_BIND` | where the host listens **and** what its CDN URLs advertise |
| `host_engine` | `EARSHOT_HOST_ENGINE` | base URL of the engine holding the session |
| `room_token` | `EARSHOT_ROOM_TOKEN` | the shared credential; minted if unset |
| `host_tls_cert` / `host_tls_key` | `EARSHOT_HOST_TLS_*` | serve the room over https (`tls` feature) |

`host_bind` must be a concrete address, because it is also what guests are told to
fetch. A wildcard (`0.0.0.0`) is refused rather than minting a
`http://0.0.0.0:8787/audio/…` that nothing can retrieve; `:0` picks a free port and
the real one is announced on stdout.

### The engine contract

One POST. Anything that speaks it works — in practice
[myx](https://github.com/HaseebKhalid1507/Myx)'s room binary.

```text
POST <host_engine>/engine-resolve
  {"uri": "spotify:track:…"}
→ 200 {"uri": "…", "format": "OGG_VORBIS_320", "key_hex": "<32 hex>",
       "url": "<absolute URL of the already-encrypted audio file>",
       "expires_in": 3600}          // optional, seconds
  or 400 {"error": "…"}
```

The host resolves **once per track, not once per listener** — a room of a hundred
people costs the engine one call. `expires_in` is how you keep that honest: state
how long the URL stays fetchable and the host reuses it for a fraction of that,
capped. Omit it and the host reuses for 30 s, enough to collapse the stampede when
everyone starts the same song. Either way, a URL the engine later refuses
(`401/403/404/410`) is dropped immediately and the next listener re-resolves, so a
wrong lifetime costs one request rather than sticking.

That URL must serve the real artifact — `0xa7` junk bytes, then the Ogg stream,
AES-128-CTR encrypted under `key_hex` — because the guest builds
`Window<Decrypt<HttpSource>>` over it and the `OggS` probe at `0xa7` is what
authenticates the result. The host never re-encrypts or inspects the body.

What the host guarantees, and what it does not:

- **The engine's address never reaches a guest.** `/resolve` returns URLs on the
  host; the engine URL travels base64'd inside an id whose signature only the host
  can mint (`SHA-256(secret ‖ id ‖ "|" ‖ exp)`, secret derived from the token).
  Links expire after 30 minutes.
- **A hostile engine is treated like a hostile host.** `format`, `key_hex` and
  `url` get the same validation a guest applies to a resolve reply, so a
  compromised engine cannot push a non-Ogg body or a bad key to listeners.
The host tolerates an engine that closes connections — HTTP/1.0, a restart, a
proxy's request ceiling — by never reusing one and by replaying a request whose
connection died before any response arrived. Engine failures are logged rather
than collapsed into a bare `502`, because at the guest a silent one reads as
"not a Spotify Ogg file" and sends you hunting for a key bug that isn't there.

### Over Tailscale

The hard part of a room is not encryption, it's **reachability**: for a listener
off your LAN you otherwise need port forwarding, dynamic DNS and a firewall hole.
A tailnet removes all three and issues a real certificate, so this is the least
work for a room that plays from anywhere.

```bash
# host
tailscale cert your-host.your-tailnet.ts.net
export EARSHOT_HOST_BIND=100.101.102.103:8787          # your tailnet address
export EARSHOT_HOST_TLS_CERT=your-host.your-tailnet.ts.net.crt
export EARSHOT_HOST_TLS_KEY=your-host.your-tailnet.ts.net.key
earshot host
```

```bash
# guest
export EARSHOT_ROOM_HOST=100.101.102.103:8787
export EARSHOT_ROOM_TLS=true
export EARSHOT_ROOM_ALLOW_NETWORKS=100.64.0.0/10       # tailnet space is CG-NAT
export EARSHOT_ROOM_TOKEN=…
earshot spotify:track:…
```

`room_allow_networks` is required here because Tailscale hands out
`100.64.0.0/10`, which is CG-NAT and blocked by default. Naming the tailnet
admits exactly that — `169.254.169.254` and RFC1918 stay refused.

No `room_ca_cert` is needed: `tailscale cert` issues a publicly trusted
certificate, so guests verify against the normal roots. WireGuard is already
encrypting underneath, which makes TLS here defence in depth rather than the only
thing between a listener and the audio key.

The tradeoff is that every listener must be on your tailnet — right for a handful
of known people, wrong for "here's a link". For that, use a public address and a
normal certificate.

### Encrypting the room

`/join` and `/resolve` carry the shared token and the audio key, so in the clear
anyone on the path can decrypt what the room is playing. The Spotify session never
crosses that wire — it stays in the engine — so this is about the room, not the
account. A plaintext host says so on startup.

Build with `--features tls`, then give the host a certificate:

```bash
export EARSHOT_HOST_TLS_CERT=/etc/earshot/room.crt   # leaf + issuer chain
export EARSHOT_HOST_TLS_KEY=/etc/earshot/room.key
earshot host                                          # now serves https, mints https CDN URLs
```

```bash
export EARSHOT_ROOM_TLS=true
export EARSHOT_ROOM_CA_CERT=/etc/earshot/room-ca.crt  # omit if publicly signed
earshot spotify:track:…
```

A room usually has no publicly-signed name, so guests are pointed at the
certificate to trust. There is deliberately **no** switch to skip verification: it
would leave the channel safe from someone listening and wide open to someone
interposing, while looking secure from the outside. Setting only one of
`host_tls_cert`/`host_tls_key` is a startup error rather than a silent downgrade
to plain HTTP.

## Architecture

Five layers, each testable over bytes — no audio device and no Spotify session
anywhere in the test suite. The only network is loopback, against a fake upstream the
tests start themselves.

| Layer | Job |
|---|---|
| `source` | `trait Source { size, read_at }` — `file://` ✅, `http(s)://` ✅, room ✅ |
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
| **M2** room guest — ranged HTTP + AES-CTR decrypt | ✅ |
| **M3** `host` — room server + signed CDN, engine-backed | ✅ |

Working today: `file://`, a bare path, `http(s)://`, or a listening room; Ogg Vorbis
and Ogg Opus; `--start-ms` seeking by granule bisection; layered config; the bounded
idle ceiling; metadata; and the full exit-code contract.
Remote reads handle the CDN quirks in `DESIGN.md` A9 — a range larger than the file
answering `200`, resources rotating mid-stream, and `416` carrying the length.

The host deliberately holds **no** Spotify credential: it wraps an external engine
that does. That is why the `oauth.rs`/PKCE of the original plan does not exist —
see [DESIGN.md](DESIGN.md) Part 5.

## Testing

152 tests. The ones that can actually falsify something:

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
- **Audio through a whole room is byte-identical to the same file on disk**, at
  every offset — a real `earshot host` subprocess over a fake engine, consumed by a
  real `earshot` guest, so the resolve, the signature, the range proxying, the
  AES-CTR offset and the `0xa7` skip are all in the path being compared.
- **A correctly signed but expired CDN URL is refused.** The test recomputes the
  host's HMAC from the shared token, which is what separates "expiry is enforced"
  from "the signature happened to be wrong" — as are signatures from the wrong
  secret and signatures lifted from another file.
- **The host serves listeners concurrently**, asserted structurally rather than by
  timing: the fake engine refuses to answer until several requests are inside it at
  once, which a host that queued them could never arrange.
- **A wrong key fails loudly instead of streaming garbage** — the `OggS` probe at
  `0xa7` is what catches it.
- **Naming one network admits it and nothing else** — allowing a tailnet leaves
  `169.254.169.254`, RFC1918 and loopback refused, and `100.0.0.0/8` at large
  stays public while `100.64.0.0/10` stays blocked.
- **Over TLS, a guest without the room's CA is refused** — and one trusting an
  unrelated CA too. Without that pair, `room_ca_cert` would be decoration over a
  channel nobody verifies. The certificates are minted during the test, so
  nothing expires on a date nobody chose.
- **The host opens a fresh engine connection per request**, asserted on the
  engine side by counting connections against requests. Reuse was a real bug:
  pooled sockets that the engine had closed surfaced at the guest as "not a
  Spotify Ogg file", roughly 7 times per 40 concurrent plays.
- **Ten listeners on one track cost the engine one resolve**, and a URL the
  engine later disowns is dropped rather than served to the next person.
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
