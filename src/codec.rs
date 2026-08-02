//! Codec-specific granule semantics — the seam that cannot live in `ogg`.
//!
//! RFC 3533 is explicit that a granule position is a unitless marker whose
//! meaning belongs to the codec's media mapping. The two codecs earshot handles
//! disagree in ways that are not cosmetic:
//!
//! | | Vorbis | Opus |
//! |---|---|---|
//! | granule timebase | the stream's sample rate | **always 48 kHz** |
//! | start trim | none | `pre_skip`, subtracted from granule |
//! | header packets | 3 (id, comment, setup) | 2 (`OpusHead`, `OpusTags`) |
//! | usable output needs | two consecutive packets (lapped transform) | ~80 ms to converge |
//!
//! A single "generic" `ms → granule` helper would be off by `pre_skip` for Opus
//! (312 samples with libopus defaults) and off by a different amount for Vorbis.
//! Hence this module. `tests/fixtures/opus_5s.opus` pins the relationship with a
//! real file: final granule 240 312 − pre-skip 312 = 240 000 = 5 s at 48 kHz.

/// Why a stream's identification header could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The first packet matches no codec earshot knows.
    Unrecognised,
    /// The identification header is shorter than its own definition allows.
    HeaderTooShort { need: usize, got: usize },
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrecognised => write!(
                f,
                "unrecognised codec: expected an Ogg Vorbis or Ogg Opus identification header"
            ),
            Self::HeaderTooShort { need, got } => {
                write!(f, "identification header too short: need {need}, got {got}")
            }
        }
    }
}

impl std::error::Error for CodecError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vorbis {
    pub channels: u8,
    /// Also the granule timebase.
    pub rate: u32,
    /// Short block size, `2^(byte 28 & 0x0f)`.
    pub blocksize_0: u32,
    /// Long block size, `2^(byte 28 >> 4)`. Half of it is the overlap region,
    /// and therefore how much audio a decoder cannot reconstruct at a splice.
    pub blocksize_1: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opus {
    pub channels: u8,
    /// Samples at 48 kHz to discard, and to subtract from any granule position.
    pub pre_skip: u64,
    /// Informational only; decoding is always at 48 kHz.
    pub input_rate: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Vorbis(Vorbis),
    Opus(Opus),
}

impl Codec {
    /// Identify a stream from its first packet.
    pub fn identify(first_packet: &[u8]) -> Result<Codec, CodecError> {
        if first_packet.starts_with(b"\x01vorbis") {
            // id(1) magic(6) version(4) channels(1) rate(4) bitrates(12)
            // blocksizes(1) framing(1) = 30 bytes, fixed.
            if first_packet.len() < 30 {
                return Err(CodecError::HeaderTooShort {
                    need: 30,
                    got: first_packet.len(),
                });
            }
            // Two 4-bit exponents packed into one byte.
            let packed = first_packet[28];
            return Ok(Codec::Vorbis(Vorbis {
                channels: first_packet[11],
                rate: u32::from_le_bytes([
                    first_packet[12],
                    first_packet[13],
                    first_packet[14],
                    first_packet[15],
                ]),
                blocksize_0: 1u32 << (packed & 0x0f),
                blocksize_1: 1u32 << (packed >> 4),
            }));
        }

        if first_packet.starts_with(b"OpusHead") {
            // magic(8) version(1) channels(1) pre_skip(2) rate(4) gain(2) map(1)
            if first_packet.len() < 19 {
                return Err(CodecError::HeaderTooShort {
                    need: 19,
                    got: first_packet.len(),
                });
            }
            return Ok(Codec::Opus(Opus {
                channels: first_packet[9],
                pre_skip: u16::from_le_bytes([first_packet[10], first_packet[11]]) as u64,
                input_rate: u32::from_le_bytes([
                    first_packet[12],
                    first_packet[13],
                    first_packet[14],
                    first_packet[15],
                ]),
            }));
        }

        Err(CodecError::Unrecognised)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Codec::Vorbis(_) => "vorbis",
            Codec::Opus(_) => "opus",
        }
    }

    pub fn channels(&self) -> u8 {
        match self {
            Codec::Vorbis(v) => v.channels,
            Codec::Opus(o) => o.channels,
        }
    }

    /// Samples per second that a granule position counts in.
    ///
    /// For Opus this is 48 000 regardless of the decode rate or the `input_rate`
    /// recorded in `OpusHead`.
    pub fn granule_rate(&self) -> u32 {
        match self {
            Codec::Vorbis(v) => v.rate,
            Codec::Opus(_) => 48_000,
        }
    }

    /// Offset subtracted from a granule position to get a PCM sample position.
    pub fn pre_skip(&self) -> u64 {
        match self {
            Codec::Vorbis(_) => 0,
            Codec::Opus(o) => o.pre_skip,
        }
    }

    /// Number of packets before audio begins.
    pub fn header_packets(&self) -> usize {
        match self {
            Codec::Vorbis(_) => 3,
            Codec::Opus(_) => 2,
        }
    }

    /// Audio a decoder needs before the target for its output to be trustworthy.
    ///
    /// Vorbis needs only the packet preceding the target, so the lapped
    /// transform has an overlap partner. That is a *packet* requirement, and the
    /// packets earlier in the same page satisfy it — hence zero extra time.
    ///
    /// Opus is different: RFC 7845 recommends 80 ms when cropping the start of an
    /// existing stream, because after a mid-stream cut the decoder has no
    /// preceding packets at all and needs that long to converge.
    pub fn preroll_ms(&self) -> u64 {
        match self {
            Codec::Vorbis(_) => 0,
            Codec::Opus(_) => 80,
        }
    }

    /// Samples a decoder discards at the head of a *spliced* stream.
    ///
    /// This is what makes `actual_start_ms` truthful rather than optimistic, and
    /// both values were measured against ffmpeg rather than assumed:
    ///
    /// - **Vorbis** loses `blocksize_1 / 2`, the overlap region the first packet
    ///   cannot reconstruct without its predecessor. For a 2048-sample long block
    ///   that is 1024 samples — 23.2 ms at 44.1 kHz, exactly the shortfall
    ///   observed in decoded output.
    /// - **Opus** discards `pre_skip` from the front of whatever stream it is
    ///   given, so a splice loses those samples again at the new head. With the
    ///   libopus default of 312 that is 6.5 ms, and accounting for it makes
    ///   decoded durations land on exact millisecond boundaries.
    ///
    /// Does not apply when the stream is emitted from its true beginning: there
    /// the encoder's own framing already accounts for the run-in.
    ///
    /// Caveat for Vorbis: this assumes the packet at the splice is a long block.
    /// A stream whose splice point falls on a short block loses
    /// `blocksize_0 / 2` instead, so the estimate can be up to
    /// `(blocksize_1 - blocksize_0) / 2` samples pessimistic.
    pub fn splice_discard_samples(&self) -> u64 {
        match self {
            Codec::Vorbis(v) => (v.blocksize_1 / 2) as u64,
            Codec::Opus(o) => o.pre_skip,
        }
    }

    /// Convert a granule position to milliseconds of PCM.
    ///
    /// Saturates at zero, because a granule below `pre_skip` denotes samples that
    /// are trimmed rather than a negative time.
    pub fn granule_to_ms(&self, granule: u64) -> u64 {
        let samples = granule.saturating_sub(self.pre_skip());
        (samples as u128 * 1000 / self.granule_rate() as u128) as u64
    }

    /// Convert milliseconds of PCM to a granule position.
    pub fn ms_to_granule(&self, ms: u64) -> u64 {
        let samples = ms as u128 * self.granule_rate() as u128 / 1000;
        (samples + self.pre_skip() as u128).min(u64::MAX as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vorbis_id(channels: u8, rate: u32) -> Vec<u8> {
        let mut v = b"\x01vorbis".to_vec();
        v.extend_from_slice(&0u32.to_le_bytes()); // version
        v.push(channels);
        v.extend_from_slice(&rate.to_le_bytes());
        v.extend_from_slice(&[0i32.to_le_bytes(), 0i32.to_le_bytes(), 0i32.to_le_bytes()].concat()); // bitrates
        v.push(0xbb); // blocksize_0 = blocksize_1 = 2048, as libvorbis emits
        v.push(1); // framing
        v
    }

    fn opus_head(channels: u8, pre_skip: u16, rate: u32) -> Vec<u8> {
        let mut v = b"OpusHead".to_vec();
        v.push(1); // version
        v.push(channels);
        v.extend_from_slice(&pre_skip.to_le_bytes());
        v.extend_from_slice(&rate.to_le_bytes());
        v.extend_from_slice(&0i16.to_le_bytes()); // output gain
        v.push(0); // mapping family
        v
    }

    #[test]
    fn identifies_vorbis() {
        let codec = Codec::identify(&vorbis_id(2, 44_100)).expect("vorbis");
        assert_eq!(codec.name(), "vorbis");
        assert_eq!(codec.channels(), 2);
        assert_eq!(codec.granule_rate(), 44_100);
        assert_eq!(codec.pre_skip(), 0);
        assert_eq!(codec.header_packets(), 3);
    }

    #[test]
    fn identifies_opus_and_reads_pre_skip() {
        let codec = Codec::identify(&opus_head(2, 312, 48_000)).expect("opus");
        assert_eq!(codec.name(), "opus");
        assert_eq!(codec.channels(), 2);
        assert_eq!(codec.pre_skip(), 312);
        assert_eq!(codec.header_packets(), 2);
        // Always 48 kHz, even when OpusHead records a different input rate.
        let odd = Codec::identify(&opus_head(1, 312, 16_000)).expect("opus");
        assert_eq!(odd.granule_rate(), 48_000);
    }

    #[test]
    fn rejects_unknown_and_short_headers() {
        assert_eq!(
            Codec::identify(b"definitely not a codec").unwrap_err(),
            CodecError::Unrecognised,
        );
        assert_eq!(
            Codec::identify(b"\x01vorbis\x00\x00").unwrap_err(),
            CodecError::HeaderTooShort { need: 30, got: 9 },
        );
        assert_eq!(
            Codec::identify(b"OpusHead\x01\x02").unwrap_err(),
            CodecError::HeaderTooShort { need: 19, got: 10 },
        );
        assert_eq!(
            Codec::identify(&[]).unwrap_err(),
            CodecError::Unrecognised,
            "empty input must not panic",
        );
    }

    /// Vorbis has no pre-skip, so the conversion is a plain rate scaling.
    ///
    /// The roundtrip is *not* an identity at 44 100 Hz, and that is arithmetic
    /// rather than a bug: one millisecond is 44.1 samples, so `ms → granule`
    /// truncates and the trip back lands up to 1 ms early. What must hold is
    /// that it never overshoots — a splice that rounded *up* would silently skip
    /// audio the caller asked for.
    #[test]
    fn vorbis_granule_conversion_never_overshoots() {
        let codec = Codec::identify(&vorbis_id(2, 44_100)).expect("vorbis");
        assert_eq!(codec.granule_to_ms(0), 0);
        assert_eq!(codec.granule_to_ms(44_100), 1_000);
        assert_eq!(codec.granule_to_ms(220_500), 5_000);
        assert_eq!(codec.ms_to_granule(5_000), 220_500);

        for ms in (0..600_000).step_by(311) {
            let back = codec.granule_to_ms(codec.ms_to_granule(ms));
            assert!(back <= ms, "ms {ms} came back as {back}: overshot");
            assert!(ms - back <= 1, "ms {ms} came back as {back}: off by >1ms");
        }
    }

    /// Whole-millisecond rates roundtrip exactly, which is why the Opus case can
    /// assert equality where Vorbis cannot: 48 000 Hz is exactly 48 samples/ms.
    #[test]
    fn whole_sample_per_ms_rates_roundtrip_exactly() {
        for rate in [8_000, 16_000, 24_000, 48_000] {
            let codec = Codec::identify(&vorbis_id(2, rate)).expect("vorbis");
            for ms in (0..600_000).step_by(311) {
                assert_eq!(
                    codec.granule_to_ms(codec.ms_to_granule(ms)),
                    ms,
                    "rate {rate}, ms {ms}",
                );
            }
        }
    }

    /// The Opus case a generic helper would get wrong.
    #[test]
    fn opus_granule_conversion_accounts_for_pre_skip() {
        let codec = Codec::identify(&opus_head(2, 312, 48_000)).expect("opus");
        // Granule 312 is PCM position zero — not granule 0.
        assert_eq!(codec.granule_to_ms(312), 0);
        assert_eq!(codec.granule_to_ms(48_312), 1_000);
        assert_eq!(codec.granule_to_ms(240_312), 5_000);
        assert_eq!(codec.ms_to_granule(5_000), 240_312);
        // Below pre-skip is trimmed audio, not negative time.
        assert_eq!(codec.granule_to_ms(100), 0);
        for ms in (0..600_000).step_by(311) {
            assert_eq!(codec.granule_to_ms(codec.ms_to_granule(ms)), ms);
        }
    }

    #[test]
    fn conversions_do_not_overflow_at_the_extremes() {
        for codec in [
            Codec::identify(&vorbis_id(2, 44_100)).unwrap(),
            Codec::identify(&opus_head(2, 312, 48_000)).unwrap(),
        ] {
            let _ = codec.granule_to_ms(u64::MAX);
            let _ = codec.ms_to_granule(u64::MAX);
            assert_eq!(codec.ms_to_granule(u64::MAX), u64::MAX);
        }
    }
}
