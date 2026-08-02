//! Ogg's CRC-32 — which is *not* the CRC-32 already in your dependency tree.
//!
//! [RFC 3533 §6] specifies a checksum over the entire page (header **and** body)
//! with the CRC field itself zeroed, using generator polynomial `0x04c11db7`.
//! The variant differs from the common zlib/PKZip CRC-32 in all three of the
//! ways that matter:
//!
//! | property   | Ogg      | common CRC-32 |
//! |------------|----------|---------------|
//! | reflection | **none** | in and out    |
//! | init       | **0**    | `0xFFFFFFFF`  |
//! | final XOR  | **none** | `0xFFFFFFFF`  |
//!
//! Reaching for an off-the-shelf `crc32` here fails *silently*: the output still
//! looks like a valid page, and the only symptom is a decoder reporting a hole
//! in the data much later. That is why this module carries its own table and why
//! the tests below cross-check it three independent ways — against hand-computed
//! entries, against a bitwise implementation derived straight from the
//! definition, and against real encoder output in `tests/`.
//!
//! Note the endianness trap while you are here: the CRC is computed MSB-first,
//! but it is *stored* in the page header little-endian, like every other
//! multi-byte header field. See [`super::page`].
//!
//! [RFC 3533 §6]: https://www.rfc-editor.org/rfc/rfc3533.html#section-6

/// The Ogg generator polynomial, in normal (non-reversed) form.
pub const POLY: u32 = 0x04c1_1db7;

/// Byte-at-a-time lookup table for [`POLY`], MSB-first.
///
/// Built at compile time so there is no initialisation path to get wrong, and
/// exposed so tests can assert on individual entries.
pub const TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        // Seed with the index in the *high* byte: this is the MSB-first form.
        let mut crc = (i as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ POLY
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// One-shot checksum over a contiguous buffer.
pub fn checksum(bytes: &[u8]) -> u32 {
    Crc::new().chain(bytes).finish()
}

/// Incremental checksum.
///
/// Needed because a page's checksum covers the header with its CRC field
/// zeroed — so verifying a page means feeding three runs (header prefix, four
/// zero bytes, remainder) without copying the page to patch it first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Crc(u32);

impl Crc {
    /// Ogg's initial value is zero — not `0xFFFFFFFF`.
    pub const fn new() -> Self {
        Self(0)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            let index = ((self.0 >> 24) as u8 ^ byte) as usize;
            self.0 = (self.0 << 8) ^ TABLE[index];
        }
    }

    /// Builder-style [`Crc::update`], for one-liners.
    pub fn chain(mut self, bytes: &[u8]) -> Self {
        self.update(bytes);
        self
    }

    /// Ogg applies no final XOR, so the state *is* the checksum.
    pub const fn finish(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRC-32 derived directly from the definition — one bit at a time, no
    /// table. If this and the table agree, the table is right.
    fn bitwise_reference(bytes: &[u8]) -> u32 {
        let mut crc: u32 = 0;
        for &byte in bytes {
            crc ^= (byte as u32) << 24;
            for _ in 0..8 {
                crc = if crc & 0x8000_0000 != 0 {
                    (crc << 1) ^ POLY
                } else {
                    crc << 1
                };
            }
        }
        crc
    }

    /// Deterministic pseudo-random bytes, so the cross-check covers real
    /// inputs without pulling in a `rand` dependency at M0.
    fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn table_head_matches_hand_computation() {
        // Worked through by hand from the definition; these are also the first
        // four entries of libogg's `crc_lookup`.
        assert_eq!(TABLE[0], 0x0000_0000);
        assert_eq!(TABLE[1], 0x04c1_1db7);
        assert_eq!(TABLE[2], 0x0982_3b6e);
        assert_eq!(TABLE[3], 0x0d43_26d9);
    }

    /// The single highest-value test in this crate.
    ///
    /// `0xEDB88320` is `POLY` bit-reversed: it is the signature of the
    /// *reflected* CRC-32 that every general-purpose crate implements. If it
    /// ever appears in this table, the table is the wrong variant and every
    /// page we emit will be quietly corrupt.
    #[test]
    fn table_is_not_the_reflected_variant() {
        const REFLECTED_SIGNATURE: u32 = 0xEDB8_8320;
        assert_eq!(TABLE[0x80], 0x690c_e0ee, "MSB-first table[0x80]");
        assert!(
            !TABLE.contains(&REFLECTED_SIGNATURE),
            "table contains the reflected-variant signature — wrong CRC form",
        );
    }

    #[test]
    fn init_is_zero_and_there_is_no_final_xor() {
        // With init 0 and no output XOR, the empty input hashes to 0. The
        // common variant would give 0x00000000 ^ 0xFFFFFFFF = 0xFFFFFFFF.
        assert_eq!(checksum(&[]), 0);
    }

    #[test]
    fn matches_the_bitwise_reference() {
        let mut cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0x00],
            vec![0xff],
            vec![0x01, 0x02, 0x03],
            b"OggS".to_vec(),
            (0..=255u8).collect(),
            vec![0u8; 1024],
            vec![0xffu8; 65_025], // the maximum Ogg page body
        ];
        for seed in 0..32u64 {
            cases.push(lcg_bytes(seed, (seed as usize * 37) % 700));
        }
        for case in &cases {
            assert_eq!(
                checksum(case),
                bitwise_reference(case),
                "mismatch on {}-byte input",
                case.len(),
            );
        }
    }

    #[test]
    fn incremental_matches_one_shot_at_every_split() {
        let data = lcg_bytes(0xEA45, 512);
        let expected = checksum(&data);
        for split in 0..=data.len() {
            let (head, tail) = data.split_at(split);
            let got = Crc::new().chain(head).chain(tail).finish();
            assert_eq!(got, expected, "split at {split}");
        }
    }

    #[test]
    fn detects_single_bit_flips() {
        let data = lcg_bytes(7, 256);
        let baseline = checksum(&data);
        for byte in 0..data.len() {
            for bit in 0..8 {
                let mut flipped = data.clone();
                flipped[byte] ^= 1 << bit;
                assert_ne!(checksum(&flipped), baseline, "byte {byte} bit {bit}");
            }
        }
    }
}
