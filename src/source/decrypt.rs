//! `Decrypt` — an AES-128-CTR keystream applied at the absolute byte offset.
//!
//! This is the Spotify audio cipher (`DESIGN.md` A8). Its property that matters
//! here is that the keystream position *is* the byte offset: CTR is a block
//! cipher in counter mode, so the keystream at offset `N` depends only on `N`,
//! never on how the stream was reached. That is what makes random access free —
//! and it is why the whole tool is offset-addressed instead of `io::Read`.
//!
//! The crate documentation for `ctr` is unusually explicit about the units,
//! which is the single fact this file exists to make structurally true:
//!
//! > CTR mode supports seeking. The parameter is a zero-based *bytes* counter
//! > (not *blocks*).
//!
//! librespot relies on exactly the same fact in `librespot-audio`'s
//! `AudioDecrypt`, whose `Seek` implementation seeks the underlying reader and
//! then calls `cipher.seek(newpos)` with the byte offset
//! (`librespot-audio-0.8.0/src/decrypt.rs`). A freshly-built cipher per read —
//! rather than a long-lived one — makes the offset/keystream pairing enforced
//! by construction: no position state can drift, at the cost of one round of
//! key expansion per read, which is nothing against the network call each read
//! already is.
//!
//! ## Integrity note
//!
//! CTR gives confidentiality, not integrity (DESIGN Part 7): a flipped bit in
//! the ciphertext flips the same bit in the decrypted stream. Ogg's page CRC
//! catches that at the page layer, and the `room` open path additionally
//! verifies the stream starts with `OggS` — but the cipher itself never
//! authenticates.

use std::io;

use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use aes::Aes128;
use ctr::Ctr128BE;

use super::Source;

/// The fixed AES-128-CTR IV Spotify uses for audio (A8). Value verified from
/// `librespot-audio-0.8.0/src/decrypt.rs`, from which it is also copied.
pub const SPOTIFY_AUDIO_IV: [u8; 16] = [
    0x72, 0xe0, 0x67, 0xfb, 0xdd, 0xcb, 0xcf, 0x77, 0xeb, 0xe8, 0xbc, 0x64, 0x3f, 0x63, 0x0d, 0x93,
];

type Aes128Ctr = Ctr128BE<Aes128>;

/// Decrypt `inner` in place, as a source.
///
/// `read_at(o)` reads `inner` at `o` and XORs the keystream generated from
/// offset `o` — the ciphertext and the plaintext are the same length at the
/// same offset. `size()` is passed through unchanged.
pub struct Decrypt<S> {
    inner: S,
    key: [u8; 16],
}

impl<S> Decrypt<S> {
    /// Wrap `inner` in a deterrent keystream for `key`.
    pub fn new(inner: S, key: [u8; 16]) -> Self {
        Decrypt { inner, key }
    }

    /// A fresh cipher, positioned at byte offset `off`.
    fn cipher_at(&self, off: u64) -> Aes128Ctr {
        let mut cipher = Aes128Ctr::new_from_slices(&self.key, &SPOTIFY_AUDIO_IV)
            .expect("16-byte key and IV, as before");
        // Redundant after construction (it starts at zero), but makes the
        // invariant local and auditable rather than an ordering assumption.
        cipher.seek(off);
        cipher
    }
}

impl<S: Source> Source for Decrypt<S> {
    fn size(&mut self) -> io::Result<Option<u64>> {
        self.inner.size()
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read_at(off, buf)?;
        if n > 0 {
            self.cipher_at(off).apply_keystream(&mut buf[..n]);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::mem::MemSource;
    use crate::source::read_exact_at;

    /// SP 800-38A F.5.1 — AES-128-CTR, anchored on published ciphertext.
    const NIST_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const NIST_IV: [u8; 16] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
    ];
    /// Plaintext: block 1 || block 2 || block 3 || block 4 (SP 800-38A).
    const NIST_PT: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];
    /// Ciphertext for the same blocks, key, and IV (SP 800-38A F.5.1).
    ///
    /// Block 4 was re-derived independently (`openssl enc -aes-128-ctr` on a
    /// zero input yields the keystream `e8 9c 39 9f … ab fe`, XORed with the
    /// plaintext below) — the value is recorded here so this test anchors the
    /// substrate against something the crate never produced itself.
    const NIST_CT: [u8; 64] = [
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6,
        0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff,
        0xfd, 0xff, 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d,
        0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0,
        0xf3, 0x00, 0x9c, 0xee,
    ];

    /// The crypto substrate matches NIST's published AES-128-CTR vector, so the
    /// fixture chain below is measuring our offset/keystream pairing, not the
    /// block cipher.
    #[test]
    fn the_block_cipher_matches_nist() {
        let mut cipher = Aes128Ctr::new_from_slices(&NIST_KEY, &NIST_IV).expect("construct");
        let mut got = NIST_PT;
        cipher.apply_keystream(&mut got);
        assert_eq!(got, NIST_CT);
    }

    /// The fixture used by the decorator tests below is encrypted with the
    /// *fixed Spotify IV* — which is what `Decrypt` hardcodes — so the plaintext
    /// comes back through it. The NIST test above already pinned the block
    /// cipher itself; these tests pin the offset/keystream pairing.
    const FIXTURE_KEY: [u8; 16] = [0x42; 16];

    fn encrypted_fixture() -> Vec<u8> {
        let mut cipher =
            Aes128Ctr::new_from_slices(&FIXTURE_KEY, &SPOTIFY_AUDIO_IV).expect("construct");
        let mut ct = SPOTIFY_FIXTURE_PT.to_vec();
        cipher.apply_keystream(&mut ct);
        ct
    }

    /// A 64-byte plaintext, not the NIST one — the two test families deliberately
    /// use different keys/IVs so neither silently depends on the other.
    const SPOTIFY_FIXTURE_PT: [u8; 64] = {
        let mut bytes = [0u8; 64];
        let mut i = 0;
        while i < 64 {
            bytes[i] = (i as u8).wrapping_mul(3).wrapping_add(7);
            i += 1;
        }
        bytes
    };

    #[test]
    fn a_read_at_zero_is_the_first_plaintext_block() {
        let mut dec = Decrypt::new(MemSource::new(encrypted_fixture()), FIXTURE_KEY);
        let mut head = [0u8; 16];
        read_exact_at(&mut dec, 0, &mut head).unwrap();
        assert_eq!(head, SPOTIFY_FIXTURE_PT[..16]);
    }

    #[test]
    fn a_read_at_sixteen_is_the_second_plaintext_block() {
        // Random access works because the keystream position is the offset.
        let mut dec = Decrypt::new(MemSource::new(encrypted_fixture()), FIXTURE_KEY);
        let mut second = [0u8; 16];
        read_exact_at(&mut dec, 16, &mut second).unwrap();
        assert_eq!(second, SPOTIFY_FIXTURE_PT[16..32]);
    }

    #[test]
    fn an_unaligned_read_decrypts_at_that_byte() {
        // 23 is not 16-aligned; a Read-based chain could never prove this.
        let mut dec = Decrypt::new(MemSource::new(encrypted_fixture()), FIXTURE_KEY);
        let mut piece = [0u8; 10];
        read_exact_at(&mut dec, 23, &mut piece).unwrap();
        assert_eq!(piece, SPOTIFY_FIXTURE_PT[23..33]);
    }

    #[test]
    fn ctr_decrypts_by_encrypting() {
        // Both decorators stream through the caller's buffer, so applying the
        // keystream twice at the same offset XORs it away again (CTR is its own
        // inverse): Decrypt∘Decrypt at one position reproduces the ciphertext.
        let mut a = Decrypt::new(MemSource::new(encrypted_fixture()), FIXTURE_KEY);
        let mut b = Decrypt::new(&mut a, FIXTURE_KEY);
        let mut plain = [0u8; 64];
        read_exact_at(&mut b, 0, &mut plain).unwrap();
        assert_eq!(&plain[..], encrypted_fixture());
    }

    #[test]
    fn size_passes_through() {
        let mut dec = Decrypt::new(MemSource::new(vec![0u8; 64]), FIXTURE_KEY);
        assert_eq!(dec.size().unwrap(), Some(64));
    }
}
