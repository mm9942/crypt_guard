//! Canonical v3 post-quantum HPKE API.
//!
//! This module promotes the audited, pure-Rust ML-KEM implementation in
//! [`crate::hpke_pq`] to the normal crypt_guard transport surface.  It is
//! revision-pinned to the HPKE PQ draft implementation vendored by this crate;
//! it is not an assertion that PQ KEM identifiers are final IANA assignments.
//!
//! Raw HPKE users should use [`setup_base_sender`] / [`setup_base_receiver`]
//! and transport `enc` separately from the ciphertext.  [`HpkeEnvelope`] is a
//! crypt_guard container for deployments that need a self-describing record.
//! `info` and message AAD are deliberately caller inputs and are never put in
//! the envelope plaintext.

use core::convert::TryInto;
use std::{error::Error as StdError, fmt};

use zeroize::Zeroizing;

pub use crate::hpke_pq::draft_ietf_hpke_pq_05_full::{
    derive_recipient_key_pair, generate_recipient_key_pair,
    setup_base_receiver as setup_base_receiver_inner, setup_base_sender as setup_base_sender_inner,
    setup_psk_receiver as setup_psk_receiver_inner, setup_psk_sender as setup_psk_sender_inner,
    Aead, Capability, Encapsulation, Error, Kdf, Kem, RecipientContext, RecipientKeyPair,
    RecipientPrivateKey, RecipientPublicKey, SenderContext, Suite,
};

/// The revision implemented by this crate's PQ KEM adapter.
pub const DRAFT_NAME: &str = crate::hpke_pq::draft_ietf_hpke_pq_05_full::DRAFT_NAME;

/// Default conservative v3 profile: ML-KEM-1024/P-384, SHAKE256, and
/// ChaCha20-Poly1305.  Suite selection remains explicit for all other uses.
pub const DEFAULT_SUITE: Suite =
    Suite::new(Kem::MlKem1024P384, Kdf::Shake256, Aead::ChaCha20Poly1305);

/// Versioned crypt_guard PQ HPKE transport magic.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"CGH3";
/// Version of [`HpkeEnvelope`].
pub const ENVELOPE_VERSION: u16 = 1;
const FIXED_HEADER_LEN: usize = 20;

/// Errors raised while decoding a [`HpkeEnvelope`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// Magic does not identify a v3 PQ HPKE envelope.
    InvalidMagic,
    /// A future envelope version was supplied.
    UnsupportedVersion { actual: u16 },
    /// The encoded algorithm identifiers are not a supported v3 suite.
    UnsupportedSuite { kem: u16, kdf: u16, aead: u16 },
    /// The record was truncated, had trailing bytes, or had an invalid length.
    InvalidEncoding,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("not a crypt_guard v3 PQ HPKE envelope"),
            Self::UnsupportedVersion { actual } => {
                write!(
                    f,
                    "unsupported crypt_guard PQ HPKE envelope version {actual}"
                )
            }
            Self::UnsupportedSuite { kem, kdf, aead } => write!(
                f,
                "unsupported crypt_guard PQ HPKE suite ({kem:#06x}, {kdf:#06x}, {aead:#06x})"
            ),
            Self::InvalidEncoding => f.write_str("invalid crypt_guard PQ HPKE envelope encoding"),
        }
    }
}

impl StdError for EnvelopeError {}

/// Set up an interoperable raw Base-mode sender context.
///
/// The returned `enc` and ciphertext are RFC-style separate artifacts. Private
/// crypt_guard AEAD extensions are rejected here and require [`HpkeEnvelope`].
pub fn setup_base_sender(
    suite: Suite,
    recipient: &RecipientPublicKey,
    info: &[u8],
) -> Result<(Encapsulation, SenderContext), Error> {
    require_standard_aead(suite)?;
    setup_base_sender_inner(suite, recipient, info)
}

/// Set up an interoperable raw Base-mode receiver context.
pub fn setup_base_receiver(
    suite: Suite,
    recipient: &RecipientPrivateKey,
    encapsulation: &Encapsulation,
    info: &[u8],
) -> Result<RecipientContext, Error> {
    require_standard_aead(suite)?;
    setup_base_receiver_inner(suite, recipient, encapsulation, info)
}

/// Set up an interoperable raw PSK-mode sender context.
pub fn setup_psk_sender(
    suite: Suite,
    recipient: &RecipientPublicKey,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(Encapsulation, SenderContext), Error> {
    require_standard_aead(suite)?;
    setup_psk_sender_inner(suite, recipient, info, psk, psk_id)
}

/// Set up an interoperable raw PSK-mode receiver context.
pub fn setup_psk_receiver(
    suite: Suite,
    recipient: &RecipientPrivateKey,
    encapsulation: &Encapsulation,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<RecipientContext, Error> {
    require_standard_aead(suite)?;
    setup_psk_receiver_inner(suite, recipient, encapsulation, info, psk, psk_id)
}

fn require_standard_aead(suite: Suite) -> Result<(), Error> {
    if suite.aead().is_private_extension() {
        return Err(Error::UnavailableCapability {
            suite,
            reason: "crypt_guard private AEAD extensions require HpkeEnvelope transport",
        });
    }
    Ok(())
}

/// A self-describing crypt_guard transport record for a single HPKE message.
///
/// It contains only routing metadata, the KEM encapsulation and ciphertext.
/// Callers must supply the exact setup `info` and per-message AAD when opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HpkeEnvelope {
    suite: Suite,
    encapsulation: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl HpkeEnvelope {
    /// Create a transport record from a raw HPKE `enc` and ciphertext.
    pub fn new(suite: Suite, encapsulation: &Encapsulation, ciphertext: Vec<u8>) -> Self {
        Self {
            suite,
            encapsulation: encapsulation.as_bytes().to_vec(),
            ciphertext,
        }
    }

    /// The exact suite encoded in this record.
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// Serialized HPKE encapsulation (`enc`).
    pub fn encapsulation(&self) -> &[u8] {
        &self.encapsulation
    }

    /// HPKE AEAD ciphertext, including its authentication tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Encode the versioned container.
    ///
    /// The encapsulation and ciphertext lengths are encoded as big-endian
    /// `u32`s, so this record format supports encapsulation/ciphertext
    /// buffers up to `u32::MAX` bytes each. In debug builds a `debug_assert!`
    /// enforces that bound; in release builds a caller-supplied buffer larger
    /// than that would silently truncate via `as u32`. Callers that cannot
    /// prove ahead of time that this envelope stays within the bound (for
    /// example, one rebuilt from untrusted or programmatically assembled
    /// parts) should prefer the fallible [`Self::try_to_bytes`], which
    /// returns [`EnvelopeError::InvalidEncoding`] instead of truncating.
    pub fn to_bytes(&self) -> Vec<u8> {
        debug_assert!(
            self.encapsulation.len() <= u32::MAX as usize,
            "HpkeEnvelope::to_bytes: encapsulation length exceeds u32::MAX; use try_to_bytes"
        );
        debug_assert!(
            self.ciphertext.len() <= u32::MAX as usize,
            "HpkeEnvelope::to_bytes: ciphertext length exceeds u32::MAX; use try_to_bytes"
        );
        let mut encoded =
            Vec::with_capacity(FIXED_HEADER_LEN + self.encapsulation.len() + self.ciphertext.len());
        encoded.extend_from_slice(&ENVELOPE_MAGIC);
        encoded.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.suite.kem().id().to_be_bytes());
        encoded.extend_from_slice(&self.suite.kdf().id().to_be_bytes());
        encoded.extend_from_slice(&self.suite.aead().id().to_be_bytes());
        encoded.extend_from_slice(&(self.encapsulation.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.encapsulation);
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    /// Fallible variant of [`Self::to_bytes`].
    ///
    /// Returns [`EnvelopeError::InvalidEncoding`] instead of truncating when
    /// the encapsulation or ciphertext length does not fit in the record's
    /// 32-bit length fields (or, in principle, when the combined record
    /// length would overflow `usize`).
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        if self.encapsulation.len() > u32::MAX as usize || self.ciphertext.len() > u32::MAX as usize
        {
            return Err(EnvelopeError::InvalidEncoding);
        }
        let total = FIXED_HEADER_LEN
            .checked_add(self.encapsulation.len())
            .and_then(|n| n.checked_add(self.ciphertext.len()))
            .ok_or(EnvelopeError::InvalidEncoding)?;
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&ENVELOPE_MAGIC);
        encoded.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.suite.kem().id().to_be_bytes());
        encoded.extend_from_slice(&self.suite.kdf().id().to_be_bytes());
        encoded.extend_from_slice(&self.suite.aead().id().to_be_bytes());
        encoded.extend_from_slice(&(self.encapsulation.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.encapsulation);
        encoded.extend_from_slice(&self.ciphertext);
        debug_assert_eq!(encoded.len(), total);
        Ok(encoded)
    }

    /// Parse a versioned container without attempting to decrypt it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < FIXED_HEADER_LEN {
            return Err(EnvelopeError::InvalidEncoding);
        }
        if bytes[..4] != ENVELOPE_MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }
        let version = u16::from_be_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidEncoding)?,
        );
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion { actual: version });
        }
        let kem = u16::from_be_bytes(
            bytes[6..8]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidEncoding)?,
        );
        let kdf = u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidEncoding)?,
        );
        let aead = u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidEncoding)?,
        );
        let enc_len = u32::from_be_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidEncoding)?,
        ) as usize;
        let ct_len = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidEncoding)?,
        ) as usize;
        let end = FIXED_HEADER_LEN
            .checked_add(enc_len)
            .and_then(|n| n.checked_add(ct_len))
            .ok_or(EnvelopeError::InvalidEncoding)?;
        if end != bytes.len() {
            return Err(EnvelopeError::InvalidEncoding);
        }
        let suite = suite_from_ids(kem, kdf, aead)?;
        Ok(Self {
            suite,
            encapsulation: bytes[FIXED_HEADER_LEN..FIXED_HEADER_LEN + enc_len].to_vec(),
            ciphertext: bytes[FIXED_HEADER_LEN + enc_len..].to_vec(),
        })
    }

    /// Seal one message into a self-describing v3 transport record.
    pub fn seal(
        suite: Suite,
        recipient: &RecipientPublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, Error> {
        let (encapsulation, mut sender) = setup_base_sender_inner(suite, recipient, info)?;
        let ciphertext = sender.seal(aad, plaintext)?;
        Ok(Self::new(suite, &encapsulation, ciphertext))
    }

    /// Open one v3 transport record.  `info` and AAD must match the sender.
    ///
    /// The returned `Vec<u8>` is ordinary, non-zeroizing heap memory: it is
    /// not wiped when dropped. Prefer [`Self::open_zeroizing`] whenever the
    /// plaintext is sensitive, which is the common case for HPKE payloads.
    pub fn open(
        &self,
        recipient: &RecipientPrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let encapsulation = Encapsulation::from_bytes(self.suite.kem(), &self.encapsulation)?;
        let mut receiver = setup_base_receiver_inner(self.suite, recipient, &encapsulation, info)?;
        receiver.open(aad, &self.ciphertext)
    }

    /// Open one v3 transport record like [`Self::open`], returning the
    /// plaintext wrapped in [`Zeroizing`].
    ///
    /// This calls [`Self::open`] and immediately moves its `Vec<u8>` result
    /// into a `Zeroizing` wrapper, so the plaintext is never held in the
    /// caller-visible, non-zeroizing form for longer than the single
    /// intervening move. Note that `Zeroizing<Vec<u8>>` zeroizes the vector's
    /// *entire allocated capacity* on drop (via `Vec`'s `Zeroize`
    /// implementation), not just its logical length, which also covers any
    /// spare capacity the underlying AEAD call may have left allocated.
    pub fn open_zeroizing(
        &self,
        recipient: &RecipientPrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.open(recipient, info, aad).map(Zeroizing::new)
    }

    /// Decode a wire-format v3 envelope and open it in one step.
    ///
    /// This is a convenience that composes [`Self::from_bytes`] and
    /// [`Self::open_zeroizing`], surfacing both fallible stages through a
    /// single [`EnvelopeOpenError`].
    pub fn open_bytes_zeroizing(
        bytes: &[u8],
        recipient: &RecipientPrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeOpenError> {
        let envelope = Self::from_bytes(bytes)?;
        envelope
            .open_zeroizing(recipient, info, aad)
            .map_err(EnvelopeOpenError::from)
    }
}

/// Combined decode-then-open error for [`HpkeEnvelope::open_bytes_zeroizing`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeOpenError {
    /// The wire bytes did not decode as a valid v3 envelope.
    Envelope(EnvelopeError),
    /// The envelope decoded, but the HPKE decapsulation/open step failed.
    Hpke(Error),
}

impl fmt::Display for EnvelopeOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => fmt::Display::fmt(e, f),
            Self::Hpke(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl StdError for EnvelopeOpenError {}

impl From<EnvelopeError> for EnvelopeOpenError {
    fn from(err: EnvelopeError) -> Self {
        Self::Envelope(err)
    }
}

impl From<Error> for EnvelopeOpenError {
    fn from(err: Error) -> Self {
        Self::Hpke(err)
    }
}

/// Map wire-format v3 envelope identifiers to a [`Suite`].
///
/// Returns [`EnvelopeError::UnsupportedSuite`] carrying the offending raw
/// identifiers if `kem`, `kdf`, or `aead` is not one of the values this v3
/// profile recognizes.
pub fn suite_from_ids(kem: u16, kdf: u16, aead: u16) -> Result<Suite, EnvelopeError> {
    let kem = match kem {
        0x0040 => Kem::MlKem512,
        0x0041 => Kem::MlKem768,
        0x0042 => Kem::MlKem1024,
        0x0050 => Kem::MlKem768P256,
        0x0051 => Kem::MlKem1024P384,
        0x647a => Kem::MlKem768X25519,
        _ => return Err(EnvelopeError::UnsupportedSuite { kem, kdf, aead }),
    };
    let kdf = match kdf {
        0x0001 => Kdf::HkdfSha256,
        0x0002 => Kdf::HkdfSha384,
        0x0003 => Kdf::HkdfSha512,
        0x0010 => Kdf::Shake128,
        0x0011 => Kdf::Shake256,
        0x0012 => Kdf::TurboShake128,
        0x0013 => Kdf::TurboShake256,
        _ => {
            return Err(EnvelopeError::UnsupportedSuite {
                kem: kem.id(),
                kdf,
                aead,
            })
        }
    };
    let aead = match aead {
        0x0001 => Aead::Aes128Gcm,
        0x0002 => Aead::Aes256Gcm,
        0x0003 => Aead::ChaCha20Poly1305,
        0xff01 => Aead::Aes256GcmSiv,
        0xff02 => Aead::XChaCha20Poly1305,
        0xffff => Aead::ExportOnly,
        _ => {
            return Err(EnvelopeError::UnsupportedSuite {
                kem: kem.id(),
                kdf: kdf.id(),
                aead,
            })
        }
    };
    Ok(Suite::new(kem, kdf, aead))
}

/// The wire-format `(kem, kdf, aead)` identifier triple for `suite`, as used
/// by the v3 envelope header. Inverse of [`suite_from_ids`] for any suite it
/// can produce.
pub const fn suite_ids(suite: Suite) -> (u16, u16, u16) {
    (suite.kem().id(), suite.kdf().id(), suite.aead().id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_key_pair_is_publicly_reexported() {
        let derive: fn(Kem, &[u8]) -> Result<RecipientKeyPair, Error> =
            crate::pq_hpke::derive_recipient_key_pair;
        let _ = derive;
    }

    #[test]
    fn default_profile_round_trip_binds_info_and_aad() {
        let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
        let envelope =
            HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"info", b"aad", b"").unwrap();
        assert_eq!(
            envelope.open(keys.private_key(), b"info", b"aad").unwrap(),
            b""
        );
        assert_eq!(
            envelope.open(keys.private_key(), b"different", b"aad"),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn envelope_is_not_cgv2_and_round_trips() {
        let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
        let envelope =
            HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"i", b"a", b"payload").unwrap();
        let encoded = envelope.to_bytes();
        assert_ne!(&encoded[..4], b"CGv2");
        let parsed = HpkeEnvelope::from_bytes(&encoded).unwrap();
        assert_eq!(
            parsed.open(keys.private_key(), b"i", b"a").unwrap(),
            b"payload"
        );
    }

    #[test]
    fn wrong_aad_fails_authentication() {
        let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
        let envelope =
            HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"info", b"aad", b"m").unwrap();
        assert_eq!(
            envelope.open(keys.private_key(), b"info", b"wrong-aad"),
            Err(Error::AuthenticationFailed)
        );
    }

    /// Assemble raw v3 envelope wire bytes from explicit field values,
    /// independent of any consistency between the declared lengths and the
    /// actual payload length -- used to craft malformed/truncated/oversized
    /// records for negative tests.
    fn craft_bytes_raw(
        magic: [u8; 4],
        version: u16,
        kem: u16,
        kdf: u16,
        aead: u16,
        enc_len: u32,
        ct_len: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&magic);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&kem.to_be_bytes());
        out.extend_from_slice(&kdf.to_be_bytes());
        out.extend_from_slice(&aead.to_be_bytes());
        out.extend_from_slice(&enc_len.to_be_bytes());
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let (kem, kdf, aead) = suite_ids(DEFAULT_SUITE);
        let bytes = craft_bytes_raw(ENVELOPE_MAGIC, 0xffff, kem, kdf, aead, 0, 0, &[]);
        assert_eq!(
            HpkeEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::UnsupportedVersion { actual: 0xffff })
        );
    }

    #[test]
    fn unsupported_kem_id_is_reported() {
        let (_, kdf, aead) = suite_ids(DEFAULT_SUITE);
        let bytes = craft_bytes_raw(
            ENVELOPE_MAGIC,
            ENVELOPE_VERSION,
            0xdead,
            kdf,
            aead,
            0,
            0,
            &[],
        );
        assert_eq!(
            HpkeEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::UnsupportedSuite {
                kem: 0xdead,
                kdf,
                aead
            })
        );
    }

    #[test]
    fn unsupported_kdf_id_is_reported() {
        let (kem, _, aead) = suite_ids(DEFAULT_SUITE);
        let bytes = craft_bytes_raw(
            ENVELOPE_MAGIC,
            ENVELOPE_VERSION,
            kem,
            0xdead,
            aead,
            0,
            0,
            &[],
        );
        assert_eq!(
            HpkeEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::UnsupportedSuite {
                kem,
                kdf: 0xdead,
                aead
            })
        );
    }

    #[test]
    fn unsupported_aead_id_is_reported() {
        let (kem, kdf, _) = suite_ids(DEFAULT_SUITE);
        let bytes = craft_bytes_raw(
            ENVELOPE_MAGIC,
            ENVELOPE_VERSION,
            kem,
            kdf,
            0xdead,
            0,
            0,
            &[],
        );
        assert_eq!(
            HpkeEnvelope::from_bytes(&bytes),
            Err(EnvelopeError::UnsupportedSuite {
                kem,
                kdf,
                aead: 0xdead
            })
        );
    }

    #[test]
    fn truncated_records_never_panic_and_always_err() {
        let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
        let envelope =
            HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"i", b"a", b"payload").unwrap();
        let encoded = envelope.to_bytes();
        for len in 0..encoded.len() {
            assert!(
                HpkeEnvelope::from_bytes(&encoded[..len]).is_err(),
                "truncation to {len} bytes unexpectedly parsed"
            );
        }
        // The full-length record must still parse.
        assert!(HpkeEnvelope::from_bytes(&encoded).is_ok());
    }

    #[test]
    fn trailing_byte_is_rejected() {
        let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
        let envelope =
            HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"i", b"a", b"payload").unwrap();
        let mut encoded = envelope.to_bytes();
        encoded.push(0);
        assert_eq!(
            HpkeEnvelope::from_bytes(&encoded),
            Err(EnvelopeError::InvalidEncoding)
        );
    }

    #[test]
    fn huge_declared_lengths_never_panic_and_err() {
        let (kem, kdf, aead) = suite_ids(DEFAULT_SUITE);
        // Neither length matches the (empty) actual payload, and their sum
        // must not panic via overflow even though each individually is huge.
        for (enc_len, ct_len) in [
            (0xFFFF_FFFFu32, 0u32),
            (0u32, 0xFFFF_FFFFu32),
            (0xFFFF_FFFFu32, 0xFFFF_FFFFu32),
        ] {
            let bytes = craft_bytes_raw(
                ENVELOPE_MAGIC,
                ENVELOPE_VERSION,
                kem,
                kdf,
                aead,
                enc_len,
                ct_len,
                &[],
            );
            assert!(HpkeEnvelope::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn bit_flips_are_detected_for_multiple_suites() {
        let suites = [
            DEFAULT_SUITE,
            Suite::new(Kem::MlKem768P256, Kdf::HkdfSha256, Aead::Aes128Gcm),
        ];
        for suite in suites {
            let keys = generate_recipient_key_pair(suite.kem()).unwrap();

            let mut tampered_enc =
                HpkeEnvelope::seal(suite, keys.public_key(), b"info", b"aad", b"message").unwrap();
            tampered_enc.encapsulation[0] ^= 0x01;
            match tampered_enc.open(keys.private_key(), b"info", b"aad") {
                Err(Error::AuthenticationFailed) | Err(Error::InvalidEncapsulation) => {}
                other => panic!("suite {suite:?}: expected tamper detection, got {other:?}"),
            }

            let mut tampered_ct =
                HpkeEnvelope::seal(suite, keys.public_key(), b"info", b"aad", b"message").unwrap();
            let last = tampered_ct.ciphertext.len() - 1;
            tampered_ct.ciphertext[last] ^= 0x01;
            assert_eq!(
                tampered_ct.open(keys.private_key(), b"info", b"aad"),
                Err(Error::AuthenticationFailed),
                "suite {suite:?}: ciphertext tamper was not detected as AuthenticationFailed"
            );
        }
    }

    #[test]
    fn open_zeroizing_matches_open() {
        let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
        let envelope =
            HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"i", b"a", b"payload").unwrap();
        let plain = envelope.open(keys.private_key(), b"i", b"a").unwrap();
        let zeroizing = envelope
            .open_zeroizing(keys.private_key(), b"i", b"a")
            .unwrap();
        assert_eq!(plain.as_slice(), zeroizing.as_slice());

        let bytes = envelope.to_bytes();
        let via_bytes =
            HpkeEnvelope::open_bytes_zeroizing(&bytes, keys.private_key(), b"i", b"a").unwrap();
        assert_eq!(plain.as_slice(), via_bytes.as_slice());
    }

    #[test]
    fn try_to_bytes_matches_to_bytes() {
        let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
        let envelope =
            HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"i", b"a", b"payload").unwrap();
        assert_eq!(envelope.to_bytes(), envelope.try_to_bytes().unwrap());
    }

    #[test]
    fn suite_from_ids_round_trips_default_suite() {
        let (kem, kdf, aead) = suite_ids(DEFAULT_SUITE);
        assert_eq!(suite_from_ids(kem, kdf, aead).unwrap(), DEFAULT_SUITE);
    }

    /// Minimal deterministic xorshift64 PRNG so the fuzz-style test below is
    /// reproducible without pulling in a `rand` dependency.
    struct XorShift64(u64);

    impl XorShift64 {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn next_byte(&mut self) -> u8 {
            (self.next_u64() & 0xff) as u8
        }
    }

    #[test]
    fn random_bytes_never_panic_in_from_bytes() {
        let mut rng = XorShift64(0x9E37_79B9_7F4A_7C15);
        for i in 0..10_000u32 {
            let len = (rng.next_u64() % 96) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(rng.next_byte());
            }
            // Fully random buffer: exercises the magic/version/length checks.
            let _ = HpkeEnvelope::from_bytes(&buf);

            // Same random tail, but behind a valid "CGH3" prefix: exercises
            // version/suite/length parsing paths past the magic check.
            let mut prefixed = ENVELOPE_MAGIC.to_vec();
            prefixed.extend_from_slice(&buf);
            let _ = HpkeEnvelope::from_bytes(&prefixed);
            if i % 997 == 0 {
                // Occasionally also round-trip through try_to_bytes-shaped
                // sizes to make sure nothing panics on odd small lengths.
                let _ = HpkeEnvelope::from_bytes(&prefixed[..prefixed.len().min(24)]);
            }
        }
    }
}
