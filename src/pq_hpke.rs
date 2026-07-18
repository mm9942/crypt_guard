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

pub use crate::hpke_pq::draft_ietf_hpke_pq_05_full::{
    generate_recipient_key_pair, setup_base_receiver as setup_base_receiver_inner,
    setup_base_sender as setup_base_sender_inner, setup_psk_receiver as setup_psk_receiver_inner,
    setup_psk_sender as setup_psk_sender_inner, Aead, Capability, Encapsulation, Error, Kdf, Kem,
    RecipientContext, RecipientKeyPair, RecipientPrivateKey, RecipientPublicKey, SenderContext,
    Suite,
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
    pub fn to_bytes(&self) -> Vec<u8> {
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
}

fn suite_from_ids(kem: u16, kdf: u16, aead: u16) -> Result<Suite, EnvelopeError> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
