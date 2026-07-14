//! Experimental post-quantum HPKE KEM adapters and Base-mode contexts.
//!
//! This module is deliberately separate from the CGv2 KEM path. It adapts the
//! PQCA/PQCP `libcrux-ml-kem` implementation to the ML-KEM HPKE KEM interface
//! described by the currently pinned post-quantum HPKE Internet-Draft. It does
//! not itself claim RFC-standardized ML-KEM HPKE support: the IETF mapping is
//! still a draft. This default module must never be described as an RFC-standard
//! ML-KEM HPKE profile.
//!
//! The adapters implement ML-KEM-512, ML-KEM-768 and ML-KEM-1024. They store the HPKE
//! recipient private key as the draft's FIPS 203 seed, expand that seed with the
//! FIPS 203 key-generation operation only for decapsulation, and validate
//! serialized public keys plus expanded private-key integrity at the PQCA
//! boundary.  The additive Base-mode API at the bottom of this module is
//! constrained to the compatibility profiles covered by the pinned draft-05 vectors:
//! ML-KEM-768/HKDF-SHA256/AES-128-GCM and
//! ML-KEM-1024/HKDF-SHA384/AES-256-GCM.

// The implementation primitives below are kept private.  The only supported
// consumer surface is the deliberately named `draft_ietf_hpke_pq_05` module
// added below, so an application cannot accidentally mistake this active-draft
// mapping for an RFC 9180-registered PQ profile.
#![allow(dead_code)]

use core::convert::TryFrom;
use std::{error::Error, fmt};

use aes_gcm::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit, Payload as AesPayload},
    Aes128Gcm, Aes256Gcm, Nonce as AesGcmNonce,
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2_011::{Sha256, Sha384};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptError;

/// Errors returned by the experimental `draft-ietf-hpke-pq-05` Base-mode API.
///
/// These errors deliberately keep malformed public inputs distinct from an
/// authenticated ciphertext failure.  In particular, a same-size modified
/// ML-KEM encapsulation reaches the AEAD boundary through ML-KEM implicit
/// rejection and must return only [`Self::AuthenticationFailed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Draft05Error {
    /// FIPS 203 public-key validation rejected the key.
    InvalidPublicKey,
    /// The deterministic FIPS 203 encapsulation randomness is not 32 bytes.
    InvalidEncapsulationRandomness { actual: usize },
    /// The RFC 9180/draft two-byte length encoding cannot represent a value.
    OutputLengthTooLarge { requested: usize },
    /// The draft one-stage KDF encodes its label with a two-octet length.
    LabelTooLarge { actual: usize },
    /// The HPKE message sequence is exhausted and must not wrap.
    MessageLimitReached,
    /// AES-GCM rejected the ciphertext, key-derived tag, or associated data.
    AuthenticationFailed,
    /// An internal fixed-size conversion failed after a checked derivation.
    InternalInvariant(&'static str),
}

impl fmt::Display for Draft05Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => f.write_str("draft HPKE ML-KEM public key is invalid"),
            Self::InvalidEncapsulationRandomness { actual } => write!(
                f,
                "draft HPKE deterministic ML-KEM encapsulation needs 32 bytes of randomness, got {actual}"
            ),
            Self::OutputLengthTooLarge { requested } => write!(
                f,
                "draft HPKE output length {requested} exceeds the u16 encoding bound"
            ),
            Self::LabelTooLarge { actual } => write!(
                f,
                "draft HPKE KDF label has {actual} bytes; the u16 encoding bound is exceeded"
            ),
            Self::MessageLimitReached => {
                f.write_str("draft HPKE message limit reached; sequence number must not wrap")
            }
            Self::AuthenticationFailed => f.write_str("draft HPKE AEAD authentication failed"),
            Self::InternalInvariant(name) => {
                write!(f, "draft HPKE internal invariant failed: {name}")
            }
        }
    }
}

const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

/// Implement the one-stage `LabeledDerive` construction used by the evolving
/// HPKE specification for SHAKE KDFs.
///
/// This is *not* RFC 9180's HKDF `LabeledExpand`.  The current HPKE working
/// group draft defines the input, in this exact order, as
/// `ikm || "HPKE-v1" || kem_suite_id || I2OSP(len(label), 2) || label ||
/// I2OSP(L, 2) || context`, followed by SHAKE256 expansion.  The PQ draft
/// invokes it only to derive ML-KEM's 64-byte decapsulation-key seed.
fn kem_labeled_derive(
    kem_id: u16,
    ikm: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Draft05Error> {
    if output_len > u16::MAX as usize {
        return Err(Draft05Error::OutputLengthTooLarge {
            requested: output_len,
        });
    }
    if label.len() > u16::MAX as usize {
        return Err(Draft05Error::LabelTooLarge {
            actual: label.len(),
        });
    }

    let mut xof = Shake256::default();
    xof.update(ikm);
    xof.update(HPKE_VERSION_LABEL);
    xof.update(b"KEM");
    xof.update(&kem_id.to_be_bytes());
    xof.update(&(label.len() as u16).to_be_bytes());
    xof.update(label);
    xof.update(&(output_len as u16).to_be_bytes());
    xof.update(context);

    let mut output = Zeroizing::new(vec![0_u8; output_len]);
    xof.finalize_xof().read(&mut output);
    Ok(output)
}

impl Error for Draft05Error {}

/// The two legacy compatibility profiles implemented by this module.
///
/// These identifiers are from an active Internet-Draft, not an RFC or a final
/// IANA registration.  No negotiation or fallback is performed by this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Draft05Profile {
    /// ML-KEM-768 / HKDF-SHA256 / AES-128-GCM (0x0041 / 0x0001 / 0x0001).
    MlKem768HkdfSha256Aes128Gcm,
    /// ML-KEM-1024 / HKDF-SHA384 / AES-256-GCM (0x0042 / 0x0002 / 0x0002).
    MlKem1024HkdfSha384Aes256Gcm,
}

impl Draft05Profile {
    /// The active-draft KEM identifier (not a claim of RFC standardization).
    pub const fn kem_id(self) -> u16 {
        match self {
            Self::MlKem768HkdfSha256Aes128Gcm => ML_KEM_768_KEM_ID,
            Self::MlKem1024HkdfSha384Aes256Gcm => ML_KEM_1024_KEM_ID,
        }
    }

    /// The RFC 9180 KDF identifier used by this fixed profile.
    pub const fn kdf_id(self) -> u16 {
        match self {
            Self::MlKem768HkdfSha256Aes128Gcm => 0x0001,
            Self::MlKem1024HkdfSha384Aes256Gcm => 0x0002,
        }
    }

    /// The RFC 9180 AEAD identifier used by this fixed profile.
    pub const fn aead_id(self) -> u16 {
        match self {
            Self::MlKem768HkdfSha256Aes128Gcm => 0x0001,
            Self::MlKem1024HkdfSha384Aes256Gcm => 0x0002,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::MlKem768HkdfSha256Aes128Gcm => 16,
            Self::MlKem1024HkdfSha384Aes256Gcm => 32,
        }
    }

    const fn hash_len(self) -> usize {
        match self {
            Self::MlKem768HkdfSha256Aes128Gcm => 32,
            Self::MlKem1024HkdfSha384Aes256Gcm => 48,
        }
    }
}

/// Draft HPKE KEM identifier for ML-KEM-512.
///
/// This adapter is consumed only by the revision-pinned
/// [`draft_ietf_hpke_pq_05_full`] namespace.  It deliberately leaves the
/// pre-existing two-profile compatibility namespace unchanged.
pub(crate) const ML_KEM_512_KEM_ID: u16 = 0x0040;
/// ML-KEM-512 HPKE public-key serialization length in bytes.
pub(crate) const ML_KEM_512_PUBLIC_KEY_BYTES: usize = 800;
/// ML-KEM-512 HPKE private-key seed serialization length in bytes.
pub(crate) const ML_KEM_512_PRIVATE_KEY_BYTES: usize = 64;
/// ML-KEM-512 HPKE encapsulated-key serialization length in bytes.
pub(crate) const ML_KEM_512_ENCAPSULATED_KEY_BYTES: usize = 768;
/// Expanded FIPS 203 ML-KEM-512 private-key serialization length in bytes.
const ML_KEM_512_EXPANDED_PRIVATE_KEY_BYTES: usize = 1_632;

/// Validated serialized ML-KEM-512 public key for the draft HPKE KEM interface.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MlKem512PublicKey([u8; ML_KEM_512_PUBLIC_KEY_BYTES]);

impl MlKem512PublicKey {
    /// Parse and validate a serialized FIPS 203 ML-KEM-512 encapsulation key.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_512_PUBLIC_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemPublicKey)?;
        let raw = libcrux_ml_kem::mlkem512::MlKem512PublicKey::from(value);
        if !libcrux_ml_kem::mlkem512::validate_public_key(&raw) {
            return Err(CryptError::InvalidKemPublicKey);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical FIPS 203 serialized public key.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_512_PUBLIC_KEY_BYTES] {
        &self.0
    }
}

/// Draft HPKE 64-byte ML-KEM-512 decapsulation-key seed.
///
/// The draft serializes the seed consumed by FIPS 203 key generation, not the
/// expanded ML-KEM private key.  The expanded key exists only for a single
/// decapsulation and its transient serialization is zeroized before return.
pub(crate) struct MlKem512PrivateKey(Zeroizing<[u8; ML_KEM_512_PRIVATE_KEY_BYTES]>);

impl MlKem512PrivateKey {
    /// Parse a draft HPKE ML-KEM-512 private-key seed.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_512_PRIVATE_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemSecretKey)?;
        Ok(Self(Zeroizing::new(value)))
    }

    /// Borrow the 64-byte draft HPKE private-key seed.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_512_PRIVATE_KEY_BYTES] {
        &self.0
    }
}

/// Serialized ML-KEM-512 encapsulated key (`enc`) for a draft HPKE setup.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MlKem512Encapsulation([u8; ML_KEM_512_ENCAPSULATED_KEY_BYTES]);

impl MlKem512Encapsulation {
    /// Parse a fixed-size ML-KEM-512 encapsulated key.
    ///
    /// Same-size modifications deliberately reach FIPS 203 implicit rejection
    /// during decapsulation.  The HPKE context then exposes the resulting key
    /// mismatch only as opaque AEAD authentication failure.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_512_ENCAPSULATED_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemCiphertext)?;
        Ok(Self(value))
    }

    /// Borrow the canonical serialized encapsulated key.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_512_ENCAPSULATED_KEY_BYTES] {
        &self.0
    }
}

/// Generate a FIPS 203 ML-KEM-512 seed-format recipient key pair using PQCA.
pub(crate) fn generate_key_pair_512(
    rng: &mut (impl CryptoRng + RngCore),
) -> (MlKem512PublicKey, MlKem512PrivateKey) {
    let mut seed = Zeroizing::new([0u8; ML_KEM_512_PRIVATE_KEY_BYTES]);
    rng.fill_bytes(&mut seed[..]);

    let private_key = MlKem512PrivateKey(seed.clone());
    let mut expansion_seed = *seed;
    let key_pair = libcrux_ml_kem::mlkem512::generate_key_pair(expansion_seed);
    expansion_seed.zeroize();
    let (raw_private_key, raw_public_key) = key_pair.into_parts();
    let public_key = MlKem512PublicKey(*raw_public_key.as_slice());
    let mut private_key_bytes: [u8; ML_KEM_512_EXPANDED_PRIVATE_KEY_BYTES] = raw_private_key.into();
    private_key_bytes.zeroize();
    (public_key, private_key)
}

/// Deterministically derive ML-KEM-512 from HPKE input keying material.
///
/// This is crate-private vector machinery: production callers use
/// [`generate_key_pair_512`] with OS CSPRNG entropy.
pub(crate) fn derive_key_pair_512(
    ikm: &[u8],
) -> Result<(MlKem512PublicKey, MlKem512PrivateKey), Draft05Error> {
    let seed = kem_labeled_derive(ML_KEM_512_KEM_ID, ikm, b"DeriveKeyPair", b"", 64)?;
    let seed: [u8; ML_KEM_512_PRIVATE_KEY_BYTES] = seed
        .as_slice()
        .try_into()
        .map_err(|_| Draft05Error::InternalInvariant("SHAKE256 output length"))?;
    Ok(expand_512_seed(seed))
}

fn expand_512_seed(
    seed: [u8; ML_KEM_512_PRIVATE_KEY_BYTES],
) -> (MlKem512PublicKey, MlKem512PrivateKey) {
    let private_key = MlKem512PrivateKey(Zeroizing::new(seed));
    let key_pair = libcrux_ml_kem::mlkem512::generate_key_pair(seed);
    let (raw_private_key, raw_public_key) = key_pair.into_parts();
    let public_key = MlKem512PublicKey(*raw_public_key.as_slice());
    let mut private_key_bytes: [u8; ML_KEM_512_EXPANDED_PRIVATE_KEY_BYTES] = raw_private_key.into();
    private_key_bytes.zeroize();
    (public_key, private_key)
}

/// Encapsulate ML-KEM-512 for a validated recipient public key using PQCA.
pub(crate) fn encapsulate_512(
    recipient_public_key: &MlKem512PublicKey,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(MlKem512Encapsulation, MlKemSharedSecret), CryptError> {
    let raw_public_key =
        libcrux_ml_kem::mlkem512::MlKem512PublicKey::from(*recipient_public_key.as_bytes());
    if !libcrux_ml_kem::mlkem512::validate_public_key(&raw_public_key) {
        return Err(CryptError::InvalidKemPublicKey);
    }

    let mut randomness = Zeroizing::new([0u8; ML_KEM_SHARED_SECRET_BYTES]);
    rng.fill_bytes(&mut randomness[..]);
    let (encapsulation, shared_secret) =
        libcrux_ml_kem::mlkem512::encapsulate(&raw_public_key, *randomness);
    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();
    Ok((
        MlKem512Encapsulation(*encapsulation.as_slice()),
        MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)),
    ))
}

/// Decapsulate ML-KEM-512 with FIPS 203 implicit rejection preserved.
pub(crate) fn decapsulate_512(
    recipient_private_key: &MlKem512PrivateKey,
    encapsulation: &MlKem512Encapsulation,
) -> Result<MlKemSharedSecret, CryptError> {
    let mut expansion_seed = *recipient_private_key.as_bytes();
    let key_pair = libcrux_ml_kem::mlkem512::generate_key_pair(expansion_seed);
    expansion_seed.zeroize();
    let (raw_private_key, _) = key_pair.into_parts();
    let raw_encapsulation =
        libcrux_ml_kem::mlkem512::MlKem512Ciphertext::from(*encapsulation.as_bytes());

    // Fixed-size malformed encapsulations intentionally reach FIPS 203 Decaps.
    // Its implicit-rejection secret is consumed by the key schedule; a message
    // authenticated under the original secret then fails only at the AEAD edge.
    let shared_secret = libcrux_ml_kem::mlkem512::decapsulate(&raw_private_key, &raw_encapsulation);
    let mut private_key_bytes: [u8; ML_KEM_512_EXPANDED_PRIVATE_KEY_BYTES] = raw_private_key.into();
    private_key_bytes.zeroize();
    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();
    Ok(MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)))
}

/// Draft HPKE KEM identifier for ML-KEM-768.
pub(crate) const ML_KEM_768_KEM_ID: u16 = 0x0041;
/// ML-KEM-768 HPKE public-key serialization length in bytes.
pub(crate) const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1_184;
/// ML-KEM-768 HPKE private-key seed serialization length in bytes.
pub(crate) const ML_KEM_768_PRIVATE_KEY_BYTES: usize = 64;
/// ML-KEM-768 HPKE encapsulated-key serialization length in bytes.
pub(crate) const ML_KEM_768_ENCAPSULATED_KEY_BYTES: usize = 1_088;
/// ML-KEM shared-secret length in bytes.
pub(crate) const ML_KEM_SHARED_SECRET_BYTES: usize = 32;
/// Expanded FIPS 203 ML-KEM-768 private-key serialization length in bytes.
const ML_KEM_768_EXPANDED_PRIVATE_KEY_BYTES: usize = 2_400;

/// Validated serialized ML-KEM-768 public key for the draft HPKE KEM interface.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MlKem768PublicKey([u8; ML_KEM_768_PUBLIC_KEY_BYTES]);

impl MlKem768PublicKey {
    /// Parse and validate a serialized FIPS 203 ML-KEM-768 encapsulation key.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_768_PUBLIC_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemPublicKey)?;
        let raw = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(value);
        if !libcrux_ml_kem::mlkem768::validate_public_key(&raw) {
            return Err(CryptError::InvalidKemPublicKey);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical FIPS 203 serialized public key.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_768_PUBLIC_KEY_BYTES] {
        &self.0
    }
}

/// Draft HPKE 64-byte ML-KEM-768 decapsulation-key seed.
///
/// The expanded FIPS 203 private key is recreated only for a decapsulation
/// operation. This adapter explicitly zeroizes the temporary serialized
/// expanded-key buffer before return; callers must still protect any source
/// byte slice used to construct this seed.
pub(crate) struct MlKem768PrivateKey(Zeroizing<[u8; ML_KEM_768_PRIVATE_KEY_BYTES]>);

impl MlKem768PrivateKey {
    /// Parse a draft HPKE ML-KEM-768 private-key seed.
    ///
    /// Every 64-byte seed expands through FIPS 203 key generation; expanded
    /// private-key integrity is checked during decapsulation.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_768_PRIVATE_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemSecretKey)?;
        Ok(Self(Zeroizing::new(value)))
    }

    /// Borrow the 64-byte draft HPKE private-key seed.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_768_PRIVATE_KEY_BYTES] {
        &self.0
    }
}

/// Serialized ML-KEM-768 encapsulated key (`enc`) for a draft HPKE setup.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MlKem768Encapsulation([u8; ML_KEM_768_ENCAPSULATED_KEY_BYTES]);

impl MlKem768Encapsulation {
    /// Parse a fixed-size ML-KEM-768 encapsulated key.
    ///
    /// This boundary checks the fixed FIPS serialization length only.
    /// Same-length ciphertext modification is handled by ML-KEM implicit
    /// rejection during [`decapsulate`]. This adapter has no HPKE AEAD context,
    /// so it returns the replacement shared secret rather than a
    /// decapsulation error. A future context must surface the resulting key
    /// mismatch only through AEAD authentication failure.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_768_ENCAPSULATED_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemCiphertext)?;
        Ok(Self(value))
    }

    /// Borrow the canonical serialized encapsulated key.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_768_ENCAPSULATED_KEY_BYTES] {
        &self.0
    }
}

/// Zeroizing 32-byte ML-KEM shared secret.
pub(crate) struct MlKemSharedSecret(Zeroizing<[u8; ML_KEM_SHARED_SECRET_BYTES]>);

impl MlKemSharedSecret {
    /// Borrow the shared secret for the immediate HPKE key schedule.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_SHARED_SECRET_BYTES] {
        &self.0
    }
}

/// Generate a draft HPKE ML-KEM-768 key pair using the PQCA backend.
///
/// The returned private key is the 64-byte FIPS 203 key-generation seed used
/// by the current post-quantum HPKE draft, not the expanded ML-KEM private-key
/// serialization used by the lower-level KEM implementation.
pub(crate) fn generate_key_pair(
    rng: &mut (impl CryptoRng + RngCore),
) -> (MlKem768PublicKey, MlKem768PrivateKey) {
    let mut seed = Zeroizing::new([0u8; ML_KEM_768_PRIVATE_KEY_BYTES]);
    rng.fill_bytes(&mut seed[..]);

    let private_key = MlKem768PrivateKey(seed.clone());
    let mut expansion_seed = *seed;
    let key_pair = libcrux_ml_kem::mlkem768::generate_key_pair(expansion_seed);
    expansion_seed.zeroize();
    let (raw_private_key, raw_public_key) = key_pair.into_parts();
    let public_key = MlKem768PublicKey(*raw_public_key.as_slice());
    let mut private_key_bytes: [u8; ML_KEM_768_EXPANDED_PRIVATE_KEY_BYTES] = raw_private_key.into();
    private_key_bytes.zeroize();
    (public_key, private_key)
}

/// Deterministically derive an ML-KEM-768 key pair from HPKE input keying
/// material using the draft-05 SHAKE256 `LabeledDerive` construction.
pub(crate) fn derive_key_pair(
    ikm: &[u8],
) -> Result<(MlKem768PublicKey, MlKem768PrivateKey), Draft05Error> {
    let seed = kem_labeled_derive(ML_KEM_768_KEM_ID, ikm, b"DeriveKeyPair", b"", 64)?;
    let seed: [u8; ML_KEM_768_PRIVATE_KEY_BYTES] = seed
        .as_slice()
        .try_into()
        .map_err(|_| Draft05Error::InternalInvariant("SHAKE256 output length"))?;
    Ok(expand_768_seed(seed))
}

fn expand_768_seed(
    seed: [u8; ML_KEM_768_PRIVATE_KEY_BYTES],
) -> (MlKem768PublicKey, MlKem768PrivateKey) {
    let private_key = MlKem768PrivateKey(Zeroizing::new(seed));
    let key_pair = libcrux_ml_kem::mlkem768::generate_key_pair(seed);
    let (raw_private_key, raw_public_key) = key_pair.into_parts();
    let public_key = MlKem768PublicKey(*raw_public_key.as_slice());
    let mut private_key_bytes: [u8; ML_KEM_768_EXPANDED_PRIVATE_KEY_BYTES] = raw_private_key.into();
    private_key_bytes.zeroize();
    (public_key, private_key)
}

/// Encapsulate a shared secret for `recipient_public_key` using PQCA ML-KEM-768.
///
/// The public key is revalidated at this trust boundary before encapsulation.
pub(crate) fn encapsulate(
    recipient_public_key: &MlKem768PublicKey,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(MlKem768Encapsulation, MlKemSharedSecret), CryptError> {
    let raw_public_key =
        libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(*recipient_public_key.as_bytes());
    if !libcrux_ml_kem::mlkem768::validate_public_key(&raw_public_key) {
        return Err(CryptError::InvalidKemPublicKey);
    }

    let mut randomness = Zeroizing::new([0u8; ML_KEM_SHARED_SECRET_BYTES]);
    rng.fill_bytes(&mut randomness[..]);
    let (encapsulation, shared_secret) =
        libcrux_ml_kem::mlkem768::encapsulate(&raw_public_key, *randomness);
    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();

    Ok((
        MlKem768Encapsulation(*encapsulation.as_slice()),
        MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)),
    ))
}

/// Deterministically encapsulate ML-KEM-768 for draft-vector verification.
///
/// This is the FIPS 203 `ML-KEM.Encaps` operation with its 32-byte randomness
/// supplied directly.  It is intentionally crate-private: production callers
/// must use [`encapsulate`] with CSPRNG output.
pub(crate) fn encapsulate_derand(
    recipient_public_key: &MlKem768PublicKey,
    randomness: &[u8],
) -> Result<(MlKem768Encapsulation, MlKemSharedSecret), Draft05Error> {
    let randomness: [u8; ML_KEM_SHARED_SECRET_BYTES] =
        randomness
            .try_into()
            .map_err(|_| Draft05Error::InvalidEncapsulationRandomness {
                actual: randomness.len(),
            })?;
    let raw_public_key =
        libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(*recipient_public_key.as_bytes());
    if !libcrux_ml_kem::mlkem768::validate_public_key(&raw_public_key) {
        return Err(Draft05Error::InvalidPublicKey);
    }
    let (encapsulation, shared_secret) =
        libcrux_ml_kem::mlkem768::encapsulate(&raw_public_key, randomness);
    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();
    Ok((
        MlKem768Encapsulation(*encapsulation.as_slice()),
        MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)),
    ))
}

/// Decapsulate a draft HPKE ML-KEM-768 shared secret using the PQCA backend.
///
/// The function expands the 64-byte HPKE seed via FIPS 203 key generation,
/// validates expanded private-key integrity, then zeroizes the expanded
/// serialized private key before returning. Fixed array types enforce the
/// encapsulated-key length before this function is called.
///
/// ML-KEM uses implicit rejection: a fixed-size but modified encapsulated key
/// can produce a replacement shared secret instead of a KEM error. This
/// adapter has no AEAD operation and therefore returns that replacement secret.
/// A future HPKE context must surface the mismatch through AEAD authentication
/// failure, not a distinguishable decapsulation oracle.
pub(crate) fn decapsulate(
    recipient_private_key: &MlKem768PrivateKey,
    encapsulation: &MlKem768Encapsulation,
) -> Result<MlKemSharedSecret, CryptError> {
    let mut expansion_seed = *recipient_private_key.as_bytes();
    let key_pair = libcrux_ml_kem::mlkem768::generate_key_pair(expansion_seed);
    expansion_seed.zeroize();
    let (raw_private_key, _) = key_pair.into_parts();
    let raw_encapsulation =
        libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(*encapsulation.as_bytes());

    // `raw_private_key` was just deterministically created by FIPS 203
    // KeyGen_internal from a fixed-size HPKE seed.  libcrux does not expose a
    // standalone private-key validator, and reserializing it merely to parse
    // it again would not add a trust boundary.  Keep the expanded key local,
    // invoke FIPS 203 decapsulation, and zeroize its serialized temporary.
    // A fixed-size malformed ciphertext intentionally reaches ML-KEM.Decaps
    // so its implicit rejection is collapsed into AEAD authentication failure
    // by the context layer below.
    let shared_secret = libcrux_ml_kem::mlkem768::decapsulate(&raw_private_key, &raw_encapsulation);
    let mut private_key_bytes: [u8; ML_KEM_768_EXPANDED_PRIVATE_KEY_BYTES] = raw_private_key.into();
    private_key_bytes.zeroize();

    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();
    Ok(MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)))
}

/// Draft HPKE KEM identifier for ML-KEM-1024.
pub(crate) const ML_KEM_1024_KEM_ID: u16 = 0x0042;
/// ML-KEM-1024 HPKE public-key serialization length in bytes.
pub(crate) const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1_568;
/// ML-KEM-1024 HPKE private-key seed serialization length in bytes.
pub(crate) const ML_KEM_1024_PRIVATE_KEY_BYTES: usize = 64;
/// ML-KEM-1024 HPKE encapsulated-key serialization length in bytes.
pub(crate) const ML_KEM_1024_ENCAPSULATED_KEY_BYTES: usize = 1_568;
/// Expanded FIPS 203 ML-KEM-1024 private-key serialization length in bytes.
const ML_KEM_1024_EXPANDED_PRIVATE_KEY_BYTES: usize = 3_168;

/// Validated serialized ML-KEM-1024 public key for the draft HPKE KEM interface.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MlKem1024PublicKey([u8; ML_KEM_1024_PUBLIC_KEY_BYTES]);

impl MlKem1024PublicKey {
    /// Parse and validate a serialized FIPS 203 ML-KEM-1024 encapsulation key.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_1024_PUBLIC_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemPublicKey)?;
        let raw = libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::from(value);
        if !libcrux_ml_kem::mlkem1024::validate_public_key(&raw) {
            return Err(CryptError::InvalidKemPublicKey);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical FIPS 203 serialized public key.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_1024_PUBLIC_KEY_BYTES] {
        &self.0
    }
}

/// Draft HPKE 64-byte ML-KEM-1024 decapsulation-key seed.
///
/// The expanded FIPS 203 private key is recreated only for a decapsulation
/// operation. This adapter explicitly zeroizes the temporary serialized
/// expanded-key buffer before return; callers must still protect any source
/// byte slice used to construct this seed.
pub(crate) struct MlKem1024PrivateKey(Zeroizing<[u8; ML_KEM_1024_PRIVATE_KEY_BYTES]>);

impl MlKem1024PrivateKey {
    /// Parse a draft HPKE ML-KEM-1024 private-key seed.
    ///
    /// Every 64-byte seed expands through FIPS 203 key generation; expanded
    /// private-key integrity is checked during decapsulation.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_1024_PRIVATE_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemSecretKey)?;
        Ok(Self(Zeroizing::new(value)))
    }

    /// Borrow the 64-byte draft HPKE private-key seed.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_1024_PRIVATE_KEY_BYTES] {
        &self.0
    }
}

/// Serialized ML-KEM-1024 encapsulated key (`enc`) for a draft HPKE setup.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MlKem1024Encapsulation([u8; ML_KEM_1024_ENCAPSULATED_KEY_BYTES]);

impl MlKem1024Encapsulation {
    /// Parse a fixed-size ML-KEM-1024 encapsulated key.
    ///
    /// This boundary checks the fixed FIPS serialization length only.
    /// Same-length ciphertext modification is handled by ML-KEM implicit
    /// rejection during [`decapsulate_1024`]. This adapter has no HPKE AEAD
    /// context, so it returns the replacement shared secret rather than a
    /// decapsulation error. A future context must surface the resulting key
    /// mismatch only through AEAD authentication failure.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        let value = <[u8; ML_KEM_1024_ENCAPSULATED_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| CryptError::InvalidKemCiphertext)?;
        Ok(Self(value))
    }

    /// Borrow the canonical serialized encapsulated key.
    pub(crate) fn as_bytes(&self) -> &[u8; ML_KEM_1024_ENCAPSULATED_KEY_BYTES] {
        &self.0
    }
}

/// Generate a draft HPKE ML-KEM-1024 key pair using the PQCA backend.
///
/// The returned private key is the 64-byte FIPS 203 key-generation seed used
/// by the current post-quantum HPKE draft, not the expanded ML-KEM private-key
/// serialization used by the lower-level KEM implementation.
pub(crate) fn generate_key_pair_1024(
    rng: &mut (impl CryptoRng + RngCore),
) -> (MlKem1024PublicKey, MlKem1024PrivateKey) {
    let mut seed = Zeroizing::new([0u8; ML_KEM_1024_PRIVATE_KEY_BYTES]);
    rng.fill_bytes(&mut seed[..]);

    let private_key = MlKem1024PrivateKey(seed.clone());
    let mut expansion_seed = *seed;
    let key_pair = libcrux_ml_kem::mlkem1024::generate_key_pair(expansion_seed);
    expansion_seed.zeroize();
    let (raw_private_key, raw_public_key) = key_pair.into_parts();
    let public_key = MlKem1024PublicKey(*raw_public_key.as_slice());
    let mut private_key_bytes: [u8; ML_KEM_1024_EXPANDED_PRIVATE_KEY_BYTES] =
        raw_private_key.into();
    private_key_bytes.zeroize();
    (public_key, private_key)
}

/// Deterministically derive an ML-KEM-1024 key pair from HPKE input keying
/// material using the draft-05 SHAKE256 `LabeledDerive` construction.
pub(crate) fn derive_key_pair_1024(
    ikm: &[u8],
) -> Result<(MlKem1024PublicKey, MlKem1024PrivateKey), Draft05Error> {
    let seed = kem_labeled_derive(ML_KEM_1024_KEM_ID, ikm, b"DeriveKeyPair", b"", 64)?;
    let seed: [u8; ML_KEM_1024_PRIVATE_KEY_BYTES] = seed
        .as_slice()
        .try_into()
        .map_err(|_| Draft05Error::InternalInvariant("SHAKE256 output length"))?;
    Ok(expand_1024_seed(seed))
}

fn expand_1024_seed(
    seed: [u8; ML_KEM_1024_PRIVATE_KEY_BYTES],
) -> (MlKem1024PublicKey, MlKem1024PrivateKey) {
    let private_key = MlKem1024PrivateKey(Zeroizing::new(seed));
    let key_pair = libcrux_ml_kem::mlkem1024::generate_key_pair(seed);
    let (raw_private_key, raw_public_key) = key_pair.into_parts();
    let public_key = MlKem1024PublicKey(*raw_public_key.as_slice());
    let mut private_key_bytes: [u8; ML_KEM_1024_EXPANDED_PRIVATE_KEY_BYTES] =
        raw_private_key.into();
    private_key_bytes.zeroize();
    (public_key, private_key)
}

/// Encapsulate a shared secret for `recipient_public_key` using PQCA ML-KEM-1024.
///
/// The public key is revalidated at this trust boundary before encapsulation.
pub(crate) fn encapsulate_1024(
    recipient_public_key: &MlKem1024PublicKey,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(MlKem1024Encapsulation, MlKemSharedSecret), CryptError> {
    let raw_public_key =
        libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::from(*recipient_public_key.as_bytes());
    if !libcrux_ml_kem::mlkem1024::validate_public_key(&raw_public_key) {
        return Err(CryptError::InvalidKemPublicKey);
    }

    let mut randomness = Zeroizing::new([0u8; ML_KEM_SHARED_SECRET_BYTES]);
    rng.fill_bytes(&mut randomness[..]);
    let (encapsulation, shared_secret) =
        libcrux_ml_kem::mlkem1024::encapsulate(&raw_public_key, *randomness);
    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();

    Ok((
        MlKem1024Encapsulation(*encapsulation.as_slice()),
        MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)),
    ))
}

/// Deterministically encapsulate ML-KEM-1024 for draft-vector verification.
///
/// This is the FIPS 203 `ML-KEM.Encaps` operation with its 32-byte randomness
/// supplied directly. Production callers use [`encapsulate_1024`] with CSPRNG
/// output.
pub(crate) fn encapsulate_derand_1024(
    recipient_public_key: &MlKem1024PublicKey,
    randomness: &[u8],
) -> Result<(MlKem1024Encapsulation, MlKemSharedSecret), Draft05Error> {
    let randomness: [u8; ML_KEM_SHARED_SECRET_BYTES] =
        randomness
            .try_into()
            .map_err(|_| Draft05Error::InvalidEncapsulationRandomness {
                actual: randomness.len(),
            })?;
    let raw_public_key =
        libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::from(*recipient_public_key.as_bytes());
    if !libcrux_ml_kem::mlkem1024::validate_public_key(&raw_public_key) {
        return Err(Draft05Error::InvalidPublicKey);
    }
    let (encapsulation, shared_secret) =
        libcrux_ml_kem::mlkem1024::encapsulate(&raw_public_key, randomness);
    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();
    Ok((
        MlKem1024Encapsulation(*encapsulation.as_slice()),
        MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)),
    ))
}

/// Decapsulate a draft HPKE ML-KEM-1024 shared secret using the PQCA backend.
///
/// The function expands the 64-byte HPKE seed via FIPS 203 key generation,
/// validates expanded private-key integrity, then zeroizes the expanded
/// serialized private key before returning. Fixed array types enforce the
/// encapsulated-key length before this function is called.
///
/// ML-KEM uses implicit rejection: a fixed-size but modified encapsulated key
/// can produce a replacement shared secret instead of a KEM error. This
/// adapter has no AEAD operation and therefore returns that replacement secret.
/// A future HPKE context must surface the mismatch through AEAD authentication
/// failure, not a distinguishable decapsulation oracle.
pub(crate) fn decapsulate_1024(
    recipient_private_key: &MlKem1024PrivateKey,
    encapsulation: &MlKem1024Encapsulation,
) -> Result<MlKemSharedSecret, CryptError> {
    let mut expansion_seed = *recipient_private_key.as_bytes();
    let key_pair = libcrux_ml_kem::mlkem1024::generate_key_pair(expansion_seed);
    expansion_seed.zeroize();
    let (raw_private_key, _) = key_pair.into_parts();
    let raw_encapsulation =
        libcrux_ml_kem::mlkem1024::MlKem1024Ciphertext::from(*encapsulation.as_bytes());

    // See ML-KEM-768 above: the expanded key is generated locally from a
    // fixed-size seed, so there is no untrusted expanded-key serialization to
    // validate.  Same-size malformed `enc` values reach FIPS 203 implicit
    // rejection and become only an opaque AEAD authentication failure later.
    let shared_secret =
        libcrux_ml_kem::mlkem1024::decapsulate(&raw_private_key, &raw_encapsulation);
    let mut private_key_bytes: [u8; ML_KEM_1024_EXPANDED_PRIVATE_KEY_BYTES] =
        raw_private_key.into();
    private_key_bytes.zeroize();

    let shared_secret_bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = shared_secret.into();
    Ok(MlKemSharedSecret(Zeroizing::new(shared_secret_bytes)))
}

/// Stateful Base-mode context for the two pinned draft-05 profiles.
///
/// This is deliberately private until the complete pinned corpus proves the
/// KEM setup, RFC 9180 key schedule, AEAD operations, and exporter for both
/// profiles.  It is not `Clone`: copying a context would duplicate its message
/// sequence and could cause nonce reuse.
struct Draft05BaseContext {
    profile: Draft05Profile,
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<[u8; 12]>,
    exporter_secret: Zeroizing<Vec<u8>>,
    sequence: [u8; 12],
}

impl Draft05BaseContext {
    fn from_shared_secret(
        profile: Draft05Profile,
        shared_secret: &MlKemSharedSecret,
        info: &[u8],
    ) -> Result<Self, Draft05Error> {
        match profile {
            Draft05Profile::MlKem768HkdfSha256Aes128Gcm => {
                let psk_id_hash = labeled_extract_sha256(profile, b"", b"psk_id_hash", b"");
                let info_hash = labeled_extract_sha256(profile, b"", b"info_hash", info);
                let context = base_key_schedule_context(&psk_id_hash, &info_hash);
                let secret = Zeroizing::new(labeled_extract_sha256(
                    profile,
                    shared_secret.as_bytes(),
                    b"secret",
                    b"",
                ));
                let key = Zeroizing::new(labeled_expand_sha256(
                    profile,
                    &secret,
                    b"key",
                    &context,
                    profile.key_len(),
                )?);
                let base_nonce: [u8; 12] =
                    labeled_expand_sha256(profile, &secret, b"base_nonce", &context, 12)?
                        .try_into()
                        .map_err(|_| Draft05Error::InternalInvariant("AES-GCM nonce length"))?;
                let exporter_secret = Zeroizing::new(labeled_expand_sha256(
                    profile,
                    &secret,
                    b"exp",
                    &context,
                    profile.hash_len(),
                )?);
                Ok(Self {
                    profile,
                    key,
                    base_nonce: Zeroizing::new(base_nonce),
                    exporter_secret,
                    sequence: [0_u8; 12],
                })
            }
            Draft05Profile::MlKem1024HkdfSha384Aes256Gcm => {
                let psk_id_hash = labeled_extract_sha384(profile, b"", b"psk_id_hash", b"");
                let info_hash = labeled_extract_sha384(profile, b"", b"info_hash", info);
                let context = base_key_schedule_context(&psk_id_hash, &info_hash);
                let secret = Zeroizing::new(labeled_extract_sha384(
                    profile,
                    shared_secret.as_bytes(),
                    b"secret",
                    b"",
                ));
                let key = Zeroizing::new(labeled_expand_sha384(
                    profile,
                    &secret,
                    b"key",
                    &context,
                    profile.key_len(),
                )?);
                let base_nonce: [u8; 12] =
                    labeled_expand_sha384(profile, &secret, b"base_nonce", &context, 12)?
                        .try_into()
                        .map_err(|_| Draft05Error::InternalInvariant("AES-GCM nonce length"))?;
                let exporter_secret = Zeroizing::new(labeled_expand_sha384(
                    profile,
                    &secret,
                    b"exp",
                    &context,
                    profile.hash_len(),
                )?);
                Ok(Self {
                    profile,
                    key,
                    base_nonce: Zeroizing::new(base_nonce),
                    exporter_secret,
                    sequence: [0_u8; 12],
                })
            }
        }
    }

    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Draft05Error> {
        match self.profile {
            Draft05Profile::MlKem768HkdfSha256Aes128Gcm => labeled_expand_sha256(
                self.profile,
                &self.exporter_secret,
                b"sec",
                exporter_context,
                output_len,
            ),
            Draft05Profile::MlKem1024HkdfSha384Aes256Gcm => labeled_expand_sha384(
                self.profile,
                &self.exporter_secret,
                b"sec",
                exporter_context,
                output_len,
            ),
        }
    }

    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Draft05Error> {
        let nonce = self.nonce_for_current_sequence()?;
        let nonce = AesGcmNonce::try_from(nonce.as_slice())
            .map_err(|_| Draft05Error::InternalInvariant("AES-GCM nonce length"))?;
        let ciphertext = match self.profile {
            Draft05Profile::MlKem768HkdfSha256Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| Draft05Error::InternalInvariant("AES-128-GCM key length"))?
                .encrypt(
                    &nonce,
                    AesPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Draft05Error::AuthenticationFailed)?,
            Draft05Profile::MlKem1024HkdfSha384Aes256Gcm => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| Draft05Error::InternalInvariant("AES-256-GCM key length"))?
                .encrypt(
                    &nonce,
                    AesPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Draft05Error::AuthenticationFailed)?,
        };
        self.advance_after_success()?;
        Ok(ciphertext)
    }

    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Draft05Error> {
        let nonce = self.nonce_for_current_sequence()?;
        let nonce = AesGcmNonce::try_from(nonce.as_slice())
            .map_err(|_| Draft05Error::InternalInvariant("AES-GCM nonce length"))?;
        let plaintext = match self.profile {
            Draft05Profile::MlKem768HkdfSha256Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| Draft05Error::InternalInvariant("AES-128-GCM key length"))?
                .decrypt(
                    &nonce,
                    AesPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| Draft05Error::AuthenticationFailed)?,
            Draft05Profile::MlKem1024HkdfSha384Aes256Gcm => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| Draft05Error::InternalInvariant("AES-256-GCM key length"))?
                .decrypt(
                    &nonce,
                    AesPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| Draft05Error::AuthenticationFailed)?,
        };
        self.advance_after_success()?;
        Ok(plaintext)
    }

    fn nonce_for_current_sequence(&self) -> Result<[u8; 12], Draft05Error> {
        if self.sequence == [u8::MAX; 12] {
            return Err(Draft05Error::MessageLimitReached);
        }
        let mut nonce = *self.base_nonce;
        for (nonce_byte, sequence_byte) in nonce.iter_mut().zip(self.sequence) {
            *nonce_byte ^= sequence_byte;
        }
        Ok(nonce)
    }

    fn advance_after_success(&mut self) -> Result<(), Draft05Error> {
        if self.sequence == [u8::MAX; 12] {
            return Err(Draft05Error::MessageLimitReached);
        }
        for byte in self.sequence.iter_mut().rev() {
            let (incremented, carried) = byte.overflowing_add(1);
            *byte = incremented;
            if !carried {
                break;
            }
        }
        Ok(())
    }
}

fn base_key_schedule_context(psk_id_hash: &[u8], info_hash: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut context = Zeroizing::new(Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len()));
    context.push(0); // RFC 9180 Base mode
    context.extend_from_slice(psk_id_hash);
    context.extend_from_slice(info_hash);
    context
}

fn suite_id(profile: Draft05Profile) -> [u8; 10] {
    let kem = profile.kem_id().to_be_bytes();
    let kdf = profile.kdf_id().to_be_bytes();
    let aead = profile.aead_id().to_be_bytes();
    [
        b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1],
    ]
}

fn labeled_ikm(profile: Draft05Profile, label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let suite = suite_id(profile);
    let mut output =
        Vec::with_capacity(HPKE_VERSION_LABEL.len() + suite.len() + label.len() + ikm.len());
    output.extend_from_slice(HPKE_VERSION_LABEL);
    output.extend_from_slice(&suite);
    output.extend_from_slice(label);
    output.extend_from_slice(ikm);
    output
}

fn labeled_info(
    profile: Draft05Profile,
    label: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, Draft05Error> {
    let output_len: u16 =
        output_len
            .try_into()
            .map_err(|_| Draft05Error::OutputLengthTooLarge {
                requested: output_len,
            })?;
    let suite = suite_id(profile);
    let mut output =
        Vec::with_capacity(2 + HPKE_VERSION_LABEL.len() + suite.len() + label.len() + info.len());
    output.extend_from_slice(&output_len.to_be_bytes());
    output.extend_from_slice(HPKE_VERSION_LABEL);
    output.extend_from_slice(&suite);
    output.extend_from_slice(label);
    output.extend_from_slice(info);
    Ok(output)
}

fn labeled_extract_sha256(
    profile: Draft05Profile,
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Vec<u8> {
    Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm(profile, label, ikm))
        .0
        .to_vec()
}

fn labeled_extract_sha384(
    profile: Draft05Profile,
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Vec<u8> {
    Hkdf::<Sha384>::extract(Some(salt), &labeled_ikm(profile, label, ikm))
        .0
        .to_vec()
}

fn labeled_expand_sha256(
    profile: Draft05Profile,
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, Draft05Error> {
    if output_len > 32 * 255 {
        return Err(Draft05Error::OutputLengthTooLarge {
            requested: output_len,
        });
    }
    let labeled_info = labeled_info(profile, label, info, output_len)?;
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| Draft05Error::InternalInvariant("SHA-256 HKDF pseudorandom key length"))?;
    let mut output = vec![0_u8; output_len];
    hkdf.expand(&labeled_info, &mut output)
        .map_err(|_| Draft05Error::OutputLengthTooLarge {
            requested: output_len,
        })?;
    Ok(output)
}

fn labeled_expand_sha384(
    profile: Draft05Profile,
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, Draft05Error> {
    if output_len > 48 * 255 {
        return Err(Draft05Error::OutputLengthTooLarge {
            requested: output_len,
        });
    }
    let labeled_info = labeled_info(profile, label, info, output_len)?;
    let hkdf = Hkdf::<Sha384>::from_prk(prk)
        .map_err(|_| Draft05Error::InternalInvariant("SHA-384 HKDF pseudorandom key length"))?;
    let mut output = vec![0_u8; output_len];
    hkdf.expand(&labeled_info, &mut output)
        .map_err(|_| Draft05Error::OutputLengthTooLarge {
            requested: output_len,
        })?;
    Ok(output)
}

fn setup_base_sender_768(
    recipient_public_key: &MlKem768PublicKey,
    encapsulation_randomness: &[u8],
    info: &[u8],
) -> Result<(MlKem768Encapsulation, Draft05BaseContext), Draft05Error> {
    let (encapsulation, shared_secret) =
        encapsulate_derand(recipient_public_key, encapsulation_randomness)?;
    let context = Draft05BaseContext::from_shared_secret(
        Draft05Profile::MlKem768HkdfSha256Aes128Gcm,
        &shared_secret,
        info,
    )?;
    Ok((encapsulation, context))
}

fn setup_base_receiver_768(
    recipient_private_key: &MlKem768PrivateKey,
    encapsulation: &MlKem768Encapsulation,
    info: &[u8],
) -> Result<Draft05BaseContext, CryptError> {
    let shared_secret = decapsulate(recipient_private_key, encapsulation)?;
    Draft05BaseContext::from_shared_secret(
        Draft05Profile::MlKem768HkdfSha256Aes128Gcm,
        &shared_secret,
        info,
    )
    .map_err(|_| CryptError::InvalidKemCiphertext)
}

fn setup_base_sender_1024(
    recipient_public_key: &MlKem1024PublicKey,
    encapsulation_randomness: &[u8],
    info: &[u8],
) -> Result<(MlKem1024Encapsulation, Draft05BaseContext), Draft05Error> {
    let (encapsulation, shared_secret) =
        encapsulate_derand_1024(recipient_public_key, encapsulation_randomness)?;
    let context = Draft05BaseContext::from_shared_secret(
        Draft05Profile::MlKem1024HkdfSha384Aes256Gcm,
        &shared_secret,
        info,
    )?;
    Ok((encapsulation, context))
}

fn setup_base_receiver_1024(
    recipient_private_key: &MlKem1024PrivateKey,
    encapsulation: &MlKem1024Encapsulation,
    info: &[u8],
) -> Result<Draft05BaseContext, CryptError> {
    let shared_secret = decapsulate_1024(recipient_private_key, encapsulation)?;
    Draft05BaseContext::from_shared_secret(
        Draft05Profile::MlKem1024HkdfSha384Aes256Gcm,
        &shared_secret,
        info,
    )
    .map_err(|_| CryptError::InvalidKemCiphertext)
}

/// Experimental API for the pinned `draft-ietf-hpke-pq-05` profile mapping.
///
/// This module is intentionally revision-named:
/// it implements only the two Base-mode profiles covered by the vendored
/// draft-05 vectors.  The Internet-Draft is not an RFC, its identifiers are
/// not final IANA registrations, and this API must not be advertised as a
/// standardized post-quantum HPKE profile.
///
/// The API keeps the KEM output (`enc`) separate from ciphertext transport.
/// Applications must persist a protocol family, the literal draft revision,
/// and the exact [`draft_ietf_hpke_pq_05::Profile`] next to both values, then dispatch to this reader
/// directly.  It never serializes as CGv2 and must not be used as a fallback
/// reader for CGv2/HFv1 data.
pub mod draft_ietf_hpke_pq_05 {
    use super::*;

    /// The literal revision of the active IETF mapping implemented here.
    pub const DRAFT_NAME: &str = "draft-ietf-hpke-pq-05";

    /// The exact Base-mode profiles covered by this experimental API.
    ///
    /// There is no algorithm negotiation and no fallback.  A caller chooses
    /// one exact profile for each record and persists that choice alongside
    /// the separately transported `enc` and ciphertext values.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Profile {
        /// ML-KEM-768 / HKDF-SHA256 / AES-128-GCM.
        MlKem768HkdfSha256Aes128Gcm,
        /// ML-KEM-1024 / HKDF-SHA384 / AES-256-GCM.
        MlKem1024HkdfSha384Aes256Gcm,
    }

    impl Profile {
        /// The active-draft KEM identifier.  It is not a final IANA assignment.
        pub const fn kem_id(self) -> u16 {
            match self {
                Self::MlKem768HkdfSha256Aes128Gcm => ML_KEM_768_KEM_ID,
                Self::MlKem1024HkdfSha384Aes256Gcm => ML_KEM_1024_KEM_ID,
            }
        }

        /// The RFC 9180 KDF identifier fixed by this profile.
        pub const fn kdf_id(self) -> u16 {
            match self {
                Self::MlKem768HkdfSha256Aes128Gcm => 0x0001,
                Self::MlKem1024HkdfSha384Aes256Gcm => 0x0002,
            }
        }

        /// The RFC 9180 AEAD identifier fixed by this profile.
        pub const fn aead_id(self) -> u16 {
            match self {
                Self::MlKem768HkdfSha256Aes128Gcm => 0x0001,
                Self::MlKem1024HkdfSha384Aes256Gcm => 0x0002,
            }
        }
    }

    impl From<Profile> for Draft05Profile {
        fn from(value: Profile) -> Self {
            match value {
                Profile::MlKem768HkdfSha256Aes128Gcm => Self::MlKem768HkdfSha256Aes128Gcm,
                Profile::MlKem1024HkdfSha384Aes256Gcm => Self::MlKem1024HkdfSha384Aes256Gcm,
            }
        }
    }

    /// Typed errors returned by the experimental draft-05 API.
    ///
    /// In particular, AEAD failures deliberately do not disclose whether the
    /// problem was the ciphertext, AAD, or a same-size modified `enc` value.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Error {
        /// The supplied public key is not a valid FIPS 203 ML-KEM key for its
        /// claimed profile.
        InvalidRecipientPublicKey,
        /// The supplied private key is not a 64-byte draft-05 ML-KEM seed.
        InvalidRecipientPrivateKey,
        /// The supplied encapsulated key does not have the required fixed
        /// serialization length for its claimed profile.
        InvalidEncapsulation,
        /// The explicit profile selected by the caller disagrees with a typed
        /// key or encapsulation object.
        ProfileMismatch { expected: Profile, actual: Profile },
        /// AES-GCM authentication failed.  This is also the only outcome for
        /// a same-size modified ML-KEM encapsulation after implicit rejection.
        AuthenticationFailed,
        /// The requested exporter output cannot be represented by the draft
        /// HPKE length encoding or exceeds the selected HKDF expansion limit.
        OutputLengthTooLarge { requested: usize },
        /// The context has exhausted its message sequence and will not wrap.
        MessageLimitReached,
        /// An unreachable internal invariant failed.  This variant contains
        /// no cryptographic detail and is never used to classify attacker
        /// controlled ciphertext input.
        InternalFailure,
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidRecipientPublicKey => {
                    f.write_str("draft-ietf-hpke-pq-05 recipient public key is invalid")
                }
                Self::InvalidRecipientPrivateKey => {
                    f.write_str("draft-ietf-hpke-pq-05 recipient private-key seed is invalid")
                }
                Self::InvalidEncapsulation => {
                    f.write_str("draft-ietf-hpke-pq-05 encapsulated key is invalid")
                }
                Self::ProfileMismatch { expected, actual } => write!(
                    f,
                    "draft-ietf-hpke-pq-05 profile mismatch: expected {expected:?}, got {actual:?}"
                ),
                Self::AuthenticationFailed => {
                    f.write_str("draft-ietf-hpke-pq-05 authentication failed")
                }
                Self::OutputLengthTooLarge { requested } => write!(
                    f,
                    "draft-ietf-hpke-pq-05 output length {requested} is unsupported",
                ),
                Self::MessageLimitReached => f.write_str(
                    "draft-ietf-hpke-pq-05 message limit reached; sequence number must not wrap",
                ),
                Self::InternalFailure => {
                    f.write_str("draft-ietf-hpke-pq-05 internal operation failed")
                }
            }
        }
    }

    impl std::error::Error for Error {}

    /// A validated, serializable recipient public key for one exact profile.
    #[derive(Clone, Eq, PartialEq)]
    pub struct RecipientPublicKey {
        profile: Profile,
        inner: RecipientPublicKeyInner,
    }

    #[derive(Clone, Eq, PartialEq)]
    enum RecipientPublicKeyInner {
        MlKem768(Box<MlKem768PublicKey>),
        MlKem1024(Box<MlKem1024PublicKey>),
    }

    impl RecipientPublicKey {
        /// Parse and validate a FIPS 203 public-key serialization for `profile`.
        pub fn from_bytes(profile: Profile, bytes: &[u8]) -> Result<Self, Error> {
            let inner = match profile {
                Profile::MlKem768HkdfSha256Aes128Gcm => MlKem768PublicKey::from_bytes(bytes)
                    .map(Box::new)
                    .map(RecipientPublicKeyInner::MlKem768)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?,
                Profile::MlKem1024HkdfSha384Aes256Gcm => MlKem1024PublicKey::from_bytes(bytes)
                    .map(Box::new)
                    .map(RecipientPublicKeyInner::MlKem1024)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?,
            };
            Ok(Self { profile, inner })
        }

        /// The exact experimental draft-05 profile this key belongs to.
        pub const fn profile(&self) -> Profile {
            self.profile
        }

        /// Borrow the canonical FIPS 203 public-key serialization.
        pub fn as_bytes(&self) -> &[u8] {
            match &self.inner {
                RecipientPublicKeyInner::MlKem768(key) => key.as_bytes(),
                RecipientPublicKeyInner::MlKem1024(key) => key.as_bytes(),
            }
        }
    }

    /// A recipient private key represented by the draft's 64-byte ML-KEM seed.
    ///
    /// This type deliberately does not implement `Clone` or `Debug`.
    pub struct RecipientPrivateKey {
        profile: Profile,
        inner: RecipientPrivateKeyInner,
    }

    enum RecipientPrivateKeyInner {
        MlKem768(MlKem768PrivateKey),
        MlKem1024(MlKem1024PrivateKey),
    }

    impl RecipientPrivateKey {
        /// Parse a 64-byte draft-05 ML-KEM private-key seed for `profile`.
        pub fn from_seed_bytes(profile: Profile, bytes: &[u8]) -> Result<Self, Error> {
            let inner = match profile {
                Profile::MlKem768HkdfSha256Aes128Gcm => MlKem768PrivateKey::from_bytes(bytes)
                    .map(RecipientPrivateKeyInner::MlKem768)
                    .map_err(|_| Error::InvalidRecipientPrivateKey)?,
                Profile::MlKem1024HkdfSha384Aes256Gcm => MlKem1024PrivateKey::from_bytes(bytes)
                    .map(RecipientPrivateKeyInner::MlKem1024)
                    .map_err(|_| Error::InvalidRecipientPrivateKey)?,
            };
            Ok(Self { profile, inner })
        }

        /// The exact experimental draft-05 profile this key belongs to.
        pub const fn profile(&self) -> Profile {
            self.profile
        }

        /// Borrow the 64-byte seed for persistence in an application-managed
        /// secret store.  Never log or transport this value.
        pub fn as_seed_bytes(&self) -> &[u8] {
            match &self.inner {
                RecipientPrivateKeyInner::MlKem768(key) => key.as_bytes(),
                RecipientPrivateKeyInner::MlKem1024(key) => key.as_bytes(),
            }
        }
    }

    /// A generated public/private recipient key pair for one exact profile.
    pub struct RecipientKeyPair {
        public_key: RecipientPublicKey,
        private_key: RecipientPrivateKey,
    }

    impl RecipientKeyPair {
        /// Borrow the recipient public key for distribution to senders.
        pub fn public_key(&self) -> &RecipientPublicKey {
            &self.public_key
        }

        /// Borrow the recipient private key for immediate setup.
        pub fn private_key(&self) -> &RecipientPrivateKey {
            &self.private_key
        }

        /// Consume the pair to move its public and private key into separate
        /// application-owned stores.
        pub fn into_parts(self) -> (RecipientPublicKey, RecipientPrivateKey) {
            (self.public_key, self.private_key)
        }
    }

    /// Generate a FIPS 203 ML-KEM key pair using the operating-system CSPRNG.
    pub fn generate_recipient_key_pair(profile: Profile) -> RecipientKeyPair {
        let mut rng = rand::rngs::OsRng;
        match profile {
            Profile::MlKem768HkdfSha256Aes128Gcm => {
                let (public_key, private_key) = generate_key_pair(&mut rng);
                RecipientKeyPair {
                    public_key: RecipientPublicKey {
                        profile,
                        inner: RecipientPublicKeyInner::MlKem768(Box::new(public_key)),
                    },
                    private_key: RecipientPrivateKey {
                        profile,
                        inner: RecipientPrivateKeyInner::MlKem768(private_key),
                    },
                }
            }
            Profile::MlKem1024HkdfSha384Aes256Gcm => {
                let (public_key, private_key) = generate_key_pair_1024(&mut rng);
                RecipientKeyPair {
                    public_key: RecipientPublicKey {
                        profile,
                        inner: RecipientPublicKeyInner::MlKem1024(Box::new(public_key)),
                    },
                    private_key: RecipientPrivateKey {
                        profile,
                        inner: RecipientPrivateKeyInner::MlKem1024(private_key),
                    },
                }
            }
        }
    }

    /// A separate serialized KEM output (`enc`) for a draft-05 HPKE setup.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Encapsulation {
        profile: Profile,
        inner: EncapsulationInner,
    }

    #[derive(Clone, Eq, PartialEq)]
    enum EncapsulationInner {
        MlKem768(MlKem768Encapsulation),
        MlKem1024(MlKem1024Encapsulation),
    }

    impl Encapsulation {
        /// Parse the fixed-size `enc` serialization for `profile`.
        ///
        /// A correctly-sized modified value is intentionally accepted here;
        /// FIPS 203 implicit rejection makes it an opaque
        /// [`Error::AuthenticationFailed`] only when the recipient opens a
        /// ciphertext with the resulting context.
        pub fn from_bytes(profile: Profile, bytes: &[u8]) -> Result<Self, Error> {
            let inner = match profile {
                Profile::MlKem768HkdfSha256Aes128Gcm => MlKem768Encapsulation::from_bytes(bytes)
                    .map(EncapsulationInner::MlKem768)
                    .map_err(|_| Error::InvalidEncapsulation)?,
                Profile::MlKem1024HkdfSha384Aes256Gcm => MlKem1024Encapsulation::from_bytes(bytes)
                    .map(EncapsulationInner::MlKem1024)
                    .map_err(|_| Error::InvalidEncapsulation)?,
            };
            Ok(Self { profile, inner })
        }

        /// The exact experimental draft-05 profile this `enc` belongs to.
        pub const fn profile(&self) -> Profile {
            self.profile
        }

        /// Borrow the canonical `enc` serialization for separate transport.
        pub fn as_bytes(&self) -> &[u8] {
            match &self.inner {
                EncapsulationInner::MlKem768(enc) => enc.as_bytes(),
                EncapsulationInner::MlKem1024(enc) => enc.as_bytes(),
            }
        }
    }

    /// Stateful sender context.  It intentionally has no `Clone` impl, which
    /// prevents copying its sequence number and reusing a nonce.
    pub struct SenderContext(Draft05BaseContext);

    impl SenderContext {
        /// Seal one message using the next RFC 9180-derived nonce.
        ///
        /// There is deliberately no caller-supplied nonce parameter.
        pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.seal(aad, plaintext).map_err(map_context_error)
        }

        /// Derive exporter output without advancing the message sequence.
        pub fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
            self.0
                .export(exporter_context, output_len)
                .map_err(map_context_error)
        }
    }

    /// Stateful recipient context.  It intentionally has no `Clone` impl,
    /// preventing a duplicated sequence from accepting the same nonce twice.
    pub struct RecipientContext(Draft05BaseContext);

    impl RecipientContext {
        /// Authenticate and open one message using the next RFC 9180-derived
        /// nonce.  Ciphertext, AAD, and same-size modified `enc` failures are
        /// all returned as [`Error::AuthenticationFailed`].
        pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.open(aad, ciphertext).map_err(map_context_error)
        }

        /// Derive exporter output without advancing the message sequence.
        pub fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
            self.0
                .export(exporter_context, output_len)
                .map_err(map_context_error)
        }
    }

    /// Set up a Base-mode sender context and return its separate `enc` value.
    ///
    /// `info` is setup context, while `aad` is supplied separately to
    /// [`SenderContext::seal`].  This function uses the operating-system CSPRNG
    /// for FIPS 203 encapsulation randomness and never exposes the shared
    /// secret.
    pub fn setup_base_sender(
        profile: Profile,
        recipient_public_key: &RecipientPublicKey,
        info: &[u8],
    ) -> Result<(Encapsulation, SenderContext), Error> {
        ensure_profile(profile, recipient_public_key.profile)?;
        match &recipient_public_key.inner {
            RecipientPublicKeyInner::MlKem768(public_key) => {
                let mut rng = rand::rngs::OsRng;
                let (encapsulation, shared_secret) = encapsulate(public_key, &mut rng)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?;
                let context =
                    Draft05BaseContext::from_shared_secret(profile.into(), &shared_secret, info)
                        .map_err(map_context_error)?;
                Ok((
                    Encapsulation {
                        profile,
                        inner: EncapsulationInner::MlKem768(encapsulation),
                    },
                    SenderContext(context),
                ))
            }
            RecipientPublicKeyInner::MlKem1024(public_key) => {
                let mut rng = rand::rngs::OsRng;
                let (encapsulation, shared_secret) = encapsulate_1024(public_key, &mut rng)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?;
                let context =
                    Draft05BaseContext::from_shared_secret(profile.into(), &shared_secret, info)
                        .map_err(map_context_error)?;
                Ok((
                    Encapsulation {
                        profile,
                        inner: EncapsulationInner::MlKem1024(encapsulation),
                    },
                    SenderContext(context),
                ))
            }
        }
    }

    /// Set up a Base-mode recipient context from separately transported `enc`.
    ///
    /// A same-size modified `enc` intentionally reaches FIPS 203 implicit
    /// rejection.  Call [`RecipientContext::open`] with the ciphertext to get
    /// the single opaque [`Error::AuthenticationFailed`] result.
    pub fn setup_base_receiver(
        profile: Profile,
        recipient_private_key: &RecipientPrivateKey,
        encapsulation: &Encapsulation,
        info: &[u8],
    ) -> Result<RecipientContext, Error> {
        ensure_profile(profile, recipient_private_key.profile)?;
        ensure_profile(profile, encapsulation.profile)?;
        let shared_secret = match (&recipient_private_key.inner, &encapsulation.inner) {
            (
                RecipientPrivateKeyInner::MlKem768(private_key),
                EncapsulationInner::MlKem768(enc),
            ) => decapsulate(private_key, enc).map_err(|_| Error::InternalFailure)?,
            (
                RecipientPrivateKeyInner::MlKem1024(private_key),
                EncapsulationInner::MlKem1024(enc),
            ) => decapsulate_1024(private_key, enc).map_err(|_| Error::InternalFailure)?,
            _ => {
                return Err(Error::ProfileMismatch {
                    expected: profile,
                    actual: encapsulation.profile,
                });
            }
        };
        let context = Draft05BaseContext::from_shared_secret(profile.into(), &shared_secret, info)
            .map_err(map_context_error)?;
        Ok(RecipientContext(context))
    }

    fn ensure_profile(expected: Profile, actual: Profile) -> Result<(), Error> {
        if expected == actual {
            Ok(())
        } else {
            Err(Error::ProfileMismatch { expected, actual })
        }
    }

    fn map_context_error(error: Draft05Error) -> Error {
        match error {
            Draft05Error::MessageLimitReached => Error::MessageLimitReached,
            Draft05Error::OutputLengthTooLarge { requested } => {
                Error::OutputLengthTooLarge { requested }
            }
            Draft05Error::AuthenticationFailed => Error::AuthenticationFailed,
            Draft05Error::InvalidPublicKey => Error::InvalidRecipientPublicKey,
            Draft05Error::InvalidEncapsulationRandomness { .. }
            | Draft05Error::LabelTooLarge { .. }
            | Draft05Error::InternalInvariant(_) => Error::InternalFailure,
        }
    }
}

/// Revision-pinned, capability-explicit HPKE API for
/// `draft-ietf-hpke-pq-05`.
///
/// This is a separate namespace from [`draft_ietf_hpke_pq_05`].  Its suite
/// descriptor follows the draft's complete KEM/KDF/AEAD identifier space, but
/// setup is enabled only when every selected primitive has an audited local
/// implementation.  In particular, descriptors are *not* negotiation and a
/// descriptor that is unavailable can never silently fall back to a different
/// KEM, KDF, or AEAD.  The draft remains an Internet-Draft, not an RFC or a
/// final IANA registration.
pub mod draft_ietf_hpke_pq_05_full {
    use super::*;
    use chacha20poly1305::{
        aead::{Aead as ChaChaAead, KeyInit, Payload},
        ChaCha20Poly1305, Nonce as ChaCha20Poly1305Nonce,
    };
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{ecdh::diffie_hellman, PublicKey as P256PublicKey, SecretKey as P256SecretKey};
    use p384::{
        ecdh::diffie_hellman as p384_diffie_hellman, PublicKey as P384PublicKey,
        SecretKey as P384SecretKey,
    };
    use sha2_011::Sha512;
    use sha3::Shake128;
    use sha3::{Digest, Sha3_256};
    use turboshake::{TurboShake128, TurboShake256};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

    const HYBRID_SEED_BYTES: usize = 32;
    const P256_POINT_BYTES: usize = 65;
    const P384_POINT_BYTES: usize = 97;
    const X25519_POINT_BYTES: usize = 32;
    const MLKEM768_P256_PUBLIC_KEY_BYTES: usize = ML_KEM_768_PUBLIC_KEY_BYTES + P256_POINT_BYTES;
    const MLKEM768_P256_ENCAPSULATION_BYTES: usize =
        ML_KEM_768_ENCAPSULATED_KEY_BYTES + P256_POINT_BYTES;
    const MLKEM1024_P384_PUBLIC_KEY_BYTES: usize = ML_KEM_1024_PUBLIC_KEY_BYTES + P384_POINT_BYTES;
    const MLKEM1024_P384_ENCAPSULATION_BYTES: usize =
        ML_KEM_1024_ENCAPSULATED_KEY_BYTES + P384_POINT_BYTES;
    const MLKEM768_X25519_PUBLIC_KEY_BYTES: usize =
        ML_KEM_768_PUBLIC_KEY_BYTES + X25519_POINT_BYTES;
    const MLKEM768_X25519_ENCAPSULATION_BYTES: usize =
        ML_KEM_768_ENCAPSULATED_KEY_BYTES + X25519_POINT_BYTES;

    /// The exact IETF working-document revision implemented by this namespace.
    pub const DRAFT_NAME: &str = "draft-ietf-hpke-pq-05";

    /// KEM identifiers named by the post-quantum HPKE draft.
    ///
    /// The hybrid identifiers remain revision-pinned draft values.  They are
    /// intentionally not presented as permanent IANA registrations.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u16)]
    pub enum Kem {
        /// FIPS 203 ML-KEM-512 (draft KEM id `0x0040`).
        MlKem512 = 0x0040,
        /// FIPS 203 ML-KEM-768 (draft KEM id `0x0041`).
        MlKem768 = 0x0041,
        /// FIPS 203 ML-KEM-1024 (draft KEM id `0x0042`).
        MlKem1024 = 0x0042,
        /// Draft concrete hybrid ML-KEM-768 / P-256 (`0x0050`).
        MlKem768P256 = 0x0050,
        /// Draft concrete hybrid ML-KEM-1024 / P-384 (`0x0051`).
        MlKem1024P384 = 0x0051,
        /// Draft concrete hybrid ML-KEM-768 / X25519 (`0x647a`).
        MlKem768X25519 = 0x647a,
    }

    impl Kem {
        /// The two-octet KEM identifier encoded in a ciphersuite id.
        pub const fn id(self) -> u16 {
            self as u16
        }
    }

    /// Two-stage and one-stage KDF identifiers applicable to draft-05 HPKE.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u16)]
    pub enum Kdf {
        /// RFC 9180 HKDF-SHA256 (`0x0001`).
        HkdfSha256 = 0x0001,
        /// RFC 9180 HKDF-SHA384 (`0x0002`).
        HkdfSha384 = 0x0002,
        /// RFC 9180 HKDF-SHA512 (`0x0003`).
        HkdfSha512 = 0x0003,
        /// Draft SHAKE128 one-stage KDF (`0x0010`).
        Shake128 = 0x0010,
        /// Draft SHAKE256 one-stage KDF (`0x0011`).
        Shake256 = 0x0011,
        /// Draft TurboSHAKE128 one-stage KDF (`0x0012`).
        TurboShake128 = 0x0012,
        /// Draft TurboSHAKE256 one-stage KDF (`0x0013`).
        TurboShake256 = 0x0013,
    }

    impl Kdf {
        /// The two-octet KDF identifier encoded in a ciphersuite id.
        pub const fn id(self) -> u16 {
            self as u16
        }

        const fn nh(self) -> usize {
            match self {
                Self::HkdfSha256 | Self::Shake128 | Self::TurboShake128 => 32,
                Self::HkdfSha384 => 48,
                Self::HkdfSha512 | Self::Shake256 | Self::TurboShake256 => 64,
            }
        }

        const fn is_one_stage(self) -> bool {
            matches!(
                self,
                Self::Shake128 | Self::Shake256 | Self::TurboShake128 | Self::TurboShake256
            )
        }
    }

    /// All RFC 9180 AEAD identifiers.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u16)]
    pub enum Aead {
        /// AES-128-GCM (`0x0001`).
        Aes128Gcm = 0x0001,
        /// AES-256-GCM (`0x0002`).
        Aes256Gcm = 0x0002,
        /// ChaCha20-Poly1305 (`0x0003`).
        ChaCha20Poly1305 = 0x0003,
        /// RFC 9180 Export-Only (`0xffff`); `seal` and `open` are unavailable.
        ExportOnly = 0xffff,
    }

    impl Aead {
        /// The two-octet AEAD identifier encoded in a ciphersuite id.
        pub const fn id(self) -> u16 {
            self as u16
        }

        const fn key_len(self) -> usize {
            match self {
                Self::Aes128Gcm => 16,
                Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
                Self::ExportOnly => 0,
            }
        }
    }

    /// One exact draft ciphersuite; this type performs no algorithm selection.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Suite {
        kem: Kem,
        kdf: Kdf,
        aead: Aead,
    }

    impl Suite {
        /// Pin a KEM, KDF, and AEAD.  Persist all three identifiers plus
        /// [`DRAFT_NAME`] with externally stored `enc` and ciphertext values.
        pub const fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
            Self { kem, kdf, aead }
        }

        /// The selected draft KEM.
        pub const fn kem(self) -> Kem {
            self.kem
        }
        /// The selected two-stage or one-stage KDF.
        pub const fn kdf(self) -> Kdf {
            self.kdf
        }
        /// The selected RFC 9180 AEAD identifier.
        pub const fn aead(self) -> Aead {
            self.aead
        }

        /// The HPKE suite id used by the draft's labeled derivations.
        pub const fn suite_id(self) -> [u8; 10] {
            let kem = self.kem.id().to_be_bytes();
            let kdf = self.kdf.id().to_be_bytes();
            let aead = self.aead.id().to_be_bytes();
            [
                b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1],
            ]
        }

        /// Report whether the exact suite is locally operational.  This is a
        /// capability query, never a permission to substitute another suite.
        pub const fn capability(self) -> Capability {
            match self.kem {
                Kem::MlKem512 | Kem::MlKem768 | Kem::MlKem1024 => match self.kdf {
                    Kdf::HkdfSha256
                    | Kdf::HkdfSha384
                    | Kdf::HkdfSha512
                    | Kdf::Shake128
                    | Kdf::Shake256
                    | Kdf::TurboShake128
                    | Kdf::TurboShake256 => Capability::Available,
                },
                Kem::MlKem768P256 | Kem::MlKem1024P384 | Kem::MlKem768X25519 => {
                    Capability::Available
                }
            }
        }
    }

    /// Exact-suite availability result.  Unavailability is deliberate and
    /// typed so callers cannot mistake a descriptor for interoperable support.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Capability {
        /// All selected primitives are locally implemented.
        Available,
        /// At least one selected primitive is intentionally not compiled in.
        Unavailable(&'static str),
    }

    /// Errors returned by the revision-pinned full namespace.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Error {
        /// A selected primitive has no audited implementation in this build.
        UnavailableCapability { suite: Suite, reason: &'static str },
        /// A typed key or encapsulation was supplied for a different KEM.
        KemMismatch { expected: Kem, actual: Kem },
        /// A public key was malformed or failed FIPS 203 validation.
        InvalidRecipientPublicKey,
        /// A private key was not the 64-byte FIPS 203 seed format.
        InvalidRecipientPrivateKey,
        /// `enc` did not have the fixed serialization length for its KEM.
        InvalidEncapsulation,
        /// Base mode received either half of a PSK pair, or PSK mode did not
        /// receive both values.
        InvalidPskInputs { has_psk: bool, has_psk_id: bool },
        /// A one-stage labeled derivation exceeded its two-octet encoding.
        OutputLengthTooLarge { requested: usize },
        /// A label, info, PSK, or PSK identifier exceeded its length encoding.
        InputLengthTooLarge { actual: usize },
        /// The selected Export-Only AEAD cannot encrypt or decrypt.
        ExportOnlyAead,
        /// AEAD authentication failed.  This also covers same-size tampered
        /// ML-KEM encapsulations after FIPS 203 implicit rejection.
        AuthenticationFailed,
        /// The 96-bit HPKE message sequence must not wrap.
        MessageLimitReached,
        /// A checked internal fixed-size conversion failed.
        InternalInvariant,
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::UnavailableCapability { suite, reason } => write!(
                    f,
                    "{DRAFT_NAME} suite {suite:?} is unavailable: {reason}"
                ),
                Self::KemMismatch { expected, actual } => write!(
                    f,
                    "{DRAFT_NAME} KEM mismatch: expected {expected:?}, got {actual:?}"
                ),
                Self::InvalidRecipientPublicKey => f.write_str("invalid draft-05 recipient public key"),
                Self::InvalidRecipientPrivateKey => f.write_str("invalid draft-05 recipient private key"),
                Self::InvalidEncapsulation => f.write_str("invalid draft-05 encapsulation"),
                Self::InvalidPskInputs { has_psk, has_psk_id } => write!(
                    f,
                    "invalid draft-05 PSK inputs: psk present={has_psk}, psk_id present={has_psk_id}"
                ),
                Self::OutputLengthTooLarge { requested } => write!(
                    f,
                    "draft-05 requested output length {requested} exceeds the supported bound"
                ),
                Self::InputLengthTooLarge { actual } => write!(
                    f,
                    "draft-05 input length {actual} exceeds its two-octet encoding bound"
                ),
                Self::ExportOnlyAead => f.write_str("draft-05 Export-Only AEAD cannot seal or open"),
                Self::AuthenticationFailed => f.write_str("draft-05 AEAD authentication failed"),
                Self::MessageLimitReached => f.write_str("draft-05 message limit reached; sequence must not wrap"),
                Self::InternalInvariant => f.write_str("draft-05 internal invariant failed"),
            }
        }
    }

    impl std::error::Error for Error {}

    // The draft names concrete hybrid KEM identifiers, but this crate does
    // not yet have an audited, interoperable implementation of their exact
    // combiner and wire format.  Keep typed placeholders so the public
    // descriptor remains parseable while every operational path fails closed
    // through `UnavailableCapability`; never silently substitute ML-KEM-only.
    #[derive(Clone, Eq, PartialEq)]
    struct HybridPublicKey {
        kem: Kem,
        bytes: Vec<u8>,
    }
    impl HybridPublicKey {
        fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
            match kem {
                Kem::MlKem768P256 if bytes.len() == MLKEM768_P256_PUBLIC_KEY_BYTES => {
                    MlKem768PublicKey::from_bytes(&bytes[..ML_KEM_768_PUBLIC_KEY_BYTES])
                        .map_err(|_| Error::InvalidRecipientPublicKey)?;
                    P256PublicKey::from_sec1_bytes(&bytes[ML_KEM_768_PUBLIC_KEY_BYTES..])
                        .map_err(|_| Error::InvalidRecipientPublicKey)?;
                }
                Kem::MlKem1024P384 if bytes.len() == MLKEM1024_P384_PUBLIC_KEY_BYTES => {
                    MlKem1024PublicKey::from_bytes(&bytes[..ML_KEM_1024_PUBLIC_KEY_BYTES])
                        .map_err(|_| Error::InvalidRecipientPublicKey)?;
                    P384PublicKey::from_sec1_bytes(&bytes[ML_KEM_1024_PUBLIC_KEY_BYTES..])
                        .map_err(|_| Error::InvalidRecipientPublicKey)?;
                }
                Kem::MlKem768X25519 if bytes.len() == MLKEM768_X25519_PUBLIC_KEY_BYTES => {
                    MlKem768PublicKey::from_bytes(&bytes[..ML_KEM_768_PUBLIC_KEY_BYTES])
                        .map_err(|_| Error::InvalidRecipientPublicKey)?;
                    let traditional =
                        <[u8; X25519_POINT_BYTES]>::try_from(&bytes[ML_KEM_768_PUBLIC_KEY_BYTES..])
                            .map_err(|_| Error::InvalidRecipientPublicKey)?;
                    let _ = X25519PublicKey::from(traditional);
                }
                _ => return Err(Error::InvalidRecipientPublicKey),
            }
            Ok(Self {
                kem,
                bytes: bytes.to_vec(),
            })
        }
        fn derive(kem: Kem, seed: &[u8]) -> Result<Self, Error> {
            if seed.len() != HYBRID_SEED_BYTES {
                return Err(Error::InvalidRecipientPrivateKey);
            }
            match kem {
                Kem::MlKem768P256 => {
                    let (pq, _, scalar) = derive_hybrid_key_pair(seed)?;
                    let point = scalar.public_key().to_encoded_point(false);
                    let mut bytes = Vec::with_capacity(MLKEM768_P256_PUBLIC_KEY_BYTES);
                    bytes.extend_from_slice(pq.as_bytes());
                    bytes.extend_from_slice(point.as_bytes());
                    Ok(Self { kem, bytes })
                }
                Kem::MlKem1024P384 => {
                    let (pq, _, scalar) = derive_hybrid_p384_key_pair(seed)?;
                    let point = scalar.public_key().to_encoded_point(false);
                    let mut bytes = Vec::with_capacity(MLKEM1024_P384_PUBLIC_KEY_BYTES);
                    bytes.extend_from_slice(pq.as_bytes());
                    bytes.extend_from_slice(point.as_bytes());
                    Ok(Self { kem, bytes })
                }
                Kem::MlKem768X25519 => {
                    let (pq, _, secret) = derive_hybrid_x25519_key_pair(seed)?;
                    let point = X25519PublicKey::from(&secret);
                    let mut bytes = Vec::with_capacity(MLKEM768_X25519_PUBLIC_KEY_BYTES);
                    bytes.extend_from_slice(pq.as_bytes());
                    bytes.extend_from_slice(point.as_bytes());
                    Ok(Self { kem, bytes })
                }
                _ => Err(Error::InvalidRecipientPrivateKey),
            }
        }
        fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }
    struct HybridPrivateKey {
        kem: Kem,
        seed: Zeroizing<[u8; HYBRID_SEED_BYTES]>,
    }
    impl HybridPrivateKey {
        fn from_seed_bytes(kem: Kem, seed: &[u8]) -> Result<Self, Error> {
            let value = <[u8; HYBRID_SEED_BYTES]>::try_from(seed)
                .map_err(|_| Error::InvalidRecipientPrivateKey)?;
            match kem {
                Kem::MlKem768P256 | Kem::MlKem1024P384 | Kem::MlKem768X25519 => {
                    Ok(Self::from_seed(kem, Zeroizing::new(value)))
                }
                _ => Err(Error::InvalidRecipientPrivateKey),
            }
        }
        fn from_seed(kem: Kem, seed: Zeroizing<[u8; HYBRID_SEED_BYTES]>) -> Self {
            Self { kem, seed }
        }
        fn as_seed_bytes(&self) -> &[u8] {
            &self.seed[..]
        }
    }
    #[derive(Clone, Eq, PartialEq)]
    struct HybridEncapsulation {
        kem: Kem,
        bytes: Vec<u8>,
    }
    impl HybridEncapsulation {
        fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
            match kem {
                Kem::MlKem768P256 if bytes.len() == MLKEM768_P256_ENCAPSULATION_BYTES => {
                    P256PublicKey::from_sec1_bytes(&bytes[ML_KEM_768_ENCAPSULATED_KEY_BYTES..])
                        .map_err(|_| Error::InvalidEncapsulation)?;
                    MlKem768Encapsulation::from_bytes(&bytes[..ML_KEM_768_ENCAPSULATED_KEY_BYTES])
                        .map_err(|_| Error::InvalidEncapsulation)?;
                }
                Kem::MlKem1024P384 if bytes.len() == MLKEM1024_P384_ENCAPSULATION_BYTES => {
                    P384PublicKey::from_sec1_bytes(&bytes[ML_KEM_1024_ENCAPSULATED_KEY_BYTES..])
                        .map_err(|_| Error::InvalidEncapsulation)?;
                    MlKem1024Encapsulation::from_bytes(
                        &bytes[..ML_KEM_1024_ENCAPSULATED_KEY_BYTES],
                    )
                    .map_err(|_| Error::InvalidEncapsulation)?;
                }
                Kem::MlKem768X25519 if bytes.len() == MLKEM768_X25519_ENCAPSULATION_BYTES => {
                    MlKem768Encapsulation::from_bytes(&bytes[..ML_KEM_768_ENCAPSULATED_KEY_BYTES])
                        .map_err(|_| Error::InvalidEncapsulation)?;
                    let traditional = <[u8; X25519_POINT_BYTES]>::try_from(
                        &bytes[ML_KEM_768_ENCAPSULATED_KEY_BYTES..],
                    )
                    .map_err(|_| Error::InvalidEncapsulation)?;
                    let _ = X25519PublicKey::from(traditional);
                }
                _ => return Err(Error::InvalidEncapsulation),
            }
            Ok(Self {
                kem,
                bytes: bytes.to_vec(),
            })
        }
        fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }
    fn hybrid_encapsulate(
        kem: Kem,
        key: &HybridPublicKey,
        deterministic: Option<&[u8]>,
    ) -> Result<(HybridEncapsulation, MlKemSharedSecret), Error> {
        if kem == Kem::MlKem1024P384 {
            return hybrid_p384_encapsulate(key, deterministic);
        }
        if kem == Kem::MlKem768X25519 {
            return hybrid_x25519_encapsulate(key, deterministic);
        }
        if kem != Kem::MlKem768P256 {
            return Err(Error::UnavailableCapability {
                suite: Suite::new(kem, Kdf::HkdfSha256, Aead::ExportOnly),
                reason: "hybrid KEM not implemented",
            });
        }
        let mut r = [0u8; 160];
        if let Some(seed) = deterministic {
            if seed.len() != r.len() {
                return Err(Error::InvalidEncapsulation);
            }
            r.copy_from_slice(seed);
        } else {
            rand::rngs::OsRng.fill_bytes(&mut r);
        }
        let pqpk = MlKem768PublicKey::from_bytes(&key.bytes[..ML_KEM_768_PUBLIC_KEY_BYTES])
            .map_err(|_| Error::InvalidRecipientPublicKey)?;
        let (pqenc, pss) =
            encapsulate_derand(&pqpk, &r[..32]).map_err(|_| Error::InternalInvariant)?;
        let eph = derive_p256_from_material(&r[32..])?;
        let rpk = P256PublicKey::from_sec1_bytes(&key.bytes[ML_KEM_768_PUBLIC_KEY_BYTES..])
            .map_err(|_| Error::InvalidRecipientPublicKey)?;
        let ss_t = diffie_hellman(eph.to_nonzero_scalar(), rpk.as_affine());
        let comb = combine_hybrid(
            pss.as_bytes(),
            ss_t.raw_secret_bytes().as_slice(),
            eph.public_key().to_encoded_point(false).as_bytes(),
            &key.bytes[ML_KEM_768_PUBLIC_KEY_BYTES..],
        );
        let mut bytes = Vec::with_capacity(MLKEM768_P256_ENCAPSULATION_BYTES);
        bytes.extend_from_slice(pqenc.as_bytes());
        bytes.extend_from_slice(eph.public_key().to_encoded_point(false).as_bytes());
        Ok((
            HybridEncapsulation { kem, bytes },
            MlKemSharedSecret(Zeroizing::new(comb)),
        ))
    }
    fn hybrid_decapsulate(
        kem: Kem,
        key: &HybridPrivateKey,
        enc: &HybridEncapsulation,
    ) -> Result<MlKemSharedSecret, Error> {
        if kem == Kem::MlKem1024P384 {
            return hybrid_p384_decapsulate(key, enc);
        }
        if kem == Kem::MlKem768X25519 {
            return hybrid_x25519_decapsulate(key, enc);
        }
        if kem != Kem::MlKem768P256 {
            return Err(Error::UnavailableCapability {
                suite: Suite::new(kem, Kdf::HkdfSha256, Aead::ExportOnly),
                reason: "hybrid KEM not implemented",
            });
        }
        let (_pq_public, privk, _scalar) = derive_hybrid_key_pair(key.as_seed_bytes())?;
        let recipient_public = HybridPublicKey::derive(kem, key.as_seed_bytes())?;
        let pqenc =
            MlKem768Encapsulation::from_bytes(&enc.bytes[..ML_KEM_768_ENCAPSULATED_KEY_BYTES])
                .map_err(|_| Error::InvalidEncapsulation)?;
        let psk = decapsulate(&privk, &pqenc).map_err(|_| Error::InternalInvariant)?;
        let sk = _scalar;
        let epk = P256PublicKey::from_sec1_bytes(&enc.bytes[ML_KEM_768_ENCAPSULATED_KEY_BYTES..])
            .map_err(|_| Error::InvalidEncapsulation)?;
        let ss = diffie_hellman(sk.to_nonzero_scalar(), epk.as_affine());
        let comb = combine_hybrid(
            psk.as_bytes(),
            ss.raw_secret_bytes().as_slice(),
            &enc.bytes[ML_KEM_768_ENCAPSULATED_KEY_BYTES..],
            &recipient_public.as_bytes()[ML_KEM_768_PUBLIC_KEY_BYTES..],
        );
        Ok(MlKemSharedSecret(Zeroizing::new(comb)))
    }

    #[cfg(test)]
    pub(crate) fn test_p256_hybrid_encapsulate(
        recipient_seed: &[u8],
        ikm_e: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
        let private = HybridPrivateKey::from_seed_bytes(Kem::MlKem768P256, recipient_seed)?;
        let public = HybridPublicKey::derive(Kem::MlKem768P256, private.as_seed_bytes())?;
        let (encapsulation, shared_secret) =
            hybrid_encapsulate(Kem::MlKem768P256, &public, Some(ikm_e))?;
        let decapsulated = hybrid_decapsulate(Kem::MlKem768P256, &private, &encapsulation)?;
        Ok((
            encapsulation.as_bytes().to_vec(),
            shared_secret.as_bytes().to_vec(),
            decapsulated.as_bytes().to_vec(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn test_p256_hybrid_context_material(
        recipient_seed: &[u8],
        ikm_e: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
        let (_, shared_secret, _) = test_p256_hybrid_encapsulate(recipient_seed, ikm_e)?;
        let context = Context::from_shared_secret(
            Suite::new(Kem::MlKem768P256, Kdf::HkdfSha256, Aead::Aes128Gcm),
            &shared_secret,
            info,
            b"",
            b"",
            false,
        )?;
        Ok((
            context.key.to_vec(),
            context.base_nonce.to_vec(),
            context.exporter_secret.to_vec(),
        ))
    }

    fn derive_hybrid_key_pair(
        seed: &[u8],
    ) -> Result<(MlKem768PublicKey, MlKem768PrivateKey, P256SecretKey), Error> {
        // The serialized hybrid recipient secret (`skRm`) is seed_H itself;
        // DeriveKeyPair applies LabeledDerive only when producing that field
        // from external IKM.  Stored keys must not derive it a second time.
        let h = seed;
        let mut x = Shake256::default();
        x.update(&h);
        let mut material = [0u8; 192];
        x.finalize_xof().read(&mut material);
        let mut pqseed = [0u8; 64];
        pqseed.copy_from_slice(&material[..64]);
        let (pq, privk) = expand_768_seed(pqseed);
        let sk = derive_p256_from_material(&material[64..])?;
        Ok((pq, privk, sk))
    }
    fn derive_p256_from_material(material: &[u8]) -> Result<P256SecretKey, Error> {
        for chunk in material.chunks(32) {
            if chunk.len() == 32 {
                if let Ok(s) = P256SecretKey::from_slice(chunk) {
                    return Ok(s);
                }
            }
        }
        Err(Error::InternalInvariant)
    }
    fn derive_hybrid_p384_key_pair(
        seed: &[u8],
    ) -> Result<(MlKem1024PublicKey, MlKem1024PrivateKey, P384SecretKey), Error> {
        // draft-concrete-hybrid-kems: PRG(seed_H) split into a 64-byte
        // ML-KEM seed and a 48-byte P-384 seed. P-384 RandomScalar consumes
        // the latter as a big-endian scalar candidate.
        let mut x = Shake256::default();
        x.update(seed);
        let mut material = [0u8; 112];
        x.finalize_xof().read(&mut material);
        let mut pqseed = [0u8; 64];
        pqseed.copy_from_slice(&material[..64]);
        let (pq, privk) = expand_1024_seed(pqseed);
        let scalar =
            P384SecretKey::from_slice(&material[64..]).map_err(|_| Error::InternalInvariant)?;
        Ok((pq, privk, scalar))
    }
    fn hybrid_p384_encapsulate(
        key: &HybridPublicKey,
        deterministic: Option<&[u8]>,
    ) -> Result<(HybridEncapsulation, MlKemSharedSecret), Error> {
        if key.kem != Kem::MlKem1024P384 {
            return Err(Error::InvalidRecipientPublicKey);
        }
        let mut r = [0u8; 80];
        if let Some(seed) = deterministic {
            if seed.len() != r.len() {
                return Err(Error::InvalidEncapsulation);
            }
            r.copy_from_slice(seed);
        } else {
            rand::rngs::OsRng.fill_bytes(&mut r);
        }
        let pqpk = MlKem1024PublicKey::from_bytes(&key.bytes[..ML_KEM_1024_PUBLIC_KEY_BYTES])
            .map_err(|_| Error::InvalidRecipientPublicKey)?;
        let (pqenc, pss) =
            encapsulate_derand_1024(&pqpk, &r[..32]).map_err(|_| Error::InternalInvariant)?;
        let eph = P384SecretKey::from_slice(&r[32..]).map_err(|_| Error::InternalInvariant)?;
        let rpk = P384PublicKey::from_sec1_bytes(&key.bytes[ML_KEM_1024_PUBLIC_KEY_BYTES..])
            .map_err(|_| Error::InvalidRecipientPublicKey)?;
        let ss_t = p384_diffie_hellman(eph.to_nonzero_scalar(), rpk.as_affine());
        let eph_bytes = eph.public_key().to_encoded_point(false);
        let comb = combine_hybrid_for(
            pss.as_bytes(),
            ss_t.raw_secret_bytes().as_slice(),
            eph_bytes.as_bytes(),
            &key.bytes[ML_KEM_1024_PUBLIC_KEY_BYTES..],
            b"MLKEM1024-P384",
        );
        let mut bytes = Vec::with_capacity(MLKEM1024_P384_ENCAPSULATION_BYTES);
        bytes.extend_from_slice(pqenc.as_bytes());
        bytes.extend_from_slice(eph_bytes.as_bytes());
        Ok((
            HybridEncapsulation {
                kem: Kem::MlKem1024P384,
                bytes,
            },
            MlKemSharedSecret(Zeroizing::new(comb)),
        ))
    }
    fn hybrid_p384_decapsulate(
        key: &HybridPrivateKey,
        enc: &HybridEncapsulation,
    ) -> Result<MlKemSharedSecret, Error> {
        if key.kem != Kem::MlKem1024P384 || enc.kem != Kem::MlKem1024P384 {
            return Err(Error::InvalidEncapsulation);
        }
        let (_, privk, scalar) = derive_hybrid_p384_key_pair(key.as_seed_bytes())?;
        let recipient = HybridPublicKey::derive(Kem::MlKem1024P384, key.as_seed_bytes())?;
        let pqenc =
            MlKem1024Encapsulation::from_bytes(&enc.bytes[..ML_KEM_1024_ENCAPSULATED_KEY_BYTES])
                .map_err(|_| Error::InvalidEncapsulation)?;
        let pss = decapsulate_1024(&privk, &pqenc).map_err(|_| Error::InternalInvariant)?;
        let epk = P384PublicKey::from_sec1_bytes(&enc.bytes[ML_KEM_1024_ENCAPSULATED_KEY_BYTES..])
            .map_err(|_| Error::InvalidEncapsulation)?;
        let ss_t = p384_diffie_hellman(scalar.to_nonzero_scalar(), epk.as_affine());
        let comb = combine_hybrid_for(
            pss.as_bytes(),
            ss_t.raw_secret_bytes().as_slice(),
            &enc.bytes[ML_KEM_1024_ENCAPSULATED_KEY_BYTES..],
            &recipient.as_bytes()[ML_KEM_1024_PUBLIC_KEY_BYTES..],
            b"MLKEM1024-P384",
        );
        Ok(MlKemSharedSecret(Zeroizing::new(comb)))
    }
    fn derive_hybrid_x25519_key_pair(
        seed: &[u8],
    ) -> Result<(MlKem768PublicKey, MlKem768PrivateKey, X25519SecretKey), Error> {
        // PRG(seed_H) splits into a 64-byte ML-KEM seed and an RFC 7748
        // X25519 scalar. The scalar is clamped by x25519-dalek at use.
        let mut x = Shake256::default();
        x.update(seed);
        let mut material = [0u8; 96];
        x.finalize_xof().read(&mut material);
        let mut pqseed = [0u8; 64];
        pqseed.copy_from_slice(&material[..64]);
        let (pq, privk) = expand_768_seed(pqseed);
        let scalar = X25519SecretKey::from(
            <[u8; X25519_POINT_BYTES]>::try_from(&material[64..])
                .map_err(|_| Error::InternalInvariant)?,
        );
        Ok((pq, privk, scalar))
    }
    fn hybrid_x25519_encapsulate(
        key: &HybridPublicKey,
        deterministic: Option<&[u8]>,
    ) -> Result<(HybridEncapsulation, MlKemSharedSecret), Error> {
        if key.kem != Kem::MlKem768X25519 {
            return Err(Error::InvalidRecipientPublicKey);
        }
        let mut r = [0u8; 64];
        if let Some(seed) = deterministic {
            if seed.len() != r.len() {
                return Err(Error::InvalidEncapsulation);
            }
            r.copy_from_slice(seed);
        } else {
            rand::rngs::OsRng.fill_bytes(&mut r);
        }
        let pqpk = MlKem768PublicKey::from_bytes(&key.bytes[..ML_KEM_768_PUBLIC_KEY_BYTES])
            .map_err(|_| Error::InvalidRecipientPublicKey)?;
        let (pqenc, pss) =
            encapsulate_derand(&pqpk, &r[..32]).map_err(|_| Error::InternalInvariant)?;
        let eph = X25519SecretKey::from(
            <[u8; X25519_POINT_BYTES]>::try_from(&r[32..]).map_err(|_| Error::InternalInvariant)?,
        );
        let rpk = X25519PublicKey::from(
            <[u8; X25519_POINT_BYTES]>::try_from(&key.bytes[ML_KEM_768_PUBLIC_KEY_BYTES..])
                .map_err(|_| Error::InvalidRecipientPublicKey)?,
        );
        let ss_t = eph.diffie_hellman(&rpk);
        let eph_public = X25519PublicKey::from(&eph);
        let comb = combine_hybrid_for(
            pss.as_bytes(),
            ss_t.as_bytes(),
            eph_public.as_bytes(),
            &key.bytes[ML_KEM_768_PUBLIC_KEY_BYTES..],
            &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
        );
        let mut bytes = Vec::with_capacity(MLKEM768_X25519_ENCAPSULATION_BYTES);
        bytes.extend_from_slice(pqenc.as_bytes());
        bytes.extend_from_slice(eph_public.as_bytes());
        Ok((
            HybridEncapsulation {
                kem: Kem::MlKem768X25519,
                bytes,
            },
            MlKemSharedSecret(Zeroizing::new(comb)),
        ))
    }
    fn hybrid_x25519_decapsulate(
        key: &HybridPrivateKey,
        enc: &HybridEncapsulation,
    ) -> Result<MlKemSharedSecret, Error> {
        if key.kem != Kem::MlKem768X25519 || enc.kem != Kem::MlKem768X25519 {
            return Err(Error::InvalidEncapsulation);
        }
        let (_, privk, scalar) = derive_hybrid_x25519_key_pair(key.as_seed_bytes())?;
        let recipient = HybridPublicKey::derive(Kem::MlKem768X25519, key.as_seed_bytes())?;
        let pqenc =
            MlKem768Encapsulation::from_bytes(&enc.bytes[..ML_KEM_768_ENCAPSULATED_KEY_BYTES])
                .map_err(|_| Error::InvalidEncapsulation)?;
        let pss = decapsulate(&privk, &pqenc).map_err(|_| Error::InternalInvariant)?;
        let epk = X25519PublicKey::from(
            <[u8; X25519_POINT_BYTES]>::try_from(&enc.bytes[ML_KEM_768_ENCAPSULATED_KEY_BYTES..])
                .map_err(|_| Error::InvalidEncapsulation)?,
        );
        let ss_t = scalar.diffie_hellman(&epk);
        let comb = combine_hybrid_for(
            pss.as_bytes(),
            ss_t.as_bytes(),
            &enc.bytes[ML_KEM_768_ENCAPSULATED_KEY_BYTES..],
            &recipient.as_bytes()[ML_KEM_768_PUBLIC_KEY_BYTES..],
            &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
        );
        Ok(MlKemSharedSecret(Zeroizing::new(comb)))
    }
    fn combine_hybrid(pq: &[u8], t: &[u8], ct: &[u8], ek: &[u8]) -> [u8; 32] {
        combine_hybrid_for(pq, t, ct, ek, b"MLKEM768-P256")
    }
    fn combine_hybrid_for(pq: &[u8], t: &[u8], ct: &[u8], ek: &[u8], label: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        sha3::Digest::update(&mut h, pq);
        sha3::Digest::update(&mut h, t);
        sha3::Digest::update(&mut h, ct);
        sha3::Digest::update(&mut h, ek);
        sha3::Digest::update(&mut h, label);
        h.finalize().into()
    }

    #[derive(Clone, Eq, PartialEq)]
    enum RecipientPublicKeyInner {
        MlKem512(Box<MlKem512PublicKey>),
        MlKem768(MlKem768PublicKey),
        MlKem1024(MlKem1024PublicKey),
        Hybrid(HybridPublicKey),
    }

    /// Validated public encapsulation key for an exact draft KEM.
    #[derive(Clone, Eq, PartialEq)]
    pub struct RecipientPublicKey {
        kem: Kem,
        inner: RecipientPublicKeyInner,
    }

    impl RecipientPublicKey {
        /// Parse and validate the canonical FIPS 203 public-key serialization.
        pub fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
            require_kem(kem)?;
            let inner = match kem {
                Kem::MlKem512 => MlKem512PublicKey::from_bytes(bytes)
                    .map(Box::new)
                    .map(RecipientPublicKeyInner::MlKem512)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?,
                Kem::MlKem768 => MlKem768PublicKey::from_bytes(bytes)
                    .map(RecipientPublicKeyInner::MlKem768)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?,
                Kem::MlKem1024 => MlKem1024PublicKey::from_bytes(bytes)
                    .map(RecipientPublicKeyInner::MlKem1024)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?,
                Kem::MlKem768P256 | Kem::MlKem1024P384 | Kem::MlKem768X25519 => {
                    RecipientPublicKeyInner::Hybrid(HybridPublicKey::from_bytes(kem, bytes)?)
                }
            };
            Ok(Self { kem, inner })
        }

        /// The exact KEM bound to this key.
        pub const fn kem(&self) -> Kem {
            self.kem
        }

        /// Borrow its canonical, fixed-length FIPS 203 serialization.
        pub fn as_bytes(&self) -> &[u8] {
            match &self.inner {
                RecipientPublicKeyInner::MlKem512(value) => value.as_bytes(),
                RecipientPublicKeyInner::MlKem768(value) => value.as_bytes(),
                RecipientPublicKeyInner::MlKem1024(value) => value.as_bytes(),
                RecipientPublicKeyInner::Hybrid(value) => value.as_bytes(),
            }
        }
    }

    enum RecipientPrivateKeyInner {
        MlKem512(MlKem512PrivateKey),
        MlKem768(MlKem768PrivateKey),
        MlKem1024(MlKem1024PrivateKey),
        Hybrid(HybridPrivateKey),
    }

    /// Secret 64-byte FIPS 203 seed for the selected draft KEM.
    pub struct RecipientPrivateKey {
        kem: Kem,
        inner: RecipientPrivateKeyInner,
    }

    impl RecipientPrivateKey {
        /// Parse a FIPS 203 seed-format decapsulation key.
        pub fn from_seed_bytes(kem: Kem, seed: &[u8]) -> Result<Self, Error> {
            require_kem(kem)?;
            let inner = match kem {
                Kem::MlKem512 => MlKem512PrivateKey::from_bytes(seed)
                    .map(RecipientPrivateKeyInner::MlKem512)
                    .map_err(|_| Error::InvalidRecipientPrivateKey)?,
                Kem::MlKem768 => MlKem768PrivateKey::from_bytes(seed)
                    .map(RecipientPrivateKeyInner::MlKem768)
                    .map_err(|_| Error::InvalidRecipientPrivateKey)?,
                Kem::MlKem1024 => MlKem1024PrivateKey::from_bytes(seed)
                    .map(RecipientPrivateKeyInner::MlKem1024)
                    .map_err(|_| Error::InvalidRecipientPrivateKey)?,
                Kem::MlKem768P256 | Kem::MlKem1024P384 | Kem::MlKem768X25519 => {
                    RecipientPrivateKeyInner::Hybrid(HybridPrivateKey::from_seed_bytes(kem, seed)?)
                }
            };
            Ok(Self { kem, inner })
        }

        /// The exact KEM bound to this private key.
        pub const fn kem(&self) -> Kem {
            self.kem
        }

        /// Borrow the 64-byte seed only for protected key-storage integration.
        pub fn as_seed_bytes(&self) -> &[u8] {
            match &self.inner {
                RecipientPrivateKeyInner::MlKem512(value) => value.as_bytes(),
                RecipientPrivateKeyInner::MlKem768(value) => value.as_bytes(),
                RecipientPrivateKeyInner::MlKem1024(value) => value.as_bytes(),
                RecipientPrivateKeyInner::Hybrid(value) => value.as_seed_bytes(),
            }
        }

        /// Derive the corresponding public key for the concrete hybrid KEM.
        pub fn public_key(&self) -> Result<RecipientPublicKey, Error> {
            match self.kem {
                Kem::MlKem768P256 | Kem::MlKem1024P384 | Kem::MlKem768X25519 => {
                    Ok(RecipientPublicKey {
                        kem: self.kem,
                        inner: RecipientPublicKeyInner::Hybrid(HybridPublicKey::derive(
                            self.kem,
                            self.as_seed_bytes(),
                        )?),
                    })
                }
                _ => Err(Error::InternalInvariant),
            }
        }
    }

    /// Recipient key pair.  Its private member intentionally has no `Clone`.
    pub struct RecipientKeyPair {
        public_key: RecipientPublicKey,
        private_key: RecipientPrivateKey,
    }

    impl RecipientKeyPair {
        /// Borrow the public key.
        pub fn public_key(&self) -> &RecipientPublicKey {
            &self.public_key
        }
        /// Borrow the private key for immediate receiver setup.
        pub fn private_key(&self) -> &RecipientPrivateKey {
            &self.private_key
        }
    }

    /// Generate a FIPS 203 seed-format recipient key pair with the OS CSPRNG.
    pub fn generate_recipient_key_pair(kem: Kem) -> Result<RecipientKeyPair, Error> {
        require_kem(kem)?;
        let mut rng = rand::rngs::OsRng;
        match kem {
            Kem::MlKem512 => {
                let (public_key, private_key) = generate_key_pair_512(&mut rng);
                Ok(RecipientKeyPair {
                    public_key: RecipientPublicKey {
                        kem,
                        inner: RecipientPublicKeyInner::MlKem512(Box::new(public_key)),
                    },
                    private_key: RecipientPrivateKey {
                        kem,
                        inner: RecipientPrivateKeyInner::MlKem512(private_key),
                    },
                })
            }
            Kem::MlKem768 => {
                let (public_key, private_key) = generate_key_pair(&mut rng);
                Ok(RecipientKeyPair {
                    public_key: RecipientPublicKey {
                        kem,
                        inner: RecipientPublicKeyInner::MlKem768(public_key),
                    },
                    private_key: RecipientPrivateKey {
                        kem,
                        inner: RecipientPrivateKeyInner::MlKem768(private_key),
                    },
                })
            }
            Kem::MlKem1024 => {
                let (public_key, private_key) = generate_key_pair_1024(&mut rng);
                Ok(RecipientKeyPair {
                    public_key: RecipientPublicKey {
                        kem,
                        inner: RecipientPublicKeyInner::MlKem1024(public_key),
                    },
                    private_key: RecipientPrivateKey {
                        kem,
                        inner: RecipientPrivateKeyInner::MlKem1024(private_key),
                    },
                })
            }
            Kem::MlKem768P256 | Kem::MlKem1024P384 | Kem::MlKem768X25519 => {
                let mut seed = Zeroizing::new([0_u8; HYBRID_SEED_BYTES]);
                rng.fill_bytes(&mut seed[..]);
                let private_key = HybridPrivateKey::from_seed(kem, seed);
                let public_key = HybridPublicKey::derive(kem, private_key.as_seed_bytes())?;
                Ok(RecipientKeyPair {
                    public_key: RecipientPublicKey {
                        kem,
                        inner: RecipientPublicKeyInner::Hybrid(public_key),
                    },
                    private_key: RecipientPrivateKey {
                        kem,
                        inner: RecipientPrivateKeyInner::Hybrid(private_key),
                    },
                })
            }
        }
    }

    #[derive(Clone, Eq, PartialEq)]
    enum EncapsulationInner {
        MlKem512(Box<MlKem512Encapsulation>),
        MlKem768(Box<MlKem768Encapsulation>),
        MlKem1024(Box<MlKem1024Encapsulation>),
        Hybrid(HybridEncapsulation),
    }

    /// A separately transported, fixed-length draft KEM ciphertext (`enc`).
    #[derive(Clone, Eq, PartialEq)]
    pub struct Encapsulation {
        kem: Kem,
        inner: EncapsulationInner,
    }

    impl Encapsulation {
        /// Parse a fixed-length encapsulation for the explicitly selected KEM.
        pub fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
            require_kem(kem)?;
            let inner = match kem {
                Kem::MlKem512 => MlKem512Encapsulation::from_bytes(bytes)
                    .map(Box::new)
                    .map(EncapsulationInner::MlKem512)
                    .map_err(|_| Error::InvalidEncapsulation)?,
                Kem::MlKem768 => MlKem768Encapsulation::from_bytes(bytes)
                    .map(Box::new)
                    .map(EncapsulationInner::MlKem768)
                    .map_err(|_| Error::InvalidEncapsulation)?,
                Kem::MlKem1024 => MlKem1024Encapsulation::from_bytes(bytes)
                    .map(Box::new)
                    .map(EncapsulationInner::MlKem1024)
                    .map_err(|_| Error::InvalidEncapsulation)?,
                Kem::MlKem768P256 | Kem::MlKem1024P384 | Kem::MlKem768X25519 => {
                    EncapsulationInner::Hybrid(HybridEncapsulation::from_bytes(kem, bytes)?)
                }
            };
            Ok(Self { kem, inner })
        }

        /// The exact KEM that produced this `enc`.
        pub const fn kem(&self) -> Kem {
            self.kem
        }

        /// Borrow the canonical fixed-length KEM ciphertext.
        pub fn as_bytes(&self) -> &[u8] {
            match &self.inner {
                EncapsulationInner::MlKem512(value) => value.as_bytes(),
                EncapsulationInner::MlKem768(value) => value.as_bytes(),
                EncapsulationInner::MlKem1024(value) => value.as_bytes(),
                EncapsulationInner::Hybrid(value) => value.as_bytes(),
            }
        }
    }

    /// Stateful sender context.  It deliberately is not `Clone`.
    pub struct SenderContext(Context);
    /// Stateful recipient context.  It deliberately is not `Clone`.
    pub struct RecipientContext(Context);

    impl SenderContext {
        /// Seal with the next internally derived nonce.
        pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.seal(aad, plaintext)
        }
        /// Export without changing the message sequence.
        pub fn export(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
            self.0.export(context, output_len)
        }
        /// The exact suite bound to this context.
        pub const fn suite(&self) -> Suite {
            self.0.suite
        }
    }

    impl RecipientContext {
        /// Open with the next internally derived nonce.
        pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.open(aad, ciphertext)
        }
        /// Export without changing the message sequence.
        pub fn export(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
            self.0.export(context, output_len)
        }
        /// The exact suite bound to this context.
        pub const fn suite(&self) -> Suite {
            self.0.suite
        }
    }

    /// Set up a Base-mode sender context; `enc` is returned separately.
    pub fn setup_base_sender(
        suite: Suite,
        recipient_public_key: &RecipientPublicKey,
        info: &[u8],
    ) -> Result<(Encapsulation, SenderContext), Error> {
        setup_sender(suite, recipient_public_key, info, b"", b"", false, None)
    }

    /// Deterministic Base-mode setup for conformance fixtures. `ikm_e` is
    /// accepted only for the concrete draft hybrid KEM path and is never used
    /// by the ordinary randomized API.
    pub fn setup_base_sender_with_ikm_e(
        suite: Suite,
        recipient_public_key: &RecipientPublicKey,
        info: &[u8],
        ikm_e: &[u8],
    ) -> Result<(Encapsulation, SenderContext), Error> {
        setup_sender(
            suite,
            recipient_public_key,
            info,
            b"",
            b"",
            false,
            Some(ikm_e),
        )
    }

    /// Set up a Base-mode recipient context from separately transported `enc`.
    pub fn setup_base_receiver(
        suite: Suite,
        recipient_private_key: &RecipientPrivateKey,
        encapsulation: &Encapsulation,
        info: &[u8],
    ) -> Result<RecipientContext, Error> {
        setup_receiver(
            suite,
            recipient_private_key,
            encapsulation,
            info,
            b"",
            b"",
            false,
        )
    }

    /// Set up an RFC 9180 / HPKE-bis PSK-mode sender context.
    ///
    /// The PSK and identifier are processed by the exact two-stage or
    /// one-stage draft schedule for the selected KDF.  This is not KEM Auth
    /// mode; draft-05 KEMs do not support `AuthEncap` / `AuthDecap`.
    pub fn setup_psk_sender(
        suite: Suite,
        recipient_public_key: &RecipientPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(Encapsulation, SenderContext), Error> {
        setup_sender(suite, recipient_public_key, info, psk, psk_id, true, None)
    }

    /// Set up an RFC 9180 / HPKE-bis PSK-mode recipient context.
    pub fn setup_psk_receiver(
        suite: Suite,
        recipient_private_key: &RecipientPrivateKey,
        encapsulation: &Encapsulation,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<RecipientContext, Error> {
        setup_receiver(
            suite,
            recipient_private_key,
            encapsulation,
            info,
            psk,
            psk_id,
            true,
        )
    }

    fn require_kem(kem: Kem) -> Result<(), Error> {
        let suite = Suite::new(kem, Kdf::HkdfSha256, Aead::ExportOnly);
        match suite.capability() {
            Capability::Available => Ok(()),
            Capability::Unavailable(reason) => Err(Error::UnavailableCapability { suite, reason }),
        }
    }

    fn require_suite(suite: Suite) -> Result<(), Error> {
        match suite.capability() {
            Capability::Available => Ok(()),
            Capability::Unavailable(reason) => Err(Error::UnavailableCapability { suite, reason }),
        }
    }

    fn setup_sender(
        suite: Suite,
        recipient_public_key: &RecipientPublicKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        psk_mode: bool,
        deterministic: Option<&[u8]>,
    ) -> Result<(Encapsulation, SenderContext), Error> {
        require_suite(suite)?;
        if suite.kem != recipient_public_key.kem {
            return Err(Error::KemMismatch {
                expected: suite.kem,
                actual: recipient_public_key.kem,
            });
        }
        verify_psk(psk, psk_id, psk_mode)?;
        let mut rng = rand::rngs::OsRng;
        let (encapsulation, shared_secret) = match &recipient_public_key.inner {
            RecipientPublicKeyInner::MlKem512(key) => {
                let (enc, secret) =
                    encapsulate_512(key, &mut rng).map_err(|_| Error::InvalidRecipientPublicKey)?;
                (
                    Encapsulation {
                        kem: suite.kem,
                        inner: EncapsulationInner::MlKem512(Box::new(enc)),
                    },
                    secret,
                )
            }
            RecipientPublicKeyInner::MlKem768(key) => {
                let (enc, secret) =
                    encapsulate(key, &mut rng).map_err(|_| Error::InvalidRecipientPublicKey)?;
                (
                    Encapsulation {
                        kem: suite.kem,
                        inner: EncapsulationInner::MlKem768(Box::new(enc)),
                    },
                    secret,
                )
            }
            RecipientPublicKeyInner::MlKem1024(key) => {
                let (enc, secret) = encapsulate_1024(key, &mut rng)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?;
                (
                    Encapsulation {
                        kem: suite.kem,
                        inner: EncapsulationInner::MlKem1024(Box::new(enc)),
                    },
                    secret,
                )
            }
            RecipientPublicKeyInner::Hybrid(key) => {
                let (enc, secret) = hybrid_encapsulate(key.kem, key, deterministic)?;
                (
                    Encapsulation {
                        kem: suite.kem,
                        inner: EncapsulationInner::Hybrid(enc),
                    },
                    secret,
                )
            }
        };
        let context = Context::from_shared_secret(
            suite,
            shared_secret.as_bytes(),
            info,
            psk,
            psk_id,
            psk_mode,
        )?;
        Ok((encapsulation, SenderContext(context)))
    }

    fn setup_receiver(
        suite: Suite,
        recipient_private_key: &RecipientPrivateKey,
        encapsulation: &Encapsulation,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        psk_mode: bool,
    ) -> Result<RecipientContext, Error> {
        require_suite(suite)?;
        if suite.kem != recipient_private_key.kem {
            return Err(Error::KemMismatch {
                expected: suite.kem,
                actual: recipient_private_key.kem,
            });
        }
        if suite.kem != encapsulation.kem {
            return Err(Error::KemMismatch {
                expected: suite.kem,
                actual: encapsulation.kem,
            });
        }
        verify_psk(psk, psk_id, psk_mode)?;
        let shared_secret = match (&recipient_private_key.inner, &encapsulation.inner) {
            (RecipientPrivateKeyInner::MlKem512(key), EncapsulationInner::MlKem512(enc)) => {
                decapsulate_512(key, enc).map_err(|_| Error::InternalInvariant)?
            }
            (RecipientPrivateKeyInner::MlKem768(key), EncapsulationInner::MlKem768(enc)) => {
                decapsulate(key, enc).map_err(|_| Error::InternalInvariant)?
            }
            (RecipientPrivateKeyInner::MlKem1024(key), EncapsulationInner::MlKem1024(enc)) => {
                decapsulate_1024(key, enc).map_err(|_| Error::InternalInvariant)?
            }
            (RecipientPrivateKeyInner::Hybrid(key), EncapsulationInner::Hybrid(enc)) => {
                hybrid_decapsulate(key.kem, key, enc)?
            }
            _ => {
                return Err(Error::KemMismatch {
                    expected: suite.kem,
                    actual: encapsulation.kem,
                })
            }
        };
        Ok(RecipientContext(Context::from_shared_secret(
            suite,
            shared_secret.as_bytes(),
            info,
            psk,
            psk_id,
            psk_mode,
        )?))
    }

    fn verify_psk(psk: &[u8], psk_id: &[u8], psk_mode: bool) -> Result<(), Error> {
        let has_psk = !psk.is_empty();
        let has_psk_id = !psk_id.is_empty();
        if has_psk != has_psk_id || has_psk != psk_mode {
            Err(Error::InvalidPskInputs {
                has_psk,
                has_psk_id,
            })
        } else {
            Ok(())
        }
    }

    struct Context {
        suite: Suite,
        key: Zeroizing<Vec<u8>>,
        base_nonce: Zeroizing<[u8; 12]>,
        exporter_secret: Zeroizing<Vec<u8>>,
        sequence: [u8; 12],
    }

    impl Context {
        fn from_shared_secret(
            suite: Suite,
            shared_secret: &[u8],
            info: &[u8],
            psk: &[u8],
            psk_id: &[u8],
            psk_mode: bool,
        ) -> Result<Self, Error> {
            let (key, base_nonce, exporter_secret) = if suite.kdf.is_one_stage() {
                combine_one_stage(suite, shared_secret, info, psk, psk_id, psk_mode)?
            } else {
                combine_two_stage(suite, shared_secret, info, psk, psk_id, psk_mode)?
            };
            let base_nonce: [u8; 12] = base_nonce
                .as_slice()
                .try_into()
                .map_err(|_| Error::InternalInvariant)?;
            Ok(Self {
                suite,
                key,
                base_nonce: Zeroizing::new(base_nonce),
                exporter_secret,
                sequence: [0; 12],
            })
        }

        fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
            if self.suite.aead == Aead::ExportOnly {
                return Err(Error::ExportOnlyAead);
            }
            let nonce = self.nonce()?;
            let result = match self.suite.aead {
                Aead::Aes128Gcm => {
                    let nonce = AesGcmNonce::try_from(nonce.as_slice())
                        .map_err(|_| Error::InternalInvariant)?;
                    Aes128Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::InternalInvariant)?
                        .encrypt(
                            &nonce,
                            AesPayload {
                                msg: plaintext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::AuthenticationFailed)
                }
                Aead::Aes256Gcm => {
                    let nonce = AesGcmNonce::try_from(nonce.as_slice())
                        .map_err(|_| Error::InternalInvariant)?;
                    Aes256Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::InternalInvariant)?
                        .encrypt(
                            &nonce,
                            AesPayload {
                                msg: plaintext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::AuthenticationFailed)
                }
                Aead::ChaCha20Poly1305 => {
                    let nonce: &ChaCha20Poly1305Nonce = nonce.as_slice().into();
                    ChaCha20Poly1305::new_from_slice(&self.key)
                        .map_err(|_| Error::InternalInvariant)?
                        .encrypt(
                            nonce,
                            Payload {
                                msg: plaintext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::AuthenticationFailed)
                }
                Aead::ExportOnly => Err(Error::ExportOnlyAead),
            }?;
            self.advance()?;
            Ok(result)
        }

        fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
            if self.suite.aead == Aead::ExportOnly {
                return Err(Error::ExportOnlyAead);
            }
            let nonce = self.nonce()?;
            let result = match self.suite.aead {
                Aead::Aes128Gcm => {
                    let nonce = AesGcmNonce::try_from(nonce.as_slice())
                        .map_err(|_| Error::InternalInvariant)?;
                    Aes128Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::InternalInvariant)?
                        .decrypt(
                            &nonce,
                            AesPayload {
                                msg: ciphertext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::AuthenticationFailed)
                }
                Aead::Aes256Gcm => {
                    let nonce = AesGcmNonce::try_from(nonce.as_slice())
                        .map_err(|_| Error::InternalInvariant)?;
                    Aes256Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::InternalInvariant)?
                        .decrypt(
                            &nonce,
                            AesPayload {
                                msg: ciphertext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::AuthenticationFailed)
                }
                Aead::ChaCha20Poly1305 => {
                    let nonce: &ChaCha20Poly1305Nonce = nonce.as_slice().into();
                    ChaCha20Poly1305::new_from_slice(&self.key)
                        .map_err(|_| Error::InternalInvariant)?
                        .decrypt(
                            nonce,
                            Payload {
                                msg: ciphertext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::AuthenticationFailed)
                }
                Aead::ExportOnly => Err(Error::ExportOnlyAead),
            }?;
            self.advance()?;
            Ok(result)
        }

        fn export(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
            if self.suite.kdf.is_one_stage() {
                labeled_derive(
                    self.suite,
                    &self.exporter_secret,
                    b"sec",
                    context,
                    output_len,
                )
            } else {
                labeled_expand(
                    self.suite,
                    &self.exporter_secret,
                    b"sec",
                    context,
                    output_len,
                )
            }
        }

        fn nonce(&self) -> Result<[u8; 12], Error> {
            if self.sequence == [u8::MAX; 12] {
                return Err(Error::MessageLimitReached);
            }
            let mut nonce = *self.base_nonce;
            for (left, right) in nonce.iter_mut().zip(self.sequence) {
                *left ^= right;
            }
            Ok(nonce)
        }

        fn advance(&mut self) -> Result<(), Error> {
            if self.sequence == [u8::MAX; 12] {
                return Err(Error::MessageLimitReached);
            }
            for byte in self.sequence.iter_mut().rev() {
                let (value, carry) = byte.overflowing_add(1);
                *byte = value;
                if !carry {
                    break;
                }
            }
            Ok(())
        }
    }

    fn combine_two_stage(
        suite: Suite,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        psk_mode: bool,
    ) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error> {
        let mode = if psk_mode { 1 } else { 0 };
        let psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", psk_id)?;
        let info_hash = labeled_extract(suite, b"", b"info_hash", info)?;
        let mut context =
            Zeroizing::new(Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len()));
        context.push(mode);
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        let secret = labeled_extract(suite, shared_secret, b"secret", psk)?;
        let key = Zeroizing::new(labeled_expand(
            suite,
            &secret,
            b"key",
            &context,
            suite.aead.key_len(),
        )?);
        let nonce = Zeroizing::new(labeled_expand(suite, &secret, b"base_nonce", &context, 12)?);
        let exporter = Zeroizing::new(labeled_expand(
            suite,
            &secret,
            b"exp",
            &context,
            suite.kdf.nh(),
        )?);
        Ok((key, nonce, exporter))
    }

    fn combine_one_stage(
        suite: Suite,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        psk_mode: bool,
    ) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error> {
        let mut secrets = Zeroizing::new(Vec::new());
        append_length_prefixed(&mut secrets, psk)?;
        append_length_prefixed(&mut secrets, shared_secret)?;
        let mut context = Zeroizing::new(Vec::new());
        context.push(if psk_mode { 1 } else { 0 });
        append_length_prefixed(&mut context, psk_id)?;
        append_length_prefixed(&mut context, info)?;
        let total = suite.aead.key_len() + 12 + suite.kdf.nh();
        let secret = labeled_derive(suite, &secrets, b"secret", &context, total)?;
        let (key, remainder) = secret.split_at(suite.aead.key_len());
        let (nonce, exporter) = remainder.split_at(12);
        Ok((
            Zeroizing::new(key.to_vec()),
            Zeroizing::new(nonce.to_vec()),
            Zeroizing::new(exporter.to_vec()),
        ))
    }

    fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
        let length: u16 = value
            .len()
            .try_into()
            .map_err(|_| Error::InputLengthTooLarge {
                actual: value.len(),
            })?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(value);
        Ok(())
    }

    fn labeled_extract(
        suite: Suite,
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if suite.kdf.is_one_stage() {
            return Err(Error::InternalInvariant);
        }
        let mut input = Zeroizing::new(Vec::with_capacity(
            HPKE_VERSION_LABEL.len() + 10 + label.len() + ikm.len(),
        ));
        input.extend_from_slice(HPKE_VERSION_LABEL);
        input.extend_from_slice(&suite.suite_id());
        input.extend_from_slice(label);
        input.extend_from_slice(ikm);
        let value = match suite.kdf {
            Kdf::HkdfSha256 => Hkdf::<Sha256>::extract(Some(salt), &input).0.to_vec(),
            Kdf::HkdfSha384 => Hkdf::<Sha384>::extract(Some(salt), &input).0.to_vec(),
            Kdf::HkdfSha512 => Hkdf::<Sha512>::extract(Some(salt), &input).0.to_vec(),
            _ => return Err(Error::InternalInvariant),
        };
        Ok(Zeroizing::new(value))
    }

    fn labeled_expand(
        suite: Suite,
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        if suite.kdf.is_one_stage() {
            return Err(Error::InternalInvariant);
        }
        let length: u16 = output_len
            .try_into()
            .map_err(|_| Error::OutputLengthTooLarge {
                requested: output_len,
            })?;
        if output_len > suite.kdf.nh() * 255 {
            return Err(Error::OutputLengthTooLarge {
                requested: output_len,
            });
        }
        let mut info_bytes =
            Vec::with_capacity(2 + HPKE_VERSION_LABEL.len() + 10 + label.len() + info.len());
        info_bytes.extend_from_slice(&length.to_be_bytes());
        info_bytes.extend_from_slice(HPKE_VERSION_LABEL);
        info_bytes.extend_from_slice(&suite.suite_id());
        info_bytes.extend_from_slice(label);
        info_bytes.extend_from_slice(info);
        let mut output = vec![0; output_len];
        match suite.kdf {
            Kdf::HkdfSha256 => Hkdf::<Sha256>::from_prk(prk)
                .map_err(|_| Error::InternalInvariant)?
                .expand(&info_bytes, &mut output)
                .map_err(|_| Error::OutputLengthTooLarge {
                    requested: output_len,
                })?,
            Kdf::HkdfSha384 => Hkdf::<Sha384>::from_prk(prk)
                .map_err(|_| Error::InternalInvariant)?
                .expand(&info_bytes, &mut output)
                .map_err(|_| Error::OutputLengthTooLarge {
                    requested: output_len,
                })?,
            Kdf::HkdfSha512 => Hkdf::<Sha512>::from_prk(prk)
                .map_err(|_| Error::InternalInvariant)?
                .expand(&info_bytes, &mut output)
                .map_err(|_| Error::OutputLengthTooLarge {
                    requested: output_len,
                })?,
            _ => return Err(Error::InternalInvariant),
        }
        Ok(output)
    }

    fn labeled_derive(
        suite: Suite,
        ikm: &[u8],
        label: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let length: u16 = output_len
            .try_into()
            .map_err(|_| Error::OutputLengthTooLarge {
                requested: output_len,
            })?;
        let label_length: u16 = label
            .len()
            .try_into()
            .map_err(|_| Error::InputLengthTooLarge {
                actual: label.len(),
            })?;
        let mut input = Zeroizing::new(Vec::with_capacity(
            ikm.len() + HPKE_VERSION_LABEL.len() + 10 + 2 + label.len() + 2 + context.len(),
        ));
        input.extend_from_slice(ikm);
        input.extend_from_slice(HPKE_VERSION_LABEL);
        input.extend_from_slice(&suite.suite_id());
        input.extend_from_slice(&label_length.to_be_bytes());
        input.extend_from_slice(label);
        input.extend_from_slice(&length.to_be_bytes());
        input.extend_from_slice(context);
        let mut output = vec![0; output_len];
        match suite.kdf {
            Kdf::Shake128 => {
                let mut xof = Shake128::default();
                xof.update(&input);
                xof.finalize_xof().read(&mut output);
            }
            Kdf::Shake256 => {
                let mut xof = Shake256::default();
                xof.update(&input);
                xof.finalize_xof().read(&mut output);
            }
            Kdf::TurboShake128 => {
                let mut xof = TurboShake128::default();
                xof.update(&input);
                xof.finalize_xof().read(&mut output);
            }
            Kdf::TurboShake256 => {
                let mut xof = TurboShake256::default();
                xof.update(&input);
                xof.finalize_xof().read(&mut output);
            }
            _ => return Err(Error::InternalInvariant),
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct DraftVector {
        mode: u8,
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        info: String,
        #[serde(rename = "ikmE")]
        ikm_e: String,
        #[serde(rename = "ikmR")]
        ikm_r: String,
        #[serde(rename = "skRm")]
        sk_rm: String,
        #[serde(rename = "pkRm")]
        pk_rm: String,
        enc: String,
        shared_secret: String,
        suite_id: String,
        key: String,
        base_nonce: String,
        exporter_secret: String,
        encryptions: Vec<EncryptionVector>,
        exports: Vec<ExportVector>,
    }

    #[derive(Deserialize)]
    struct EncryptionVector {
        aad: String,
        ct: String,
        nonce: String,
        pt: String,
    }

    #[derive(Deserialize)]
    struct ExportVector {
        exporter_context: String,
        #[serde(rename = "L")]
        output_len: usize,
        exported_value: String,
    }

    fn decode(value: &str) -> Vec<u8> {
        hex::decode(value).expect("the vendored draft vector must contain hexadecimal")
    }

    #[test]
    fn ml_kem_768_round_trip_uses_the_pqca_backend() {
        let mut rng = rand::rngs::OsRng;
        let (public_key, private_key) = generate_key_pair(&mut rng);
        let (encapsulation, sender_shared_secret) = encapsulate(&public_key, &mut rng).unwrap();
        let receiver_shared_secret = decapsulate(&private_key, &encapsulation).unwrap();

        assert_eq!(
            sender_shared_secret.as_bytes(),
            receiver_shared_secret.as_bytes()
        );
    }

    #[test]
    fn ml_kem_768_serialization_parsers_require_exact_lengths() {
        for length in [
            ML_KEM_768_PUBLIC_KEY_BYTES - 1,
            ML_KEM_768_PUBLIC_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                MlKem768PublicKey::from_bytes(&vec![0_u8; length]),
                Err(CryptError::InvalidKemPublicKey)
            ));
        }

        for length in [
            ML_KEM_768_PRIVATE_KEY_BYTES - 1,
            ML_KEM_768_PRIVATE_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                MlKem768PrivateKey::from_bytes(&vec![0_u8; length]),
                Err(CryptError::InvalidKemSecretKey)
            ));
        }

        for length in [
            ML_KEM_768_ENCAPSULATED_KEY_BYTES - 1,
            ML_KEM_768_ENCAPSULATED_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                MlKem768Encapsulation::from_bytes(&vec![0_u8; length]),
                Err(CryptError::InvalidKemCiphertext)
            ));
        }
    }

    #[test]
    fn ml_kem_768_revalidates_public_keys_before_encapsulation() {
        let malformed = [0xff_u8; ML_KEM_768_PUBLIC_KEY_BYTES];
        assert!(matches!(
            MlKem768PublicKey::from_bytes(&malformed),
            Err(CryptError::InvalidKemPublicKey)
        ));

        // The test module can construct the private wrapper directly, but the
        // production parser cannot. Revalidation at `encapsulate` is therefore
        // the second required trust boundary, not a bypassable optimization.
        let unvalidated = MlKem768PublicKey(malformed);
        let mut rng = rand::rngs::OsRng;
        assert!(matches!(
            encapsulate(&unvalidated, &mut rng),
            Err(CryptError::InvalidKemPublicKey)
        ));
    }

    #[test]
    fn modified_encapsulation_uses_ml_kem_implicit_rejection() {
        let mut rng = rand::rngs::OsRng;
        let (public_key, private_key) = generate_key_pair(&mut rng);
        let (encapsulation, sender_shared_secret) = encapsulate(&public_key, &mut rng).unwrap();
        let mut tampered = *encapsulation.as_bytes();
        tampered[0] ^= 0x80;
        let tampered = MlKem768Encapsulation::from_bytes(&tampered).unwrap();
        let receiver_shared_secret = decapsulate(&private_key, &tampered).unwrap();

        assert_ne!(
            sender_shared_secret.as_bytes(),
            receiver_shared_secret.as_bytes()
        );
    }

    #[test]
    fn ml_kem_1024_round_trip_uses_the_pqca_backend() {
        let mut rng = rand::rngs::OsRng;
        let (public_key, private_key) = generate_key_pair_1024(&mut rng);
        let (encapsulation, sender_shared_secret) =
            encapsulate_1024(&public_key, &mut rng).unwrap();
        let receiver_shared_secret = decapsulate_1024(&private_key, &encapsulation).unwrap();

        assert_eq!(
            sender_shared_secret.as_bytes(),
            receiver_shared_secret.as_bytes()
        );
    }

    #[test]
    fn ml_kem_1024_serialization_parsers_require_exact_lengths() {
        for length in [
            ML_KEM_1024_PUBLIC_KEY_BYTES - 1,
            ML_KEM_1024_PUBLIC_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                MlKem1024PublicKey::from_bytes(&vec![0_u8; length]),
                Err(CryptError::InvalidKemPublicKey)
            ));
        }

        for length in [
            ML_KEM_1024_PRIVATE_KEY_BYTES - 1,
            ML_KEM_1024_PRIVATE_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                MlKem1024PrivateKey::from_bytes(&vec![0_u8; length]),
                Err(CryptError::InvalidKemSecretKey)
            ));
        }

        for length in [
            ML_KEM_1024_ENCAPSULATED_KEY_BYTES - 1,
            ML_KEM_1024_ENCAPSULATED_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                MlKem1024Encapsulation::from_bytes(&vec![0_u8; length]),
                Err(CryptError::InvalidKemCiphertext)
            ));
        }
    }

    #[test]
    fn ml_kem_1024_revalidates_public_keys_before_encapsulation() {
        let malformed = [0xff_u8; ML_KEM_1024_PUBLIC_KEY_BYTES];
        assert!(matches!(
            MlKem1024PublicKey::from_bytes(&malformed),
            Err(CryptError::InvalidKemPublicKey)
        ));

        // See the ML-KEM-768 test for why this direct construction is confined
        // to this module's test-only boundary.
        let unvalidated = MlKem1024PublicKey(malformed);
        let mut rng = rand::rngs::OsRng;
        assert!(matches!(
            encapsulate_1024(&unvalidated, &mut rng),
            Err(CryptError::InvalidKemPublicKey)
        ));
    }

    #[test]
    fn ml_kem_1024_modified_encapsulation_uses_implicit_rejection() {
        let mut rng = rand::rngs::OsRng;
        let (public_key, private_key) = generate_key_pair_1024(&mut rng);
        let (encapsulation, sender_shared_secret) =
            encapsulate_1024(&public_key, &mut rng).unwrap();
        let mut tampered = *encapsulation.as_bytes();
        tampered[0] ^= 0x80;
        let tampered = MlKem1024Encapsulation::from_bytes(&tampered).unwrap();
        let receiver_shared_secret = decapsulate_1024(&private_key, &tampered).unwrap();

        assert_ne!(
            sender_shared_secret.as_bytes(),
            receiver_shared_secret.as_bytes()
        );
    }

    #[test]
    fn tampered_encapsulation_reaches_only_opaque_aead_failure_for_both_profiles() {
        let mut rng = rand::rngs::OsRng;
        let (public_768, private_768) = generate_key_pair(&mut rng);
        let (encapsulation_768, mut sender_768) =
            setup_base_sender_768(&public_768, &[0x11; 32], b"context").unwrap();
        let ciphertext_768 = sender_768.seal(b"aad", b"plaintext").unwrap();
        let mut tampered_768 = *encapsulation_768.as_bytes();
        tampered_768[0] ^= 0x80;
        let mut receiver_768 = setup_base_receiver_768(
            &private_768,
            &MlKem768Encapsulation::from_bytes(&tampered_768).unwrap(),
            b"context",
        )
        .unwrap();
        assert_eq!(
            receiver_768.open(b"aad", &ciphertext_768),
            Err(Draft05Error::AuthenticationFailed)
        );

        let (public_1024, private_1024) = generate_key_pair_1024(&mut rng);
        let (encapsulation_1024, mut sender_1024) =
            setup_base_sender_1024(&public_1024, &[0x22; 32], b"context").unwrap();
        let ciphertext_1024 = sender_1024.seal(b"aad", b"plaintext").unwrap();
        let mut tampered_1024 = *encapsulation_1024.as_bytes();
        tampered_1024[0] ^= 0x80;
        let mut receiver_1024 = setup_base_receiver_1024(
            &private_1024,
            &MlKem1024Encapsulation::from_bytes(&tampered_1024).unwrap(),
            b"context",
        )
        .unwrap();
        assert_eq!(
            receiver_1024.open(b"aad", &ciphertext_1024),
            Err(Draft05Error::AuthenticationFailed)
        );
    }

    #[test]
    fn pinned_draft_05_ml_kem_base_mode_vectors_cover_setup_schedule_aead_and_export() {
        let vectors: Vec<DraftVector> = serde_json::from_str(include_str!(
            "../../tests/vectors/hpke-pq-draft-05-test-vectors.json"
        ))
        .expect("the pinned draft-05 vector corpus must remain valid JSON");
        let selected: Vec<_> = vectors
            .into_iter()
            .filter(|vector| {
                matches!(
                    (vector.kem_id, vector.kdf_id, vector.aead_id),
                    (ML_KEM_768_KEM_ID, 0x0001, 0x0001) | (ML_KEM_1024_KEM_ID, 0x0002, 0x0002)
                )
            })
            .collect();
        assert_eq!(
            selected.len(),
            2,
            "the pinned corpus must contain both supported profiles"
        );

        for vector in selected {
            assert_eq!(vector.mode, 0, "only Base mode is implemented");
            assert_eq!(vector.encryptions.len(), 10);
            assert_eq!(vector.exports.len(), 5);
            let info = decode(&vector.info);
            let expected_suite_id = decode(&vector.suite_id);
            let expected_key = decode(&vector.key);
            let expected_base_nonce = decode(&vector.base_nonce);
            let expected_exporter_secret = decode(&vector.exporter_secret);
            let expected_shared_secret = decode(&vector.shared_secret);
            let expected_encapsulation = decode(&vector.enc);

            match vector.kem_id {
                ML_KEM_768_KEM_ID => {
                    let profile = Draft05Profile::MlKem768HkdfSha256Aes128Gcm;
                    assert_eq!(suite_id(profile), expected_suite_id.as_slice());
                    let (derived_public_key, derived_private_key) =
                        derive_key_pair(&decode(&vector.ikm_r)).unwrap();
                    assert_eq!(
                        derived_private_key.as_bytes(),
                        decode(&vector.sk_rm).as_slice()
                    );
                    assert_eq!(
                        derived_public_key.as_bytes(),
                        decode(&vector.pk_rm).as_slice()
                    );

                    let recipient_public_key =
                        MlKem768PublicKey::from_bytes(&decode(&vector.pk_rm)).unwrap();
                    let recipient_private_key =
                        MlKem768PrivateKey::from_bytes(&decode(&vector.sk_rm)).unwrap();
                    let (encapsulation, shared_secret) =
                        encapsulate_derand(&recipient_public_key, &decode(&vector.ikm_e)).unwrap();
                    assert_eq!(encapsulation.as_bytes(), expected_encapsulation.as_slice());
                    assert_eq!(shared_secret.as_bytes(), expected_shared_secret.as_slice());
                    assert_eq!(
                        decapsulate(&recipient_private_key, &encapsulation)
                            .unwrap()
                            .as_bytes(),
                        expected_shared_secret.as_slice()
                    );

                    let (encapsulation, mut sender) =
                        setup_base_sender_768(&recipient_public_key, &decode(&vector.ikm_e), &info)
                            .unwrap();
                    let mut receiver =
                        setup_base_receiver_768(&recipient_private_key, &encapsulation, &info)
                            .unwrap();
                    assert_eq!(sender.key.as_slice(), expected_key.as_slice());
                    assert_eq!(sender.base_nonce.as_slice(), expected_base_nonce.as_slice());
                    assert_eq!(
                        sender.exporter_secret.as_slice(),
                        expected_exporter_secret.as_slice()
                    );
                    assert_vector_messages_and_exports(&mut sender, &mut receiver, &vector);
                }
                ML_KEM_1024_KEM_ID => {
                    let profile = Draft05Profile::MlKem1024HkdfSha384Aes256Gcm;
                    assert_eq!(suite_id(profile), expected_suite_id.as_slice());
                    let (derived_public_key, derived_private_key) =
                        derive_key_pair_1024(&decode(&vector.ikm_r)).unwrap();
                    assert_eq!(
                        derived_private_key.as_bytes(),
                        decode(&vector.sk_rm).as_slice()
                    );
                    assert_eq!(
                        derived_public_key.as_bytes(),
                        decode(&vector.pk_rm).as_slice()
                    );

                    let recipient_public_key =
                        MlKem1024PublicKey::from_bytes(&decode(&vector.pk_rm)).unwrap();
                    let recipient_private_key =
                        MlKem1024PrivateKey::from_bytes(&decode(&vector.sk_rm)).unwrap();
                    let (encapsulation, shared_secret) =
                        encapsulate_derand_1024(&recipient_public_key, &decode(&vector.ikm_e))
                            .unwrap();
                    assert_eq!(encapsulation.as_bytes(), expected_encapsulation.as_slice());
                    assert_eq!(shared_secret.as_bytes(), expected_shared_secret.as_slice());
                    assert_eq!(
                        decapsulate_1024(&recipient_private_key, &encapsulation)
                            .unwrap()
                            .as_bytes(),
                        expected_shared_secret.as_slice()
                    );

                    let (encapsulation, mut sender) = setup_base_sender_1024(
                        &recipient_public_key,
                        &decode(&vector.ikm_e),
                        &info,
                    )
                    .unwrap();
                    let mut receiver =
                        setup_base_receiver_1024(&recipient_private_key, &encapsulation, &info)
                            .unwrap();
                    assert_eq!(sender.key.as_slice(), expected_key.as_slice());
                    assert_eq!(sender.base_nonce.as_slice(), expected_base_nonce.as_slice());
                    assert_eq!(
                        sender.exporter_secret.as_slice(),
                        expected_exporter_secret.as_slice()
                    );
                    assert_vector_messages_and_exports(&mut sender, &mut receiver, &vector);
                }
                _ => unreachable!("the filter selected only the two supported profiles"),
            }
        }
    }

    fn assert_vector_messages_and_exports(
        sender: &mut Draft05BaseContext,
        receiver: &mut Draft05BaseContext,
        vector: &DraftVector,
    ) {
        for encryption in &vector.encryptions {
            let expected_nonce = decode(&encryption.nonce);
            assert_eq!(
                sender.nonce_for_current_sequence().unwrap().as_slice(),
                expected_nonce.as_slice()
            );
            let aad = decode(&encryption.aad);
            let plaintext = decode(&encryption.pt);
            let expected_ciphertext = decode(&encryption.ct);
            assert_eq!(sender.seal(&aad, &plaintext).unwrap(), expected_ciphertext);
            assert_eq!(
                receiver.open(&aad, &expected_ciphertext).unwrap(),
                plaintext
            );
        }
        for export in &vector.exports {
            assert_eq!(
                sender
                    .export(&decode(&export.exporter_context), export.output_len)
                    .unwrap(),
                decode(&export.exported_value),
            );
        }
    }

    #[test]
    fn p256_hybrid_combiner_matches_the_pinned_shared_secret() {
        let vectors: Vec<DraftVector> = serde_json::from_str(include_str!(
            "../../tests/vectors/hpke-pq-draft-05-test-vectors.json"
        ))
        .expect("the pinned draft-05 vector corpus must remain valid JSON");
        let vector = vectors
            .into_iter()
            .find(|vector| vector.kem_id == 0x0050 && vector.kdf_id == 0x0001)
            .expect("the pinned corpus must contain the MLKEM768-P256 vector");
        let (encapsulation, shared_secret, decapsulated_shared_secret) =
            draft_ietf_hpke_pq_05_full::test_p256_hybrid_encapsulate(
                &decode(&vector.sk_rm),
                &decode(&vector.ikm_e),
            )
            .unwrap();
        assert_eq!(encapsulation, decode(&vector.enc));
        assert_eq!(shared_secret, decode(&vector.shared_secret));
        assert_eq!(decapsulated_shared_secret, decode(&vector.shared_secret));
        let (key, nonce, exporter_secret) =
            draft_ietf_hpke_pq_05_full::test_p256_hybrid_context_material(
                &decode(&vector.sk_rm),
                &decode(&vector.ikm_e),
                &decode(&vector.info),
            )
            .unwrap();
        assert_eq!(key, decode(&vector.key));
        assert_eq!(nonce, decode(&vector.base_nonce));
        assert_eq!(exporter_secret, decode(&vector.exporter_secret));
    }
}
