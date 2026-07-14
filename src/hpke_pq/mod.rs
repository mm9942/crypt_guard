//! Experimental post-quantum HPKE KEM adapters and Base-mode contexts.
//!
//! This module is deliberately separate from the CGv2 KEM path. It adapts the
//! PQCA/PQCP `libcrux-ml-kem` implementation to the ML-KEM HPKE KEM interface
//! described by the currently pinned post-quantum HPKE Internet-Draft. It does
//! not itself claim RFC-standardized ML-KEM HPKE support: the IETF mapping is
//! still a draft.  This module is compiled only by the non-default
//! `hpke-pq-draft-05` feature and must never be described as an RFC-standard
//! ML-KEM HPKE profile.
//!
//! The adapters implement ML-KEM-768 and ML-KEM-1024. They store the HPKE
//! recipient private key as the draft's 64-byte seed, expand that seed with the
//! FIPS 203 key-generation operation only for decapsulation, and validate
//! serialized public keys plus expanded private-key integrity at the PQCA
//! boundary.  The additive Base-mode API at the bottom of this module is
//! constrained to the two profiles covered by the pinned draft-05 vectors:
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

/// The two non-default, vector-gated profiles implemented by this module.
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
/// This module is intentionally feature-gated and explicitly revision-named:
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
        MlKem768(MlKem768PublicKey),
        MlKem1024(MlKem1024PublicKey),
    }

    impl RecipientPublicKey {
        /// Parse and validate a FIPS 203 public-key serialization for `profile`.
        pub fn from_bytes(profile: Profile, bytes: &[u8]) -> Result<Self, Error> {
            let inner = match profile {
                Profile::MlKem768HkdfSha256Aes128Gcm => MlKem768PublicKey::from_bytes(bytes)
                    .map(RecipientPublicKeyInner::MlKem768)
                    .map_err(|_| Error::InvalidRecipientPublicKey)?,
                Profile::MlKem1024HkdfSha384Aes256Gcm => MlKem1024PublicKey::from_bytes(bytes)
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
                        inner: RecipientPublicKeyInner::MlKem768(public_key),
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
                        inner: RecipientPublicKeyInner::MlKem1024(public_key),
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
}
