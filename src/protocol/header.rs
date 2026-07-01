//! Envelope header: algorithm identifiers, flags, and version.
//!
//! # Responsibility scope
//! Owns [`Header`], its field types, and its serialization/deserialization to
//! a fixed-width byte representation. The header is always 14 bytes when
//! serialized:
//!
//! ```text
//! Offset  Len  Field
//!   0      4   magic     [u8; 4]     b"CGv2"
//!   4      2   version   u16-LE      currently 2
//!   6      1   kem_alg   u8          KemAlgId
//!   7      1   aead_alg  u8          AeadAlgId
//!   8      1   kdf_alg   u8          KdfAlgId
//!   9      1   flags     u8          reserved, must be 0
//!  10      4   (reserved / padding)
//! Total = 14 bytes
//! ```
//!
//! # Key types exported
//! - [`Header`] — the full header struct
//! - [`KemAlgId`] — one-byte KEM algorithm identifier
//! - [`AeadAlgId`] — one-byte AEAD algorithm identifier
//! - [`KdfAlgId`] — one-byte KDF algorithm identifier
//!
//! # Concurrency
//! [`Header`] is `Clone + Copy + Send + Sync`.
//!
//! # Errors
//! - [`crate::error::CryptError::InvalidEnvelope`]: header bytes are too short.
//! - [`crate::error::CryptError::UnsupportedEnvelopeVersion`]: version ≠ 2.
//! - [`crate::error::CryptError::UnsupportedAlgorithm`]: unknown algorithm byte.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::protocol::header::{Header, KemAlgId, AeadAlgId, KdfAlgId};
//! let hdr = Header::new(KemAlgId::MlKem768, AeadAlgId::XChaCha20Poly1305, KdfAlgId::HkdfSha256);
//! let bytes = hdr.to_bytes();
//! let parsed = Header::from_bytes(&bytes).unwrap();
//! assert_eq!(hdr, parsed);
//! ```

use crate::error::CryptError;
use crate::protocol::version::{MAGIC, VERSION_V2};

/// Serialized size of the header in bytes.
pub const HEADER_SIZE: usize = 14;

/// One-byte KEM algorithm identifier.
///
/// # Description
/// Stored in byte 6 of the serialized header. Parsers that encounter an unknown
/// value return [`CryptError::UnsupportedAlgorithm`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KemAlgId {
    /// ML-KEM-512 (FIPS 203, security category 1).
    MlKem512 = 1,
    /// ML-KEM-768 (FIPS 203, security category 3).
    MlKem768 = 2,
    /// ML-KEM-1024 (FIPS 203, security category 5).
    MlKem1024 = 3,
}

impl KemAlgId {
    /// Parse from a raw byte.
    ///
    /// # Errors
    /// Returns [`CryptError::UnsupportedAlgorithm`] for unknown values.
    pub fn from_byte(b: u8) -> Result<Self, CryptError> {
        match b {
            1 => Ok(Self::MlKem512),
            2 => Ok(Self::MlKem768),
            3 => Ok(Self::MlKem1024),
            _ => Err(CryptError::UnsupportedAlgorithm),
        }
    }
}

/// One-byte AEAD/symmetric algorithm identifier.
///
/// # Description
/// Stored in byte 7 of the serialized header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AeadAlgId {
    /// AES-256-CBC + HMAC-SHA512 (non-AEAD, explicit MAC).
    AesCbc = 1,
    /// AES-256-GCM-SIV (AEAD, built-in authentication).
    AesGcmSiv = 2,
    /// AES-256-CTR + HMAC-SHA512 (non-AEAD, explicit MAC).
    AesCtr = 3,
    /// AES-256-XTS + HMAC-SHA512 (non-AEAD, explicit MAC; sector-tweak model).
    AesXts = 4,
    /// XChaCha20 + HMAC-SHA512 (non-AEAD, explicit MAC).
    XChaCha20 = 5,
    /// XChaCha20-Poly1305 (AEAD, built-in authentication).
    XChaCha20Poly1305 = 6,
}

impl AeadAlgId {
    /// Returns `true` when this algorithm provides built-in AEAD authentication.
    ///
    /// # Description
    /// AEAD algorithms (GCM-SIV, XChaCha20-Poly1305) authenticate plaintext as
    /// part of the cipher; no additional HMAC is computed. Non-AEAD algorithms
    /// (CBC, CTR, XTS, XChaCha20) require an explicit HMAC over the envelope.
    pub fn is_aead(self) -> bool {
        matches!(self, Self::AesGcmSiv | Self::XChaCha20Poly1305)
    }

    /// Parse from a raw byte.
    ///
    /// # Errors
    /// Returns [`CryptError::UnsupportedAlgorithm`] for unknown values.
    pub fn from_byte(b: u8) -> Result<Self, CryptError> {
        match b {
            1 => Ok(Self::AesCbc),
            2 => Ok(Self::AesGcmSiv),
            3 => Ok(Self::AesCtr),
            4 => Ok(Self::AesXts),
            5 => Ok(Self::XChaCha20),
            6 => Ok(Self::XChaCha20Poly1305),
            _ => Err(CryptError::UnsupportedAlgorithm),
        }
    }
}

/// One-byte KDF algorithm identifier.
///
/// # Description
/// Stored in byte 8 of the serialized header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfAlgId {
    /// HKDF-SHA256 (RFC 5869 with SHA-256).
    HkdfSha256 = 1,
    /// HKDF-SHA512 (RFC 5869 with SHA-512).
    HkdfSha512 = 2,
}

impl KdfAlgId {
    /// Parse from a raw byte.
    ///
    /// # Errors
    /// Returns [`CryptError::UnsupportedAlgorithm`] for unknown values.
    pub fn from_byte(b: u8) -> Result<Self, CryptError> {
        match b {
            1 => Ok(Self::HkdfSha256),
            2 => Ok(Self::HkdfSha512),
            _ => Err(CryptError::UnsupportedAlgorithm),
        }
    }
}

/// Envelope header: identifies the algorithms used and the protocol version.
///
/// # Description
/// The header is always the first 14 bytes of a serialized [`super::Envelope`].
/// It carries enough information to reconstruct the full key schedule and select
/// the correct cipher on the decrypt side, without reading the rest of the
/// envelope.
///
/// # Concurrency
/// `Clone + Copy + Send + Sync`.
///
/// # Examples
/// ```rust,no_run
/// use crypt_guard::protocol::header::{Header, KemAlgId, AeadAlgId, KdfAlgId};
/// let hdr = Header::new(KemAlgId::MlKem768, AeadAlgId::XChaCha20Poly1305, KdfAlgId::HkdfSha256);
/// let bytes = hdr.to_bytes();
/// assert_eq!(bytes.len(), 14);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Protocol magic bytes (`b"CGv2"`).
    pub magic: [u8; 4],
    /// Envelope version (`2`).
    pub version: u16,
    /// KEM algorithm used for key encapsulation.
    pub kem_alg: KemAlgId,
    /// Symmetric/AEAD algorithm used for data encryption.
    pub aead_alg: AeadAlgId,
    /// KDF algorithm used to derive the session key.
    pub kdf_alg: KdfAlgId,
    /// Reserved flags byte (must be 0; reserved for future use).
    pub flags: u8,
}

impl Header {
    /// Construct a new header with the given algorithm identifiers.
    ///
    /// # Arguments
    /// - `kem_alg` (`KemAlgId`): KEM parameter set.
    /// - `aead_alg` (`AeadAlgId`): symmetric/AEAD algorithm.
    /// - `kdf_alg` (`KdfAlgId`): KDF variant.
    ///
    /// # Returns
    /// A `Header` with `magic = b"CGv2"`, `version = 2`, `flags = 0`.
    pub fn new(kem_alg: KemAlgId, aead_alg: AeadAlgId, kdf_alg: KdfAlgId) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION_V2,
            kem_alg,
            aead_alg,
            kdf_alg,
            flags: 0,
        }
    }

    /// Serialize the header to a fixed-size 14-byte array.
    ///
    /// # Returns
    /// `[u8; HEADER_SIZE]` in the layout described in the module doc.
    pub fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(&self.magic);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6] = self.kem_alg as u8;
        out[7] = self.aead_alg as u8;
        out[8] = self.kdf_alg as u8;
        out[9] = self.flags;
        // bytes 10–13 are reserved / padding (zero)
        out
    }

    /// Deserialize a header from a byte slice.
    ///
    /// # Arguments
    /// - `bytes` (`&[u8]`): must be at least [`HEADER_SIZE`] bytes long.
    ///
    /// # Returns
    /// `Ok(Header)` on success.
    ///
    /// # Errors
    /// - [`CryptError::InvalidEnvelope`]: fewer than `HEADER_SIZE` bytes provided, or
    ///   magic does not match `b"CGv2"`.
    /// - [`CryptError::UnsupportedEnvelopeVersion`]: version field ≠ 2.
    /// - [`CryptError::UnsupportedAlgorithm`]: unknown algorithm byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        if bytes.len() < HEADER_SIZE {
            return Err(CryptError::InvalidEnvelope);
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != MAGIC {
            return Err(CryptError::InvalidEnvelope);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != VERSION_V2 {
            return Err(CryptError::UnsupportedEnvelopeVersion);
        }
        let kem_alg = KemAlgId::from_byte(bytes[6])?;
        let aead_alg = AeadAlgId::from_byte(bytes[7])?;
        let kdf_alg = KdfAlgId::from_byte(bytes[8])?;
        let flags = bytes[9];
        Ok(Self {
            magic,
            version,
            kem_alg,
            aead_alg,
            kdf_alg,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let hdr = Header::new(
            KemAlgId::MlKem768,
            AeadAlgId::XChaCha20Poly1305,
            KdfAlgId::HkdfSha256,
        );
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = Header::from_bytes(&bytes).unwrap();
        assert_eq!(hdr, parsed);
    }

    #[test]
    fn test_header_bad_magic() {
        let mut bytes = Header::new(
            KemAlgId::MlKem512,
            AeadAlgId::AesGcmSiv,
            KdfAlgId::HkdfSha512,
        )
        .to_bytes();
        bytes[0] = 0xFF;
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(CryptError::InvalidEnvelope)
        ));
    }

    #[test]
    fn test_header_bad_version() {
        let mut bytes = Header::new(
            KemAlgId::MlKem512,
            AeadAlgId::AesGcmSiv,
            KdfAlgId::HkdfSha256,
        )
        .to_bytes();
        bytes[4] = 9;
        bytes[5] = 0;
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(CryptError::UnsupportedEnvelopeVersion)
        ));
    }

    #[test]
    fn test_header_short_bytes() {
        assert!(matches!(
            Header::from_bytes(&[0u8; 5]),
            Err(CryptError::InvalidEnvelope)
        ));
    }

    #[test]
    fn test_aead_alg_is_aead() {
        assert!(AeadAlgId::AesGcmSiv.is_aead());
        assert!(AeadAlgId::XChaCha20Poly1305.is_aead());
        assert!(!AeadAlgId::AesCbc.is_aead());
        assert!(!AeadAlgId::AesCtr.is_aead());
        assert!(!AeadAlgId::XChaCha20.is_aead());
    }
}
