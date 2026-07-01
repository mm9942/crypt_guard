//! Authenticated `Envelope` — the CGv2 wire container.
//!
//! # Responsibility scope
//! Owns the [`Envelope`] struct and its deterministic serialization to/from bytes.
//! The envelope carries everything the decrypt side needs: the header (algorithm
//! IDs + version), the KEM ciphertext, the symmetric nonce/IV, and the symmetric
//! ciphertext. No secret material is stored here.
//!
//! # Wire format (serialized layout)
//! ```text
//! Offset  Len    Field
//! ──────────────────────────────────────────────
//!   0     14     header bytes ([Header::HEADER_SIZE])
//!  14      4     kem_ct length (LE u32)
//!  18      N     kem_ciphertext bytes
//!  18+N    4     nonce length (LE u32)
//!  22+N    M     nonce bytes
//!  22+N+M  4     ciphertext length (LE u32)
//!  26+N+M  P     ciphertext bytes
//! ```
//!
//! All variable-length fields are length-prefixed with 4-byte little-endian u32
//! so the parser can validate bounds before allocating.
//!
//! # Key types exported
//! - [`Envelope`] — the authenticated envelope
//!
//! # Concurrency
//! [`Envelope`] is `Clone + Send + Sync`.
//!
//! # Errors
//! - [`crate::error::CryptError::InvalidEnvelope`]: any parse error.
//! - [`crate::error::CryptError::UnsupportedEnvelopeVersion`]: version mismatch.
//! - [`crate::error::CryptError::UnsupportedAlgorithm`]: unknown algorithm byte.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::protocol::{
//!     header::{Header, KemAlgId, AeadAlgId, KdfAlgId},
//!     envelope::Envelope,
//! };
//! let hdr = Header::new(KemAlgId::MlKem768, AeadAlgId::XChaCha20Poly1305, KdfAlgId::HkdfSha256);
//! let env = Envelope::new(hdr, vec![0u8; 32], vec![0u8; 24], vec![0u8; 64]);
//! let bytes = env.to_bytes();
//! let parsed = Envelope::from_bytes(&bytes).unwrap();
//! assert_eq!(env.ciphertext, parsed.ciphertext);
//! ```

use crate::error::CryptError;
use crate::protocol::aad::build_aad;
use crate::protocol::header::{Header, HEADER_SIZE};

/// Authenticated envelope containing all fields needed for a single
/// encrypt/decrypt operation.
///
/// # Description
/// Produced by the encrypt path and consumed by the decrypt path. The envelope
/// must be stored (or transmitted) alongside the recipient's KEM secret key;
/// the secret key is not stored here.
///
/// The `nonce` field is stored inside the envelope and must **never** be
/// printed to stdout or logged at `info` level or above.
///
/// # Concurrency
/// `Clone + Send + Sync`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Parsed envelope header.
    pub header: Header,
    /// KEM ciphertext (produced by the sender's `encapsulate` call).
    pub kem_ciphertext: Vec<u8>,
    /// Symmetric nonce/IV used for the AEAD or stream cipher.
    ///
    /// **Not to be logged or printed.** Store in the envelope; recover on decrypt.
    pub nonce: Vec<u8>,
    /// Symmetric ciphertext (the encrypted payload).
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Construct a new envelope.
    ///
    /// # Arguments
    /// - `header` (`Header`): algorithm identifiers + version.
    /// - `kem_ciphertext` (`Vec<u8>`): KEM ciphertext from the sender.
    /// - `nonce` (`Vec<u8>`): symmetric nonce/IV (empty for AES-CBC which
    ///   embeds its IV in the ciphertext).
    /// - `ciphertext` (`Vec<u8>`): encrypted payload bytes.
    ///
    /// # Returns
    /// A new `Envelope`.
    pub fn new(
        header: Header,
        kem_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            header,
            kem_ciphertext,
            nonce,
            ciphertext,
        }
    }

    /// Compute the AAD bytes that must be bound by the AEAD authentication tag.
    ///
    /// # Description
    /// Delegates to [`build_aad`] with this envelope's header, KEM ciphertext,
    /// and nonce. The result must be passed as `aad` when calling
    /// `cipher.encrypt(nonce, aad, plaintext)` on the encrypt path and
    /// `cipher.decrypt(nonce, aad, ciphertext)` on the decrypt path.
    ///
    /// # Arguments
    /// - `metadata` (`&[u8]`): optional caller-supplied context bytes.
    ///
    /// # Returns
    /// The canonical AAD `Vec<u8>`.
    pub fn build_aad(&self, metadata: &[u8]) -> Vec<u8> {
        build_aad(&self.header, &self.kem_ciphertext, &self.nonce, metadata)
    }

    /// Serialize the envelope to bytes.
    ///
    /// # Description
    /// Layout: `header(14) || len(kem_ct)(4) || kem_ct || len(nonce)(4) || nonce || len(ct)(4) || ct`.
    ///
    /// # Returns
    /// The serialized envelope as a `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let hdr = self.header.to_bytes();
        let kem_ct_len = (self.kem_ciphertext.len() as u32).to_le_bytes();
        let nonce_len = (self.nonce.len() as u32).to_le_bytes();
        let ct_len = (self.ciphertext.len() as u32).to_le_bytes();

        let cap = HEADER_SIZE
            + 4
            + self.kem_ciphertext.len()
            + 4
            + self.nonce.len()
            + 4
            + self.ciphertext.len();
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&kem_ct_len);
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&nonce_len);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&ct_len);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserialize an envelope from a byte slice.
    ///
    /// # Arguments
    /// - `bytes` (`&[u8]`): the full serialized envelope.
    ///
    /// # Returns
    /// `Ok(Envelope)` on success.
    ///
    /// # Errors
    /// - [`CryptError::InvalidEnvelope`]: byte slice is too short for the header, any
    ///   length-prefix field, or the declared payload.
    /// - [`CryptError::UnsupportedEnvelopeVersion`]: header version ≠ 2.
    /// - [`CryptError::UnsupportedAlgorithm`]: unknown algorithm byte in header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptError> {
        if bytes.len() < HEADER_SIZE {
            return Err(CryptError::InvalidEnvelope);
        }
        let header = Header::from_bytes(&bytes[..HEADER_SIZE])?;
        let mut pos = HEADER_SIZE;

        let kem_ciphertext = read_len_prefixed(bytes, &mut pos)?;
        let nonce = read_len_prefixed(bytes, &mut pos)?;
        let ciphertext = read_len_prefixed(bytes, &mut pos)?;

        Ok(Self {
            header,
            kem_ciphertext,
            nonce,
            ciphertext,
        })
    }
}

/// Read a length-prefixed (LE u32) byte field from `bytes` at `*pos`, advancing `*pos`.
///
/// # Errors
/// Returns [`CryptError::InvalidEnvelope`] if there are insufficient bytes.
fn read_len_prefixed(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, CryptError> {
    if *pos + 4 > bytes.len() {
        return Err(CryptError::InvalidEnvelope);
    }
    let len = u32::from_le_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
    ]) as usize;
    *pos += 4;
    if *pos + len > bytes.len() {
        return Err(CryptError::InvalidEnvelope);
    }
    let field = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::header::{AeadAlgId, KdfAlgId, KemAlgId};

    fn make_env() -> Envelope {
        let hdr = Header::new(
            KemAlgId::MlKem768,
            AeadAlgId::XChaCha20Poly1305,
            KdfAlgId::HkdfSha256,
        );
        Envelope::new(hdr, vec![0u8; 32], vec![1u8; 24], vec![2u8; 64])
    }

    #[test]
    fn test_envelope_roundtrip() {
        let env = make_env();
        let bytes = env.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, parsed);
    }

    #[test]
    fn test_envelope_short_parse_error() {
        assert!(matches!(
            Envelope::from_bytes(&[0u8; 5]),
            Err(CryptError::InvalidEnvelope)
        ));
    }

    #[test]
    fn test_tamper_kem_ct_detected_in_aad() {
        let env = make_env();
        let mut tampered = env.clone();
        tampered.kem_ciphertext[0] ^= 0xFF;
        // AAD must differ
        assert_ne!(env.build_aad(b""), tampered.build_aad(b""));
    }

    #[test]
    fn test_tamper_nonce_detected_in_aad() {
        let env = make_env();
        let mut tampered = env.clone();
        tampered.nonce[0] ^= 0x01;
        assert_ne!(env.build_aad(b""), tampered.build_aad(b""));
    }

    #[test]
    fn test_tamper_ciphertext_roundtrip_still_parses() {
        // Ciphertext mutation should parse OK but AEAD auth will reject at cipher layer.
        let env = make_env();
        let mut bytes = env.to_bytes();
        // Flip a byte in the ciphertext section (last byte).
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        // ciphertext differs
        assert_ne!(parsed.ciphertext, env.ciphertext);
    }
}
