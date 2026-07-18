//! AAD (Additional Authenticated Data) construction for CGv2 envelopes.
//!
//! # Responsibility scope
//! Owns the canonical function that assembles the AAD blob bound by every AEAD
//! operation. The AAD includes all envelope metadata so that any field mutation
//! (version, algorithm choice, KEM ciphertext, nonce, metadata) is detected by
//! the AEAD authentication check.
//!
//! # Wire format (AAD byte layout)
//! ```text
//! Field                         Length
//! ─────────────────────────────────────
//! magic (b"CGv2")               4
//! version (LE u16)              2
//! kem_alg (u8)                  1
//! aead_alg (u8)                 1
//! kdf_alg (u8)                  1
//! flags (u8)                    1
//! kem_ciphertext length (LE u32) 4
//! kem_ciphertext bytes          variable
//! nonce bytes                   variable
//! metadata bytes                variable
//! ─────────────────────────────────────
//! ```
//!
//! Note: the nonce and metadata are appended without a length prefix because
//! their lengths are fixed and derivable from the algorithm ID and the caller's
//! context. A future version may add length prefixes if variable-length nonces
//! are introduced.
//!
//! # Concurrency
//! Pure function; no shared state.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::protocol::{header::{Header, KemAlgId, AeadAlgId, KdfAlgId}, aad::build_aad};
//! let hdr = Header::new(KemAlgId::MlKem768, AeadAlgId::XChaCha20Poly1305, KdfAlgId::HkdfSha256);
//! let aad = build_aad(&hdr, &[0u8; 32], &[0u8; 24], &[]);
//! assert!(!aad.is_empty());
//! ```

use crate::error::CryptError;
use crate::protocol::header::Header;

/// Construct the AAD for a CGv2 envelope.
///
/// # Description
/// Concatenates all fields that must be authenticated:
/// `magic || version || kem_alg || aead_alg || kdf_alg || flags || len(kem_ct) || kem_ct || nonce || metadata`.
///
/// The KEM ciphertext length is encoded as a 4-byte little-endian `u32` to make the
/// AAD unambiguous even when ciphertext sizes vary across parameter sets.
///
/// # Arguments
/// - `header` (`&Header`): the envelope header (provides algorithm IDs + version).
/// - `kem_ciphertext` (`&[u8]`): the raw KEM ciphertext bytes.
/// - `nonce` (`&[u8]`): the symmetric cipher nonce/IV bytes (empty for AES-CBC which
///   prepends its IV to the ciphertext instead).
/// - `metadata` (`&[u8]`): optional caller-supplied context bytes (empty slice if none).
///
/// # Returns
/// The complete AAD as a `Vec<u8>`.
///
/// # Concurrency
/// Pure function; no shared state. Safe to call from any thread.
///
/// # Examples
/// ```rust,no_run
/// use crypt_guard::protocol::{header::{Header, KemAlgId, AeadAlgId, KdfAlgId}, aad::build_aad};
/// let hdr = Header::new(KemAlgId::MlKem768, AeadAlgId::XChaCha20Poly1305, KdfAlgId::HkdfSha256);
/// let aad = build_aad(&hdr, b"fake_kem_ct", b"nonce_24_bytes___nonce__", b"");
/// // AAD is non-empty and deterministic.
/// assert!(aad.len() > 14);
/// ```
pub fn build_aad(header: &Header, kem_ciphertext: &[u8], nonce: &[u8], metadata: &[u8]) -> Vec<u8> {
    try_build_aad(header, kem_ciphertext, nonce, metadata)
        .unwrap_or_else(|_| panic!("CGv2 AAD fields exceed the canonical wire representation"))
}

/// Construct the AAD for a CGv2 envelope with checked wire-length arithmetic.
///
/// # Description
/// Produces exactly the same bytes as [`build_aad`] for valid inputs, while
/// rejecting a KEM ciphertext that cannot be represented by its `u32`
/// little-endian length prefix and checked allocation failures.
///
/// # Arguments
/// - `header` (`&Header`): the envelope header.
/// - `kem_ciphertext` (`&[u8]`): the raw KEM ciphertext bytes.
/// - `nonce` (`&[u8]`): the symmetric cipher nonce or IV bytes.
/// - `metadata` (`&[u8]`): optional caller-supplied context bytes.
///
/// # Returns
/// The complete canonical AAD as a `Vec<u8>`.
///
/// # Errors
/// Returns [`CryptError::InvalidEnvelope`] when the KEM ciphertext length
/// cannot be encoded in the CGv2 AAD or the combined allocation length
/// overflows or cannot be reserved.
pub fn try_build_aad(
    header: &Header,
    kem_ciphertext: &[u8],
    nonce: &[u8],
    metadata: &[u8],
) -> Result<Vec<u8>, CryptError> {
    let hdr_bytes = header.try_to_bytes()?;
    let kem_ct_len =
        u32::try_from(kem_ciphertext.len()).map_err(|_| CryptError::InvalidEnvelope)?;
    let capacity = hdr_bytes
        .len()
        .checked_add(4) // u32 length prefix for kem_ciphertext
        .and_then(|capacity| capacity.checked_add(kem_ciphertext.len()))
        .and_then(|capacity| capacity.checked_add(nonce.len()))
        .and_then(|capacity| capacity.checked_add(metadata.len()))
        .ok_or(CryptError::InvalidEnvelope)?;
    let mut aad = Vec::new();
    aad.try_reserve_exact(capacity)
        .map_err(|_| CryptError::InvalidEnvelope)?;
    aad.extend_from_slice(&hdr_bytes);
    aad.extend_from_slice(&kem_ct_len.to_le_bytes());
    aad.extend_from_slice(kem_ciphertext);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(metadata);
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::header::{AeadAlgId, Header, KdfAlgId, KemAlgId};

    #[test]
    fn test_build_aad_deterministic() {
        let hdr = Header::new(
            KemAlgId::MlKem768,
            AeadAlgId::XChaCha20Poly1305,
            KdfAlgId::HkdfSha256,
        );
        let ct = vec![1u8; 32];
        let nonce = [2u8; 24];
        let meta = b"test";
        let aad1 = build_aad(&hdr, &ct, &nonce, meta);
        let aad2 = build_aad(&hdr, &ct, &nonce, meta);
        assert_eq!(aad1, aad2);
    }

    #[test]
    fn test_build_aad_ct_mutation_changes_aad() {
        let hdr = Header::new(
            KemAlgId::MlKem768,
            AeadAlgId::AesGcmSiv,
            KdfAlgId::HkdfSha256,
        );
        let ct1 = vec![1u8; 32];
        let ct2 = vec![2u8; 32];
        let nonce = [];
        assert_ne!(
            build_aad(&hdr, &ct1, &nonce, b""),
            build_aad(&hdr, &ct2, &nonce, b"")
        );
    }

    #[test]
    fn test_build_aad_nonce_mutation_changes_aad() {
        let hdr = Header::new(
            KemAlgId::MlKem768,
            AeadAlgId::XChaCha20Poly1305,
            KdfAlgId::HkdfSha256,
        );
        let ct = vec![0u8; 32];
        let nonce1 = [0u8; 24];
        let nonce2 = [1u8; 24];
        assert_ne!(
            build_aad(&hdr, &ct, &nonce1, b""),
            build_aad(&hdr, &ct, &nonce2, b"")
        );
    }
}
