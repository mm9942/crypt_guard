//! Typed cryptographic key representation and KEM operations.
//!
//! # Responsibility scope
//! Defines [`Key`] — a typed wrapper around raw key bytes that provides KEM encapsulation
//! and decapsulation (via the legacy pqcrypto-kyber1024 path when `legacy-pqclean` is
//! active) and file-save helpers.
//!
//! All methods return `Result<_, CryptError>` and contain no `unwrap`/`expect`/`panic`.
//!
//! # Key types exported
//! - [`Key`] — typed key container
//!
//! # Concurrency
//! `Key` holds a `Vec<u8>`; it is `Clone` and `Send + Sync`.
//!
//! # Errors
//! See [`crate::error::CryptError`]: `InvalidParameters`, `EncapsulationError`,
//! `DecapsulationError`, `InvalidKeyType`, `UnsupportedOperation`.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard_core::key_control::{Key, KeyTypes};
//! let key = Key::new_public_key(vec![0u8; 32]);
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use crate::error::CryptError;
use crate::key_control::*;
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Represents a cryptographic key — its type tag and raw bytes.
///
/// # Description
/// Provides factory constructors for each key role, KEM encapsulation/decapsulation
/// (behind the `legacy-pqclean` feature), and file save helpers.
///
/// # Concurrency
/// `Clone + Send + Sync`.
#[derive(Clone)]
pub struct Key {
    /// The type of the key.
    key_type: KeyTypes,
    /// The raw key bytes.
    content: Vec<u8>,
}

/// Manual `Debug` impl that redacts secret-bearing content.
///
/// For `SecretKey` and `SharedSecret` key types, the raw bytes are never
/// written to the formatter — only the key type and byte length are shown.
/// Other key types (public key, ciphertext) are not secret and are printed
/// as before.
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key_type {
            KeyTypes::SecretKey | KeyTypes::SharedSecret => f
                .debug_struct("Key")
                .field("key_type", &self.key_type)
                .field(
                    "content",
                    &format_args!("<redacted {} bytes>", self.content.len()),
                )
                .finish(),
            _ => f
                .debug_struct("Key")
                .field("key_type", &self.key_type)
                .field("content", &self.content)
                .finish(),
        }
    }
}

/// Manual, constant-time `PartialEq` impl.
///
/// The byte comparison walks every byte of the longer buffer without
/// short-circuiting on the first mismatch, so equality checks on secret key
/// material do not leak timing information about *where* two keys differ.
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        let type_eq = self.key_type == other.key_type;
        let len_eq = self.content.len() == other.content.len();
        let max_len = self.content.len().max(other.content.len());

        let mut diff: u8 = 0;
        for i in 0..max_len {
            let a = self.content.get(i).copied().unwrap_or(0);
            let b = other.content.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }

        type_eq && len_eq && diff == 0
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        if matches!(self.key_type, KeyTypes::SecretKey | KeyTypes::SharedSecret) {
            self.content.zeroize();
        }
    }
}

impl Key {
    /// Construct a new `Key` with specified type and content.
    ///
    /// # Description
    /// When `legacy-pqclean` is enabled, validates the byte length against the
    /// expected size for the given Kyber-1024 key type. On failure returns an empty
    /// key with the given type (matching previous behaviour).
    ///
    /// # Arguments
    /// - `key_type` (`KeyTypes`): the role of this key.
    /// - `content` (`Vec<u8>`): the raw bytes.
    ///
    /// # Returns
    /// A new `Key`.
    pub fn new(key_type: KeyTypes, content: Vec<u8>) -> Self {
        let content = Self::validate_and_copy(&key_type, content);
        Key { key_type, content }
    }

    /// Validate key bytes for the given type; return them unchanged if invalid.
    ///
    /// This replaces the old `optimize()` which called `.unwrap()` on pqcrypto conversions.
    /// If the byte slice does not match the expected key structure, the raw bytes are
    /// returned as-is (preserving the previous fallback behaviour).
    #[cfg_attr(not(feature = "legacy-pqclean"), allow(unused_mut))]
    fn validate_and_copy(key_type: &KeyTypes, mut content: Vec<u8>) -> Vec<u8> {
        #[cfg(feature = "legacy-pqclean")]
        {
            use pqcrypto_kyber::kyber1024;
            use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
            match key_type {
                KeyTypes::PublicKey => {
                    if let Ok(k) = kyber1024::PublicKey::from_bytes(&content) {
                        let validated = k.as_bytes().to_vec();
                        // The caller's buffer is superseded by `validated`; wipe it
                        // before it is dropped so no stale copy of the key lingers.
                        content.zeroize();
                        return validated;
                    }
                }
                KeyTypes::SecretKey => {
                    if let Ok(k) = kyber1024::SecretKey::from_bytes(&content) {
                        let validated = k.as_bytes().to_vec();
                        content.zeroize();
                        return validated;
                    }
                }
                KeyTypes::Ciphertext => {
                    if let Ok(k) = kyber1024::Ciphertext::from_bytes(&content) {
                        let validated = k.as_bytes().to_vec();
                        content.zeroize();
                        return validated;
                    }
                }
                KeyTypes::SharedSecret => {
                    if let Ok(k) = kyber1024::SharedSecret::from_bytes(&content) {
                        let validated = k.as_bytes().to_vec();
                        content.zeroize();
                        return validated;
                    }
                }
                _ => {}
            }
        }
        let _ = key_type; // suppress unused warning when feature is off
        content
    }

    // ── Factory constructors ──────────────────────────────────────────────────

    /// Create a public key.
    ///
    /// # Arguments
    /// - `key` (`Vec<u8>`): raw public key bytes.
    pub fn new_public_key(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::PublicKey,
            content: key,
        }
    }

    /// Create a secret key.
    ///
    /// # Arguments
    /// - `key` (`Vec<u8>`): raw secret key bytes.
    pub fn new_secret_key(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::SecretKey,
            content: key,
        }
    }

    /// Create a ciphertext key entry.
    ///
    /// # Arguments
    /// - `key` (`Vec<u8>`): raw ciphertext bytes.
    pub fn new_ciphertext(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::Ciphertext,
            content: key,
        }
    }

    /// Create a shared secret key entry.
    ///
    /// # Arguments
    /// - `key` (`Vec<u8>`): raw shared secret bytes.
    pub fn new_shared_secret(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::SharedSecret,
            content: key,
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Return a reference to this key.
    ///
    /// # Returns
    /// `Ok(&Key)`.
    pub fn get(&self) -> Result<&Key, CryptError> {
        Ok(self)
    }

    /// Return the key type.
    ///
    /// # Returns
    /// `Ok(&KeyTypes)`.
    pub fn key_type(&self) -> Result<&KeyTypes, CryptError> {
        Ok(&self.key_type)
    }

    /// Return the raw key bytes.
    ///
    /// # Returns
    /// `Ok(&[u8])`.
    pub fn content(&self) -> Result<&[u8], CryptError> {
        Ok(&self.content)
    }

    // ── File save ─────────────────────────────────────────────────────────────

    /// Save the key to a file under `base_path`.
    ///
    /// # Arguments
    /// - `base_path` (`PathBuf`): directory in which to create the key file.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// - [`CryptError::UnsupportedOperation`]: attempting to save a `SharedSecret`.
    /// - [`CryptError::InvalidKeyType`]: key type is `None` or unrecognised.
    /// - I/O errors from [`FileMetadata::save`].
    pub fn save(&self, base_path: PathBuf) -> Result<(), CryptError> {
        let file_name = match self.key_type {
            KeyTypes::PublicKey => "public_key.pub",
            KeyTypes::SecretKey => "secret_key.sec",
            KeyTypes::Ciphertext => "ciphertext.ct",
            KeyTypes::SharedSecret => return Err(CryptError::UnsupportedOperation),
            _ => return Err(CryptError::InvalidKeyType),
        };

        let path = base_path.join(file_name);
        let file_metadata =
            FileMetadata::from(path, self.file_type_from_key_type(), FileState::Encrypted);
        file_metadata.save(&self.content)
    }

    /// Map `KeyTypes` to the corresponding `FileTypes`.
    fn file_type_from_key_type(&self) -> FileTypes {
        match self.key_type {
            KeyTypes::PublicKey => FileTypes::PublicKey,
            KeyTypes::SecretKey => FileTypes::SecretKey,
            KeyTypes::Ciphertext => FileTypes::Ciphertext,
            _ => FileTypes::Other,
        }
    }

    // ── KEM operations (legacy path) ──────────────────────────────────────────

    /// Encapsulate against this public key to produce a ciphertext and shared secret.
    ///
    /// # Returns
    /// `Ok((ciphertext_key, shared_secret_key))` on success.
    ///
    /// # Errors
    /// - [`CryptError::EncapsulationError`]: this is not a public key, or the bytes are invalid.
    pub fn encap(&self) -> Result<(Key, Key), CryptError> {
        match self.key_type {
            KeyTypes::PublicKey => self.encap_inner(),
            _ => Err(CryptError::EncapsulationError),
        }
    }

    #[cfg(feature = "legacy-pqclean")]
    fn encap_inner(&self) -> Result<(Key, Key), CryptError> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{Ciphertext as CT, PublicKey, SharedSecret as SST};
        let pk = kyber1024::PublicKey::from_bytes(self.content()?)
            .map_err(|_| CryptError::InvalidKemPublicKey)?;
        let (ss, ct) = kyber1024::encapsulate(&pk);
        // `ss.as_bytes().to_vec()` is passed straight into `Key::new_shared_secret`,
        // which takes ownership of the buffer; `Key`'s `Drop` impl zeroizes it, so
        // no separate leftover copy of the shared secret exists to scrub here. The
        // opaque `ss`/`ct` values themselves expose no mutable byte access and
        // cannot be zeroized directly.
        Ok((
            Key::new_ciphertext(ct.as_bytes().to_vec()),
            Key::new_shared_secret(ss.as_bytes().to_vec()),
        ))
    }

    #[cfg(not(feature = "legacy-pqclean"))]
    fn encap_inner(&self) -> Result<(Key, Key), CryptError> {
        Err(CryptError::UnsupportedOperation)
    }

    /// Decapsulate the given `ciphertext` with this secret key to recover the shared secret.
    ///
    /// # Arguments
    /// - `ciphertext` (`Key`): the ciphertext produced by encapsulation.
    ///
    /// # Returns
    /// `Ok(shared_secret_key)` on success.
    ///
    /// # Errors
    /// - [`CryptError::DecapsulationError`]: this is not a secret key, or bytes are invalid.
    pub fn decap(&self, ciphertext: Key) -> Result<Key, CryptError> {
        match self.key_type {
            KeyTypes::SecretKey => self.decap_inner(ciphertext),
            _ => Err(CryptError::DecapsulationError),
        }
    }

    #[cfg(feature = "legacy-pqclean")]
    fn decap_inner(&self, ciphertext: Key) -> Result<Key, CryptError> {
        use pqcrypto_kyber::kyber1024;
        use pqcrypto_traits::kem::{Ciphertext as CT, SecretKey};
        let ct = kyber1024::Ciphertext::from_bytes(ciphertext.content()?)
            .map_err(|_| CryptError::InvalidKemCiphertext)?;
        let sk = kyber1024::SecretKey::from_bytes(self.content()?)
            .map_err(|_| CryptError::InvalidKemSecretKey)?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        use pqcrypto_traits::kem::SharedSecret as SST;
        // See the comment in `encap_inner`: the `to_vec()` result is moved
        // directly into `Key`, whose `Drop` impl zeroizes it on release.
        Ok(Key::new_shared_secret(ss.as_bytes().to_vec()))
    }

    #[cfg(not(feature = "legacy-pqclean"))]
    fn decap_inner(&self, _ciphertext: Key) -> Result<Key, CryptError> {
        Err(CryptError::UnsupportedOperation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinctive byte pattern unlikely to appear by coincidence in the
    /// `Debug` output unless the raw bytes are actually printed.
    const MARKER: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xCA, 0xFE];

    #[test]
    fn secret_key_debug_redacts_content() {
        let key = Key::new_secret_key(MARKER.to_vec());
        let debug_str = format!("{:?}", key);
        assert!(
            !debug_str.contains("222"),
            "decimal byte leaked: {debug_str}"
        );
        assert!(!debug_str.contains("de, ad, be, ef"));
        assert!(!debug_str.contains(&format!("{:?}", MARKER.to_vec())));
        assert!(debug_str.contains("SecretKey"));
        assert!(debug_str.contains(&MARKER.len().to_string()));
    }

    #[test]
    fn shared_secret_debug_redacts_content() {
        let key = Key::new_shared_secret(MARKER.to_vec());
        let debug_str = format!("{:?}", key);
        assert!(!debug_str.contains(&format!("{:?}", MARKER.to_vec())));
        assert!(debug_str.contains("SharedSecret"));
    }

    #[test]
    fn public_key_debug_still_shows_bytes() {
        // Public keys are not secret; Debug output is unchanged from the
        // previous derived behaviour.
        let key = Key::new_public_key(MARKER.to_vec());
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains(&format!("{:?}", MARKER.to_vec())));
    }

    #[test]
    fn partial_eq_still_works() {
        let a = Key::new_secret_key(MARKER.to_vec());
        let b = Key::new_secret_key(MARKER.to_vec());
        let mut c = MARKER.to_vec();
        c[0] ^= 0xFF;
        let c = Key::new_secret_key(c);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let pub_a = Key::new_public_key(MARKER.to_vec());
        assert_ne!(a, pub_a, "different key types must not compare equal");
    }
}
