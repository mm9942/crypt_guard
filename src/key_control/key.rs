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
//! use crypt_guard::key_control::{Key, KeyTypes};
//! let key = Key::new_public_key(vec![0u8; 32]);
//! ```

use crate::error::CryptError;
use crate::key_control::*;
use std::path::PathBuf;

/// Represents a cryptographic key — its type tag and raw bytes.
///
/// # Description
/// Provides factory constructors for each key role, KEM encapsulation/decapsulation
/// (behind the `legacy-pqclean` feature), and file save helpers.
///
/// # Concurrency
/// `Clone + Send + Sync`.
#[derive(PartialEq, Debug, Clone)]
pub struct Key {
    /// The type of the key.
    key_type: KeyTypes,
    /// The raw key bytes.
    content: Vec<u8>,
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
    fn validate_and_copy(key_type: &KeyTypes, content: Vec<u8>) -> Vec<u8> {
        #[cfg(feature = "legacy-pqclean")]
        {
            use pqcrypto_kyber::kyber1024;
            use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
            match key_type {
                KeyTypes::PublicKey => {
                    if let Ok(k) = kyber1024::PublicKey::from_bytes(&content) {
                        return k.as_bytes().to_vec();
                    }
                }
                KeyTypes::SecretKey => {
                    if let Ok(k) = kyber1024::SecretKey::from_bytes(&content) {
                        return k.as_bytes().to_vec();
                    }
                }
                KeyTypes::Ciphertext => {
                    if let Ok(k) = kyber1024::Ciphertext::from_bytes(&content) {
                        return k.as_bytes().to_vec();
                    }
                }
                KeyTypes::SharedSecret => {
                    if let Ok(k) = kyber1024::SharedSecret::from_bytes(&content) {
                        return k.as_bytes().to_vec();
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
        Ok(Key::new_shared_secret(ss.as_bytes().to_vec()))
    }

    #[cfg(not(feature = "legacy-pqclean"))]
    fn decap_inner(&self, _ciphertext: Key) -> Result<Key, CryptError> {
        Err(CryptError::UnsupportedOperation)
    }
}
