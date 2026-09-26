//! Legacy `CipherChaCha` symmetric cipher: raw XChaCha20 stream cipher with an
//! HMAC-SHA512 tag.
//!
//! [`CipherChaCha`](crate::cryptography::CipherChaCha) wraps the `chacha20`
//! crate's `XChaCha20` stream cipher. Its `new`, `encryption`/`decryption`
//! helpers and nonce generation are unconditionally compiled (see
//! `crates/core/src/core/mod.rs`), while the
//! [`CryptographicFunctions`](crate::core::CryptographicFunctions) impl that
//! binds it to a Kyber KEM shared secret is gated behind the `legacy-pqclean`
//! feature. This is part of the pre-v3 / CGv2 legacy API surface; new code
//! should use [`crypt_guard_core::pq_hpke`](crate::pq_hpke) instead.
//!
//! # Security
//! XChaCha20 alone is a stream cipher with no built-in authentication: it
//! provides confidentiality only, and reusing a nonce with the same key
//! breaks that confidentiality. This module compensates by prepending an
//! HMAC-SHA512 tag (keyed with the caller's passphrase) to the plaintext
//! before encryption and verifying it after decryption.
//!
//! # Examples
//! ```ignore
//! use crypt_guard_core::cryptography::{
//!     CipherChaCha, ContentType, CryptographicInformation, CryptographicMechanism,
//!     CryptographicMetadata, KeyEncapMechanism, Process,
//! };
//!
//! let infos = CryptographicInformation {
//!     content: message.as_bytes().to_owned(),
//!     passphrase: passphrase.as_bytes().to_vec(),
//!     metadata: CryptographicMetadata {
//!         process: Process::Encryption,
//!         encryption_type: CryptographicMechanism::XChaCha20,
//!         key_type: KeyEncapMechanism::kyber1024(),
//!         content_type: ContentType::RawData,
//!     },
//!     safe: false,
//!     location: None,
//! };
//! let mut cipher = CipherChaCha::new(infos, None);
//! let (encrypted, ciphertext) = cipher.encrypt(public_key)?;
//! ```
//use super::*;

//use crypt_guard_proc::{*, log_activity, write_log};
#[cfg(feature = "legacy-pqclean")]
use crate::core::{CryptographicFunctions, KeyControlVariant};
use crate::{
    cryptography::{
        hmac_sign::{Operation, Sign, SignType},
        *,
    },
    error::*,
};

use chacha20::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    XChaCha20,
};
use hex;
use rand::{rngs::OsRng, RngCore};
use std::{fs, result::Result};

/// Generates a 24-byte nonce using OS-level randomness.
///
/// # Returns
/// A 24-byte array filled with secure random bytes.
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// The main struct for handling cryptographic operations with ChaCha20 algorithm.
/// It encapsulates the cryptographic information, shared secret, and nonce required for encryption and decryption.
impl CipherChaCha {
    /// Constructs a new `CipherChaCha` instance with specified cryptographic information and an optional nonce.
    ///
    /// # Parameters
    /// - `infos`: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    /// - `nonce`: Optional hexadecimal string representation of the nonce. If not provided, a nonce will be generated.
    ///
    /// # Returns
    /// A new `CipherChaCha` instance.
    pub fn new(infos: CryptographicInformation, nonce: Option<String>) -> Self {
        let nonce: [u8; 24] = match nonce {
            // A malformed nonce (not hex, wrong length) must not panic: fall back to a
            // fresh random nonce, so decryption fails authentication with an error.
            Some(nonce) => hex::decode(nonce)
                .ok()
                .and_then(|decoded| <[u8; 24]>::try_from(decoded).ok())
                .unwrap_or_else(generate_nonce),
            None => generate_nonce(),
        };
        // println!("infos: {:?}", infos);
        CipherChaCha {
            infos,
            sharedsecret: Vec::new(),
            nonce,
        }
    }

    /// Retrieves the encrypted or decrypted data stored within the `CryptographicInformation`.
    ///
    /// # Returns
    /// A result containing the data as a vector of bytes (`Vec<u8>`) or a `CryptError`.
    pub fn get_data(&self) -> Result<Vec<u8>, CryptError> {
        let data = &self.infos.content()?;
        let data = data.to_vec();

        Ok(data)
    }
    /// Sets the shared secret for the cryptographic operation.
    ///
    /// # Parameters
    /// - `sharedsecret`: A vector of bytes (`Vec<u8>`) representing the shared secret.
    ///
    /// # Returns
    /// A reference to the `CipherChaCha` instance to allow method chaining.
    pub fn set_shared_secret(&mut self, sharedsecret: Vec<u8>) -> &Self {
        use zeroize::Zeroize;
        self.sharedsecret.zeroize();
        self.sharedsecret = sharedsecret;
        self
    }

    /// Retrieves the shared secret.
    ///
    /// # Returns
    /// A result containing a slice of the shared secret (`&[u8]`) or a `CryptError`.    
    pub fn sharedsecret(&self) -> Result<&[u8], CryptError> {
        Ok(&self.sharedsecret)
    }

    /// Sets the nonce for cryptographic operations.
    ///
    /// # Parameters
    /// - `nonce`: A 24-byte array representing the nonce.
    ///
    /// # Returns
    /// A slice of the set nonce (`&[u8; 24]`).
    pub fn set_nonce(&mut self, nonce: [u8; 24]) -> &[u8; 24] {
        self.nonce = nonce;
        &self.nonce
    }

    /// Retrieves the nonce.
    ///
    /// # Returns
    /// A slice of the current nonce (`&[u8; 24]`).
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Performs encryption or decryption based on the process type defined in `CryptographicInformation`.
    ///
    /// # Returns
    /// A result containing a tuple of encrypted data (`Vec<u8>`) and the nonce vector (`Vec<u8>`) used, or a `CryptError`.
    /// This method reads the file if `ContentType` is File and performs cryptographic operations accordingly.
    // Legacy raw-XChaCha20 orchestration helper; kept for the tuple-return path,
    // not reachable from the default envelope API.
    #[allow(dead_code)]
    fn cryptography(&mut self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let passphrase = self.infos.passphrase()?.to_vec();
        let file_contained = self.infos.contains_file()?;

        if file_contained && self.infos.metadata.content_type == ContentType::File {
            let content = fs::read(self.infos.location()?).map_err(|_| CryptError::FileNotFound)?;
            self.infos.set_data(&content)?;
        }

        match self.infos.metadata.process()? {
            Process::Encryption => {
                let (encrypted_data, nonce_vec) = self.process_data()?;
                let mut hmac = Sign::new(
                    encrypted_data,
                    passphrase,
                    Operation::Sign,
                    SignType::Sha512,
                );
                let data = hmac.try_hmac()?;
                if self.infos.safe()? {
                    self.infos.set_data(&data)?;
                    self.infos.safe_file()?;
                }
                Ok((data, nonce_vec))
            }
            Process::Decryption => {
                let mut verifier = Sign::new(
                    self.infos.content()?.to_vec(),
                    passphrase,
                    Operation::Verify,
                    SignType::Sha512,
                );
                let data = verifier.try_hmac()?;
                self.infos.set_data(&data)?;
                let (decrypted, nonce_vec) = self.process_data()?;
                if self.infos.safe()? {
                    self.infos.set_data(&decrypted)?;
                    self.infos.safe_file()?;
                }
                Ok((decrypted, nonce_vec))
            }
        }
    }

    /// Helper function to perform the encryption or decryption process based on the current settings.
    ///
    /// # Returns
    /// A result containing a tuple of processed data (`Vec<u8>`) and nonce vector (`Vec<u8>`), or a `CryptError`.
    // Legacy raw-XChaCha20 keystream helper; reached only via `cryptography` above.
    #[allow(dead_code)]
    fn process_data(&self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let data = &self.infos.content()?;
        let sharedsecret = self.sharedsecret()?;
        let nonce = self.nonce();
        let mut encrypted_data = data.to_vec();
        let mut cipher = XChaCha20::new(
            GenericArray::from_slice(sharedsecret),
            GenericArray::from_slice(nonce),
        );
        cipher.apply_keystream(&mut encrypted_data);
        Ok((encrypted_data, nonce.to_vec()))
    }
}

#[cfg(feature = "legacy-pqclean")]
impl CryptographicFunctions for CipherChaCha {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - `public_key`: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (`Vec<u8>`) and the key used, or a `CryptError`.
    /// Additionally, prints a message to stdout with the nonce for user reference.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let (sharedsecret, ciphertext) = key.encap(&public_key)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (encrypted_data, nonce) = self.cryptography()?;
        println!("Please write down this nonce: {}", hex::encode(nonce));
        Ok((encrypted_data, ciphertext))
    }

    /// Decrypts the provided data using the secret key and ciphertext.
    ///
    /// # Parameters
    /// - `secret_key`: The secret key used for decryption.
    /// - `ciphertext`: The ciphertext to decrypt.
    ///
    /// # Returns
    /// A result containing the decrypted data (`Vec<u8>`), or a `CryptError`.
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let sharedsecret = key.decap(&secret_key, &ciphertext)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (decrypted_data, _nonce) = self.cryptography()?;
        Ok(decrypted_data)
    }
}
