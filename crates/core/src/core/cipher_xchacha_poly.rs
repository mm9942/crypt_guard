//! Legacy `CipherChaChaPoly` symmetric cipher: XChaCha20-Poly1305 AEAD with an
//! outer HMAC-SHA512 tag.
//!
//! [`CipherChaChaPoly`](crate::cryptography::CipherChaChaPoly) wraps the
//! `chacha20poly1305` crate's XChaCha20-Poly1305 implementation. Its `new`,
//! `encryption`/`decryption` helpers and nonce generation are unconditionally
//! compiled (see `crates/core/src/core/mod.rs`), while the
//! [`CryptographicFunctions`] impl that binds it to a Kyber KEM shared secret
//! is gated behind the `legacy-pqclean` feature. This is part of the pre-v3 /
//! CGv2 legacy API surface; new code should use
//! [`crypt_guard_core::pq_hpke`](crate::pq_hpke) instead.
//!
//! # Security
//! XChaCha20-Poly1305 is itself an AEAD construction. This module additionally
//! prepends an HMAC-SHA512 tag (keyed with the caller's passphrase) to the
//! plaintext before encryption and verifies it after decryption, so integrity
//! is checked twice: once by Poly1305 over the ciphertext, once by the
//! passphrase-keyed HMAC over the plaintext.
//!
//! # Examples
//! ```ignore
//! use crypt_guard_core::cryptography::{
//!     CipherChaChaPoly, ContentType, CryptographicInformation, CryptographicMechanism,
//!     CryptographicMetadata, KeyEncapMechanism, Process,
//! };
//!
//! let infos = CryptographicInformation {
//!     content: message.as_bytes().to_owned(),
//!     passphrase: passphrase.as_bytes().to_vec(),
//!     metadata: CryptographicMetadata {
//!         process: Process::Encryption,
//!         encryption_type: CryptographicMechanism::XChaCha20Poly1305,
//!         key_type: KeyEncapMechanism::kyber1024(),
//!         content_type: ContentType::RawData,
//!     },
//!     safe: false,
//!     location: None,
//! };
//! let mut cipher = CipherChaChaPoly::new(infos, None);
//! let (encrypted, ciphertext) = cipher.encrypt(public_key)?;
//! ```
//use crypt_guard_proc::{*, log_actnonceity, write_log};
#[cfg(feature = "legacy-pqclean")]
use crate::core::{CryptographicFunctions, KeyControlVariant};
use crate::{
    cryptography::{
        hmac_sign::{Operation, Sign, SignType},
        *,
    },
    error::CryptError,
};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hex;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng};
use sha2::Sha256;
use std::result::Result;

/// Generates a 24-byte nonce using OS-level randomness.
///
/// # Returns
/// A 24-byte array filled with secure random bytes.
pub fn generate_nonce() -> [u8; 24] {
    OsRng.gen()
}

fn derive_legacy_xchacha_poly_key(
    sharedsecret: &[u8],
    nonce: &[u8; 24],
) -> Result<[u8; 32], CryptError> {
    type HmacSha256 = Hmac<Sha256>;
    let mut extract =
        <HmacSha256 as Mac>::new_from_slice(nonce).expect("HMAC-SHA256 accepts any key length");
    extract.update(sharedsecret);
    let prk = extract.finalize().into_bytes();

    let mut expand =
        <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC-SHA256 accepts any key length");
    expand.update(b"crypt_guard:legacy:xchacha20poly1305:key");
    expand.update(&[1]);
    let okm = expand.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    Ok(key)
}

/// The main struct for handling cryptographic operations with ChaCha20 algorithm.
/// It encapsulates the cryptographic information, shared secret, and nonce required for encryption and decryption.
impl CipherChaChaPoly {
    /// Constructs a new CipherChaCha instance with specified cryptographic information and an optional nonce.
    ///
    /// # Parameters
    /// - infos: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    /// - nonce: Optional hexadecimal string representation of the nonce. If not provided, a nonce will be generated.
    ///
    /// # Returns
    /// A new CipherChaCha instance.
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
        CipherChaChaPoly {
            infos,
            sharedsecret: Vec::new(),
            nonce,
        }
    }

    /// Retrieves the encrypted or decrypted data stored within the CryptographicInformation.
    ///
    /// # Returns
    /// A result containing the data as a vector of bytes (Vec<u8>) or a CryptError.
    pub fn get_data(&self) -> Result<Vec<u8>, CryptError> {
        let data = &self.infos.content()?;
        let data = data.to_vec();

        Ok(data)
    }

    /// Sets the shared secret for the cryptographic operation.
    ///
    /// # Parameters
    /// - sharedsecret: A vector of bytes (Vec<u8>) representing the shared secret.
    ///
    /// # Returns
    /// A reference to the CipherChaCha instance to allow method chaining.
    pub fn set_shared_secret(&mut self, sharedsecret: Vec<u8>) -> &Self {
        use zeroize::Zeroize;
        self.sharedsecret.zeroize();
        self.sharedsecret = sharedsecret;
        self
    }

    /// Retrieves the shared secret.
    ///
    /// # Returns
    /// A result containing a slice of the shared secret (&[u8]) or a CryptError.    
    pub fn sharedsecret(&self) -> Result<&[u8], CryptError> {
        Ok(&self.sharedsecret)
    }

    /// Sets the nonce for cryptographic operations.
    ///
    /// # Parameters
    /// - nonce: A fixed-size array of bytes representing the nonce.
    ///
    /// # Returns
    /// A reference to the set nonce (&[u8; 24]).
    pub fn set_nonce(&mut self, nonce: [u8; 24]) -> &[u8; 24] {
        self.nonce = nonce;
        &self.nonce
    }

    /// Retrieves the nonce.
    ///
    /// # Returns
    /// A reference to the current nonce (&[u8; 24]).
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    // Legacy tuple-return XChaCha20Poly1305 path; kept for source compatibility,
    // not reached from the default envelope API.
    #[allow(dead_code)]
    fn encryption(&self) -> Result<(Vec<u8>, [u8; 24]), CryptError> {
        let plaintext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let derived_key = derive_legacy_xchacha_poly_key(&self.sharedsecret, &self.nonce)?;
        let key = GenericArray::from_slice(&derived_key);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XNonce::from_slice(&self.nonce);
        let mut hmac = Sign::new(
            plaintext.to_vec(),
            passphrase,
            Operation::Sign,
            SignType::Sha512,
        );
        let data = hmac.try_hmac()?;
        let encrypted = cipher
            .encrypt(nonce, &*data)
            .map_err(|e| CryptError::new(e.to_string().as_str()))?;
        let nonce = *self.nonce();
        Ok((encrypted, nonce))
    }

    #[allow(dead_code)]
    fn decryption(&self) -> Result<(Vec<u8>, [u8; 24]), CryptError> {
        let ciphertext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let nonce = XNonce::from_slice(&self.nonce);
        let derived_key = derive_legacy_xchacha_poly_key(&self.sharedsecret, &self.nonce)?;
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&derived_key));
        let decrypted = match cipher.decrypt(nonce, &*ciphertext.to_vec()) {
            Ok(decrypted) => decrypted,
            Err(_) => {
                let legacy_cipher =
                    XChaCha20Poly1305::new(GenericArray::from_slice(&self.sharedsecret));
                legacy_cipher
                    .decrypt(nonce, &*ciphertext.to_vec())
                    .map_err(|e| CryptError::new(e.to_string().as_str()))?
            }
        };
        let mut hmac = Sign::new(
            decrypted.to_vec(),
            passphrase,
            Operation::Verify,
            SignType::Sha512,
        );
        let data = hmac.try_hmac()?;
        let nonce = *self.nonce();
        Ok((data, nonce))
    }
}

#[cfg(feature = "legacy-pqclean")]
impl CryptographicFunctions for CipherChaChaPoly {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - public_key: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (Vec<u8>) and the key used, or a CryptError.
    /// Additionally, prints a message to stdout with the nonce for user reference.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let (sharedsecret, ciphertext) = key.encap(&public_key)?;
        let _ = self.set_shared_secret(sharedsecret);
        // File mode: read the plaintext file, then persist `<file>.enc`.
        self.infos.load_file_content()?;
        let (encrypted_data, nonce) = self.encryption()?;
        self.infos.persist_file_output(&encrypted_data)?;
        println!("Please write down this nonce: {}", hex::encode(nonce));
        Ok((encrypted_data, ciphertext))
    }

    /// Decrypts the provided data using the secret key and ciphertext.
    ///
    /// # Parameters
    /// - secret_key: The secret key used for decryption.
    /// - ciphertext: The ciphertext to decrypt.
    ///
    /// # Returns
    /// A result containing the decrypted data (Vec<u8>), or a CryptError.
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let sharedsecret = key.decap(&secret_key, &ciphertext)?;
        let _ = self.set_shared_secret(sharedsecret);
        self.infos.load_file_content()?;
        let (decrypted_data, _nonce) = self.decryption()?;
        self.infos.persist_file_output(&decrypted_data)?;
        Ok(decrypted_data)
    }
}
