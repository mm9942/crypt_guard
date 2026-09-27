//! Legacy `CipherAesGcmSiv` symmetric cipher: AES-256-GCM-SIV AEAD with an
//! outer HMAC-SHA512 tag.
//!
//! [`CipherAesGcmSiv`](crate::cryptography::CipherAesGcmSiv) is compiled when
//! `aes-gcm-siv-cipher` or `legacy-pqclean` is active (see
//! `crates/core/src/core/mod.rs`). Its
//! [`CryptographicFunctions`](crate::core::CryptographicFunctions) impl, which
//! binds it to a Kyber KEM shared secret, additionally requires
//! `legacy-pqclean`. This is part of the pre-v3 / CGv2 legacy API surface; new
//! code should use [`crypt_guard_core::pq_hpke`](crate::pq_hpke) instead,
//! since AES-256-GCM-SIV is a crypt_guard private extension there and is only
//! reachable through [`pq_hpke::HpkeEnvelope`](crate::pq_hpke::HpkeEnvelope).
//!
//! # Security
//! AES-256-GCM-SIV is itself an AEAD construction, nonce-misuse-resistant by
//! design. This module additionally prepends an HMAC-SHA512 tag (keyed with
//! the caller's passphrase) to the plaintext before encryption and verifies
//! it after decryption.
//!
//! # Examples
//! ```ignore
//! use crypt_guard_core::cryptography::{
//!     CipherAesGcmSiv, ContentType, CryptographicInformation, CryptographicMechanism,
//!     CryptographicMetadata, KeyEncapMechanism, Process,
//! };
//!
//! let infos = CryptographicInformation {
//!     content: message.as_bytes().to_owned(),
//!     passphrase: passphrase.as_bytes().to_vec(),
//!     metadata: CryptographicMetadata {
//!         process: Process::Encryption,
//!         encryption_type: CryptographicMechanism::AesGcmSiv,
//!         key_type: KeyEncapMechanism::kyber1024(),
//!         content_type: ContentType::RawData,
//!     },
//!     safe: false,
//!     location: None,
//! };
//! let mut cipher = CipherAesGcmSiv::new(infos, None);
//! let (encrypted, ciphertext) = cipher.encrypt(public_key)?;
//! let iv = cipher.iv();
//! ```
//use super::*;

//use crypt_guard_proc::{*, log_activity, write_log};
// `KeyControlVariant` (legacy Kyber KEM dispatch) only exists with `legacy-pqclean`;
// gate its import so this file compiles standalone under `aes-gcm-siv-cipher` alone.
#[cfg(feature = "legacy-pqclean")]
use crate::core::KeyControlVariant;
use crate::{
    cryptography::{
        hmac_sign::{Operation, Sign, SignType},
        *,
    },
    error::*,
    *,
};
use aes::cipher::generic_array::GenericArray;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use hex;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng};
use sha2::Sha256;
use std::result::Result;

/// Generates a 12-byte iv using OS-level randomness.
///
/// # Returns
/// A 24-byte array filled with secure random bytes.
pub fn generate_iv() -> [u8; 12] {
    OsRng.gen()
}

fn derive_legacy_aes_gcm_siv_key(sharedsecret: &[u8], iv: &[u8]) -> Result<[u8; 32], CryptError> {
    type HmacSha256 = Hmac<Sha256>;
    let mut extract =
        <HmacSha256 as Mac>::new_from_slice(iv).expect("HMAC-SHA256 accepts any key length");
    extract.update(sharedsecret);
    let prk = extract.finalize().into_bytes();

    let mut expand =
        <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC-SHA256 accepts any key length");
    expand.update(b"crypt_guard:legacy:aes-gcm-siv:key");
    expand.update(&[1]);
    let okm = expand.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    Ok(key)
}

/// The main struct for handling cryptographic operations with ChaCha20 algorithm.
/// It encapsulates the cryptographic information, shared secret, and iv required for encryption and decryption.
impl CipherAesGcmSiv {
    /// Constructs a new CipherChaCha instance with specified cryptographic information and an optional iv.
    ///
    /// # Parameters
    /// - infos: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    /// - iv: Optional hexadecimal string representation of the iv. If not provided, a iv will be generated.
    ///
    /// # Returns
    /// A new CipherChaCha instance.
    pub fn new(infos: CryptographicInformation, iv: Option<String>) -> Self {
        let iv: Vec<u8> = match iv {
            // A malformed IV (not hex, wrong length) must not panic: fall back to a
            // fresh random IV, so decryption fails authentication with an error.
            Some(iv) => match hex::decode(iv) {
                Ok(iv) if iv.len() == 12 => iv,
                _ => generate_iv().to_vec(),
            },
            None => generate_iv().to_vec(),
        };
        // println!("infos: {:?}", infos);
        CipherAesGcmSiv {
            infos,
            sharedsecret: Vec::new(),
            iv,
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

    /// Sets the iv for cryptographic operations.
    ///
    /// # Parameters
    /// - iv: A vector of bytes representing the iv.
    ///
    /// # Returns
    /// A reference to the set iv (&Vec<u8>).
    pub fn set_iv(&mut self, iv: Vec<u8>) -> &Vec<u8> {
        self.iv = iv;
        &self.iv
    }

    /// Retrieves the iv.
    ///
    /// # Returns
    /// A reference to the current iv (&Vec<u8>).
    pub fn iv(&self) -> &Vec<u8> {
        &self.iv
    }

    fn encryption(&self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let plaintext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let derived_key = derive_legacy_aes_gcm_siv_key(&self.sharedsecret, &self.iv)?;
        let key = GenericArray::from_slice(&derived_key);
        let cipher = Aes256GcmSiv::new(key);
        let iv = Nonce::from_slice(&self.iv);
        let mut hmac = Sign::new(
            plaintext.to_vec(),
            passphrase,
            Operation::Sign,
            SignType::Sha512,
        );
        let data = hmac.try_hmac()?;
        let encrypted = cipher
            .encrypt(iv, &*data)
            .map_err(|e| CryptError::new(e.to_string().as_str()))?;
        let iv = self.iv();
        Ok((encrypted, iv.to_owned()))
    }

    fn decryption(&self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let ciphertext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let iv = Nonce::from_slice(&self.iv);
        let derived_key = derive_legacy_aes_gcm_siv_key(&self.sharedsecret, &self.iv)?;
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&derived_key));
        let decrypted = match cipher.decrypt(iv, &*ciphertext.to_vec()) {
            Ok(decrypted) => decrypted,
            Err(_) => {
                let legacy_cipher = Aes256GcmSiv::new(GenericArray::from_slice(&self.sharedsecret));
                legacy_cipher
                    .decrypt(iv, &*ciphertext.to_vec())
                    .map_err(|e| CryptError::new(e.to_string().as_str()))?
            }
        };
        //println!("decrypted: {:?}", &decrypted);
        let mut hmac = Sign::new(
            decrypted.to_vec(),
            passphrase,
            Operation::Verify,
            SignType::Sha512,
        );
        let data = hmac.try_hmac()?;
        //println!("Verified: {:?}", &data);
        let iv = self.iv();
        Ok((data, iv.to_owned()))
    }
}

// The KEM-based `CryptographicFunctions` impl depends on `KeyControlVariant`
// (legacy Kyber key control), so it is only available under `legacy-pqclean`.
#[cfg(feature = "legacy-pqclean")]
impl CryptographicFunctions for CipherAesGcmSiv {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - public_key: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (Vec<u8>) and the key used, or a CryptError.
    /// Additionally, prints a message to stdout with the iv for user reference.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let (sharedsecret, ciphertext) = key.encap(&public_key)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (encrypted_data, iv) = self.encryption()?;
        println!("Please write down this iv: {}", hex::encode(iv));
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
        let (decrypted_data, _iv) = self.decryption()?;
        Ok(decrypted_data)
    }
}
