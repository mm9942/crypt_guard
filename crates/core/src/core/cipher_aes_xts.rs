//! Legacy `CipherAesXts` symmetric cipher: AES-256-XTS (via the `xts-mode`
//! crate's `Xts128`) with an HMAC-SHA512 tag.
//!
//! [`CipherAesXts`](crate::cryptography::CipherAesXts) is compiled behind the
//! `aes-xts` feature (see `crates/core/src/core/mod.rs`). Its
//! [`CryptographicFunctions`](crate::core::CryptographicFunctions) impl, which
//! binds it to a Kyber KEM shared secret, additionally requires
//! `legacy-pqclean`. This is part of the pre-v3 / CGv2 legacy API surface; new
//! code should use [`crypt_guard_core::pq_hpke`](crate::pq_hpke) instead.
//!
//! # Security
//! XTS is a tweakable narrow-block mode designed for encrypting fixed-size
//! blocks in place, such as disk sectors — it is a storage-encryption mode,
//! not a general-purpose AEAD, and provides no authentication of its own.
//! This module compensates by prepending an HMAC-SHA512 tag (keyed with the
//! caller's passphrase) to the plaintext before encryption and verifying it
//! after decryption. Prefer an AEAD cipher for new designs that are not
//! constrained to fixed-size in-place storage blocks.
//!
//! # Examples
//! ```ignore
//! use crypt_guard_core::cryptography::{
//!     CipherAesXts, ContentType, CryptographicInformation, CryptographicMechanism,
//!     CryptographicMetadata, KeyEncapMechanism, Process,
//! };
//!
//! let infos = CryptographicInformation {
//!     content: message.as_bytes().to_owned(),
//!     passphrase: passphrase.as_bytes().to_vec(),
//!     metadata: CryptographicMetadata {
//!         process: Process::Encryption,
//!         encryption_type: CryptographicMechanism::AesXts,
//!         key_type: KeyEncapMechanism::kyber1024(),
//!         content_type: ContentType::RawData,
//!     },
//!     safe: false,
//!     location: None,
//! };
//! let mut cipher = CipherAesXts::new(infos);
//! let (encrypted, ciphertext) = cipher.encrypt(public_key)?;
//! ```
//use super::*;

//use crypt_guard_proc::{*, log_activity, write_log};
// `KeyControlVariant` (legacy Kyber KEM dispatch) only exists with `legacy-pqclean`;
// gate its import so this file compiles standalone under `aes-xts` alone.
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
use aes::{cipher::generic_array::GenericArray, cipher::KeyInit, Aes256};
use std::result::Result;
use xts_mode::{get_tweak_default, Xts128};

/// XTS sector size used by the legacy cipher.
#[cfg_attr(not(feature = "legacy-pqclean"), allow(dead_code))]
const XTS_SECTOR_SIZE: usize = 0x200;

/// `xts-mode` panics when the area is shorter than one AES block or its last
/// (partial) sector is shorter than one block. Reject those lengths up front
/// so neither encryption nor decryption of hostile input can panic.
#[cfg_attr(not(feature = "legacy-pqclean"), allow(dead_code))]
fn check_xts_area_len(len: usize) -> Result<(), CryptError> {
    const BLOCK: usize = 16;
    let tail = len % XTS_SECTOR_SIZE;
    if len < BLOCK || (tail != 0 && tail < BLOCK) {
        return Err(CryptError::InvalidDataLength);
    }
    Ok(())
}

/// Legacy AES-256-XTS cipher with an HMAC-SHA512 tag over the plaintext.
/// It encapsulates the cryptographic information and shared secret required for encryption and decryption.
impl CipherAesXts {
    /// Constructs a new CipherChaCha instance with specified cryptographic information.
    ///
    /// # Parameters
    /// - infos: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    ///
    /// # Returns
    /// A new CipherChaCha instance.
    pub fn new(infos: CryptographicInformation) -> Self {
        // println!("infos: {:?}", infos);
        CipherAesXts {
            infos,
            sharedsecret: Vec::new(),
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

    /// Splits the 64-byte shared secret into the two AES-256 XTS keys.
    fn xts_keys(&self) -> Result<(&[u8], &[u8]), CryptError> {
        if self.sharedsecret.len() != 64 {
            return Err(CryptError::InvalidDataLength);
        }
        Ok(self.sharedsecret.split_at(32))
    }

    fn encryption(&self) -> Result<Vec<u8>, CryptError> {
        let plaintext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();

        let (key_1, key_2) = self.xts_keys()?;
        let cipher_1 = Aes256::new(GenericArray::from_slice(key_1));
        let cipher_2 = Aes256::new(GenericArray::from_slice(key_2));

        let cipher = Xts128::<Aes256>::new(cipher_1, cipher_2);

        let mut hmac = Sign::new(
            plaintext.to_vec(),
            passphrase,
            Operation::Sign,
            SignType::Sha512,
        );
        let mut data = hmac.try_hmac()?;
        check_xts_area_len(data.len())?;

        let sector_size = XTS_SECTOR_SIZE;
        let first_sector_index = 0;

        cipher.encrypt_area(
            &mut data,
            sector_size,
            first_sector_index,
            get_tweak_default,
        );

        Ok(data)
    }

    fn decryption(&self) -> Result<Vec<u8>, CryptError> {
        let mut buffer = self.infos.content()?.to_owned();
        let passphrase = self.infos.passphrase()?.to_vec();

        let (key_1, key_2) = self.xts_keys()?;
        let cipher_1 = Aes256::new(GenericArray::from_slice(key_1));
        let cipher_2 = Aes256::new(GenericArray::from_slice(key_2));

        let cipher = Xts128::<Aes256>::new(cipher_1, cipher_2);

        check_xts_area_len(buffer.len())?;
        let sector_size = XTS_SECTOR_SIZE;
        let first_sector_index = 0;

        cipher.decrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default)/*.map_err(|e| CryptError::new(e.to_string().as_str()))?*/;

        //println!("decrypted: {:?}", &decrypted);
        let mut hmac = Sign::new(
            buffer.to_vec(),
            passphrase,
            Operation::Verify,
            SignType::Sha512,
        );
        let data = hmac.try_hmac()?;
        //println!("Verified: {:?}", &data);
        Ok(data)
    }
}

// The KEM-based `CryptographicFunctions` impl depends on `KeyControlVariant`
// (legacy Kyber key control), so it is only available under `legacy-pqclean`.
#[cfg(feature = "legacy-pqclean")]
impl CryptographicFunctions for CipherAesXts {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - public_key: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (Vec<u8>) and the key used, or a CryptError.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);

        // Generate the first shared secret and ciphertext
        let (sharedsecret1, ciphertext1) = key.encap(&public_key)?;

        // Generate the second shared secret and ciphertext
        let (sharedsecret2, ciphertext2) = key.encap(&public_key)?;

        // Concatenate both shared secrets and ciphertexts
        let sharedsecret = [sharedsecret1.to_owned(), sharedsecret2.to_owned()].concat();
        let ciphertext = [ciphertext1.to_owned(), ciphertext2.to_owned()].concat();

        let _ = self.set_shared_secret(sharedsecret);
        // File mode: read the plaintext file, then persist `<file>.enc`.
        self.infos.load_file_content()?;
        let encrypted_data = self.encryption()?;
        self.infos.persist_file_output(&encrypted_data)?;
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

        let ciphertext_len = ciphertext.len() / 2;
        let ciphertext1 = ciphertext[..ciphertext_len].to_vec();
        let ciphertext2 = ciphertext[ciphertext_len..].to_vec();

        let sharedsecret1 = key.decap(&secret_key, &ciphertext1)?;
        let sharedsecret2 = key.decap(&secret_key, &ciphertext2)?;

        let sharedsecret = [sharedsecret1.to_owned(), sharedsecret2.to_owned()].concat();

        let _ = self.set_shared_secret(sharedsecret);
        self.infos.load_file_content()?;
        let decrypted_data = self.decryption()?;
        self.infos.persist_file_output(&decrypted_data)?;
        Ok(decrypted_data)
    }
}
