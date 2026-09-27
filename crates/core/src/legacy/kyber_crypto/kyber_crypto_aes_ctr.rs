//! Legacy Kyber + AES-CTR (stream mode, unauthenticated) cipher glue for the
//! pqcrypto-backed `Kyber` typestate.
//!
//! This implements the crate-local `KyberFunctions` trait for
//! `Kyber<Encryption, KyberSize, ContentStatus, AesCtr>`, wiring the legacy Kyber KEM key
//! material into [`CipherAesCtr`](crate::cryptography::CipherAesCtr) for messages,
//! in-memory data and files. It is part of the `legacy-pqclean` migration path described
//! in `crates/core/src/legacy/mod.rs`: the underlying `pqcrypto-kyber` / `pqcrypto-traits`
//! crates wrap PQClean, which is unmaintained and being archived (see `SECURITY.md`).
//! New code should use [`crypt_guard_core::pq_hpke`](crate::pq_hpke) instead of this
//! module.
//!
//! # Security
//! AES-CTR itself is not an AEAD mode, and reusing an IV/counter with the same key breaks confidentiality.
//! The legacy cipher wrapper adds an HMAC-SHA512 tag over the plaintext before
//! encrypting and verifies it after decrypting (MAC-then-encrypt). That gives
//! integrity checking, but it is a non-standard construction; do not use it for
//! new designs, use `crypt_guard_core::pq_hpke` instead.
//!
//! # Examples
//! ```ignore
//! use crypt_guard_core::core::kyber::*;
//!
//! let (public_key, secret_key) = KeyControKyber1024::keypair()?;
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AesCtr>::new(public_key, None)?;
//! let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), "Test Passphrase")?;
//!
//! let nonce = encryptor.get_nonce();
//! let decryptor = Kyber::<Decryption, Kyber1024, Data, AesCtr>::new(secret_key, Some(nonce?.to_string()))?;
//! let decrypt_message = decryptor.decrypt_data(encrypt_message, "Test Passphrase", cipher)?;
//! ```
use crate::{
    core::CryptographicFunctions,
    cryptography::{
        CipherAesCtr, ContentType, CryptographicInformation, CryptographicMechanism,
        CryptographicMetadata, KeyEncapMechanism, Process,
    },
    error::CryptError,
    key_control::FileMetadata,
    *,
};
use std::{
    path::{Path, PathBuf},
    result::Result,
};

/// Provides Kyber encryption functions for AES-CTR algorithm.
impl<KyberSize, ContentStatus> KyberFunctions
    for Kyber<Encryption, KyberSize, ContentStatus, AesCtr>
where
    KyberSize: KyberSizeVariant,
{
    /// Encrypts a file with AES-CTR algorithm, given a path and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_file(
        &mut self,
        path: PathBuf,
        passphrase: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        if !Path::new(&path).exists() {
            return Err(CryptError::FileNotFound);
        }

        let (key_encap_mechanism, _kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => (KeyEncapMechanism::kyber512(), 512_usize),
            KyberVariant::Kyber768 => (KeyEncapMechanism::kyber768(), 768_usize),
            KyberVariant::Kyber1024 => (KeyEncapMechanism::kyber1024(), 1024_usize),
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Encryption,
            encryption_type: CryptographicMechanism::AesCtr,
            key_type: key_encap_mechanism,
            content_type: ContentType::File,
        };

        let file = FileMetadata::from(path.to_owned(), FileTypes::Other, FileState::NotEncrypted);

        let infos = CryptographicInformation {
            content: Vec::new(),
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: true,
            location: Some(file),
        };

        let mut aes_gcm_siv = CipherAesCtr::new(infos, None);

        let _ = self.kyber_data.set_nonce(hex::encode(aes_gcm_siv.iv()));
        let (data, cipher) = aes_gcm_siv.encrypt(self.kyber_data.key()?)?;
        Ok((data, cipher))
    }

    /// Encrypts a message with AES-CTR algorithm, given the message and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_msg(
        &mut self,
        message: &str,
        passphrase: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let (key_encap_mechanism, _kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => (KeyEncapMechanism::kyber512(), 512_usize),
            KyberVariant::Kyber768 => (KeyEncapMechanism::kyber768(), 768_usize),
            KyberVariant::Kyber1024 => (KeyEncapMechanism::kyber1024(), 1024_usize),
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Encryption,
            encryption_type: CryptographicMechanism::AesCtr,
            key_type: key_encap_mechanism,
            content_type: ContentType::Message,
        };

        let infos = CryptographicInformation {
            content: message.as_bytes().to_vec(),
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: false,
            location: None,
        };

        let mut aes_gcm_siv = CipherAesCtr::new(infos, None);

        let _ = self.kyber_data.set_nonce(hex::encode(aes_gcm_siv.iv()));

        let (data, cipher) = aes_gcm_siv.encrypt(self.kyber_data.key()?)?;
        Ok((data, cipher))
    }

    /// Encrypts data with AES-CTR algorithm, given the data and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_data(
        &mut self,
        data: Vec<u8>,
        passphrase: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let (key_encap_mechanism, _kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => (KeyEncapMechanism::kyber512(), 512_usize),
            KyberVariant::Kyber768 => (KeyEncapMechanism::kyber768(), 768_usize),
            KyberVariant::Kyber1024 => (KeyEncapMechanism::kyber1024(), 1024_usize),
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Encryption,
            encryption_type: CryptographicMechanism::AesCtr,
            key_type: key_encap_mechanism,
            content_type: ContentType::RawData, // Using File here for generic data
        };

        let infos = CryptographicInformation {
            content: data,
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: false,
            location: None,
        };

        let mut aes_gcm_siv = CipherAesCtr::new(infos, None);

        let _ = self.kyber_data.set_nonce(hex::encode(aes_gcm_siv.iv()));
        let (data, cipher) = aes_gcm_siv.encrypt(self.kyber_data.key()?)?;
        Ok((data, cipher))
    }

    /// Placeholder for decrypt_file, indicating operation not allowed in encryption mode.
    fn decrypt_file(
        &self,
        _path: PathBuf,
        _passphrase: &str,
        _ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of files isn't allowed!"))
    }
    /// Placeholder for decrypt_msg, indicating operation not allowed in encryption mode.
    fn decrypt_msg(
        &self,
        _message: Vec<u8>,
        _passphrase: &str,
        _ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }
    /// Placeholder for decrypt_data, indicating operation not allowed in encryption mode.
    fn decrypt_data(
        &self,
        _data: Vec<u8>,
        _passphrase: &str,
        _ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of data isn't allowed!"))
    }
}
impl<KyberSize, ContentStatus> KyberFunctions
    for Kyber<Decryption, KyberSize, ContentStatus, AesCtr>
where
    KyberSize: KyberSizeVariant,
{
    /// Placeholder for encrypt_file, indicating operation not allowed in decryption mode.
    fn encrypt_file(
        &mut self,
        _path: PathBuf,
        _passphrase: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of files isn't allowed!"))
    }
    /// Placeholder for encrypt_msg, indicating operation not allowed in decryption mode.
    fn encrypt_msg(
        &mut self,
        _message: &str,
        _passphrase: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }
    /// Placeholder for encrypt_data, indicating operation not allowed in decryption mode.
    fn encrypt_data(
        &mut self,
        _data: Vec<u8>,
        _passphrase: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }

    /// Decrypts a file with AES-CBC algorithm, given a path, passphrase, and cipherteGCM-SIV
    /// Returns the decrypted data.
    fn decrypt_file(
        &self,
        path: PathBuf,
        passphrase: &str,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptError> {
        if !Path::new(&path).exists() {
            return Err(CryptError::FileNotFound);
        }

        let (key_encap_mechanism, _kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => (KeyEncapMechanism::kyber512(), 512_usize),
            KyberVariant::Kyber768 => (KeyEncapMechanism::kyber768(), 768_usize),
            KyberVariant::Kyber1024 => (KeyEncapMechanism::kyber1024(), 1024_usize),
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Decryption,
            encryption_type: CryptographicMechanism::AesCtr,
            key_type: key_encap_mechanism,
            content_type: ContentType::File,
        };

        let file = FileMetadata::from(path.to_owned(), FileTypes::Other, FileState::Encrypted);

        let infos = CryptographicInformation {
            content: Vec::new(),
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: true,
            location: Some(file),
        };

        let mut aes_gcm_siv = CipherAesCtr::new(
            infos,
            Some(super::checked_nonce(self.kyber_data.nonce()?, 16)?),
        );

        let data = aes_gcm_siv.decrypt(self.kyber_data.key()?, ciphertext)?;
        Ok(data)
    }

    /// Decrypts a message with AES-CBC algorithm, given the message, passphrase, and cipherteGCM-SIV
    /// Returns the decrypted data.
    fn decrypt_msg(
        &self,
        message: Vec<u8>,
        passphrase: &str,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptError> {
        let (key_encap_mechanism, _kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => (KeyEncapMechanism::kyber512(), 512_usize),
            KyberVariant::Kyber768 => (KeyEncapMechanism::kyber768(), 768_usize),
            KyberVariant::Kyber1024 => (KeyEncapMechanism::kyber1024(), 1024_usize),
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Decryption,
            encryption_type: CryptographicMechanism::AesCtr,
            key_type: key_encap_mechanism,
            content_type: ContentType::Message,
        };

        let infos = CryptographicInformation {
            content: message,
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: false,
            location: None,
        };

        let mut aes_gcm_siv = CipherAesCtr::new(
            infos,
            Some(super::checked_nonce(self.kyber_data.nonce()?, 16)?),
        );

        let data = aes_gcm_siv.decrypt(self.kyber_data.key()?, ciphertext)?;
        Ok(data)
    }

    /// Decrypts data with AES-CTR algorithm, given the data, passphrase, and ciphertext.
    /// Returns the decrypted data.
    fn decrypt_data(
        &self,
        data: Vec<u8>,
        passphrase: &str,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptError> {
        let (key_encap_mechanism, _kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => (KeyEncapMechanism::kyber512(), 512_usize),
            KyberVariant::Kyber768 => (KeyEncapMechanism::kyber768(), 768_usize),
            KyberVariant::Kyber1024 => (KeyEncapMechanism::kyber1024(), 1024_usize),
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Decryption,
            encryption_type: CryptographicMechanism::AesCtr,
            key_type: key_encap_mechanism,
            content_type: ContentType::File, // Using File here for generic data
        };

        let infos = CryptographicInformation {
            content: data,
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: false,
            location: None,
        };

        let mut aes_gcm_siv = CipherAesCtr::new(
            infos,
            Some(super::checked_nonce(self.kyber_data.nonce()?, 16)?),
        );

        let data = aes_gcm_siv.decrypt(self.kyber_data.key()?, ciphertext)?;
        Ok(data)
    }
}
