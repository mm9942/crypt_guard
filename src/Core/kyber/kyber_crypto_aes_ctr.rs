use super::*;
use crate::{
    cryptography::{CipherAES_CTR, CryptographicInformation, CryptographicMetadata, ContentType, Process, CryptographicMechanism, KeyEncapMechanism},
    error::CryptError,
    Core::CryptographicFunctions,
    KeyControl::FileMetadata,
};
use std::{
    path::{Path, PathBuf},
    result::Result,
};

/// Provides Kyber encryption functions for AES-CTR algorithm.
impl<KyberSize, ContentStatus> KyberFunctions for Kyber<Encryption, KyberSize, ContentStatus, AES_CTR>
where
    KyberSize: KyberSizeVariant,
{   
    /// Encrypts a file with AES-CTR algorithm, given a path and a passphrase.
    /// Returns the encrypted data and cipher.
     fn encrypt_file(&mut self, path: PathBuf, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        if !Path::new(&path).exists() {
            return Err(CryptError::FileNotFound);
        }

        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Encryption,
            encryption_type: CryptographicMechanism::AES_CTR,
            key_type: key_encap_mechanism,
            content_type: ContentType::File,
        };

        let file = FileMetadata::from(path.clone(), FileTypes::Other, FileState::NotEncrypted);

        let infos = CryptographicInformation {
            content: Vec::new(),
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: true,
            location: Some(file),
        };

        let mut aes_gcm_siv = CipherAES_CTR::new(infos, None);

        let _ = self.kyber_data.set_nonce(hex::encode(aes_gcm_siv.iv()));
        let (data, cipher) = aes_gcm_siv.encrypt(self.kyber_data.key()?)?;
        println!("{:?}", &data);
        Ok((data, cipher))
    }

    /// Encrypts a message with AES-CTR algorithm, given the message and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_msg(&mut self, message: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Encryption,
            encryption_type: CryptographicMechanism::AES_CTR,
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

        let mut aes_gcm_siv = CipherAES_CTR::new(infos, None);

        let _ = self.kyber_data.set_nonce(hex::encode(aes_gcm_siv.iv()));

        let (data, cipher) = aes_gcm_siv.encrypt(self.kyber_data.key()?)?;
        println!("{:?}", &data);
        Ok((data, cipher))
    }


    /// Encrypts data with AES-CTR algorithm, given the data and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_data(&mut self, data: Vec<u8>, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Encryption,
            encryption_type: CryptographicMechanism::AES_CTR,
            key_type: KeyEncapMechanism::kyber1024(),
            content_type: ContentType::RawData, // Using File here for generic data
        };

        let infos = CryptographicInformation {
            content: data,
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: false,
            location: None,
        };

        let mut aes_gcm_siv = CipherAES_CTR::new(infos, None);

        let _ = self.kyber_data.set_nonce(hex::encode(aes_gcm_siv.iv()));
        let (data, cipher) = aes_gcm_siv.encrypt(self.kyber_data.key()?)?;
        println!("{:?}", &data);
        Ok((data, cipher))
    }

    /// Placeholder for decrypt_file, indicating operation not allowed in encryption mode.
    fn decrypt_file(&self, _path: PathBuf, _passphrase: &str, _ciphertext:Vec<u8>) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of files isn't allowed!"))
    }
    /// Placeholder for decrypt_msg, indicating operation not allowed in encryption mode.
    fn decrypt_msg(&self, _message: Vec<u8>, _passphrase: &str, _ciphertext:Vec<u8>) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }
    /// Placeholder for decrypt_data, indicating operation not allowed in encryption mode.
    fn decrypt_data(&self, _data: Vec<u8>, _passphrase: &str, _ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of data isn't allowed!"))
    }
}
impl<KyberSize, ContentStatus> KyberFunctions for Kyber<Decryption, KyberSize, ContentStatus, AES_CTR>
where
    KyberSize: KyberSizeVariant,
{   
    /// Placeholder for encrypt_file, indicating operation not allowed in decryption mode.
    fn encrypt_file(&mut self, _path: PathBuf, _passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of files isn't allowed!"))
    }
    /// Placeholder for encrypt_msg, indicating operation not allowed in decryption mode.
    fn encrypt_msg(&mut self, _message: &str, _passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }
    /// Placeholder for encrypt_data, indicating operation not allowed in decryption mode.
    fn encrypt_data(&mut self, _data: Vec<u8>, _passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }

    /// Decrypts a file with AES-CBC algorithm, given a path, passphrase, and cipherteGCM-SIV
    /// Returns the decrypted data.
    fn decrypt_file(&self, path: PathBuf, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        if !Path::new(&path).exists() {
            return Err(CryptError::FileNotFound);
        }

        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Decryption,
            encryption_type: CryptographicMechanism::AES_CTR,
            key_type: key_encap_mechanism,
            content_type: ContentType::File,
        };

        let file = FileMetadata::from(path.clone(), FileTypes::Other, FileState::Encrypted);

        let infos = CryptographicInformation {
            content: Vec::new(),
            passphrase: passphrase.as_bytes().to_vec(),
            metadata: crypt_metadata,
            safe: true,
            location: Some(file),
        };

        let mut aes_gcm_siv = CipherAES_CTR::new(infos, Some(self.kyber_data.nonce()?.to_string()));

        let data = aes_gcm_siv.decrypt(self.kyber_data.key()?, ciphertext)?;
        println!("{:?}", &data);
        Ok(data)
    }

    /// Decrypts a message with AES-CBC algorithm, given the message, passphrase, and cipherteGCM-SIV
    /// Returns the decrypted data.
    fn decrypt_msg(&self, message: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Decryption,
            encryption_type: CryptographicMechanism::AES_CTR,
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

        let mut aes_gcm_siv = CipherAES_CTR::new(infos, Some(self.kyber_data.nonce()?.to_string()));

        let data = aes_gcm_siv.decrypt(self.kyber_data.key()?, ciphertext)?;
        println!("{:?}", &data);
        Ok(data)
    }

    /// Decrypts data with AES-CTR algorithm, given the data, passphrase, and ciphertext.
    /// Returns the decrypted data.
    fn decrypt_data(&self, data: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };

        let crypt_metadata = CryptographicMetadata {
            process: Process::Decryption,
            encryption_type: CryptographicMechanism::AES_CTR,
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

        let mut aes_gcm_siv = CipherAES_CTR::new(infos, Some(self.kyber_data.nonce()?.to_string()));

        let data = aes_gcm_siv.decrypt(self.kyber_data.key()?, ciphertext)?;
        println!("{:?}", &data);
        Ok(data)
    }
}