/// The `hmac` module provides functionality for generating, managing, and verifying digital hmacs, supporting various algorithms including post-quantum secure schemes.
pub mod hmac_sign;

/// The `cryptographic` module encapsulates core cryptographic operations, including key management, encryption, decryption, and cryptographic utility functions.
mod cryptographic;

use crate::{error::CryptError, FileMetadata};
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Represents the AES cipher for encryption and decryption processes.
/// It holds cryptographic information and a shared secret for operations.
#[derive(PartialEq, Clone)]
pub struct CipherAES {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
}

impl Drop for CipherAES {
    fn drop(&mut self) {
        self.sharedsecret.zeroize();
    }
}

impl fmt::Debug for CipherAES {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherAES")
            .field("infos", &self.infos)
            .field(
                "sharedsecret",
                &format_args!("<redacted {} bytes>", self.sharedsecret.len()),
            )
            .finish()
    }
}

impl fmt::Display for CipherAES {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CipherAES with the following Cryptographic Informations: {}",
            self.infos.metadata
        )
    }
}

#[derive(PartialEq, Clone)]
pub struct CipherAesGcmSiv {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
    pub iv: Vec<u8>,
}

impl Drop for CipherAesGcmSiv {
    fn drop(&mut self) {
        self.sharedsecret.zeroize();
    }
}

impl fmt::Debug for CipherAesGcmSiv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherAesGcmSiv")
            .field("infos", &self.infos)
            .field(
                "sharedsecret",
                &format_args!("<redacted {} bytes>", self.sharedsecret.len()),
            )
            .field("iv", &self.iv)
            .finish()
    }
}

impl fmt::Display for CipherAesGcmSiv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CipherAesGcmSiv with the following Cryptographic Informations: {}",
            self.infos.metadata
        )
    }
}

#[derive(PartialEq, Clone)]
pub struct CipherAesCtr {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
    pub iv: Vec<u8>,
}

impl Drop for CipherAesCtr {
    fn drop(&mut self) {
        self.sharedsecret.zeroize();
    }
}

impl fmt::Debug for CipherAesCtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherAesCtr")
            .field("infos", &self.infos)
            .field(
                "sharedsecret",
                &format_args!("<redacted {} bytes>", self.sharedsecret.len()),
            )
            .field("iv", &self.iv)
            .finish()
    }
}

impl fmt::Display for CipherAesCtr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CipherAesCtr with the following Cryptographic Informations: {}",
            self.infos.metadata
        )
    }
}

#[derive(PartialEq, Clone)]
pub struct CipherAesXts {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
}

impl Drop for CipherAesXts {
    fn drop(&mut self) {
        self.sharedsecret.zeroize();
    }
}

impl fmt::Debug for CipherAesXts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherAesXts")
            .field("infos", &self.infos)
            .field(
                "sharedsecret",
                &format_args!("<redacted {} bytes>", self.sharedsecret.len()),
            )
            .finish()
    }
}

impl fmt::Display for CipherAesXts {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CipherAesXts with the following Cryptographic Informations: {}",
            self.infos.metadata
        )
    }
}

/// Represents the XChaCha20 cipher for encryption and decryption processes.
/// It includes cryptographic information, a nonce for the operation, and a shared secret.
#[derive(PartialEq, Clone)]
pub struct CipherChaCha {
    pub infos: CryptographicInformation,
    pub nonce: [u8; 24],
    pub sharedsecret: Vec<u8>,
}

impl Drop for CipherChaCha {
    fn drop(&mut self) {
        self.sharedsecret.zeroize();
    }
}

impl fmt::Debug for CipherChaCha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherChaCha")
            .field("infos", &self.infos)
            .field("nonce", &self.nonce)
            .field(
                "sharedsecret",
                &format_args!("<redacted {} bytes>", self.sharedsecret.len()),
            )
            .finish()
    }
}

impl fmt::Display for CipherChaCha {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CipherChaCha with the following Cryptographic Informations {}",
            self.infos.metadata
        )
    }
}

/// Represents the XChaCha20Poly1305 cipher for encryption and decryption processes.
/// It includes cryptographic information, a nonce for the operation, and a shared secret.
#[derive(PartialEq, Clone)]
pub struct CipherChaChaPoly {
    pub infos: CryptographicInformation,
    pub nonce: [u8; 24],
    pub sharedsecret: Vec<u8>,
}

impl Drop for CipherChaChaPoly {
    fn drop(&mut self) {
        self.sharedsecret.zeroize();
    }
}

impl fmt::Debug for CipherChaChaPoly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherChaChaPoly")
            .field("infos", &self.infos)
            .field("nonce", &self.nonce)
            .field(
                "sharedsecret",
                &format_args!("<redacted {} bytes>", self.sharedsecret.len()),
            )
            .finish()
    }
}

impl fmt::Display for CipherChaChaPoly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CipherChaCha with the following Cryptographic Informations {}",
            self.infos.metadata
        )
    }
}

/// Enumerates the cryptographic mechanisms supported, such as AES and XChaCha20.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum CryptographicMechanism {
    AES,
    AesGcmSiv,
    AesCtr,
    AesXts,
    XChaCha20Poly1305,
    XChaCha20,
}

impl fmt::Display for CryptographicMechanism {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mechanism = match self {
            CryptographicMechanism::AES => "AES",
            CryptographicMechanism::AesGcmSiv => "AES-GCM-SIV",
            CryptographicMechanism::AesCtr => "AES-CTR",
            CryptographicMechanism::AesXts => "AES-XTS",
            CryptographicMechanism::XChaCha20Poly1305 => "XChaCha20Poly1305",
            CryptographicMechanism::XChaCha20 => "XChaCha20",
        };
        write!(f, "{}", mechanism)
    }
}

/// Enumerates the key encapsulation mechanisms supported, such as Kyber1024.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum KeyEncapMechanism {
    Kyber1024,
    Kyber768,
    Kyber512,
}

impl fmt::Display for KeyEncapMechanism {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mechanism = match self {
            KeyEncapMechanism::Kyber1024 => "Kyber1024",
            KeyEncapMechanism::Kyber768 => "Kyber768",
            KeyEncapMechanism::Kyber512 => "Kyber512",
        };
        write!(f, "{}", mechanism)
    }
}

/// Enumerates the types of content that can be encrypted or decrypted, such as messages or files.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ContentType {
    Message,
    File,
    RawData,
    Device,
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let content_type = match self {
            ContentType::Message => "Message",
            ContentType::File => "File",
            ContentType::RawData => "RawData",
            ContentType::Device => "Device",
        };
        write!(f, "{}", content_type)
    }
}

/// Enumerates the cryptographic processes, such as encryption and decryption.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Process {
    Encryption,
    Decryption,
}

impl fmt::Display for Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let process = match self {
            Process::Encryption => "Encryption",
            Process::Decryption => "Decryption",
        };
        write!(f, "{}", process)
    }
}

/// Holds metadata for cryptographic operations, specifying the process, encryption type,
/// key encapsulation mechanism, and content type.
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct CryptographicMetadata {
    pub process: Process,
    pub encryption_type: CryptographicMechanism,
    pub key_type: KeyEncapMechanism,
    pub content_type: ContentType,
}

impl fmt::Display for CryptographicMetadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Process: {}\nEncryption Type: {}\nKey Type: {}\nContent Type: {}",
            self.process, self.encryption_type, self.key_type, self.content_type
        )
    }
}

/// Contains information necessary for performing cryptographic operations, including the content
/// to be encrypted or decrypted, a passphrase, metadata defining the operation context, and a flag
/// indicating whether the content should be saved securely.
#[derive(PartialEq, Clone)]
pub struct CryptographicInformation {
    pub content: Vec<u8>,
    pub passphrase: Vec<u8>,
    pub metadata: CryptographicMetadata,
    pub safe: bool,
    pub location: Option<FileMetadata>,
}

/// Manual `Debug` impl that redacts `content` and `passphrase`, both of which
/// may hold plaintext or key material, showing only their lengths.
impl fmt::Debug for CryptographicInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptographicInformation")
            .field(
                "content",
                &format_args!("<redacted {} bytes>", self.content.len()),
            )
            .field(
                "passphrase",
                &format_args!("<redacted {} bytes>", self.passphrase.len()),
            )
            .field("metadata", &self.metadata)
            .field("safe", &self.safe)
            .field("location", &self.location)
            .finish()
    }
}

impl Drop for CryptographicInformation {
    /// Wipes the secret-bearing fields when the value is dropped.
    ///
    /// `content` (plaintext on the encrypt side) and `passphrase` are zeroized
    /// so that neither lingers in freed heap memory. Non-secret metadata is left
    /// untouched.
    fn drop(&mut self) {
        self.content.zeroize();
        self.passphrase.zeroize();
    }
}

impl fmt::Display for CryptographicInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Cryptographic Information:\n\
                   -\tMetadata:\t\t{}\n\
                   -\tContent Length:\t{} bytes\n",
            self.metadata,
            self.content.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xCA, 0xFE];

    fn info(content: Vec<u8>, passphrase: Vec<u8>) -> CryptographicInformation {
        CryptographicInformation {
            content,
            passphrase,
            metadata: CryptographicMetadata {
                process: Process::Encryption,
                encryption_type: CryptographicMechanism::AES,
                key_type: KeyEncapMechanism::Kyber1024,
                content_type: ContentType::Message,
            },
            safe: false,
            location: None,
        }
    }

    #[test]
    fn cryptographic_information_debug_redacts_secrets() {
        let infos = info(MARKER.to_vec(), MARKER.to_vec());
        let debug_str = format!("{:?}", infos);
        assert!(!debug_str.contains(&format!("{:?}", MARKER.to_vec())));
        assert!(debug_str.contains("redacted"));
    }

    #[test]
    fn cipher_aes_debug_redacts_sharedsecret() {
        let cipher = CipherAES {
            infos: info(vec![1, 2, 3], vec![4, 5, 6]),
            sharedsecret: MARKER.to_vec(),
        };
        let debug_str = format!("{:?}", cipher);
        assert!(!debug_str.contains(&format!("{:?}", MARKER.to_vec())));
        assert!(!debug_str.contains(&format!("{:?}", vec![1u8, 2, 3])));
        assert!(!debug_str.contains(&format!("{:?}", vec![4u8, 5, 6])));
    }
}
