 /// The `hmac` module provides functionality for generating, managing, and verifying digital hmacs, supporting various algorithms including post-quantum secure schemes.
pub mod hmac_sign;

/// The `cryptographic` module encapsulates core cryptographic operations, including key management, encryption, decryption, and cryptographic utility functions.
mod cryptographic; 

//pub use cipher_aes::*;
//pub use cipher_xchacha::*;
pub use cryptographic::*;
use std::path::PathBuf;
use crate::{error::CryptError, FileMetadata, Key};
use std::fmt;

/// Represents the AES cipher for encryption and decryption processes.
/// It holds cryptographic information and a shared secret for operations.
#[derive(PartialEq, Debug, Clone)]
pub struct CipherAES {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
}

impl fmt::Display for CipherAES {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CipherAES with the following Cryptographic Informations: {}", self.infos.metadata)
    }
}

/// Represents the ChaCha cipher for encryption and decryption processes.
/// It includes cryptographic information, a nonce for the operation, and a shared secret.
#[derive(PartialEq, Debug, Clone)]
pub struct CipherChaCha {
    pub infos: CryptographicInformation,
    pub nonce: [u8; 24],
    pub sharedsecret: Vec<u8>,
}

impl fmt::Display for CipherChaCha {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CipherChaCha with the following Cryptographic Informations {}", self.infos.metadata)
    }
}

/// Enumerates the cryptographic mechanisms supported, such as AES and XChaCha20.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum CryptographicMechanism {
    AES,
    XChaCha20,
}

impl fmt::Display for CryptographicMechanism {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mechanism = match self {
            CryptographicMechanism::AES => "AES",
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
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let content_type = match self {
            ContentType::Message => "Message",
            ContentType::File => "File",
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
        write!(f, "Process: {}\nEncryption Type: {}\nKey Type: {}\nContent Type: {}", self.process, self.encryption_type, self.key_type, self.content_type)
    }
}

/// Contains information necessary for performing cryptographic operations, including the content
/// to be encrypted or decrypted, a passphrase, metadata defining the operation context, and a flag
/// indicating whether the content should be saved securely.
#[derive(PartialEq, Debug, Clone)]
pub struct CryptographicInformation {
    pub content: Vec<u8>,
    pub passphrase: Vec<u8>,
    pub metadata: CryptographicMetadata,
    pub safe: bool,
    pub location: Option<FileMetadata>,
}