/// The `hmac` module provides functionality for generating, managing, and verifying digital hmacs, supporting various algorithms including post-quantum secure schemes.
pub mod hmac_sign;

/// The `cryptographic` module encapsulates core cryptographic operations, including key management, encryption, decryption, and cryptographic utility functions.
mod cryptographic; 

use std::path::PathBuf;
use crate::{error::CryptError, FileMetadata};
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

#[derive(PartialEq, Debug, Clone)]
pub struct CipherAES_GCM_SIV {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
    pub iv: Vec<u8>,
}

impl fmt::Display for CipherAES_GCM_SIV {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CipherAES_GCM_SIV with the following Cryptographic Informations: {}", self.infos.metadata)
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct CipherAES_CTR {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
    pub iv: Vec<u8>,
}

impl fmt::Display for CipherAES_CTR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CipherAES_CTR with the following Cryptographic Informations: {}", self.infos.metadata)
    }
}

/// Represents the XChaCha20 cipher for encryption and decryption processes.
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

/// Represents the XChaCha20Poly1305 cipher for encryption and decryption processes.
/// It includes cryptographic information, a nonce for the operation, and a shared secret.
#[derive(PartialEq, Debug, Clone)]
pub struct CipherChaCha_Poly {
    pub infos: CryptographicInformation,
    pub nonce: [u8; 24],
    pub sharedsecret: Vec<u8>,
}

impl fmt::Display for CipherChaCha_Poly {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CipherChaCha with the following Cryptographic Informations {}", self.infos.metadata)
    }
}

/// Enumerates the cryptographic mechanisms supported, such as AES and XChaCha20.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum CryptographicMechanism {
    AES,
    AES_GCM_SIV,
    AES_CTR,
    XChaCha20Poly1305,
    XChaCha20,
}

impl fmt::Display for CryptographicMechanism {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mechanism = match self {
            CryptographicMechanism::AES => "AES",
            CryptographicMechanism::AES_GCM_SIV => "AES-GCM-SIV",
            CryptographicMechanism::AES_CTR => "AES-CTR",
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

impl fmt::Display for CryptographicInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Cryptographic Information:\n\
                   -\tMetadata:\t\t{}\n\
                   -\tContent Length:\t{} bytes\n",
                   self.metadata,
                   self.content.len())
    }
}
 