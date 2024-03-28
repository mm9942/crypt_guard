 /// The `signature` module provides functionality for generating, managing, and verifying digital signatures, supporting various algorithms including post-quantum secure schemes.
pub mod signature;
/// The `cipher_aes` module implements the AES (Advanced Encryption Standard) algorithm for secure data encryption and decryption, providing a robust symmetric key cryptography solution.
pub mod cipher_aes; 
/// The `cipher_xchacha` module offers encryption and decryption functionalities using the XChaCha20 algorithm, extending ChaCha for higher nonce sizes and additional security.
pub mod cipher_xchacha; 
/// The `cryptographic` module encapsulates core cryptographic operations, including key management, encryption, decryption, and cryptographic utility functions.
mod cryptographic; 
pub use cipher_aes::*;
pub use cipher_xchacha::*;
pub use cryptographic::*;
use std::path::PathBuf;
use crate::{error::CryptError, FileMetadata, Key};

/// Represents the AES cipher for encryption and decryption processes.
/// It holds cryptographic information and a shared secret for operations.
#[derive(PartialEq, Debug, Clone)]
pub struct CipherAES {
    pub infos: CryptographicInformation,
    pub sharedsecret: Vec<u8>,
}

/// Represents the ChaCha cipher for encryption and decryption processes.
/// It includes cryptographic information, a nonce for the operation, and a shared secret.
#[derive(PartialEq, Debug, Clone)]
pub struct CipherChaCha {
    pub infos: CryptographicInformation,
    pub nonce: [u8; 24],
    pub sharedsecret: Vec<u8>,
}

/// Enumerates the cryptographic mechanisms supported, such as AES and XChaCha20.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum CryptographicMechanism {
    AES,
    XChaCha20,
}

/// Enumerates the key encapsulation mechanisms supported, such as Kyber1024.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum KeyEncapMechanism {
    Kyber1024,
}

/// Enumerates the types of content that can be encrypted or decrypted, such as messages or files.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ContentType {
    Message,
    File,
}

/// Enumerates the cryptographic processes, such as encryption and decryption.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Process {
    Encryption,
    Decryption,
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

/// Defines the functionalities for cryptographic operations, providing abstract methods for
/// encryption and decryption that need to be implemented by specific cryptographic algorithms.
pub trait CryptographicFunctions {
    /// Encrypts data using a public key, returning the encrypted data and potentially a new key.
    ///
    /// # Parameters
    /// - `public_key`: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing the encrypted data and a new key on success, or a `CryptError` on failure.
    fn encrypt(&mut self, public_key: Key) -> Result<(Vec<u8>, Key), CryptError>;

    /// Decrypts data using a secret key and a given ciphertext.
    ///
    /// # Parameters
    /// - `secret_key`: The secret key used for decryption.
    /// - `ciphertext`: The ciphertext to be decrypted.
    ///
    /// # Returns
    /// A result containing the decrypted data on success, or a `CryptError` on failure.
    fn decrypt(&mut self, secret_key: Key, ciphertext: Key) -> Result<Vec<u8>, CryptError>;
}
