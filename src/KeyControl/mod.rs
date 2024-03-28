/// A module defining the cryptographic keychain functionality.
pub mod keychain;
/// A module for handling file-related metadata and operations in a cryptographic context.
pub mod file;

/// Re-exports for convenient use of file and keychain functionalities.
pub use file::*;
pub use keychain::*;

use std::path::PathBuf;

/// Enumerates the types of cryptographic keys supported by the system.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum KeyTypes {
    /// Represents an unspecified or undefined key type.
    None,
    /// Represents a public key.
    PublicKey,
    /// Represents a secret (private) key.
    SecretKey,
    /// Represents a ciphertext, typically the result of encrypting some plaintext.
    Ciphertext,
    /// Represents a shared secret, typically derived through key exchange mechanisms.
    SharedSecret,
}

/// Represents a cryptographic key, including its type and raw content.
#[derive(PartialEq, Debug, Clone)]
pub struct Key {
    /// The type of the key, as defined in `KeyTypes`.
    pub key_type: KeyTypes,
    /// The raw content of the key.
    pub content: Vec<u8>
}

/// Represents a pair of cryptographic keys, including a public and a corresponding secret key.
#[derive(PartialEq, Debug, Clone)]
pub struct KeyPair {
    /// The public key part of the key pair.
    pub public_key: Key,
    /// The secret (private) key part of the key pair.
    pub secret_key: Key,
}

/// Enumerates the types of files recognized by the cryptographic system.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FileTypes {
    /// Represents an unspecified or other type of file not explicitly listed.
    Other,
    /// Represents a file containing a public key.
    PublicKey,
    /// Represents a file containing a secret (private) key.
    SecretKey,
    /// Represents a file containing ciphertext.
    Ciphertext,
    /// Represents a file containing a plaintext message.
    Message,
    /// Represents a generic file, without specifying its content type.
    File,
}

/// Enumerates possible states a file can be in, especially in the context of encryption and decryption.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FileState {
    /// Represents an unspecified or other state not explicitly listed.
    Other,
    /// Represents a file that has been encrypted.
    Encrypted,
    /// Represents a file that has been decrypted.
    Decrypted,
    /// Indicates the file content is stored in hexadecimal format.
    Hex,
}

/// Manages metadata related to a file, including its location, type, and state within a cryptographic context.
#[derive(PartialEq, Debug, Clone)]
pub struct FileMetadata {
    /// The filesystem path where the file is located.
    pub location: PathBuf,
    /// The type of the file, as defined in `FileTypes`.
    pub file_type: FileTypes,
    /// The current state of the file, as defined in `FileState`.
    pub file_state: FileState,
}
