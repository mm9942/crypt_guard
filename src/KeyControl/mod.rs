


use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

/// A module defining the cryptographic key functionality.
mod key;
//mod container;
/// A module for handling file-related metadata and operations in a cryptographic context.
pub mod file;

pub use key::Key;
pub use file::*;
//pub use keypair::*;



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

impl KeyTypes {
    pub fn none() -> Self {
        Self::None
    }
    pub fn public_key()  -> Self {
        Self::PublicKey
    }
    pub fn secret_key()  -> Self {
        Self::SecretKey
    }
    pub fn Ciphertext()  -> Self {
        Self::Ciphertext
    }
    pub fn shared_secret()  -> Self {
        Self::SharedSecret
    }

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

impl FileTypes {
    /// Represents an unspecified or other type of file not explicitly listed.
    pub fn other() -> Self {
        Self::Other
    }
    /// Represents a file containing a public key.
    pub fn public_key() -> Self {
        Self::PublicKey
    }
    /// Represents a file containing a secret (private) key.
    pub fn secret_key() -> Self {
        Self::SecretKey
    }
    /// Represents a file containing ciphertext.
    pub fn ciphertext() -> Self {
        Self::Ciphertext
    }
    /// Represents a file containing a plaintext message.
    pub fn message() -> Self {
        Self::Message
    }
    /// Represents a generic file, without specifying its content type.
    pub fn file() -> Self {
        Self::File
    }
}

/// Enumerates possible states a file can be in, especially in the context of encryption and decryption.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FileState {
    /// Represents an unspecified or other state not explicitly listed.
    Other,
    /// Represents a file that has not yet been encrypted.
    NotEncrypted,
    /// Represents a file that has been encrypted.
    Encrypted,
    /// Represents a file that has been decrypted.
    Decrypted,
    /// Indicates the file content is stored in hexadecimal format.
    Hex,
}

impl FileState {
    /// Represents an unspecified or other state not explicitly listed.
    pub fn other() -> Self {
        Self::Other
    }
    /// Represents a file that has not yet been encrypted.
    pub fn not_encrypted() -> Self {
        Self::NotEncrypted
    }
    /// Represents a file that has been encrypted.
    pub fn encrypted() -> Self {
        Self::Encrypted
    }
    /// Represents a file that has been decrypted.
    pub fn decrypted() -> Self {
        Self::Decrypted
    }
    /// Indicates the file content is stored in hexadecimal format.
    pub fn hex() -> Self {
        Self::Hex
    }
}