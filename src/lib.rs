//! # CryptGuard Programming Library
//! 
//! [![Crates.io][crates-badge]][crates-url]
//! [![MIT licensed][mit-badge]][mit-url]
//! [![Documentation][doc-badge]][doc-url]
//! [![Hashnode Blog][blog-badge]][blog-url]
//! [![GitHub Library][lib-badge]][lib-link]
//! 
//!  [blog-badge]: https://img.shields.io/badge/blog-hashnode-lightblue.svg?style=for-the-badge
//!  [blog-url]: https://blog.mm29942.com/
//!  [crates-badge]: https://img.shields.io/badge/crates.io-v1.2-blue.svg?style=for-the-badge
//!  [crates-url]: https://crates.io/crates/crypt_guard
//!  [mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
//!  [mit-url]: https://github.com/mm9942/CryptGuardLib/blob/main/LICENSE
//!  [doc-badge]: https://img.shields.io/badge/docs-v1.2-yellow.svg?style=for-the-badge
//!  [doc-url]: https://docs.rs/crypt_guard/
//!  [lib-badge]: https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge
//!  [lib-link]: https://github.com/mm9942/CryptGuardLib
//! 
//! ## Introduction
//! 
//! CryptGuard is a comprehensive cryptographic library, offering robust encryption and decryption capabilities. It integrates traditional cryptography with post-quantum algorithms, ensuring resilience against quantum computing threats. Designed for developers, CryptGuard empowers applications to withstand future digital security challenges. Embrace CryptGuard as your trusted ally in safeguarding privacy in the digital realm.
//! 
//! ## Key Features and Capabilities
//! 
//! This library supports AES-256 and XChaCha20 encryption algorithms, providing a secure means to protect data. To cater to a variety of security requirements and operational contexts, CryptGuard integrates seamlessly with Kyber512, Kyber768, and Kyber1024 for encryption, ensuring compatibility with post-quantum cryptography standards.
//! 
//! For developers who require digital signing capabilities, CryptGuard incorporates Falcon and Dilithium algorithms, offering robust options for creating and verifying digital signatures. This feature is particularly crucial for applications that necessitate authenticity and integrity of data, ensuring that digital communications remain secure and verifiable.
//! 
//! An additional layer of security is provided through the appending of a HMAC (Hash-Based Message Authentication Code) to encrypted data. This critical feature enables the authentication of encrypted information, ensuring that any tampering with the data can be reliably detected. This HMAC attachment underscores CryptGuard's commitment to comprehensive data integrity and security, offering developers and end-users peace of mind regarding the authenticity and safety of their data.
//!
//! # Examples
//! 
//! ### Encryption:
//!
//! The encryption functions `encrypt_msg`, `encrypt_data`, and `encrypt_file` are specifically tailored for different types of data. Using distinct functions ensures that the correct methods and optimizations are applied depending on whether you're encrypting raw bytes, structured data, or files. Each encryption function requires a new instance of the Kyber object, tailored for the type of encryption (Message, Data, Files), to guarantee that the cryptographic parameters are initialized correctly and securely for each session.
//!
//! ```rust
//! use crypt_guard::*;
//!
//! let message = "Hey, how are you doing?";
//! let passphrase = "Test Passphrase";
//! 
//! let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");
//! 
//! // Creating new Kyber AES message instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None).unwrap();
//! 
//! // Now are multiple options available:
//! // Using the Macro
//! let (encrypt_message, cipher) = encrypt!(encryptor, message.clone(), passphrase.clone()).unwrap();
//! 
//! // Using the encrypt_ functions:
//! 
//! // Message:
//! let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone()).unwrap();
//! 
//! // Data:
//! // Creating new Kyber AES data instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.clone(), None).unwrap();
//! let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone().as_bytes().to_owned(), passphrase.clone()).unwrap();
//! 
//! // Last but not least the encryption function for files:
//! fs::write(PathBuf::from("message.txt"), message.clone().as_bytes()).unwrap();
//! 
//! // Creating new Kyber AES file instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None).unwrap();
//! 
//! // Encrypt file macro:
//! let (encrypt_message, cipher) = encrypt_file!(encryptor, PathBuf::from("message.txt"), passphrase.clone()).unwrap();
//! 
//! // Encrypt file function:
//! let (encrypt_message, cipher) = encryptor.encrypt_file(PathBuf::from("message.txt"), passphrase.clone()).unwrap();
//! ```
//!
//! #### Infos about XChaCha20 differences
//!
//! XChaCha20, unlike AES, requires handling of a nonce (number used once) which must be generated during encryption and subsequently used during decryption. This introduces additional steps in the cryptographic process when using XChaCha20 compared to AES, which does not explicitly require nonce management by the user.
//!
//! ```rust
//! use crypt_guard::*;
//!
//! // You need to save the nonce when not using AES but XChaCha20 instead:
//! // Creating new Kyber XChaCha20 file encryption instance
//! let mut encryptor = Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(public_key.clone(), None).unwrap();
//! 
//! // Encrypt file
//! let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone()).unwrap();
//!
//! // Should be executed after encryption is already done, since doing it before that would trigger an error.
//! let nonce = encryptor.get_nonce(); 
//! 
//! // Creating new Kyber XChaCha20 file decryption instance (this time also adding the nonce beside the key)
//! let mut decryptor = Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string())).unwrap();
//! 
//! // Decrypt message
//! let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher).unwrap();
//! ```
//!
//! ### Decryption:
//!
//! Decryption functions work similarly to encryption but in reverse, designed to safely convert encrypted data back into its original form. Each type of data (Message, Data, Files) requires a specific decryption function to correctly handle the format and details of the encrypted content. Like encryption, every decryption session uses a fresh Kyber object to ensure isolation between sessions, enhancing security by preventing potential leakage or reuse of cryptographic parameters.
//!
//! ```rust
//! use crypt_guard::*;
//!
//! // Creating new Kyber AES message instance for decryption
//! let mut decryptor = Kyber::<Decryption, Kyber1024, Message, AES>::new(secret_key, None).unwrap();
//! let decrypt_message = decrypt!(decryptor, encrypt_message.clone(), passphrase.clone(), cipher).unwrap();
//!
//!  // Using the decrypt_ functions:
//! 
//! // Message:
//! let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher).unwrap();
//! 
//! // Data:
//! // Creating new Kyber AES data instance for decryption
//! let mut decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(secret_key, None).unwrap();
//! let decrypt_message = decryptor.decrypt_data(encrypt_message.clone(), passphrase.clone(), cipher).unwrap();
//! 
//! // Last but not least the decryption function for files:
//! let file_path = PathBuf::from("message.txt");
//! let encrypted_file_path = PathBuf::from("message.txt.enc");
//!
//! // Creating new Kyber AES file instance for decryption
//! let mut decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None).unwrap();
//! 
//! // Decrypt file macro
//! let decrypt_message = decrypt!(decryptor, encrypted_file_path, passphrase.clone(), cipher).unwrap();
//! 
//! // Decrypt file function
//! let decrypt_message = decryptor.decrypt_file(encrypted_file_path, passphrase.clone(), cipher).unwrap();
//! ```

#[macro_use]
extern crate lazy_static;


/// Core functionalitys for control of Kyber keys as well as encryption and decryption
mod Core;
/// Cryptographic related functionalitys, enums structs and modules
pub mod cryptography;
/// File and Key related functionalitys, enums structs and modules
pub mod KeyControl;
/// Logging related functionalitys
pub mod log;
/// Error types
pub mod error;

#[cfg(test)]
mod tests;

pub use crate::{
    log::*,
    KeyControl::{
        *,
        file, 
    },
    Core::{
        *,
        KDF,
        kyber::*,
    },
};

use KeyControl::*;
use pqcrypto_falcon::falcon1024::{self, *};
use pqcrypto_kyber::kyber1024::{self, *};
use std::{
    error::Error,
    fmt::{self, *},
    iter::repeat,
    path::{PathBuf, Path}, 
    marker::PhantomData, 
    result::Result, 
    io::{Read, Write}, 
    sync::Mutex,
    fs
};


lazy_static! {
    static ref LOGGER: Mutex<Log> = Mutex::new(Log {
        activated: false,
        log: String::new(),
        location: None,
    });
}

/// Function activating the log, it takes one arg: `&str` which represents the location of the logfile
pub fn activate_log<P: AsRef<Path>>(log_file: P) {
    let mut logger = LOGGER.lock().unwrap();
    logger.activated = true;
    logger.location = Some(log_file.as_ref().to_path_buf());
}

/// Macro for encryption of data, taking a Kyber encryption instance, a `Vec<u8>` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! encrypt {
    ($kyber:expr, $data:expr, $passphrase:expr) => {{
        $kyber.encrypt_data($data, $passphrase)
    }};
}
/// Macro for encryption of a file, taking a Kyber decryption instance, a `PathBuf` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! encrypt_file {
    ($kyber:expr, $path:expr, $passphrase:expr) => {{
        $kyber.encrypt_file($path, $passphrase)
    }};
}

/// Macro for decryption of data, taking a Kyber decryption instance, a `Vec<u8>` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! decrypt {
    ($kyber:expr, $encrypted_data:expr, $passphrase:expr, $cipher:expr) => {{
        $kyber.decrypt_data($encrypted_data, $passphrase, $cipher)
    }};
}

/// Macro for decryption of a file, taking a Kyber decryption instance, a `PathBuf` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! decrypt_file {
    ($kyber:expr, $path:expr, $passphrase:expr, $cipher:expr) => {{
        $kyber.decrypt_file($path, $passphrase, $cipher)
    }};
}


#[macro_export]
macro_rules! log_activity {
    ($process:expr, $detail:expr) => {
        match LOGGER.lock() {
            Ok(mut logger) => {
                let _ = logger.append_log($process, $detail);
            },
            Err(e) => eprintln!("Logger lock error: {}", e),
        }
    };
}

/// Macro commanding to write the current in a string stored log into a logfile
#[macro_export]
macro_rules! write_log {
    () => {
        {
            let mut logger = $crate::LOGGER.lock().expect("Logger lock failed");
            if let Err(e) = logger.write_log_file() {
                eprintln!("Failed to write log file: {:?}", e);
            }
            logger.log.clear();
        }
    };
}