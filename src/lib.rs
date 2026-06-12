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
//!  [mit-url]: https://github.com/mm9942/crypt_guard/blob/main/LICENSE
//!  [doc-badge]: https://img.shields.io/badge/docs-v1.2-yellow.svg?style=for-the-badge
//!  [doc-url]: https://docs.rs/crypt_guard/
//!  [lib-badge]: https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge
//!  [lib-link]: https://github.com/mm9942/crypt_guard
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
//! use crypt_guard::{*, error::*};
//! use std::{
//!     path::{Path, PathBuf},
//!     fs,
//! };
//!
//! let mut message = "Hey, how are you doing?";
//! let passphrase= "Test Passphrase";
//! 
//! let (mut public_key, mut secret_key) = kyber_keypair!(1024);
//! 
//! // Creating new Kyber AES message instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.to_owned(), None).expect("");
//! 
//! // Now are multiple options available:
//! // Using the Macro
//! let (mut encrypt_message, mut cipher) = encryption!(public_key.to_owned(), 1024, message.clone().as_bytes().to_owned(), passphrase.clone(), AES).expect("");
//! 
//! // Using the encrypt_ functions:
//! 
//! // Message:
//! let (mut encrypt_message, mut cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone()).expect("");
//! 
//! // Data:
//! // Creating new Kyber AES data instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.to_owned(), None).expect("");
//! let (mut encrypt_message, mut cipher) = encryptor.encrypt_data(message.clone().as_bytes().to_owned(), passphrase.clone()).expect("");
//! 
//! // Last but not least the encryption function for files:
//! fs::write(PathBuf::from("message.txt"), message.clone().as_bytes()).expect("");
//! 
//! // Creating new Kyber AES file instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.to_owned(), None).expect("");
//! 
//! // Encrypt file macro:
//! let (mut encrypt_message, mut cipher) = encrypt_file!(public_key.to_owned(), 1024, PathBuf::from("message.txt"), passphrase.clone(), AES).expect("");
//! 
//! // Encrypt file function:
//! let (mut encrypt_message, mut cipher) = encryptor.encrypt_file(PathBuf::from("message.txt"), passphrase.clone()).expect("");
//!
//! let _ = fs::remove_file("crypt_tests.log");
//! let _ = fs::remove_file("message.txt");
//! let _ = fs::remove_file("log.txt");
//! let _ = fs::remove_file("crypt_tests.log");
//! let _ = fs::remove_file("message.txt.enc");
//! let _ = fs::remove_dir_all("./crypt_tests");
//! let _ = fs::remove_dir_all("./key");
//! let _ = fs::remove_dir_all("./log");
//! ```
//!
//! #### Infos about XChaCha20 differences
//!
//! XChaCha20, unlike AES, requires handling of a nonce (number used once) which must be generated during encryption and subsequently used during decryption. This introduces additional steps in the cryptographic process when using XChaCha20 compared to AES, which does not explicitly require nonce management by the user.
//!
//! ```rust
//! use crypt_guard::{*, error::*, kdf::*};
//! use std::{
//!     path::{Path, PathBuf},
//!     fs,
//! };
//!
//! let (mut public_key, mut secret_key) = kyber_keypair!(768);
//!
//! let mut message = "Hey, how are you doing?";
//! let passphrase= "Test Passphrase";
//! 
//! fs::write(PathBuf::from("message.txt"), message.clone().as_bytes()).expect("");
//!
//! // You need to save the nonce when not using AES but XChaCha20 instead:
//! // Creating new Kyber XChaCha20 file encryption instance
//! let mut encryptor = Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(public_key.to_owned(), None).expect("");
//! 
//! // Encrypt file
//! let (mut encrypt_message, mut cipher) = encryptor.encrypt_file(PathBuf::from("message.txt"), passphrase.clone()).expect("");
//!
//! // Should be executed after encryption is already done, since doing it before that would trigger an error.
//! let nonce = encryptor.get_nonce().expect("").to_string(); 
//! 
//! // Creating new Kyber XChaCha20 file decryption instance (this time also adding the nonce beside the key)
//! let decryptor = Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(secret_key.to_owned(), Some(nonce)).expect("");
//! 
//! // Decrypt message
//! let mut decrypt_message = decryptor.decrypt_file(PathBuf::from("message.txt.enc"), passphrase.clone(), cipher.to_owned()).expect("");
//!
//! let _ = fs::remove_file("crypt_tests.log");
//! let _ = fs::remove_file("message.txt");
//! let _ = fs::remove_file("log.txt");
//! let _ = fs::remove_file("crypt_tests.log");
//! let _ = fs::remove_file("message.txt.enc");
//! let _ = fs::remove_dir_all("./crypt_tests");
//! let _ = fs::remove_dir_all("./key");
//! let _ = fs::remove_dir_all("./log");
//! ```
//!
//! ### Using Encryption and Decryption macros
//!
//! Beside the main macros encrypt, decrypt, encrypt_file, decrypt_file, I've added the `encryption` and `decryption` macros. Instead of linking the encryption/ decryption instance, we define the macro by using `encryption!(public_key, keysize [ 1024 | 768 | 512 ] contents_bytes_vec, passphrase_as_str, [ AES | XChaCha20 ])` and get the content and ciphertext returned, or additionally when using XChaCha20, we also get the nonce.
//!
//! ```rust
//! use crypt_guard::{*, error::*};
//! use std::{
//!     fs::{self, File}, 
//!     marker::PhantomData,
//!     path::{PathBuf, Path},
//!     io::{Read, Write},
//! 
//! };
//! //use crypt_guard_proc::{*, log_activity, write_log};
//! use tempfile::{TempDir, Builder};
//! use crypt_guard::KeyControl;
//! 
//! //#[crypt_guard_proc]
//! #[activate_log("log.txt")]
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let _ = initialize_logger(); 
//!     let mut message = "Hey, how are you doing?";
//!     let passphrase= "Test Passphrase";
//! 
//!     let mut key_control = KeyControl::<KeyControKyber1024>::new();
//!     let _ = log_activity!("Starting with signing of the message.", "Test");
//! 
//!     // Generate key pair
//!     let (mut public_key, mut secret_key) = kyber_keypair!(1024);
//! 
//!     // Instantiate Kyber for encryption of a message with Kyber1024 and AES
//!     // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!    
//!     // Encrypt message
//!     let (mut encrypt_message, mut cipher) = encryption!(public_key.to_owned(), 1024, message.as_bytes().to_owned(), passphrase.clone(), AES)?;
//! 
//!     key_control.set_ciphertext(cipher.to_owned()).unwrap();
//!     key_control.save(KeyTypes::Ciphertext, "./key".into()).unwrap();
//! 
//!     // Decrypt message
//!     let mut decrypt_message = decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase.clone(), cipher.to_owned(), AES)?;
//! 
//!     let mut decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");
//!     write_log!();
//!     println!("{:?}", decrypted_text);
//!
//!     let _ = fs::remove_file("crypt_tests.log");
//!     let _ = fs::remove_file("message.txt");
//!     let _ = fs::remove_file("log.txt");
//!     let _ = fs::remove_file("crypt_tests.log");
//!     let _ = fs::remove_file("message.txt.enc");
//!     let _ = fs::remove_dir_all("./crypt_tests");
//!     let _ = fs::remove_dir_all("./key");
//!     let _ = fs::remove_dir_all("./log");

//!     Ok(())
//! }  
//! ```

pub use crypt_guard_proc::*;

/// Shared zero-sized-type axis markers (Encryption/Decryption, Files/Message/Data, cipher markers).
/// Re-exported here so `crate::*` continues to expose them.
pub mod markers;

/// Core functionalitys for control of Kyber keys as well as encryption and decryption
mod core;
/// Cryptographic related functionalitys, enums structs and modules
pub mod cryptography;
/// File and Key related functionalitys, enums structs and modules
pub mod key_control;
/// Logging related functionalitys
pub mod log;
/// Error types
pub mod error;

pub mod utils;

// ── Phase 2: New FIPS primitive modules ────────────────────────────────────
/// ML-KEM backend trait and ML-KEM-512/768/1024 implementations (FIPS 203).
pub mod kem;
/// SignAlgorithm trait and ML-DSA/SLH-DSA implementations (FIPS 204/205).
pub mod sign;
/// HKDF-SHA256/512 key schedule with domain separation.
pub mod kdf;
/// Builder-style API for encryption/decryption, keygen, and signature flows
pub mod builder;

/// Legacy pqcrypto-backed KEM + signature path (Kyber/Falcon/Dilithium).
/// Only compiled when the `legacy-pqclean` feature is active.
#[cfg(feature = "legacy-pqclean")]
pub mod legacy;

#[cfg(test)]
mod tests;

pub use crate::{
    log::*,
    key_control::{
        *,
        file,
    },
    core::{
        *,
        kyber::*,
    },
    utils::{
        archive,
        zip_manager,
    }
};

// Re-export the legacy kdf module when the feature is active so that
// existing call sites using `crypt_guard::kdf::Falcon1024` etc. keep working.
#[cfg(feature = "legacy-pqclean")]
#[cfg(feature = "legacy-pqclean")]
pub use crate::core::kdf as legacy_kdf;
pub use builder::*;
use std::path::Path;
/// Function activating the log, it takes one arg: `&str` which represents the location of the logfile
pub fn activate_log<P: AsRef<Path>>(log_file: P) {
    // Initialize internal logger state and set up tracing to write to the same file
    crate::log::initialize_logger(log_file.as_ref().to_path_buf());
}

/// Macro for signing and encrypting data, a 1024 falcon secret key is required for signing
#[macro_export]
macro_rules! encrypt_sign {
    ($key:expr, $sign:expr, $content:expr, $passphrase:expr)  => {{
        let mut key = $key;
        let mut sign = $sign;
        let mut content = $content;
        let passphrase = $passphrase;
        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            let mut signer = Signature::<Falcon1024, Message>::new();
            let mut signed_message = signer.signature(content.to_owned(), sign.to_owned()).map_err($crate::error::CryptError::from)?;
            encryptor.encrypt_data(signed_message, &passphrase)
        })();
        key.zeroize();
        sign.zeroize();
        content.zeroize();
        result
    }};
}

/// Macro for decrypting and opening data, a 1024 falcon public key is required
#[macro_export]
macro_rules! decrypt_open {
    ($key:expr, $sign:expr, $content:expr, $passphrase:expr, $cipher:expr)  => {{
        let mut key = $key;
        let mut sign = $sign;
        let mut content = $content;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let out = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            let data = decryptor.decrypt_data(content.to_owned(), &passphrase, cipher.to_owned())?;
            let mut signer = Signature::<Falcon1024, Message>::new();
            signer.open(data, sign.to_owned()).map_err($crate::error::CryptError::from)
        })().expect("decrypt_open failed");

        key.zeroize();
        sign.zeroize();
        content.zeroize();
        cipher.zeroize();
        out
    }};
}


/// Macro to archive a directory or file.
#[macro_export]
macro_rules! archive {
    ($source_path:expr, $delete_dir:expr) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        let source = $source_path.to_path_buf();
        let archive_operation = ArchiveOperation::Archive;
        let archive_instance = Archive::new(source, archive_operation);
        let _ = archive_instance.execute($delete_dir);
    }};
}

/// Macro to extract a `.tar.xz` archive.
#[macro_export]
macro_rules! extract {
    ($archive_path:expr, $delete_archive:expr) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        let archive = $archive_path.to_path_buf();
        let archive_operation = ArchiveOperation::Unarchive;
        let extract_instance = Archive::new(archive, archive_operation);
        let _ = extract_instance.execute($delete_archive);
    }};
}

/// Macro for archiving and extracting directories or files.
#[macro_export]
macro_rules! archive_util {
    // Variant for Archiving
    ($path:expr, $delete_dir:expr, Archive) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        // Convert the provided path to a PathBuf
        let source = $path.to_path_buf();
        // Specify the archive operation
        let archive_operation = ArchiveOperation::Archive;
        // Create a new Archive instance
        let archive_instance = Archive::new(source, archive_operation);
        // Execute the archiving process with the specified delete flag
        let _ = archive_instance.execute($delete_dir);
    }};
    
    // Variant for Extracting
    ($archive_path:expr, $delete_archive:expr, Extract) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        // Convert the provided archive path to a PathBuf
        let archive = $archive_path.to_path_buf();
        // Specify the extraction operation
        let archive_operation = ArchiveOperation::Unarchive;
        // Create a new Archive instance
        let extract_instance = Archive::new(archive, archive_operation);
        // Execute the extraction process with the specified delete flag
        let _ = extract_instance.execute($delete_archive);
    }};
}

/// Macro for kyber keypair generation
#[macro_export]
macro_rules! kyber_keypair {
    ($size:expr) => {{
        match $size {
            1024 => KeyControKyber1024::keypair().expect("Failed to generate keypair"),
            768 => KeyControKyber768::keypair().expect("Failed to generate keypair"),
            512 => KeyControKyber512::keypair().expect("Failed to generate keypair"),
            _ => panic!("Wrong key size!"),
        }
    }};
}

/// Macro for falcon keypair generation
#[macro_export]
macro_rules! falcon_keypair {
    ($size:expr) => {{
        match $size {
            1024 => Falcon1024::keypair().expect("Failed to generate Falcon keypair"),
            512 => Falcon512::keypair().expect("Failed to generate Falcon keypair"),
            _ => panic!("Wrong key size!"),
        }
    }};
}

/// Macro for dilithium keypair generation
#[macro_export]
macro_rules! dilithium_keypair {
    ($version:expr) => {{
        match $version {
            5 => Dilithium5::keypair().expect("Failed to generate Dilithium keypair"),
            3 => Dilithium3::keypair().expect("Failed to generate Dilithium keypair"),
            2 => Dilithium2::keypair().expect("Failed to generate Dilithium keypair"),
            _ => panic!("Wrong key size!"),
        }
    }};
}

#[macro_export]
macro_rules! encryption {
    // AES      
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 768, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 512, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // AES_XTS  
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AesXts>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AesXts>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AesXts>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};

    // AES_CBC
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?; 
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // AES_GCM_SIV
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AesGcmSiv>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AesGcmSiv>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AesGcmSiv>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;         
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};

    // AES_CTR
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AesCtr>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AesCtr>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AesCtr>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;         
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // XChaCha20Poly1305
    ($key:expr, 1024, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        
        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, XChaCha20Poly1305>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        
        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, XChaCha20Poly1305>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, XChaCha20Poly1305>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
}

#[macro_export]
macro_rules! decryption {
    // AES
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AesXts>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    
    // AES_XTS
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AesXts>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AesXts>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};


    // AES_CBC
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_GCM_SIV
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AesGcmSiv>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AesGcmSiv>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AesGcmSiv>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_CTR
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AesCtr>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AesCtr>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AesCtr>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // XChaCha20
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};

    // XChaCha20Poly1305
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20Poly1305>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20Poly1305>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20Poly1305>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
}

/// Macro for encryption of a file, taking a Kyber decryption instance, a `PathBuf` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! encrypt_file {
    // AES
    ($key:expr, 1024, $path:expr, $passphrase:expr, AES) => {{
        
        let mut key = $key;
        let passphrase = $passphrase;
        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_file($path, &passphrase)
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, AES) => {{
        
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_file($path, &passphrase)
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, AES) => {{
        
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_file($path, &passphrase)
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $path:expr, $passphrase:expr, XChaCha20) => {{
        
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_file($path, &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, XChaCha20) => {{
        
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_file($path, &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, XChaCha20) => {{
        
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_file($path, &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
}


/// Macro for encryption of a file, taking a Kyber decryption instance, a `PathBuf` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! decrypt_file {
    // AES
    ($key:expr, 1024, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase= $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
}



#[macro_export]
macro_rules! signature {
    // Falcon
    // 1024
    (Falcon, $key:expr, 1024, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Falcon1024, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Falcon1024, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Falcon512, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Falcon512, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // Dilithium
    // 5
    (Dilithium, $key:expr, 5, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium5, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium5, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium3, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium3, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium2, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium2, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
}

#[macro_export]
macro_rules! verify {
    // Falcon
    // 1024
    (Falcon, $key:expr, 1024, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Falcon1024, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let result = (|| {
            let mut sign = Signature::<Falcon1024, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Falcon512, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let result = (|| {
            let mut sign = Signature::<Falcon512, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // Dilithium
    // 5
    (Dilithium, $key:expr, 5, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium5, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 
        let result = (|| {
            let mut sign = Signature::<Dilithium5, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium3, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let result = (|| {
            let mut sign = Signature::<Dilithium3, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let mut sign = Signature::<Dilithium2, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let result = (|| {
            let mut sign = Signature::<Dilithium2, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};
}
