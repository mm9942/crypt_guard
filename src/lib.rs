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
//! let mut passphrase = "Test Passphrase";
//! 
//! let (mut public_key, mut secret_key) = KyberKeypair!(1024);
//! 
//! // Creating new Kyber AES message instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None).expect("");
//! 
//! // Now are multiple options available:
//! // Using the Macro
//! let (mut encrypt_message, mut cipher) = Encryption!(public_key.clone(), 1024, message.clone().as_bytes().to_owned(), passphrase.clone(), AES).expect("");
//! 
//! // Using the encrypt_ functions:
//! 
//! // Message:
//! let (mut encrypt_message, mut cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone()).expect("");
//! 
//! // Data:
//! // Creating new Kyber AES data instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.clone(), None).expect("");
//! let (mut encrypt_message, mut cipher) = encryptor.encrypt_data(message.clone().as_bytes().to_owned(), passphrase.clone()).expect("");
//! 
//! // Last but not least the encryption function for files:
//! fs::write(PathBuf::from("message.txt"), message.clone().as_bytes()).expect("");
//! 
//! // Creating new Kyber AES file instance
//! let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None).expect("");
//! 
//! // Encrypt file macro:
//! let (mut encrypt_message, mut cipher) = EncryptFile!(public_key.clone(), 1024, PathBuf::from("message.txt"), passphrase.clone(), AES).expect("");
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
//! use crypt_guard::{*, error::*, KDF::*};
//! use std::{
//!     path::{Path, PathBuf},
//!     fs,
//! };
//!
//! let (mut public_key, mut secret_key) = KyberKeypair!(768);
//!
//! let mut message = "Hey, how are you doing?";
//! let mut passphrase = "Test Passphrase";
//! 
//! fs::write(PathBuf::from("message.txt"), message.clone().as_bytes()).expect("");
//!
//! // You need to save the nonce when not using AES but XChaCha20 instead:
//! // Creating new Kyber XChaCha20 file encryption instance
//! let mut encryptor = Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(public_key.clone(), None).expect("");
//! 
//! // Encrypt file
//! let (mut encrypt_message, mut cipher) = encryptor.encrypt_file(PathBuf::from("message.txt"), passphrase.clone()).expect("");
//!
//! // Should be executed after encryption is already done, since doing it before that would trigger an error.
//! let mut nonce = encryptor.get_nonce().expect("").to_string(); 
//! 
//! // Creating new Kyber XChaCha20 file decryption instance (this time also adding the nonce beside the key)
//! let mut decryptor = Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(secret_key.clone(), Some(nonce)).expect("");
//! 
//! // Decrypt message
//! let mut decrypt_message = decryptor.decrypt_file(PathBuf::from("message.txt.enc"), passphrase.clone(), cipher.clone()).expect("");
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
//! Beside the main macros encrypt, decrypt, encrypt_file, decrypt_file, I've added the Encryption and Decryption macros. Instead of linking the encryption/ decryption instance, we define the macro by using Encryption!(public_key, keysize [ 1024 | 768 | 512 ] contents_bytes_vec, passphrase_as_str, [ AES | XChaCha20 ]) and get the content and ciphertext returned, or additionally when using XChaCha20, we also get the nonce.
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
//! use crypt_guard::KeyControler::KeyControl;
//! 
//! //#[crypt_guard_proc]
//! #[activate_log("log.txt")]
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let _ = initialize_logger(); 
//!     let mut message = "Hey, how are you doing?";
//!     let mut passphrase = "Test Passphrase";
//! 
//!     let mut key_control = KeyControl::<KeyControKyber1024>::new();
//!     let _ = log_activity!("Starting with signing of the message.", "Test");
//! 
//!     // Generate key pair
//!     let (mut public_key, mut secret_key) = KyberKeypair!(1024);
//! 
//!     // Instantiate Kyber for encryption of a message with Kyber1024 and AES
//!     // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!    
//!     // Encrypt message
//!     let (mut encrypt_message, mut cipher) = Encryption!(public_key.to_owned(), 1024, message.as_bytes().to_owned(), passphrase.clone(), AES)?;
//! 
//!     key_control.set_ciphertext(cipher.clone()).unwrap();
//!     key_control.save(KeyTypes::Ciphertext, "./key".into()).unwrap();
//! 
//!     // Decrypt message
//!     let mut decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase.clone(), cipher.to_owned(), AES)?;
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

#[macro_use]
extern crate lazy_static;
pub use crypt_guard_proc::*;

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

use std::{
    fmt::{*}
};
use hex;
use zeroize::Zeroize;
/// Function activating the log, it takes one arg: `&str` which represents the location of the logfile
/*pub fn activate_log<P: AsRef<Path>>(log_file: P) {
    let mut logger = LOGGER.lock().unwrap();
    logger.activated = true;
    logger.location = Some(log_file.as_ref().to_path_buf());
}*/

/// Macro for signing and encrypting data, a 1024 falcon secret key is required for signing
#[macro_export]
macro_rules! EncryptSign {
    ($key:expr, $sign:expr, $content:expr, $passphrase:expr)  => {{
        let mut key = $key;
        let mut sign = $sign;
        let mut content = $content;
        let passphrase = $passphrase;
        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new($key.clone(), None).unwrap();
            let sign = Signature::<Falcon1024, Message>::new();
            let signed_message = sign.signature($content.clone(), $sign.clone()).unwrap();
            encryptor.encrypt_data(signed_message, $passphrase.clone())
        };
        key.zeroize();
        sign.zeroize();
        content.zeroize();
        result
    }};
}

/// Macro for decrypting and opening data, a 1024 falcon public key is required
#[macro_export]
macro_rules! DecryptOpen {
    ($key:expr, $sign:expr, $content:expr, $passphrase:expr, $cipher:expr)  => {{
        let mut key = $key;
        let mut sign = $sign;
        let mut content = $content;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let result = {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new($key, None).unwrap();
            let data = decryptor.decrypt_data($content, $passphrase, $cipher).unwrap();
            let sign = Signature::<Falcon1024, Message>::new();
            sign.open(data, $sign).unwrap()
        };

        key.zeroize();
        sign.zeroize();
        content.zeroize();
        cipher.zeroize();
        result
    }};
}

/// Macro for kyber keypair generation
#[macro_export]
macro_rules! KyberKeypair {
    ($size:expr) => {{
        let (public_key, secret_key) = match $size {
            1024 => {
                KeyControKyber1024::keypair().expect("Failed to generate keypair")
            },
            768 => {
                KeyControKyber768::keypair().expect("Failed to generate keypair")
            },
            512 => {
                KeyControKyber512::keypair().expect("Failed to generate keypair")
            },
            _ => {
                Err(Box::new(CryptError::new("Wrong key size!")) as Box<dyn std::error::Error>)
            }.unwrap()
        };
        (public_key, secret_key)
    }};
}

/// Macro for falcon keypair generation
#[macro_export]
macro_rules! FalconKeypair {
    ($size:expr) => {{
        let (public_key, secret_key) = match $size {
            1024 => {
                Falcon1024::keypair().expect("Failed to generate keypair")
            },
            512 => {
                Falcon512::keypair().expect("Failed to generate keypair")
            },
            _ => {
                Err(Box::new(CryptError::new("Wrong key size!")) as Box<dyn std::error::Error>)
            }.unwrap()
        };
        (public_key, secret_key)
    }};
}

/// Macro for dilithium keypair generation
#[macro_export]
macro_rules! DilithiumKeypair {
    ($version:expr) => {{
        let (public_key, secret_key) = match $version {
            5 => {
                Dilithium5::keypair().expect("Failed to generate keypair")
            },
            3 => {
                Dilithium3::keypair().expect("Failed to generate keypair")
            },
            2 => {
                Dilithium2::keypair().expect("Failed to generate keypair")
            },
            _ => {
                Err(Box::new(CryptError::new("Wrong key size!")) as Box<dyn std::error::Error>)
            }.unwrap()
        };
        (public_key, secret_key)
    }};
}

#[macro_export]
macro_rules! Encryption {
    // AES      
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
        let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new($key, None).expect("");
            encryptor.encrypt_data($data, $passphrase)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 768, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES>::new($key, None).expect("");
            encryptor.encrypt_data($data, $passphrase)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 512, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
        let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES>::new($key, None).expect("");
            encryptor.encrypt_data($data, $passphrase)
        };
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

        let result = {
        let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES_XTS>::new($key, None).expect("");
            encryptor.encrypt_data($data, $passphrase)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES_XTS>::new($key, None).expect("");
            encryptor.encrypt_data($data, $passphrase)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};     
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
        let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES_XTS>::new($key, None).expect("");
            encryptor.encrypt_data($data, $passphrase)
        };
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
        let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES_CBC>::new($key, None).expect("");
            let (encrypt_message, cipher) = encryptor.encrypt_data($data, $passphrase).expect(""); 
            (encrypt_message, cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        
        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES_CBC>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            (encrypt_message, cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES_CBC>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            (encrypt_message, cipher)
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
        let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES_GCM_SIV>::new($key, None).expect("");
            let (encrypt_message, cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        
        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES_GCM_SIV>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES_GCM_SIV>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");         
            (encrypt_message, cipher, nonce.to_string())
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
        let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES_CTR>::new($key, None).expect("");
            let (encrypt_message, cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        
        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES_CTR>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES_CTR>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");         
            (encrypt_message, cipher, nonce.to_string())
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
        let mut encryptor = Kyber::<Encryption, Kyber1024, Data, XChaCha20>::new($key, None).expect("");
            let (encrypt_message, cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        
        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, XChaCha20>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let mut nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, XChaCha20>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let mut nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
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
        
        let result = {
        let mut encryptor = Kyber::<Encryption, Kyber1024, Data, XChaCha20Poly1305>::new($key, None).expect("");
            let (encrypt_message, cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        
        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, XChaCha20Poly1305>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let mut nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, XChaCha20Poly1305>::new($key, None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_data($data, $passphrase).expect("");
            let mut nonce = encryptor.get_nonce().expect("");
            (encrypt_message, cipher, nonce.to_string())
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
}

#[macro_export]
macro_rules! Decryption {
    // AES
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
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

        let result = {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES_XTS>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, AES_XTS>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};


    // AES_CBC
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES_CBC>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        $key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, AES_CBC>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, AES_CBC>::new($key, None).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_GCM_SIV
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES_GCM_SIV>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        $key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, AES_GCM_SIV>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, AES_GCM_SIV>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_CTR
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES_CTR>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        $key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, AES_CTR>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, AES_CTR>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // XChaCha20
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        $key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
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
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};

    // XChaCha20Poly1305
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = {        
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20Poly1305>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
        $key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20Poly1305>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
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
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20Poly1305>::new($key, $nonce).expect("");
            decryptor.decrypt_data($data, $passphrase, $cipher)
        };
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
macro_rules! EncryptFile {
    // AES
    ($key:expr, 1024, $path:expr, $passphrase:expr, AES) => {{
        
        let mut key = $key;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new($key.clone(), None).expect("");
            encryptor.encrypt_file($path.clone(), $passphrase.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, AES) => {{
        
        let mut key = $key;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, AES>::new($key.clone(), None).expect("");
            encryptor.encrypt_file($path.clone(), $passphrase.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, AES) => {{
        
        let mut key = $key;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, AES>::new($key.clone(), None).expect("");
            encryptor.encrypt_file($path.clone(), $passphrase.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $path:expr, $passphrase:expr, XChaCha20) => {{
        
        let mut key = $key;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber1024, Data, XChaCha20>::new($key.clone(), None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_file($path.clone(), $passphrase.clone());
            let mut nonce = encryptor.get_nonce();
            (encrypt_message, cipher, nonce)
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, XChaCha20) => {{
        
        let mut key = $key;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber768, Data, XChaCha20>::new($key.clone(), None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_file($path.clone(), $passphrase.clone());
            let mut nonce = encryptor.get_nonce();
            (encrypt_message, cipher, nonce)
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, XChaCha20) => {{
    
        let mut key = $key;
        let mut passphrase = $passphrase;

        let mut result = {
            let mut encryptor = Kyber::<Encryption, Kyber512, Data, XChaCha20>::new($key.clone(), None).expect("");
            let (mut encrypt_message, mut cipher) = encryptor.encrypt_file($path.clone(), $passphrase.clone());
            let mut nonce = encryptor.get_nonce();
            (encrypt_message, cipher, nonce)
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
}


/// Macro for encryption of a file, taking a Kyber decryption instance, a `PathBuf` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! DecryptFile {
    // AES
    ($key:expr, 1024, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new($key.clone(), None).expect("");
            decryptor.decrypt_file($path.clone(), $passphrase.clone(), $cipher.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new($key.clone(), None).expect("");
            decryptor.decrypt_file($path.clone(), $passphrase.clone(), $cipher.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new($key.clone(), None).expect("");
            decryptor.decrypt_file($path.clone(), $passphrase.clone(), $cipher.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20>::new($key.clone(), Some($nonce.clone())).expect("");
            decryptor.decrypt_file($path.clone(), $passphrase.clone(), $cipher.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20>::new($key.clone(), Some($nonce.clone())).expect("");
            decryptor.decrypt_file($path.clone(), $passphrase.clone(), $cipher.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let mut result = {
            let mut decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20>::new($key.clone(), Some($nonce.clone())).expect("");
            decryptor.decrypt_file($path.clone(), $passphrase.clone(), $cipher.clone())
        };
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
}



#[macro_export]
macro_rules! Signature {
    // Falcon
    // 1024
    (Falcon, $key:expr, 1024, $content:expr, Message) => {{
        let mut key = $key;;
        let mut content = $content;;

        let result = {
            let sign = Signature::<Falcon1024, Message>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $content:expr, Detached) => {{
        let mut key = $key;;
        let mut content = $content;;

        let result = {
            let sign = Signature::<Falcon1024, Detached>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Falcon512, Message>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $content:expr, Detached) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Falcon512, Detached>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // Dilithium
    // 5
    (Dilithium, $key:expr, 5, $content:expr, Message) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Dilithium5, Message>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $content:expr, Detached) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Dilithium5, Detached>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Dilithium3, Message>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $content:expr, Detached) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Dilithium3, Detached>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Dilithium2, Message>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $content:expr, Detached) => {{
        let mut key = $key;;
        let mut content = $content;;

        let mut result = {
            let mut sign = Signature::<Dilithium2, Detached>::new();
            sign.signature($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
}

#[macro_export]
macro_rules! Verify {
    // Falcon
    // 1024
    (Falcon, $key:expr, 1024, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Falcon1024, Message>::new();
            sign.open($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let result = {
            let sign = Signature::<Falcon1024, Detached>::new();
            sign.verify($content.clone(), $signature.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let mut result = {
            let mut sign = Signature::<Falcon512, Message>::new();
            sign.open($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let mut result = {
            let mut sign = Signature::<Falcon512, Detached>::new();
            sign.verify($content.clone(), $signature.clone(), $key.clone()).unwrap()
        };
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

        let mut result = {
            let mut sign = Signature::<Dilithium5, Message>::new();
            sign.open($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 
        let mut result = {
            let mut sign = Signature::<Dilithium5, Detached>::new();
            sign.verify($content.clone(), $signature.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let mut result = {
            let mut sign = Signature::<Dilithium3, Message>::new();
            sign.open($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let mut result = {
            let mut sign = Signature::<Dilithium3, Detached>::new();
            sign.verify($content.clone(), $signature.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let mut result = {
            let mut sign = Signature::<Dilithium2, Message>::new();
            sign.open($content.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content; 

        let mut result = {
            let mut sign = Signature::<Dilithium2, Detached>::new();
            sign.verify($content.clone(), $signature.clone(), $key.clone()).unwrap()
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};
}