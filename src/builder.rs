//! Fluent builder API over the legacy Kyber encryption, decryption, and signing macros.
//!
//! # Responsibility scope
//! Wraps the working `encryption!`, `decryption!`, `encrypt_file!`, `decrypt_file!`,
//! `signature!`, `verify!`, and `kyber_keypair!` macros in ergonomic builder structs so
//! callers can configure a Kyber size, symmetric cipher, passphrase, and content without
//! invoking the macros directly. The whole module is gated behind the `legacy-pqclean`
//! feature because it depends on the pqcrypto-backed Kyber path; it adds no new
//! cryptographic capability of its own.
//!
//! # Key types exported
//! - [`SymmetricAlg`] / [`SignAlgorithm`] / [`SignMode`] — configuration enums.
//! - [`EncryptionOutput`] — result of an encryption run.
//! - [`EncryptBuilder`], [`DecryptBuilder`], [`KyberKeygenBuilder`], [`SignBuilder`],
//!   [`VerifyBuilder`] — the builders.
//!
//! # Concurrency
//! Builders own their inputs by value and hold no shared state; each is `Send` and is
//! consumed by its terminal method (`run`/`generate`/`sign`/`open`/`verify`).
//!
//! # Errors
//! Encryption/decryption/keygen paths return [`CryptError`]; signing/verification paths
//! return [`SigningErr`]. Missing required fields and invalid Kyber sizes are surfaced as
//! errors rather than panics.
//!
//! # Examples
//! ```rust,no_run
//! # #[cfg(feature = "legacy-pqclean")] {
//! use crypt_guard::builder::{KyberKeygenBuilder, EncryptBuilder, SymmetricAlg};
//! let (pk, _sk) = KyberKeygenBuilder::new().size(1024).generate().unwrap();
//! let out = EncryptBuilder::new()
//!     .key(pk).key_size(1024)
//!     .data(b"hello".to_vec())
//!     .passphrase("pw")
//!     .algorithm(SymmetricAlg::Aes)
//!     .run()
//!     .unwrap();
//! let _ = out.cipher;
//! # }
//! ```

#[cfg(feature = "legacy-pqclean")]
use std::path::PathBuf;

#[cfg(feature = "legacy-pqclean")]
use zeroize::Zeroize;
// bring exported macros into scope (legacy-only macros gated below)
#[cfg(feature = "legacy-pqclean")]
use crate::{decrypt_file, decryption, encrypt_file, encryption, kyber_keypair, signature, verify};
// Macro expansions require these types in scope at the callsite
#[cfg(feature = "legacy-pqclean")]
use crate::core::{
    kdf::{
        Detached, Dilithium2, Dilithium3, Dilithium5, Falcon1024, Falcon512, Message, Signature,
    },
    kyber::key_controler::{KeyControKyber1024, KeyControKyber512, KeyControKyber768},
};
// Types required by macro expansions
#[cfg(feature = "legacy-pqclean")]
use crate::core::kyber::KyberFunctions;
#[cfg(feature = "legacy-pqclean")]
use crate::core::kyber::{
    AesCtr, AesGcmSiv, AesXts, Data, Decryption, Encryption, Kyber, Kyber1024, Kyber512, Kyber768,
    XChaCha20, XChaCha20Poly1305, AES,
};
// Error types referenced by the legacy builder return signatures.
#[cfg(feature = "legacy-pqclean")]
use crate::error::{CryptError, SigningErr};

/// Symmetric algorithms supported by the builders
#[cfg(feature = "legacy-pqclean")]
#[derive(Clone, Copy, Debug)]
pub enum SymmetricAlg {
    /// AES-256-CBC with HMAC (default AES path; no nonce in output).
    Aes,
    /// AES-256-XTS (double-width key; no nonce in output).
    AesXts,
    /// AES-256-CBC (no nonce in output).
    AesCbc,
    /// AES-256-GCM-SIV AEAD (produces a nonce).
    AesGcmSiv,
    /// AES-256-CTR (produces a nonce).
    AesCtr,
    /// XChaCha20 stream cipher (produces a nonce).
    XChaCha20,
    /// XChaCha20-Poly1305 AEAD (produces a nonce).
    XChaCha20Poly1305,
}

/// Output of an encryption operation.
///
/// # Description
/// Bundles the encrypted payload, the Kyber-encapsulated ciphertext, and an optional
/// nonce. `nonce` is `Some` only for nonce-bearing ciphers (GCM-SIV, CTR, XChaCha20,
/// XChaCha20-Poly1305) and `None` for CBC/XTS-style AES.
#[cfg(feature = "legacy-pqclean")]
#[derive(Clone, Debug)]
pub struct EncryptionOutput {
    /// The encrypted content bytes.
    pub content: Vec<u8>,
    /// The Kyber-encapsulated ciphertext bytes.
    pub cipher: Vec<u8>,
    /// The nonce, present only for nonce-bearing ciphers.
    pub nonce: Option<String>,
}

#[cfg(feature = "legacy-pqclean")]
#[derive(Clone, Debug)]
enum Content {
    Data(Vec<u8>),
    File(PathBuf),
}

/// Builder for Kyber-wrapped symmetric encryption of in-memory data or a file.
///
/// # Description
/// Collects a Kyber public key, key size, content (data or file path), passphrase, and
/// symmetric algorithm, then dispatches to the appropriate `encryption!`/`encrypt_file!`
/// macro in [`run`](EncryptBuilder::run).
#[cfg(feature = "legacy-pqclean")]
#[derive(Default)]
pub struct EncryptBuilder {
    key: Option<Vec<u8>>,     // Kyber public key
    key_size: Option<u16>,    // 1024 | 768 | 512
    content: Option<Content>, // Data or File
    passphrase: Option<String>,
    algorithm: Option<SymmetricAlg>,
}

#[cfg(feature = "legacy-pqclean")]
impl EncryptBuilder {
    /// Creates a new, empty [`EncryptBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Kyber public key bytes used for encapsulation.
    pub fn key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }
    /// Sets the Kyber size selector (`1024`, `768`, or `512`).
    pub fn key_size(mut self, size: u16) -> Self {
        self.key_size = Some(size);
        self
    }

    /// Sets in-memory bytes as the content to encrypt.
    ///
    /// # Arguments
    /// - `data` (`impl Into<Vec<u8>>`): the plaintext bytes.
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.content = Some(Content::Data(data.into()));
        self
    }

    /// Sets a filesystem path as the content to encrypt.
    ///
    /// # Arguments
    /// - `path` (`PathBuf`): the file to encrypt.
    pub fn file(mut self, path: PathBuf) -> Self {
        self.content = Some(Content::File(path));
        self
    }

    /// Sets the passphrase mixed into key derivation.
    pub fn passphrase<S: Into<String>>(mut self, passphrase: S) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }

    /// Sets the symmetric cipher to use.
    pub fn algorithm(mut self, alg: SymmetricAlg) -> Self {
        self.algorithm = Some(alg);
        self
    }

    /// Runs the encryption, consuming the builder.
    ///
    /// # Returns
    /// `Ok(EncryptionOutput)` with the encrypted content, Kyber ciphertext, and an
    /// optional nonce.
    ///
    /// # Errors
    /// - [`CryptError`]: a required field (key, size, passphrase, algorithm, content) is
    ///   missing, the Kyber size is not `1024`/`768`/`512`, the cipher/content combination
    ///   is unsupported for files, or the underlying macro fails.
    pub fn run(self) -> Result<EncryptionOutput, CryptError> {
        let key = self
            .key
            .ok_or_else(|| CryptError::new("missing public key"))?;
        let size = self
            .key_size
            .ok_or_else(|| CryptError::new("missing key size"))?;
        let pass = self
            .passphrase
            .ok_or_else(|| CryptError::new("missing passphrase"))?;
        let alg = self
            .algorithm
            .ok_or_else(|| CryptError::new("missing algorithm"))?;
        let content = self
            .content
            .ok_or_else(|| CryptError::new("missing content (data or file)"))?;

        match content {
            Content::Data(data) => match alg {
                SymmetricAlg::Aes => {
                    let (content, cipher) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: None,
                    })
                }
                SymmetricAlg::AesXts => {
                    let (content, cipher) = match size {
                        1024 => {
                            encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_XTS)?
                        }
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_XTS)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_XTS)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: None,
                    })
                }
                SymmetricAlg::AesCbc => {
                    let (content, cipher) = match size {
                        1024 => {
                            encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_CBC)?
                        }
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_CBC)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_CBC)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: None,
                    })
                }
                SymmetricAlg::AesGcmSiv => {
                    let (content, cipher, nonce) = match size {
                        1024 => {
                            encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_GCM_SIV)?
                        }
                        768 => {
                            encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_GCM_SIV)?
                        }
                        512 => {
                            encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_GCM_SIV)?
                        }
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: Some(nonce),
                    })
                }
                SymmetricAlg::AesCtr => {
                    let (content, cipher, nonce) = match size {
                        1024 => {
                            encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_CTR)?
                        }
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_CTR)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_CTR)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: Some(nonce),
                    })
                }
                SymmetricAlg::XChaCha20 => {
                    let (content, cipher, nonce) = match size {
                        1024 => {
                            encryption!(key.clone(), 1024, data.clone(), pass.clone(), XChaCha20)?
                        }
                        768 => {
                            encryption!(key.clone(), 768, data.clone(), pass.clone(), XChaCha20)?
                        }
                        512 => {
                            encryption!(key.clone(), 512, data.clone(), pass.clone(), XChaCha20)?
                        }
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: Some(nonce),
                    })
                }
                SymmetricAlg::XChaCha20Poly1305 => {
                    let (content, cipher, nonce) = match size {
                        1024 => encryption!(
                            key.clone(),
                            1024,
                            data.clone(),
                            pass.clone(),
                            XChaCha20Poly1305
                        )?,
                        768 => encryption!(
                            key.clone(),
                            768,
                            data.clone(),
                            pass.clone(),
                            XChaCha20Poly1305
                        )?,
                        512 => encryption!(
                            key.clone(),
                            512,
                            data.clone(),
                            pass.clone(),
                            XChaCha20Poly1305
                        )?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: Some(nonce),
                    })
                }
            },
            Content::File(path) => match alg {
                SymmetricAlg::Aes => {
                    let (content, cipher) = match size {
                        1024 => encrypt_file!(key.clone(), 1024, path.clone(), pass.clone(), AES)?,
                        768 => encrypt_file!(key.clone(), 768, path.clone(), pass.clone(), AES)?,
                        512 => encrypt_file!(key.clone(), 512, path.clone(), pass.clone(), AES)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce: None,
                    })
                }
                SymmetricAlg::XChaCha20 => {
                    // Returns a nonce (as Option<String>) in macro; normalize to Option<String>
                    let (content, cipher, nonce_str) = match size {
                        1024 => {
                            encrypt_file!(key.clone(), 1024, path.clone(), pass.clone(), XChaCha20)?
                        }
                        768 => {
                            encrypt_file!(key.clone(), 768, path.clone(), pass.clone(), XChaCha20)?
                        }
                        512 => {
                            encrypt_file!(key.clone(), 512, path.clone(), pass.clone(), XChaCha20)?
                        }
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    let nonce = Some(nonce_str);
                    Ok(EncryptionOutput {
                        content,
                        cipher,
                        nonce,
                    })
                }
                _ => Err(CryptError::new(
                    "file encryption supported only for AES and XChaCha20",
                )),
            },
        }
    }
}

/// Builder for Kyber-wrapped symmetric decryption of in-memory data or a file.
///
/// # Description
/// Mirrors [`EncryptBuilder`] in reverse: it collects the Kyber secret key, size, content,
/// passphrase, Kyber ciphertext, and (for nonce-bearing ciphers) a nonce, then dispatches
/// to the matching `decryption!`/`decrypt_file!` macro in [`run`](DecryptBuilder::run).
#[cfg(feature = "legacy-pqclean")]
#[derive(Default)]
pub struct DecryptBuilder {
    key: Option<Vec<u8>>,     // Kyber secret key
    key_size: Option<u16>,    // 1024 | 768 | 512
    content: Option<Content>, // Data (encrypted bytes) or File (.enc path)
    passphrase: Option<String>,
    cipher: Option<Vec<u8>>,
    nonce: Option<String>,
    algorithm: Option<SymmetricAlg>,
}

#[cfg(feature = "legacy-pqclean")]
impl DecryptBuilder {
    /// Creates a new, empty [`DecryptBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Kyber secret key bytes used for decapsulation.
    pub fn key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }
    /// Sets the Kyber size selector (`1024`, `768`, or `512`).
    pub fn key_size(mut self, size: u16) -> Self {
        self.key_size = Some(size);
        self
    }
    /// Sets the encrypted in-memory bytes to decrypt.
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.content = Some(Content::Data(data.into()));
        self
    }
    /// Sets a filesystem path (e.g. an `.enc` file) to decrypt.
    pub fn file(mut self, path: PathBuf) -> Self {
        self.content = Some(Content::File(path));
        self
    }
    /// Sets the passphrase mixed into key derivation.
    pub fn passphrase<S: Into<String>>(mut self, passphrase: S) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }
    /// Sets the Kyber-encapsulated ciphertext bytes.
    pub fn cipher<T: Into<Vec<u8>>>(mut self, cipher: T) -> Self {
        self.cipher = Some(cipher.into());
        self
    }
    /// Sets the nonce required by nonce-bearing ciphers.
    pub fn nonce<S: Into<String>>(mut self, nonce: S) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
    /// Sets the symmetric cipher to use.
    pub fn algorithm(mut self, alg: SymmetricAlg) -> Self {
        self.algorithm = Some(alg);
        self
    }

    /// Runs the decryption, consuming the builder.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the recovered plaintext bytes.
    ///
    /// # Errors
    /// - [`CryptError`]: a required field is missing (including the nonce for nonce-bearing
    ///   ciphers or the cipher for data/file paths), the Kyber size is invalid, the
    ///   cipher/content combination is unsupported, or the underlying macro fails.
    pub fn run(self) -> Result<Vec<u8>, CryptError> {
        let key = self
            .key
            .ok_or_else(|| CryptError::new("missing secret key"))?;
        let size = self
            .key_size
            .ok_or_else(|| CryptError::new("missing key size"))?;
        let pass = self
            .passphrase
            .ok_or_else(|| CryptError::new("missing passphrase"))?;
        let alg = self
            .algorithm
            .ok_or_else(|| CryptError::new("missing algorithm"))?;
        let content = self
            .content
            .ok_or_else(|| CryptError::new("missing content (data or file)"))?;

        match content {
            Content::Data(data) => {
                let cipher = self
                    .cipher
                    .ok_or_else(|| CryptError::new("missing cipher"))?;
                match alg {
                    SymmetricAlg::Aes => match size {
                        1024 => decryption!(
                            key.clone(),
                            1024,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES
                        ),
                        768 => decryption!(
                            key.clone(),
                            768,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES
                        ),
                        512 => decryption!(
                            key.clone(),
                            512,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES
                        ),
                        _ => Err(CryptError::new("invalid Kyber size")),
                    },
                    SymmetricAlg::AesXts => match size {
                        1024 => decryption!(
                            key.clone(),
                            1024,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES_XTS
                        ),
                        768 => decryption!(
                            key.clone(),
                            768,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES_XTS
                        ),
                        512 => decryption!(
                            key.clone(),
                            512,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES_XTS
                        ),
                        _ => Err(CryptError::new("invalid Kyber size")),
                    },
                    SymmetricAlg::AesCbc => match size {
                        1024 => decryption!(
                            key.clone(),
                            1024,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES_CBC
                        ),
                        768 => decryption!(
                            key.clone(),
                            768,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES_CBC
                        ),
                        512 => decryption!(
                            key.clone(),
                            512,
                            data.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES_CBC
                        ),
                        _ => Err(CryptError::new("invalid Kyber size")),
                    },
                    SymmetricAlg::AesGcmSiv => {
                        let n = self
                            .nonce
                            .ok_or_else(|| CryptError::new("missing nonce for AES_GCM_SIV"))?;
                        match size {
                            1024 => decryption!(
                                key.clone(),
                                1024,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                AES_GCM_SIV
                            ),
                            768 => decryption!(
                                key.clone(),
                                768,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                AES_GCM_SIV
                            ),
                            512 => decryption!(
                                key.clone(),
                                512,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                AES_GCM_SIV
                            ),
                            _ => Err(CryptError::new("invalid Kyber size")),
                        }
                    }
                    SymmetricAlg::AesCtr => {
                        let n = self
                            .nonce
                            .ok_or_else(|| CryptError::new("missing nonce for AES_CTR"))?;
                        match size {
                            1024 => decryption!(
                                key.clone(),
                                1024,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                AES_CTR
                            ),
                            768 => decryption!(
                                key.clone(),
                                768,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                AES_CTR
                            ),
                            512 => decryption!(
                                key.clone(),
                                512,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                AES_CTR
                            ),
                            _ => Err(CryptError::new("invalid Kyber size")),
                        }
                    }
                    SymmetricAlg::XChaCha20 => {
                        let n = self
                            .nonce
                            .ok_or_else(|| CryptError::new("missing nonce for XChaCha20"))?;
                        match size {
                            1024 => decryption!(
                                key.clone(),
                                1024,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                XChaCha20
                            ),
                            768 => decryption!(
                                key.clone(),
                                768,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                XChaCha20
                            ),
                            512 => decryption!(
                                key.clone(),
                                512,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                XChaCha20
                            ),
                            _ => Err(CryptError::new("invalid Kyber size")),
                        }
                    }
                    SymmetricAlg::XChaCha20Poly1305 => {
                        let n = self.nonce.ok_or_else(|| {
                            CryptError::new("missing nonce for XChaCha20Poly1305")
                        })?;
                        match size {
                            1024 => decryption!(
                                key.clone(),
                                1024,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                XChaCha20Poly1305
                            ),
                            768 => decryption!(
                                key.clone(),
                                768,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                XChaCha20Poly1305
                            ),
                            512 => decryption!(
                                key.clone(),
                                512,
                                data.clone(),
                                pass.clone(),
                                cipher.clone(),
                                Some(n.clone()),
                                XChaCha20Poly1305
                            ),
                            _ => Err(CryptError::new("invalid Kyber size")),
                        }
                    }
                }
            }
            Content::File(path) => match alg {
                SymmetricAlg::Aes => {
                    let cipher = self
                        .cipher
                        .ok_or_else(|| CryptError::new("missing cipher"))?;
                    match size {
                        1024 => decrypt_file!(
                            key.clone(),
                            1024,
                            path.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES
                        ),
                        768 => decrypt_file!(
                            key.clone(),
                            768,
                            path.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES
                        ),
                        512 => decrypt_file!(
                            key.clone(),
                            512,
                            path.clone(),
                            pass.clone(),
                            cipher.clone(),
                            AES
                        ),
                        _ => Err(CryptError::new("invalid Kyber size")),
                    }
                }
                SymmetricAlg::XChaCha20 => {
                    let cipher = self
                        .cipher
                        .ok_or_else(|| CryptError::new("missing cipher"))?;
                    let n = self
                        .nonce
                        .ok_or_else(|| CryptError::new("missing nonce for XChaCha20"))?;
                    match size {
                        1024 => decrypt_file!(
                            key.clone(),
                            1024,
                            path.clone(),
                            pass.clone(),
                            cipher.clone(),
                            Some(n.clone()),
                            XChaCha20
                        ),
                        768 => decrypt_file!(
                            key.clone(),
                            768,
                            path.clone(),
                            pass.clone(),
                            cipher.clone(),
                            Some(n.clone()),
                            XChaCha20
                        ),
                        512 => decrypt_file!(
                            key.clone(),
                            512,
                            path.clone(),
                            pass.clone(),
                            cipher.clone(),
                            Some(n.clone()),
                            XChaCha20
                        ),
                        _ => Err(CryptError::new("invalid Kyber size")),
                    }
                }
                _ => Err(CryptError::new(
                    "file decryption supported only for AES and XChaCha20",
                )),
            },
        }
    }
}

/// Builder that generates a Kyber keypair for a chosen size.
#[cfg(feature = "legacy-pqclean")]
#[derive(Default)]
pub struct KyberKeygenBuilder {
    size: Option<u16>,
}
#[cfg(feature = "legacy-pqclean")]
impl KyberKeygenBuilder {
    /// Creates a new, empty [`KyberKeygenBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the Kyber size selector (`1024`, `768`, or `512`).
    pub fn size(mut self, size: u16) -> Self {
        self.size = Some(size);
        self
    }
    /// Generates the keypair, consuming the builder.
    ///
    /// # Returns
    /// `Ok((public_key, secret_key))` as raw byte vectors.
    ///
    /// # Errors
    /// - [`CryptError`]: the Kyber size was never set.
    pub fn generate(self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let size = self
            .size
            .ok_or_else(|| CryptError::new("missing kyber size"))?;
        let (pk, sk) = kyber_keypair!(size);
        Ok((pk, sk))
    }
}

/// Post-quantum signature algorithm selector for [`SignBuilder`]/[`VerifyBuilder`].
#[cfg(feature = "legacy-pqclean")]
#[derive(Clone, Copy, Debug)]
pub enum SignAlgorithm {
    /// Falcon-1024.
    Falcon1024,
    /// Falcon-512.
    Falcon512,
    /// Dilithium2.
    Dilithium2,
    /// Dilithium3.
    Dilithium3,
    /// Dilithium5.
    Dilithium5,
}

/// Signing mode: an attached signed message or a detached signature.
#[cfg(feature = "legacy-pqclean")]
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum SignMode {
    /// Produce/consume a signed message with the payload embedded.
    Message,
    /// Produce/verify a detached signature over separate data.
    Detached,
}

/// Builder for producing a post-quantum signature over data.
#[cfg(feature = "legacy-pqclean")]
#[derive(Default)]
pub struct SignBuilder {
    alg: Option<SignAlgorithm>,
    mode: Option<SignMode>,
    key: Option<Vec<u8>>, // secret key for signing
    data: Option<Vec<u8>>,
}

#[cfg(feature = "legacy-pqclean")]
impl SignBuilder {
    /// Creates a new, empty [`SignBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the signature algorithm.
    pub fn algorithm(mut self, alg: SignAlgorithm) -> Self {
        self.alg = Some(alg);
        self
    }
    /// Sets the signing mode (attached message or detached signature).
    pub fn mode(mut self, mode: SignMode) -> Self {
        self.mode = Some(mode);
        self
    }
    /// Sets the secret key used for signing.
    pub fn key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }
    /// Sets the data to sign.
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Signs the data, consuming the builder.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` — the signed message (in `Message` mode) or the detached signature
    /// bytes (in `Detached` mode).
    ///
    /// # Errors
    /// - [`SigningErr`]: a required field (algorithm, mode, key, data) is missing or the
    ///   underlying signing macro fails.
    pub fn sign(self) -> Result<Vec<u8>, SigningErr> {
        let alg = self
            .alg
            .ok_or_else(|| SigningErr::new("missing algorithm"))?;
        let mode = self
            .mode
            .ok_or_else(|| SigningErr::new("missing sign mode"))?;
        let key = self.key.ok_or_else(|| SigningErr::new("missing key"))?;
        let data = self.data.ok_or_else(|| SigningErr::new("missing data"))?;

        let res = match (alg, mode) {
            (SignAlgorithm::Falcon1024, SignMode::Message) => {
                signature!(Falcon, key.clone(), 1024, data.clone(), Message)
            }
            (SignAlgorithm::Falcon1024, SignMode::Detached) => {
                signature!(Falcon, key.clone(), 1024, data.clone(), Detached)
            }
            (SignAlgorithm::Falcon512, SignMode::Message) => {
                signature!(Falcon, key.clone(), 512, data.clone(), Message)
            }
            (SignAlgorithm::Falcon512, SignMode::Detached) => {
                signature!(Falcon, key.clone(), 512, data.clone(), Detached)
            }
            (SignAlgorithm::Dilithium5, SignMode::Message) => {
                signature!(Dilithium, key.clone(), 5, data.clone(), Message)
            }
            (SignAlgorithm::Dilithium5, SignMode::Detached) => {
                signature!(Dilithium, key.clone(), 5, data.clone(), Detached)
            }
            (SignAlgorithm::Dilithium3, SignMode::Message) => {
                signature!(Dilithium, key.clone(), 3, data.clone(), Message)
            }
            (SignAlgorithm::Dilithium3, SignMode::Detached) => {
                signature!(Dilithium, key.clone(), 3, data.clone(), Detached)
            }
            (SignAlgorithm::Dilithium2, SignMode::Message) => {
                signature!(Dilithium, key.clone(), 2, data.clone(), Message)
            }
            (SignAlgorithm::Dilithium2, SignMode::Detached) => {
                signature!(Dilithium, key.clone(), 2, data.clone(), Detached)
            }
        };
        Ok(res?)
    }
}

/// Builder for verifying a post-quantum signature.
///
/// # Description
/// Use [`open`](VerifyBuilder::open) in `Message` mode to recover the payload from a
/// signed message, or [`verify`](VerifyBuilder::verify) in `Detached` mode to check a
/// detached signature against separate data.
#[cfg(feature = "legacy-pqclean")]
#[derive(Default)]
pub struct VerifyBuilder {
    alg: Option<SignAlgorithm>,
    mode: Option<SignMode>,
    key: Option<Vec<u8>>,            // public key for verification
    signed_message: Option<Vec<u8>>, // for Message mode
    data: Option<Vec<u8>>,           // for Detached mode
    signature: Option<Vec<u8>>,      // for Detached mode
}

#[cfg(feature = "legacy-pqclean")]
impl VerifyBuilder {
    /// Creates a new, empty [`VerifyBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the signature algorithm.
    pub fn algorithm(mut self, alg: SignAlgorithm) -> Self {
        self.alg = Some(alg);
        self
    }
    /// Sets the verification mode (attached message or detached signature).
    pub fn mode(mut self, mode: SignMode) -> Self {
        self.mode = Some(mode);
        self
    }
    /// Sets the public key used for verification.
    pub fn key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }
    /// Sets the signed message to open (used in `Message` mode).
    pub fn signed_message<T: Into<Vec<u8>>>(mut self, msg: T) -> Self {
        self.signed_message = Some(msg.into());
        self
    }
    /// Sets the original data (used in `Detached` mode).
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.data = Some(data.into());
        self
    }
    /// Sets the detached signature bytes (used in `Detached` mode).
    pub fn signature<T: Into<Vec<u8>>>(mut self, sig: T) -> Self {
        self.signature = Some(sig.into());
        self
    }

    /// Opens a signed message and returns its recovered payload.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the verified message bytes.
    ///
    /// # Errors
    /// - [`SigningErr`]: a required field is missing, the mode is not `Message`, or
    ///   verification fails.
    pub fn open(self) -> Result<Vec<u8>, SigningErr> {
        let alg = self
            .alg
            .ok_or_else(|| SigningErr::new("missing algorithm"))?;
        let mode = self
            .mode
            .ok_or_else(|| SigningErr::new("missing sign mode"))?;
        if mode != SignMode::Message {
            return Err(SigningErr::new("open() requires Message mode"));
        }
        let key = self.key.ok_or_else(|| SigningErr::new("missing key"))?;
        let msg = self
            .signed_message
            .ok_or_else(|| SigningErr::new("missing signed message"))?;
        let res = match alg {
            SignAlgorithm::Falcon1024 => verify!(Falcon, key.clone(), 1024, msg.clone(), Message),
            SignAlgorithm::Falcon512 => verify!(Falcon, key.clone(), 512, msg.clone(), Message),
            SignAlgorithm::Dilithium5 => verify!(Dilithium, key.clone(), 5, msg.clone(), Message),
            SignAlgorithm::Dilithium3 => verify!(Dilithium, key.clone(), 3, msg.clone(), Message),
            SignAlgorithm::Dilithium2 => verify!(Dilithium, key.clone(), 2, msg.clone(), Message),
        };
        Ok(res?)
    }

    /// Verifies a detached signature against the configured data.
    ///
    /// # Returns
    /// `Ok(true)` if the signature is valid, `Ok(false)` otherwise.
    ///
    /// # Errors
    /// - [`SigningErr`]: a required field is missing, the mode is not `Detached`, or the
    ///   underlying verification macro fails.
    pub fn verify(self) -> Result<bool, SigningErr> {
        let alg = self
            .alg
            .ok_or_else(|| SigningErr::new("missing algorithm"))?;
        let mode = self
            .mode
            .ok_or_else(|| SigningErr::new("missing sign mode"))?;
        if mode != SignMode::Detached {
            return Err(SigningErr::new("verify() requires Detached mode"));
        }
        let key = self.key.ok_or_else(|| SigningErr::new("missing key"))?;
        let data = self.data.ok_or_else(|| SigningErr::new("missing data"))?;
        let signature = self
            .signature
            .ok_or_else(|| SigningErr::new("missing signature"))?;
        let res = match alg {
            SignAlgorithm::Falcon1024 => verify!(
                Falcon,
                key.clone(),
                1024,
                signature.clone(),
                data.clone(),
                Detached
            ),
            SignAlgorithm::Falcon512 => verify!(
                Falcon,
                key.clone(),
                512,
                signature.clone(),
                data.clone(),
                Detached
            ),
            SignAlgorithm::Dilithium5 => verify!(
                Dilithium,
                key.clone(),
                5,
                signature.clone(),
                data.clone(),
                Detached
            ),
            SignAlgorithm::Dilithium3 => verify!(
                Dilithium,
                key.clone(),
                3,
                signature.clone(),
                data.clone(),
                Detached
            ),
            SignAlgorithm::Dilithium2 => verify!(
                Dilithium,
                key.clone(),
                2,
                signature.clone(),
                data.clone(),
                Detached
            ),
        };
        Ok(res?)
    }
}
