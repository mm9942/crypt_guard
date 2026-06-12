//! Hub module: `Kyber<P, K, D, C>` four-axis typestate, KEM variant traits, and cipher markers.
//!
//! The pqcrypto-backed KEM key-control (`KeyControKyber*`) and all `KyberFunctions`
//! implementations have been moved to `src/legacy/kyber_crypto/` and are compiled only
//! when the `legacy-pqclean` feature is active.
//!
//! # Key types exported
//! - [`Kyber`] — four-axis typestate struct
//! - [`KyberFunctions`] — encrypt/decrypt trait (implemented in `legacy/kyber_crypto/`)
//! - [`KyberSizeVariant`] / [`KyberVariant`] — size-dispatch trait and enum
//! - [`Kyber512`], [`Kyber768`], [`Kyber1024`] — legacy KEM size markers
//! - All cipher/process/content markers re-exported from [`crate::markers`]
//!
//! # Feature gate
//! The `key_controler` sub-module and the cipher impl blocks are gated behind
//! `legacy-pqclean` (now in default — see TODO in Cargo.toml).

// Legacy KEM key-control: only available with the legacy-pqclean feature.
#[cfg(feature = "legacy-pqclean")]
pub mod key_controler;

use std::{marker::PhantomData, path::PathBuf};
use crate::error::CryptError;

// Re-export all shared ZST markers from the thin markers shim so that the
// public `crate::core::kyber::*` glob continues to expose them.
pub use crate::markers::{
    Encryption, Decryption,
    Files, Message, Data,
    AES, AesGcmSiv, AesCtr, AesXts, XChaCha20, XChaCha20Poly1305,
};

/// Trait for Kyber cryptographic functions.
pub trait KyberFunctions {
    /// Encrypts a file at a given path with a passphrase, returning the encrypted data and nonce.
    fn encrypt_file(&mut self, path: PathBuf, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Encrypts a message with a passphrase, returning the encrypted data and nonce.
    fn encrypt_msg(&mut self, message: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Encrypts data with a passphrase, returning the encrypted data and nonce.
    fn encrypt_data(&mut self, data: Vec<u8>, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Decrypts a file at a given path with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_file(&self, path: PathBuf, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
    /// Decrypts a message with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_msg(&self, message: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
    /// Decrypts data with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_data(&self, data: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
}


/// Enum representing Kyber variants.
pub enum KyberVariant {
    Kyber512,
    Kyber768,
    Kyber1024,
}

/// Trait to specify Kyber size variants.
pub trait KyberSizeVariant {
    /// Returns the Kyber variant.
    fn variant() -> KyberVariant;
}

/// Legacy KEM size marker: Kyber-512.
///
/// Kept for source compatibility; will be deprecated in favour of `MlKem512` in Phase 2.
pub struct Kyber512;
/// Legacy KEM size marker: Kyber-768.
///
/// Kept for source compatibility; will be deprecated in favour of `MlKem768` in Phase 2.
pub struct Kyber768;
/// Legacy KEM size marker: Kyber-1024.
///
/// Kept for source compatibility; will be deprecated in favour of `MlKem1024` in Phase 2.
pub struct Kyber1024;

impl KyberSizeVariant for Kyber512 {
    fn variant() -> KyberVariant { KyberVariant::Kyber512 }
}

impl KyberSizeVariant for Kyber768 {
    fn variant() -> KyberVariant { KyberVariant::Kyber768 }
}

impl KyberSizeVariant for Kyber1024 {
    fn variant() -> KyberVariant { KyberVariant::Kyber1024 }
}

/// Represents the data structure for Kyber algorithm, including key and nonce.
#[derive(PartialEq, Debug, Clone)]
pub struct KyberData {
    key: Vec<u8>,
    nonce: String,
}

impl KyberData {
    /// Returns the cryptographic key.
    pub fn key(&self) -> Result<Vec<u8>, CryptError> {
        Ok(self.key.to_vec())
    }
    /// Returns the nonce.
    pub fn nonce(&self) -> Result<&str, CryptError> {
        Ok(&self.nonce)
    }
    /// Sets the nonce.
    pub fn set_nonce(&mut self, nonce: String) -> Result<(), CryptError> {
        self.nonce = nonce;
        Ok(())
    }
    /// Sets the cryptographic key.
    pub fn set_key(&mut self, key: Vec<u8>) -> Result<(), CryptError> {
        self.key = key;
        Ok(())
    }
}

/// Represents a generic Kyber structure with templated parameters for process status,
/// Kyber size, content status, and algorithm parameter.
pub struct Kyber<ProcessStatus = Encryption, KyberSize=Kyber1024, ContentStatus=Files, AlgorithmParam=AES>
where
    KyberSize: KyberSizeVariant,
{
    pub(crate) kyber_data: KyberData,
    hmac_size: usize,
    content_state: PhantomData<ContentStatus>,
    kyber_state: PhantomData<KyberSize>,
    algorithm_state: PhantomData<AlgorithmParam>,
    process_state: PhantomData<ProcessStatus>,
}

impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus, AlgorithmParam> Kyber<ProcessStatus, KyberSize, ContentStatus, AlgorithmParam> {
    /// Constructs a new Kyber instance with a key and an optional nonce.
    pub fn new(key: Vec<u8>, nonce: Option<String>) -> Result<Self, CryptError> {
        let nonce = nonce.map_or(String::new(), |data| data);
        Ok(Self {
            kyber_data: KyberData { key, nonce },
            hmac_size: 512,
            content_state: PhantomData,
            kyber_state: PhantomData,
            algorithm_state: PhantomData,
            process_state: PhantomData,
        })
    }

    /// Returns the cryptographic key.
    pub fn get_key(&self) -> Result<Vec<u8>, CryptError> {
        self.kyber_data.key()
    }

    /// Returns the nonce.
    pub fn get_nonce(&self) -> Result<&str, CryptError> {
        self.kyber_data.nonce()
    }

    /// Switches the HMAC size to SHA-256 (default is SHA-512).
    pub fn hmac_sha256(&mut self) -> Result<(), CryptError> {
        self.hmac_size = 256;
        Ok(())
    }
}

/// Usable when KyberSize = Kyber1024
impl Kyber<Encryption, Kyber1024, Files, AES> {
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber768
impl Kyber<Encryption, Kyber768, Files, AES> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AES>  {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber512
impl Kyber<Encryption, Kyber512, Files, AES> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber1024
impl Kyber<Encryption, Kyber1024, Files, AesGcmSiv> {
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AesGcmSiv>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AesGcmSiv> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AesGcmSiv>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AesGcmSiv> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber768
impl Kyber<Encryption, Kyber768, Files, AesGcmSiv> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AesGcmSiv>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AesGcmSiv> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AesGcmSiv>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AesGcmSiv>  {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber512
impl Kyber<Encryption, Kyber512, Files, AesGcmSiv> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AesGcmSiv>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AesGcmSiv> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AesGcmSiv>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AesGcmSiv> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber1024
impl Kyber<Encryption, Kyber1024, Files, AesCtr> {
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AesCtr>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AesCtr> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AesCtr>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AesCtr> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber768
impl Kyber<Encryption, Kyber768, Files, AesCtr> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AesCtr>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AesCtr> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AesCtr>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AesCtr>  {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber512
impl Kyber<Encryption, Kyber512, Files, AesCtr> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AesCtr>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AesCtr> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AesCtr>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AesCtr> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when AlgorithmParam = AES
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesGcmSiv> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesCtr> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_xts(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesXts> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn xchacha20poly1305(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20Poly1305> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}

/// Usable when AlgorithmParam = XChaCha20
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesGcmSiv> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesCtr> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_xts(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesXts> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn xchacha20poly1305(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20Poly1305> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}

/// Usable when AlgorithmParam = XChaCha20Poly1305
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20Poly1305> {
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesGcmSiv> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesCtr> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_xts(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesXts> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}

/// Usable when AlgorithmParam = AesGcmSiv
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AesGcmSiv> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn xchacha20poly1305(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20Poly1305> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesCtr> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_xts(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesXts> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}

/// Usable when AlgorithmParam = AesCtr
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AesCtr> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesGcmSiv> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_xts(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesXts> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn xchacha20poly1305(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20Poly1305> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}

/// Usable when AlgorithmParam = AesXts
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AesXts> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn xchacha20poly1305(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20Poly1305> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesGcmSiv> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AesCtr> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}

/// Usable when ContentStatus = Files
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, Files, AlgorithmParam> {
    pub fn message(self) -> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn data(self) -> Kyber<ProcessStatus, KyberSize, Data, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn is_file(self) -> bool { true }
    pub fn is_message(self) -> bool { false }
    pub fn is_data(self) -> bool { false }
}

/// Usable when ContentStatus = Message
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
    pub fn file(self) -> Kyber<ProcessStatus, KyberSize, Files, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn data(self) -> Kyber<ProcessStatus, KyberSize, Data, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn is_file(self) -> bool { false }
    pub fn is_message(self) -> bool { true }
    pub fn is_data(self) -> bool { false }
}

/// Usable when ContentStatus = Data
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, Data, AlgorithmParam> {
    pub fn file(self) -> Kyber<ProcessStatus, KyberSize, Files, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn message(self) -> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
    pub fn is_file(self) -> bool { false }
    pub fn is_message(self) -> bool { false }
    pub fn is_data(self) -> bool { true }
}

/// Usable when ProcessStatus = Encryption
impl<KyberSize: KyberSizeVariant, ContentStatus, AlgorithmParam> Kyber<Encryption, KyberSize, ContentStatus, AlgorithmParam> {
    pub fn decryption(self) -> Kyber<Decryption, KyberSize, Message, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}

/// Usable when ProcessStatus = Decryption
impl<KyberSize: KyberSizeVariant, ContentStatus, AlgorithmParam> Kyber<Decryption, KyberSize, ContentStatus, AlgorithmParam> {
    pub fn encryption(self) -> Kyber<Encryption, KyberSize, Files, AlgorithmParam> {
        Kyber { kyber_data: self.kyber_data, hmac_size: self.hmac_size, content_state: PhantomData, kyber_state: PhantomData, algorithm_state: PhantomData, process_state: PhantomData }
    }
}
