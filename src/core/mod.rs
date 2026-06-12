//! Core cryptographic hub: cipher implementations, Kyber typestate, and KEM dispatch.
//!
//! # Module declarations
//! - `kdf` — pqcrypto-backed Falcon/Dilithium signing (legacy-pqclean)
//! - `kyber` — `Kyber<P,K,D,C>` typestate + KEM traits + cipher markers
//! - `cipher_*` — six symmetric cipher implementations
//!
//! # Key public types
//! - [`KeyControlVariant`] — runtime KEM dispatch enum (legacy-pqclean only)
//! - [`CryptographicFunctions`] — abstract encrypt/decrypt trait
//! - All types from `kyber::*` re-exported via `pub use kyber::*`

/// Functions for usage of falcon and dilithium (legacy pqcrypto — gated by legacy-pqclean).
#[cfg(feature = "legacy-pqclean")]
pub mod kdf;

/// Functions for usage of kyber for key generation and the Kyber typestate.
pub mod kyber;

/// AES-256-GCM-SIV symmetric cipher implementation.
pub mod cipher_aes_gcm_siv;
/// AES-256-CTR symmetric cipher implementation.
pub mod cipher_aes_ctr;
/// AES-256-XTS symmetric cipher implementation.
pub mod cipher_aes_xts;
/// AES-256-CBC + HMAC symmetric cipher implementation.
pub mod cipher_aes;
/// XChaCha20 stream cipher implementation.
pub mod cipher_xchacha;
/// XChaCha20-Poly1305 AEAD implementation.
pub mod cipher_xchacha_poly;

use crate::{cryptography::*, error::CryptError};

// Legacy KEM key-control types: only present when legacy-pqclean is active.
#[cfg(feature = "legacy-pqclean")]
pub use kyber::key_controler::*;

/// Runtime KEM dispatch enum.
///
/// Selects among Kyber-512/768/1024 KEM implementations at runtime based on the provided
/// [`KeyEncapMechanism`] variant. Delegates `encap` and `decap` to the appropriate
/// `KeyControl<KeyControKyberN>`. Only available with the `legacy-pqclean` feature.
#[cfg(feature = "legacy-pqclean")]
pub enum KeyControlVariant {
    Kyber1024(KeyControl<KeyControKyber1024>),
    Kyber768(KeyControl<KeyControKyber768>),
    Kyber512(KeyControl<KeyControKyber512>),
}

#[cfg(feature = "legacy-pqclean")]
impl KeyControlVariant {
    /// Creates a new `KeyControlVariant` from a [`KeyEncapMechanism`].
    pub fn new(keytype: KeyEncapMechanism) -> Self {
        match keytype {
            KeyEncapMechanism::Kyber1024 => Self::Kyber1024(KeyControl::<KeyControKyber1024>::new()),
            KeyEncapMechanism::Kyber768 => Self::Kyber768(KeyControl::<KeyControKyber768>::new()),
            KeyEncapMechanism::Kyber512 => Self::Kyber512(KeyControl::<KeyControKyber512>::new()),
        }
    }

    /// Encapsulates a shared secret using the given public key bytes.
    pub fn encap(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        match self {
            KeyControlVariant::Kyber1024(k) => k.encap(public_key),
            KeyControlVariant::Kyber768(k) => k.encap(public_key),
            KeyControlVariant::Kyber512(k) => k.encap(public_key),
        }
    }

    /// Decapsulates a shared secret from the given secret key and ciphertext bytes.
    pub fn decap(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptError> {
        match self {
            KeyControlVariant::Kyber1024(k) => k.decap(secret_key, ciphertext),
            KeyControlVariant::Kyber768(k) => k.decap(secret_key, ciphertext),
            KeyControlVariant::Kyber512(k) => k.decap(secret_key, ciphertext),
        }
    }
}

/// Abstract encrypt/decrypt trait.
///
/// Defines the minimal interface for a type that can encrypt/decrypt data using a
/// public or secret key respectively.
pub trait CryptographicFunctions {
    /// Encrypts data using a public key, returning the encrypted data and a new key.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Decrypts data using a secret key and a given ciphertext.
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
}
