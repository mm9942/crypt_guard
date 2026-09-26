//! Core cryptographic hub: cipher implementations, Kyber typestate, and KEM dispatch.
//!
//! # Module declarations
//! - `kdf` — pqcrypto-backed Falcon/Dilithium signing (legacy-pqclean)
//! - `kyber` — legacy `Kyber<P,K,D,C>` typestate (still has the key_controler sub-module)
//! - `hub` — Phase 3 new hub: same `Kyber` struct, EncryptFunctions/DecryptFunctions traits,
//!            ML-KEM + HKDF + Envelope-wired cipher impls
//! - `cipher_*` — six symmetric cipher implementations
//!
//! # Key public types
//! - [`KeyControlVariant`] — runtime KEM dispatch enum (legacy-pqclean only)
//! - [`CryptographicFunctions`] — abstract encrypt/decrypt trait
//! - All types from `hub::*` re-exported (including Kyber, KyberFunctions, etc.)

/// Functions for usage of falcon and dilithium (legacy pqcrypto — gated by legacy-pqclean).
#[cfg(feature = "legacy-pqclean")]
pub mod kdf;

/// Legacy hub module (src/core/kyber/): keeps KyberData, Kyber struct, KyberFunctions trait,
/// KyberSizeVariant, deprecated size markers, and key_controler (legacy-pqclean).
pub mod kyber;

/// Legacy CGv2 hub module (src/core/hub/): EncryptFunctions + DecryptFunctions
/// traits, FIPS primary size markers, and Envelope-wired cipher implementations.
///
/// This path is intentionally available only for explicit CGv2 compatibility
/// migrations; new applications should use [`crate::pq_hpke`].
#[cfg(feature = "cgv2-compat")]
pub mod hub;

/// AES-256-CBC + HMAC symmetric cipher implementation.
#[cfg(feature = "legacy-aes")]
pub mod cipher_aes;
/// AES-256-CTR symmetric cipher implementation.
#[cfg(feature = "aes-ctr")]
pub mod cipher_aes_ctr;
/// AES-256-GCM-SIV symmetric cipher implementation.
#[cfg(any(feature = "aes-gcm-siv-cipher", feature = "legacy-pqclean"))]
pub mod cipher_aes_gcm_siv;
/// AES-256-XTS symmetric cipher implementation.
#[cfg(feature = "aes-xts")]
pub mod cipher_aes_xts;
/// XChaCha20 stream cipher implementation.
pub mod cipher_xchacha;
/// XChaCha20-Poly1305 AEAD implementation.
pub mod cipher_xchacha_poly;

use crate::error::CryptError;

// Legacy KEM key-control types: only present when legacy-pqclean is active.
#[cfg(feature = "legacy-pqclean")]
pub use kyber::key_controler::*;
// KEM selector enum used by the legacy runtime-dispatch constructor below.
#[cfg(feature = "legacy-pqclean")]
use crate::cryptography::KeyEncapMechanism;

/// Runtime KEM dispatch enum.
///
/// Selects among Kyber-512/768/1024 KEM implementations at runtime based on the provided
/// [`KeyEncapMechanism`] variant. Delegates `encap` and `decap` to the appropriate
/// `KeyControl<KeyControKyberN>`. Only available with the `legacy-pqclean` feature.
#[cfg(feature = "legacy-pqclean")]
pub enum KeyControlVariant {
    /// Kyber-1024 variant.
    Kyber1024(KeyControl<KeyControKyber1024>),
    /// Kyber-768 variant.
    Kyber768(KeyControl<KeyControKyber768>),
    /// Kyber-512 variant.
    Kyber512(KeyControl<KeyControKyber512>),
}

#[cfg(feature = "legacy-pqclean")]
impl KeyControlVariant {
    /// Creates a new `KeyControlVariant` from a [`KeyEncapMechanism`].
    pub fn new(keytype: KeyEncapMechanism) -> Self {
        match keytype {
            KeyEncapMechanism::Kyber1024 => {
                Self::Kyber1024(KeyControl::<KeyControKyber1024>::new())
            }
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
