//! Typed newtypes for ML-KEM key material.
//!
//! # Responsibility scope
//! This module owns the concrete newtype wrappers around raw byte vectors that hold
//! ML-KEM cryptographic material. Every secret-bearing type implements [`zeroize::ZeroizeOnDrop`]
//! so that key bytes are overwritten when the value is dropped.
//!
//! # Key types exported
//! - [`MlKemPublicKey`] — encapsulation key (public; not zeroized, safe to share)
//! - [`MlKemSecretKey`] — decapsulation key (secret; `ZeroizeOnDrop`)
//! - [`KemCiphertext`] — KEM ciphertext produced by encapsulation (not secret itself)
//! - [`KemSharedSecret`] — shared secret derived from encapsulation/decapsulation (`ZeroizeOnDrop`)
//!
//! # Concurrency
//! All types are `Send + Sync` (they contain only `Vec<u8>` and a `PhantomData` marker).
//!
//! # Errors
//! This module produces no errors directly; it is data-only.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::kem::types::KemSharedSecret;
//! let ss = KemSharedSecret::from_bytes(vec![0u8; 32]);
//! assert_eq!(ss.as_ref().len(), 32);
//! ```

use std::marker::PhantomData;
use zeroize::ZeroizeOnDrop;

/// Marker for the ML-KEM security parameter set (512, 768, or 1024).
pub trait KemSize: Send + Sync + 'static {}

/// ML-KEM public (encapsulation) key newtype.
///
/// # Description
/// Wraps the raw public key bytes for a given ML-KEM parameter set `N`.
/// Not secret; safe to transmit. Does not implement `ZeroizeOnDrop` because
/// public keys carry no secret material.
///
/// # Concurrency
/// `Send + Sync` — contains only a `Vec<u8>` and a `PhantomData` marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey<N: KemSize> {
    bytes: Vec<u8>,
    _marker: PhantomData<N>,
}

impl<N: KemSize> MlKemPublicKey<N> {
    /// Construct from raw bytes.
    ///
    /// # Arguments
    /// - `bytes` (`Vec<u8>`): raw key bytes as returned by the KEM backend.
    ///
    /// # Returns
    /// A new `MlKemPublicKey<N>`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

/// Borrows the raw public-key bytes.
///
/// # Returns
/// A `&[u8]` slice over the wrapped encapsulation-key bytes.
impl<N: KemSize> AsRef<[u8]> for MlKemPublicKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM secret (decapsulation) key newtype.
///
/// # Description
/// Wraps the raw secret key bytes. Secret-bearing; implements [`ZeroizeOnDrop`] so
/// the bytes are overwritten when this value is dropped.
///
/// # Concurrency
/// `Send + Sync` — contains only a `Vec<u8>` and a `PhantomData` marker.
#[derive(ZeroizeOnDrop)]
pub struct MlKemSecretKey<N: KemSize> {
    #[zeroize(skip)]
    _marker: PhantomData<N>,
    bytes: Vec<u8>,
}

impl<N: KemSize> MlKemSecretKey<N> {
    /// Construct from raw bytes.
    ///
    /// # Arguments
    /// - `bytes` (`Vec<u8>`): raw key bytes as returned by the KEM backend.
    ///
    /// # Returns
    /// A new `MlKemSecretKey<N>`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

/// Borrows the raw secret-key bytes.
///
/// # Returns
/// A `&[u8]` slice over the wrapped decapsulation-key bytes. The borrow does not
/// affect the [`ZeroizeOnDrop`] guarantee; bytes are still cleared on drop.
impl<N: KemSize> AsRef<[u8]> for MlKemSecretKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// KEM ciphertext newtype.
///
/// # Description
/// Wraps the ciphertext produced during KEM encapsulation. The ciphertext is not secret
/// and does not require zeroization; it is transmitted to the decapsulating party.
///
/// # Concurrency
/// `Send + Sync`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemCiphertext {
    bytes: Vec<u8>,
}

impl KemCiphertext {
    /// Construct from raw bytes.
    ///
    /// # Arguments
    /// - `bytes` (`Vec<u8>`): ciphertext bytes as returned by the encapsulation operation.
    ///
    /// # Returns
    /// A new `KemCiphertext`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Borrows the raw ciphertext bytes.
///
/// # Returns
/// A `&[u8]` slice over the wrapped KEM ciphertext bytes.
impl AsRef<[u8]> for KemCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// KEM shared secret newtype.
///
/// # Description
/// Holds the shared secret produced by both KEM encapsulation (sender) and decapsulation
/// (receiver). Secret-bearing; implements [`ZeroizeOnDrop`].
///
/// # Concurrency
/// `Send + Sync`.
#[derive(ZeroizeOnDrop)]
pub struct KemSharedSecret {
    bytes: Vec<u8>,
}

impl KemSharedSecret {
    /// Construct from raw bytes.
    ///
    /// # Arguments
    /// - `bytes` (`Vec<u8>`): raw shared-secret bytes.
    ///
    /// # Returns
    /// A new `KemSharedSecret`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Borrows the raw shared-secret bytes.
///
/// # Returns
/// A `&[u8]` slice over the wrapped shared-secret bytes. The borrow does not affect
/// the [`ZeroizeOnDrop`] guarantee; bytes are still cleared on drop.
impl AsRef<[u8]> for KemSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
