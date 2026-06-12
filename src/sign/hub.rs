//! Blanket `Signature<A, S>` struct wrapping any `SignAlgorithm + SignatureMode`.
//!
//! # Responsibility scope
//! Provides one generic `Signature<A, S>` struct that replaces the 10 hand-written
//! impl blocks in the legacy path. Each method delegates to the corresponding
//! `SignAlgorithm` method; the type parameters enforce at compile time that only valid
//! `(algorithm, mode)` combinations are assembled.
//!
//! This module does NOT touch the legacy `Signature<A, S>` types in `src/legacy/`.
//! The two coexist until Phase 4 re-wires the facade.
//!
//! # Key types exported
//! - [`Signature`] — generic signature container
//!
//! # Concurrency
//! `Signature<A, S>` holds no mutable state; it is trivially `Send + Sync`.
//!
//! # Examples
//! ```rust,no_run
//! #[cfg(feature = "ml-dsa-backend")]
//! {
//!     use crypt_guard::sign::{hub::Signature, algorithm::{Detached, SignAlgorithm}};
//!     use crypt_guard::sign::ml_dsa::MlDsa65Impl;
//!     use crypt_guard::kem::backend::OsRng;
//!     let mut rng = OsRng;
//!     let mut sig = Signature::<MlDsa65Impl, Detached>::new();
//!     let (sk, vk) = MlDsa65Impl::keypair(&mut rng).unwrap();
//!     let s = sig.sign_detached(&sk, b"hello world").unwrap();
//!     sig.verify_detached(&vk, b"hello world", &s).unwrap();
//! }
//! ```

use std::marker::PhantomData;
use crate::error::CryptError;
use crate::sign::algorithm::{SignAlgorithm, SignatureMode};

/// Generic signature container parameterised over algorithm `A` and mode `S`.
///
/// # Description
/// Holds no persistent state. All operations are pure; the struct exists to scope the
/// type parameters together and provide an ergonomic API surface that mirrors the legacy
/// `Signature<A, S>` without the 10 separate hand-written impl blocks.
///
/// # Type parameters
/// - `A: SignAlgorithm` — the signature algorithm (e.g. `MlDsa65Impl`).
/// - `S: SignatureMode` — the mode marker (`Detached` or `MessageMode`).
///
/// # Concurrency
/// Zero-sized logic; `Send + Sync` trivially.
pub struct Signature<A: SignAlgorithm, S: SignatureMode> {
    _algorithm: PhantomData<A>,
    _mode: PhantomData<S>,
}

impl<A: SignAlgorithm, S: SignatureMode> Default for Signature<A, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: SignAlgorithm, S: SignatureMode> Signature<A, S> {
    /// Create a new `Signature<A, S>` instance.
    ///
    /// # Returns
    /// A new zero-allocation `Signature<A, S>`.
    pub fn new() -> Self {
        Self {
            _algorithm: PhantomData,
            _mode: PhantomData,
        }
    }

    /// Generate a fresh keypair for algorithm `A`.
    ///
    /// # Arguments
    /// - `rng`: cryptographically secure RNG.
    ///
    /// # Returns
    /// `Ok((signing_key, verifying_key))`.
    ///
    /// # Errors
    /// Propagates from [`SignAlgorithm::keypair`].
    pub fn keypair(
        &self,
        rng: &mut impl crate::kem::backend::rand_core_010::CryptoRng,
    ) -> Result<(A::SigningKey, A::VerifyingKey), CryptError> {
        A::keypair(rng)
    }

    /// Produce a detached signature over `message`.
    ///
    /// # Arguments
    /// - `sk` (`&A::SigningKey`): the signing key.
    /// - `message` (`&[u8]`): message bytes to sign.
    ///
    /// # Returns
    /// `Ok(A::Sig)` — the raw signature bytes.
    ///
    /// # Errors
    /// - [`CryptError::SigningFailed`]: the signing operation failed.
    pub fn sign_detached(
        &self,
        sk: &A::SigningKey,
        message: &[u8],
    ) -> Result<A::Sig, CryptError> {
        A::sign(sk, message)
    }

    /// Verify a detached signature.
    ///
    /// # Arguments
    /// - `vk` (`&A::VerifyingKey`): the verifying key.
    /// - `message` (`&[u8]`): the original message bytes.
    /// - `sig` (`&A::Sig`): the signature to verify.
    ///
    /// # Returns
    /// `Ok(())` if valid.
    ///
    /// # Errors
    /// - [`CryptError::SignatureVerificationFailed`]: signature did not verify.
    pub fn verify_detached(
        &self,
        vk: &A::VerifyingKey,
        message: &[u8],
        sig: &A::Sig,
    ) -> Result<(), CryptError> {
        A::verify(vk, message, sig)
    }
}
