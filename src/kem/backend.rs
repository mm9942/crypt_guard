//! `KemBackend` trait and `KemId` constant enum.
//!
//! # Responsibility scope
//! Defines the abstract interface that every KEM algorithm implementation must satisfy.
//! Concrete impls live in `ml_kem.rs` (and future `preview/hqc_kem.rs`). This module
//! owns only the trait and the identifier enum — no algorithm logic.
//!
//! # Key types exported
//! - [`KemBackend`] — the core KEM trait
//! - [`KemId`] — stable identifier for each parameter set
//!
//! # Concurrency
//! The trait requires `Sized + Send + Sync + 'static`; no mutable state is held
//! by implementors — all operations are pure functions over borrowed key material.
//!
//! # Errors
//! Every fallible operation returns `Result<_, crate::error::CryptError>`.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::kem::backend::{KemBackend, KemId};
//! ```

use crate::error::CryptError;
use crate::kem::KemSize;

/// Stable identifier for each KEM parameter set.
///
/// # Description
/// Used in envelope headers and KDF domain-separation labels to identify
/// which KEM algorithm and security level was used for a given ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KemId {
    /// ML-KEM-512 (FIPS 203, security category 1).
    MlKem512,
    /// ML-KEM-768 (FIPS 203, security category 3 — recommended default).
    MlKem768,
    /// ML-KEM-1024 (FIPS 203, security category 5).
    MlKem1024,
}

/// Human-readable formatting for [`KemId`].
///
/// # Description
/// Renders the canonical algorithm name (`"ML-KEM-512"`, `"ML-KEM-768"`,
/// `"ML-KEM-1024"`), matching the FIPS 203 designation for each parameter set.
impl std::fmt::Display for KemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemId::MlKem512 => write!(f, "ML-KEM-512"),
            KemId::MlKem768 => write!(f, "ML-KEM-768"),
            KemId::MlKem1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

/// Abstract interface for a Key Encapsulation Mechanism (KEM) backend.
///
/// # Description
/// Implementors provide a complete KEM: key generation, encapsulation (sender side),
/// and decapsulation (receiver side). All operations take an explicit RNG where needed.
///
/// The associated types carry ownership semantics:
/// - `PublicKey` and `Ciphertext` need not be secret; they are safe to transmit.
/// - `SecretKey` and `SharedSecret` must implement [`zeroize::ZeroizeOnDrop`] to ensure
///   secret material is cleared from memory when the value is dropped.
///
/// # Concurrency
/// Implementations must be `Send + Sync`. All operations are pure functions; no shared
/// mutable state is permitted inside implementors.
///
/// # Errors
/// - [`CryptError::EncapsulationError`]: RNG failure or public-key validation failure.
/// - [`CryptError::DecapsulationError`]: ciphertext length mismatch or implicit rejection.
/// - [`CryptError::InvalidKemPublicKey`]: public key bytes are malformed.
/// - [`CryptError::InvalidKemSecretKey`]: secret key bytes are malformed.
/// - [`CryptError::InvalidKemCiphertext`]: ciphertext bytes are malformed.
///
/// # Examples
/// ```rust,no_run
/// use crypt_guard::kem::backend::KemBackend;
/// #[cfg(feature = "ml-kem-backend")]
/// {
///     use crypt_guard::kem::ml_kem::MlKem768Impl;
///     let mut rng = rand::thread_rng();
///     // let (pk, sk) = MlKem768Impl::keypair(&mut rng).unwrap();
/// }
/// ```
pub trait KemBackend: Sized + Send + Sync + 'static {
    /// Zero-sized marker for the parameter-set size axis.
    type Size: KemSize;

    /// Public (encapsulation) key type.
    type PublicKey: AsRef<[u8]> + Send + Sync;

    /// Secret (decapsulation) key type; must be zeroized on drop.
    type SecretKey: AsRef<[u8]> + zeroize::ZeroizeOnDrop + Send + Sync;

    /// Ciphertext produced by encapsulation.
    type Ciphertext: AsRef<[u8]> + Send + Sync;

    /// Shared secret produced by both sides; must be zeroized on drop.
    type SharedSecret: AsRef<[u8]> + zeroize::ZeroizeOnDrop + Send + Sync;

    /// Stable identifier for this KEM instance.
    const ID: KemId;

    /// Generate a fresh keypair.
    ///
    /// # Arguments
    /// - `rng` (`&mut impl rand_core::CryptoRng`): a cryptographically secure RNG.
    ///
    /// # Returns
    /// `Ok((public_key, secret_key))` on success.
    ///
    /// # Errors
    /// - [`CryptError::EncapsulationError`]: if the RNG fails.
    fn keypair(
        rng: &mut impl rand_core_010::CryptoRng,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptError>;

    /// Encapsulate: produce a ciphertext and the sender's shared secret.
    ///
    /// # Arguments
    /// - `pk` (`&Self::PublicKey`): the recipient's public key.
    /// - `rng` (`&mut impl rand_core::CryptoRng`): a cryptographically secure RNG.
    ///
    /// # Returns
    /// `Ok((ciphertext, shared_secret))` on success.
    ///
    /// # Errors
    /// - [`CryptError::EncapsulationError`]: if the public key is malformed or the RNG fails.
    fn encapsulate(
        pk: &Self::PublicKey,
        rng: &mut impl rand_core_010::CryptoRng,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptError>;

    /// Decapsulate: recover the shared secret from the ciphertext using the secret key.
    ///
    /// # Arguments
    /// - `sk` (`&Self::SecretKey`): the recipient's secret key.
    /// - `ct` (`&Self::Ciphertext`): the KEM ciphertext from the sender.
    ///
    /// # Returns
    /// `Ok(shared_secret)` on success.
    ///
    /// # Errors
    /// - [`CryptError::DecapsulationError`]: if the ciphertext or secret key is malformed.
    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptError>;
}

/// Re-export of the `rand_core` 0.10 crate under a stable alias.
///
/// # Description
/// Exposes the exact `rand_core` version used internally by the `ml-kem` backend so
/// callers can name the [`rand_core_010::CryptoRng`] bound required by [`KemBackend`]
/// without taking a direct dependency on that specific `rand_core` release.
pub use rand_core_010;

/// Zero-sized OS-backed cryptographic RNG that satisfies `rand_core_010::CryptoRng`.
///
/// # Description
/// Delegates to [`getrandom::fill`] for entropy. Intended for use in doc examples
/// and in code that needs a concrete `CryptoRng` implementor without pulling in
/// the full `rand` crate. All state is transient — construct freely.
///
/// # Concurrency
/// Stateless; safe to construct and use from any thread.
///
/// # Examples
/// ```rust,no_run
/// use crypt_guard::kem::backend::OsRng;
/// let mut rng = OsRng;
/// ```
pub struct OsRng;

/// Fallible RNG implementation for [`OsRng`] backed by [`getrandom::fill`].
///
/// # Description
/// Each method draws fresh entropy from the operating system. The associated error type
/// is [`core::convert::Infallible`] because OS entropy failures are surfaced as panics
/// inside the implementation rather than returned as recoverable errors.
impl rand_core_010::TryRng for OsRng {
    type Error = core::convert::Infallible;
    /// Returns a random `u32` drawn from OS entropy.
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u32::from_le_bytes(buf))
    }
    /// Returns a random `u64` drawn from OS entropy.
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("getrandom failed");
        Ok(u64::from_le_bytes(buf))
    }
    /// Fills `dst` entirely with OS entropy.
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("getrandom failed");
        Ok(())
    }
}

/// Marks [`OsRng`] as cryptographically secure.
///
/// # Description
/// This empty impl certifies that the entropy produced by [`OsRng`] is suitable for
/// cryptographic use, satisfying the [`KemBackend`] RNG bound.
impl rand_core_010::TryCryptoRng for OsRng {}
