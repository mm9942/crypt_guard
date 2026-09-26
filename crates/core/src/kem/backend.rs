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
//! use crypt_guard_core::kem::backend::{KemBackend, KemId};
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

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
/// use crypt_guard_core::kem::backend::KemBackend;
/// #[cfg(feature = "ml-kem-backend")]
/// {
///     use crypt_guard_core::kem::ml_kem::MlKem768Impl;
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
/// use crypt_guard_core::kem::backend::OsRng;
/// let mut rng = OsRng;
/// ```
pub struct OsRng;

/// Fallible RNG implementation for [`OsRng`] backed by [`getrandom::fill`].
///
/// # Description
/// Each method draws fresh entropy from the operating system. The associated error type
/// is [`core::convert::Infallible`] because OS entropy failures are surfaced as panics
/// inside the implementation rather than returned as recoverable errors.
///
/// # Panics
/// Every method panics (via `.expect("getrandom failed")`) if the underlying
/// [`getrandom::fill`] call fails — for example, if the OS entropy source is
/// unavailable or the platform is unsupported. This is a deliberate trade-off:
/// [`OsRng`]'s `Error` type is [`core::convert::Infallible`], which cannot carry
/// a real error value, so an OS-level failure has no way to be reported to the
/// caller except by panicking. Applications that must not panic on entropy
/// failure — long-running services, code invoked from a context where
/// unwinding/aborting is unacceptable — should use [`TryOsRng`] instead, which
/// surfaces `getrandom::Error` as an ordinary `Result` rather than panicking.
// Deliberate: see the `# Panics` section above — `Error = Infallible` leaves
// panicking as the only way to surface an OS entropy failure here.
#[allow(clippy::expect_used)]
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

/// Zero-sized OS-backed cryptographic RNG that surfaces entropy failures as `Err`
/// instead of panicking.
///
/// # Description
/// Delegates to [`getrandom::fill`] for entropy, exactly like [`OsRng`], but never
/// panics: an OS entropy failure is returned as `Err(getrandom::Error)` from every
/// method instead of being unwrapped internally. Prefer this over [`OsRng`] in any
/// context where a panic (and the resulting unwind or abort) is unacceptable —
/// for example inside a library that must propagate errors to its own caller, or
/// a long-running service that should keep running (and retry, log, or fail a
/// single request) rather than crash on a transient entropy-source hiccup.
///
/// All state is transient — construct freely.
///
/// # Concurrency
/// Stateless; safe to construct and use from any thread.
///
/// # Examples
/// ```rust,no_run
/// use crypt_guard_core::kem::backend::TryOsRng;
/// use crypt_guard_core::kem::backend::rand_core_010::TryRng;
///
/// let mut rng = TryOsRng;
/// let mut buf = [0u8; 32];
/// rng.try_fill_bytes(&mut buf).expect("OS entropy source failed");
/// ```
pub struct TryOsRng;

/// Fallible RNG implementation for [`TryOsRng`] backed by [`getrandom::fill`].
///
/// # Description
/// Each method draws fresh entropy from the operating system and reports a
/// failure to do so as `Err(getrandom::Error)`, without panicking.
impl rand_core_010::TryRng for TryOsRng {
    type Error = getrandom::Error;
    /// Returns a random `u32` drawn from OS entropy, or the underlying
    /// [`getrandom::Error`] on failure.
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
    /// Returns a random `u64` drawn from OS entropy, or the underlying
    /// [`getrandom::Error`] on failure.
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
    /// Fills `dst` entirely with OS entropy, or returns the underlying
    /// [`getrandom::Error`] on failure.
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

/// Marks [`TryOsRng`] as cryptographically secure.
///
/// # Description
/// This empty impl certifies that the entropy produced by [`TryOsRng`] is
/// suitable for cryptographic use.
///
/// Note that [`rand_core_010::CryptoRng`] (the bound [`KemBackend`] requires) is
/// defined as `TryCryptoRng<Error = Infallible>`, so [`TryOsRng`] — whose error
/// type is [`getrandom::Error`], not `Infallible` — does not itself satisfy that
/// narrower bound and cannot be passed directly to [`KemBackend`] methods. It is
/// meant for call sites that consume [`rand_core_010::TryRng`] /
/// [`rand_core_010::TryCryptoRng`] directly and want to handle entropy failures
/// as an ordinary `Result` instead of a panic.
impl rand_core_010::TryCryptoRng for TryOsRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core_010::TryRng;

    /// `TryOsRng::try_fill_bytes` should draw real OS entropy: filling a
    /// reasonably large buffer and getting back all zero bytes has
    /// astronomically small probability (2^-256 and below for the sizes used
    /// here) and would indicate the RNG is not actually wired up to entropy.
    #[test]
    fn try_os_rng_fills_buffer_with_nonzero_bytes() {
        let mut rng = TryOsRng;
        let mut buf = [0u8; 32];
        rng.try_fill_bytes(&mut buf)
            .expect("OS entropy source should be available in the test environment");
        assert!(
            buf.iter().any(|&b| b != 0),
            "a 32-byte OS-entropy fill should overwhelmingly not be all zero"
        );
    }

    #[test]
    fn try_os_rng_next_u32_and_u64_are_not_trivially_zero() {
        let mut rng = TryOsRng;
        let a = rng
            .try_next_u32()
            .expect("OS entropy source should be available");
        let b = rng
            .try_next_u64()
            .expect("OS entropy source should be available");
        // Not a strict guarantee, but failing would be a 1-in-4-billion (or
        // 1-in-2^64) coincidence and far more likely indicates a bug.
        assert_ne!(a, 0);
        assert_ne!(b, 0);
    }

    /// [`OsRng`] (the panicking RNG) should still function normally end-to-end.
    #[test]
    fn os_rng_fills_buffer_with_nonzero_bytes() {
        let mut rng = OsRng;
        let mut buf = [0u8; 32];
        rng.try_fill_bytes(&mut buf)
            .expect("OS entropy source should be available in the test environment");
        assert!(buf.iter().any(|&b| b != 0));
    }
}
