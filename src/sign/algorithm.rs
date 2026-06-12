//! `SignAlgorithm` trait and supporting types.
//!
//! # Responsibility scope
//! Defines the abstract interface for digital signature algorithms. Concrete implementations
//! live in `ml_dsa.rs` and `slh_dsa.rs`. This module owns the trait, `SignatureMode` markers,
//! and the `Keypair<A>` convenience wrapper.
//!
//! # Key types exported
//! - [`SignAlgorithm`] — core signature trait
//! - [`SignatureMode`] — marker trait for signature modes
//! - [`Detached`] — mode marker: signature is separate from message
//! - [`MessageMode`] — mode marker: signature is prepended to message
//! - [`Keypair`] — convenience holder for a signing + verifying key pair
//!
//! # Concurrency
//! `SignAlgorithm` requires `Send + Sync + 'static`. All operations are pure functions
//! over borrowed data; no mutable shared state.
//!
//! # Errors
//! Every fallible operation returns `Result<_, crate::error::CryptError>`.
//!
//! # Examples
//! ```rust,no_run
//! #[cfg(feature = "ml-dsa-backend")]
//! {
//!     use crypt_guard::sign::algorithm::SignAlgorithm;
//! }
//! ```

use crate::error::CryptError;
use zeroize::ZeroizeOnDrop;

/// Marker trait for signature output modes.
///
/// # Description
/// Two modes are supported: [`Detached`] (signature bytes separate from the original message)
/// and [`MessageMode`] (signature prepended to the message). The mode is a type-level marker
/// so that the type system distinguishes the two at compile time.
///
/// # Concurrency
/// All implementors are ZST markers; `Send + Sync` trivially.
pub trait SignatureMode: Send + Sync + 'static {}

/// Signature mode: the signature is stored separately from the message.
///
/// # Description
/// Use `Detached` when you want to distribute the original message and the signature
/// independently. The signature can be verified against the original message bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Detached;
impl SignatureMode for Detached {}

/// Signature mode: the signature bytes are prepended to the message.
///
/// # Description
/// Use `MessageMode` when the signed+message bundle is transmitted as a single blob.
/// Verification extracts the original message bytes from the bundle.
#[derive(Clone, Copy, Debug, Default)]
pub struct MessageMode;
impl SignatureMode for MessageMode {}

/// Abstract interface for a digital signature algorithm.
///
/// # Description
/// Implementors provide keypair generation, message signing, and signature verification.
/// The associated types carry ownership semantics:
/// - `SigningKey` must implement `ZeroizeOnDrop` to ensure secret material is wiped.
/// - `VerifyingKey` is not secret; no zeroization requirement.
/// - `Sig` holds raw signature bytes.
///
/// # Concurrency
/// Implementations must be `Send + Sync`. All operations are pure functions; no shared
/// mutable state is permitted inside implementors.
///
/// # Errors
/// - [`CryptError::SigningFailed`]: failure to produce a signature.
/// - [`CryptError::SignatureVerificationFailed`]: the signature did not verify.
///
/// # Examples
/// ```rust,no_run
/// #[cfg(feature = "ml-dsa-backend")]
/// {
///     use crypt_guard::sign::algorithm::SignAlgorithm;
///     use crypt_guard::sign::ml_dsa::MlDsa65Impl;
///     use crypt_guard::kem::backend::OsRng;
///     let mut rng = OsRng;
///     let (sk, vk) = MlDsa65Impl::keypair(&mut rng).unwrap();
///     let sig = MlDsa65Impl::sign(&sk, b"hello").unwrap();
///     MlDsa65Impl::verify(&vk, b"hello", &sig).unwrap();
/// }
/// ```
pub trait SignAlgorithm: Sized + Send + Sync + 'static {
    /// The signing (secret) key. Must be zeroized on drop.
    type SigningKey: ZeroizeOnDrop + Send + Sync;

    /// The verifying (public) key. No secret material; no zeroization required.
    type VerifyingKey: Clone + Send + Sync;

    /// The signature bytes.
    type Sig: AsRef<[u8]> + Send + Sync;

    /// Generate a fresh signing+verifying keypair.
    ///
    /// # Arguments
    /// - `rng` (`&mut impl CryptoRng`): cryptographically secure RNG.
    ///
    /// # Returns
    /// `Ok((signing_key, verifying_key))` on success.
    ///
    /// # Errors
    /// - [`CryptError::SigningFailed`]: RNG failure.
    fn keypair(
        rng: &mut impl crate::kem::backend::rand_core_010::CryptoRng,
    ) -> Result<(Self::SigningKey, Self::VerifyingKey), CryptError>;

    /// Sign a message.
    ///
    /// # Arguments
    /// - `sk` (`&Self::SigningKey`): the signing key.
    /// - `message` (`&[u8]`): the message bytes to sign.
    ///
    /// # Returns
    /// `Ok(Sig)` containing the raw signature bytes.
    ///
    /// # Errors
    /// - [`CryptError::SigningFailed`]: the signing operation failed.
    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Sig, CryptError>;

    /// Verify a signature over a message.
    ///
    /// # Arguments
    /// - `vk` (`&Self::VerifyingKey`): the verifying key.
    /// - `message` (`&[u8]`): the original message bytes.
    /// - `sig` (`&Self::Sig`): the signature to verify.
    ///
    /// # Returns
    /// `Ok(())` if valid.
    ///
    /// # Errors
    /// - [`CryptError::SignatureVerificationFailed`]: the signature is invalid.
    fn verify(
        vk: &Self::VerifyingKey,
        message: &[u8],
        sig: &Self::Sig,
    ) -> Result<(), CryptError>;
}

/// Convenience pair holding both keys from a `SignAlgorithm::keypair()` call.
///
/// # Description
/// Wraps a signing key and its paired verifying key. The verifying key can be
/// cloned and shared freely; the signing key is secret and will be zeroized on drop.
///
/// # Concurrency
/// `Send + Sync` where `A: SignAlgorithm`.
pub struct Keypair<A: SignAlgorithm> {
    /// The secret signing key. Zeroized on drop.
    pub signing_key: A::SigningKey,
    /// The corresponding verifying (public) key.
    pub verifying_key: A::VerifyingKey,
}

impl<A: SignAlgorithm> Keypair<A> {
    /// Construct a `Keypair` from its constituent parts.
    ///
    /// # Arguments
    /// - `signing_key` (`A::SigningKey`): the signing key.
    /// - `verifying_key` (`A::VerifyingKey`): the verifying key.
    ///
    /// # Returns
    /// A new `Keypair<A>`.
    pub fn new(signing_key: A::SigningKey, verifying_key: A::VerifyingKey) -> Self {
        Self { signing_key, verifying_key }
    }

    /// Generate a fresh `Keypair<A>` using the provided RNG.
    ///
    /// # Arguments
    /// - `rng` (`&mut impl CryptoRng`): cryptographically secure RNG.
    ///
    /// # Returns
    /// `Ok(Keypair<A>)` on success.
    ///
    /// # Errors
    /// Propagates errors from `A::keypair`.
    pub fn generate(
        rng: &mut impl crate::kem::backend::rand_core_010::CryptoRng,
    ) -> Result<Self, CryptError> {
        let (signing_key, verifying_key) = A::keypair(rng)?;
        Ok(Self { signing_key, verifying_key })
    }
}
