//! ML-DSA implementations of [`SignAlgorithm`] (FIPS 204).
//!
//! # Responsibility scope
//! Provides three zero-sized marker types — [`MlDsa44Impl`], [`MlDsa65Impl`],
//! [`MlDsa87Impl`] — each implementing [`SignAlgorithm`] via the RustCrypto `ml-dsa`
//! crate (FIPS 204). The `ml-dsa` crate is unaudited as of 2026-06; see crate docs.
//!
//! # Key serialization
//! - `SigningKey`: serialized via `KeyExport::to_bytes()` (returns a 32-byte seed);
//!   restored via `KeyInit::new_from_slice`.
//! - `VerifyingKey`: serialized via `KeyExport::to_bytes()` (returns the encoded key);
//!   restored via `KeyInit::new_from_slice`.
//!
//! # Security notice
//! The `ml-dsa` crate has NOT been independently audited (stated in its own README).
//! It is wrapped here behind the `SignAlgorithm` trait so that a future audited
//! replacement can be substituted without changing call sites.
//!
//! # Examples
//! ```rust,no_run
//! #[cfg(feature = "ml-dsa-backend")]
//! {
//!     use crypt_guard::sign::{SignAlgorithm, ml_dsa::MlDsa65Impl};
//!     use crypt_guard::kem::backend::OsRng;
//!     let mut rng = OsRng;
//!     let (sk, vk) = MlDsa65Impl::keypair(&mut rng).unwrap();
//!     let sig = MlDsa65Impl::sign(&sk, b"test message").unwrap();
//!     MlDsa65Impl::verify(&vk, b"test message", &sig).unwrap();
//! }
//! ```

use ml_dsa::{
    Generate, KeyExport, KeyInit, MlDsa44, MlDsa65, MlDsa87, Signature, SignatureEncoding, Signer,
    SigningKey, Verifier, VerifyingKey,
};
// Keypair trait provides .verifying_key() on SigningKey.
use ml_dsa::Keypair as MlDsaKeypairTrait;

use crate::error::CryptError;
use crate::kem::backend::rand_core_010;
use crate::sign::algorithm::SignAlgorithm;
use zeroize::ZeroizeOnDrop;

/// ML-DSA signing key newtype (secret; `ZeroizeOnDrop`).
///
/// # Description
/// Wraps the raw 32-byte seed bytes for a `SigningKey<P>`. Secret-bearing; wiped on drop.
///
/// # Concurrency
/// `Send + Sync`.
#[derive(ZeroizeOnDrop)]
pub struct MlDsaSigningKey(Vec<u8>);

impl MlDsaSigningKey {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA verifying key newtype (public; no zeroization).
///
/// # Description
/// Wraps the encoded verifying-key bytes. Safe to share freely.
///
/// # Concurrency
/// `Send + Sync`.
#[derive(Clone, Debug)]
pub struct MlDsaVerifyingKey(Vec<u8>);

impl MlDsaVerifyingKey {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA signature newtype.
///
/// # Description
/// Wraps the raw signature bytes. Not secret.
///
/// # Concurrency
/// `Send + Sync`.
#[derive(Clone, Debug)]
pub struct MlDsaSignature(Vec<u8>);

impl MlDsaSignature {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Borrow the raw signature bytes of an [`MlDsaSignature`].
///
/// # Description
/// Exposes the wrapped signature byte vector as a `&[u8]` slice, enabling the
/// type to satisfy the [`SignAlgorithm::Sig`] bound (`AsRef<[u8]>`).
impl AsRef<[u8]> for MlDsaSignature {
    /// Return the signature bytes as a slice.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Implement `SignAlgorithm` for one ML-DSA parameter set.
macro_rules! impl_ml_dsa {
    ($impl_ty:ty, $param:ty) => {
        impl SignAlgorithm for $impl_ty {
            type SigningKey = MlDsaSigningKey;
            type VerifyingKey = MlDsaVerifyingKey;
            type Sig = MlDsaSignature;

            fn keypair(
                rng: &mut impl rand_core_010::CryptoRng,
            ) -> Result<(Self::SigningKey, Self::VerifyingKey), CryptError> {
                let sk: SigningKey<$param> = Generate::generate_from_rng(rng);
                // MlDsaKeypairTrait provides .verifying_key()
                let vk: VerifyingKey<$param> = MlDsaKeypairTrait::verifying_key(&sk);
                // Serialize: signing key as seed (32 bytes), verifying key as encoded bytes.
                let sk_bytes = KeyExport::to_bytes(&sk).as_slice().to_vec();
                let vk_bytes = KeyExport::to_bytes(&vk).as_slice().to_vec();
                Ok((
                    MlDsaSigningKey::from_bytes(sk_bytes),
                    MlDsaVerifyingKey::from_bytes(vk_bytes),
                ))
            }

            fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Sig, CryptError> {
                let signing_key = SigningKey::<$param>::new_from_slice(sk.as_bytes())
                    .map_err(|_| CryptError::SigningFailed)?;
                let sig: Signature<$param> = Signer::sign(&signing_key, message);
                Ok(MlDsaSignature(sig.to_vec()))
            }

            fn verify(
                vk: &Self::VerifyingKey,
                message: &[u8],
                sig: &Self::Sig,
            ) -> Result<(), CryptError> {
                let verifying_key = VerifyingKey::<$param>::new_from_slice(vk.as_bytes())
                    .map_err(|_| CryptError::SignatureVerificationFailed)?;
                let signature = Signature::<$param>::try_from(sig.as_ref())
                    .map_err(|_| CryptError::SignatureVerificationFailed)?;
                Verifier::verify(&verifying_key, message, &signature)
                    .map_err(|_| CryptError::SignatureVerificationFailed)
            }
        }
    };
}

/// ML-DSA-44 `SignAlgorithm` implementation (FIPS 204, security category 2 / 128-bit).
///
/// # Description
/// The smallest ML-DSA parameter set. Fastest but lowest security level.
/// Use ML-DSA-65 or -87 for production deployments.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa44Impl;

/// ML-DSA-65 `SignAlgorithm` implementation (FIPS 204, security category 3 / 192-bit).
///
/// # Description
/// Recommended default. Balances signature size, signing speed, and post-quantum security.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa65Impl;

/// ML-DSA-87 `SignAlgorithm` implementation (FIPS 204, security category 5 / 256-bit).
///
/// # Description
/// Highest security level ML-DSA parameter set. Larger signatures and slower operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa87Impl;

impl_ml_dsa!(MlDsa44Impl, MlDsa44);
impl_ml_dsa!(MlDsa65Impl, MlDsa65);
impl_ml_dsa!(MlDsa87Impl, MlDsa87);
