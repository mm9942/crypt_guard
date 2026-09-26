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
//!     use crypt_guard_core::sign::{SignAlgorithm, ml_dsa::MlDsa65Impl};
//!     use crypt_guard_core::kem::backend::OsRng;
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
use zeroize::{Zeroize, ZeroizeOnDrop};

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
                // `sk` (the SigningKey itself) implements `ZeroizeOnDrop` (its seed and
                // expanded-key fields are wiped when it goes out of scope at the end of
                // this function, since the `ml-dsa` `zeroize` feature is enabled).
                let sk: SigningKey<$param> = Generate::generate_from_rng(rng);
                // MlDsaKeypairTrait provides .verifying_key()
                let vk: VerifyingKey<$param> = MlDsaKeypairTrait::verifying_key(&sk);
                // Serialize: signing key as seed (32 bytes), verifying key as encoded bytes.
                // `KeyExport::to_bytes(&sk)` returns a stack-allocated `Array` holding the
                // secret 32-byte seed; copy it into the returned `Vec` and then wipe the
                // `Array` temporary explicitly rather than relying only on its eventual
                // stack reuse.
                let mut sk_seed = KeyExport::to_bytes(&sk);
                let sk_bytes = sk_seed.as_slice().to_vec();
                sk_seed.as_mut_slice().zeroize();
                let vk_bytes = KeyExport::to_bytes(&vk).as_slice().to_vec();
                Ok((
                    MlDsaSigningKey::from_bytes(sk_bytes),
                    MlDsaVerifyingKey::from_bytes(vk_bytes),
                ))
            }

            fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Sig, CryptError> {
                // `signing_key` is re-parsed from the stored seed on every call; it
                // implements `ZeroizeOnDrop` (via the `ml-dsa` `zeroize` feature) and is
                // wiped automatically when it drops at the end of this function.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::backend::OsRng;

    const MESSAGE: &[u8] = b"CryptGuard ML-DSA test message";

    fn sign_verify_round_trip<A: SignAlgorithm>() {
        let mut rng = OsRng;
        let (sk, vk) = A::keypair(&mut rng).expect("keypair generation should succeed");
        let sig = A::sign(&sk, MESSAGE).expect("signing should succeed");
        A::verify(&vk, MESSAGE, &sig).expect("signature should verify against the signed message");
    }

    fn tampered_message_is_rejected<A: SignAlgorithm>() {
        let mut rng = OsRng;
        let (sk, vk) = A::keypair(&mut rng).expect("keypair generation should succeed");
        let sig = A::sign(&sk, MESSAGE).expect("signing should succeed");
        assert!(
            A::verify(&vk, b"a different, tampered message", &sig).is_err(),
            "verification must fail for a message that was not signed"
        );
    }

    /// Not generic over `A: SignAlgorithm`, because it needs to construct a
    /// concrete `MlDsaSignature` (`A::Sig` is an opaque associated type from the
    /// caller's point of view, even though every `MlDsa*Impl` happens to use the
    /// same concrete `Sig` type).
    fn tampered_signature_is_rejected<A>(sk: &A::SigningKey, vk: &A::VerifyingKey)
    where
        A: SignAlgorithm<Sig = MlDsaSignature>,
    {
        let sig = A::sign(sk, MESSAGE).expect("signing should succeed");
        let mut bad_sig_bytes = sig.as_ref().to_vec();
        // Flip a bit in the first byte to corrupt the signature.
        bad_sig_bytes[0] ^= 0x01;
        let bad_sig = MlDsaSignature::from_bytes(bad_sig_bytes);
        assert!(
            A::verify(vk, MESSAGE, &bad_sig).is_err(),
            "verification must fail for a tampered signature"
        );
    }

    #[test]
    fn ml_dsa_44_sign_verify_round_trip() {
        sign_verify_round_trip::<MlDsa44Impl>();
    }

    #[test]
    fn ml_dsa_65_sign_verify_round_trip() {
        sign_verify_round_trip::<MlDsa65Impl>();
    }

    #[test]
    fn ml_dsa_87_sign_verify_round_trip() {
        sign_verify_round_trip::<MlDsa87Impl>();
    }

    #[test]
    fn ml_dsa_44_tampered_message_rejected() {
        tampered_message_is_rejected::<MlDsa44Impl>();
    }

    #[test]
    fn ml_dsa_65_tampered_message_rejected() {
        tampered_message_is_rejected::<MlDsa65Impl>();
    }

    #[test]
    fn ml_dsa_87_tampered_message_rejected() {
        tampered_message_is_rejected::<MlDsa87Impl>();
    }

    #[test]
    fn ml_dsa_44_tampered_signature_rejected() {
        let mut rng = OsRng;
        let (sk, vk) = MlDsa44Impl::keypair(&mut rng).expect("keypair generation");
        tampered_signature_is_rejected::<MlDsa44Impl>(&sk, &vk);
    }

    #[test]
    fn ml_dsa_65_tampered_signature_rejected() {
        let mut rng = OsRng;
        let (sk, vk) = MlDsa65Impl::keypair(&mut rng).expect("keypair generation");
        tampered_signature_is_rejected::<MlDsa65Impl>(&sk, &vk);
    }

    #[test]
    fn ml_dsa_87_tampered_signature_rejected() {
        let mut rng = OsRng;
        let (sk, vk) = MlDsa87Impl::keypair(&mut rng).expect("keypair generation");
        tampered_signature_is_rejected::<MlDsa87Impl>(&sk, &vk);
    }
}
