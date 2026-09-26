//! SLH-DSA implementations of [`SignAlgorithm`] (FIPS 205, behind `sign-slhdsa` feature).
//!
//! # Responsibility scope
//! Provides `SignAlgorithm` implementations for a representative selection of SLH-DSA
//! parameter sets. The full FIPS 205 spec defines 12 parameter sets; this module exposes
//! the four recommended variants and the two high-security variants. The `slh-dsa` crate
//! allocates signatures on the stack — they range from 7 KB to ~50 KB.
//!
//! # Key types exported
//! - [`SlhDsaShake128fImpl`], [`SlhDsaShake128sImpl`] — L1 security
//! - [`SlhDsaShake192fImpl`], [`SlhDsaShake192sImpl`] — L3 security
//! - [`SlhDsaShake256fImpl`], [`SlhDsaShake256sImpl`] — L5 security
//! - [`SlhDsaSigningKey`], [`SlhDsaVerifyingKey`], [`SlhDsaSignature`]
//!
//! # Feature gate
//! This module is only compiled when the `sign-slhdsa` feature is enabled.
//! SLH-DSA is NOT in the default feature set because its signature sizes (7–50 KB)
//! may be unsuitable for many applications.
//!
//! # Zeroization
//! The `slh-dsa` dependency is built with its `zeroize` feature, so its
//! `SigningKey<P>` wipes `sk_seed`/`sk_prf` on drop. Every transient
//! `SigningKey` constructed in this module (in [`SignAlgorithm::keypair`] and
//! [`SignAlgorithm::sign`]) is therefore wiped when it goes out of scope, and
//! the serialized key bytes copied out of it are zeroized explicitly via
//! [`zeroize::Zeroize`].
//!
//! # Concurrency
//! All types are `Send + Sync`. Operations are pure functions.
//!
//! # Examples
//! ```rust,no_run
//! #[cfg(feature = "sign-slhdsa")]
//! {
//!     use crypt_guard_core::sign::{SignAlgorithm, slh_dsa::SlhDsaShake128fImpl};
//!     use crypt_guard_core::kem::backend::OsRng;
//!     let mut rng = OsRng;
//!     let (sk, vk) = SlhDsaShake128fImpl::keypair(&mut rng).unwrap();
//!     let sig = SlhDsaShake128fImpl::sign(&sk, b"test").unwrap();
//!     SlhDsaShake128fImpl::verify(&vk, b"test", &sig).unwrap();
//! }
//! ```

use crate::error::CryptError;
use crate::kem::backend::rand_core_010;
use crate::sign::algorithm::SignAlgorithm;
use slh_dsa::{
    signature::{Signer, Verifier},
    Shake128f, Shake128s, Shake192f, Shake192s, Shake256f, Shake256s, SigningKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLH-DSA signing key newtype (secret; `ZeroizeOnDrop`).
///
/// # Description
/// Wraps the raw signing-key bytes. Secret-bearing; wiped on drop.
/// Note: SLH-DSA signing keys are 64 bytes (seed only).
///
/// # Concurrency
/// `Send + Sync`.
#[derive(ZeroizeOnDrop)]
pub struct SlhDsaSigningKey(Vec<u8>);

impl SlhDsaSigningKey {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// SLH-DSA verifying key newtype (public; no zeroization).
///
/// # Concurrency
/// `Send + Sync`.
#[derive(Clone, Debug)]
pub struct SlhDsaVerifyingKey(Vec<u8>);

impl SlhDsaVerifyingKey {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// SLH-DSA signature newtype.
///
/// # Description
/// Wraps raw signature bytes. Not secret. SLH-DSA signatures range from 7 KB
/// (Shake128f) to ~50 KB (Shake256s).
///
/// # Concurrency
/// `Send + Sync`.
#[derive(Clone, Debug)]
pub struct SlhDsaSignature(Vec<u8>);

impl SlhDsaSignature {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Borrow the raw signature bytes of an [`SlhDsaSignature`].
///
/// # Description
/// Exposes the wrapped signature byte vector as a `&[u8]` slice, enabling the
/// type to satisfy the [`SignAlgorithm::Sig`] bound (`AsRef<[u8]>`).
impl AsRef<[u8]> for SlhDsaSignature {
    /// Return the signature bytes as a slice.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Implement `SignAlgorithm` for one SLH-DSA parameter set.
macro_rules! impl_slh_dsa {
    ($impl_ty:ty, $param:ty) => {
        impl SignAlgorithm for $impl_ty {
            type SigningKey = SlhDsaSigningKey;
            type VerifyingKey = SlhDsaVerifyingKey;
            type Sig = SlhDsaSignature;

            fn keypair(
                rng: &mut impl rand_core_010::CryptoRng,
            ) -> Result<(Self::SigningKey, Self::VerifyingKey), CryptError> {
                // `sk` wipes its `sk_seed`/`sk_prf` on drop (slh-dsa `zeroize`
                // feature, enabled in Cargo.toml).
                let sk = SigningKey::<$param>::new(rng);
                // sk_bytes layout: [sk_seed(N) | sk_prf(N) | pk_seed(N) | pk_root(N)]
                // vk bytes are the second half: sk_bytes[sk_len/2..]
                // `sk.to_bytes()` returns a stack-allocated `Array` holding the full
                // secret signing key; copy it into the returned `Vec`s and then wipe
                // the `Array` temporary explicitly.
                let mut sk_arr = sk.to_bytes();
                let sk_bytes = sk_arr.as_slice().to_vec();
                let vk_bytes = sk_bytes[sk_bytes.len() / 2..].to_vec();
                sk_arr.as_mut_slice().zeroize();
                Ok((
                    SlhDsaSigningKey::from_bytes(sk_bytes),
                    SlhDsaVerifyingKey::from_bytes(vk_bytes),
                ))
            }

            fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Sig, CryptError> {
                // `signing_key` is re-parsed from the stored bytes on every call and
                // wiped on drop (slh-dsa `zeroize` feature, enabled in Cargo.toml).
                let signing_key = SigningKey::<$param>::try_from(sk.as_bytes())
                    .map_err(|_| CryptError::SigningFailed)?;
                // Use deterministic signing (no RNG needed).
                let sig = signing_key.sign(message);
                Ok(SlhDsaSignature(sig.to_vec()))
            }

            fn verify(
                vk: &Self::VerifyingKey,
                message: &[u8],
                sig: &Self::Sig,
            ) -> Result<(), CryptError> {
                use slh_dsa::VerifyingKey;
                let verifying_key = VerifyingKey::<$param>::try_from(vk.as_bytes())
                    .map_err(|_| CryptError::SignatureVerificationFailed)?;
                let signature = <slh_dsa::Signature<$param>>::try_from(sig.as_ref())
                    .map_err(|_| CryptError::SignatureVerificationFailed)?;
                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| CryptError::SignatureVerificationFailed)
            }
        }
    };
}

/// SLH-DSA Shake128f `SignAlgorithm` (FIPS 205, L1 fast variant).
///
/// # Description
/// Recommended default SLH-DSA parameter set. 7 KB signatures; fast generation.
/// Security category 1 (128-bit post-quantum security equivalent).
#[derive(Clone, Copy, Debug, Default)]
pub struct SlhDsaShake128fImpl;

/// SLH-DSA Shake128s `SignAlgorithm` (FIPS 205, L1 small variant).
///
/// # Description
/// L1 security level with smaller signatures at the cost of slower signing.
#[derive(Clone, Copy, Debug, Default)]
pub struct SlhDsaShake128sImpl;

/// SLH-DSA Shake192f `SignAlgorithm` (FIPS 205, L3 fast variant).
///
/// # Description
/// L3 security level (192-bit), fast variant.
#[derive(Clone, Copy, Debug, Default)]
pub struct SlhDsaShake192fImpl;

/// SLH-DSA Shake192s `SignAlgorithm` (FIPS 205, L3 small variant).
///
/// # Description
/// L3 security level (192-bit), smaller signatures.
#[derive(Clone, Copy, Debug, Default)]
pub struct SlhDsaShake192sImpl;

/// SLH-DSA Shake256f `SignAlgorithm` (FIPS 205, L5 fast variant).
///
/// # Description
/// L5 security level (256-bit), fast variant. ~50 KB signatures.
#[derive(Clone, Copy, Debug, Default)]
pub struct SlhDsaShake256fImpl;

/// SLH-DSA Shake256s `SignAlgorithm` (FIPS 205, L5 small variant).
///
/// # Description
/// L5 security level (256-bit), smaller signatures at cost of slower signing.
#[derive(Clone, Copy, Debug, Default)]
pub struct SlhDsaShake256sImpl;

impl_slh_dsa!(SlhDsaShake128fImpl, Shake128f);
impl_slh_dsa!(SlhDsaShake128sImpl, Shake128s);
impl_slh_dsa!(SlhDsaShake192fImpl, Shake192f);
impl_slh_dsa!(SlhDsaShake192sImpl, Shake192s);
impl_slh_dsa!(SlhDsaShake256fImpl, Shake256f);
impl_slh_dsa!(SlhDsaShake256sImpl, Shake256s);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::backend::OsRng;

    const MESSAGE: &[u8] = b"CryptGuard SLH-DSA test message";

    // Only the "f" (fast) L1 variant is exercised as a full sign/verify round
    // trip in tests: SLH-DSA signing is comparatively expensive (hypertree
    // traversal over many WOTS+/FORS instances), and `Shake128f` is
    // representative of the sign/verify code path shared by every parameter
    // set through the `impl_slh_dsa!` macro.
    #[test]
    fn shake128f_sign_verify_round_trip() {
        let mut rng = OsRng;
        let (sk, vk) = SlhDsaShake128fImpl::keypair(&mut rng).expect("keypair generation");
        let sig = SlhDsaShake128fImpl::sign(&sk, MESSAGE).expect("signing should succeed");
        SlhDsaShake128fImpl::verify(&vk, MESSAGE, &sig)
            .expect("signature should verify against the signed message");
    }

    #[test]
    fn shake128f_tampered_message_is_rejected() {
        let mut rng = OsRng;
        let (sk, vk) = SlhDsaShake128fImpl::keypair(&mut rng).expect("keypair generation");
        let sig = SlhDsaShake128fImpl::sign(&sk, MESSAGE).expect("signing should succeed");
        assert!(
            SlhDsaShake128fImpl::verify(&vk, b"a different, tampered message", &sig).is_err(),
            "verification must fail for a message that was not signed"
        );
    }

    #[test]
    fn shake128f_tampered_signature_is_rejected() {
        let mut rng = OsRng;
        let (sk, vk) = SlhDsaShake128fImpl::keypair(&mut rng).expect("keypair generation");
        let sig = SlhDsaShake128fImpl::sign(&sk, MESSAGE).expect("signing should succeed");
        let mut bad_sig_bytes = sig.as_ref().to_vec();
        bad_sig_bytes[0] ^= 0x01;
        let bad_sig = SlhDsaSignature::from_bytes(bad_sig_bytes);
        assert!(
            SlhDsaShake128fImpl::verify(&vk, MESSAGE, &bad_sig).is_err(),
            "verification must fail for a tampered signature"
        );
    }

    #[test]
    fn keypair_verifying_key_is_second_half_of_signing_key() {
        let mut rng = OsRng;
        let (sk, vk) = SlhDsaShake128fImpl::keypair(&mut rng).expect("keypair generation");
        assert_eq!(sk.as_bytes().len(), vk.as_bytes().len() * 2);
        assert_eq!(&sk.as_bytes()[sk.as_bytes().len() / 2..], vk.as_bytes());
    }
}
