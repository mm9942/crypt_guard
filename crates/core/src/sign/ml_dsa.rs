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

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ml_dsa::{
    ExpandedSigningKey, Generate, KeyExport, KeyInit, MlDsa44, MlDsa65, MlDsa87, Seed, Signature,
    SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey,
};
// Keypair trait provides .verifying_key() on SigningKey.
use ml_dsa::Keypair as MlDsaKeypairTrait;

use crate::error::CryptError;
use crate::kem::backend::rand_core_010;
use crate::kem::backend::rand_core_010::TryRng;
use crate::kem::backend::TryOsRng;
use crate::sign::algorithm::SignAlgorithm;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length in bytes of an ML-DSA seed `ξ` (FIPS 204, Algorithm 6 input).
///
/// # Description
/// Every ML-DSA parameter set derives its whole key pair from exactly this many
/// bytes. [`MlDsaSigningKey`] stores the seed, never the expanded key.
pub const ML_DSA_SEED_LEN: usize = 32;

/// Maximum length in bytes of a FIPS 204 context string.
///
/// # Description
/// FIPS 204 encodes the context length in one byte, so contexts longer than
/// 255 bytes are rejected with [`CryptError::InvalidParameters`].
pub const ML_DSA_MAX_CONTEXT_LEN: usize = 255;

/// Length in bytes of a verifying-key fingerprint.
pub const ML_DSA_FINGERPRINT_LEN: usize = 32;

/// Domain label of [`MlDsa44Impl::fingerprint`] and its siblings.
const FINGERPRINT_LABEL: &[u8] = b"crypt_guard/v3/fingerprint/ml-dsa";

/// Fixed error text for an unavailable OS entropy source.
///
/// # Description
/// [`CryptError`] has no randomness variant and is not `#[non_exhaustive]`, so
/// adding one would be a breaking change. The text is constant and carries no
/// secret data.
const ENTROPY_UNAVAILABLE: &str = "os entropy source unavailable";

/// Draw a fresh 32-byte ML-DSA seed from the OS without panicking.
fn fresh_seed() -> Result<Zeroizing<[u8; ML_DSA_SEED_LEN]>, CryptError> {
    let mut seed = Zeroizing::new([0u8; ML_DSA_SEED_LEN]);
    TryOsRng
        .try_fill_bytes(seed.as_mut_slice())
        .map_err(|_| CryptError::CustomError(ENTROPY_UNAVAILABLE.to_owned()))?;
    Ok(seed)
}

/// Convert caller bytes into an ML-DSA [`Seed`], rejecting any other length.
fn seed_from_slice(bytes: &[u8]) -> Result<Zeroizing<Seed>, CryptError> {
    let seed = Seed::try_from(bytes).map_err(|_| CryptError::InvalidDataLength)?;
    Ok(Zeroizing::new(seed))
}

/// Reject context strings that FIPS 204 cannot encode.
fn check_context(context: &[u8]) -> Result<(), CryptError> {
    if context.len() > ML_DSA_MAX_CONTEXT_LEN {
        return Err(CryptError::InvalidParameters);
    }
    Ok(())
}

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

/// Add the seed, context and fingerprint API to one ML-DSA parameter set.
///
/// # Description
/// These inherent functions are additive to [`SignAlgorithm`]. They never panic:
/// entropy comes from [`TryOsRng`], every length is checked, and every failure
/// is returned as a [`CryptError`].
macro_rules! impl_ml_dsa_ext {
    ($impl_ty:ty, $param:ty, $id:expr, $vk_len:expr, $sig_len:expr) => {
        impl $impl_ty {
            /// Stable parameter-set identifier bound into fingerprints (44, 65 or 87).
            pub const PARAMETER_SET_ID: u16 = $id;
            /// Length in bytes of an encoded verifying key of this parameter set.
            pub const VERIFYING_KEY_LEN: usize = $vk_len;
            /// Length in bytes of a signature of this parameter set.
            pub const SIGNATURE_LEN: usize = $sig_len;

            /// Generate a fresh 32-byte seed from the OS entropy source.
            ///
            /// # Description
            /// Store this seed in your key-management boundary; it re-derives the
            /// same key pair through [`Self::keypair_from_seed`].
            ///
            /// # Returns
            /// The seed in zeroizing memory.
            ///
            /// # Errors
            /// - [`CryptError::CustomError`]: the OS entropy source failed.
            ///
            /// # Concurrency
            /// Stateless; callable from any thread.
            pub fn generate_seed() -> Result<Zeroizing<[u8; ML_DSA_SEED_LEN]>, CryptError> {
                fresh_seed()
            }

            /// Deterministically derive a key pair from a 32-byte seed (FIPS 204 Algorithm 6).
            ///
            /// # Arguments
            /// - `seed` (`&[u8]`): exactly [`ML_DSA_SEED_LEN`] bytes of secret seed.
            ///
            /// # Returns
            /// `(signing_key, verifying_key)`; the signing key stores only the seed.
            ///
            /// # Errors
            /// - [`CryptError::InvalidDataLength`]: `seed` is not 32 bytes long.
            ///
            /// # Concurrency
            /// Pure function; callable from any thread.
            pub fn keypair_from_seed(
                seed: &[u8],
            ) -> Result<(MlDsaSigningKey, MlDsaVerifyingKey), CryptError> {
                let seed = seed_from_slice(seed)?;
                let sk = SigningKey::<$param>::from_seed(&seed);
                let vk: VerifyingKey<$param> = MlDsaKeypairTrait::verifying_key(&sk);
                let vk_bytes = KeyExport::to_bytes(&vk).as_slice().to_vec();
                Ok((
                    MlDsaSigningKey::from_bytes(seed.as_slice().to_vec()),
                    MlDsaVerifyingKey::from_bytes(vk_bytes),
                ))
            }

            /// Generate a key pair from OS entropy without any panic path.
            ///
            /// # Description
            /// Unlike [`SignAlgorithm::keypair`] with `OsRng`, an entropy failure
            /// is returned as an error instead of a panic.
            ///
            /// # Errors
            /// - [`CryptError::CustomError`]: the OS entropy source failed.
            ///
            /// # Concurrency
            /// Stateless; callable from any thread.
            pub fn try_keypair() -> Result<(MlDsaSigningKey, MlDsaVerifyingKey), CryptError> {
                let seed = fresh_seed()?;
                Self::keypair_from_seed(seed.as_slice())
            }

            /// Recompute the verifying key that belongs to a stored signing key.
            ///
            /// # Arguments
            /// - `sk` (`&MlDsaSigningKey`): the seed-backed signing key.
            ///
            /// # Errors
            /// - [`CryptError::InvalidDataLength`]: the stored seed is not 32 bytes long.
            ///
            /// # Concurrency
            /// Pure function; callable from any thread.
            pub fn verifying_key_from_seed(
                sk: &MlDsaSigningKey,
            ) -> Result<MlDsaVerifyingKey, CryptError> {
                Self::keypair_from_seed(sk.as_bytes()).map(|(_, vk)| vk)
            }

            /// Sign `message` under a FIPS 204 context string with hedged randomness.
            ///
            /// # Description
            /// Uses the randomized ("hedged") ML-DSA.Sign variant: 32 fresh bytes
            /// from [`TryOsRng`] are mixed into the signing nonce, which protects
            /// against fault and side-channel attacks on devices such as phones.
            /// Use a distinct `context` per purpose (domain separation).
            ///
            /// # Arguments
            /// - `sk` (`&MlDsaSigningKey`): the seed-backed signing key.
            /// - `message` (`&[u8]`): the bytes to sign.
            /// - `context` (`&[u8]`): FIPS 204 context, at most 255 bytes.
            ///
            /// # Errors
            /// - [`CryptError::InvalidParameters`]: `context` is longer than 255 bytes.
            /// - [`CryptError::InvalidDataLength`]: the stored seed is not 32 bytes long.
            /// - [`CryptError::CustomError`]: the OS entropy source failed.
            ///
            /// # Concurrency
            /// Stateless; callable from any thread.
            pub fn sign_with_context(
                sk: &MlDsaSigningKey,
                message: &[u8],
                context: &[u8],
            ) -> Result<MlDsaSignature, CryptError> {
                check_context(context)?;
                let seed = seed_from_slice(sk.as_bytes())?;
                // `ExpandedSigningKey` zeroizes itself on drop (ml-dsa `zeroize` feature).
                let expanded = ExpandedSigningKey::<$param>::from_seed(&seed);
                let sig = expanded
                    .sign_randomized(message, context, &mut TryOsRng)
                    .map_err(|_| CryptError::CustomError(ENTROPY_UNAVAILABLE.to_owned()))?;
                Ok(MlDsaSignature(sig.to_vec()))
            }

            /// Sign under a context string with the deterministic FIPS 204 variant.
            ///
            /// # Description
            /// Produces reproducible signatures. Intended for known-answer tests and
            /// interoperability checks; prefer [`Self::sign_with_context`] in production.
            ///
            /// # Errors
            /// - [`CryptError::InvalidParameters`]: `context` is longer than 255 bytes.
            /// - [`CryptError::InvalidDataLength`]: the stored seed is not 32 bytes long.
            ///
            /// # Concurrency
            /// Pure function; callable from any thread.
            pub fn sign_with_context_deterministic(
                sk: &MlDsaSigningKey,
                message: &[u8],
                context: &[u8],
            ) -> Result<MlDsaSignature, CryptError> {
                check_context(context)?;
                let seed = seed_from_slice(sk.as_bytes())?;
                let expanded = ExpandedSigningKey::<$param>::from_seed(&seed);
                let sig = expanded
                    .sign_deterministic(message, context)
                    .map_err(|_| CryptError::InvalidParameters)?;
                Ok(MlDsaSignature(sig.to_vec()))
            }

            /// Verify a signature produced under a FIPS 204 context string.
            ///
            /// # Description
            /// Verification with an empty `context` accepts signatures from
            /// [`SignAlgorithm::sign`], which signs with the empty context.
            ///
            /// # Errors
            /// - [`CryptError::SignatureVerificationFailed`]: malformed key or
            ///   signature, oversized context, or a signature that does not verify.
            ///
            /// # Concurrency
            /// Pure function; callable from any thread.
            pub fn verify_with_context(
                vk: &MlDsaVerifyingKey,
                message: &[u8],
                context: &[u8],
                sig: &MlDsaSignature,
            ) -> Result<(), CryptError> {
                if context.len() > ML_DSA_MAX_CONTEXT_LEN {
                    return Err(CryptError::SignatureVerificationFailed);
                }
                let verifying_key = VerifyingKey::<$param>::new_from_slice(vk.as_bytes())
                    .map_err(|_| CryptError::SignatureVerificationFailed)?;
                let signature = Signature::<$param>::try_from(sig.as_ref())
                    .map_err(|_| CryptError::SignatureVerificationFailed)?;
                if verifying_key.verify_with_context(message, context, &signature) {
                    Ok(())
                } else {
                    Err(CryptError::SignatureVerificationFailed)
                }
            }

            /// Compute the stable fingerprint of a verifying key.
            ///
            /// # Description
            /// `SHA3-256("crypt_guard/v3/fingerprint/ml-dsa" ‖ 0x00 ‖ id_be16 ‖ len_be32 ‖ vk)`,
            /// where `id` is [`Self::PARAMETER_SET_ID`]. The parameter set is bound
            /// in, so the same bytes can never collide across parameter sets.
            ///
            /// # Errors
            /// - [`CryptError::InvalidDataLength`]: `vk` is not a valid key of this
            ///   parameter set.
            ///
            /// # Concurrency
            /// Pure function; callable from any thread.
            pub fn fingerprint(
                vk: &MlDsaVerifyingKey,
            ) -> Result<[u8; ML_DSA_FINGERPRINT_LEN], CryptError> {
                VerifyingKey::<$param>::new_from_slice(vk.as_bytes())
                    .map_err(|_| CryptError::InvalidDataLength)?;
                let len = u32::try_from(vk.as_bytes().len())
                    .map_err(|_| CryptError::InvalidDataLength)?;
                let mut h = Sha3_256::new();
                Digest::update(&mut h, FINGERPRINT_LABEL);
                Digest::update(&mut h, [0u8]);
                Digest::update(&mut h, Self::PARAMETER_SET_ID.to_be_bytes());
                Digest::update(&mut h, len.to_be_bytes());
                Digest::update(&mut h, vk.as_bytes());
                Ok(h.finalize().into())
            }
        }
    };
}

impl_ml_dsa_ext!(MlDsa44Impl, MlDsa44, 44, 1312, 2420);
impl_ml_dsa_ext!(MlDsa65Impl, MlDsa65, 65, 1952, 3309);
impl_ml_dsa_ext!(MlDsa87Impl, MlDsa87, 87, 2592, 4627);

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
