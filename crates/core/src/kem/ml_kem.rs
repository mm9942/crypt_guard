//! Concrete ML-KEM implementations of [`KemBackend`].
//!
//! # Responsibility scope
//! Provides three zero-sized marker types — [`MlKem512Impl`], [`MlKem768Impl`],
//! [`MlKem1024Impl`] — each implementing [`KemBackend`] against the corresponding parameter
//! set from the `ml-kem` crate (RustCrypto, FIPS 203). All internal operations are
//! delegated directly to that crate; this module owns only the adapter code.
//!
//! # Key types exported
//! - [`MlKem512Impl`], [`MlKem768Impl`], [`MlKem1024Impl`] — `KemBackend` implementors
//! - [`Size512`], [`Size768`], [`Size1024`] — `KemSize` markers
//!
//! # Concurrency
//! All types are ZST markers; operations are pure functions. `Send + Sync` trivially.
//!
//! # Errors
//! Propagates [`crate::error::CryptError`] variants `EncapsulationError`,
//! `DecapsulationError`, `InvalidKemPublicKey`, `InvalidKemSecretKey`,
//! `InvalidKemCiphertext`.
//!
//! # Examples
//! ```rust,no_run
//! #[cfg(feature = "ml-kem-backend")]
//! {
//!     use crypt_guard_core::kem::{KemBackend, ml_kem::MlKem768Impl};
//!     use crypt_guard_core::kem::backend::OsRng;
//!     let mut rng = OsRng;
//!     let (pk, sk) = MlKem768Impl::keypair(&mut rng).unwrap();
//!     let (ct, ss_send) = MlKem768Impl::encapsulate(&pk, &mut rng).unwrap();
//!     let ss_recv = MlKem768Impl::decapsulate(&sk, &ct).unwrap();
//!     assert_eq!(ss_send.as_ref(), ss_recv.as_ref());
//! }
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use crate::error::CryptError;
use crate::kem::backend::{rand_core_010, KemBackend, KemId};
use crate::kem::types::{KemCiphertext, KemSharedSecret, KemSize, MlKemPublicKey, MlKemSecretKey};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, FromSeed, Kem, KeyExport, TryKeyInit},
    MlKem1024, MlKem512, MlKem768,
};
use zeroize::Zeroize;

/// Size marker for ML-KEM-512.
///
/// # Description
/// Zero-sized type encoding the ML-KEM-512 security parameter set on the type level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size512;
/// Marks [`Size512`] as a valid ML-KEM parameter-set size.
impl KemSize for Size512 {}

/// Size marker for ML-KEM-768.
///
/// # Description
/// Zero-sized type encoding the ML-KEM-768 security parameter set on the type level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size768;
/// Marks [`Size768`] as a valid ML-KEM parameter-set size.
impl KemSize for Size768 {}

/// Size marker for ML-KEM-1024.
///
/// # Description
/// Zero-sized type encoding the ML-KEM-1024 security parameter set on the type level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Size1024;
/// Marks [`Size1024`] as a valid ML-KEM parameter-set size.
impl KemSize for Size1024 {}

/// ML-KEM-512 `KemBackend` implementation (FIPS 203, security category 1).
///
/// # Description
/// Wraps the `ml-kem` crate's `MlKem512` parameter set. Suitable for constrained
/// environments where performance is prioritised over maximum security level.
///
/// # Concurrency
/// ZST; all methods are pure functions. `Send + Sync`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlKem512Impl;

/// ML-KEM-768 `KemBackend` implementation (FIPS 203, security category 3 — recommended).
///
/// # Description
/// The recommended default parameter set. Provides 192-bit post-quantum security.
///
/// # Concurrency
/// ZST; all methods are pure functions. `Send + Sync`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlKem768Impl;

/// ML-KEM-1024 `KemBackend` implementation (FIPS 203, security category 5).
///
/// # Description
/// The highest security level (256-bit post-quantum). Larger keys and ciphertexts.
///
/// # Concurrency
/// ZST; all methods are pure functions. `Send + Sync`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlKem1024Impl;

/// Generate implementation of `KemBackend` for one ML-KEM size.
///
/// Uses the `kem` crate's `generate_keypair_from_rng`, `encapsulate_with_rng`, and
/// `decapsulate` methods. Key serialization uses `to_bytes()` (encapsulation key) and
/// `to_seed()` + seed-based init (decapsulation key) per the ml-kem benchmark pattern.
macro_rules! impl_ml_kem {
    ($impl_ty:ty, $kem_ty:ty, $size_ty:ty, $kem_id:expr) => {
        impl KemBackend for $impl_ty {
            type Size = $size_ty;
            type PublicKey = MlKemPublicKey<$size_ty>;
            type SecretKey = MlKemSecretKey<$size_ty>;
            type Ciphertext = KemCiphertext;
            type SharedSecret = KemSharedSecret;

            const ID: KemId = $kem_id;

            fn keypair(
                rng: &mut impl rand_core_010::CryptoRng,
            ) -> Result<(Self::PublicKey, Self::SecretKey), CryptError> {
                let (dk, ek) = <$kem_ty>::generate_keypair_from_rng(rng);
                // ek: encapsulation key — public, no zeroization required.
                let ek_bytes = ek.to_bytes();
                let pk = MlKemPublicKey::from_bytes(ek_bytes.as_slice().to_vec());
                // dk: decapsulation key — exported via to_seed() (compact 64-byte seed).
                // `seed` is secret key material; wipe the stack-allocated `Array`
                // temporary once its bytes have been copied into the zeroizing
                // `MlKemSecretKey` newtype.
                let mut seed = dk.to_seed().ok_or(CryptError::EncapsulationError)?;
                let sk = MlKemSecretKey::from_bytes(seed.as_slice().to_vec());
                seed.as_mut_slice().zeroize();
                Ok((pk, sk))
            }

            fn encapsulate(
                pk: &Self::PublicKey,
                rng: &mut impl rand_core_010::CryptoRng,
            ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptError> {
                type EK = <$kem_ty as Kem>::EncapsulationKey;
                let ek =
                    EK::new_from_slice(pk.as_ref()).map_err(|_| CryptError::InvalidKemPublicKey)?;
                let (ct, mut ss) = ek.encapsulate_with_rng(rng);
                // `ss` (the sender's shared secret) is secret; copy it into the
                // zeroizing `KemSharedSecret` newtype, then wipe the local `Array`.
                let result = (
                    KemCiphertext::from_bytes(ct.as_slice().to_vec()),
                    KemSharedSecret::from_bytes(ss.as_slice().to_vec()),
                );
                ss.as_mut_slice().zeroize();
                Ok(result)
            }

            fn decapsulate(
                sk: &Self::SecretKey,
                ct: &Self::Ciphertext,
            ) -> Result<Self::SharedSecret, CryptError> {
                // Restore from the compact seed bytes saved during keypair generation.
                // `seed_arr` is a secret decapsulation-key seed; wipe it once the
                // expanded decapsulation key has been derived from it.
                let mut seed_arr = <ml_kem::kem::Seed<$kem_ty>>::try_from(sk.as_ref())
                    .map_err(|_| CryptError::InvalidKemSecretKey)?;
                let dk = <$kem_ty>::from_seed(&seed_arr).0;
                seed_arr.as_mut_slice().zeroize();
                // Parse the ciphertext from raw bytes (not secret).
                let ct_arr = <ml_kem::kem::Ciphertext<$kem_ty>>::try_from(ct.as_ref())
                    .map_err(|_| CryptError::InvalidKemCiphertext)?;
                // `ss` (the receiver's shared secret) is secret; copy it into the
                // zeroizing `KemSharedSecret` newtype, then wipe the local `Array`.
                let mut ss = dk.decapsulate(&ct_arr);
                let result = KemSharedSecret::from_bytes(ss.as_slice().to_vec());
                ss.as_mut_slice().zeroize();
                Ok(result)
            }
        }
    };
}

impl_ml_kem!(MlKem512Impl, MlKem512, Size512, KemId::MlKem512);
impl_ml_kem!(MlKem768Impl, MlKem768, Size768, KemId::MlKem768);
impl_ml_kem!(MlKem1024Impl, MlKem1024, Size1024, KemId::MlKem1024);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::backend::OsRng;

    fn round_trip<B: KemBackend>() {
        let mut rng = OsRng;
        let (pk, sk) = B::keypair(&mut rng).expect("keypair generation should succeed");
        let (ct, ss_send) = B::encapsulate(&pk, &mut rng).expect("encapsulation should succeed");
        let ss_recv = B::decapsulate(&sk, &ct).expect("decapsulation should succeed");
        assert_eq!(
            ss_send.as_ref(),
            ss_recv.as_ref(),
            "sender and receiver shared secrets must match"
        );
    }

    #[test]
    fn round_trip_ml_kem_512() {
        round_trip::<MlKem512Impl>();
    }

    #[test]
    fn round_trip_ml_kem_768() {
        round_trip::<MlKem768Impl>();
    }

    #[test]
    fn round_trip_ml_kem_1024() {
        round_trip::<MlKem1024Impl>();
    }

    #[test]
    fn decapsulate_rejects_wrong_length_ciphertext() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem768Impl::keypair(&mut rng).expect("keypair generation");
        let (_ct, _ss) = MlKem768Impl::encapsulate(&pk, &mut rng).expect("encapsulate");
        let bad_ct = KemCiphertext::from_bytes(vec![0u8; 3]);
        assert!(
            MlKem768Impl::decapsulate(&sk, &bad_ct).is_err(),
            "a malformed (wrong-length) ciphertext must be rejected"
        );
    }

    #[test]
    fn decapsulate_rejects_wrong_length_secret_key() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem768Impl::keypair(&mut rng).expect("keypair generation");
        let (ct, _ss) = MlKem768Impl::encapsulate(&pk, &mut rng).expect("encapsulate");
        let bad_sk: MlKemSecretKey<Size768> = MlKemSecretKey::from_bytes(vec![0u8; 3]);
        assert!(
            MlKem768Impl::decapsulate(&bad_sk, &ct).is_err(),
            "a malformed (wrong-length) secret key must be rejected"
        );
    }

    #[test]
    fn encapsulate_rejects_wrong_length_public_key() {
        let mut rng = OsRng;
        let bad_pk: MlKemPublicKey<Size768> = MlKemPublicKey::from_bytes(vec![0u8; 3]);
        assert!(
            MlKem768Impl::encapsulate(&bad_pk, &mut rng).is_err(),
            "a malformed (wrong-length) public key must be rejected"
        );
    }
}
