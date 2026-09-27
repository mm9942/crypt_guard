//! Concrete ML-KEM implementations of [`KemBackend`].
//!
//! # Responsibility scope
//! Provides three zero-sized marker types — [`MlKem512Impl`], [`MlKem768Impl`],
//! [`MlKem1024Impl`] — each implementing [`KemBackend`] against the corresponding parameter
//! set of `libcrux-ml-kem` (FIPS 203), the PQCA / PQ Code Package implementation that the
//! `pq_hpke` transport already uses. All internal operations are delegated to that crate;
//! this module owns only the adapter code.
//!
//! # Key format
//! Secret keys are the 64-byte FIPS 203 seed `d || z`; the expanded decapsulation key is
//! re-derived for each decapsulation and wiped afterwards. Public keys and ciphertexts use
//! the FIPS 203 encodings. Keys and ciphertexts created by the earlier RustCrypto `ml-kem`
//! backend are fully interchangeable (see the cross-implementation tests below).
//!
//! # Key types exported
//! - [`MlKem512Impl`], [`MlKem768Impl`], [`MlKem1024Impl`] — `KemBackend` implementors
//! - [`Size512`], [`Size768`], [`Size1024`] — `KemSize` markers
//!
//! # Concurrency
//! All types are ZST markers; operations are pure functions. `Send + Sync` trivially.
//!
//! # Errors
//! Propagates [`crate::error::CryptError`] variants `InvalidKemPublicKey`,
//! `InvalidKemSecretKey` and `InvalidKemCiphertext`.
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
use zeroize::{Zeroize, Zeroizing};

/// Length of the FIPS 203 secret-key seed `d || z`.
const SEED_LEN: usize = 64;
/// Length of the encapsulation randomness `m`.
const RANDOMNESS_LEN: usize = 32;

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
/// Wraps `libcrux_ml_kem::mlkem512`. Suitable for constrained environments where
/// performance is prioritised over maximum security level.
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

/// Implement `KemBackend` for one ML-KEM parameter set on top of `libcrux-ml-kem`.
///
/// `$m` is the libcrux parameter-set module; `$pk_len`, `$ct_len` and `$dk_len` are the
/// FIPS 203 encapsulation-key, ciphertext and expanded decapsulation-key lengths.
macro_rules! impl_ml_kem {
    (
        $impl_ty:ty, $size_ty:ty, $kem_id:expr, $m:ident,
        $pk_ty:ident, $ct_ty:ident, $pk_len:expr, $ct_len:expr, $dk_len:expr
    ) => {
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
                let mut seed = Zeroizing::new([0u8; SEED_LEN]);
                rng.fill_bytes(&mut seed[..]);
                let sk = MlKemSecretKey::from_bytes(seed.to_vec());

                let mut expansion_seed = *seed;
                let key_pair = libcrux_ml_kem::$m::generate_key_pair(expansion_seed);
                expansion_seed.zeroize();
                let (raw_dk, raw_ek) = key_pair.into_parts();
                let pk = MlKemPublicKey::from_bytes(raw_ek.as_slice().to_vec());
                let mut dk_bytes: [u8; $dk_len] = raw_dk.into();
                dk_bytes.zeroize();
                Ok((pk, sk))
            }

            fn encapsulate(
                pk: &Self::PublicKey,
                rng: &mut impl rand_core_010::CryptoRng,
            ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptError> {
                let pk_bytes = <[u8; $pk_len]>::try_from(pk.as_ref())
                    .map_err(|_| CryptError::InvalidKemPublicKey)?;
                let raw_ek = libcrux_ml_kem::$m::$pk_ty::from(pk_bytes);
                // FIPS 203 §7.2 encapsulation-key check (modulus check).
                if !libcrux_ml_kem::$m::validate_public_key(&raw_ek) {
                    return Err(CryptError::InvalidKemPublicKey);
                }

                let mut randomness = Zeroizing::new([0u8; RANDOMNESS_LEN]);
                rng.fill_bytes(&mut randomness[..]);
                let (ct, mut ss) = libcrux_ml_kem::$m::encapsulate(&raw_ek, *randomness);
                let result = (
                    KemCiphertext::from_bytes(ct.as_slice().to_vec()),
                    KemSharedSecret::from_bytes(ss.to_vec()),
                );
                ss.zeroize();
                Ok(result)
            }

            fn decapsulate(
                sk: &Self::SecretKey,
                ct: &Self::Ciphertext,
            ) -> Result<Self::SharedSecret, CryptError> {
                let mut expansion_seed = <[u8; SEED_LEN]>::try_from(sk.as_ref())
                    .map_err(|_| CryptError::InvalidKemSecretKey)?;
                let ct_bytes = <[u8; $ct_len]>::try_from(ct.as_ref())
                    .map_err(|_| CryptError::InvalidKemCiphertext);
                let ct_bytes = match ct_bytes {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        expansion_seed.zeroize();
                        return Err(err);
                    }
                };

                let key_pair = libcrux_ml_kem::$m::generate_key_pair(expansion_seed);
                expansion_seed.zeroize();
                let (raw_dk, _) = key_pair.into_parts();
                let raw_ct = libcrux_ml_kem::$m::$ct_ty::from(ct_bytes);
                // Fixed-size malformed ciphertexts reach FIPS 203 Decaps, which
                // answers with its implicit-rejection secret instead of an error.
                let mut ss = libcrux_ml_kem::$m::decapsulate(&raw_dk, &raw_ct);
                let mut dk_bytes: [u8; $dk_len] = raw_dk.into();
                dk_bytes.zeroize();
                let result = KemSharedSecret::from_bytes(ss.to_vec());
                ss.zeroize();
                Ok(result)
            }
        }
    };
}

impl_ml_kem!(
    MlKem512Impl,
    Size512,
    KemId::MlKem512,
    mlkem512,
    MlKem512PublicKey,
    MlKem512Ciphertext,
    800,
    768,
    1632
);
impl_ml_kem!(
    MlKem768Impl,
    Size768,
    KemId::MlKem768,
    mlkem768,
    MlKem768PublicKey,
    MlKem768Ciphertext,
    1184,
    1088,
    2400
);
impl_ml_kem!(
    MlKem1024Impl,
    Size1024,
    KemId::MlKem1024,
    mlkem1024,
    MlKem1024PublicKey,
    MlKem1024Ciphertext,
    1568,
    1568,
    3168
);

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

    #[test]
    fn encapsulate_rejects_public_key_failing_the_modulus_check() {
        // Correct length, but every coefficient is out of range (FIPS 203 §7.2).
        let mut rng = OsRng;
        let bad_pk: MlKemPublicKey<Size768> = MlKemPublicKey::from_bytes(vec![0xff; 1184]);
        assert!(
            MlKem768Impl::encapsulate(&bad_pk, &mut rng).is_err(),
            "an encapsulation key that fails the modulus check must be rejected"
        );
    }

    /// Keys and ciphertexts must stay interchangeable with the former
    /// RustCrypto `ml-kem` backend, so data and key files created before the
    /// switch to libcrux keep working.
    mod cross_implementation {
        use super::*;
        use ml_kem::{
            kem::{Decapsulate, Encapsulate, FromSeed, Kem, KeyExport, TryKeyInit},
            MlKem1024, MlKem512, MlKem768,
        };

        macro_rules! cross_check {
            ($name:ident, $impl_ty:ty, $size_ty:ty, $rc:ty) => {
                #[test]
                fn $name() {
                    let mut rng = OsRng;

                    // Same seed => same public key in both implementations.
                    let (pk, sk) = <$impl_ty>::keypair(&mut rng).expect("keypair");
                    let seed = <ml_kem::kem::Seed<$rc>>::try_from(sk.as_ref()).expect("seed");
                    let (rc_dk, rc_ek) = <$rc>::from_seed(&seed);
                    assert_eq!(rc_ek.to_bytes().as_slice(), pk.as_ref());

                    // libcrux encapsulates, RustCrypto decapsulates.
                    let (ct, ss) = <$impl_ty>::encapsulate(&pk, &mut rng).expect("encapsulate");
                    let rc_ct = <ml_kem::kem::Ciphertext<$rc>>::try_from(ct.as_ref()).expect("ct");
                    assert_eq!(rc_dk.decapsulate(&rc_ct).as_slice(), ss.as_ref());

                    // A key pair created by RustCrypto, used with libcrux.
                    let (rc_dk, rc_ek) = <$rc>::generate_keypair_from_rng(&mut rng);
                    let old_pk: MlKemPublicKey<$size_ty> =
                        MlKemPublicKey::from_bytes(rc_ek.to_bytes().as_slice().to_vec());
                    let old_sk: MlKemSecretKey<$size_ty> = MlKemSecretKey::from_bytes(
                        rc_dk.to_seed().expect("seed export").as_slice().to_vec(),
                    );
                    type EK = <$rc as Kem>::EncapsulationKey;
                    let rc_ek = EK::new_from_slice(old_pk.as_ref()).expect("ek");
                    let (rc_ct, rc_ss) = rc_ek.encapsulate_with_rng(&mut rng);
                    let ct = KemCiphertext::from_bytes(rc_ct.as_slice().to_vec());
                    let ss = <$impl_ty>::decapsulate(&old_sk, &ct).expect("decapsulate");
                    assert_eq!(ss.as_ref(), rc_ss.as_slice());
                }
            };
        }

        cross_check!(
            ml_kem_512_matches_rustcrypto,
            MlKem512Impl,
            Size512,
            MlKem512
        );
        cross_check!(
            ml_kem_768_matches_rustcrypto,
            MlKem768Impl,
            Size768,
            MlKem768
        );
        cross_check!(
            ml_kem_1024_matches_rustcrypto,
            MlKem1024Impl,
            Size1024,
            MlKem1024
        );
    }
}
