//! Seed-derived ML-DSA keys, FIPS 204 context signing and key fingerprints (3.2.0).
//!
//! # Responsibility scope
//! Integration tests for the additive 3.2.0 API on `MlDsa{44,65,87}Impl` and
//! `RecipientPublicKey::fingerprint`:
//! - Known-answer tests against the LAMPS / RFC 9881 example keys (seed `00..1f`).
//! - Independent fingerprint KATs computed with Python `hashlib.sha3_256`.
//! - Hedged vs. deterministic signing, context binding and length limits.
//!
//! # Examples
//! ```text
//! cargo test -p crypt_guard --test ml_dsa_seed_context
//! ```

// The whole file needs ML-DSA; the `legacy-pqclean` lane builds without it.
#![cfg(feature = "ml-dsa-backend")]

use crypt_guard::error::CryptError;
use crypt_guard::pq_hpke::{derive_recipient_key_pair, Kem, DEFAULT_SUITE};
use crypt_guard::sign::ml_dsa::{
    MlDsa44Impl, MlDsa65Impl, MlDsa87Impl, MlDsaSignature, MlDsaSigningKey, ML_DSA_SEED_LEN,
};
use crypt_guard::sign::SignAlgorithm;
use sha3::{Digest, Sha3_256};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const VECTORS: &str = include_str!("../crates/core/tests/vectors/ml-dsa-lamps-example-keys.json");

/// Fingerprints of the LAMPS example keys, computed independently in Python:
/// `sha3_256(b"crypt_guard/v3/fingerprint/ml-dsa" + b"\0" + id_be16 + len_be32 + pk)`.
const FP_44: &str = "2950eb4f6a741f228cf54daab5adbdf5362dc5a0abd78817ce856c2d06f653be";
const FP_65: &str = "f84c7bf60586286f94089fcf7bb5e24e43f36adf614f8df7e51c5f8204d792e7";
const FP_87: &str = "6a272a2da6395d538441c1ded8da8ad0687c9457ad23119f18919b7981f8d379";

struct Lamps {
    seed: Vec<u8>,
    pk44: Vec<u8>,
    pk65: Vec<u8>,
    pk87: Vec<u8>,
}

fn lamps() -> Result<Lamps, Box<dyn std::error::Error>> {
    let v: serde_json::Value = serde_json::from_str(VECTORS)?;
    let field = |path: &[&str]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut node = &v;
        for key in path {
            node = node.get(key).ok_or("missing vector field")?;
        }
        let text = node.as_str().ok_or("vector field is not a string")?;
        Ok(hex::decode(text)?)
    };
    Ok(Lamps {
        seed: field(&["seed"])?,
        pk44: field(&["public_keys", "ML-DSA-44"])?,
        pk65: field(&["public_keys", "ML-DSA-65"])?,
        pk87: field(&["public_keys", "ML-DSA-87"])?,
    })
}

#[test]
fn lamps_seed_derives_the_published_public_keys() -> TestResult {
    let l = lamps()?;
    assert_eq!(l.seed.len(), ML_DSA_SEED_LEN);

    let (_, vk44) = MlDsa44Impl::keypair_from_seed(&l.seed)?;
    let (_, vk65) = MlDsa65Impl::keypair_from_seed(&l.seed)?;
    let (_, vk87) = MlDsa87Impl::keypair_from_seed(&l.seed)?;

    assert_eq!(vk44.as_bytes(), l.pk44.as_slice());
    assert_eq!(vk65.as_bytes(), l.pk65.as_slice());
    assert_eq!(vk87.as_bytes(), l.pk87.as_slice());
    assert_eq!(vk44.as_bytes().len(), MlDsa44Impl::VERIFYING_KEY_LEN);
    assert_eq!(vk65.as_bytes().len(), MlDsa65Impl::VERIFYING_KEY_LEN);
    assert_eq!(vk87.as_bytes().len(), MlDsa87Impl::VERIFYING_KEY_LEN);
    Ok(())
}

#[test]
fn fingerprints_match_independent_python_kats() -> TestResult {
    let l = lamps()?;
    let (_, vk44) = MlDsa44Impl::keypair_from_seed(&l.seed)?;
    let (_, vk65) = MlDsa65Impl::keypair_from_seed(&l.seed)?;
    let (_, vk87) = MlDsa87Impl::keypair_from_seed(&l.seed)?;

    assert_eq!(hex::encode(MlDsa44Impl::fingerprint(&vk44)?), FP_44);
    assert_eq!(hex::encode(MlDsa65Impl::fingerprint(&vk65)?), FP_65);
    assert_eq!(hex::encode(MlDsa87Impl::fingerprint(&vk87)?), FP_87);
    Ok(())
}

#[test]
fn fingerprint_rejects_a_key_of_another_parameter_set() -> TestResult {
    let l = lamps()?;
    let (_, vk44) = MlDsa44Impl::keypair_from_seed(&l.seed)?;
    assert!(matches!(
        MlDsa87Impl::fingerprint(&vk44),
        Err(CryptError::InvalidDataLength)
    ));
    Ok(())
}

#[test]
fn keypair_from_seed_is_deterministic_and_length_checked() -> TestResult {
    let seed = [0x42u8; ML_DSA_SEED_LEN];
    let (sk_a, vk_a) = MlDsa87Impl::keypair_from_seed(&seed)?;
    let (sk_b, vk_b) = MlDsa87Impl::keypair_from_seed(&seed)?;
    assert_eq!(sk_a.as_bytes(), sk_b.as_bytes());
    assert_eq!(vk_a.as_bytes(), vk_b.as_bytes());
    assert_eq!(sk_a.as_bytes(), seed.as_slice());

    for bad in [&seed[..31], &[0u8; 33][..], &[][..]] {
        assert!(matches!(
            MlDsa87Impl::keypair_from_seed(bad),
            Err(CryptError::InvalidDataLength)
        ));
    }
    Ok(())
}

#[test]
fn verifying_key_from_seed_recovers_the_public_half() -> TestResult {
    let (sk, vk) = MlDsa65Impl::try_keypair()?;
    let recovered = MlDsa65Impl::verifying_key_from_seed(&sk)?;
    assert_eq!(recovered.as_bytes(), vk.as_bytes());

    let broken = MlDsaSigningKey::from_bytes(vec![1, 2, 3]);
    assert!(matches!(
        MlDsa65Impl::verifying_key_from_seed(&broken),
        Err(CryptError::InvalidDataLength)
    ));
    Ok(())
}

#[test]
fn generate_seed_yields_distinct_seeds() -> TestResult {
    let a = MlDsa87Impl::generate_seed()?;
    let b = MlDsa87Impl::generate_seed()?;
    assert_ne!(a.as_slice(), b.as_slice());
    Ok(())
}

#[test]
fn context_signatures_round_trip_and_bind_the_context() -> TestResult {
    let (sk, vk) = MlDsa87Impl::try_keypair()?;
    let msg = b"comnet:msg:v1 transcript";
    let sig = MlDsa87Impl::sign_with_context(&sk, msg, b"comnet:msg:v1")?;
    assert_eq!(sig.as_ref().len(), MlDsa87Impl::SIGNATURE_LEN);

    MlDsa87Impl::verify_with_context(&vk, msg, b"comnet:msg:v1", &sig)?;
    assert!(MlDsa87Impl::verify_with_context(&vk, msg, b"comnet:batch:v1", &sig).is_err());
    assert!(MlDsa87Impl::verify_with_context(&vk, msg, b"", &sig).is_err());
    assert!(MlDsa87Impl::verify_with_context(&vk, b"other", b"comnet:msg:v1", &sig).is_err());
    // The plain trait API signs with the empty context; it must not accept a
    // context-bound signature.
    assert!(MlDsa87Impl::verify(&vk, msg, &sig).is_err());
    Ok(())
}

#[test]
fn empty_context_interoperates_with_the_trait_api() -> TestResult {
    let (sk, vk) = MlDsa44Impl::try_keypair()?;
    let msg = b"interop";
    let trait_sig = MlDsa44Impl::sign(&sk, msg)?;
    MlDsa44Impl::verify_with_context(&vk, msg, b"", &trait_sig)?;

    let ctx_sig = MlDsa44Impl::sign_with_context(&sk, msg, b"")?;
    MlDsa44Impl::verify(&vk, msg, &ctx_sig)?;
    Ok(())
}

#[test]
fn hedged_signing_is_randomized_and_deterministic_signing_is_stable() -> TestResult {
    let (sk, vk) = MlDsa65Impl::keypair_from_seed(&[7u8; ML_DSA_SEED_LEN])?;
    let msg = b"same message";
    let ctx = b"ctx";

    let h1 = MlDsa65Impl::sign_with_context(&sk, msg, ctx)?;
    let h2 = MlDsa65Impl::sign_with_context(&sk, msg, ctx)?;
    assert_ne!(h1.as_ref(), h2.as_ref(), "hedged signatures must differ");
    MlDsa65Impl::verify_with_context(&vk, msg, ctx, &h1)?;
    MlDsa65Impl::verify_with_context(&vk, msg, ctx, &h2)?;

    let d1 = MlDsa65Impl::sign_with_context_deterministic(&sk, msg, ctx)?;
    let d2 = MlDsa65Impl::sign_with_context_deterministic(&sk, msg, ctx)?;
    assert_eq!(d1.as_ref(), d2.as_ref());
    MlDsa65Impl::verify_with_context(&vk, msg, ctx, &d1)?;
    Ok(())
}

#[test]
fn oversized_contexts_are_rejected() -> TestResult {
    let (sk, vk) = MlDsa87Impl::try_keypair()?;
    let long = [0u8; 256];
    let ok = [0u8; 255];

    assert!(matches!(
        MlDsa87Impl::sign_with_context(&sk, b"m", &long),
        Err(CryptError::InvalidParameters)
    ));
    assert!(matches!(
        MlDsa87Impl::sign_with_context_deterministic(&sk, b"m", &long),
        Err(CryptError::InvalidParameters)
    ));
    let sig = MlDsa87Impl::sign_with_context(&sk, b"m", &ok)?;
    MlDsa87Impl::verify_with_context(&vk, b"m", &ok, &sig)?;
    assert!(matches!(
        MlDsa87Impl::verify_with_context(&vk, b"m", &long, &sig),
        Err(CryptError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn malformed_signatures_are_rejected_without_panicking() -> TestResult {
    let (_, vk) = MlDsa87Impl::try_keypair()?;
    for bytes in [vec![], vec![0u8; 10], vec![0u8; MlDsa87Impl::SIGNATURE_LEN]] {
        let sig = MlDsaSignature::from_bytes(bytes);
        assert!(MlDsa87Impl::verify_with_context(&vk, b"m", b"c", &sig).is_err());
    }
    Ok(())
}

#[test]
fn recipient_public_key_fingerprint_binds_kem_and_bytes() -> TestResult {
    let seed = [9u8; 32];
    let keys = derive_recipient_key_pair(DEFAULT_SUITE.kem(), &seed)?;
    let pk = keys.public_key();

    // Recompute the documented construction independently.
    let bytes = pk.as_bytes();
    let mut h = Sha3_256::new();
    h.update(b"crypt_guard/v3/fingerprint/pq-hpke");
    h.update([0u8]);
    h.update(DEFAULT_SUITE.kem().id().to_be_bytes());
    h.update(u32::try_from(bytes.len())?.to_be_bytes());
    h.update(bytes);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(pk.fingerprint(), expected);

    // Stable across re-derivation, distinct across KEMs and seeds.
    let again = derive_recipient_key_pair(DEFAULT_SUITE.kem(), &seed)?;
    assert_eq!(again.public_key().fingerprint(), pk.fingerprint());
    let other_kem = derive_recipient_key_pair(Kem::MlKem768X25519, &seed)?;
    assert_ne!(other_kem.public_key().fingerprint(), pk.fingerprint());
    let other_seed = derive_recipient_key_pair(DEFAULT_SUITE.kem(), &[10u8; 32])?;
    assert_ne!(other_seed.public_key().fingerprint(), pk.fingerprint());
    Ok(())
}
