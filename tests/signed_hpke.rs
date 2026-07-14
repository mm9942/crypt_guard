//! Tests for the generic Signed-HPKE application binding.

use crypt_guard::{
    error::CryptError,
    hpke::{AeadId, HpkeSuite, KdfId, KemId, Mode},
    sign::SignAlgorithm,
    signed_hpke::{
        SignedHpkeBinding, SignedHpkeEnvelope, SignedHpkeEnvelopeParts, SignedHpkeError,
        SIGNED_HPKE_V1,
    },
};
use zeroize::ZeroizeOnDrop;

const SUITE: HpkeSuite = HpkeSuite::new(
    KemId::DhKemX25519HkdfSha256,
    KdfId::HkdfSha256,
    AeadId::ChaCha20Poly1305,
);

struct TestSigningKey([u8; 32]);
impl ZeroizeOnDrop for TestSigningKey {}

#[derive(Clone)]
struct TestVerifyingKey([u8; 32]);

struct TestSignature(Vec<u8>);
impl AsRef<[u8]> for TestSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Deliberately simple test-only backend: it proves the binding accepts an
/// arbitrary `SignAlgorithm`, not the security of this toy construction.
struct TestSigner;

impl SignAlgorithm for TestSigner {
    type SigningKey = TestSigningKey;
    type VerifyingKey = TestVerifyingKey;
    type Sig = TestSignature;

    fn keypair(
        _rng: &mut impl crypt_guard::kem::backend::rand_core_010::CryptoRng,
    ) -> Result<(Self::SigningKey, Self::VerifyingKey), CryptError> {
        Ok((TestSigningKey([0xA5; 32]), TestVerifyingKey([0xA5; 32])))
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Sig, CryptError> {
        let mut output = vec![0_u8; 32];
        for (index, byte) in message.iter().enumerate() {
            let slot = index % output.len();
            output[slot] = output[slot]
                .wrapping_add(*byte)
                .rotate_left((index % 8) as u32);
        }
        for (output_byte, key_byte) in output.iter_mut().zip(sk.0) {
            *output_byte ^= key_byte;
        }
        Ok(TestSignature(output))
    }

    fn verify(vk: &Self::VerifyingKey, message: &[u8], sig: &Self::Sig) -> Result<(), CryptError> {
        let expected = Self::sign(&TestSigningKey(vk.0), message)?;
        if expected.as_ref() == sig.as_ref() {
            Ok(())
        } else {
            Err(CryptError::SignatureVerificationFailed)
        }
    }
}

fn signed_envelope() -> (
    TestSigningKey,
    TestVerifyingKey,
    SignedHpkeEnvelope<TestSigner>,
) {
    let signing_key = TestSigningKey([0xA5; 32]);
    let verifying_key = TestVerifyingKey([0xA5; 32]);
    let envelope = SignedHpkeEnvelope::<TestSigner>::sign(&signing_key, binding()).unwrap();
    (signing_key, verifying_key, envelope)
}

fn binding() -> SignedHpkeBinding<'static> {
    SignedHpkeBinding {
        suite: SUITE,
        mode: Mode::Base,
        recipient_key_id: b"recipient-42",
        info: b"setup info",
        encapsulation: b"encapsulation",
        aad: b"application aad",
        ciphertext: b"ciphertext-and-tag",
    }
}

#[test]
fn generic_signer_verifies_and_only_then_exposes_hpke_parts() {
    let (_signing_key, verifying_key, envelope) = signed_envelope();

    let verified = envelope.verify(&verifying_key).unwrap();
    assert_eq!(verified.version(), SIGNED_HPKE_V1);
    assert_eq!(verified.suite(), SUITE);
    assert_eq!(verified.mode(), Mode::Base);
    assert_eq!(verified.recipient_key_id(), b"recipient-42");
    assert_eq!(verified.info(), b"setup info");
    assert_eq!(verified.encapsulation(), b"encapsulation");
    assert_eq!(verified.aad(), b"application aad");
    assert_eq!(verified.ciphertext(), b"ciphertext-and-tag");
}

#[test]
fn each_signed_field_tamper_is_rejected() {
    let (_signing_key, verifying_key, _envelope) = signed_envelope();

    // Re-signing the fixture would hide transcript omissions. Reuse the exact
    // signature through the decoding boundary and alter one field at a time.
    for (version, suite, mode, recipient_key_id, info, encapsulation, aad, ciphertext, label) in [
        (
            2,
            SUITE,
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "version",
        ),
        (
            SIGNED_HPKE_V1,
            HpkeSuite::new(
                KemId::DhKemP256HkdfSha256,
                KdfId::HkdfSha256,
                AeadId::ChaCha20Poly1305,
            ),
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "suite",
        ),
        (
            SIGNED_HPKE_V1,
            HpkeSuite::new(
                KemId::DhKemX25519HkdfSha256,
                KdfId::HkdfSha384,
                AeadId::ChaCha20Poly1305,
            ),
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "KDF suite identifier",
        ),
        (
            SIGNED_HPKE_V1,
            HpkeSuite::new(
                KemId::DhKemX25519HkdfSha256,
                KdfId::HkdfSha256,
                AeadId::AesGcm256,
            ),
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "AEAD suite identifier",
        ),
        (
            SIGNED_HPKE_V1,
            SUITE,
            Mode::Auth,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "mode",
        ),
        (
            SIGNED_HPKE_V1,
            SUITE,
            Mode::Base,
            b"recipient-43".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "recipient key id",
        ),
        (
            SIGNED_HPKE_V1,
            SUITE,
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup infp".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "info",
        ),
        (
            SIGNED_HPKE_V1,
            SUITE,
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulatioo".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "encapsulation",
        ),
        (
            SIGNED_HPKE_V1,
            SUITE,
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aae".to_vec(),
            b"ciphertext-and-tag".to_vec(),
            "aad",
        ),
        (
            SIGNED_HPKE_V1,
            SUITE,
            Mode::Base,
            b"recipient-42".to_vec(),
            b"setup info".to_vec(),
            b"encapsulation".to_vec(),
            b"application aad".to_vec(),
            b"ciphertext-and-taf".to_vec(),
            "ciphertext",
        ),
    ] {
        // Test signatures are intentionally clone-free to model all generic
        // backends. Recreate the valid original and move its signature out by
        // deriving an equivalent fresh signature over the original transcript.
        let (signing_key, _, _original) = signed_envelope();
        let replacement = SignedHpkeEnvelope::<TestSigner>::sign(&signing_key, binding()).unwrap();
        let tampered = SignedHpkeEnvelope::<TestSigner>::from_parts(SignedHpkeEnvelopeParts {
            version,
            suite,
            mode,
            recipient_key_id,
            info,
            encapsulation,
            aad,
            ciphertext,
            signature: TestSignature(replacement.signature().as_ref().to_vec()),
        });
        let result = tampered.verify(&verifying_key);
        assert!(result.is_err(), "tampering {label} unexpectedly verified");
    }
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let (_signing_key, _verifying_key, envelope) = signed_envelope();
    let wrong_key = TestVerifyingKey([0x5A; 32]);

    assert!(matches!(
        envelope.verify(&wrong_key),
        Err(SignedHpkeError::SignatureVerification(
            CryptError::SignatureVerificationFailed
        ))
    ));
}

#[test]
fn signature_tamper_is_rejected() {
    let (_signing_key, verifying_key, envelope) = signed_envelope();
    let mut signature = envelope.signature().as_ref().to_vec();
    signature[0] ^= 0x80;
    let tampered = SignedHpkeEnvelope::<TestSigner>::from_parts(SignedHpkeEnvelopeParts {
        version: SIGNED_HPKE_V1,
        suite: SUITE,
        mode: Mode::Base,
        recipient_key_id: b"recipient-42".to_vec(),
        info: b"setup info".to_vec(),
        encapsulation: b"encapsulation".to_vec(),
        aad: b"application aad".to_vec(),
        ciphertext: b"ciphertext-and-tag".to_vec(),
        signature: TestSignature(signature),
    });

    assert!(matches!(
        tampered.verify(&verifying_key),
        Err(SignedHpkeError::SignatureVerification(
            CryptError::SignatureVerificationFailed
        ))
    ));
}

#[cfg(feature = "ml-dsa-backend")]
#[test]
fn fips204_ml_dsa_backend_participates_without_an_adapter() {
    use crypt_guard::{
        kem::backend::OsRng, sign::ml_dsa::MlDsa65Impl, signed_hpke::SignedHpkeEnvelope,
    };

    let mut rng = OsRng;
    let (signing_key, verifying_key) = MlDsa65Impl::keypair(&mut rng).unwrap();
    let envelope = SignedHpkeEnvelope::<MlDsa65Impl>::sign(&signing_key, binding()).unwrap();

    assert_eq!(
        envelope.verify(&verifying_key).unwrap().ciphertext(),
        b"ciphertext-and-tag"
    );
}
