//! External contract tests for the CGv2 signed-envelope binding.
//!
//! Production-API assumptions deliberately locked by this suite:
//! `SignedEnvelope::sign` takes ownership of an `Envelope`; `from_parts`
//! accepts an untrusted `SignedEnvelopeParts`; and `verify` returns the only
//! public view of the signed envelope, recipient key ID, and metadata.

use crypt_guard::{
    error::CryptError,
    protocol::{
        envelope::Envelope,
        header::{AeadAlgId, Header, KdfAlgId, KemAlgId},
        signed_envelope::{
            SignedEnvelope, SignedEnvelopeError, SignedEnvelopeParts, SIGNED_ENVELOPE_V1,
        },
    },
    sign::SignAlgorithm,
};
use zeroize::ZeroizeOnDrop;

const SIGNATURE_KEY_BYTES: usize = 32;
const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1_088;
const XCHACHA20_POLY1305_NONCE_BYTES: usize = 24;
const FIXTURE_KEM_BYTE: u8 = 0xC3;
const FIXTURE_NONCE_BYTE: u8 = 0x5A;

struct TestSigningKey([u8; SIGNATURE_KEY_BYTES]);
impl ZeroizeOnDrop for TestSigningKey {}

#[derive(Clone)]
struct TestVerifyingKey([u8; SIGNATURE_KEY_BYTES]);

/// Deliberately not `Clone`: the signed-envelope API must work with every
/// `SignAlgorithm::Sig`, not just backends whose signatures can be cloned.
struct TestSignature(Vec<u8>);

impl TestSignature {
    fn from_wire(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn captured_transcript(&self) -> &[u8] {
        &self.0[SIGNATURE_KEY_BYTES..]
    }
}

impl AsRef<[u8]> for TestSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Test-only signer that retains the signed transcript in its wire form.
///
/// This checks generic transcript handling rather than cryptographic strength.
struct TestSigner;

impl SignAlgorithm for TestSigner {
    type SigningKey = TestSigningKey;
    type VerifyingKey = TestVerifyingKey;
    type Sig = TestSignature;

    fn keypair(
        _rng: &mut impl crypt_guard::kem::backend::rand_core_010::CryptoRng,
    ) -> Result<(Self::SigningKey, Self::VerifyingKey), CryptError> {
        Ok((
            TestSigningKey([0xA5; SIGNATURE_KEY_BYTES]),
            TestVerifyingKey([0xA5; SIGNATURE_KEY_BYTES]),
        ))
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Sig, CryptError> {
        let mut wire = Vec::with_capacity(SIGNATURE_KEY_BYTES + message.len());
        wire.extend_from_slice(&sk.0);
        wire.extend_from_slice(message);
        Ok(TestSignature(wire))
    }

    fn verify(vk: &Self::VerifyingKey, message: &[u8], sig: &Self::Sig) -> Result<(), CryptError> {
        if sig.0.len() == SIGNATURE_KEY_BYTES + message.len()
            && sig.0[..SIGNATURE_KEY_BYTES] == vk.0
            && sig.captured_transcript() == message
        {
            Ok(())
        } else {
            Err(CryptError::SignatureVerificationFailed)
        }
    }
}

fn fixture_envelope() -> Envelope {
    Envelope::new(
        Header::new(
            KemAlgId::MlKem768,
            AeadAlgId::XChaCha20Poly1305,
            KdfAlgId::HkdfSha256,
        ),
        vec![FIXTURE_KEM_BYTE; ML_KEM_768_CIPHERTEXT_BYTES],
        vec![FIXTURE_NONCE_BYTE; XCHACHA20_POLY1305_NONCE_BYTES],
        b"cipher".to_vec(),
    )
}

/// Independent, readable golden construction for the canonical V1 transcript.
///
/// Keep this separate from production serialization so the test detects wire
/// format regressions without embedding a 1,144-byte literal in the source.
fn fixture_golden_transcript() -> Vec<u8> {
    let mut envelope = Vec::with_capacity(1_144);
    envelope.extend_from_slice(b"CGv2\x02\x00\x02\x06\x01\x00\x00\x00\x00\x00");
    envelope.extend_from_slice(&(ML_KEM_768_CIPHERTEXT_BYTES as u32).to_le_bytes());
    envelope.extend_from_slice(&[FIXTURE_KEM_BYTE; ML_KEM_768_CIPHERTEXT_BYTES]);
    envelope.extend_from_slice(&(XCHACHA20_POLY1305_NONCE_BYTES as u32).to_le_bytes());
    envelope.extend_from_slice(&[FIXTURE_NONCE_BYTE; XCHACHA20_POLY1305_NONCE_BYTES]);
    envelope.extend_from_slice(&(b"cipher".len() as u32).to_le_bytes());
    envelope.extend_from_slice(b"cipher");

    let mut transcript = Vec::with_capacity(
        b"crypt_guard:signed-envelope".len() + 2 + 4 + envelope.len() + 4 + 12 + 4 + 16,
    );
    transcript.extend_from_slice(b"crypt_guard:signed-envelope");
    transcript.extend_from_slice(&SIGNED_ENVELOPE_V1.to_be_bytes());
    for field in [&envelope[..], b"recipient-42", b"message metadata"] {
        transcript.extend_from_slice(&(field.len() as u32).to_be_bytes());
        transcript.extend_from_slice(field);
    }
    transcript
}

fn signing_key() -> TestSigningKey {
    TestSigningKey([0xA5; SIGNATURE_KEY_BYTES])
}

fn verifying_key() -> TestVerifyingKey {
    TestVerifyingKey([0xA5; SIGNATURE_KEY_BYTES])
}

fn signed_fixture() -> SignedEnvelope<TestSigner> {
    SignedEnvelope::<TestSigner>::sign(
        &signing_key(),
        fixture_envelope(),
        b"recipient-42",
        b"message metadata",
    )
    .unwrap()
}

fn signature_over_fixture() -> TestSignature {
    // Copying the transport bytes is intentionally not `Sig::clone()`: generic
    // signatures are not required to implement Clone.
    TestSignature::from_wire(signed_fixture().signature().as_ref().to_vec())
}

#[test]
fn generic_non_clone_signature_roundtrip_only_exposes_verified_fields() {
    let envelope = signed_fixture();

    let verified = envelope.verify(&verifying_key()).unwrap();
    assert_eq!(verified.version(), SIGNED_ENVELOPE_V1);
    assert_eq!(verified.envelope(), &fixture_envelope());
    assert_eq!(verified.recipient_key_id(), b"recipient-42");
    assert_eq!(verified.metadata(), b"message metadata");

    // `SignedEnvelope` intentionally has no envelope/recipient/metadata
    // accessors. The values above are available only through `verified`.
}

#[test]
fn canonical_transcript_has_a_stable_v1_golden_encoding() {
    let envelope = signed_fixture();

    // LABEL || version(BE) || len(envelope)(BE) || Envelope::to_bytes()
    //       || len(recipient_key_id)(BE) || recipient_key_id
    //       || len(metadata)(BE) || metadata
    // The enclosed Envelope retains its established LE length prefixes. The
    // fixture uses parser-canonical ML-KEM-768/XChaCha field lengths; the
    // golden builder avoids an opaque multi-kilobyte byte-string literal.

    assert_eq!(
        envelope.signature().captured_transcript(),
        fixture_golden_transcript()
    );
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let envelope = signed_fixture();
    let wrong_key = TestVerifyingKey([0x5A; SIGNATURE_KEY_BYTES]);

    assert!(matches!(
        envelope.verify(&wrong_key),
        Err(SignedEnvelopeError::SignatureVerification(
            CryptError::SignatureVerificationFailed
        ))
    ));
}

#[test]
fn every_bound_cgv2_and_application_field_rejects_tampering() {
    let original = fixture_envelope();
    let mut changed_kem_ciphertext = original.clone();
    changed_kem_ciphertext.kem_ciphertext[0] ^= 0x01;
    let mut changed_nonce = original.clone();
    changed_nonce.nonce[0] ^= 0x01;
    let mut changed_ciphertext = original.clone();
    changed_ciphertext.ciphertext[0] ^= 0x01;

    for (label, envelope, recipient_key_id, metadata) in [
        (
            "KEM ciphertext",
            changed_kem_ciphertext,
            b"recipient-42".to_vec(),
            b"message metadata".to_vec(),
        ),
        (
            "nonce",
            changed_nonce,
            b"recipient-42".to_vec(),
            b"message metadata".to_vec(),
        ),
        (
            "ciphertext",
            changed_ciphertext,
            b"recipient-42".to_vec(),
            b"message metadata".to_vec(),
        ),
        (
            "recipient key ID",
            original.clone(),
            b"recipient-43".to_vec(),
            b"message metadata".to_vec(),
        ),
        (
            "metadata",
            original,
            b"recipient-42".to_vec(),
            b"message metadatb".to_vec(),
        ),
    ] {
        let tampered = SignedEnvelope::<TestSigner>::from_parts(SignedEnvelopeParts {
            version: SIGNED_ENVELOPE_V1,
            envelope,
            recipient_key_id,
            metadata,
            signature: signature_over_fixture(),
        });

        assert!(
            matches!(
                tampered.verify(&verifying_key()),
                Err(SignedEnvelopeError::SignatureVerification(
                    CryptError::SignatureVerificationFailed
                ))
            ),
            "tampering {label} unexpectedly verified"
        );
    }
}

#[test]
fn unsupported_signed_envelope_version_is_rejected_before_signature_verification() {
    let unsupported_version = SIGNED_ENVELOPE_V1 + 1;
    let untrusted = SignedEnvelope::<TestSigner>::from_parts(SignedEnvelopeParts {
        version: unsupported_version,
        envelope: fixture_envelope(),
        recipient_key_id: b"recipient-42".to_vec(),
        metadata: b"message metadata".to_vec(),
        signature: signature_over_fixture(),
    });

    assert!(matches!(
        untrusted.verify(&verifying_key()),
        Err(SignedEnvelopeError::UnsupportedVersion { version }) if version == unsupported_version
    ));
}

#[test]
fn malformed_untrusted_envelope_parts_are_rejected_before_signature_verification() {
    let mut noncanonical_header = fixture_envelope();
    noncanonical_header.header.flags = 1;
    let mut wrong_kem_length = fixture_envelope();
    wrong_kem_length.kem_ciphertext.pop();
    let mut wrong_nonce_length = fixture_envelope();
    wrong_nonce_length.nonce.pop();

    for (label, envelope) in [
        ("reserved header flags", noncanonical_header),
        ("ML-KEM-768 ciphertext length", wrong_kem_length),
        ("XChaCha20-Poly1305 nonce length", wrong_nonce_length),
    ] {
        let untrusted = SignedEnvelope::<TestSigner>::from_parts(SignedEnvelopeParts {
            version: SIGNED_ENVELOPE_V1,
            envelope,
            recipient_key_id: b"recipient-42".to_vec(),
            metadata: b"message metadata".to_vec(),
            signature: signature_over_fixture(),
        });

        assert!(
            matches!(
                untrusted.verify(&verifying_key()),
                Err(SignedEnvelopeError::EnvelopeSerialization(
                    CryptError::InvalidEnvelope
                ))
            ),
            "malformed {label} did not return the typed invalid-envelope error"
        );
    }
}

#[cfg(feature = "ml-dsa-backend")]
#[test]
fn fips204_ml_dsa_backend_roundtrips_without_an_adapter() {
    use crypt_guard::{kem::backend::OsRng, sign::ml_dsa::MlDsa65Impl};

    let mut rng = OsRng;
    let (signing_key, verifying_key) = MlDsa65Impl::keypair(&mut rng).unwrap();
    let envelope = SignedEnvelope::<MlDsa65Impl>::sign(
        &signing_key,
        fixture_envelope(),
        b"recipient-42",
        b"message metadata",
    )
    .unwrap();

    assert_eq!(
        envelope
            .verify(&verifying_key)
            .unwrap()
            .envelope()
            .ciphertext,
        b"cipher"
    );
}
