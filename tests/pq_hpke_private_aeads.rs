//! Contract tests for crypt_guard's private PQ HPKE AEAD extensions.
//!
//! These suites deliberately use the crypt_guard v3 envelope namespace rather
//! than claiming RFC 9180/IANA wire interoperability.

use crypt_guard::pq_hpke::{
    generate_recipient_key_pair, Aead, HpkeEnvelope, Kdf, Kem, Suite, ENVELOPE_MAGIC,
    ENVELOPE_VERSION,
};

const KEM: Kem = Kem::MlKem768;
const KDF: Kdf = Kdf::HkdfSha256;
const PRIVATE_AEADS: [Aead; 2] = [Aead::Aes256GcmSiv, Aead::XChaCha20Poly1305];

#[test]
fn private_aeads_are_explicitly_marked_as_non_rfc_extensions() {
    for aead in PRIVATE_AEADS {
        assert!(
            aead.is_private_extension(),
            "{aead:?} must remain in crypt_guard's private suite namespace"
        );
    }
    assert!(!Aead::Aes256Gcm.is_private_extension());
    assert!(!Aead::ChaCha20Poly1305.is_private_extension());
}

#[test]
fn private_aead_envelopes_round_trip_with_pure_ml_kem() {
    let keys = generate_recipient_key_pair(KEM).expect("ML-KEM key generation must succeed");

    for aead in PRIVATE_AEADS {
        let suite = Suite::new(KEM, KDF, aead);
        let envelope = HpkeEnvelope::seal(
            suite,
            keys.public_key(),
            b"private AEAD suite info",
            b"private AEAD authenticated data",
            b"private extension plaintext",
        )
        .expect("private HPKE suite must seal through its envelope namespace");

        assert_eq!(envelope.suite(), suite);
        assert_eq!(
            envelope
                .open(
                    keys.private_key(),
                    b"private AEAD suite info",
                    b"private AEAD authenticated data",
                )
                .expect("private HPKE envelope must open"),
            b"private extension plaintext",
        );
    }
}

#[test]
fn private_aead_envelope_bytes_retain_explicit_suite_metadata() {
    let keys = generate_recipient_key_pair(KEM).expect("ML-KEM key generation must succeed");

    for aead in PRIVATE_AEADS {
        let suite = Suite::new(KEM, KDF, aead);
        let envelope = HpkeEnvelope::seal(suite, keys.public_key(), b"info", b"aad", b"payload")
            .expect("private HPKE suite must seal");
        let bytes = envelope.to_bytes();

        assert_eq!(&bytes[..4], &ENVELOPE_MAGIC);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), ENVELOPE_VERSION);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), KEM.id());
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), KDF.id());
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), aead.id());

        let parsed = HpkeEnvelope::from_bytes(&bytes)
            .expect("private suite IDs must be decoded only as a v3 envelope");
        assert_eq!(parsed.suite(), suite);
        assert_eq!(parsed.encapsulation(), envelope.encapsulation());
        assert_eq!(parsed.ciphertext(), envelope.ciphertext());
    }
}
