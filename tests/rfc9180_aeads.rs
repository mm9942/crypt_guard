//! Public RFC 9180 AEAD-context behaviour tests.

use crypt_guard::hpke::{
    key_schedule, AeadId, BaseContext, HpkeError, HpkeSuite, KdfId, KemId, Mode,
};

const SHARED_SECRET: [u8; 32] = [0x47; 32];

fn base_context(aead_id: AeadId) -> BaseContext {
    let suite = HpkeSuite::new(KemId::DhKemX25519HkdfSha256, KdfId::HkdfSha256, aead_id);
    key_schedule(
        suite,
        Mode::Base,
        &SHARED_SECRET,
        b"RFC 9180 registered AEAD test",
        b"",
        b"",
    )
    .expect("fixed Base-mode input is valid")
    .into_base_context()
}

fn encryption_aeads() -> [AeadId; 3] {
    [
        AeadId::AesGcm128,
        AeadId::AesGcm256,
        AeadId::ChaCha20Poly1305,
    ]
}

#[test]
fn each_registered_encryption_aead_round_trips_with_distinct_sequence_nonces() {
    for aead_id in encryption_aeads() {
        let mut sender = base_context(aead_id);
        let mut receiver = base_context(aead_id);
        let aad = b"authenticated associated data";
        let plaintext = b"same plaintext under two consecutive HPKE sequence values";

        let first = sender.seal(aad, plaintext).unwrap();
        let second = sender.seal(aad, plaintext).unwrap();

        assert_ne!(
            first, second,
            "{aead_id:?} must derive a new nonce per sequence"
        );
        assert_eq!(receiver.open(aad, &first).unwrap(), plaintext);
        assert_eq!(receiver.open(aad, &second).unwrap(), plaintext);
    }
}

#[test]
fn each_registered_encryption_aead_authenticates_aad_and_ciphertext_without_skipping_sequence() {
    for aead_id in encryption_aeads() {
        let mut sender = base_context(aead_id);
        let mut receiver = base_context(aead_id);
        let first = sender.seal(b"correct AAD", b"first message").unwrap();

        assert_eq!(
            receiver.open(b"wrong AAD", &first),
            Err(HpkeError::AuthenticationFailed),
            "{aead_id:?} must authenticate AAD"
        );
        assert_eq!(
            receiver.open(b"correct AAD", &first).unwrap(),
            b"first message"
        );

        let second = sender.seal(b"correct AAD", b"second message").unwrap();
        let mut tampered = second.clone();
        tampered[0] ^= 0x80;
        assert_eq!(
            receiver.open(b"correct AAD", &tampered),
            Err(HpkeError::AuthenticationFailed),
            "{aead_id:?} must authenticate ciphertext"
        );
        assert_eq!(
            receiver.open(b"correct AAD", &second).unwrap(),
            b"second message"
        );
    }
}

#[test]
fn export_only_context_never_attempts_to_compute_or_use_a_nonce() {
    let mut context = base_context(AeadId::ExportOnly);

    assert_eq!(context.seal(b"", b""), Err(HpkeError::ExportOnlyAead));
    assert_eq!(context.open(b"", b""), Err(HpkeError::ExportOnlyAead));
    assert!(context.export(b"still available", 32).is_ok());
}
