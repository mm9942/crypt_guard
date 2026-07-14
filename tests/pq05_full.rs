//! Contract tests for the revision-pinned full draft-05 namespace.

#![cfg(feature = "hpke-pq-draft-05")]

use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05_full::{
    generate_recipient_key_pair, setup_base_receiver, setup_base_sender, setup_psk_receiver,
    setup_psk_sender, Aead, Capability, Encapsulation, Error, Kdf, Kem, Suite,
};

const OPERATIONAL_KEMS: [Kem; 3] = [Kem::MlKem512, Kem::MlKem768, Kem::MlKem1024];
const ENCRYPTING_AEADS: [Aead; 3] = [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305];

fn kdf_for(kem: Kem) -> Kdf {
    match kem {
        Kem::MlKem512 => Kdf::HkdfSha256,
        Kem::MlKem768 => Kdf::HkdfSha256,
        Kem::MlKem1024 => Kdf::HkdfSha384,
        _ => unreachable!("only operational ML-KEM suites are passed here"),
    }
}

#[test]
fn each_implemented_kem_works_with_every_registered_encryption_aead() {
    for kem in OPERATIONAL_KEMS {
        let pair = generate_recipient_key_pair(kem).expect("implemented KEM must generate keys");
        for aead in ENCRYPTING_AEADS {
            let suite = Suite::new(kem, kdf_for(kem), aead);
            assert_eq!(suite.capability(), Capability::Available);
            let (enc, mut sender) =
                setup_base_sender(suite, pair.public_key(), b"full-namespace base info")
                    .expect("sender setup must succeed");
            let mut receiver =
                setup_base_receiver(suite, pair.private_key(), &enc, b"full-namespace base info")
                    .expect("recipient setup must succeed");
            assert_eq!(
                sender.export(b"full export", 48).unwrap(),
                receiver.export(b"full export", 48).unwrap(),
            );
            let ciphertext = sender.seal(b"full aad", b"all three AEADs").unwrap();
            assert_eq!(
                receiver.open(b"full aad", &ciphertext).unwrap(),
                b"all three AEADs",
            );
        }
    }
}

#[test]
fn psk_schedule_is_explicit_and_round_trips_for_two_stage_and_shake_kdfs() {
    let pair = generate_recipient_key_pair(Kem::MlKem768).unwrap();
    for kdf in [Kdf::HkdfSha256, Kdf::Shake128, Kdf::Shake256] {
        let suite = Suite::new(Kem::MlKem768, kdf, Aead::ChaCha20Poly1305);
        let (enc, mut sender) = setup_psk_sender(
            suite,
            pair.public_key(),
            b"PSK setup information",
            &[0xA5; 32],
            b"psk-key-id",
        )
        .unwrap();
        let mut receiver = setup_psk_receiver(
            suite,
            pair.private_key(),
            &enc,
            b"PSK setup information",
            &[0xA5; 32],
            b"psk-key-id",
        )
        .unwrap();
        let ciphertext = sender.seal(b"aad", b"psk message").unwrap();
        assert_eq!(receiver.open(b"aad", &ciphertext).unwrap(), b"psk message");
        assert_eq!(
            sender.export(b"psk export", 31).unwrap(),
            receiver.export(b"psk export", 31).unwrap()
        );
    }
}

#[test]
fn export_only_constructs_a_context_but_never_an_encryption_context() {
    let suite = Suite::new(Kem::MlKem768, Kdf::HkdfSha256, Aead::ExportOnly);
    let pair = generate_recipient_key_pair(Kem::MlKem768).unwrap();
    let (enc, mut sender) = setup_base_sender(suite, pair.public_key(), b"export-only").unwrap();
    let mut receiver =
        setup_base_receiver(suite, pair.private_key(), &enc, b"export-only").unwrap();
    assert_eq!(
        sender.export(b"ctx", 32).unwrap(),
        receiver.export(b"ctx", 32).unwrap()
    );
    assert_eq!(sender.seal(b"aad", b"nope"), Err(Error::ExportOnlyAead));
    assert_eq!(receiver.open(b"aad", b"nope"), Err(Error::ExportOnlyAead));
}

#[test]
fn unsupported_draft_kems_and_turboshake_are_typed_not_substituted() {
    let unavailable = [Kem::MlKem1024P384, Kem::MlKem768X25519];
    for kem in unavailable {
        let suite = Suite::new(kem, Kdf::HkdfSha256, Aead::Aes128Gcm);
        assert!(matches!(suite.capability(), Capability::Unavailable(_)));
        assert!(matches!(
            generate_recipient_key_pair(kem),
            Err(Error::UnavailableCapability { suite: actual, .. }) if actual == Suite::new(kem, Kdf::HkdfSha256, Aead::ExportOnly)
        ));
    }
    let suite = Suite::new(Kem::MlKem768, Kdf::TurboShake128, Aead::Aes128Gcm);
    assert_eq!(suite.capability(), Capability::Available);
}

#[test]
fn corpus_manifest_preserves_all_thirteen_pinned_vector_descriptors() {
    // This is deliberately a manifest rather than a false vector-success
    // claim: the official corpus covers 13 Base vectors, several of which use
    // KEMs or TurboSHAKE not locally available yet.  Future vector execution
    // must consume every entry and may mark none as "passed" by fallback.
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("vectors/hpke-pq-draft-05-test-vectors.json"))
            .expect("vendored draft corpus is JSON");
    let entries = vectors.as_array().expect("draft corpus is an array");
    assert_eq!(
        entries.len(),
        13,
        "draft-05 corpus changed; update this pinned harness deliberately"
    );
    for entry in entries {
        assert_eq!(entry["mode"], 0, "current corpus entry must be Base mode");
        assert!(entry["kem_id"].as_u64().is_some());
        assert!(entry["kdf_id"].as_u64().is_some());
        assert!(entry["aead_id"].as_u64().is_some());
    }
}

#[test]
fn same_size_encapsulation_tampering_is_observed_only_as_aead_failure() {
    let suite = Suite::new(Kem::MlKem768, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let pair = generate_recipient_key_pair(Kem::MlKem768).unwrap();
    let (enc, mut sender) = setup_base_sender(suite, pair.public_key(), b"tamper").unwrap();
    let ciphertext = sender.seal(b"aad", b"plaintext").unwrap();
    let mut modified = enc.as_bytes().to_vec();
    modified[0] ^= 0x80;
    let tampered = Encapsulation::from_bytes(Kem::MlKem768, &modified).unwrap();
    let mut receiver =
        setup_base_receiver(suite, pair.private_key(), &tampered, b"tamper").unwrap();
    assert_eq!(
        receiver.open(b"aad", &ciphertext),
        Err(Error::AuthenticationFailed)
    );
}
