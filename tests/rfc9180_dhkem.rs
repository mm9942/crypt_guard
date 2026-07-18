//! Endpoint-level RFC 9180 conformance tests for the complete classical DHKEM API.

use crypt_guard::hpke::{
    rfc9180::{
        generate_key_pair, setup_auth_psk_r, setup_auth_psk_s, setup_auth_r, setup_auth_s,
        setup_base_r, setup_base_s, setup_psk_r, setup_psk_s, EncapsulatedKey, PrivateKey,
        PublicKey, Rfc9180Error,
    },
    AeadId, HpkeSuite, KdfId, KemId,
};
use serde::Deserialize;

const VECTORS: &str = include_str!("vectors/rfc9180-test-vectors.json");

#[derive(Deserialize)]
struct Vector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "skRm")]
    recipient_private_key: String,
    enc: String,
    #[serde(rename = "pkSm")]
    sender_public_key: Option<String>,
    psk: Option<String>,
    psk_id: Option<String>,
    exports: Vec<Export>,
    encryptions: Vec<Encryption>,
}

#[derive(Deserialize)]
struct Export {
    exporter_context: String,
    #[serde(rename = "L")]
    output_len: usize,
    exported_value: String,
}

#[derive(Deserialize)]
struct Encryption {
    aad: String,
    ct: String,
    pt: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(VECTORS).expect("vendored RFC 9180 corpus must parse")
}

fn decode(case_index: usize, name: &str, encoded: &str) -> Vec<u8> {
    hex::decode(encoded)
        .unwrap_or_else(|error| panic!("vector {case_index}: malformed {name}: {error}"))
}

fn kem_id(id: u16) -> KemId {
    match id {
        0x0010 => KemId::DhKemP256HkdfSha256,
        0x0011 => KemId::DhKemP384HkdfSha384,
        0x0012 => KemId::DhKemP521HkdfSha512,
        0x0020 => KemId::DhKemX25519HkdfSha256,
        0x0021 => KemId::DhKemX448HkdfSha512,
        _ => panic!("unknown RFC 9180 KEM identifier {id:#06x}"),
    }
}

fn kdf_id(id: u16) -> KdfId {
    match id {
        0x0001 => KdfId::HkdfSha256,
        0x0002 => KdfId::HkdfSha384,
        0x0003 => KdfId::HkdfSha512,
        _ => panic!("unknown RFC 9180 KDF identifier {id:#06x}"),
    }
}

fn aead_id(id: u16) -> AeadId {
    match id {
        0x0001 => AeadId::AesGcm128,
        0x0002 => AeadId::AesGcm256,
        0x0003 => AeadId::ChaCha20Poly1305,
        0xffff => AeadId::ExportOnly,
        _ => panic!("unknown RFC 9180 AEAD identifier {id:#06x}"),
    }
}

fn suite(vector: &Vector) -> HpkeSuite {
    HpkeSuite::new(
        kem_id(vector.kem_id),
        kdf_id(vector.kdf_id),
        aead_id(vector.aead_id),
    )
}

fn receiver_from_vector(
    case_index: usize,
    vector: &Vector,
) -> crypt_guard::hpke::rfc9180::ReceiverContext {
    let suite = suite(vector);
    let info = decode(case_index, "info", &vector.info);
    let recipient_private_key = PrivateKey::from_bytes(
        suite.kem_id(),
        &decode(case_index, "skRm", &vector.recipient_private_key),
    )
    .unwrap_or_else(|error| panic!("vector {case_index}: private key parse: {error}"));
    let enc = EncapsulatedKey::from_bytes(suite.kem_id(), &decode(case_index, "enc", &vector.enc))
        .unwrap_or_else(|error| panic!("vector {case_index}: enc parse: {error}"));
    let psk = vector
        .psk
        .as_deref()
        .map(|encoded| decode(case_index, "psk", encoded))
        .unwrap_or_default();
    let psk_id = vector
        .psk_id
        .as_deref()
        .map(|encoded| decode(case_index, "psk_id", encoded))
        .unwrap_or_default();

    match vector.mode {
        0 => setup_base_r(suite, &recipient_private_key, &enc, &info),
        1 => setup_psk_r(suite, &recipient_private_key, &enc, &info, &psk, &psk_id),
        2 => {
            let sender_public_key = PublicKey::from_bytes(
                suite.kem_id(),
                &decode(
                    case_index,
                    "pkSm",
                    vector
                        .sender_public_key
                        .as_deref()
                        .expect("Auth vector pkSm"),
                ),
            )
            .unwrap_or_else(|error| panic!("vector {case_index}: sender public parse: {error}"));
            setup_auth_r(
                suite,
                &recipient_private_key,
                &enc,
                &sender_public_key,
                &info,
            )
        }
        3 => {
            let sender_public_key = PublicKey::from_bytes(
                suite.kem_id(),
                &decode(
                    case_index,
                    "pkSm",
                    vector
                        .sender_public_key
                        .as_deref()
                        .expect("AuthPSK vector pkSm"),
                ),
            )
            .unwrap_or_else(|error| panic!("vector {case_index}: sender public parse: {error}"));
            setup_auth_psk_r(
                suite,
                &recipient_private_key,
                &enc,
                &sender_public_key,
                &info,
                &psk,
                &psk_id,
            )
        }
        mode => panic!("vector {case_index}: unknown mode {mode}"),
    }
    .unwrap_or_else(|error| panic!("vector {case_index}: Setup*R failed: {error}"))
}

#[test]
fn all_supported_rfc9180_receiver_vectors_match_every_mode_and_encryption() {
    let corpus = vectors();
    let mut exercised_suites = 0;
    let mut exercised_encryptions = 0;
    let mut modes = [0_usize; 4];

    for (case_index, vector) in corpus.iter().enumerate() {
        let mut context = receiver_from_vector(case_index, vector);

        for (export_index, export) in vector.exports.iter().enumerate() {
            let actual = context
                .export(
                    &decode(case_index, "exporter_context", &export.exporter_context),
                    export.output_len,
                )
                .unwrap_or_else(|error| {
                    panic!("vector {case_index}, export {export_index}: export failed: {error}")
                });
            assert_eq!(
                actual,
                decode(case_index, "exported_value", &export.exported_value),
                "vector {case_index}, export {export_index}: value mismatch"
            );
        }

        for (encryption_index, encryption) in vector.encryptions.iter().enumerate() {
            let plaintext = context
                .open(
                    &decode(case_index, "aad", &encryption.aad),
                    &decode(case_index, "ct", &encryption.ct),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "vector {case_index}, encryption {encryption_index}: Open failed: {error}"
                    )
                });
            assert_eq!(
                plaintext,
                decode(case_index, "pt", &encryption.pt),
                "vector {case_index}, encryption {encryption_index}: plaintext mismatch"
            );
            exercised_encryptions += 1;
        }
        modes[vector.mode as usize] += 1;
        exercised_suites += 1;
    }

    // The corpus has no P-384 endpoint vector, but it does cover every mode
    // for P-256, P-521, X25519, and X448, including Export-Only suites.
    assert_eq!(exercised_suites, 128);
    assert_eq!(modes, [32, 32, 32, 32]);
    assert_eq!(exercised_encryptions, 24_672);
}

fn all_kems() -> [KemId; 5] {
    [
        KemId::DhKemP256HkdfSha256,
        KemId::DhKemP384HkdfSha384,
        KemId::DhKemP521HkdfSha512,
        KemId::DhKemX25519HkdfSha256,
        KemId::DhKemX448HkdfSha512,
    ]
}

fn all_kdfs() -> [KdfId; 3] {
    [KdfId::HkdfSha256, KdfId::HkdfSha384, KdfId::HkdfSha512]
}

fn all_aeads() -> [AeadId; 3] {
    [
        AeadId::AesGcm128,
        AeadId::AesGcm256,
        AeadId::ChaCha20Poly1305,
    ]
}

#[test]
fn all_supported_kems_kdfs_aeads_and_modes_round_trip() {
    const INFO: &[u8] = b"RFC 9180 complete API integration test";
    const PSK: &[u8] = b"0123456789abcdef0123456789abcdef";
    const PSK_ID: &[u8] = b"service.example/psk/2026-07";
    let mut exercised = 0;

    for kem in all_kems() {
        for kdf in all_kdfs() {
            for aead in all_aeads() {
                let suite = HpkeSuite::new(kem, kdf, aead);
                let recipient = generate_key_pair(kem).unwrap();
                let sender = generate_key_pair(kem).unwrap();
                let aad = b"associated data";
                let plaintext = b"one message for each RFC 9180 KEM/KDF/AEAD/mode combination";

                let (enc, mut sender_context) =
                    setup_base_s(suite, &recipient.public_key, INFO).unwrap();
                let mut receiver_context =
                    setup_base_r(suite, &recipient.private_key, &enc, INFO).unwrap();
                assert_eq!(
                    receiver_context
                        .open(aad, &sender_context.seal(aad, plaintext).unwrap())
                        .unwrap(),
                    plaintext
                );

                let recipient = generate_key_pair(kem).unwrap();
                let (enc, mut sender_context) =
                    setup_psk_s(suite, &recipient.public_key, INFO, PSK, PSK_ID).unwrap();
                let mut receiver_context =
                    setup_psk_r(suite, &recipient.private_key, &enc, INFO, PSK, PSK_ID).unwrap();
                assert_eq!(
                    receiver_context
                        .open(aad, &sender_context.seal(aad, plaintext).unwrap())
                        .unwrap(),
                    plaintext
                );

                let recipient = generate_key_pair(kem).unwrap();
                let (enc, mut sender_context) =
                    setup_auth_s(suite, &recipient.public_key, &sender.private_key, INFO).unwrap();
                let mut receiver_context = setup_auth_r(
                    suite,
                    &recipient.private_key,
                    &enc,
                    &sender.public_key,
                    INFO,
                )
                .unwrap();
                assert_eq!(
                    receiver_context
                        .open(aad, &sender_context.seal(aad, plaintext).unwrap())
                        .unwrap(),
                    plaintext
                );

                let recipient = generate_key_pair(kem).unwrap();
                let (enc, mut sender_context) = setup_auth_psk_s(
                    suite,
                    &recipient.public_key,
                    &sender.private_key,
                    INFO,
                    PSK,
                    PSK_ID,
                )
                .unwrap();
                let mut receiver_context = setup_auth_psk_r(
                    suite,
                    &recipient.private_key,
                    &enc,
                    &sender.public_key,
                    INFO,
                    PSK,
                    PSK_ID,
                )
                .unwrap();
                assert_eq!(
                    receiver_context
                        .open(aad, &sender_context.seal(aad, plaintext).unwrap())
                        .unwrap(),
                    plaintext
                );
                exercised += 4;
            }
        }
    }

    assert_eq!(exercised, 180);
}

#[test]
fn x448_rejects_an_all_zero_dh_output_without_substitution() {
    let suite = HpkeSuite::new(
        KemId::DhKemX448HkdfSha512,
        KdfId::HkdfSha512,
        AeadId::AesGcm128,
    );
    let recipient = generate_key_pair(KemId::DhKemX448HkdfSha512).unwrap();
    let all_zero_enc =
        EncapsulatedKey::from_bytes(KemId::DhKemX448HkdfSha512, &[0_u8; 56]).unwrap();

    assert!(matches!(
        setup_base_r(
            suite,
            &recipient.private_key,
            &all_zero_enc,
            b"all-zero X448 DH"
        ),
        Err(Rfc9180Error::InvalidDhSharedSecret)
    ));
}
