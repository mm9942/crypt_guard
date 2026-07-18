//! Offline RFC 9180 vectors for the HPKE key-schedule foundation.
//!
//! This test intentionally validates only the part this crate currently
//! implements: Base-mode key-schedule derivation from an already-established
//! shared secret, including the exporter operation. It does not validate KEM
//! setup or AEAD encryption/decryption. Those operations need their own
//! endpoint-level vector harnesses once the corresponding public APIs exist.

use crypt_guard::hpke::{key_schedule, AeadId, HpkeSuite, KdfId, KemId, Mode};
use serde::Deserialize;

const RFC_9180_VECTORS: &str = include_str!("vectors/rfc9180-test-vectors.json");

#[derive(Deserialize)]
struct Vector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    shared_secret: String,
    key_schedule_context: String,
    secret: String,
    key: String,
    base_nonce: String,
    exporter_secret: String,
    exports: Vec<Export>,
    // Kept as a zero-sized structure so the harness can explicitly inventory
    // AEAD vectors without pretending that it can execute them.
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
struct Encryption {}

fn corpus() -> Vec<Vector> {
    serde_json::from_str(RFC_9180_VECTORS).expect("vendored RFC 9180 vector corpus must parse")
}

fn kem_id(id: u16) -> Option<KemId> {
    match id {
        0x0010 => Some(KemId::DhKemP256HkdfSha256),
        0x0011 => Some(KemId::DhKemP384HkdfSha384),
        0x0012 => Some(KemId::DhKemP521HkdfSha512),
        0x0020 => Some(KemId::DhKemX25519HkdfSha256),
        0x0021 => Some(KemId::DhKemX448HkdfSha512),
        _ => None,
    }
}

fn kdf_id(id: u16) -> Option<KdfId> {
    match id {
        0x0001 => Some(KdfId::HkdfSha256),
        0x0002 => Some(KdfId::HkdfSha384),
        0x0003 => Some(KdfId::HkdfSha512),
        _ => None,
    }
}

fn aead_id(id: u16) -> Option<AeadId> {
    match id {
        0x0001 => Some(AeadId::AesGcm128),
        0x0002 => Some(AeadId::AesGcm256),
        0x0003 => Some(AeadId::ChaCha20Poly1305),
        0xffff => Some(AeadId::ExportOnly),
        _ => None,
    }
}

fn suite(vector: &Vector) -> Option<HpkeSuite> {
    Some(HpkeSuite::new(
        kem_id(vector.kem_id)?,
        kdf_id(vector.kdf_id)?,
        aead_id(vector.aead_id)?,
    ))
}

fn decode(case_index: usize, field: &str, encoded: &str) -> Vec<u8> {
    hex::decode(encoded).unwrap_or_else(|error| {
        panic!("RFC 9180 vector {case_index} has malformed {field} hex: {error}")
    })
}

fn assert_vector_bytes(case_index: usize, field: &str, actual: &[u8], encoded: &str) {
    assert_eq!(
        actual,
        decode(case_index, field, encoded),
        "RFC 9180 vector {case_index}: {field} mismatch"
    );
}

#[test]
fn rfc9180_base_mode_key_schedule_vectors_match() {
    let vectors = corpus();
    let mut exercised_schedules = 0;
    let mut exercised_exports = 0;

    for (case_index, vector) in vectors.iter().enumerate() {
        // The crate intentionally supports only Base mode for its current
        // key-schedule core. PSK/Auth/AuthPSK vectors are covered by the
        // explicit inventory test below and must not be silently treated as
        // passing by this harness.
        if vector.mode != Mode::Base.as_u8() {
            continue;
        }

        let suite = suite(vector).unwrap_or_else(|| {
            panic!(
                "RFC 9180 Base vector {case_index} uses an unimplemented suite: \
                 kem={:#06x}, kdf={:#06x}, aead={:#06x}",
                vector.kem_id, vector.kdf_id, vector.aead_id
            )
        });
        let expected_suite_id = [
            b'H',
            b'P',
            b'K',
            b'E',
            (vector.kem_id >> 8) as u8,
            vector.kem_id as u8,
            (vector.kdf_id >> 8) as u8,
            vector.kdf_id as u8,
            (vector.aead_id >> 8) as u8,
            vector.aead_id as u8,
        ];
        assert_eq!(
            suite.suite_id(),
            expected_suite_id,
            "RFC 9180 vector {case_index}: suite identifier mismatch"
        );

        let shared_secret = decode(case_index, "shared_secret", &vector.shared_secret);
        let info = decode(case_index, "info", &vector.info);
        let schedule = key_schedule(suite, Mode::Base, &shared_secret, &info, b"", b"")
            .unwrap_or_else(|error| {
                panic!("RFC 9180 Base vector {case_index}: key schedule failed: {error}")
            });

        assert_vector_bytes(
            case_index,
            "key_schedule_context",
            schedule.key_schedule_context(),
            &vector.key_schedule_context,
        );
        assert_vector_bytes(case_index, "secret", schedule.secret(), &vector.secret);
        assert_vector_bytes(case_index, "key", schedule.key(), &vector.key);
        assert_vector_bytes(
            case_index,
            "base_nonce",
            schedule.base_nonce(),
            &vector.base_nonce,
        );
        assert_vector_bytes(
            case_index,
            "exporter_secret",
            schedule.exporter_secret(),
            &vector.exporter_secret,
        );

        let context = schedule.into_base_context();
        for (export_index, export) in vector.exports.iter().enumerate() {
            let exporter_context = decode(case_index, "exporter_context", &export.exporter_context);
            let actual = context
                .export(&exporter_context, export.output_len)
                .unwrap_or_else(|error| {
                    panic!(
                        "RFC 9180 Base vector {case_index}, export {export_index}: export failed: {error}"
                    )
                });
            assert_vector_bytes(
                case_index,
                "exported_value",
                &actual,
                &export.exported_value,
            );
            exercised_exports += 1;
        }

        exercised_schedules += 1;
    }

    assert_eq!(
        exercised_schedules, 32,
        "the vendored RFC 9180 corpus currently has 32 Base-mode suite vectors"
    );
    assert_eq!(
        exercised_exports, 96,
        "each of the 32 Base-mode vectors has three exporter checks"
    );
}

#[test]
fn rfc9180_vector_coverage_boundary_is_explicit() {
    let vectors = corpus();
    let mut base_mode = 0;
    let mut unsupported_modes = 0;
    let mut base_exports = 0;
    let mut aead_operations_not_exercised = 0;

    for (case_index, vector) in vectors.iter().enumerate() {
        assert!(
            suite(vector).is_some(),
            "RFC 9180 vector {case_index} uses an unknown suite identifier"
        );
        if vector.mode == Mode::Base.as_u8() {
            base_mode += 1;
            base_exports += vector.exports.len();
        } else {
            unsupported_modes += 1;
        }
        aead_operations_not_exercised += vector.encryptions.len();
    }

    assert_eq!(vectors.len(), 128, "unexpected RFC 9180 corpus size");
    assert_eq!(
        base_mode, 32,
        "all Base-mode suites must be exercised above"
    );
    assert_eq!(
        base_exports, 96,
        "all Base-mode exporter outputs are exercised"
    );
    assert_eq!(
        unsupported_modes, 96,
        "PSK/Auth/AuthPSK vectors remain unsupported until their key schedules are implemented"
    );
    assert_eq!(
        aead_operations_not_exercised, 24_672,
        "KEM setup and AEAD ciphertexts are intentionally outside this key-schedule harness"
    );
}
