//! External contract tests for CGv2 canonical wire validation.
//!
//! These tests deliberately use only public APIs. They lock down the strict
//! parser boundary and the checked serializer/AAD APIs introduced for CGv2
//! wire hardening:
//! - `Header::{validate, try_to_bytes}`
//! - `Envelope::{try_to_bytes, try_build_aad}`
//!
//! The fixture uses the standardized ML-KEM-768 encapsulation length (1088)
//! and the XChaCha20-Poly1305 nonce length (24). A production implementation
//! that exposes the named checked APIs is therefore required for this suite to
//! compile.

use crypt_guard::protocol::{
    aad::build_aad,
    envelope::Envelope,
    header::{AeadAlgId, Header, KdfAlgId, KemAlgId, HEADER_SIZE},
};

const ML_KEM_768_CIPHERTEXT_LEN: usize = 1_088;
const XCHACHA20_POLY1305_NONCE_LEN: usize = 24;

fn fixture_header() -> Header {
    Header::new(
        KemAlgId::MlKem768,
        AeadAlgId::XChaCha20Poly1305,
        KdfAlgId::HkdfSha256,
    )
}

fn fixture_envelope() -> Envelope {
    Envelope::new(
        fixture_header(),
        vec![0xA5; ML_KEM_768_CIPHERTEXT_LEN],
        vec![0x5A; XCHACHA20_POLY1305_NONCE_LEN],
        b"canonical CGv2 payload".to_vec(),
    )
}

#[test]
fn header_parser_requires_canonical_flags_reserved_bytes_and_exact_length() {
    let canonical = fixture_header().to_bytes();

    let mut nonzero_flags = canonical;
    nonzero_flags[9] = 1;
    assert!(
        Header::from_bytes(&nonzero_flags).is_err(),
        "nonzero header flags must be rejected"
    );

    let mut nonzero_reserved = canonical;
    nonzero_reserved[10] = 1;
    assert!(
        Header::from_bytes(&nonzero_reserved).is_err(),
        "nonzero reserved header bytes must be rejected"
    );

    assert!(
        Header::from_bytes(&canonical[..HEADER_SIZE - 1]).is_err(),
        "headers shorter than the exact wire width must be rejected"
    );

    let mut overlong = canonical.to_vec();
    overlong.push(0);
    assert!(
        Header::from_bytes(&overlong).is_err(),
        "headers longer than the exact wire width must be rejected"
    );
}

#[test]
fn envelope_parser_rejects_trailing_data_and_algorithm_length_mismatches() {
    let valid = fixture_envelope();
    let canonical = valid.try_to_bytes().unwrap();

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(
        Envelope::from_bytes(&trailing).is_err(),
        "a CGv2 envelope must consume its full input"
    );

    let kem_length_mismatch = Envelope::new(
        fixture_header(),
        vec![0xA5; ML_KEM_768_CIPHERTEXT_LEN - 1],
        vec![0x5A; XCHACHA20_POLY1305_NONCE_LEN],
        b"canonical CGv2 payload".to_vec(),
    )
    .to_bytes();
    assert!(
        Envelope::from_bytes(&kem_length_mismatch).is_err(),
        "KEM ciphertext length must match the declared ML-KEM parameter set"
    );

    let nonce_length_mismatch = Envelope::new(
        fixture_header(),
        vec![0xA5; ML_KEM_768_CIPHERTEXT_LEN],
        vec![0x5A; XCHACHA20_POLY1305_NONCE_LEN - 1],
        b"canonical CGv2 payload".to_vec(),
    )
    .to_bytes();
    assert!(
        Envelope::from_bytes(&nonce_length_mismatch).is_err(),
        "nonce length must match the declared AEAD algorithm"
    );
}

#[test]
fn valid_cgv2_roundtrip_preserves_its_canonical_wire_bytes() {
    let original = fixture_envelope();
    let canonical = original.try_to_bytes().unwrap();
    let parsed = Envelope::from_bytes(&canonical).unwrap();

    assert_eq!(parsed, original);
    assert_eq!(parsed.try_to_bytes().unwrap(), canonical);
}

#[test]
fn checked_serializers_and_aad_preserve_the_legacy_valid_encoding() {
    let header = fixture_header();
    let envelope = fixture_envelope();
    let metadata = b"caller-bound metadata";

    assert!(header.validate().is_ok());
    assert_eq!(header.try_to_bytes().unwrap(), header.to_bytes());
    assert_eq!(envelope.try_to_bytes().unwrap(), envelope.to_bytes());
    assert_eq!(
        envelope.try_build_aad(metadata).unwrap(),
        build_aad(
            &envelope.header,
            &envelope.kem_ciphertext,
            &envelope.nonce,
            metadata,
        )
    );
}
