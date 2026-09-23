//! Public v3 PQ HPKE transport contracts.

use crypt_guard::pq_hpke::{
    derive_recipient_key_pair, generate_recipient_key_pair, setup_base_receiver, setup_base_sender,
    Aead, EnvelopeError, Error, HpkeEnvelope, Kdf, Kem, Suite, DEFAULT_SUITE,
};

#[test]
fn provenance_seed_rederives_v3_recipient_for_open_without_persisting_private_material() {
    // This is the only secret material a provenance store retains. In
    // particular, it is not the 64-byte ML-KEM recipient seed created inside
    // the v3 derivation path.
    let provenance_seed = [0x4d_u8; 32];
    let suite = Suite::new(Kem::MlKem768, Kdf::Shake256, Aead::ChaCha20Poly1305);

    let sealing_pair = derive_recipient_key_pair(suite.kem(), &provenance_seed)
        .expect("a validated provenance seed must derive a v3 recipient");
    assert_eq!(sealing_pair.private_key().as_seed_bytes().len(), 64);
    assert_ne!(sealing_pair.private_key().as_seed_bytes(), provenance_seed);
    let envelope = HpkeEnvelope::seal(
        suite,
        sealing_pair.public_key(),
        b"Harw provenance record",
        b"provenance-bound AAD",
        b"payload opened after rederivation",
    )
    .expect("derived recipient must seal");
    drop(sealing_pair);

    // Model an open after process restart: rederive from the retained original
    // 32-byte seed, rather than serializing the internal recipient private
    // representation.
    let opening_pair = derive_recipient_key_pair(suite.kem(), &provenance_seed)
        .expect("the retained provenance seed must rederive the same recipient");
    assert_eq!(
        envelope
            .open(
                opening_pair.private_key(),
                b"Harw provenance record",
                b"provenance-bound AAD",
            )
            .expect("rederived recipient must open"),
        b"payload opened after rederivation"
    );
}

#[test]
fn default_envelope_round_trip_preserves_the_default_profile() {
    let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
    let envelope = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        b"v3 transport context",
        b"request metadata",
        b"post-quantum payload",
    )
    .unwrap();

    assert_eq!(envelope.suite(), DEFAULT_SUITE);
    assert_eq!(&envelope.to_bytes()[..4], b"CGH3");

    let decoded = HpkeEnvelope::from_bytes(&envelope.to_bytes()).unwrap();
    assert_eq!(
        decoded
            .open(
                keys.private_key(),
                b"v3 transport context",
                b"request metadata",
            )
            .unwrap(),
        b"post-quantum payload"
    );
}

#[test]
fn envelope_open_reports_only_opaque_authentication_failure() {
    let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
    let envelope = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        b"bound info",
        b"bound aad",
        b"authenticated plaintext",
    )
    .unwrap();

    assert_eq!(
        envelope.open(keys.private_key(), b"different info", b"bound aad"),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        envelope.open(keys.private_key(), b"bound info", b"different aad"),
        Err(Error::AuthenticationFailed)
    );

    let mut encoded = envelope.to_bytes();
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    let tampered = HpkeEnvelope::from_bytes(&encoded).unwrap();
    assert_eq!(
        tampered.open(keys.private_key(), b"bound info", b"bound aad"),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn malformed_envelopes_are_rejected_before_decryption() {
    assert_eq!(
        HpkeEnvelope::from_bytes(b"CGH3"),
        Err(EnvelopeError::InvalidEncoding)
    );

    let mut invalid_magic = vec![0_u8; 20];
    invalid_magic[..4].copy_from_slice(b"CGv2");
    assert_eq!(
        HpkeEnvelope::from_bytes(&invalid_magic),
        Err(EnvelopeError::InvalidMagic)
    );

    let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
    let mut encoded = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        b"info",
        b"aad",
        b"payload",
    )
    .unwrap()
    .to_bytes();
    encoded.push(0);
    assert_eq!(
        HpkeEnvelope::from_bytes(&encoded),
        Err(EnvelopeError::InvalidEncoding)
    );
}

#[test]
fn raw_base_contexts_round_trip_with_separately_transport_encapsulation() {
    let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
    let (encapsulation, mut sender) =
        setup_base_sender(DEFAULT_SUITE, keys.public_key(), b"raw transport info").unwrap();
    let ciphertext = sender.seal(b"raw aad", b"raw HPKE ciphertext").unwrap();

    let mut receiver = setup_base_receiver(
        DEFAULT_SUITE,
        keys.private_key(),
        &encapsulation,
        b"raw transport info",
    )
    .unwrap();
    assert_eq!(
        receiver.open(b"raw aad", &ciphertext).unwrap(),
        b"raw HPKE ciphertext"
    );
}
