//! Draft-05 MLKEM1024-P384 endpoint-vector interoperability.
use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05_full::{
    generate_recipient_key_pair, setup_base_receiver, setup_base_sender,
    setup_base_sender_with_ikm_e, Aead, Capability, Kdf, Kem, RecipientPrivateKey, Suite,
};
use serde_json::Value;

#[test]
fn p384_hybrid_matches_the_pinned_draft05_base_endpoint_vector() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("vectors/hpke-pq-draft-05-test-vectors.json")).unwrap();
    let vectors: Vec<_> = vectors
        .iter()
        .filter(|v| v["kem_id"].as_u64() == Some(0x0051))
        .collect();
    assert_eq!(vectors.len(), 1, "pinned corpus must retain the P-384 case");
    let vector = vectors[0];
    let decode = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
    let suite = Suite::new(Kem::MlKem1024P384, Kdf::HkdfSha384, Aead::Aes256Gcm);
    let recipient =
        RecipientPrivateKey::from_seed_bytes(Kem::MlKem1024P384, &decode("skRm")).unwrap();
    let public = recipient.public_key().unwrap();
    assert_eq!(public.as_bytes(), decode("pkRm"));
    let (enc, mut sender) =
        setup_base_sender_with_ikm_e(suite, &public, &decode("info"), &decode("ikmE")).unwrap();
    assert_eq!(enc.as_bytes(), decode("enc"));
    let mut receiver = setup_base_receiver(suite, &recipient, &enc, &decode("info")).unwrap();
    for encryption in vector["encryptions"].as_array().unwrap() {
        let aad = hex::decode(encryption["aad"].as_str().unwrap()).unwrap();
        let plaintext = hex::decode(encryption["pt"].as_str().unwrap()).unwrap();
        let ciphertext = hex::decode(encryption["ct"].as_str().unwrap()).unwrap();
        assert_eq!(sender.seal(&aad, &plaintext).unwrap(), ciphertext);
        assert_eq!(receiver.open(&aad, &ciphertext).unwrap(), plaintext);
    }
    for export in vector["exports"].as_array().unwrap() {
        let context = hex::decode(export["exporter_context"].as_str().unwrap()).unwrap();
        let length = export["L"].as_u64().unwrap() as usize;
        let expected = hex::decode(export["exported_value"].as_str().unwrap()).unwrap();
        assert_eq!(sender.export(&context, length).unwrap(), expected);
        assert_eq!(receiver.export(&context, length).unwrap(), expected);
    }
}

#[test]
fn p384_hybrid_works_with_every_registered_encryption_aead() {
    let pair = generate_recipient_key_pair(Kem::MlKem1024P384).unwrap();
    for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
        let suite = Suite::new(Kem::MlKem1024P384, Kdf::HkdfSha384, aead);
        assert_eq!(suite.capability(), Capability::Available);
        let (enc, mut sender) =
            setup_base_sender(suite, pair.public_key(), b"P384 all-AEAD").unwrap();
        let mut receiver =
            setup_base_receiver(suite, pair.private_key(), &enc, b"P384 all-AEAD").unwrap();
        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        assert_eq!(receiver.open(b"aad", &ciphertext).unwrap(), b"message");
        assert_eq!(
            sender.export(b"context", 42).unwrap(),
            receiver.export(b"context", 42).unwrap()
        );
    }
}
