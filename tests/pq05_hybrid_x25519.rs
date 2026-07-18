//! Draft-05 MLKEM768-X25519 endpoint-vector interoperability.

use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05_full::{
    generate_recipient_key_pair, setup_base_receiver, setup_base_sender,
    setup_base_sender_with_ikm_e, Aead, Capability, Kdf, Kem, RecipientPrivateKey, Suite,
};
use serde_json::Value;

fn kdf(id: u64) -> Kdf {
    match id {
        0x0001 => Kdf::HkdfSha256,
        0x0011 => Kdf::Shake256,
        _ => panic!("unexpected pinned KDF id {id:#06x}"),
    }
}

#[test]
fn x25519_hybrid_matches_all_pinned_draft05_base_endpoint_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("vectors/hpke-pq-draft-05-test-vectors.json")).unwrap();
    let vectors: Vec<_> = vectors
        .iter()
        .filter(|vector| vector["kem_id"].as_u64() == Some(0x647a))
        .collect();
    assert_eq!(
        vectors.len(),
        2,
        "pinned corpus must retain both X25519 cases"
    );

    for vector in vectors {
        let decode = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let suite = Suite::new(
            Kem::MlKem768X25519,
            kdf(vector["kdf_id"].as_u64().unwrap()),
            Aead::ChaCha20Poly1305,
        );
        assert_eq!(suite.capability(), Capability::Available);
        let recipient =
            RecipientPrivateKey::from_seed_bytes(Kem::MlKem768X25519, &decode("skRm")).unwrap();
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
}

#[test]
fn x25519_hybrid_works_with_every_registered_encryption_aead() {
    let pair = generate_recipient_key_pair(Kem::MlKem768X25519).unwrap();
    for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
        let suite = Suite::new(Kem::MlKem768X25519, Kdf::HkdfSha256, aead);
        assert_eq!(suite.capability(), Capability::Available);
        let (enc, mut sender) =
            setup_base_sender(suite, pair.public_key(), b"X25519 all-AEAD").unwrap();
        let mut receiver =
            setup_base_receiver(suite, pair.private_key(), &enc, b"X25519 all-AEAD").unwrap();
        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        assert_eq!(receiver.open(b"aad", &ciphertext).unwrap(), b"message");
        assert_eq!(
            sender.export(b"context", 42).unwrap(),
            receiver.export(b"context", 42).unwrap()
        );
    }
}
