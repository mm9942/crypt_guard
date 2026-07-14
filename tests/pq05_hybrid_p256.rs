//! Draft-05 MLKEM768-P256 endpoint-vector interoperability.
#![cfg(feature = "hpke-pq-draft-05")]

use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05_full::{
    setup_base_receiver, setup_base_sender_with_ikm_e, Aead, Kdf, Kem, RecipientPrivateKey, Suite,
};
use serde_json::Value;

fn kdf(id: u64) -> Kdf {
    match id {
        0x0001 => Kdf::HkdfSha256,
        0x0010 => Kdf::Shake128,
        _ => panic!("unexpected pinned KDF id {id:#06x}"),
    }
}

fn aead(id: u64) -> Aead {
    match id {
        0x0001 => Aead::Aes128Gcm,
        0x0002 => Aead::Aes256Gcm,
        _ => panic!("unexpected pinned AEAD id {id:#06x}"),
    }
}

#[test]
fn p256_hybrid_matches_all_pinned_draft05_base_endpoint_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("vectors/hpke-pq-draft-05-test-vectors.json")).unwrap();
    let vectors: Vec<_> = vectors
        .iter()
        .filter(|vector| vector["kem_id"].as_u64() == Some(0x0050))
        .collect();
    assert_eq!(
        vectors.len(),
        2,
        "pinned corpus must retain both P-256 cases"
    );

    for vector in vectors {
        let decode = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let suite = Suite::new(
            Kem::MlKem768P256,
            kdf(vector["kdf_id"].as_u64().unwrap()),
            aead(vector["aead_id"].as_u64().unwrap()),
        );
        let recipient =
            RecipientPrivateKey::from_seed_bytes(Kem::MlKem768P256, &decode("skRm")).unwrap();
        let public = recipient.public_key().unwrap();
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
            let output_len = export["L"].as_u64().unwrap() as usize;
            let expected = hex::decode(export["exported_value"].as_str().unwrap()).unwrap();
            assert_eq!(sender.export(&context, output_len).unwrap(), expected);
            assert_eq!(receiver.export(&context, output_len).unwrap(), expected);
        }
    }
}
