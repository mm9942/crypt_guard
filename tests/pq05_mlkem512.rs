//! Official draft-05 corpus coverage for the FIPS 203 ML-KEM-512 adapter.

#![cfg(feature = "hpke-pq-draft-05")]

use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05_full::{
    generate_recipient_key_pair, setup_base_receiver, setup_base_sender, Aead, Capability,
    Encapsulation, Error, Kdf, Kem, RecipientPrivateKey, RecipientPublicKey, Suite,
};
use serde::Deserialize;

const ML_KEM_512_ID: u16 = 0x0040;

#[derive(Deserialize)]
struct Vector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    enc: String,
    encryptions: Vec<Encryption>,
    exports: Vec<Export>,
}

#[derive(Deserialize)]
struct Encryption {
    aad: String,
    ct: String,
    pt: String,
}

#[derive(Deserialize)]
struct Export {
    exporter_context: String,
    #[serde(rename = "L")]
    output_len: usize,
    exported_value: String,
}

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vendored draft vector contains hexadecimal")
}

fn kdf(id: u16) -> Kdf {
    match id {
        0x0001 => Kdf::HkdfSha256,
        0x0002 => Kdf::HkdfSha384,
        0x0003 => Kdf::HkdfSha512,
        0x0010 => Kdf::Shake128,
        0x0011 => Kdf::Shake256,
        0x0012 => Kdf::TurboShake128,
        0x0013 => Kdf::TurboShake256,
        other => panic!("unrecognized KDF id in pinned ML-KEM-512 vector: {other:#06x}"),
    }
}

fn aead(id: u16) -> Aead {
    match id {
        0x0001 => Aead::Aes128Gcm,
        0x0002 => Aead::Aes256Gcm,
        0x0003 => Aead::ChaCha20Poly1305,
        0xffff => Aead::ExportOnly,
        other => panic!("unrecognized AEAD id in pinned ML-KEM-512 vector: {other:#06x}"),
    }
}

#[test]
fn ml_kem_512_supports_every_rfc_9180_encryption_aead_without_suite_substitution() {
    let pair = generate_recipient_key_pair(Kem::MlKem512)
        .expect("ML-KEM-512 PQCA adapter generates seed-format keys");
    for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
        let suite = Suite::new(Kem::MlKem512, Kdf::HkdfSha256, aead);
        assert_eq!(suite.capability(), Capability::Available);
        let (encapsulation, mut sender) =
            setup_base_sender(suite, pair.public_key(), b"ml-kem-512 all-aead contract")
                .expect("sender setup must use exactly the selected suite");
        let mut receiver = setup_base_receiver(
            suite,
            pair.private_key(),
            &encapsulation,
            b"ml-kem-512 all-aead contract",
        )
        .expect("recipient setup must use exactly the selected suite");
        let ciphertext = sender
            .seal(b"ml-kem-512 aad", b"all registered AEADs")
            .expect("selected AEAD seals");
        assert_eq!(
            receiver
                .open(b"ml-kem-512 aad", &ciphertext)
                .expect("exact selected AEAD authenticates"),
            b"all registered AEADs",
        );
    }
}

#[test]
fn ml_kem_512_official_base_vectors_validate_fips_seed_decapsulation_and_hpke_context() {
    let all: Vec<Vector> =
        serde_json::from_str(include_str!("vectors/hpke-pq-draft-05-test-vectors.json"))
            .expect("vendored draft corpus is JSON");
    let vectors: Vec<_> = all
        .iter()
        .filter(|vector| vector.kem_id == ML_KEM_512_ID)
        .collect();
    assert_eq!(
        vectors.len(),
        1,
        "pinned corpus must retain its ML-KEM-512 record"
    );

    for vector in vectors {
        assert_eq!(vector.mode, 0, "draft corpus record is Base mode");
        let suite = Suite::new(Kem::MlKem512, kdf(vector.kdf_id), aead(vector.aead_id));
        assert_eq!(suite.capability(), Capability::Available);

        let public_key = RecipientPublicKey::from_bytes(Kem::MlKem512, &decode(&vector.pk_rm))
            .expect("official FIPS 203 ML-KEM-512 public key validates");
        assert_eq!(public_key.as_bytes(), decode(&vector.pk_rm));
        let private_key =
            RecipientPrivateKey::from_seed_bytes(Kem::MlKem512, &decode(&vector.sk_rm))
                .expect("official 64-byte ML-KEM-512 seed parses");
        let encapsulation = Encapsulation::from_bytes(Kem::MlKem512, &decode(&vector.enc))
            .expect("official ML-KEM-512 encapsulation has canonical length");

        let mut receiver =
            setup_base_receiver(suite, &private_key, &encapsulation, &decode(&vector.info))
                .expect("FIPS 203 decapsulation and HPKE schedule reproduce the corpus");
        for encryption in &vector.encryptions {
            assert_eq!(
                receiver
                    .open(&decode(&encryption.aad), &decode(&encryption.ct))
                    .expect("official ciphertext authenticates"),
                decode(&encryption.pt),
            );
        }
        for export in &vector.exports {
            assert_eq!(
                receiver
                    .export(&decode(&export.exporter_context), export.output_len)
                    .expect("official exporter derives"),
                decode(&export.exported_value),
            );
        }
    }
}

#[test]
fn ml_kem_512_fixed_size_encapsulation_tampering_is_only_an_aead_failure() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("vectors/hpke-pq-draft-05-test-vectors.json"))
            .expect("vendored draft corpus is JSON");
    let vector = vectors
        .iter()
        .find(|vector| vector.kem_id == ML_KEM_512_ID)
        .expect("pinned corpus contains ML-KEM-512");
    let suite = Suite::new(Kem::MlKem512, kdf(vector.kdf_id), aead(vector.aead_id));
    let private_key = RecipientPrivateKey::from_seed_bytes(Kem::MlKem512, &decode(&vector.sk_rm))
        .expect("official seed parses");
    let mut tampered = decode(&vector.enc);
    tampered[0] ^= 0x80;
    let encapsulation = Encapsulation::from_bytes(Kem::MlKem512, &tampered)
        .expect("same-size encapsulation remains a KEM input");
    let mut receiver =
        setup_base_receiver(suite, &private_key, &encapsulation, &decode(&vector.info))
            .expect("implicit rejection does not create a KEM oracle");
    let encryption = &vector.encryptions[0];
    assert_eq!(
        receiver.open(&decode(&encryption.aad), &decode(&encryption.ct)),
        Err(Error::AuthenticationFailed),
    );
}
