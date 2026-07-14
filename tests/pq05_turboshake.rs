#![cfg(feature = "hpke-pq-draft-05")]

use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05_full as hpke;
use turboshake::{
    digest::{ExtendableOutput, Update, XofReader},
    TurboShake128, TurboShake256,
};

#[test]
fn rfc9861_turboshake128_default_domain_empty_vectors() {
    let expected32 =
        hex::decode("1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c").unwrap();
    let expected64 =
        [
            &expected32[..],
            &hex::decode("3e8ccae2a4dae56c84a04c2385c03c15e8193bdf58737363321691c05462c8df")
                .unwrap()[..],
        ]
        .concat();
    let mut xof = TurboShake128::default();
    xof.update(&[]);
    let mut reader = xof.finalize_xof();
    let mut actual = vec![0; 64];
    reader.read(&mut actual);
    assert_eq!(&actual[..32], expected32.as_slice());
    assert_eq!(actual, expected64);
}

#[test]
fn rfc9861_turboshake256_default_domain_empty_vector() {
    let expected = hex::decode(
        "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0",
    )
    .unwrap();
    let mut xof = TurboShake256::default();
    xof.update(&[]);
    let mut actual = vec![0; 64];
    xof.finalize_xof().read(&mut actual);
    assert_eq!(actual, expected);
}

#[test]
fn draft05_turboshake128_base_round_trip_and_export() {
    let suite = hpke::Suite::new(
        hpke::Kem::MlKem768,
        hpke::Kdf::TurboShake128,
        hpke::Aead::Aes128Gcm,
    );
    assert_eq!(suite.capability(), hpke::Capability::Available);
    let key_pair = hpke::generate_recipient_key_pair(suite.kem()).unwrap();
    let (enc, mut sender) = hpke::setup_base_sender(suite, key_pair.public_key(), b"info").unwrap();
    let mut receiver =
        hpke::setup_base_receiver(suite, key_pair.private_key(), &enc, b"info").unwrap();
    let ciphertext = sender.seal(b"aad", b"message").unwrap();
    assert_eq!(receiver.open(b"aad", &ciphertext).unwrap(), b"message");
    assert_eq!(
        sender.export(b"ctx", 48).unwrap(),
        receiver.export(b"ctx", 48).unwrap()
    );
}

#[test]
fn draft05_turboshake256_supports_remaining_rfc9180_aeads() {
    for aead in [hpke::Aead::Aes256Gcm, hpke::Aead::ChaCha20Poly1305] {
        let suite = hpke::Suite::new(hpke::Kem::MlKem768, hpke::Kdf::TurboShake256, aead);
        let key_pair = hpke::generate_recipient_key_pair(suite.kem()).unwrap();
        let (enc, mut sender) =
            hpke::setup_base_sender(suite, key_pair.public_key(), b"info").unwrap();
        let mut receiver =
            hpke::setup_base_receiver(suite, key_pair.private_key(), &enc, b"info").unwrap();
        let ciphertext = sender.seal(b"aad", b"message").unwrap();
        assert_eq!(receiver.open(b"aad", &ciphertext).unwrap(), b"message");
    }
}
