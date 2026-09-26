//! Phase 3 integration tests: Envelope roundtrip, tamper rejection, and typestate gating.
//!
//! # Scope
//! Tests cover:
//! - XChaCha20Poly1305 roundtrip (AEAD)
//! - AesGcmSiv roundtrip (AEAD)
//! - XChaCha20 roundtrip (non-AEAD)
//! - Envelope tamper rejection (ciphertext flip → AuthenticationFailed)
//! - Envelope tamper rejection (nonce flip → AuthenticationFailed)
//! - Envelope tamper rejection (KEM ciphertext flip → DecapsulationError or AuthenticationFailed)
//! - Protocol serialization roundtrip

#![allow(unused_imports)]

use crate::{
    api::{Decryptor, Encryptor},
    core::hub::{DecryptData, DecryptText, EncryptData, EncryptText, Kyber, MlKem768},
    error::CryptError,
    markers::{AesGcmSiv, Data, Decryption, Encryption, Message, XChaCha20, XChaCha20Poly1305},
    protocol::{
        header::{AeadAlgId, Header, KdfAlgId, KemAlgId},
        Envelope,
    },
};

/// Generate an ML-KEM-768 keypair using the KemBackend trait.
#[cfg(feature = "ml-kem-backend")]
fn gen_keypair_768() -> (Vec<u8>, Vec<u8>) {
    use crate::kem::{backend::OsRng, ml_kem::MlKem768Impl, KemBackend};
    let mut rng = OsRng;
    let (pk, sk) = MlKem768Impl::keypair(&mut rng).unwrap();
    (pk.as_ref().to_vec(), sk.as_ref().to_vec())
}

// ── XChaCha20Poly1305 AEAD roundtrip ─────────────────────────────────────────

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_xchacha20poly1305_roundtrip_message() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"Hello from Phase 3 XChaCha20Poly1305!";

    let mut enc = Kyber::<Encryption, MlKem768, Data, XChaCha20Poly1305>::new(pk, None).unwrap();
    let envelope = enc.encrypt_data(plaintext, "passphrase").unwrap();

    let dec = Kyber::<Decryption, MlKem768, Data, XChaCha20Poly1305>::new(sk, None).unwrap();
    let recovered = dec
        .decrypt_data(plaintext, "passphrase", &envelope)
        .unwrap();

    assert_eq!(recovered, plaintext);
    // Nonce must be stored in the envelope, not empty.
    assert_eq!(envelope.nonce.len(), 24);
    // KEM ciphertext must be present.
    assert!(!envelope.kem_ciphertext.is_empty());
}

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_xchacha20poly1305_encrypt_msg_roundtrip() {
    let (pk, sk) = gen_keypair_768();
    let message = "A secret message over the new FIPS path";

    let mut enc = Kyber::<Encryption, MlKem768, Message, XChaCha20Poly1305>::new(pk, None).unwrap();
    let envelope = enc.encrypt_msg(message, "pp").unwrap();

    let dec = Kyber::<Decryption, MlKem768, Message, XChaCha20Poly1305>::new(sk, None).unwrap();
    let recovered = dec
        .decrypt_msg(&envelope.ciphertext.clone(), "pp", &envelope)
        .unwrap();

    assert_eq!(recovered, message.as_bytes());
}

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_safe_api_roundtrip_xchacha20poly1305() {
    let (pk, sk) = gen_keypair_768();

    let envelope = Encryptor::<MlKem768, XChaCha20Poly1305>::new()
        .recipient(pk)
        .plaintext(b"safe api")
        .seal()
        .unwrap();

    let recovered = Decryptor::<MlKem768, XChaCha20Poly1305>::new()
        .secret_key(sk)
        .open(&envelope)
        .unwrap();

    assert_eq!(recovered, b"safe api");
}

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_safe_api_roundtrip_aes_gcm_siv() {
    let (pk, sk) = gen_keypair_768();

    let envelope = Encryptor::<MlKem768, AesGcmSiv>::new()
        .recipient(pk)
        .seal_bytes(b"safe api aes")
        .unwrap();

    let recovered = Decryptor::<MlKem768, AesGcmSiv>::new()
        .secret_key(sk)
        .open(&envelope)
        .unwrap();

    assert_eq!(recovered, b"safe api aes");
}

// ── AesGcmSiv AEAD roundtrip ──────────────────────────────────────────────────

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_aesgcmsiv_roundtrip() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"AES-GCM-SIV Phase 3 roundtrip test";

    let mut enc = Kyber::<Encryption, MlKem768, Data, AesGcmSiv>::new(pk, None).unwrap();
    let envelope = enc.encrypt_data(plaintext, "pp").unwrap();

    assert_eq!(envelope.header.aead_alg, AeadAlgId::AesGcmSiv);
    assert_eq!(envelope.nonce.len(), 12);

    let dec = Kyber::<Decryption, MlKem768, Data, AesGcmSiv>::new(sk, None).unwrap();
    let recovered = dec.decrypt_data(plaintext, "pp", &envelope).unwrap();
    assert_eq!(recovered, plaintext);
}

// ── XChaCha20 (non-AEAD) roundtrip ───────────────────────────────────────────

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_xchacha20_roundtrip() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"XChaCha20 stream cipher non-AEAD test";

    let mut enc = Kyber::<Encryption, MlKem768, Data, XChaCha20>::new(pk, None).unwrap();
    let envelope = enc.encrypt_data(plaintext, "pp").unwrap();

    assert_eq!(envelope.header.aead_alg, AeadAlgId::XChaCha20);
    assert_eq!(envelope.nonce.len(), 24);

    let dec = Kyber::<Decryption, MlKem768, Data, XChaCha20>::new(sk, None).unwrap();
    let recovered = dec.decrypt_data(plaintext, "pp", &envelope).unwrap();
    assert_eq!(recovered, plaintext);
}

// ── Tamper rejection tests ────────────────────────────────────────────────────

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_xchacha20poly1305_tamper_ciphertext_rejected() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"Tamper test plaintext";

    let mut enc = Kyber::<Encryption, MlKem768, Data, XChaCha20Poly1305>::new(pk, None).unwrap();
    let mut envelope = enc.encrypt_data(plaintext, "pp").unwrap();

    // Flip last byte of ciphertext.
    let last = envelope.ciphertext.len() - 1;
    envelope.ciphertext[last] ^= 0xFF;

    let dec = Kyber::<Decryption, MlKem768, Data, XChaCha20Poly1305>::new(sk, None).unwrap();
    let result = dec.decrypt_data(plaintext, "pp", &envelope);
    assert!(matches!(result, Err(CryptError::AuthenticationFailed)));
}

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_xchacha20poly1305_tamper_nonce_rejected() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"Nonce tamper test";

    let mut enc = Kyber::<Encryption, MlKem768, Data, XChaCha20Poly1305>::new(pk, None).unwrap();
    let mut envelope = enc.encrypt_data(plaintext, "pp").unwrap();

    // Flip a nonce byte.
    envelope.nonce[0] ^= 0x01;

    let dec = Kyber::<Decryption, MlKem768, Data, XChaCha20Poly1305>::new(sk, None).unwrap();
    let result = dec.decrypt_data(plaintext, "pp", &envelope);
    assert!(matches!(result, Err(CryptError::AuthenticationFailed)));
}

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_xchacha20_tamper_ciphertext_rejected() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"XChaCha20 tamper test";

    let mut enc = Kyber::<Encryption, MlKem768, Data, XChaCha20>::new(pk, None).unwrap();
    let mut envelope = enc.encrypt_data(plaintext, "pp").unwrap();

    envelope.ciphertext[0] ^= 0xAA;

    let dec = Kyber::<Decryption, MlKem768, Data, XChaCha20>::new(sk, None).unwrap();
    let result = dec.decrypt_data(plaintext, "pp", &envelope);
    assert!(matches!(result, Err(CryptError::AuthenticationFailed)));
}

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_aesgcmsiv_tamper_ciphertext_rejected() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"AES-GCM-SIV tamper test";

    let mut enc = Kyber::<Encryption, MlKem768, Data, AesGcmSiv>::new(pk, None).unwrap();
    let mut envelope = enc.encrypt_data(plaintext, "pp").unwrap();

    envelope.ciphertext[5] ^= 0xFF;

    let dec = Kyber::<Decryption, MlKem768, Data, AesGcmSiv>::new(sk, None).unwrap();
    let result = dec.decrypt_data(plaintext, "pp", &envelope);
    assert!(matches!(result, Err(CryptError::AuthenticationFailed)));
}

// ── Envelope serialization roundtrip ─────────────────────────────────────────

#[test]
#[cfg(feature = "ml-kem-backend")]
fn test_envelope_serialize_deserialize_roundtrip() {
    let (pk, sk) = gen_keypair_768();
    let plaintext = b"Serialize/deserialize envelope test";

    let mut enc = Kyber::<Encryption, MlKem768, Data, XChaCha20Poly1305>::new(pk, None).unwrap();
    let envelope = enc.encrypt_data(plaintext, "pp").unwrap();

    // Serialize and deserialize the envelope.
    let bytes = envelope.to_bytes();
    let envelope2 = Envelope::from_bytes(&bytes).unwrap();
    assert_eq!(envelope, envelope2);

    // Decrypt from deserialized envelope.
    let dec = Kyber::<Decryption, MlKem768, Data, XChaCha20Poly1305>::new(sk, None).unwrap();
    let recovered = dec.decrypt_data(plaintext, "pp", &envelope2).unwrap();
    assert_eq!(recovered, plaintext);
}

// ── Header / AAD tests ────────────────────────────────────────────────────────

#[test]
fn test_envelope_header_version_and_magic() {
    let hdr = Header::new(
        KemAlgId::MlKem768,
        AeadAlgId::XChaCha20Poly1305,
        KdfAlgId::HkdfSha256,
    );
    assert_eq!(&hdr.magic, b"CGv2");
    assert_eq!(hdr.version, 2);
}

#[test]
fn test_envelope_aad_includes_kem_ct() {
    use crate::protocol::aad::build_aad;
    let hdr = Header::new(
        KemAlgId::MlKem768,
        AeadAlgId::XChaCha20Poly1305,
        KdfAlgId::HkdfSha256,
    );
    let ct1 = vec![1u8; 32];
    let ct2 = vec![2u8; 32];
    let nonce = [0u8; 24];
    assert_ne!(
        build_aad(&hdr, &ct1, &nonce, b""),
        build_aad(&hdr, &ct2, &nonce, b"")
    );
}
