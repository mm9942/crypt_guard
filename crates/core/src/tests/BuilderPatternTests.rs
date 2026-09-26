use std::fs;
use tempfile::{Builder as TmpBuilder, TempDir};

use crate::builder::{
    DecryptBuilder, EncryptBuilder, KyberKeygenBuilder, SignAlgorithm, SignBuilder, SignMode,
    SymmetricAlg, VerifyBuilder,
};
use crate::core::kyber::key_controler::{KeyControKyber512, KeyControKyber768};

#[test]
fn builder_encrypt_decrypt_data_aes_gcm_siv_kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = KeyControKyber768::keypair()?;
    let msg = b"builder aead 768".to_vec();

    let enc = EncryptBuilder::new()
        .key(pk)
        .key_size(768)
        .data(msg.clone())
        .passphrase("pass")
        .algorithm(SymmetricAlg::AesGcmSiv)
        .run()?;

    let nonce = enc.nonce.expect("nonce required for AES_GCM_SIV");
    let out = DecryptBuilder::new()
        .key(sk)
        .key_size(768)
        .data(enc.content)
        .passphrase("pass")
        .cipher(enc.cipher)
        .nonce(nonce)
        .algorithm(SymmetricAlg::AesGcmSiv)
        .run()?;

    assert_eq!(out, msg);
    Ok(())
}

#[test]
fn builder_encrypt_decrypt_data_aes_xts_kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = KeyControKyber512::keypair()?;
    let msg = b"builder xts 512".to_vec();

    let enc = EncryptBuilder::new()
        .key(pk)
        .key_size(512)
        .data(msg.clone())
        .passphrase("p@ssw0rd")
        .algorithm(SymmetricAlg::AesXts)
        .run()?;

    // AES-XTS uses no external nonce in the builder API
    let out = DecryptBuilder::new()
        .key(sk)
        .key_size(512)
        .data(enc.content)
        .passphrase("p@ssw0rd")
        .cipher(enc.cipher)
        .algorithm(SymmetricAlg::AesXts)
        .run()?;

    assert_eq!(out, msg);
    Ok(())
}

#[test]
fn builder_encrypt_decrypt_file_xchacha20_kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = KeyControKyber768::keypair()?;
    let _tmp = TempDir::new()?;
    let dir = TmpBuilder::new().prefix("builder_file").tempdir()?;
    let enc_path = dir.path().join("msg.txt");
    let encd_path = dir.path().join("msg.txt.enc");

    let msg = "file with xchacha";
    fs::write(&enc_path, msg.as_bytes())?;

    let enc = EncryptBuilder::new()
        .key(pk)
        .key_size(768)
        .file(enc_path.clone())
        .passphrase("pass")
        .algorithm(SymmetricAlg::XChaCha20)
        .run()?;

    let nonce = enc.nonce.expect("nonce required for XChaCha20");
    // Remove plaintext to mirror macro tests pattern
    let _ = fs::remove_file(&enc_path);

    let dec = DecryptBuilder::new()
        .key(sk)
        .key_size(768)
        .file(encd_path.clone())
        .passphrase("pass")
        .cipher(enc.cipher)
        .nonce(nonce)
        .algorithm(SymmetricAlg::XChaCha20)
        .run()?;

    let out = String::from_utf8(dec)?;
    assert_eq!(out, msg);
    // restored plaintext exists again
    assert!(enc_path.exists());
    assert_eq!(fs::read_to_string(&enc_path)?, msg);
    Ok(())
}

#[test]
fn builder_sign_open_message_falcon1024() -> Result<(), Box<dyn std::error::Error>> {
    let (pubk, seck) = crate::core::kdf::Falcon1024::keypair()?;
    let data = b"signed by builder".to_vec();

    let signed = SignBuilder::new()
        .algorithm(SignAlgorithm::Falcon1024)
        .mode(SignMode::Message)
        .key(seck)
        .data(data.clone())
        .sign()?;

    let opened = VerifyBuilder::new()
        .algorithm(SignAlgorithm::Falcon1024)
        .mode(SignMode::Message)
        .key(pubk)
        .signed_message(signed)
        .open()?;

    assert_eq!(opened, data);
    Ok(())
}

#[test]
fn builder_keygen_768() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = KyberKeygenBuilder::new().size(768).generate()?;
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
    Ok(())
}

// Merged from the orphaned BuilderTests.rs: additional coverage the rest of
// this file did not exercise (Kyber1024 AES/XChaCha20 data + file round trips,
// Falcon512 message signing, Dilithium2 detached signing, Kyber1024 keygen).
#[test]
fn builder_encrypt_decrypt_data_aes_kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    use crate::core::kyber::key_controler::KeyControKyber1024;
    let (public_key, secret_key) = KeyControKyber1024::keypair()?;
    let msg = b"Hello from builder".to_vec();

    let enc = EncryptBuilder::new()
        .key(public_key)
        .key_size(1024)
        .data(msg.clone())
        .passphrase("Test Passphrase")
        .algorithm(SymmetricAlg::Aes)
        .run()?;

    let dec = DecryptBuilder::new()
        .key(secret_key)
        .key_size(1024)
        .data(enc.content)
        .passphrase("Test Passphrase")
        .cipher(enc.cipher)
        .algorithm(SymmetricAlg::Aes)
        .run()?;

    assert_eq!(dec, msg);
    Ok(())
}

#[test]
fn builder_encrypt_decrypt_data_xchacha20_kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    use crate::core::kyber::key_controler::KeyControKyber1024;
    let (public_key, secret_key) = KeyControKyber1024::keypair()?;
    let msg = b"Hello XChaCha20".to_vec();

    let enc = EncryptBuilder::new()
        .key(public_key)
        .key_size(1024)
        .data(msg.clone())
        .passphrase("Test Passphrase")
        .algorithm(SymmetricAlg::XChaCha20)
        .run()?;

    let nonce = enc.nonce.expect("nonce must be present for XChaCha20");
    let dec = DecryptBuilder::new()
        .key(secret_key)
        .key_size(1024)
        .data(enc.content)
        .passphrase("Test Passphrase")
        .cipher(enc.cipher)
        .nonce(nonce)
        .algorithm(SymmetricAlg::XChaCha20)
        .run()?;

    assert_eq!(dec, msg);
    Ok(())
}

#[test]
fn builder_encrypt_decrypt_file_aes_kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    use crate::core::kyber::key_controler::KeyControKyber1024;
    let (public_key, secret_key) = KeyControKyber1024::keypair()?;

    let tmp_dir = TmpBuilder::new().prefix("builder_messages").tempdir()?;
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    let message = "Builder file flow";
    fs::write(&enc_path, message.as_bytes())?;

    let enc = EncryptBuilder::new()
        .key(public_key)
        .key_size(1024)
        .file(enc_path.clone())
        .passphrase("Test Passphrase")
        .algorithm(SymmetricAlg::Aes)
        .run()?;

    // mimic existing tests: remove plaintext, then decrypt from .enc
    let _ = fs::remove_file(enc_path.clone());

    let dec = DecryptBuilder::new()
        .key(secret_key)
        .key_size(1024)
        .file(dec_path.clone())
        .passphrase("Test Passphrase")
        .cipher(enc.cipher)
        .algorithm(SymmetricAlg::Aes)
        .run()?;

    let out = String::from_utf8(dec).expect("utf8");
    assert_eq!(out, message);

    assert!(enc_path.exists());
    let restored = fs::read_to_string(&enc_path)?;
    assert_eq!(restored, message);
    Ok(())
}

#[test]
fn builder_sign_open_message_falcon512() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = crate::core::kdf::Falcon512::keypair()?;
    let data = b"sign this message".to_vec();

    let signed = SignBuilder::new()
        .algorithm(SignAlgorithm::Falcon512)
        .mode(SignMode::Message)
        .key(secret_key)
        .data(data.clone())
        .sign()?;

    let opened = VerifyBuilder::new()
        .algorithm(SignAlgorithm::Falcon512)
        .mode(SignMode::Message)
        .key(public_key)
        .signed_message(signed)
        .open()?;

    assert_eq!(opened, data);
    Ok(())
}

#[test]
fn builder_detached_signature_dilithium2() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = crate::core::kdf::Dilithium2::keypair()?;
    let data = b"detached".to_vec();

    let sig = SignBuilder::new()
        .algorithm(SignAlgorithm::Dilithium2)
        .mode(SignMode::Detached)
        .key(secret_key)
        .data(data.clone())
        .sign()?;

    let ok = VerifyBuilder::new()
        .algorithm(SignAlgorithm::Dilithium2)
        .mode(SignMode::Detached)
        .key(public_key)
        .data(data)
        .signature(sig)
        .verify()?;

    assert!(ok);
    Ok(())
}

#[test]
fn builder_kyber_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = KyberKeygenBuilder::new().size(1024).generate()?;
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
    Ok(())
}
