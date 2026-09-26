use std::fs;
use std::path::PathBuf;
use tempfile::{Builder as TmpBuilder, TempDir};

use crate::{
    builder::{EncryptBuilder, DecryptBuilder, KyberKeygenBuilder, SymmetricAlg, SignBuilder, VerifyBuilder, SignAlgorithm, SignMode},
    core::{
        kyber::*,
    },
};

#[test]
fn builder_encrypt_decrypt_data_aes_kyber1024() -> Result<(), Box<dyn std::error::Error>> {
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
    let (public_key, secret_key) = KeyControKyber1024::keypair()?;

    let _tmp_dir = TempDir::new()?;
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

