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
