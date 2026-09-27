use crate::{
    core::KeyControl, FileMetadata, FileState, FileTypes, KeyControKyber1024, KeyControKyber512,
    KeyControKyber768, KeyTypes, KyberKeyFunctions,
};
use std::path::PathBuf;

use crate::initialize_logger;
use tempfile::tempdir;

fn test_keypair_generation<T: KyberKeyFunctions>() {
    let (public_key, secret_key) = T::keypair().expect("Key pair generation failed");
    assert!(!public_key.is_empty(), "Public key is empty");
    assert!(!secret_key.is_empty(), "Secret key is empty");
}

#[test]
fn begin() {
    // Use a tempdir instead of a fixed "crypt_tests.log" path in the crate
    // root so this test does not race with other tests over a shared file,
    // and the log file is cleaned up automatically when the dir drops.
    let log_dir = tempdir().expect("Failed to create temp directory");
    initialize_logger(log_dir.path().join("crypt_tests.log"));
}

#[test]
fn keypair_generation_kyber1024() {
    test_keypair_generation::<KeyControKyber1024>();
}

#[test]
fn keypair_generation_kyber768() {
    test_keypair_generation::<KeyControKyber768>();
}

#[test]
fn keypair_generation_kyber512() {
    test_keypair_generation::<KeyControKyber512>();
}

// Tests encapsulation and decapsulation using the generated keys
fn test_encap_decap<T: KyberKeyFunctions>() {
    let (public_key, secret_key) = T::keypair().unwrap();
    let (shared_secret_encap, ciphertext) = T::encap(&public_key).unwrap();
    let shared_secret_decap = T::decap(&secret_key, &ciphertext).unwrap();

    assert_eq!(
        shared_secret_encap, shared_secret_decap,
        "Shared secrets do not match"
    );
}

#[test]
fn encap_decap_kyber1024() {
    test_encap_decap::<KeyControKyber1024>();
}

#[test]
fn encap_decap_kyber768() {
    test_encap_decap::<KeyControKyber768>();
}

#[test]
fn encap_decap_kyber512() {
    test_encap_decap::<KeyControKyber512>();
}

// Test the functionality of the KeyControl struct
#[test]
fn key_control_functionality() {
    let _base_path = PathBuf::from("/tmp"); // Example path, adjust as needed
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("");
    let mut key_control = KeyControl::<KeyControKyber1024>::new();
    key_control.set_public_key(public_key).unwrap();

    // Use the public key from KeyControl to encapsulate
    let (shared_secret, ciphertext) = key_control
        .encap(key_control.public_key().unwrap().as_slice())
        .unwrap();
    key_control.set_ciphertext(ciphertext).unwrap();
    // Use the secret key from KeyControl to decapsulate
    let decrypted_shared_secret = key_control
        .decap(&secret_key, key_control.ciphertext().unwrap().as_slice())
        .unwrap();

    assert_eq!(
        shared_secret, decrypted_shared_secret,
        "Shared secrets do not match after KeyControl operations"
    );
}

#[test]
fn test_key_control_safe_functionality() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a keypair
    let (public_key, secret_key) = KeyControKyber1024::keypair().unwrap();

    // Encapsulate a secret with the public key
    let (_shared_secret, ciphertext) = KeyControKyber1024::encap(&public_key).unwrap();

    // Use a tempdir instead of a fixed "./key" path so this test cannot race
    // with any other test over a shared, process-relative directory.
    let key_dir = tempdir().expect("Failed to create temp directory");
    let key_dir_path = key_dir.path();
    let ciphertext_path = key_dir_path.join("ciphertext.ct");
    let public_key_path = key_dir_path.join("public_key.pub");
    let secret_key_path = key_dir_path.join("secret_key.sec");

    // Initialize KeyControl and set keys
    let mut key_control = KeyControl::<KeyControKyber1024>::new();
    // key_control.set_public_key(pqcrypto_traits::kem::PublicKey::from_bytes(public_key.clone()).as_bytes().to_owned()).unwrap();
    key_control.set_public_key(public_key.clone()).unwrap();
    key_control
        .save(KeyTypes::PublicKey, key_dir_path.to_path_buf())
        .unwrap();

    key_control.set_secret_key(secret_key.clone()).unwrap();
    key_control
        .save(KeyTypes::SecretKey, key_dir_path.to_path_buf())
        .unwrap();

    key_control.set_ciphertext(ciphertext.clone()).unwrap();
    key_control
        .save(KeyTypes::Ciphertext, key_dir_path.to_path_buf())
        .unwrap();

    let cipher = key_control.load(KeyTypes::Ciphertext, ciphertext_path.as_path());
    let pubk = key_control.load(KeyTypes::PublicKey, public_key_path.as_path());
    let seck = key_control.load(KeyTypes::SecretKey, secret_key_path.as_path());

    // Verify the integrity of the saved keys
    assert!(ciphertext_path.exists());
    assert!(public_key_path.exists());
    assert!(secret_key_path.exists());
    assert_eq!(&public_key.len(), &pubk.clone()?.len());
    assert_eq!(public_key, pubk?, "Public keys do not match");
    assert_eq!(secret_key, seck?, "Secret keys do not match");
    assert_eq!(ciphertext, cipher?, "Ciphertexts do not match");

    Ok(())
}

#[test]
fn test_key() {
    let (public_key, secret_key) = KeyControKyber1024::keypair().unwrap();

    let keycontrol = KeyControl::<KeyControKyber1024>::new();

    // Use a tempdir instead of fixed "key.pub"/"key.sec" filenames in the
    // crate root so this test cannot race with other tests writing the same
    // relative paths.
    let key_dir = tempdir().expect("Failed to create temp directory");
    let pub_path = key_dir.path().join("key.pub");
    let sec_path = key_dir.path().join("key.sec");

    let pubkey_file = FileMetadata::from(pub_path.clone(), FileTypes::PublicKey, FileState::Other);
    let seckey_file = FileMetadata::from(sec_path.clone(), FileTypes::SecretKey, FileState::Other);

    let _ = pubkey_file.save(&public_key);
    let _ = seckey_file.save(&secret_key);

    let public_key2 = keycontrol
        .load(KeyTypes::PublicKey, pub_path.as_path())
        .unwrap();
    let secret_key2 = keycontrol
        .load(KeyTypes::SecretKey, sec_path.as_path())
        .unwrap();

    assert_eq!(public_key2, public_key);
    assert_eq!(secret_key2, secret_key);
}
