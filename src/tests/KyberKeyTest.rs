

use std::{
    fs::{self},
    io::{Read},
    path::{PathBuf, Path},
};
use crate::{
    cryptography::{
        hmac_sign::*, 
    },
    KeyControKyber1024, 
    KeyControKyber512, 
    KeyControKyber768,
    Core::KeyControl,
    KyberKeyFunctions,
    KeyTypes,
    FileTypes,
    FileMetadata,
    FileState,
};


use crate::initialize_logger;

fn test_keypair_generation<T: KyberKeyFunctions>() {
    let (public_key, secret_key) = T::keypair().expect("Key pair generation failed");
    assert!(!public_key.is_empty(), "Public key is empty");
    assert!(!secret_key.is_empty(), "Secret key is empty");
}

#[test]
fn begin() {
    initialize_logger(PathBuf::from("crypt_tests.log"));
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
    
    assert_eq!(shared_secret_encap, shared_secret_decap, "Shared secrets do not match");
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
    let _ = key_control.set_public_key(public_key).unwrap();

    // Use the public key from KeyControl to encapsulate
    let (shared_secret, ciphertext) = key_control.encap(key_control.public_key().unwrap().as_slice()).unwrap();
    let _ = key_control.set_ciphertext(ciphertext).unwrap();
    // Use the secret key from KeyControl to decapsulate
    let decrypted_shared_secret = key_control.decap(&secret_key, key_control.ciphertext().unwrap().as_slice()).unwrap();

    assert_eq!(shared_secret, decrypted_shared_secret, "Shared secrets do not match after KeyControl operations");
}

// Helper function to read a file into a Vec<u8>
fn read_file(path: &PathBuf) -> Result<Vec<u8>, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut contents = vec![];
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

#[test]
fn test_key_control_safe_functionality() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a keypair
    let (public_key, secret_key) = KeyControKyber1024::keypair().unwrap();

    // Encapsulate a secret with the public key
    let (_shared_secret, ciphertext) = KeyControKyber1024::encap(&public_key).unwrap();

    // Initialize KeyControl and set keys
    let mut key_control = KeyControl::<KeyControKyber1024>::new();
    // key_control.set_public_key(pqcrypto_traits::kem::PublicKey::from_bytes(public_key.clone()).as_bytes().to_owned()).unwrap();
    key_control.set_public_key(public_key.clone()).unwrap();
    key_control.save(KeyTypes::PublicKey, "./key".into()).unwrap();

    key_control.set_secret_key(secret_key.clone()).unwrap();
    key_control.save(KeyTypes::SecretKey, "./key".into()).unwrap();

    key_control.set_ciphertext(ciphertext.clone()).unwrap();
    key_control.save(KeyTypes::Ciphertext, "./key".into()).unwrap();

    let cipher = key_control.load(KeyTypes::Ciphertext, Path::new("./key/ciphertext.ct"));
    let pubk = key_control.load(KeyTypes::PublicKey, Path::new("./key/public_key.pub"));
    let seck = key_control.load(KeyTypes::SecretKey, Path::new("./key/secret_key.sec"));

    // Verify the integrity of the saved keys
    assert!(Path::new("./key/ciphertext.ct").exists());
    assert!(Path::new("./key/public_key.pub").exists());
    assert!(Path::new("./key/secret_key.sec").exists());
    assert_eq!(&public_key.len(), &pubk.clone()?.len());
    assert_eq!(public_key, pubk?, "Public keys do not match");
    assert_eq!(secret_key, seck?, "Secret keys do not match");
    assert_eq!(ciphertext, cipher?, "Ciphertexts do not match");

    let _ = fs::remove_dir_all("./key")?;
    Ok(())
}

#[test]
fn test_key() {
    let (public_key, secret_key) = KeyControKyber1024::keypair().unwrap();

    let keycontrol = KeyControl::<KeyControKyber1024>::new();

    let pubkey_file = FileMetadata::from(
        PathBuf::from("key.pub"),
        FileTypes::PublicKey,
        FileState::Other
    );
    let seckey_file = FileMetadata::from(
        PathBuf::from("key.sec"),
        FileTypes::SecretKey,
        FileState::Other
    );


    let _ = pubkey_file.save(&public_key);
    let _ = seckey_file.save(&secret_key);
    
    let public_key2 = keycontrol.load(KeyTypes::PublicKey, &Path::new("key.pub")).unwrap();
    let secret_key2 = keycontrol.load(KeyTypes::SecretKey, &Path::new("key.sec")).unwrap();

    assert_eq!(public_key2, public_key);
    assert_eq!(secret_key2, secret_key);


    let _ = fs::remove_file(Path::new("key.pub"));
    let _ = fs::remove_file(Path::new("key.sec"));
}
