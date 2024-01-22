mod keychain;
mod decrypt;
mod encrypt;

use crate::keychain::*;
use crate::encrypt::*;
use crate::decrypt::*;
use std::path::PathBuf;
use std::fs;
use pqcrypto::kem::kyber1024::decapsulate;
use pqcrypto_traits::kem::{SharedSecret as SharedSecretTrait, SecretKey as SecretKeyTrait};
use hex;

#[tokio::main]
async fn main() {
    let keychain = Keychain::new().unwrap();

    let pubkey = PathBuf::from("/Users/mm29942/EncryptMod/keychain/key/key.pub");
    let secret_key = PathBuf::from("/Users/mm29942/EncryptMod/keychain/key/key.sec");
    let ciphertext = PathBuf::from("/Users/mm29942/EncryptMod/keychain/cipher/cipher_1.ct");
    
    let original_file_path = PathBuf::from("./README.md");
    let encrypted_file_path = PathBuf::from("./README.md_1.enc");
    //let original_file_contents = fs::read_to_string(&original_file_path).expect("Failed to read original file");

    // Perform the encryption
    //let _ = Encrypt::encrypt(pubkey, None, Some(original_file_path.clone()), b"secret").await;

    //fs::remove_file(&original_file_path).unwrap();
    // Decrypt the file
    let _ = Decrypt::decrypt(secret_key, ciphertext, Some(&encrypted_file_path), None, b"secret").await;

    // Compare the original and decrypted file contents
    //assert_eq!(original_file_contents, decrypted_file_contents);
}