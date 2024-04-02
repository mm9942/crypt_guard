use super::*;
use crate::error::CryptError;
use std::{
    fs::{self, File},
    io::{Read, self},
    path::{PathBuf, Path},
};
use crate::{
	signature::*,
	falcon,
	dilithium,
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

use tempfile::{TempDir, Builder, tempdir};

#[test]
fn test_sign_and_verify_message() {
    let mut instance = falcon::keypair();
    let message = b"Test message".to_vec();
    instance.set_data(message.clone()).unwrap();
    let signature = instance.sign_msg().expect("Failed to sign message");
    instance.set_signed_msg(signature).expect("Failed to set signed message");
    let verified_message = instance.verify_msg().expect("Failed to verify message");
    assert_eq!(verified_message, message, "The verified message does not match the original message");
}

#[test]
fn test_sign_and_verify_detached_signature() {
    let mut instance = falcon::keypair();
    let message = b"Test message for detached signature".to_vec();
    instance.set_data(message.clone()).unwrap();
    let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
    instance.set_detached(detached_signature).expect("Failed to set detached signature");
    let verification_result = instance.verify_detached().expect("Failed to verify detached signature");
    assert!(verification_result, "Detached signature verification failed");
}

#[test]
fn test_save_signed_msg() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("signed_message.sig");

    let mut instance = falcon::keypair();
    let message = b"This is a test message.".to_vec();
    instance.set_data(message.clone()).unwrap();

    // Sign the message
    let signature = instance.sign_msg().expect("Failed to sign message");
    instance.set_signed_msg(signature.clone()).expect("Failed to set signed message");

    // Save the signed message
    assert!(instance.save_signed_msg(file_path.clone()).is_ok(), "Failed to save signed message");

    // Read and verify the contents of the saved file
    let mut saved_file = File::open(file_path).unwrap();
    let mut saved_signature = Vec::new();
    saved_file.read_to_end(&mut saved_signature).unwrap();
    assert_eq!(signature, saved_signature, "The saved signed message does not match the expected signature");
}

#[test]
fn test_save_detached() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("detached_signature.sig");

    let mut instance = falcon::keypair();
    let message = b"This is a test message for detached signature.".to_vec();
    instance.set_data(message.clone()).unwrap();

    // Sign with a detached signature
    let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
    instance.set_detached(detached_signature.clone()).expect("Failed to set detached signature");

    // Save the detached signature
    assert!(instance.save_detached(file_path.clone()).is_ok(), "Failed to save detached signature");

    // Read and verify the contents of the saved file
    let mut saved_file = File::open(file_path).unwrap();
    let mut saved_detached_signature = Vec::new();
    saved_file.read_to_end(&mut saved_detached_signature).unwrap();
    assert_eq!(detached_signature, saved_detached_signature, "The saved detached signature does not match the expected signature");
}

#[test]
fn test_sign_and_verify_message_dilithium() {
    let mut instance = dilithium::keypair();
    let message = b"Test message".to_vec();
    instance.set_data(message.clone()).unwrap();
    let signature = instance.sign_msg().expect("Failed to sign message");
    instance.set_signed_msg(signature).expect("Failed to set signed message");
    let verified_message = instance.verify_msg().expect("Failed to verify message");
    assert_eq!(verified_message, message, "The verified message does not match the original message");
}

#[test]
fn test_sign_and_verify_detached_signature_dilithium() {
    let mut instance = dilithium::keypair();
    let message = b"Test message for detached signature".to_vec();
    instance.set_data(message.clone()).unwrap();
    let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
    instance.set_detached(detached_signature).expect("Failed to set detached signature");
    let verification_result = instance.verify_detached().expect("Failed to verify detached signature");
    assert!(verification_result, "Detached signature verification failed");
}

#[test]
fn test_save_signed_msg_dilithium() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("signed_message.sig");

    let mut instance = dilithium::keypair();
    let message = b"This is a test message.".to_vec();
    instance.set_data(message.clone()).unwrap();

    // Sign the message
    let signature = instance.sign_msg().expect("Failed to sign message");
    instance.set_signed_msg(signature.clone()).expect("Failed to set signed message");

    // Save the signed message
    assert!(instance.save_signed_msg(file_path.clone()).is_ok(), "Failed to save signed message");

    // Read and verify the contents of the saved file
    let mut saved_file = File::open(file_path).unwrap();
    let mut saved_signature = Vec::new();
    saved_file.read_to_end(&mut saved_signature).unwrap();
    assert_eq!(signature, saved_signature, "The saved signed message does not match the expected signature");
}

#[test]
fn test_save_detached_dilithium() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("detached_signature.sig");

    let mut instance = dilithium::keypair();
    let message = b"This is a test message for detached signature.".to_vec();
    instance.set_data(message.clone()).unwrap();

    // Sign with a detached signature
    let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
    instance.set_detached(detached_signature.clone()).expect("Failed to set detached signature");

    // Save the detached signature
    assert!(instance.save_detached(file_path.clone()).is_ok(), "Failed to save detached signature");

    // Read and verify the contents of the saved file
    let mut saved_file = File::open(file_path).unwrap();
    let mut saved_detached_signature = Vec::new();
    saved_file.read_to_end(&mut saved_detached_signature).unwrap();
    assert_eq!(detached_signature, saved_detached_signature, "The saved detached signature does not match the expected signature");
}


#[test]
fn test_generate_and_verify_sha256_hmac() {
    let data = b"Example data for SHA256".to_vec();
    let passphrase = b"secret key".to_vec();

    let mut sign = Sign::new(data.clone(), passphrase.clone(), Operation::Sign, SignType::Sha256);
    let concat_data = sign.hmac();
    let mut verify_sign = Sign::new(concat_data, passphrase, Operation::Verify, SignType::Sha256);
    let verified_data = verify_sign.verify_hmac().expect("HMAC verification failed");

    assert_eq!(verified_data, data, "Verified data does not match the original data for SHA256");
}

#[test]
fn test_generate_and_verify_sha512_hmac() {
    let data = b"Example data for SHA512".to_vec();
    let passphrase = b"secret key".to_vec();

    let mut sign = Sign::new(data.clone(), passphrase.clone(), Operation::Sign, SignType::Sha512);
    let concat_data = sign.hmac();
    let mut verify_sign = Sign::new(concat_data, passphrase, Operation::Verify, SignType::Sha512);
    let verified_data = verify_sign.verify_hmac().expect("HMAC verification failed");

    assert_eq!(verified_data, data, "Verified data does not match the original data for SHA512");
}