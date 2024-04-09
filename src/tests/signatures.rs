use super::*;
use crate::KDF::*;

#[test]
fn test_falcon1024_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon1024::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Falcon1024, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key)?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    Ok(())
}


#[test]
fn test_falcon1024_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon1024::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Falcon1024, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key)?;

    assert!(is_valid);
    Ok(())
}

#[test]
fn test_falcon512_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon512::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Falcon512, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key)?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    Ok(())
}


#[test]
fn test_falcon512_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon512::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Falcon512, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key)?;

    assert!(is_valid);
    Ok(())
}


#[test]
fn test_dilithium2_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium2::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Dilithium2, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key)?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    Ok(())
}


#[test]
fn test_dilithium2_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium2::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Dilithium2, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key)?;

    assert!(is_valid);
    Ok(())
}


#[test]
fn test_dilithium3_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium3::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Dilithium3, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key)?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    Ok(())
}


#[test]
fn test_dilithium3_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium3::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Dilithium3, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key)?;

    assert!(is_valid);
    Ok(())
}


#[test]
fn test_dilithium5_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium5::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Dilithium5, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key)?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    Ok(())
}


#[test]
fn test_dilithium5_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium5::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Dilithium5, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key)?;

    assert!(is_valid);
    Ok(())
}