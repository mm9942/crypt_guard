use super::*;
use std::io::{Read, Write};
use tempfile::{TempDir, Builder};
use std::fs::{self, File};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use crate::{
    encrypt,
    decrypt,
    encrypt_file,
    decrypt_file,
    Core::{kyber::{KyberFunctions, *}, *},
    error::*
};

#[test]
fn encrypt_decrypt_msg_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encrypt!(encryptor, message.as_bytes().to_owned(), passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Message, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decrypt!(decryptor, encrypt_message, passphrase, cipher);

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let data = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encrypt!(encryptor, data.clone(), passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decrypt!(decryptor, encrypt_message, passphrase, cipher);

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message?, data);

    Ok(())
}

#[test]
fn encrypt_decrypt_file_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encrypt_file!(encryptor, enc_path.clone(), passphrase)?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decrypt_file!(decryptor, dec_path.clone(), passphrase, cipher);

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}


#[test]
fn encrypt_message_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Message, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

#[test]
fn encrypt_data_AES_XTS_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    //let message = "Hey, how are you doing?".as_bytes().to_owned();
    
    let message = [5; 0x400];
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES_XTS>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase.clone())?;

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Data, AES_XTS>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_data(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_data_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase.clone())?;

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_data(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message);

    Ok(())
}


#[test]
fn encrypt_message_AES_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber768
    let mut encryptor = Kyber::<Encryption, Kyber768, Message, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    // Instantiate Kyber for decryption with Kyber768
    let mut decryptor = Kyber::<Decryption, Kyber768, Message, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

fn encrypt_message_AES_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Message, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    // Instantiate Kyber for decryption with Kyber512
    let mut decryptor = Kyber::<Decryption, Kyber512, Message, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

#[test]
fn encrypt_file_AES_XTS_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES_XTS>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Files, AES_XTS>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_file_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_file_AES_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber768, Files, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber768, Files, AES>::new(secret_key, None)?;
    
    // Decrypt file
    let decrypt_file = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_file).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}


#[test]
fn encrypt_file_AES_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Files, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber512
    let mut decryptor = Kyber::<Decryption, Kyber512, Files, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_message_XChaCha20_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Message, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Message, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Assert that the decrypted message matches the original message
    assert_eq!(String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string"), message);

    Ok(())
}

#[test]
fn encrypt_message_XChaCha20_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber768
    let mut encryptor = Kyber::<Encryption, Kyber768, Message, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber768
    let mut decryptor = Kyber::<Decryption, Kyber768, Message, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Assert that the decrypted message matches the original message
    assert_eq!(String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string"), message);

    Ok(())
}

#[test]
fn encrypt_message_XChaCha20_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Message, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber512
    let mut decryptor = Kyber::<Decryption, Kyber512, Message, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Assert that the decrypted message matches the original message
    assert_eq!(String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string"), message);

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    let nonce = encryptor.get_nonce();

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber768
    let mut encryptor = Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    let nonce = encryptor.get_nonce();

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber768
    let mut decryptor = Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    let nonce = encryptor.get_nonce();

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber512
    let mut decryptor = Kyber::<Decryption, Kyber512, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message.clone());

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}