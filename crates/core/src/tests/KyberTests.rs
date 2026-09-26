#![allow(non_snake_case)]
use crate::{
    core::{
        kyber::{KyberFunctions, *},
        *,
    },
    cryptography::*,
    decrypt_file, decryption, encrypt_file, encryption,
    error::*,
    kyber_keypair,
};

use std::fs::{self};
use tempfile::{Builder, TempDir};

#[test]
fn encrypt_decrypt_msg_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");
    let key = &public_key;

    // Encrypt message
    let (encrypt_message, cipher) =
        encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES)?;

    // Decrypt message
    let decrypt_message = decryption!(
        secret_key.to_owned(),
        1024,
        encrypt_message.to_owned(),
        passphrase,
        cipher.to_owned(),
        AES
    );

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message?, message.to_owned());

    Ok(())
}
#[test]
fn encrypt_decrypt_msg_macro_AES_XTS_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");
    let key = &public_key;

    // Encrypt message
    let (encrypt_message, cipher) =
        encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_XTS)?;

    // Decrypt message
    let decrypt_message = decryption!(
        secret_key.to_owned(),
        1024,
        encrypt_message.to_owned(),
        passphrase,
        cipher.to_owned(),
        AES_XTS
    );

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message?, message.to_owned());

    Ok(())
}

#[test]
fn encrypt_decrypt_msg_macro_XChaCha20_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    // Generate key pair

    let (public_key, secret_key) = kyber_keypair!(1024);
    let key = public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) = encryption!(
        key.to_owned(),
        1024,
        message.to_owned(),
        passphrase,
        XChaCha20
    )?;

    // Decrypt message
    let decrypt_message = decryption!(
        secret_key.to_owned(),
        1024,
        encrypt_message.to_owned(),
        passphrase,
        cipher.to_owned(),
        Some(nonce.clone()),
        XChaCha20
    );
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message?, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_msg_macro_AES_GCM_SIV_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Encryption,
        encryption_type: CryptographicMechanism::AesGcmSiv,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: message.as_bytes().to_owned(),
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_gcm_siv = CipherAesGcmSiv::new(infos, None);
    let (encrypt_message, cipher) = aes_gcm_siv.encrypt(public_key)?;
    let iv = aes_gcm_siv.iv();
    println!("IV: {:?}", iv);
    println!("encrypt_message: {:?}", encrypt_message);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Decryption,
        encryption_type: CryptographicMechanism::AesGcmSiv,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: encrypt_message,
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_gcm_siv_dec = CipherAesGcmSiv::new(infos, Some(hex::encode(iv)));
    let decrypt_message = aes_gcm_siv_dec.decrypt(secret_key, cipher)?;

    println!("{:?}", decrypt_message);
    for enc_b in decrypt_message.clone() {
        print!("{:02x} ", enc_b);
    }

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message.clone(), message.as_bytes().to_owned());
    Ok(())
}

#[test]
fn encrypt_decrypt_AES_GCM_SIV_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Data, AesGcmSiv>::new(public_key.clone(), None)?;
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let decryptor =
        Kyber::<Decryption, Kyber1024, Data, AesGcmSiv>::new(secret_key, Some(nonce?.to_string()))?;
    let decrypt_message =
        decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_AES_XTS_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Data, AesXts>::new(public_key.clone(), None)?;
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let decryptor =
        Kyber::<Decryption, Kyber1024, Data, AesXts>::new(secret_key, Some(nonce?.to_string()))?;
    let decrypt_message =
        decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_AES_GCM_SIV_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    println!("{:?}", message);

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) = encryption!(
        key.to_owned(),
        1024,
        message.to_vec(),
        passphrase,
        AES_GCM_SIV
    )?;
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = decryption!(
        secret_key.to_owned(),
        1024,
        encrypt_message.to_owned(),
        passphrase,
        cipher.to_owned(),
        Some(nonce),
        AES_GCM_SIV
    )?;

    println!("{:?}", decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}

/*#[test]
fn encrypt_decrypt_msg_macro_AES_CTR_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Encrypt message
    let (encrypt_message, cipher) = encryption!(public_key.to_owned(), 1024, message.to_vec(), passphrase, AES_CTR);
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), AES_CTR)?;

    println!("{:?}", decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}
*/
#[test]
fn encrypt_decrypt_msg_AES_XTS_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Encryption,
        encryption_type: CryptographicMechanism::AesXts,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: message.as_bytes().to_owned(),
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_xts = CipherAesXts::new(infos);
    let (encrypt_message, cipher) = aes_xts.encrypt(public_key)?;
    println!("encrypt_message: {:?}", encrypt_message);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Decryption,
        encryption_type: CryptographicMechanism::AesXts,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: encrypt_message,
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_xts_dec = CipherAesXts::new(infos);
    let decrypt_message = aes_xts_dec.decrypt(secret_key, cipher)?;

    println!("{:?}", decrypt_message);
    for enc_b in decrypt_message.clone() {
        print!("{:02x} ", enc_b);
    }

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message.clone(), message.as_bytes().to_owned());
    Ok(())
}
#[test]
fn encrypt_decrypt_msg_macro_AES_CTR_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Encryption,
        encryption_type: CryptographicMechanism::AesGcmSiv,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: message.as_bytes().to_owned(),
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_gcm_siv = CipherAesCtr::new(infos, None);
    let (encrypt_message, cipher) = aes_gcm_siv.encrypt(public_key)?;
    let iv = aes_gcm_siv.iv();
    println!("IV: {:?}", iv);
    println!("encrypt_message: {:?}", encrypt_message);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Decryption,
        encryption_type: CryptographicMechanism::AesGcmSiv,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: encrypt_message,
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_gcm_siv_dec = CipherAesCtr::new(infos, Some(hex::encode(iv)));
    let decrypt_message = aes_gcm_siv_dec.decrypt(secret_key, cipher)?;

    println!("{:?}", decrypt_message);
    for enc_b in decrypt_message.clone() {
        print!("{:02x} ", enc_b);
    }

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message.clone(), message.as_bytes().to_owned());
    Ok(())
}

#[test]
fn encrypt_decrypt_AES_CTR_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Data, AesCtr>::new(public_key.clone(), None)?;
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let decryptor =
        Kyber::<Decryption, Kyber1024, Data, AesCtr>::new(secret_key, Some(nonce?.to_string()))?;
    let decrypt_message =
        decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_AES_CTR_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    println!("{:?}", message);

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) =
        encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_CTR)?;
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = decryption!(
        secret_key.to_owned(),
        1024,
        encrypt_message.to_owned(),
        passphrase,
        cipher.to_owned(),
        Some(nonce),
        AES_CTR
    )?;

    println!("{:?}", decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}

#[test]
fn encrypt_decrypt_msg_macro_XChaCha20Poly1305_Kyber1024() -> Result<(), Box<dyn std::error::Error>>
{
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Encryption,
        encryption_type: CryptographicMechanism::XChaCha20Poly1305,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: message.as_bytes().to_owned(),
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_gcm_siv = CipherChaChaPoly::new(infos, None);
    let (encrypt_message, cipher) = aes_gcm_siv.encrypt(public_key)?;
    let iv = aes_gcm_siv.nonce();
    println!("IV: {:?}", iv);
    println!("encrypt_message: {:?}", encrypt_message);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Decryption,
        encryption_type: CryptographicMechanism::XChaCha20Poly1305,
        key_type: KeyEncapMechanism::kyber1024(),
        content_type: ContentType::RawData, // Using File here for generic data
    };

    let infos = CryptographicInformation {
        content: encrypt_message,
        passphrase: passphrase.as_bytes().to_vec(),
        metadata: crypt_metadata,
        safe: false,
        location: None,
    };

    let mut aes_gcm_siv_dec = CipherChaChaPoly::new(infos, Some(hex::encode(iv)));
    let decrypt_message = aes_gcm_siv_dec.decrypt(secret_key, cipher)?;

    println!("{:?}", decrypt_message);
    for enc_b in decrypt_message.clone() {
        print!("{:02x} ", enc_b);
    }

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message.clone(), message.as_bytes().to_owned());
    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_XChaCha20Poly1305_Kyber1024() -> Result<(), Box<dyn std::error::Error>>
{
    // Generate key pair
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    println!("{:?}", message);

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) = encryption!(
        key.to_owned(),
        1024,
        message.to_vec(),
        passphrase,
        XChaCha20Poly1305
    )?;
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = decryption!(
        secret_key.to_owned(),
        1024,
        encrypt_message.to_owned(),
        passphrase,
        cipher.to_owned(),
        Some(nonce.to_owned()),
        XChaCha20Poly1305
    )?;

    println!("{:?}", decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}

#[test]
fn encrypt_decrypt_XChaCha20Poly1305_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Data, XChaCha20Poly1305>::new(public_key.clone(), None)?;
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20Poly1305>::new(
        secret_key,
        Some(nonce?.to_string()),
    )?;
    let decrypt_message =
        decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    println!("{:?}", message);

    // Generate key pair
    let (public_key, secret_key) = kyber_keypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher) =
        encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES)?;
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = decryption!(
        secret_key.to_owned(),
        1024,
        encrypt_message.to_owned(),
        passphrase,
        cipher.to_owned(),
        AES
    )?;

    println!("{:?}", decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}

#[test]
fn encrypt_decrypt_file_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(CryptError::from)?;
    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Encrypt message
    let (_encrypt_message, cipher) = encrypt_file!(
        public_key.to_owned(),
        1024,
        enc_path.clone(),
        passphrase,
        AES
    )?;

    let _ = fs::remove_file(enc_path.clone());

    // Decrypt message
    let decrypt_message = decrypt_file!(
        secret_key.to_owned(),
        1024,
        dec_path.clone(),
        passphrase,
        cipher.to_owned(),
        AES
    );

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

#[test]
fn encrypt_message_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Message, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

#[test]
fn encrypt_data_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_message_AES_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber768
    let mut encryptor = Kyber::<Encryption, Kyber768, Message, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    // Instantiate Kyber for decryption with Kyber768
    let decryptor = Kyber::<Decryption, Kyber768, Message, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

#[test]
fn encrypt_message_AES_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Message, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    // Instantiate Kyber for decryption with Kyber512
    let decryptor = Kyber::<Decryption, Kyber512, Message, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

#[test]
fn encrypt_file_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(CryptError::from)?;
    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

#[test]
fn encrypt_file_AES_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(CryptError::from)?;
    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber768, Files, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber768, Files, AES>::new(secret_key, None)?;

    // Decrypt file
    let decrypt_file = decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_file).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

#[test]
fn encrypt_file_AES_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(CryptError::from)?;
    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Files, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber512
    let decryptor = Kyber::<Decryption, Kyber512, Files, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

#[test]
fn encrypt_message_XChaCha20_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Message, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Message, XChaCha20>::new(
        secret_key,
        Some(nonce?.to_string()),
    )?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Assert that the decrypted message matches the original message
    assert_eq!(
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string"),
        message
    );

    Ok(())
}

#[test]
fn encrypt_message_XChaCha20_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber768
    let mut encryptor =
        Kyber::<Encryption, Kyber768, Message, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber768
    let decryptor = Kyber::<Decryption, Kyber768, Message, XChaCha20>::new(
        secret_key,
        Some(nonce?.to_string()),
    )?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Assert that the decrypted message matches the original message
    assert_eq!(
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string"),
        message
    );

    Ok(())
}

#[test]
fn encrypt_message_XChaCha20_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor =
        Kyber::<Encryption, Kyber512, Message, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber512
    let decryptor = Kyber::<Decryption, Kyber512, Message, XChaCha20>::new(
        secret_key,
        Some(nonce?.to_string()),
    )?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Assert that the decrypted message matches the original message
    assert_eq!(
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string"),
        message
    );

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(CryptError::from)?;
    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Files, XChaCha20>::new(
        secret_key,
        Some(nonce?.to_string()),
    )?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(CryptError::from)?;
    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber768
    let mut encryptor =
        Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber768
    let decryptor =
        Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(CryptError::from)?;
    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor =
        Kyber::<Encryption, Kyber512, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber512
    let decryptor =
        Kyber::<Decryption, Kyber512, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

// Merged from the orphaned kyber_tests.rs: encryption-only (no round-trip via
// separate encrypt/decrypt macro helpers) coverage for AES-XTS that the rest of
// this file did not otherwise exercise for `Data` content.
#[test]
fn encrypt_data_AES_XTS_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = [5u8; 0x400];
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Data, AesXts>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.to_vec(), passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Data, AesXts>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message);

    Ok(())
}

// Merged from the orphaned kyber_tests.rs: AES-XTS file round-trip, which the
// rest of this file did not otherwise cover for `Files` content.
#[test]
fn encrypt_file_AES_XTS_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let tmp_dir = Builder::new()
        .prefix("messages")
        .tempdir()
        .map_err(CryptError::from)?;

    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc");

    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) =
        KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Files, AesXts>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Files, AesXts>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message =
        decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text =
        String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(
        enc_path.exists(),
        "Decrypted file should exist after decryption."
    );
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(
        decrypted_message, message,
        "Decrypted message should match the original message."
    );

    Ok(())
}

/// Legacy AES-XTS must never panic: `xts-mode` panics on a last sector
/// shorter than one AES block, so such lengths are rejected with an error,
/// and every other length round-trips.
#[test]
fn aes_xts_lengths_near_sector_boundary_never_panic() -> Result<(), Box<dyn std::error::Error>> {
    let passphrase = "Test Passphrase";
    let (public_key, secret_key) = KeyControKyber1024::keypair()?;
    let mut rejected = 0;
    for len in 430..470usize {
        let message = vec![0x5a; len];
        let mut encryptor =
            Kyber::<Encryption, Kyber1024, Data, AesXts>::new(public_key.clone(), None)?;
        let Ok((encrypted, cipher)) = encryptor.encrypt_data(message.clone(), passphrase) else {
            rejected += 1;
            continue;
        };
        let nonce = encryptor.get_nonce()?.to_string();
        let decryptor =
            Kyber::<Decryption, Kyber1024, Data, AesXts>::new(secret_key.clone(), Some(nonce))?;
        let decrypted = decryptor.decrypt_data(encrypted, passphrase, cipher)?;
        assert_eq!(decrypted, message, "length {len}");
    }
    // Exactly the lengths whose last sector would be 1..=15 bytes are refused.
    assert_eq!(rejected, 15);
    Ok(())
}

/// Hostile ciphertext lengths are decrypted before the legacy HMAC check,
/// so they must fail with an error rather than panic.
#[test]
fn aes_xts_hostile_ciphertext_lengths_error_without_panicking(
) -> Result<(), Box<dyn std::error::Error>> {
    let passphrase = "Test Passphrase";
    let (public_key, secret_key) = KeyControKyber1024::keypair()?;
    let mut encryptor =
        Kyber::<Encryption, Kyber1024, Data, AesXts>::new(public_key.clone(), None)?;
    let (_, cipher) = encryptor.encrypt_data(vec![1u8; 100], passphrase)?;
    let nonce = encryptor.get_nonce()?.to_string();
    for len in (0..40usize).chain(510..540) {
        let decryptor = Kyber::<Decryption, Kyber1024, Data, AesXts>::new(
            secret_key.clone(),
            Some(nonce.clone()),
        )?;
        let result = decryptor.decrypt_data(vec![0xa5; len], passphrase, cipher.clone());
        assert!(result.is_err(), "garbage of length {len} must not decrypt");
    }
    Ok(())
}

/// Every legacy Kyber cipher must report a wrong passphrase, a tampered or
/// truncated ciphertext and a garbage KEM ciphertext as an error, never panic.
macro_rules! legacy_hostile_input_test {
    ($name:ident, $alg:ty) => {
        #[test]
        fn $name() -> Result<(), Box<dyn std::error::Error>> {
            let passphrase = "Test Passphrase";
            let message = vec![0x42u8; 300];
            let (public_key, secret_key) = KeyControKyber1024::keypair()?;
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, $alg>::new(public_key.clone(), None)?;
            let (encrypted, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;
            let nonce = encryptor.get_nonce()?.to_string();
            let decryptor = || {
                Kyber::<Decryption, Kyber1024, Data, $alg>::new(
                    secret_key.clone(),
                    Some(nonce.clone()),
                )
            };

            assert!(decryptor()?
                .decrypt_data(encrypted.clone(), "wrong passphrase", cipher.clone())
                .is_err());

            let mut tampered = encrypted.clone();
            if let Some(byte) = tampered.last_mut() {
                *byte ^= 1;
            }
            assert!(decryptor()?
                .decrypt_data(tampered, passphrase, cipher.clone())
                .is_err());

            for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 513] {
                let _ = decryptor()?.decrypt_data(vec![0xa5; len], passphrase, cipher.clone());
            }
            assert!(decryptor()?
                .decrypt_data(encrypted.clone(), passphrase, vec![0u8; 7])
                .is_err());

            assert_eq!(
                decryptor()?.decrypt_data(encrypted, passphrase, cipher)?,
                message
            );
            Ok(())
        }
    };
}

legacy_hostile_input_test!(legacy_aes_hostile_input_errors_without_panicking, AES);
legacy_hostile_input_test!(
    legacy_aes_ctr_hostile_input_errors_without_panicking,
    AesCtr
);
legacy_hostile_input_test!(
    legacy_aes_gcm_siv_hostile_input_errors_without_panicking,
    AesGcmSiv
);
legacy_hostile_input_test!(
    legacy_aes_xts_hostile_input_errors_without_panicking,
    AesXts
);
legacy_hostile_input_test!(
    legacy_xchacha20_hostile_input_errors_without_panicking,
    XChaCha20
);
legacy_hostile_input_test!(
    legacy_xchacha20poly1305_hostile_input_errors_without_panicking,
    XChaCha20Poly1305
);
