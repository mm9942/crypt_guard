use crate::{
    Encryption,
    Decryption,
    EncryptFile,
    DecryptFile,
    Core::{
        kyber::{
            KyberFunctions, 
            *
        }, 
        *
    },
    error::*,
    cryptography::*,
    KyberKeypair,
};

use tempfile::{TempDir, Builder};
use std::fs::{self};

#[test]
fn encrypt_decrypt_msg_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");
    let key = &public_key;

    // Encrypt message
    let (encrypt_message, cipher) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES)?;
    
    // Decrypt message
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), AES);

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message?, message.to_owned());

    Ok(())
}


#[test]
fn encrypt_decrypt_msg_macro_XChaCha20_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";

    // Generate key pair

    let (public_key, secret_key) = KyberKeypair!(1024);
    let mut key = public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) = Encryption!(key.to_owned(), 1024, message.to_owned(), passphrase, XChaCha20);

    // Decrypt message
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), Some(nonce.clone()), XChaCha20);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message?, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_msg_macro_AES_GCM_SIV_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KyberKeypair!(1024);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Encryption,
        encryption_type: CryptographicMechanism::AES_GCM_SIV,
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

    let mut aes_gcm_siv = CipherAES_GCM_SIV::new(infos, None);
    let (encrypt_message, cipher) = aes_gcm_siv.encrypt(public_key)?;
    let iv = aes_gcm_siv.iv();
    println!("IV: {:?}", &iv);
    println!("encrypt_message: {:?}", &encrypt_message);

        // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Decryption,
        encryption_type: CryptographicMechanism::AES_GCM_SIV,
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

    let mut aes_gcm_siv_dec = CipherAES_GCM_SIV::new(infos, Some(hex::encode(iv)));
    let decrypt_message = aes_gcm_siv_dec.decrypt(secret_key, cipher)?;

    println!("{:?}", &decrypt_message);
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

    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES_GCM_SIV>::new(public_key.clone(), None)?;
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let decryptor = Kyber::<Decryption, Kyber1024, Data, AES_GCM_SIV>::new(secret_key, Some(nonce?.to_string()))?;
    let decrypt_message = decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_AES_GCM_SIV_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {    // Generate key pair    
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";
    
    println!("{:?}", &message);
   
    // Generate key pair
    let (public_key, secret_key) = KyberKeypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_GCM_SIV);
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), Some(nonce), AES_GCM_SIV)?;
    
    println!("{:?}", &decrypt_message);
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
    let (encrypt_message, cipher) = Encryption!(public_key.to_owned(), 1024, message.to_vec(), passphrase, AES_CTR);
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), AES_CTR)?;
    
    println!("{:?}", &decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}
*/

#[test]
fn encrypt_decrypt_msg_macro_AES_CTR_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KyberKeypair!(1024);

    // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Encryption,
        encryption_type: CryptographicMechanism::AES_GCM_SIV,
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

    let mut aes_gcm_siv = CipherAES_CTR::new(infos, None);
    let (encrypt_message, cipher) = aes_gcm_siv.encrypt(public_key)?;
    let iv = aes_gcm_siv.iv();
    println!("IV: {:?}", &iv);
    println!("encrypt_message: {:?}", &encrypt_message);

        // Encrypt message
    let crypt_metadata = CryptographicMetadata {
        process: Process::Decryption,
        encryption_type: CryptographicMechanism::AES_GCM_SIV,
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

    let mut aes_gcm_siv_dec = CipherAES_CTR::new(infos, Some(hex::encode(iv)));
    let decrypt_message = aes_gcm_siv_dec.decrypt(secret_key, cipher)?;

    println!("{:?}", &decrypt_message);
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

    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES_CTR>::new(public_key.clone(), None)?;
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let decryptor = Kyber::<Decryption, Kyber1024, Data, AES_CTR>::new(secret_key, Some(nonce?.to_string()))?;
    let decrypt_message = decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_AES_CTR_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {    // Generate key pair    
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";
    
    println!("{:?}", &message);
   
    // Generate key pair
    let (public_key, secret_key) = KyberKeypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_CTR);
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), Some(nonce), AES_CTR)?;
    
    println!("{:?}", &decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}

#[test]
fn encrypt_decrypt_msg_macro_XChaCha20Poly1305_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KyberKeypair!(1024);

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

    let mut aes_gcm_siv = CipherChaCha_Poly::new(infos, None);
    let (encrypt_message, cipher) = aes_gcm_siv.encrypt(public_key)?;
    let iv = aes_gcm_siv.nonce();
    println!("IV: {:?}", &iv);
    println!("encrypt_message: {:?}", &encrypt_message);

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

    let mut aes_gcm_siv_dec = CipherChaCha_Poly::new(infos, Some(hex::encode(iv)));
    let decrypt_message = aes_gcm_siv_dec.decrypt(secret_key, cipher)?;

    println!("{:?}", &decrypt_message);
    for enc_b in decrypt_message.clone() {
            print!("{:02x} ", enc_b);
    }

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message.clone(), message.as_bytes().to_owned());
    Ok(())
}


#[test]
fn encrypt_decrypt_data_macro_XChaCha20Poly1305_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {    // Generate key pair    
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";
    
    println!("{:?}", &message);
   
    // Generate key pair
    let (public_key, secret_key) = KyberKeypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher, nonce) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, XChaCha20Poly1305);
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), Some(nonce.to_owned()), XChaCha20Poly1305)?;
    
    println!("{:?}", &decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}

#[test]
fn encrypt_decrypt_XChaCha20Poly1305_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    let mut encryptor = Kyber::<Encryption, Kyber1024, Data, XChaCha20Poly1305>::new(public_key.clone(), None)?;
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20Poly1305>::new(secret_key, Some(nonce?.to_string()))?;
    let decrypt_message = decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    assert_eq!(decrypt_message, message);

    Ok(())
}

#[test]
fn encrypt_decrypt_data_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {    // Generate key pair    
    let message = "Hey, how are you doing?".as_bytes();
    let passphrase = "Test Passphrase";
    
    println!("{:?}", &message);
   
    // Generate key pair
    let (public_key, secret_key) = KyberKeypair!(1024);
    let key: &[u8] = &public_key;

    // Encrypt message
    let (encrypt_message, cipher) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES)?;
    println!("{:?}", encrypt_message);
    // Decrypt message
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), AES)?;
    
    println!("{:?}", &decrypt_message);
    // Assert that the decrypted message matches the original message
    assert_eq!(decrypt_message, message.to_owned());

    Ok(())
}

#[test]
fn encrypt_decrypt_file_macro_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Encrypt message
    let (_encrypt_message, cipher) = EncryptFile!(public_key.to_owned(), 1024, enc_path.clone(), passphrase, AES)?;

    fs::remove_file(enc_path.clone());
    
    // Decrypt message
    let decrypt_message = DecryptFile!(secret_key.to_owned(), 1024, dec_path.clone(), passphrase, cipher.to_owned(), AES);

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

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
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Message, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

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
    let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_data(encrypt_message.clone(), passphrase, cipher.to_owned())?;

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
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    // Instantiate Kyber for decryption with Kyber768
    let decryptor = Kyber::<Decryption, Kyber768, Message, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

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
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    // Instantiate Kyber for decryption with Kyber512
    let decryptor = Kyber::<Decryption, Kyber512, Message, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    Ok(())
}

#[test]
fn encrypt_file_AES_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_file_AES_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber768, Files, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber768, Files, AES>::new(secret_key, None)?;
    
    // Decrypt file
    let decrypt_file = decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_file).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}


#[test]
fn encrypt_file_AES_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Files, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber512
    let decryptor = Kyber::<Decryption, Kyber512, Files, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

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
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Message, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

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
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber768
    let decryptor = Kyber::<Decryption, Kyber768, Message, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

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
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    let nonce = encryptor.get_nonce();

    // Instantiate Kyber for decryption with Kyber512
    let decryptor = Kyber::<Decryption, Kyber512, Message, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher.to_owned())?;

    // Assert that the decrypted message matches the original message
    assert_eq!(String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string"), message);

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber1024() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber1024
    let decryptor = Kyber::<Decryption, Kyber1024, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber768() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber768
    let mut encryptor = Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber768
    let decryptor = Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}

#[test]
fn encrypt_file_XChaCha20_Kyber512() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";

    let _tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().join("message.txt");
    let dec_path = tmp_dir.path().join("message.txt.enc"); 
    
    fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber512::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber512
    let mut encryptor = Kyber::<Encryption, Kyber512, Files, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (_encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase)?;

    let nonce = encryptor.get_nonce();

    fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption with Kyber512
    let decryptor = Kyber::<Decryption, Kyber512, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase, cipher.to_owned())?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");

    // Assert that the decrypted message matches the original message
    assert_eq!(decrypted_text, message);

    assert!(enc_path.exists(), "Decrypted file should exist after decryption.");
    let decrypted_message = fs::read_to_string(&enc_path)?;
    assert_eq!(decrypted_message, message, "Decrypted message should match the original message.");

    Ok(())
}