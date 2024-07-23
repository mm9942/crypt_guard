use crypt_guard_proc::*;
use crate::{
    error::*,
    cryptography::{
        hmac_sign::*, 
    },
    Core::kyber::KyberFunctions,
    KDF::*,
    KeyControKyber1024, 
    KeyControKyber512, 
    KeyControKyber768,
    KyberKeyFunctions,
    KyberKeypair,
    DilithiumKeypair,
    FalconKeypair,
    EncryptSign,
    DecryptOpen,
    // decrypt,
    AES,
    //falcon1024,
    Kyber1024,
    Data,
    Kyber,
    Decryption,
    Encryption,
};

#[test]
fn test_kyber_keypair_1024() {
    let (public, secret) = KyberKeypair!(1024);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
    assert_eq!(public.len(), 1568, "Public key length should be correct for 512 bits");
    assert_eq!(secret.len(), 3168, "Secret key length should be correct for 512 bits");
}

#[test]
fn test_kyber_keypair_768() {
    let (public, secret) = KyberKeypair!(768);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
    assert_eq!(public.len(), 1184, "Public key length should be correct for 512 bits");
    assert_eq!(secret.len(), 2400, "Secret key length should be correct for 512 bits");
}

#[test]
fn test_kyber_keypair_512() {
    let (public, secret) = KyberKeypair!(512);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
    assert_eq!(public.len(), 800, "Public key length should be correct for 512 bits");
    assert_eq!(secret.len(), 1632, "Secret key length should be correct for 512 bits");
}

#[test]
fn test_dilithium_keypair_5() {
    let (public, secret) = DilithiumKeypair!(5);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
}

#[test]
fn test_dilithium_keypair_3() {
    let (public, secret) = DilithiumKeypair!(3);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
}

#[test]
fn test_dilithium_keypair_2() {
    let (public, secret) = DilithiumKeypair!(2);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
}

#[test]
fn test_falcon_keypair_1024() {
    let (public, secret) = FalconKeypair!(1024);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
    assert_eq!(public.len(), 1793, "Public key length should be correct for 512 bits");
    assert_eq!(secret.len(), 2305, "Secret key length should be correct for 512 bits");
}

#[test]
fn test_falcon_keypair_512() {
    let (public, secret) = FalconKeypair!(512);
    assert!(!public.is_empty(), "Public key must not be empty");
    assert!(!secret.is_empty(), "Secret key must not be empty");
    assert_eq!(public.len(), 897, "Public key length should be correct for 512 bits");
    assert_eq!(secret.len(), 1281, "Secret key length should be correct for 512 bits");
}

#[test]
fn SignEncrypt() {
    let message = b"hey, how are you doing?".to_vec();
    let (public, secret) = FalconKeypair!(1024);
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");
    let (encrypt_message, cipher) = EncryptSign!(public_key.clone(), secret.clone(), message.to_owned(), "hey, how are you?").unwrap();
    let decrypt_message = Decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), "hey, how are you?", cipher.to_owned(), AES).unwrap();
    let sign = Signature::<Falcon1024, Message>::new();
    let opened_message = sign.open(decrypt_message, public).unwrap();
    assert_eq!(message, opened_message);
}

#[test]
fn SignEncrypt_DecryptOpen() {
    let message = b"hey, how are you doing?".to_vec();
    let (public, secret) = FalconKeypair!(1024);
    let (public_key, secret_key) = KyberKeypair!(1024);

    let (encrypt_message, cipher) = EncryptSign!(public_key.to_owned(), secret.to_owned(), message.clone(), "hey, how are you?").unwrap();

    let decrypt_message = DecryptOpen!(secret_key.to_owned(), public.to_owned(), encrypt_message.clone(), "hey, how are you?", cipher.to_owned());
    
    assert_eq!(message, decrypt_message);
}


#[test]
fn test_concat_and_split_key() {
    let key = b"hello";  // Example key
    let cipher = b"world";  // Example cipher

    // Encode to hex
    let key_hex = hex::encode(key);
    let cipher_hex = hex::encode(cipher);

    // Concatenate and split
    let concatenated = ConcatCipher!((key_hex.clone(), cipher_hex.clone()));
    let result = SplitCipher!(concatenated);

    // Ensure the result is okay
    assert!(result.is_ok(), "Splitting failed with error");

    // Decode from hex to bytes before comparing
    let (split_key, split_cipher) = result.unwrap();
    let decoded_key = hex::decode(split_key).expect("Failed to decode key");
    let decoded_cipher = hex::decode(split_cipher).expect("Failed to decode cipher");

    // Compare the decoded bytes to the original bytes
    assert_eq!(decoded_key, key, "Keys do not match");
    assert_eq!(decoded_cipher, cipher, "Ciphers do not mammtch");
}
