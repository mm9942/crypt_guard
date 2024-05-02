use crypt_guard::{
    KyberFunctions,
    KeyControKyber1024,
    KyberKeyFunctions,
    error::*,
    Encryption, 
    Decryption, 
    Kyber1024, 
    Message, 
    AES,
    Kyber,
    Data,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Encrypt message
    let (encrypt_message, cipher) = Encryption!(public_key.clone(), 1024, message, passphrase, AES)?;

    // Decrypt message
    let decrypt_message = Decryption!(secret_key, 1024, encrypt_message, passphrase, cipher, AES);
    println!("{}", String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string"));
    Ok(())
}