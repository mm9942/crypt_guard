use crypt_guard::{
    KyberFunctions,
    KeyControKyber1024,
    KyberKeyFunctions,
    error::*,
    Encryption,
    Decryption,
    Kyber1024,
    AES,
    Kyber,
    Data,
    // bring exported macros into scope
    encryption,
    decryption,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Encrypt message using macro
    let (encrypt_message, cipher) = encryption!(public_key.to_owned(), 1024, message.to_owned(), passphrase, AES)?;

    // Decrypt message using macro
    let decrypt_message = decryption!(secret_key.to_owned(), 1024, encrypt_message.to_owned(), passphrase, cipher.to_owned(), AES);
    println!("{}", String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string"));
    Ok(())
}
