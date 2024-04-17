use crypt_guard::{
    encrypt,
    decrypt,
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
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?".as_bytes().to_owned();
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encrypt!(encryptor, message, passphrase)?;

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Message, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message = decrypt!(decryptor, encrypt_message, passphrase, cipher);
    println!("{}", String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string"));
    Ok(())
}