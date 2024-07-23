use crypt_guard::KeyControler::KeyControl;
use crypt_guard::*;
use std::fs::{File};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    let mut key_control = KeyControl::<KeyControKyber1024>::new();

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption of a message with Kyber1024 and AES
    // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
    let mut encryptor = Kyber::<Encryption, Kyber1024, File, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    key_control.set_ciphertext(cipher.clone()).unwrap();
    key_control.save(KeyTypes::Ciphertext, "./key".into()).unwrap();

    // Instantiate Kyber for decryption of a message with Kyber1024 and AES
    // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
    let decryptor = Kyber::<Decryption, Kyber1024, File, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase, cipher)?;

    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");
    println!("{:?}", decrypted_text);
    Ok(())
}  