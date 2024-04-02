//use crypt_guard::KeyKyber::KeyControl;
use crypt_guard::{*, error::*};
use std::{
    fs::{self, File}, 
    marker::PhantomData,
    path::{PathBuf, Path},
    io::{Read, Write},

};
use tempfile::{TempDir, Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption of a message with Kyber1024 and AES
    // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
    let mut encryptor = Kyber::<Encryption, Kyber1024, File, AES>::new(public_key.clone(), None)?;
    
    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    // Instantiate Kyber for decryption of a message with Kyber1024 and AES
    // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
    let mut decryptor = Kyber::<Decryption, Kyber1024, File, AES>::new(secret_key, None)?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");
    println!("{:?}", decrypted_text);
    Ok(())
}  