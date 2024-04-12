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

    let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
    let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;
    
    let enc_path = tmp_dir.path().clone().join("message.txt");
    let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 
    
    let _ = fs::write(&enc_path, message.as_bytes())?;

    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption of a file with Kyber768 and XChaCha20
    // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
    let mut encryptor = Kyber::<Encryption, Kyber768, File, XChaCha20>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

    let nonce = encryptor.get_nonce();

    let _ = fs::remove_file(enc_path.clone());

    // Instantiate Kyber for decryption of a file with Kyber768 and XChaCha20
    // Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
    let mut decryptor = Kyber::<Decryption, Kyber768, File, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;
    
    // Decrypt message
    let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;
    Ok(())
}