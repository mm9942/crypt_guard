use crate::keychain::*;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{SharedSecret};
use aes::Aes256;
use aes::cipher::{
    BlockDecrypt, KeyInit, generic_array::GenericArray
};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::{fs, path::PathBuf};
use std::io::Write;

pub struct Decrypt;

impl Decrypt {
    pub async fn generate_original_filename(encrypted_path: &str) -> String {
       // let encrypted_path = format!("./{}", encrypted_path);
        let path = std::path::Path::new(&encrypted_path);
        let dir = path.parent().unwrap_or_else(|| std::path::Path::new(""));
        let mut file_name = path.file_stem().unwrap().to_str().unwrap().to_string();

        // Remove appended numbers and extensions like _1, _2, etc.
        if let Some(index) = file_name.rfind('_') {
            if file_name[index + 1..].chars().all(char::is_numeric) {
                file_name.truncate(index);
            }
        }

        format!("{}/{}", dir.display(), file_name)
    }
    fn verify(key: &[u8], data_with_hmac: &[u8], hmac_len: usize) -> Result<Vec<u8>, CryptError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        if data_with_hmac.len() < hmac_len {
            return Err(CryptError::HmacShortData);
        }

        let (data, hmac) = data_with_hmac.split_at(data_with_hmac.len() - hmac_len);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).map_err(|_| CryptError::HmacKeyErr)?;

        mac.update(data);

        if mac.verify_slice(hmac).is_err() {
            return Err(CryptError::HmacVerificationError);
        }

        Ok(data.to_vec())
    }

    // Function to verify the HMAC of the data
    pub fn verify_hmac(key: &[u8], data_with_hmac: &[u8], hmac_len: usize) -> Result<Vec<u8>, &'static str> {
        if data_with_hmac.len() < hmac_len {
            return Err("Data is too short for HMAC verification");
        }

        let (data, hmac) = data_with_hmac.split_at(data_with_hmac.len() - hmac_len);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key)
            .expect("HMAC can take key of any size");

        mac.update(data);

        if let Err(_) = mac.verify_slice(hmac) {
            eprintln!("HMAC verification failed!");
            eprintln!("Data: {:?}", data);
            eprintln!("HMAC: {:?}", hmac);
            return Err("HMAC verification failed");
        }

        Ok(data.to_vec())
    }

    pub async fn decrypt_with_aes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let mut decrypted_data = vec![0u8; data.len()];
        let cipher = Aes256::new(GenericArray::from_slice(key));
        for (chunk, decrypted_chunk) in data.chunks(16).zip(decrypted_data.chunks_mut(16)) {
            let mut block = GenericArray::clone_from_slice(chunk); // Create a mutable copy
            cipher.decrypt_block(&mut block);
            decrypted_chunk.copy_from_slice(&block);
        }

        // Remove padding if present
        while decrypted_data.last() == Some(&0) {
            decrypted_data.pop();
        }

        Ok(decrypted_data)
    }

    pub async fn decrypt_file(encrypted_file_path: &PathBuf, key: &dyn SharedSecret, hmac_key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let decrypted_file_path = encrypted_file_path.as_os_str().to_str().ok_or(CryptError::PathError)?;
        let decrypt_file_path = Decrypt::generate_original_filename(decrypted_file_path).await;
        println!("Decrypted file path: {:?}", decrypt_file_path);

        let data_with_hmac = fs::read(&encrypted_file_path).map_err(|_| CryptError::IOError)?;
        let encrypted_data = Decrypt::verify_hmac(hmac_key, &data_with_hmac, 64).unwrap();
        let decrypted_data = Decrypt::decrypt_with_aes(&encrypted_data, key.as_bytes()).await?;

        fs::write(&decrypt_file_path, &decrypted_data).map_err(|_| CryptError::WriteError)?;

        println!("Decryption completed and file written to {:?}", decrypt_file_path);
        Ok(decrypted_data)
    }

    pub async fn decrypt_msg(encrypted_data_with_hmac: &[u8], key: &dyn SharedSecret, hmac_key: &[u8], safe: bool) -> Result<String, CryptError> {
        let encrypted_data = Decrypt::verify_hmac(hmac_key, encrypted_data_with_hmac, 64).unwrap();
        let decrypted_data = Decrypt::decrypt_with_aes(&encrypted_data, key.as_bytes()).await?;
        let decrypted_str = String::from_utf8(decrypted_data)
            .map_err(|_| CryptError::Utf8Error)?;
        if safe {
            let mut message_file = fs::File::create("./message.txt");
            write!(message_file.unwrap(), "{}", &decrypted_str).unwrap();
        }
        Ok(decrypted_str)
    }


    pub async fn decrypt(
        secret_key: PathBuf,
        ciphertext: PathBuf,
        encrypted_file_path: Option<&PathBuf>,
        encrypted_data_with_hmac: Option<&[u8]>,
        hmac_key: &[u8],
    ) -> Result<(), CryptError> {
        let mut keychain = Keychain::new().unwrap();

        // Load the secret key and ciphertext
        let secret = keychain.load_secret_key(secret_key).await?;
        let cipher = keychain.load_ciphertext(ciphertext).await?;

        // Decapsulate using the secret key
        let shared_secret = decapsulate(&cipher, &secret);

        // Decrypt the file or message
        match (encrypted_file_path, encrypted_data_with_hmac) {
            (Some(path), None) => {
                println!("Decrypting file...");
                Decrypt::decrypt_file(path, &shared_secret, hmac_key).await?;
                Ok(())
            },
            (None, Some(data)) => {
                println!("Decrypting message...");
                let _ = Decrypt::decrypt_msg(data, &shared_secret, hmac_key, true).await?;
                Ok(())
            },
            _ => {
                println!("Invalid parameters for decryption");
                Err(CryptError::InvalidParameters)
            },
        }
    }


}
