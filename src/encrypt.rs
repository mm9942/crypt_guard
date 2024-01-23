use crate::keychain::*;
use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, 
    generic_array::GenericArray,
    KeyInit
};
use pqcrypto_kyber::kyber1024::{self, *};

use pqcrypto_traits::kem::{PublicKey as PublicKeyKem, SecretKey as SecKeyKem, SharedSecret as SharedSecretKem, Ciphertext as CiphertextKem};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::{
    fs, 
    path::{PathBuf, Path},
    io,
    env::current_dir
};

pub struct Encrypt;

impl Encrypt {
    pub fn new() -> Self {
        Self
    }
    pub fn generate_hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn append_hmac(&self, encrypted_data: Vec<u8>, hmac: Vec<u8>) -> Vec<u8> {
        [encrypted_data, hmac].concat()
    }

    pub async fn encrypt_with_aes_hmac(&self, data: &[u8], key: &[u8], hmac_secret: &[u8]) -> Result<Vec<u8>, CryptError> {
        let block_size = 16;
        let mut padded_data = data.to_vec();

        // Padding the data if necessary
        let padding_needed = block_size - (padded_data.len() % block_size);
        if padding_needed < block_size {
            padded_data.extend(vec![0u8; padding_needed]);
        }

        let mut encrypted_data = vec![0u8; padded_data.len()];
        let cipher = Aes256::new(GenericArray::from_slice(key));
        for (chunk, encrypted_chunk) in padded_data.chunks(block_size).zip(encrypted_data.chunks_mut(block_size)) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            encrypted_chunk.copy_from_slice(&block);
        }
        
        let hmac = self.generate_hmac(hmac_secret, &encrypted_data);
        let encrypted_and_signed_data = self.append_hmac(encrypted_data, hmac);
        
        Ok(encrypted_and_signed_data)
    }

    pub async fn load_pub_key(&self, pub_key_path: PathBuf) -> Result<PublicKey, CryptError> {
        let public_key_bytes = File::load(pub_key_path, KeyTypes::PublicKey).await?;
        let public_key = kyber1024::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| CryptError::EncapsulationError)?;
        Ok(public_key)
    }

    pub async fn encrypt_file(&self, file_path: PathBuf, shared_secret: &dyn SharedSecretKem, hmac_key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let data = fs::read(&file_path).map_err(|_| CryptError::IOError)?;
        let encrypted_data = self.encrypt_with_aes_hmac(&data, shared_secret.as_bytes(), hmac_key).await?;
        let mut encrypted_file_path = file_path.clone();
        let unique_encrypted_file_path = Keychain::generate_unique_filename(encrypted_file_path.as_os_str().to_str().expect("REASON"), "enc");
        let enc_file_path = PathBuf::from(unique_encrypted_file_path);
        fs::write(&enc_file_path, &encrypted_data).map_err(|_| CryptError::WriteError)?;
        Ok(encrypted_data) // Return the path of the encrypted file
    }

    pub async fn encrypt_msg(&self, message: &str, shared_secret: &dyn SharedSecretKem, hmac_key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let data = message.as_bytes();
        self.encrypt_with_aes_hmac(data, shared_secret.as_bytes(), hmac_key).await
    }

    pub async fn save_encrypted_message(&self, message: &[u8], path: PathBuf) -> Result<(), CryptError> {
        let hex_message = format!(
        "-----BEGIN ENCRYPTED MESSAGE-----\n{}\n-----END ENCRYPTED MESSAGE-----",
            hex::encode(&message)
        );
        let _ = fs::write("./message.enc", &hex_message)
            .map_err(|_| CryptError::WriteError);

        Ok(())
    }

    pub async fn encrypt(
        &self, 
        public_key_path: PathBuf,
        encrypted_file_path: Option<&PathBuf>,
        message: Option<&str>,
        hmac_key: &[u8],
    ) -> Result<Vec<u8>, CryptError> {
        let mut keychain = Keychain::new().unwrap();
        
        // Load the public key from the given path
        let public_key = keychain.load_public_key(public_key_path).await?;

        // Encapsulate using the public key
        let (shared_secret, ciphertext) = kyber1024::encapsulate(&public_key);

        // Create a new keychain instance to save the ciphertext
        let mut keychain = Keychain {
            public_key: None,
            secret_key: None,
            shared_secret: None,
            ciphertext: Some(ciphertext),
        };

        // Save the ciphertext
        keychain.save_ciphertext("./keychain", "cipher").await?;
        let ciphertext_hex = hex::encode(&keychain.get_ciphertext().await.unwrap().as_bytes());
        //println!("please note: {}", ciphertext_hex);

        // Encrypt the message or file
        match (message, encrypted_file_path) {
            (Some(msg), None) => {
                self.encrypt_msg(msg, &shared_secret, hmac_key).await
            },
            (None, Some(file_path)) => {
                self.encrypt_file(file_path.clone(), &shared_secret, hmac_key).await
            },
            _ => return Err(CryptError::InvalidParameters)
        }
    }
}

impl From<io::Error> for CryptError {
    fn from(_: io::Error) -> Self {
        CryptError::IOError
    }
}
