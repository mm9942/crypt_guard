use crate::keychain::*;
use pqcrypto_kyber::kyber1024;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_falcon::falcon1024::{self, *};
use pqcrypto_traits::kem::{PublicKey as PublicKeyKem, SecretKey as SecKeyKem, SharedSecret as SharedSecretKem, Ciphertext as CiphertextKem};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::{
    fs::{self, File}, 
    path::{PathBuf, Path},
    io::{self, Read, Write},
    env::current_dir
};
use crate::{
    ActionType,
    Encrypt,
    Keychain, 
};
use rand::{rngs::OsRng, RngCore};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureSign, PublicKey as PublicKeySign,
    SecretKey as SecretKeySign, SignedMessage as SignedMessageSign,
};
use byteorder::{BigEndian, WriteBytesExt};
 use crypt_guard_sign::{self, *};

#[cfg(feature = "xchacha20")]
use chacha20::{
    XChaCha20, 
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek}
};
use std::iter::repeat;

#[cfg(feature = "default")]
use aes::{
    cipher::{
        BlockEncrypt, 
        generic_array::GenericArray,
        KeyInit
    },
    Aes256
};


impl Encrypt {
    pub fn new() -> Self {
        Self
    }
    pub fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn append_hmac(encrypted_data: Vec<u8>, hmac: Vec<u8>) -> Vec<u8> {
        [encrypted_data, hmac].concat()
    }

    pub fn generate_signature(data: &[u8], sk: falcon1024::SecretKey) -> Vec<u8> {
        let signature = detached_sign(&data, &sk);
        let signed_message = DetachedSignatureSign::as_bytes(&signature);
        signed_message.to_owned()
    }

    pub fn append_signature(data: &[u8], signature: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let data_length = data.len() as u64;
        let mut data_length_bytes = vec![];
        data_length_bytes.write_u64::<BigEndian>(data_length).unwrap();

        let signed_data = [data_length_bytes, data.to_vec(), signature].concat();

        Ok(signed_data)
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
        encrypt: &str,
        action: ActionType,
        hmac_key: &[u8],
        nonce: Option<&[u8; 24]>,
    ) -> Result<Vec<u8>, CryptError> {
        let mut keychain = Keychain::new()?;

        // Load the public key from the given path
        let public_key = keychain.load_public_key(public_key_path).await?;

        // Encapsulate using the public key
        let (shared_secret, ciphertext) = kyber1024::encapsulate(&public_key);

        match action {
            ActionType::FileAction => {
                let path = PathBuf::from(encrypt);
                println!("Encrypting file...");

                #[cfg(feature = "default")]
                let encrypted_data = self.encrypt_file(path.clone(), &shared_secret, hmac_key).await?;
                #[cfg(feature = "xchacha20")]
                if nonce != None {
                    let nonce: &[u8; 24] = nonce.unwrap();
                    let encrypted_data = self.encrypt_file_xchacha20(path, &shared_secret, nonce, hmac_key).await?;
                }
                Ok(encrypted_data)
            },
            ActionType::MessageAction => {
                println!("Encrypting message...\n");

                #[cfg(feature = "default")]
                let encrypted_data = self.encrypt_msg(encrypt, &shared_secret, hmac_key).await?;
                #[cfg(feature = "xchacha20")]
                if nonce != None {
                    let nonce: &[u8; 24] = nonce.unwrap();
                    let encrypted_data = self.encrypt_msg_xchacha20(encrypt, &shared_secret, nonce, hmac_key).await?;
                }

                self.save_encrypted_message(&encrypted_data, PathBuf::from("./message.enc")).await?;
                Ok(encrypted_data)
            },
            _ => Err(CryptError::InvalidParameters),
        }
    }
}



#[cfg(feature = "default")]
impl Encrypt {
    #[cfg(feature = "default")]
    pub async fn encrypt_data(&self, data: &[u8], key: &[u8], hmac_secret: &[u8]) -> Result<Vec<u8>, CryptError> {
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
        
        let hmac = Self::generate_hmac(hmac_secret, &encrypted_data);
        let encrypted_and_signed_data = Self::append_hmac(encrypted_data, hmac);
        
        Ok(encrypted_and_signed_data)
    }

    pub async fn encrypt_file(&self, file_path: PathBuf, shared_secret: &dyn SharedSecretKem, hmac_key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let data = fs::read(&file_path).map_err(|_| CryptError::IOError)?;
        let encrypted_data = self.encrypt_data(&data, shared_secret.as_bytes(), hmac_key).await?;

        let mut encrypted_file_path = file_path.clone();
        let unique_encrypted_file_path = Keychain::generate_unique_filename(encrypted_file_path.as_os_str().to_str().expect("REASON"), "enc");
        let enc_file_path = PathBuf::from(unique_encrypted_file_path);
        fs::write(&enc_file_path, &encrypted_data).map_err(|_| CryptError::WriteError)?;
        Ok(encrypted_data) // Return the path of the encrypted file
    }

    pub async fn encrypt_msg(&self, message: &str, shared_secret: &dyn SharedSecretKem, hmac_key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let data = message.as_bytes();
        self.encrypt_data(data, shared_secret.as_bytes(), hmac_key).await
    }
}

#[cfg(feature = "xchacha20")]
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(feature = "xchacha20")]
impl Encrypt {
    #[cfg(feature = "xchacha20")]
    pub async fn encrypt_data_xchacha20(&self, data: &[u8], key: &[u8], nonce: &[u8; 24], hmac_secret: &[u8]) -> Result<Vec<u8>, CryptError> { 
        let mut cipher = XChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(nonce));
        let mut encrypted_data = data.to_vec();
        cipher.apply_keystream(&mut encrypted_data);

        let hmac = Self::generate_hmac(hmac_secret, &encrypted_data);
        let encrypted_and_signed_data = Self::append_hmac(encrypted_data, (*hmac).to_vec());

        Ok(encrypted_and_signed_data)
    }

    pub async fn encrypt_file_xchacha20(&self, file_path: PathBuf, shared_secret: &dyn SharedSecretKem, nonce: &[u8; 24], hmac_key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let data = fs::read(&file_path).map_err(|_| CryptError::IOError)?;
        let encrypted_data = self.encrypt_data_xchacha20(&data, shared_secret.as_bytes(), nonce, hmac_key).await?;

        let mut encrypted_file_path = file_path.clone();
        let unique_encrypted_file_path = Keychain::generate_unique_filename(encrypted_file_path.as_os_str().to_str().expect("REASON"), "enc");
        let enc_file_path = PathBuf::from(unique_encrypted_file_path);
        fs::write(&enc_file_path, &encrypted_data).map_err(|_| CryptError::WriteError)?;
        Ok(encrypted_data) // Return the path of the encrypted file
    }

    pub async fn encrypt_msg_xchacha20(&self, message: &str, shared_secret: &dyn SharedSecretKem, nonce: &[u8; 24], hmac_key: &[u8]) -> Result<Vec<u8>, CryptError> {
        let data = message.as_bytes();
        let encrypted_msg = self.encrypt_data_xchacha20(data, shared_secret.as_bytes(), nonce, hmac_key).await;
        encrypted_msg
    }
}

impl From<io::Error> for CryptError {
    fn from(_: io::Error) -> Self {
        CryptError::IOError
    }
}
