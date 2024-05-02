use crate::error::CryptError;
use pqcrypto_kyber::kyber1024;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use crate::KeyControl::*;
use std::{
    path::{PathBuf},
};

/// Represents a cryptographic key, including its type and raw content.
#[derive(PartialEq, Debug, Clone)]
pub struct Key {
    /// The type of the key, as defined in `KeyTypes`.
    key_type: KeyTypes,
    /// The raw content of the key.
    content: Vec<u8>
}

/// Represents a cryptographic key with its type and content.
/// It provides functionalities to manipulate and store keys in various formats.
impl Key {
    /// Constructs a new `Key` with specified type and content, optimizing storage based on the key type.
    ///
    /// # Parameters
    /// - `key_type`: The type of the key (public, secret, ciphertext, shared secret).
    /// - `content`: The raw content of the key.
    ///
    /// # Returns
    /// A new instance of `Key`.
    pub fn new(key_type: KeyTypes, content: Vec<u8>) -> Self {
        let content = Self::optimize(&key_type, content);
        Key {
            key_type,
            content,
        }
    }

    /// Optimizes the storage of the key based on its type.
    ///
    /// # Parameters
    /// - `key_type`: The type of the key being optimized.
    /// - `content`: The raw key content.
    ///
    /// # Returns
    /// Optimized key content as a byte vector.
    fn optimize(key_type: &KeyTypes, content: Vec<u8>) -> Vec<u8> {
        let key: Vec<u8> = match key_type {
            KeyTypes::PublicKey => {
                let key: kyber1024::PublicKey = PublicKey::from_bytes(&content).unwrap();
                key.as_bytes().to_vec()
            },
            KeyTypes::SecretKey => {
                let key: kyber1024::SecretKey = SecretKey::from_bytes(&content).unwrap();
                key.as_bytes().to_vec()
            },
            KeyTypes::Ciphertext => {
                let key: kyber1024::Ciphertext = Ciphertext::from_bytes(&content).unwrap();
                key.as_bytes().to_vec()
            },
            KeyTypes::SharedSecret => {
                let key: kyber1024::SharedSecret = SharedSecret::from_bytes(&content).unwrap();
                key.as_bytes().to_vec()
            },
            _ => {
                content
            }
        };
        key
    }


    /// Factory methods for creating specific types of keys by building new Self elements.
    pub fn new_public_key(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::PublicKey,
            content: key,
        }
    }
    pub fn new_secret_key(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::SecretKey,
            content: key,
        }
    }
    pub fn new_ciphertext(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::Ciphertext,
            content: key,
        }
    }
    pub fn new_shared_secret(key: Vec<u8>) -> Self {
        Key {
            key_type: KeyTypes::SharedSecret,
            content: key,
        }
    }

    /// Accessors for the key's properties.
    pub fn get(&self) -> Result<&Key, CryptError> {
        Ok(&self)
    }
    pub fn key_type(&self) -> Result<&KeyTypes, CryptError> {
        Ok(&self.key_type)
    }
    pub fn content(&self) -> Result<&[u8], CryptError> {
        Ok(&self.content)
    }

    /// Safely stores the key to a specified path.
    ///
    /// # Parameters
    /// - `base_path`: The base directory path where the key will be saved.
    ///
    /// # Returns
    /// An `Ok(())` on success or a `CryptError` on failure.
    pub fn save(&self, base_path: PathBuf) -> Result<(), CryptError> {
        let file_name = match self.key_type {
            KeyTypes::PublicKey => "public_key.pub",
            KeyTypes::SecretKey => "secret_key.sec",
            KeyTypes::Ciphertext => "ciphertext.ct",
            KeyTypes::SharedSecret => return Err(CryptError::UnsupportedOperation),
            _ => return Err(CryptError::InvalidKeyType),
        };

        let path = base_path.join(file_name);
        let file_metadata = FileMetadata::from(path, self.file_type_from_key_type(), FileState::Encrypted);
        
        file_metadata.save(&self.content)
    }

    fn file_type_from_key_type(&self) -> FileTypes {
        match self.key_type {
            KeyTypes::PublicKey => FileTypes::PublicKey,
            KeyTypes::SecretKey => FileTypes::SecretKey,
            KeyTypes::Ciphertext => FileTypes::Ciphertext,
            _ => FileTypes::Other,
        }
    }

    /// Encapsulates the key, generating a ciphertext and shared secret.
    ///
    /// # Returns
    /// A tuple containing the ciphertext and shared secret as `Key` instances, or a `CryptError`.
    pub fn encap(&self) -> Result<(Key,Key), CryptError> {
        match self.key_type {
            KeyTypes::PublicKey => {
                let pk = PublicKey::from_bytes(self.content()?).unwrap();
                let (ss, ct) = encapsulate(&pk);
                let ciphertext = Key::new_ciphertext(ct.as_bytes().to_vec());
                let shared_secret = Key::new_shared_secret(ss.as_bytes().to_vec());
                //Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()));
                Ok((ciphertext, shared_secret))
            }
            _ => Err(CryptError::EncapsulationError)
        }
    }

    /// Decapsulates the ciphertext using the secret key, retrieving the shared secret.
    ///
    /// # Parameters
    /// - `ciphertext`: The ciphertext `Key` to be decapsulated.
    ///
    /// # Returns
    /// The shared secret as a `Key`, or a `CryptError`.
    pub fn decap(&self, ciphertext: Key) -> Result<Key, CryptError> {
        match self.key_type {
            KeyTypes::SecretKey => {
                let ct = Ciphertext::from_bytes(ciphertext.content()?).unwrap();
                let sk = SecretKey::from_bytes(self.content()?).unwrap();
                let ss2 = decapsulate(&ct, &sk);
                let shared_secret = Key::new_shared_secret(ss2.as_bytes().to_vec());
                Ok(shared_secret)
            }
            _ => Err(CryptError::DecapsulationError)
        }
    }
}