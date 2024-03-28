use crate::error::CryptError;
use pqcrypto_kyber::kyber1024;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use crate::KeyControl::*;
use std::{
    path::{Path, PathBuf},
};

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


    /// Factory methods for creating specific types of keys.
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
    pub fn safe(&self, base_path: PathBuf) -> Result<(), CryptError> {
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

/// Manages a pair of public and secret keys for cryptographic operations.
impl KeyPair {
    /// Creates a new key pair using the underlying cryptographic algorithm.
    ///
    /// # Returns
    /// A new instance of `KeyPair` with generated public and secret keys.
    pub fn new() -> Self {
        let (pk, sk) = keypair();
        let public_key = Key::new_public_key(pk.as_bytes().to_vec());
        let secret_key = Key::new_secret_key(sk.as_bytes().to_vec());

        KeyPair {
            public_key,
            secret_key,
        }
    }

    /// Constructs a `KeyPair` from existing public and secret keys.
    ///
    /// # Parameters
    /// - `public_key`: The public key component of the pair.
    /// - `secret_key`: The secret key component of the pair.
    ///
    /// # Returns
    /// A `KeyPair` instance composed of the provided keys.
    pub fn from(public_key: Key, secret_key: Key) -> Self {
        KeyPair { public_key, secret_key }
    }

    /// Retrieves the public and secret keys, providing access to the Key values content as &[u8].
    pub fn get_public_key(&self) -> Result<&[u8], CryptError> {
        let public = self.public_key.content().unwrap();
        Ok(public)
    }

    pub fn get_secret_key(&self) -> Result<&[u8], CryptError> {
        let secret = self.secret_key.content().unwrap();
        Ok(secret)
    }

    /// Retrieves the public and secret keys, providing access to their Key struct elements and utility methods.
    pub fn public_key(&self) -> Result<&Key, CryptError> {
        let public = &self.public_key;
        Ok(public)
    }

    pub fn secret_key(&self) -> Result<&Key, CryptError> {
        let secret = &self.secret_key;
        Ok(secret)
    }

    /// Encapsulates a message using the public key, producing ciphertext and a shared secret.
    ///
    /// # Returns
    /// A vector of keys including the ciphertext and shared secret, or a `CryptError`.
    pub fn encap(&self) -> Result<Vec<Key>, CryptError> {
        let pk = PublicKey::from_bytes(self.get_public_key()?).unwrap();
        let (ss, ct) = encapsulate(&pk);
        let ciphertext = Key::new_ciphertext(ct.as_bytes().to_vec());
        let shared_secret = Key::new_shared_secret(ss.as_bytes().to_vec());
        let mut keys = Vec::new();
        let _ = keys.push(ciphertext);
        let _ = keys.push(shared_secret);
        Ok(keys)
    }
    
    /// Decapsulates the ciphertext using the secret key to retrieve the shared secret.
    ///
    /// # Parameters
    /// - `ciphertext`: The byte array of the ciphertext.
    ///
    /// # Returns
    /// The shared secret as a `Key`, or a `CryptError`.
    pub fn decap(&self, ciphertext: &[u8]) -> Result<Key, CryptError> {
        let ct = Ciphertext::from_bytes(ciphertext).unwrap();
        let sk = SecretKey::from_bytes(self.get_secret_key()?).unwrap();
        let ss2 = decapsulate(&ct, &sk);
        let shared_secret = Key::new_shared_secret(ss2.as_bytes().to_vec());
        Ok(shared_secret)
    }
}