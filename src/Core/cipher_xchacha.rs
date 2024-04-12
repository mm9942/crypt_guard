use crate::{
    *,
    cryptography::*, 
    error::*, 
    hmac_sign::*, 
    Core::{
        CryptographicFunctions, 
        KeyControl, 
        KeyControKyber512, 
        KeyControKyber768, 
        KeyControKyber1024, 
        KyberKeyFunctions, 
        kyber::KyberSizeVariant,
        KeyControlVariant,
    }
};
use pqcrypto_traits::kem::{PublicKey as PublicKeyKem, SecretKey as SecKeyKem, SharedSecret as SharedSecretKem, Ciphertext as CiphertextKem};
use pqcrypto_kyber::kyber1024;
use pqcrypto_kyber::kyber1024::*;
use chacha20::{
    XChaCha20, 
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, generic_array::GenericArray}
};
use std::{
    iter::repeat,
    path::{PathBuf, Path}, 
    marker::PhantomData, 
    result::Result, 
    io::{Read, Write}, 
    fs
};
use rand::{RngCore, rngs::OsRng};
use hex;


/// Generates a 24-byte nonce using OS-level randomness.
///
/// # Returns
/// A 24-byte array filled with secure random bytes.
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// The main struct for handling cryptographic operations with ChaCha20 algorithm.
/// It encapsulates the cryptographic information, shared secret, and nonce required for encryption and decryption.
impl CipherChaCha {
    /// Constructs a new `CipherChaCha` instance with specified cryptographic information and an optional nonce.
    ///
    /// # Parameters
    /// - `infos`: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    /// - `nonce`: Optional hexadecimal string representation of the nonce. If not provided, a nonce will be generated.
    ///
    /// # Returns
    /// A new `CipherChaCha` instance.
	pub fn new(infos: CryptographicInformation, nonce: Option<String>) -> Self {
        let nonce: [u8; 24] = match nonce {
            Some(nonce) => hex::decode(nonce).expect("An error occoured while decoding hex!").try_into().unwrap(),
            None => generate_nonce(),
        };
        // println!("infos: {:?}", infos);
		CipherChaCha { infos, sharedsecret: Vec::new(), nonce: nonce }
	}

    /// Retrieves the encrypted or decrypted data stored within the `CryptographicInformation`.
    ///
    /// # Returns
    /// A result containing the data as a vector of bytes (`Vec<u8>`) or a `CryptError`.
	pub fn get_data(&self) -> Result<Vec<u8>, CryptError> {
		let data = &self.infos.content()?;
		let mut data = data.to_vec();

        Ok(data)
    }
    /// Sets the shared secret for the cryptographic operation.
    ///
    /// # Parameters
    /// - `sharedsecret`: A vector of bytes (`Vec<u8>`) representing the shared secret.
    ///
    /// # Returns
    /// A reference to the `CipherChaCha` instance to allow method chaining.
	pub fn set_shared_secret(&mut self, sharedsecret: Vec<u8>) -> &Self {
		self.sharedsecret = sharedsecret;
		self
	}

    /// Retrieves the shared secret.
    ///
    /// # Returns
    /// A result containing a slice of the shared secret (`&[u8]`) or a `CryptError`.    
    pub fn sharedsecret(&self) -> Result<&[u8], CryptError> {
        Ok(&self.sharedsecret)
    }

    /// Sets the nonce for cryptographic operations.
    ///
    /// # Parameters
    /// - `nonce`: A 24-byte array representing the nonce.
    ///
    /// # Returns
    /// A slice of the set nonce (`&[u8; 24]`).
    pub fn set_nonce(&mut self, nonce: [u8; 24]) -> &[u8; 24] {
        self.nonce = nonce;
        &self.nonce
    }

    /// Retrieves the nonce.
    ///
    /// # Returns
    /// A slice of the current nonce (`&[u8; 24]`).
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Performs encryption or decryption based on the process type defined in `CryptographicInformation`.
    ///
    /// # Returns
    /// A result containing a tuple of encrypted data (`Vec<u8>`) and the nonce vector (`Vec<u8>`) used, or a `CryptError`.
    /// This method reads the file if `ContentType` is File and performs cryptographic operations accordingly.
    fn cryptography(&mut self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let passphrase = self.infos.passphrase()?.to_vec();
        let file_contained = self.infos.contains_file()?;
    
        if file_contained && self.infos.metadata.content_type == ContentType::File {
            let content = fs::read(self.infos.location()?).unwrap();
            self.infos.set_data(&content)?;
        }
        
        let mut encrypted_data: Vec<u8> = Vec::new();
        let mut nonce_vec: Vec<u8> = Vec::new();
        
        let process_result = match self.infos.metadata.process()? {
            Process::Encryption => {
                let process_data_result = self.process_data()?;
                encrypted_data = process_data_result.0;
                nonce_vec = process_data_result.1;
                
                let mut hmac = Sign::new(encrypted_data, passphrase, Operation::Sign, SignType::Sha512);
                let data = hmac.hmac();

                if self.infos.safe()? {
                    let _ = self.infos.set_data(&data)?;
                    let _ = self.infos.safe_file()?;
                }
                Ok((data, nonce_vec))
            },
            Process::Decryption => {
                let mut verifier = Sign::new((&self.infos.content()?).to_vec(), passphrase, Operation::Verify, SignType::Sha512);
                let data = verifier.hmac();

                self.infos.set_data(&data)?;
                let process_data_result = self.process_data()?;
                encrypted_data = process_data_result.0;
                nonce_vec = process_data_result.1;
                if self.infos.safe()? {
                    let _ = self.infos.set_data(&encrypted_data)?;
                    let _ = self.infos.safe_file()?;
                }
                Ok((encrypted_data, nonce_vec))
            },
            _ => Err(|e| CryptError::IOError(e)),
        };
        let result = process_result.map_err(|_| CryptError::EncryptionFailed)?;
        Ok(result)
    }

    /// Helper function to perform the encryption or decryption process based on the current settings.
    ///
    /// # Returns
    /// A result containing a tuple of processed data (`Vec<u8>`) and nonce vector (`Vec<u8>`), or a `CryptError`.
    fn process_data(&self) -> Result<(Vec<u8>, Vec<u8>), CryptError> { 
        let data = &self.infos.content()?;
        let sharedsecret = self.sharedsecret()?;
        let nonce = self.nonce();
        let mut encrypted_data = data.to_vec();
        let mut cipher = XChaCha20::new(GenericArray::from_slice(sharedsecret), GenericArray::from_slice(nonce));
        cipher.apply_keystream(&mut encrypted_data);
        Ok((encrypted_data, nonce.to_vec()))
    }
}

impl CryptographicFunctions for CipherChaCha {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - `public_key`: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (`Vec<u8>`) and the key used, or a `CryptError`.
    /// Additionally, prints a message to stdout with the nonce for user reference.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let mut key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let (sharedsecret, ciphertext) = key.encap(&public_key)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (encrypted_data, nonce) = self.cryptography()?;
        println!("Please write down this nonce: {}", hex::encode(nonce));
        Ok((encrypted_data, ciphertext))
    }

    /// Decrypts the provided data using the secret key and ciphertext.
    ///
    /// # Parameters
    /// - `secret_key`: The secret key used for decryption.
    /// - `ciphertext`: The ciphertext to decrypt.
    ///
    /// # Returns
    /// A result containing the decrypted data (`Vec<u8>`), or a `CryptError`.
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>{
        let mut key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let sharedsecret = key.decap(&secret_key, &ciphertext)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (decrypted_data, nonce) = self.cryptography()?;
        Ok(decrypted_data)
    }
}