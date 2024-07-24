use super::*;

//use crypt_guard_proc::{*, log_activity, write_log};
use crate::{
    *,
    cryptography::{
        CryptographicInformation,
        CipherAES_CTR, 
    },
    error::{*}, 
    Core::{
        KyberKeyFunctions,
        KeyControlVariant,
    },
};
use std::{
    result::Result, 
    fs
};
use rand::{RngCore, rngs::OsRng};
use hex;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, generic_array::GenericArray};

/// Generates a 16-byte iv using OS-level randomness.
///
/// # Returns
/// A 24-byte array filled with secure random bytes.
pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

type Aes256Ctr64LE = ctr::Ctr64LE<aes::Aes256>;

/// The main struct for handling cryptographic operations with ChaCha20 algorithm.
/// It encapsulates the cryptographic information, shared secret, and iv required for encryption and decryption.
impl CipherAES_CTR {
    /// Constructs a new CipherAES_CTR instance with specified cryptographic information and an optional iv.
    ///
    /// # Parameters
    /// - infos: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    /// - iv: Optional hexadecimal string representation of the iv. If not provided, a iv will be generated.
    ///
    /// # Returns
    /// A new CipherAES_CTR instance.
    pub fn new(infos: CryptographicInformation, iv: Option<String>) -> Self {
        let iv: Vec<u8> = match iv {
            Some(iv) => hex::decode(iv).expect("An error occoured while decoding hex!"),
            None => generate_iv().to_vec(),
        };
        // println!("infos: {:?}", infos);
        CipherAES_CTR { infos, sharedsecret: Vec::new(), iv }
    }

    /// Retrieves the encrypted or decrypted data stored within the CryptographicInformation.
    ///
    /// # Returns
    /// A result containing the data as a vector of bytes (Vec<u8>) or a CryptError.
    pub fn get_data(&self) -> Result<Vec<u8>, CryptError> {
        let data = &self.infos.content()?;
        let data = data.to_vec();

        Ok(data)
    }
    /// Sets the shared secret for the cryptographic operation.
    ///
    /// # Parameters
    /// - sharedsecret: A vector of bytes (Vec<u8>) representing the shared secret.
    ///
    /// # Returns
    /// A reference to the CipherAES_CTR instance to allow method chaining.
    pub fn set_shared_secret(&mut self, sharedsecret: Vec<u8>) -> &Self {
        self.sharedsecret = sharedsecret;
        self
    }

    /// Retrieves the shared secret.
    ///
    /// # Returns
    /// A result containing a slice of the shared secret (&[u8]) or a CryptError.    
    pub fn sharedsecret(&self) -> Result<&[u8], CryptError> {
        Ok(&self.sharedsecret)
    }

    /// Sets the iv for cryptographic operations.
    ///
    /// # Parameters
    /// - iv: A vector of bytes representing the iv.
    ///
    /// # Returns
    /// A reference to the set iv (&Vec<u8>).
    pub fn set_iv(&mut self, iv: Vec<u8>) -> &Vec<u8> {
        self.iv = iv;
        &self.iv
    }

    /// Retrieves the iv.
    ///
    /// # Returns
    /// A reference to the current iv (&Vec<u8>).
    pub fn iv(&self) -> &Vec<u8> {
        &self.iv
    }

    fn encryption(&self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let plaintext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let key = GenericArray::from_slice(&self.sharedsecret);
        let iv = GenericArray::from_slice(&self.iv);
        let mut cipher = Aes256Ctr64LE::new(key, iv);

        let mut hmac = Sign::new(plaintext.to_vec(), passphrase, Operation::Sign, SignType::Sha512);
        let mut data = hmac.hmac();

        let mut buf = data;
        let _ = cipher.apply_keystream(&mut buf);

        //let encrypted = cipher.encrypt(iv, &*data).map_err(|e| CryptError::new(e.to_string().as_str()))?;
        let iv = self.iv();
        Ok((buf.to_owned(), iv.clone()))
    }

    fn decryption(&self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let mut ciphertext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let key = GenericArray::from_slice(&self.sharedsecret);
        let iv = GenericArray::from_slice(&self.iv);
        let mut cipher = Aes256Ctr64LE::new(key, iv);

        let mut buf = ciphertext.to_owned();
        let _ = cipher.apply_keystream(&mut buf);

        //println!("decrypted: {:?}", &decrypted);
        let mut hmac = Sign::new(buf.to_owned(), passphrase, Operation::Verify, SignType::Sha512);
        let data = hmac.hmac();

        //println!("Verified: {:?}", &data);
        let iv = self.iv();
        Ok((data, iv.clone()))
    }
}

impl CryptographicFunctions for CipherAES_CTR {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - public_key: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (Vec<u8>) and the key used, or a CryptError.
    /// Additionally, prints a message to stdout with the iv for user reference.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let (sharedsecret, ciphertext) = key.encap(&public_key)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (encrypted_data, iv) = self.encryption()?;
        println!("Please write down this iv: {}", hex::encode(iv));
        Ok((encrypted_data, ciphertext))
    }

    /// Decrypts the provided data using the secret key and ciphertext.
    ///
    /// # Parameters
    /// - secret_key: The secret key used for decryption.
    /// - ciphertext: The ciphertext to decrypt.
    ///
    /// # Returns
    /// A result containing the decrypted data (Vec<u8>), or a CryptError.
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>{
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let sharedsecret = key.decap(&secret_key, &ciphertext)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (decrypted_data, _iv) = self.decryption()?;
        Ok(decrypted_data)
    }
}