use kyber::KeyControler::*;
//use crypt_guard_proc::{*, log_actnonceity, write_log};
use crate::{
    *,
    cryptography::{*, hmac_sign::{Sign, SignType, Operation}},
    error::CryptError, 
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
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce
};
use aes::cipher::generic_array::GenericArray;

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
impl CipherChaCha_Poly {
    /// Constructs a new CipherChaCha instance with specified cryptographic information and an optional nonce.
    ///
    /// # Parameters
    /// - infos: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    /// - nonce: Optional hexadecimal string representation of the nonce. If not provided, a nonce will be generated.
    ///
    /// # Returns
    /// A new CipherChaCha instance.
    pub fn new(infos: CryptographicInformation, nonce: Option<String>) -> Self {
        let nonce: [u8; 24] = match nonce {
            Some(nonce) => {
                let mut array = [0u8; 24];
                let decoded = hex::decode(nonce).expect("An error occurred while decoding hex!");
                array.copy_from_slice(&decoded);
                array
            },
            None => generate_nonce(),
        };
        CipherChaCha_Poly { infos, sharedsecret: Vec::new(), nonce }
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
    /// A reference to the CipherChaCha instance to allow method chaining.
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

    /// Sets the nonce for cryptographic operations.
    ///
    /// # Parameters
    /// - nonce: A fixed-size array of bytes representing the nonce.
    ///
    /// # Returns
    /// A reference to the set nonce (&[u8; 24]).
    pub fn set_nonce(&mut self, nonce: [u8; 24]) -> &[u8; 24] {
        self.nonce = nonce;
        &self.nonce
    }

    /// Retrieves the nonce.
    ///
    /// # Returns
    /// A reference to the current nonce (&[u8; 24]).
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    fn encryption(&self) -> Result<(Vec<u8>, [u8; 24]), CryptError> {
        let plaintext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let key = GenericArray::from_slice(&self.sharedsecret);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XNonce::from_slice(&self.nonce);
        let mut hmac = Sign::new(plaintext.to_vec(), passphrase, Operation::Sign, SignType::Sha512);
        let data = hmac.hmac();
        let encrypted = cipher.encrypt(nonce, &*data).map_err(|e| CryptError::new(e.to_string().as_str()))?;
        let nonce = *self.nonce();
        Ok((encrypted, nonce))
    }

    fn decryption(&self) -> Result<(Vec<u8>, [u8; 24]), CryptError> {
        let ciphertext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();
        let key = GenericArray::from_slice(&self.sharedsecret);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XNonce::from_slice(&self.nonce);
        let decrypted = cipher.decrypt(nonce, &*ciphertext.to_vec()).map_err(|e| CryptError::new(e.to_string().as_str()))?;
        let mut hmac = Sign::new(decrypted.to_vec(), passphrase, Operation::Verify, SignType::Sha512);
        let data = hmac.hmac();
        let nonce = *self.nonce();
        Ok((data, nonce))
    }
}

impl CryptographicFunctions for CipherChaCha_Poly {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - public_key: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (Vec<u8>) and the key used, or a CryptError.
    /// Additionally, prints a message to stdout with the nonce for user reference.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let (sharedsecret, ciphertext) = key.encap(&public_key)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (encrypted_data, nonce) = self.encryption()?;
        println!("Please write down this nonce: {}", hex::encode(nonce));
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
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let sharedsecret = key.decap(&secret_key, &ciphertext)?;
        let _ = self.set_shared_secret(sharedsecret);
        let (decrypted_data, _nonce) = self.decryption()?;
        Ok(decrypted_data)
    }
}
