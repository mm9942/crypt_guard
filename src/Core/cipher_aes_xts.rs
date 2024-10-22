use super::*;

//use crypt_guard_proc::{*, log_activity, write_log};
use crate::{
    *,
    cryptography::{
        CryptographicInformation,
        CipherChaCha, 
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
use aes::{Aes256, cipher::KeyInit, cipher::generic_array::GenericArray};
use xts_mode::{Xts128, get_tweak_default};

/// The main struct for handling cryptographic operations with ChaCha20 algorithm.
/// It encapsulates the cryptographic information and shared secret required for encryption and decryption.
impl CipherAES_XTS {
    /// Constructs a new CipherChaCha instance with specified cryptographic information.
    ///
    /// # Parameters
    /// - infos: Cryptographic information including content, passphrase, metadata, and location for encryption or decryption.
    ///
    /// # Returns
    /// A new CipherChaCha instance.
    pub fn new(infos: CryptographicInformation) -> Self {
        // println!("infos: {:?}", infos);
        CipherAES_XTS { infos, sharedsecret: Vec::new() }
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

    fn encryption(&self) -> Result<Vec<u8>, CryptError> {
        let plaintext = self.infos.content()?;
        let passphrase = self.infos.passphrase()?.to_vec();

        let cipher_1 = Aes256::new(GenericArray::from_slice(&self.sharedsecret[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&self.sharedsecret[32..]));

        let cipher = Xts128::<Aes256>::new(cipher_1, cipher_2);

        let mut hmac = Sign::new(plaintext.to_vec(), passphrase, Operation::Sign, SignType::Sha512);
        let mut data = hmac.hmac();

        let sector_size = 0x200;
        let first_sector_index = 0;
        
        let _ = cipher.encrypt_area(&mut data, sector_size, first_sector_index, get_tweak_default)/*.map_err(|e| CryptError::new(e.to_string().as_str()))?*/;

        Ok(data)
    }

    fn decryption(&self) -> Result<Vec<u8>, CryptError> {
        let mut buffer = self.infos.content()?.to_owned();
        let passphrase = self.infos.passphrase()?.to_vec();
        
        let cipher_1 = Aes256::new(GenericArray::from_slice(&self.sharedsecret[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&self.sharedsecret[32..]));

        let cipher = Xts128::<Aes256>::new(cipher_1, cipher_2);
        
        let sector_size = 0x200;
        let first_sector_index = 0;
        
        cipher.decrypt_area(&mut buffer, sector_size, first_sector_index, get_tweak_default)/*.map_err(|e| CryptError::new(e.to_string().as_str()))?*/;

        //println!("decrypted: {:?}", &decrypted);
        let mut hmac = Sign::new(buffer.to_vec(), passphrase, Operation::Verify, SignType::Sha512);
        let data = hmac.hmac();
        //println!("Verified: {:?}", &data);
        Ok(data)
    }
}

impl CryptographicFunctions for CipherAES_XTS {
    /// Encrypts the provided data using the public key.
    ///
    /// # Parameters
    /// - public_key: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing a tuple of the encrypted data (Vec<u8>) and the key used, or a CryptError.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);

         // Generate the first shared secret and ciphertext
         let (sharedsecret1, ciphertext1) = key.encap(&public_key)?;
        
         // Generate the second shared secret and ciphertext
         let (sharedsecret2, ciphertext2) = key.encap(&public_key)?;
         
         // Concatenate both shared secrets and ciphertexts
         let sharedsecret = [sharedsecret1.clone(), sharedsecret2.clone()].concat();
         let ciphertext = [ciphertext1.clone(), ciphertext2.clone()].concat();
        
        let _ = self.set_shared_secret(sharedsecret);
        let encrypted_data = self.encryption()?;
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

        let ciphertext_len = ciphertext.len() / 2;
        let ciphertext1 = ciphertext[..ciphertext_len].to_vec();
        let ciphertext2 = ciphertext[ciphertext_len..].to_vec();

        let sharedsecret1 = key.decap(&secret_key, &ciphertext1)?;
        let sharedsecret2 = key.decap(&secret_key, &ciphertext2)?;

        let sharedsecret = [sharedsecret1.clone(), sharedsecret2.clone()].concat();

        let _ = self.set_shared_secret(sharedsecret);
        let decrypted_data = self.decryption()?;
        Ok(decrypted_data)
    }
}