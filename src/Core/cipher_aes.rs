//use super::*;
use crate::{
    *,
    error::CryptError,
    cryptography::{*, hmac_sign::{Sign, SignType, Operation}},
    Core::{
        KyberKeyFunctions,
        KeyControlVariant,
    }
};
use aes::{
    cipher::{
        BlockEncrypt, 
        BlockDecrypt, 
        generic_array::GenericArray,
        KeyInit
    },
    Aes256,
    Aes128,
};
use std::{
    path::{PathBuf}, 
    result::Result, 
    io::{Write}, 
    fs
};

use cbc::{cipher::{KeyIvInit, BlockDecryptMut, BlockEncryptMut}, Encryptor as CbcEncryptor, Decryptor as CbcDecryptor};

use block_padding::Pkcs7;
use rand::Rng;

type Aes128CbcEnc = CbcEncryptor<Aes128>;
type Aes128CbcDec = CbcDecryptor<Aes128>;

/// Provides AES encryption functionality, handling cryptographic information and shared secrets.
impl CipherAES {
    /// Initializes a new `CipherAES` instance with the provided cryptographic information.
    ///
    /// # Parameters
    /// - `infos`: Cryptographic information detailing the encryption or decryption process, content type, and more.
    ///
    /// # Returns
    /// A new instance of `CipherAES`.
	pub fn new(infos: CryptographicInformation) -> Self {
		CipherAES { infos, sharedsecret: Vec::new() }
	}
	
    /// Retrieves the current data intended for encryption or decryption.
    ///
    /// # Returns
    /// The data as a vector of bytes (`Vec<u8>`) or a `CryptError` if the content cannot be accessed.
    pub fn get_data(&self) -> Result<Vec<u8>, CryptError> {
		let data = &self.infos.content()?;
		let data = data.to_vec();
		Ok(data)
	}
	    
    /// Sets the shared secret key used for AES encryption and decryption.
    ///
    /// # Parameters
    /// - `sharedsecret`: The shared secret as a byte vector.
    ///
    /// # Returns
    /// A mutable reference to the `CipherAES` instance, allowing for chaining of operations.
    pub fn set_shared_secret(&mut self, sharedsecret: Vec<u8>) -> &Self {
		self.sharedsecret = sharedsecret;
		self
	}
	    
    /// Retrieves the shared secret key.
    ///
    /// # Returns
    /// A reference to the shared secret as a byte vector or a `CryptError` if it cannot be accessed.
    pub fn sharedsecret(&self) -> Result<&Vec<u8>, CryptError> {
        Ok(&self.sharedsecret)
    }
    
    /// Retrieves the shared secret key.
    ///
    /// # Returns
    /// A reference to the shared secret as a byte vector or a `CryptError` if it cannot be accessed.
    fn encryption(&mut self) -> Result<Vec<u8>, CryptError> {
	    let file_contained = self.infos.contains_file()?;
	    if file_contained && self.infos.metadata.content_type == ContentType::File {
	        self.infos.content = fs::read(self.infos.location()?).unwrap();
	    }
        let encrypted_data = self.encrypt_aes()?;
    	// println!("Encrypted Data: {:?}", encrypted_data);

        let passphrase = self.infos.passphrase()?.to_vec();
        let mut hmac = Sign::new(encrypted_data, passphrase, Operation::Sign, SignType::Sha512);
        let data = hmac.hmac();
        if self.infos.safe()? {
        	let _ = self.infos.set_data(&data)?;
        	let _ = self.infos.safe_file()?;
        }
        Ok(data)
	}

    /// Saves the ciphertext to a file specified within the cryptographic information's location.
    ///
    /// # Parameters
    /// - `encrypted_data`: The ciphertext to be saved.
    ///
    /// # Returns
    /// An `Ok(())` upon successful save or a `CryptError` if saving fails.
    fn save_ciphertext(&self, _encrypted_data: &[u8]) -> Result<(), CryptError> {
    	use std::{fs::File, io::Write};
        
        if let Some(file_metadata) = &self.infos.location {
            let file_path = file_metadata.parent()?;
            let filename = format!("{}/ciphertext.pem", file_path.as_os_str().to_str().unwrap());
            let file_path_with_enc = PathBuf::from(filename);
            
            let mut buffer = File::create(file_path_with_enc).map_err(|_| CryptError::WriteError)?;
        	buffer.write_all(self.sharedsecret()?).map_err(|_| CryptError::WriteError)?;
            
            Ok(())
        } else {
            Err(CryptError::PathError)
        }
    }

    /// Encrypts the provided data with AES-256.
    ///
    /// # Returns
    /// A result containing the encrypted data as a byte vector or a `CryptError` if encryption fails.
	fn encrypt_aes(&mut self) -> Result<Vec<u8>, CryptError> {
        let block_size = 16;
        let mut padded_data = self.get_data()?;

        // Padding the data if necessary
        let padding_needed = block_size - (padded_data.len() % block_size);
        padded_data.extend(vec![padding_needed as u8; padding_needed]);

        let mut encrypted_data = vec![0u8; padded_data.len()];
        let sharedsecret = self.sharedsecret()?;
        let cipher = Aes256::new(GenericArray::from_slice(sharedsecret));

        for (chunk, encrypted_chunk) in padded_data.chunks(block_size).zip(encrypted_data.chunks_mut(block_size)) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            encrypted_chunk.copy_from_slice(&block);
        }

        Ok(encrypted_data)
    }

    fn generate_cbc_iv(&mut self) -> Result<Vec<u8>, CryptError> {
        let mut iv = vec![0u8; 16];
        let mut rng = rand::thread_rng();
        rng.try_fill(&mut iv[..]);
        Ok(iv)
    }

    /// Encrypts the provided data using AES-256 in CBC mode.
    /// This function securely generates an IV for each encryption operation.
    pub fn aes_cbc_encrypt(&mut self) -> Result<Vec<u8>, CryptError> {
        let data = self.get_data()?;
        let key = GenericArray::from_slice(&self.sharedsecret);
        let mut iv = vec![0u8; 16];  // AES block size
        rand::thread_rng().fill(&mut iv[..]);
        let iv_arr = GenericArray::from_slice(&iv);

        let cipher = Aes128CbcEnc::new(key, iv_arr);
        let mut buffer = data.clone(); // Clone the data to a mutable buffer
        let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
            .map_err(|_| CryptError::EncryptionFailed)?;

        // Prepend IV to the ciphertext to use it during decryption
        let mut result = iv;
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypts data encrypted using AES-256 in CBC mode.
    /// Assumes the IV is prepended to the ciphertext.
    pub fn aes_cbc_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptError> {
        if ciphertext.len() < 16 {
            return Err(CryptError::InvalidDataLength);  // Ensure there's enough data for the IV
        }

        let (iv, encrypted_data) = ciphertext.split_at(16);
        let key = GenericArray::from_slice(&self.sharedsecret);
        let iv_arr = GenericArray::from_slice(iv);

        let mut cipher = Aes128CbcDec::new(key, iv_arr);
        let mut buffer = encrypted_data.to_vec();
        cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|_| CryptError::DecryptionFailed)?;

        Ok(buffer)
    }

    /// Decrypts data using AES-256.
    ///
    /// # Returns
    /// The decrypted data as a byte vector or a `CryptError` if decryption fails.
    fn decryption(&mut self) -> Result<Vec<u8>, CryptError> {
	    let file_contained = self.infos.contains_file()?;
	    if file_contained && self.infos.metadata.content_type == ContentType::File {
	        self.infos.content = fs::read(self.infos.location()?).unwrap();

	    }

	    let encrypted_data_with_hmac = self.infos.content()?.to_vec();
        let passphrase = self.infos.passphrase()?.to_vec();
        // println!("Data Length: {}", encrypted_data_with_hmac.len());

        let mut verifier = Sign::new(encrypted_data_with_hmac, passphrase, Operation::Verify, SignType::Sha512);
        let verified_data = verifier.hmac();

        self.infos.set_data(&verified_data)?;
        // println!("{:?}", verified_data);
        let data = self.decrypt_aes()?;
        if self.infos.safe()? {
        	let _ = self.infos.set_data(&data)?;
        	let _ = self.infos.safe_file()?;
        }
        // println!("Decrypted Data: {:?}", data);
        Ok(data)
    }

    /// Decrypts the provided data with AES-256.
    ///
    /// # Returns
    /// A result containing the decrypted data as a byte vector or a `CryptError` if decryption fails.
    fn decrypt_aes(&mut self) -> Result<Vec<u8>, CryptError> {
        let data = &self.infos.content()?;
        let block_size = 16;

        // Ensure the data length is a multiple of the block size
        if data.len() % block_size != 0 {
            return Err(CryptError::InvalidDataLength);
        }

        let mut decrypted_data = vec![0u8; data.len()];
        let sharedsecret = self.sharedsecret()?;
        let cipher = Aes256::new(GenericArray::from_slice(sharedsecret));

        for (chunk, decrypted_chunk) in data.chunks(block_size).zip(decrypted_data.chunks_mut(block_size)) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            decrypted_chunk.copy_from_slice(&block);
        }

	    if let Some(&padding_length) = decrypted_data.last() {
	        decrypted_data.truncate(decrypted_data.len() - padding_length as usize);
	    }
    	
        Ok(decrypted_data)
    }
}


impl CryptographicFunctions for CipherAES {
    /// Performs the encryption process using a public key.
    ///
    /// # Parameters
    /// - `public_key`: The public key for encryption.
    ///
    /// # Returns
    /// A result containing the encrypted data and the ciphertext as a key, or a `CryptError`.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let (sharedsecret, ciphertext) = key.encap(&public_key)?;
        // println!("Shared secret: {:?}\nLength: {}", sharedsecret, sharedsecret.len());
        let _ = self.set_shared_secret(sharedsecret);

        Ok((self.encryption()?, ciphertext))
    }
    
    /// Performs the decryption process using a secret key and ciphertext.
    ///
    /// # Parameters
    /// - `secret_key`: The secret key for decryption.
    /// - `ciphertext`: The ciphertext to decrypt.
    ///
    /// # Returns
    /// The decrypted data as a byte vector or a `CryptError` if decryption fails.
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>{
        let key = KeyControlVariant::new(self.infos.metadata.key_type()?);
        let sharedsecret = key.decap(&secret_key, &ciphertext)?;
        // println!("shared secret: {:?}\nLength: {}", sharedsecret, sharedsecret.len());
        let _ = self.set_shared_secret(sharedsecret);

        Ok(self.decryption()?)
    }
}
