//! # Dilithium Signature Module
//!
//! This module provides functionality for generating and verifying
//! Dilithium signatures. It includes support for key generation, signing
//! messages, and verifying signatures. This module is built upon the
//! `pqcrypto_dilithium` crate for post-quantum cryptographic operations.

use crate::signature::*;
use pqcrypto_dilithium::dilithium5::{*, keypair}; // Adjusted for Dilithium specific functionality
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage, DetachedSignature};
use std::{
    fs::File, 
    io::Write,
};

/// Represents a Dilithium signature mechanism including the data,
/// signature, and secret key components necessary for signing and
/// verification processes.
#[derive(PartialEq, Debug, Clone)]
pub struct dilithium {
    /// The data to be signed or verified.
    pub data: Vec<u8>,
    /// The mechanism used for the signature process.
    pub signature: SignatureMechanism,
    /// The secret key used for signing the data.
    pub secret_key: SignatureKey,
}

impl dilithium {
    /// Constructs a new Dilithium signature element with specified data, public key, and secret key.
    ///
    /// This constructor adapts to various needs such as signing and key generation. It is crucial to use the parameters according to the specific requirements of the operation being performed.
    ///
    /// # Parameters
    /// - `data`: Data intended for signing. This is optional and can be empty (`Vec::new()`) for key generation operations. For signing, it should be populated with the content to be signed.
    /// - `public_key`: The public key used in the verification process. It is necessary for verifying signatures and does not play a role in the signing process itself.
    /// - `secret_key`: The secret key used for signing data. This is essential for the creation of signatures and is not used in verification.
    ///
    /// # Usage
    /// - To generate a new key pair, leave `data` empty.
    /// - For signing operations, ensure `data` is populated with the content to be signed.
	pub fn new(data: Vec<u8>, public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        let mut secret = SignatureKey::new();
		let _ = secret.set_secret_key(secret_key);
		let signature = SignatureMechanism::new(public_key);
		dilithium { data, signature, secret_key: secret }
	}

	/// Sets the data to be signed.
    ///
    /// # Parameters
    /// - `data`: The data to be used.
    ///
    /// # Returns
    /// A result containing a reference to the data on success, or
    /// a `SigningErr` on failure.
	pub fn set_data(&mut self, data: Vec<u8>) -> Result<&[u8], SigningErr> {
		self.data = data;
		Ok(&self.data)
	}

	/// Sets the secret key for signing operations.
    ///
    /// # Parameters
    /// - `key`: The secret key in bytes.
    ///
    /// # Returns
    /// A result containing a reference to the `SignatureKey` on success,
    /// or a `SigningErr` on failure.
	pub fn set_secret_key(&mut self, key: Vec<u8>) -> Result<&SignatureKey, SigningErr> {
		self.secret_key.set_secret_key(key);
		Ok(&self.secret_key)
	}

	/// Sets the secret key for verification operations.
    ///
    /// # Parameters
    /// - `key`: The secret key in bytes.
    ///
    /// # Returns
    /// A result containing a reference to the `SignatureKey` on success,
    /// or a `SigningErr` on failure.
	pub fn set_public_key(&mut self, key: Vec<u8>) -> Result<&SignatureKey, SigningErr> {
		self.signature.public_key.set_public_key(key);
		Ok(&self.signature.public_key)
	}

	/// Sets the signed message for verification operations.
    ///
    /// # Parameters
    /// - `signature`: The secret key in bytes.
    ///
    /// # Returns
    /// A result containing a reference to the `signature` as byte slice on success,
    /// or a `SigningErr` on failure.
	pub fn set_signed_msg(&mut self, signature: Vec<u8>) -> Result<&[u8], SigningErr> {
		let _ = self.signature.set_signed_msg(signature)?;
		Ok(self.signature.signature()?)
	}

	/// Sets the detached signature for verification operations.
    ///
    /// # Parameters
    /// - `signature`: The secret key in bytes.
    ///
    /// # Returns
    /// A result containing a reference to the `signature` as byte slice on success,
    /// or a `SigningErr` on failure.
	pub fn set_detached(&mut self, signature: Vec<u8>) -> Result<&[u8], SigningErr> {
		let _ = self.signature.set_detached_sign(signature)?;
		Ok(self.signature.signature()?)
	}
}

impl Mechanism for dilithium {
    /// Generates a new keypair for Dilithium signature operations.
    ///
    /// # Returns
    /// A new `dilithium` instance with generated public and secret keys.
	fn keypair() -> Self {
		let (pk, sk) = keypair();
		let mut secret = SignatureKey::new();
		let _ = secret.set_secret_key(sk.as_bytes().to_vec());
		let signature = SignatureMechanism::new(pk.as_bytes().to_vec());
		dilithium { data: Vec::new(), signature, secret_key: secret }
	}
    
    // Signs a message using the Dilithium signature scheme.
    ///
    /// # Returns
    /// A result containing the signed message on success, or
    /// a `SigningErr` on failure.
    fn sign_msg(&mut self) -> Result<Vec<u8>, SigningErr> {
        let sk = dilithium5::SecretKey::from_bytes(&self.secret_key.secret_key().unwrap())?;
        let signed_message = dilithium5::sign(&self.data, &sk);
        Ok(signed_message.as_bytes().to_vec())
    }

	/// Creates a detached signature for the data using the Dilithium signature scheme.
    ///
    /// # Returns
    /// A result containing the detached signature as a `Vec<u8>` on success,
    /// or a `SigningErr` on failure.
    ///
    /// This function generates a signature that can be verified independently of the original message.
    fn sign_detached(&mut self) -> Result<Vec<u8>, SigningErr> {
        let sk = dilithium5::SecretKey::from_bytes(&self.secret_key.secret_key().unwrap())?;
        let signature = dilithium5::detached_sign(&self.data, &sk);
        Ok(signature.as_bytes().to_vec())
    }


    /// Saves a signed message to a specified file.
    ///
    /// # Parameters
    /// - `path`: The path where the signed message will be saved.
    ///
    /// # Returns
    /// A result indicating success or an error of type `SigningErr`.
    ///
    /// This function writes the signed message to a file, creating the file if it does not exist.
    /// Errors may occur due to missing signature data or file system issues.
    fn save_signed_msg(&self, path: PathBuf) -> Result<(), SigningErr> {
        let signed_message = self.signature.signature().map_err(|_| SigningErr::SignatureMissing)?;
        let mut file = File::create(path).map_err(|_| SigningErr::FileCreationFailed)?;
        file.write_all(signed_message).map_err(|_| SigningErr::FileWriteFailed)?;
        Ok(())
    }

	/// Saves a detached signature to a specified file.
    ///
    /// # Parameters
    /// - `path`: The path where the detached signature will be saved.
    ///
    /// # Returns
    /// A result indicating success or an error of type `SigningErr`.
    ///
    /// This function writes the detached signature to a file, creating the file if it does not exist.
    /// Errors may occur due to missing signature data or file system issues.
    fn save_detached(&self, path: PathBuf) -> Result<(), SigningErr> {
        let signature = self.signature.signature().map_err(|_| SigningErr::SignatureMissing)?;
        let mut file = File::create(path).map_err(|_| SigningErr::FileCreationFailed)?;
        file.write_all(signature).map_err(|_| SigningErr::FileWriteFailed)?;
        Ok(())
    }

    /// Verifies a signed message using the public key.
    ///
    /// # Returns
    /// A result containing the original message if the verification succeeds,
    /// or a `SigningErr` if verification fails.
    ///
    /// This function attempts to verify the authenticity and integrity of the signed message.
    /// A verification failure occurs if the message has been tampered with or the wrong public key is used.
    fn verify_msg(&mut self) -> Result<Vec<u8>, SigningErr> {
    	if self.signature.is_signed_msg()? {
	        let pk = dilithium5::PublicKey::from_bytes(&self.signature.public_key.public_key().unwrap())?;
	        let sm = dilithium5::SignedMessage::from_bytes(&self.signature.signature().unwrap())?;
	        let verified = pqcrypto_dilithium::dilithium5::open(&sm, &pk)
	            .map_err(|_| SigningErr::SignatureVerificationFailed)?;
	    	Ok(verified)
    	} else {
    		Err(SigningErr::SignatureVerificationFailed)
    	}
    }

	/// Verifies a detached signature against the original data using the public key.
    ///
    /// # Returns
    /// A result indicating whether the verification is successful (`true`) or not (`false`),
    /// or a `SigningErr` on failure.
    ///
    /// This function verifies the signature separately from the original message.
    /// Useful for cases where the message is available but its integrity needs to be verified without modifying it.
    fn verify_detached(&mut self) -> Result<bool, SigningErr> {
    	if !self.signature.is_signed_msg()? {
	        let pk = dilithium5::PublicKey::from_bytes(&self.signature.public_key.public_key().unwrap())
	            .map_err(|_| SigningErr::PublicKeyMissing)?;
	        let ds = dilithium5::DetachedSignature::from_bytes(&self.signature.signature().unwrap())?;
	        dilithium5::verify_detached_signature(&ds, &self.data, &pk)
		        .map(|_| true)
		        .map_err(|_| SigningErr::SignatureVerificationFailed)
        } else {
    		Err(SigningErr::SignatureVerificationFailed)
    	}
    }
}