use crate::signature::*;
use crate::error::SigningErr;

use hmac::{Hmac, Mac};
use sha2::{Sha512, Sha256};
use crate::{cryptography::*, error::*};

/// Represents a cryptographic signing operation, including data, passphrase, operational status,
/// hash type, signature length, and verification status.
impl Sign {
    /// Constructs a new `Sign` instance with specified data, passphrase, operation status, and hash type.
    ///
    /// # Parameters
    /// - `data`: The data to be signed or verified.
    /// - `passphrase`: The passphrase used for HMAC generation.
    /// - `status`: The operation status (signing or verifying).
    /// - `hash_type`: The hash algorithm to use for signing.
    ///
    /// # Returns
    /// A new `Sign` instance.
    pub fn new(data: Vec<u8>, passphrase: Vec<u8>, status: Operation, hash_type: SignType) -> Self {
        let data = SignatureData {
            data, passphrase, hmac: Vec::new(), concat_data: Vec::new()
        };
        match hash_type {
            SignType::Sha512 => Sign { data, status, hash_type, length: 64, veryfied: false},
            SignType::Sha256 => Sign { data, status, hash_type, length: 32, veryfied: false},
            SignType::Falcon => unimplemented!(),
            SignType::Dilithium => unimplemented!(),
         } 
    }

    /// Performs the HMAC operation based on the operation status: generates HMAC for signing
    /// or verifies HMAC for verification.
    ///
    /// # Returns
    /// HMAC as a `Vec<u8>` for signing or the verified data for verification.
    pub fn hmac(&mut self) -> Vec<u8> {
        match &self.status {
            Operation::Sign => {
                let data = self.generate_hmac();
                data
            },
            Operation::Verify => {
                let data = self.verify_hmac();
                data.unwrap()
            },
        }
    }

    /// Generates HMAC for the data using the specified hash type and passphrase.
    ///
    /// # Returns
    /// Concatenated original data and its HMAC as a `Vec<u8>`.
    pub fn generate_hmac(&self) -> Vec<u8> {
        let mut data = &self.data.data;
        match &self.hash_type {
            SignType::Sha512 => {
                let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.data.passphrase)
                    .expect("HMAC can take key of any size");
                mac.update(&data);
                let hmac = mac.finalize().into_bytes().to_vec();
                //println!("HMAC: {:?}", hmac);
                let concat_data = [&self.data.data, hmac.as_slice()].concat();
                //println!("Concated data: {:?}", concat_data);
                concat_data
            },
            SignType::Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.data.passphrase)
                    .expect("HMAC can take key of any size");
                mac.update(&data);
                let hmac = mac.finalize().into_bytes().to_vec();
                println!("HMAC: {:?}", hmac);
                let concat_data = [&self.data.data, hmac.as_slice()].concat();
                println!("Concated data: {:?}", concat_data);
                concat_data
            },
            SignType::Falcon => unimplemented!(),
            SignType::Dilithium => unimplemented!(),
        }
    }

    /// Verifies HMAC using SHA-512.
    ///
    /// # Parameters
    /// - `data`: The data part of the message.
    /// - `hmac`: The HMAC to verify against.
    /// - `passphrase`: The passphrase used for HMAC generation.
    ///
    /// # Returns
    /// `true` if verification is successful, `false` otherwise.
    fn verify_hmac_sha512(data: &[u8], hmac: &[u8], passphrase: &[u8]) -> bool {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(passphrase)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.verify_slice(hmac).is_ok()
    }

    /// Verifies HMAC using SHA-256.
    ///
    /// # Parameters
    /// - `data`: The data part of the message.
    /// - `hmac`: The HMAC to verify against.
    /// - `passphrase`: The passphrase used for HMAC generation.
    ///
    /// # Returns
    /// `true` if verification is successful, `false` otherwise.
    fn verify_hmac_sha256(data: &[u8], hmac: &[u8], passphrase: &[u8]) -> bool {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(passphrase)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.verify_slice(hmac).is_ok()
    }

    /// Verifies HMAC based on the hash type. Splits the provided data into the original data
    /// and HMAC, then verifies the HMAC.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the original data if verification is successful, `Err(&'static str)` otherwise.
    pub fn verify_hmac(&self) -> Result<Vec<u8>, &'static str> {
        if self.data.data.len() < self.length {
            return Err("Data is too short for HMAC verification");
        }

        let (data, hmac) = self.data.data.split_at(self.data.data.len() - self.length);

        let verification_success = match &self.hash_type {
            SignType::Sha512 => Self::verify_hmac_sha512(data, hmac, &self.data.passphrase),
            SignType::Sha256 => Self::verify_hmac_sha256(data, hmac, &self.data.passphrase),
            _ => return Err("Unsupported HMAC hash type"),
        };

        if verification_success {
            println!("splittet data: {:?}", data);
            Ok(data.to_owned())
        } else {
            Err("HMAC verification failed")
        }
    }
}