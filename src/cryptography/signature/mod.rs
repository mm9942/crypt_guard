mod sign;
pub mod sign_falcon;
pub mod sign_dilithium;
pub use sign::*;
use hmac::{Hmac, Mac};
use sha2::{Sha512, Sha256};
use crate::{cryptography::*, error::*};
use crate::error::SigningErr;

/// Defines the operation being performed, either verification or signing.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Operation {
    Verify,
    Sign,
}

/// Defines the types of signatures supported by the system.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum SignType {
    Sha512,
    Sha256,
    Falcon,
    Dilithium
}

/// Represents a signing operation including the data and metadata for the operation.
#[derive(PartialEq, Debug, Clone)]
pub struct Sign {
    pub data: SignatureData,
    pub status: Operation,
    pub hash_type: SignType,
    pub length: usize,
    pub veryfied: bool
}

/// Contains the data to be signed or verified, alongside necessary metadata like passphrase.
#[derive(PartialEq, Debug, Clone)]
pub struct SignatureData {
    pub data: Vec<u8>,
    pub passphrase: Vec<u8>,
    pub hmac: Vec<u8>,
    pub concat_data: Vec<u8>,
}

/// Defines the type of data associated with a signature.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum SignatureDataType {
    None,
    SignedMessage,
    DetachedSignature,
    PublicKey,
    SecretKey,
}

/// Defines whether a signature is attached to the message or detached.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum SignatureType {
    UnSigned,
    SignedMessage,
    DetachedSignature,
}

/// Represents a key used in the signature process, identifying its type and content.
#[derive(PartialEq, Debug, Clone)]
pub struct SignatureKey {
    pub data: Vec<u8>,
    pub key_type: SignatureDataType,
}

/// Represents the mechanism used for signing, along with the signature and public key used.
#[derive(PartialEq, Debug, Clone)]
pub struct SignatureMechanism {
    pub signature: Vec<u8>,
    pub public_key: SignatureKey,
    pub signature_type: SignatureType,
}

impl SignatureMechanism {
    /// Constructs a new `SignatureMechanism` with a public key.
    pub fn new(public_key: Vec<u8>) -> Self {
        let mut public = SignatureKey::new();
        let _ = public.set_public_key(public_key).unwrap();
        let signature_type = SignatureType::UnSigned;
        SignatureMechanism { signature: Vec::new(), public_key: public, signature_type }
    }

    /// Sets the signature for the mechanism. but doesn't define the type of signature.
    pub fn set_signature(&mut self, signature: Vec<u8>) -> Result<&[u8], SigningErr> {
        self.signature = signature;
        Ok(&self.signature)
    }

    /// Retrieves the signature.
    pub fn signature(&self) -> Result<&[u8], SigningErr> {
        Ok(&self.signature)
    }

    /// Defines the signed message signature.
    pub fn set_signed_msg(&mut self, signature: Vec<u8>) -> Result<(), SigningErr> {
        self.signature = signature;
        self.signature_type = SignatureType::SignedMessage;
        Ok(())
    }

    /// Defines the detached signature.
    pub fn set_detached_sign(&mut self, signature: Vec<u8>) -> Result<(), SigningErr> {
        self.signature = signature;
        self.signature_type = SignatureType::DetachedSignature;
        Ok(())
    }

    /// Checks if the message is a signed message (true) or a detached signature (false).
    pub fn is_signed_msg(&self) -> Result<bool, SigningErr> {
        match self.signature_type {
            SignatureType::SignedMessage => Ok(true),
            SignatureType::DetachedSignature => Ok(false),
            _ => Err(SigningErr::SignatureVerificationFailed),
        }
    }
}

/// Trait for setting cryptographic mechanisms.
pub trait MechanismSetter {
    fn set_public_key(&mut self, public_key: Vec<u8>) -> Result<(), SigningErr>;
    fn set_secret_key(&mut self, secret_key: Vec<u8>) -> Result<(), SigningErr>;
    fn set_signed_msg(&mut self, signed_message: Vec<u8>) -> Result<(), SigningErr>;
    fn set_signature(&mut self, detached_signature: Vec<u8>) -> Result<(), SigningErr>;
}

/// Defines functionality for cryptographic mechanisms.
pub trait Mechanism {
    fn keypair() -> Self;

    fn save_signed_msg(&self, path: PathBuf) -> Result<(), SigningErr>;
    fn save_detached(&self, path: PathBuf) -> Result<(), SigningErr>;
    
    fn sign_msg(&mut self) -> Result<Vec<u8>, SigningErr>;
    fn sign_detached(&mut self) -> Result<Vec<u8>, SigningErr>;

    fn verify_msg(&mut self) -> Result<Vec<u8>, SigningErr>;
    fn verify_detached(&mut self) -> Result<bool, SigningErr>;
}

impl MechanismSetter for SignatureKey {
    /// Sets the public key for the signature.
    fn set_public_key(&mut self, public_key: Vec<u8>) -> Result<(), SigningErr> {
        self.data = public_key;
        self.key_type = SignatureDataType::PublicKey;
        Ok(())
    }
    /// Sets the secret key for the signature.
    fn set_secret_key(&mut self, secret_key: Vec<u8>) -> Result<(), SigningErr> {
        self.data = secret_key;
        self.key_type = SignatureDataType::SecretKey;
        Ok(())
    }
    /// Sets the signed message.
    fn set_signed_msg(&mut self, signed_message: Vec<u8>) -> Result<(), SigningErr> {
        self.data = signed_message;
        self.key_type = SignatureDataType::SignedMessage;
        Ok(())
    }
    /// Sets the detached signature.
    fn set_signature(&mut self, detached_signature: Vec<u8>) -> Result<(), SigningErr> {
        self.data  = detached_signature;
        self.key_type = SignatureDataType::DetachedSignature;
        Ok(())
    }
}
impl SignatureKey {
    /// Constructs a new `SignatureKey`.
    fn new() -> Self {
        Self {
            data: Vec::new(), key_type: SignatureDataType::None
        }
    }
    /// Sets and gets the public key.
    fn public_key(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::PublicKey;
        Ok(&self.data)
    }
    /// Sets and gets the secret key.
    fn secret_key(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::SecretKey;
        Ok(&self.data)
    }
    /// Sets and gets the signed message.
    fn signed_msg(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::SignedMessage;
        Ok(&self.data)
    }
    /// Sets and gets the detached signature.
    fn signature(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::DetachedSignature;
        Ok(&self.data)
    }
}