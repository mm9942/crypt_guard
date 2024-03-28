mod sign;
pub mod sign_falcon;
pub mod sign_dilithium;
pub use sign::*;
use hmac::{Hmac, Mac};
use sha2::{Sha512, Sha256};
use crate::{cryptography::*, error::*};
use crate::error::SigningErr;

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Operation {
    Verify,
    Sign,
}
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum SignType {
    Sha512,
    Sha256,
    Falcon,
    Dilithium
}

#[derive(PartialEq, Debug, Clone)]
pub struct Sign {
    pub data: SignatureData,
    pub status: Operation,
    pub hash_type: SignType,
    pub length: usize,
    pub veryfied: bool
}

#[derive(PartialEq, Debug, Clone)]
pub struct SignatureData {
    pub data: Vec<u8>,
    pub passphrase: Vec<u8>,
    pub hmac: Vec<u8>,
    pub concat_data: Vec<u8>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum SignatureDataType {
    None,
    SignedMessage,
    DetachedSignature,
    PublicKey,
    SecretKey,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum SignatureType {
    UnSigned,
    SignedMessage,
    DetachedSignature,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SignatureKey {
    pub data: Vec<u8>,
    pub key_type: SignatureDataType,
}

#[derive(PartialEq, Debug, Clone)]
pub struct SignatureMechanism {
    pub signature: Vec<u8>,
    pub public_key: SignatureKey,
    pub signature_type: SignatureType,
}

impl SignatureMechanism {
    pub fn new(public_key: Vec<u8>) -> Self {
        let mut public = SignatureKey::new();
        let _ = public.set_public_key(public_key).unwrap();
        let signature_type = SignatureType::UnSigned;
        SignatureMechanism { signature: Vec::new(), public_key: public, signature_type }
    }
    pub fn set_signature(&mut self, signature: Vec<u8>) -> Result<&[u8], SigningErr> {
        self.signature = signature;
        Ok(&self.signature)
    }
    pub fn signature(&self) -> Result<&[u8], SigningErr> {
        Ok(&self.signature)
    }
    pub fn set_signed_msg(&mut self, signature: Vec<u8>) -> Result<(), SigningErr> {
        self.signature = signature;
        self.signature_type = SignatureType::SignedMessage;
        Ok(())
    }
    pub fn set_detached_sign(&mut self, signature: Vec<u8>) -> Result<(), SigningErr> {
        self.signature = signature;
        self.signature_type = SignatureType::DetachedSignature;
        Ok(())
    }
    pub fn is_signed_msg(&self) -> Result<bool, SigningErr> {
        match self.signature_type {
            SignatureType::SignedMessage => Ok(true),
            SignatureType::DetachedSignature => Ok(false),
            _ => Err(SigningErr::SignatureVerificationFailed),
        }
    }
}

pub trait MechanismSetter {
    fn set_public_key(&mut self, public_key: Vec<u8>) -> Result<(), SigningErr>;
    fn set_secret_key(&mut self, secret_key: Vec<u8>) -> Result<(), SigningErr>;
    fn set_signed_msg(&mut self, signed_message: Vec<u8>) -> Result<(), SigningErr>;
    fn set_signature(&mut self, detached_signature: Vec<u8>) -> Result<(), SigningErr>;
}

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
    fn set_public_key(&mut self, public_key: Vec<u8>) -> Result<(), SigningErr> {
        self.data = public_key;
        self.key_type = SignatureDataType::PublicKey;
        Ok(())
    }
    fn set_secret_key(&mut self, secret_key: Vec<u8>) -> Result<(), SigningErr> {
        self.data = secret_key;
        self.key_type = SignatureDataType::SecretKey;
        Ok(())
    }
    fn set_signed_msg(&mut self, signed_message: Vec<u8>) -> Result<(), SigningErr> {
        self.data = signed_message;
        self.key_type = SignatureDataType::SignedMessage;
        Ok(())
    }
    fn set_signature(&mut self, detached_signature: Vec<u8>) -> Result<(), SigningErr> {
        self.data  = detached_signature;
        self.key_type = SignatureDataType::DetachedSignature;
        Ok(())
    }
}
impl SignatureKey {
    fn new() -> Self {
        Self {
            data: Vec::new(), key_type: SignatureDataType::None
        }
    }
    fn public_key(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::PublicKey;
        Ok(&self.data)
    }
    fn secret_key(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::SecretKey;
        Ok(&self.data)
    }
    fn signed_msg(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::SignedMessage;
        Ok(&self.data)
    }
    fn signature(&mut self) -> Result<&[u8], SigningErr> {
        self.key_type = SignatureDataType::DetachedSignature;
        Ok(&self.data)
    }
}