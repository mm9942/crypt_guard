use hmac::{Hmac, Mac};
use sha2::{Sha512, Sha256};
use pqcrypto_falcon::{falcon1024, falcon512};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use std::{
    path::{PathBuf, Path}, 
    collections::HashMap,
    marker::PhantomData, 
    result::Result, 
    io::{Read, Write}, 
    fs,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage, DetachedSignature};

pub enum KeyVariant {
    Public,
    Secret,
}

pub trait SignatureFunctions {
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Vec<u8>;
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Vec<u8>;
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8>;
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> bool;
}

pub trait KeyOperations {
    fn keypair() -> (Vec<u8>, Vec<u8>);
}

pub struct Falcon1024;
impl KeyOperations for Falcon1024 {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = falcon1024::keypair();
        (public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned())
    }
}
impl SignatureFunctions for Falcon1024 {
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = falcon1024::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon1024::sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = falcon1024::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon1024::detached_sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = falcon1024::PublicKey::from_bytes(&key).unwrap();
        let signed_message = falcon1024::SignedMessage::from_bytes(&signed_data).unwrap();
        falcon1024::open(&signed_message, &key).unwrap()
    }
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> bool {
        let key = falcon1024::PublicKey::from_bytes(&key).unwrap();
        let ds = falcon1024::DetachedSignature::from_bytes(&signature).unwrap();
        falcon1024::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .expect("REASON")
    }
}

pub struct Falcon512;
impl KeyOperations for Falcon512 {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = falcon512::keypair();
        (public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned())
    }
}
impl SignatureFunctions for Falcon512 {
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = falcon512::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon512::sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = falcon512::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon512::detached_sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = falcon512::PublicKey::from_bytes(&key).unwrap();
        let signed_message = falcon512::SignedMessage::from_bytes(&signed_data).unwrap();
        falcon512::open(&signed_message, &key).unwrap()
    }
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> bool {
        let key = falcon512::PublicKey::from_bytes(&key).unwrap();
        let ds = falcon512::DetachedSignature::from_bytes(&signature).unwrap();
        falcon512::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .expect("REASON")
    }
}


pub struct Dilithium2;
impl KeyOperations for Dilithium2 {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = dilithium2::keypair();
        (public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned())
    }
}
impl SignatureFunctions for Dilithium2 {
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium2::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium2::sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium2::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium2::detached_sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium2::PublicKey::from_bytes(&key).unwrap();
        let signed_message = dilithium2::SignedMessage::from_bytes(&signed_data).unwrap();
        dilithium2::open(&signed_message, &key).unwrap()
    }
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> bool {
        let key = dilithium2::PublicKey::from_bytes(&key).unwrap();
        let ds = dilithium2::DetachedSignature::from_bytes(&signature).unwrap();
        dilithium2::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .expect("REASON")
    }
}

pub struct Dilithium3;
impl KeyOperations for Dilithium3 {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = dilithium3::keypair();
        (public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned())
    }
}
impl SignatureFunctions for Dilithium3 {
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium3::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium3::sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium3::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium3::detached_sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium3::PublicKey::from_bytes(&key).unwrap();
        let signed_message = dilithium3::SignedMessage::from_bytes(&signed_data).unwrap();
        dilithium3::open(&signed_message, &key).unwrap()
    }
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> bool {
        let key = dilithium3::PublicKey::from_bytes(&key).unwrap();
        let ds = dilithium3::DetachedSignature::from_bytes(&signature).unwrap();
        dilithium3::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .expect("REASON")
    }
}

pub struct Dilithium5;
impl KeyOperations for Dilithium5 {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = dilithium5::keypair();
        (public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned())
    }
}
impl SignatureFunctions for Dilithium5 {
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium5::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium5::sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium5::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium5::detached_sign(&data, &key).as_bytes().to_owned();
        signature
    }
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        let key = dilithium5::PublicKey::from_bytes(&key).unwrap();
        let signed_message = dilithium5::SignedMessage::from_bytes(&signed_data).unwrap();
        dilithium5::open(&signed_message, &key).unwrap()
    }
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> bool {
        let key = dilithium5::PublicKey::from_bytes(&key).unwrap();
        let ds = dilithium5::DetachedSignature::from_bytes(&signature).unwrap();
        dilithium5::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .expect("REASON")
    }
}

pub struct Detached;
pub struct Message;


pub struct Signature<AlgorithmType=Falcon1024, SignatureType=Message> {
    algorithm: PhantomData<AlgorithmType>,
    signature_type: PhantomData<SignatureType>,
}

impl<AlgorithmType, SignatureType> Signature<AlgorithmType, SignatureType> {
    pub fn new() -> Self {
        Signature { algorithm: PhantomData, signature_type: PhantomData }
    }
}

// Implementation of Signature for Falcon1024
impl Signature<Falcon1024, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Falcon1024::sign_message(data, key)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Falcon1024::open_message(signed_data, key)
    }
}

impl Signature<Falcon1024, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Falcon1024::detached_signature(data, key)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> bool {
        Falcon1024::verify(signature, data, key)
    }
}

// Implementation of Signature for Falcon512
impl Signature<Falcon512, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Falcon512::sign_message(data, key)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Falcon512::open_message(signed_data, key)
    }
}

impl Signature<Falcon512, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Falcon512::detached_signature(data, key)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> bool {
        Falcon512::verify(signature, data, key)
    }
}

// Implementation of Signature for Dilithium2
impl Signature<Dilithium2, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium2::sign_message(data, key)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium2::open_message(signed_data, key)
    }
}

impl Signature<Dilithium2, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium2::detached_signature(data, key)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> bool {
        Dilithium2::verify(signature, data, key)
    }
}

// Implementation of Signature for Dilithium3
impl Signature<Dilithium3, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium3::sign_message(data, key)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium3::open_message(signed_data, key)
    }
}

impl Signature<Dilithium3, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium3::detached_signature(data, key)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> bool {
        Dilithium3::verify(signature, data, key)
    }
}

// Implementation of Signature for Dilithium5
impl Signature<Dilithium5, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium5::sign_message(data, key)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium5::open_message(signed_data, key)
    }
}

impl Signature<Dilithium5, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
        Dilithium5::detached_signature(data, key)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> bool {
        Dilithium5::verify(signature, data, key)
    }
}