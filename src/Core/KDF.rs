use hmac::{Mac};

use pqcrypto_falcon::{falcon1024, falcon512};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use std::{
    path::{PathBuf},
    marker::PhantomData, 
    result::Result,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage, DetachedSignature};
use crate::{
    FileMetadata,
    FileTypes,
    FileState,
    error::SigningErr,
    //log_activity,
    LOGGER,
};
use crate::{log_activity};

/// Represents the type of key used in cryptographic operations.
pub enum KeyVariant {
    Public,
    Secret,
}

/// Defines the necessary functions for signing and verifying messages.
pub trait SignatureFunctions {
    /// Signs a given message with the provided key.
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr>;
    /// Creates a detached signature for the given data.
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr>;
    
    /// Opens (or verifies) a signed message with the provided key.
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr>;
    /// Verifies a signature against the provided data and key.
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr>;
}


/// Defines operations for key pair generation.
pub trait KeyOperations {
    /// Generates a public and secret key pair.
    fn keypair() -> Result<(Vec<u8>, Vec<u8>), SigningErr>;
    fn save_public(public_key: &[u8]) -> Result<(), SigningErr>;
    fn save_secret(secret_key: &[u8]) -> Result<(), SigningErr>;
    fn load(path: &PathBuf) -> Result<Vec<u8>, SigningErr>;
}

/// Implements Falcon1024 algorithm operations.
pub struct Falcon1024;
impl KeyOperations for Falcon1024 {
    /// Generates a Falcon1024 key pair.
    fn keypair() -> Result<(Vec<u8>, Vec<u8>), SigningErr> {
        let (public_key, secret_key) = falcon1024::keypair();
        Ok((public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned()))
    }
    fn save_public(public_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Falcon1024/key.pub"), FileTypes::public_key(), FileState::not_encrypted());
        let _ = file.save(public_key);
        Ok(())
    }
    fn save_secret(secret_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Falcon1024/key.sec"), FileTypes::secret_key(), FileState::not_encrypted());
        let _ = file.save(secret_key);
        Ok(())
    }
    fn load(path: &PathBuf) -> Result<Vec<u8>, SigningErr> {
        let file = match path.extension().and_then(|s| s.to_str()) {
            Some("pub") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::public_key(), FileState::not_encrypted()),
            Some("sec") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::secret_key(), FileState::not_encrypted()),
            _ => FileMetadata::new(),
        };
        let key = file.load().map_err(|_e| SigningErr::UnsupportedFileType(path.extension().unwrap().to_str().unwrap().to_string()))?;
        Ok(key)
    }
}
impl SignatureFunctions for Falcon1024 {
    /// Signs a given message with the provided key.
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Falcon1024");
        let key = falcon1024::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon1024::sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Falcon1024");
        Ok(signature)
    }
    /// Creates a detached signature for the given data.
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Generating a detached signature from the specified data.", "\nUsed key: Falcon1024");
        let key = falcon1024::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon1024::detached_sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Falcon1024");
        Ok(signature)
    }
    /// Opens (or verifies) a signed message with the provided key.
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Falcon1024");
        let key = falcon1024::PublicKey::from_bytes(&key).unwrap();
        let signed_message = falcon1024::SignedMessage::from_bytes(&signed_data).unwrap();
        log_activity!("Completed signing the message.", "\nUsed key: Falcon1024");
        Ok(falcon1024::open(&signed_message, &key).unwrap())
    }
    /// Verifies a signature against the provided data and key.
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        log_activity!("Starting verification of signed message.", "\nUsed key: Falcon1024");
        let key = falcon1024::PublicKey::from_bytes(&key).unwrap();
        let ds = falcon1024::DetachedSignature::from_bytes(&signature).unwrap();
        
        let data = falcon1024::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .map_err(|_| SigningErr::SignatureVerificationFailed)?;
        match &data {
            true => log_activity!("Verification completed.", "\nUsed key: Falcon1024"),
            false => log_activity!("Verification failed! Please use for more infos: RUST_BACKTRACE=[1 or full]", "\nUsed key: Falcon1024"),
        };
        Ok(
            data
        )
    }
}

pub struct Falcon512;
impl KeyOperations for Falcon512 {
    /// Generates a Falcon512 key pair.
    fn keypair() -> Result<(Vec<u8>, Vec<u8>), SigningErr> {
        let (public_key, secret_key) = falcon512::keypair();
        Ok((public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned()))
    }
    fn save_public(public_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Falcon512/key.pub"), FileTypes::public_key(), FileState::not_encrypted());
        let _ = file.save(public_key);
        Ok(())
    }
    fn save_secret(secret_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Falcon512/key.sec"), FileTypes::secret_key(), FileState::not_encrypted());
        let _ = file.save(secret_key);
        Ok(())
    }
    fn load(path: &PathBuf) -> Result<Vec<u8>, SigningErr> {
        let file = match path.extension().and_then(|s| s.to_str()) {
            Some("pub") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::public_key(), FileState::not_encrypted()),
            Some("sec") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::secret_key(), FileState::not_encrypted()),
            _ => FileMetadata::new(),
        };
        let key = file.load().map_err(|_e| SigningErr::UnsupportedFileType(path.extension().unwrap().to_str().unwrap().to_string()))?;
        Ok(key)
    }
}
impl SignatureFunctions for Falcon512 {
    /// Signs a given message with the provided key.
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Falcon512");
        let key = falcon512::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon512::sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Falcon512");
        Ok(signature)
    }
    /// Creates a detached signature for the given data.
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Generating a detached signature from the specified data.", "\nUsed key: Falcon512");
        let key = falcon512::SecretKey::from_bytes(&key).unwrap();
        let signature = falcon512::detached_sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Falcon512");
        Ok(signature)
    }
    /// Opens (or verifies) a signed message with the provided key.
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nSelected KDF: Falcon512");
        let key = falcon512::PublicKey::from_bytes(&key).unwrap();
        let signed_message = falcon512::SignedMessage::from_bytes(&signed_data).unwrap();
        log_activity!("Completed signing the message.", "\nSelected KDF: Falcon512");
        Ok(falcon512::open(&signed_message, &key).unwrap())
    }
    /// Verifies a signature against the provided data and key.
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        log_activity!("Starting verification of signed message.", "\nSelected KDF: Falcon512");
        let key = falcon512::PublicKey::from_bytes(&key).unwrap();
        let ds = falcon512::DetachedSignature::from_bytes(&signature).unwrap();
        
        let data = falcon512::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .map_err(|_| SigningErr::SignatureVerificationFailed)?;
        match &data {
            true => log_activity!("Verification completed.", "\nSelected KDF: Falcon512"),
            false => log_activity!("Verification failed! Please use for more infos: RUST_BACKTRACE=[1 or full]", "\nSelected KDF: Falcon512"),
        };
        Ok(
            data
        )
    }
}


pub struct Dilithium2;
impl KeyOperations for Dilithium2 {
    /// Generates a Dilithium2 key pair.
    fn keypair() -> Result<(Vec<u8>, Vec<u8>), SigningErr> {
        let (public_key, secret_key) = dilithium2::keypair();
        Ok((public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned()))
    }

    fn save_public(public_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Dilithium2/key.pub"), FileTypes::public_key(), FileState::not_encrypted());
        let _ = file.save(public_key);
        Ok(())
    }
    fn save_secret(secret_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Dilithium2/key.sec"), FileTypes::secret_key(), FileState::not_encrypted());
        let _ = file.save(secret_key);
        Ok(())
    }
    fn load(path: &PathBuf) -> Result<Vec<u8>, SigningErr> {
        let file = match path.extension().and_then(|s| s.to_str()) {
            Some("pub") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::public_key(), FileState::not_encrypted()),
            Some("sec") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::secret_key(), FileState::not_encrypted()),
            _ => FileMetadata::new(),
        };
        let key = file.load().map_err(|_e| SigningErr::UnsupportedFileType(path.extension().unwrap().to_str().unwrap().to_string()))?;
        Ok(key)
    }
}
impl SignatureFunctions for Dilithium2 {
    /// Signs a given message with the provided key.
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nSelected KDF: Dilithium2");
        let key = dilithium2::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium2::sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nSelected KDF: Dilithium2");
        Ok(signature)
    }
    /// Creates a detached signature for the given data.
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nSelected KDF: Dilithium2");
        let key = dilithium2::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium2::detached_sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nSelected KDF: Dilithium2");
        Ok(signature)
    }
    /// Opens (or verifies) a signed message with the provided key.
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nSelected KDF: Dilithium2");
        let key = dilithium2::PublicKey::from_bytes(&key).unwrap();
        let signed_message = dilithium2::SignedMessage::from_bytes(&signed_data).unwrap();
        log_activity!("Completed signing the message.", "\nSelected KDF: Dilithium2");
        Ok(dilithium2::open(&signed_message, &key).unwrap())
    }
    /// Verifies a signature against the provided data and key.
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        log_activity!("Starting verification of signed message.", "\nSelected KDF: Dilithium2");
        let key = dilithium2::PublicKey::from_bytes(&key).unwrap();
        let ds = dilithium2::DetachedSignature::from_bytes(&signature).unwrap();
        
        let data = dilithium2::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .map_err(|_| SigningErr::SignatureVerificationFailed)?;
        match &data {
            true => log_activity!("Verification completed.", "\nSelected KDF: Dilithiu2"),
            false => log_activity!("Verification failed! Please use for more infos: RUST_BACKTRACE=[1 or full]", "\nSelected KDF: Dilithium2"),
        };
        Ok(
            data
        )
    }
}

pub struct Dilithium3;
impl KeyOperations for Dilithium3 {
    /// Generates a Dilithium3 key pair.
    fn keypair() -> Result<(Vec<u8>, Vec<u8>), SigningErr> {
        let (public_key, secret_key) = dilithium3::keypair();
        Ok((public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned()))
    }
    fn save_public(public_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Dilithium3/key.pub"), FileTypes::public_key(), FileState::not_encrypted());
        let _ = file.save(public_key);
        Ok(())
    }
    fn save_secret(secret_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Dilithium3/key.sec"), FileTypes::secret_key(), FileState::not_encrypted());
        let _ = file.save(secret_key);
        Ok(())
    }
    fn load(path: &PathBuf) -> Result<Vec<u8>, SigningErr> {
        let file = match path.extension().and_then(|s| s.to_str()) {
            Some("pub") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::public_key(), FileState::not_encrypted()),
            Some("sec") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::secret_key(), FileState::not_encrypted()),
            _ => FileMetadata::new(),
        };
        let key = file.load().map_err(|_e| SigningErr::UnsupportedFileType(path.extension().unwrap().to_str().unwrap().to_string()))?;
        Ok(key)
    }
}
impl SignatureFunctions for Dilithium3 {
    /// Signs a given message with the provided key.
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Dilithium3");
        let key = dilithium3::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium3::sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Dilithium3");
        Ok(signature)
    }
    /// Creates a detached signature for the given data.
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Dilithium3");
        let key = dilithium3::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium3::detached_sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Dilithium3");
        Ok(signature)
    }
    /// Opens (or verifies) a signed message with the provided key.
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Dilithium3");
        let key = dilithium3::PublicKey::from_bytes(&key).unwrap();
        let signed_message = dilithium3::SignedMessage::from_bytes(&signed_data).unwrap();
        log_activity!("Completed signing the message.", "\nUsed key: Dilithium3");

        Ok(dilithium3::open(&signed_message, &key).unwrap())
    }
    /// Verifies a signature against the provided data and key.
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        log_activity!("Starting verification of signed message.", "\nUsed key: Dilithium3");
        let key = dilithium3::PublicKey::from_bytes(&key).unwrap();
        let ds = dilithium3::DetachedSignature::from_bytes(&signature).unwrap();
        
        let data = dilithium3::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .map_err(|_| SigningErr::SignatureVerificationFailed)?;
        match &data {
            true => log_activity!("Verification completed.", "\nUsed key: Dilithium3"),
            false => log_activity!("Verification failed! Please use for more infos: RUST_BACKTRACE=[1 or full]", "\nUsed key: Dilithium3"),
        };
        Ok(
            data
        )
    }
}

pub struct Dilithium5;
impl KeyOperations for Dilithium5 {
    /// Generates a Dilithium5 key pair.
    fn keypair() -> Result<(Vec<u8>, Vec<u8>), SigningErr> {
        let (public_key, secret_key) = dilithium5::keypair();
        Ok((public_key.as_bytes().to_owned(), secret_key.as_bytes().to_owned()))
    }
    fn save_public(public_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Dilithium5/key.pub"), FileTypes::public_key(), FileState::not_encrypted());
        let _ = file.save(public_key);
        Ok(())
    }
    fn save_secret(secret_key: &[u8]) -> Result<(), SigningErr> {
        let file = FileMetadata::from(PathBuf::from("./Dilithium5/key.sec"), FileTypes::secret_key(), FileState::not_encrypted());
        let _ = file.save(secret_key);
        Ok(())
    }
    fn load(path: &PathBuf) -> Result<Vec<u8>, SigningErr> {
        let file = match path.extension().and_then(|s| s.to_str()) {
            Some("pub") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::public_key(), FileState::not_encrypted()),
            Some("sec") => FileMetadata::from(PathBuf::from(path.as_os_str().to_str().unwrap()), FileTypes::secret_key(), FileState::not_encrypted()),
            _ => FileMetadata::new(),
        };
        let key = file.load().map_err(|_e| SigningErr::UnsupportedFileType(path.extension().unwrap().to_str().unwrap().to_string()))?;
        Ok(key)
    }
}
impl SignatureFunctions for Dilithium5 {
    /// Signs a given message with the provided key.
    fn sign_message(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Dilithium5");
        let key = dilithium5::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium5::sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Dilithium5");
        Ok(signature)
    }
    /// Creates a detached signature for the given data.
    fn detached_signature(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Dilithium5");
        let key = dilithium5::SecretKey::from_bytes(&key).unwrap();
        let signature = dilithium5::detached_sign(&data, &key).as_bytes().to_owned();
        log_activity!("Completed signing the message.", "\nUsed key: Dilithium5");
        Ok(signature)
    }
    /// Opens (or verifies) a signed message with the provided key.
    fn open_message(signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        log_activity!("Starting with signing of the message.", "\nUsed key: Dilithium5");
        let key = dilithium5::PublicKey::from_bytes(&key).unwrap();
        let signed_message = dilithium5::SignedMessage::from_bytes(&signed_data).unwrap();
        log_activity!("Completed signing the message.", "\nUsed key: Dilithium5");
        Ok(dilithium5::open(&signed_message, &key).unwrap())
    }
    /// Verifies a signature against the provided data and key.
    fn verify(signature: Vec<u8>, data: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        log_activity!("Starting verification of signed message.", "\nUsed key: Dilithium5");
        let key = dilithium5::PublicKey::from_bytes(&key).unwrap();
        let ds = dilithium5::DetachedSignature::from_bytes(&signature).unwrap();
        
        let data = dilithium5::verify_detached_signature(&ds, &data, &key)
            .map(|_| true)
            .map_err(|_| SigningErr::SignatureVerificationFailed)?;
        match &data {
            true => log_activity!("Verification completed.", "\nUsed key: Dilithium5"),
            false => log_activity!("Verification failed! Please use for more infos: RUST_BACKTRACE=[1 or full]", "\nUsed key: Dilithium5"),
        };
        Ok(
            data
        )
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
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Falcon1024::sign_message(data, key)?)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Falcon1024::open_message(signed_data, key)?)
    }
}

impl Signature<Falcon1024, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Falcon1024::detached_signature(data, key)?)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        Ok(Falcon1024::verify(signature, data, key)?)
    }
}

// Implementation of Signature for Falcon512
impl Signature<Falcon512, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Falcon512::sign_message(data, key)?)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Falcon512::open_message(signed_data, key)?)
    }
}

impl Signature<Falcon512, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Falcon512::detached_signature(data, key)?)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        Ok(Falcon512::verify(signature, data, key)?)
    }
}

// Implementation of Signature for Dilithium2
impl Signature<Dilithium2, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium2::sign_message(data, key)?)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium2::open_message(signed_data, key)?)
    }
}

impl Signature<Dilithium2, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium2::detached_signature(data, key)?)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        Ok(Dilithium2::verify(signature, data, key)?)
    }
}

// Implementation of Signature for Dilithium3
impl Signature<Dilithium3, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium3::sign_message(data, key)?)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium3::open_message(signed_data, key)?)
    }
}

impl Signature<Dilithium3, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium3::detached_signature(data, key)?)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        Ok(Dilithium3::verify(signature, data, key)?)
    }
}

// Implementation of Signature for Dilithium5
impl Signature<Dilithium5, Message> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium5::sign_message(data, key)?)
    }
    pub fn open(&self, signed_data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium5::open_message(signed_data, key)?)
    }
}

impl Signature<Dilithium5, Detached> {
    pub fn signature(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, SigningErr> {
        Ok(Dilithium5::detached_signature(data, key)?)
    }
    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>, key: Vec<u8>) -> Result<bool, SigningErr> {
        Ok(Dilithium5::verify(signature, data, key)?)
    }
}