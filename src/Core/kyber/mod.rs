pub mod KeyKyber;
mod kyber_crypto;
pub use kyber_crypto::*;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use crate::{
	*,
	cryptography::*, 
	error::CryptError, 
	signature::*,
	FileTypes,
	FileState,
	FileMetadata,
	KeyTypes,
	Key,
	Core::CryptographicFunctions,
};
use std::{
    path::{PathBuf, Path}, 
    collections::HashMap,
    marker::PhantomData, 
    result::Result, 
    io::{Read, Write}, 
    fs,
};

/// Trait for Kyber cryptographic functions.
pub trait KyberFunctions {
    /// Encrypts a file at a given path with a passphrase, returning the encrypted data and nonce.
    fn encrypt_file(&mut self, path: PathBuf, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Encrypts a message with a passphrase, returning the encrypted data and nonce.
    fn encrypt_msg(&mut self, message: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;

    /// Decrypts a file at a given path with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_file(&self, path: PathBuf, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
    /// Decrypts a message with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_msg(&self, message: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
}


/// Enum representing Kyber variants.
pub enum KyberVariant {
    Kyber512,
    Kyber768,
    Kyber1024,
}

/// Trait to specify Kyber size variants.
pub trait KyberSizeVariant {
    /// Returns the Kyber variant.
    fn variant() -> KyberVariant;
}

impl KyberSizeVariant for Kyber512 {
    fn variant() -> KyberVariant { KyberVariant::Kyber512 }
}

impl KyberSizeVariant for Kyber768 {
    fn variant() -> KyberVariant { KyberVariant::Kyber768 }
}

impl KyberSizeVariant for Kyber1024 {
    fn variant() -> KyberVariant { KyberVariant::Kyber1024 }
}

pub struct Kyber512;
pub struct Kyber768;
pub struct Kyber1024;

pub struct AES;
pub struct XChaCha20;

pub struct Encryption;
pub struct Decryption;

pub struct File;
pub struct Message;


/// Represents the data structure for Kyber algorithm, including key and nonce.
#[derive(PartialEq, Debug, Clone)]
pub struct KyberData {
	key: Vec<u8>,
	nonce: String,
}

impl KyberData {
    /// Returns the cryptographic key.
	pub fn key(&self) -> Result<Vec<u8>, CryptError> {
		let key = &self.key;
		let key = key.to_vec();
		Ok(key)
	}
    /// Returns the nonce.
	pub fn nonce(&self) -> Result<&str, CryptError> {
		let nonce = &self.nonce;
		Ok(nonce)
	}
    /// Sets the nonce.
	pub fn set_nonce(&mut self, nonce: String) -> Result<(), CryptError> {
		self.nonce = nonce;
		Ok(())
	}
    /// Sets the cryptographic key.
    pub fn set_key(&mut self, key: Vec<u8>) -> Result<(), CryptError> {
        self.key = key;
        Ok(())
    }
}

/// Represents a generic Kyber structure with templated parameters for process status, Kyber size, content status, and algorithm parameter.
pub struct Kyber<ProcessStatus = Encryption, KyberSize=Kyber1024, ContentStatus=File, AlgorithmParam=AES> 
where
    KyberSize: KyberSizeVariant,
{
	kyber_data: KyberData,
	content_state: PhantomData<ContentStatus>,
    kyber_state: PhantomData<KyberSize>,
    algorithm_state: PhantomData<AlgorithmParam>,
	process_state: PhantomData<ProcessStatus>,
}

impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus, AlgorithmParam> Kyber<ProcessStatus, KyberSize, ContentStatus, AlgorithmParam> {
    /// Constructs a new Kyber instance with a key and an optional nonce.
    pub fn new(key: Vec<u8>, nonce: Option<String>) -> Result<Self, CryptError> {
        let nonce = nonce.map_or(String::new(), |data| data);
        Ok(Self {
            kyber_data: KyberData { key, nonce },
            content_state: PhantomData,
            kyber_state: PhantomData,
            algorithm_state: PhantomData,
            process_state: PhantomData,
        })
    }

    /// Returns the cryptographic key.
    pub fn get_key(&self) -> Result<Vec<u8>, CryptError> {
        self.kyber_data.key()
    }

    /// Returns the nonce.
    pub fn get_nonce(&self) -> Result<&str, CryptError> {
        self.kyber_data.nonce()
    }
}

/// Usable when KyberSize = Kyber1024
impl Kyber<Encryption, Kyber1024, File, AES> {
	pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, File, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber768, File, AES> {kyber_data: self.kyber_data, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
	pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, File, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber512, File, AES> {kyber_data: self.kyber_data, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
}

/// Usable when KyberSize = Kyber768
impl Kyber<Encryption, Kyber768, File, AES> {
	pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, File, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber1024, File, AES> {kyber_data: self.kyber_data, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
	pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, File, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber512, File, AES>  {kyber_data: self.kyber_data, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
}

/// Usable when KyberSize = Kyber512
impl Kyber<Encryption, Kyber512, File, AES> {
	pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, File, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber1024, File, AES> {kyber_data: self.kyber_data, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
	pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, File, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber768, File, AES> {kyber_data: self.kyber_data, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
}

/// Usable when AlgorithmParam = AES
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber {
            kyber_data: self.kyber_data,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}

/// Usable when AlgorithmParam = XChaCha20
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber {
            kyber_data: self.kyber_data,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}
/// Usable when ContentStatus = File
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, File, AlgorithmParam> {
    pub fn message(self) -> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}

/// Usable when ContentStatus = Message
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
    pub fn file(self) -> Kyber<ProcessStatus, KyberSize, File, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}

/// Usable when ProcessStatus = Encryption
impl<KyberSize: KyberSizeVariant, ContentStatus, AlgorithmParam> Kyber<Encryption, KyberSize, ContentStatus, AlgorithmParam> {
    pub fn decryption(self) -> Kyber<Decryption, KyberSize, Message, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}

/// Usable when ProcessStatus = Decryption
impl<KyberSize: KyberSizeVariant, ContentStatus: KyberSizeVariant, AlgorithmParam> Kyber<Decryption, KyberSize, ContentStatus, AlgorithmParam> {
    pub fn encryption(self) -> Kyber<Encryption, KyberSize, File, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}