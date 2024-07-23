/// Kyber key functionalitys
pub mod KeyControler;
mod kyber_crypto_xchacha;
mod kyber_crypto_aes;
mod kyber_crypto_aes_gcm_siv;
//mod kyber_crypto_aes_ctr;

use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use crate::{
	*,
    log_activity,
	cryptography::*, 
	error::CryptError, 
	//hmac_sign::*,
	FileTypes,
	FileState,
	FileMetadata,
	KeyTypes,
	Key,
	Core::CryptographicFunctions,
    write_log,
};
use std::{
    path::{PathBuf, Path},
    marker::PhantomData, 
    result::Result,
};

/// Trait for Kyber cryptographic functions.
pub trait KyberFunctions {
    /// Encrypts a files at a given path with a passphrase, returning the encrypted data and nonce.
    fn encrypt_file(&mut self, path: PathBuf, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Encrypts a message with a passphrase, returning the encrypted data and nonce.
    fn encrypt_msg(&mut self, message: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Encrypts data with a passphrase, returning the encrypted data and nonce.
    fn encrypt_data(&mut self, data: Vec<u8>, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Decrypts a files at a given path with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_file(&self, path: PathBuf, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
    /// Decrypts a message with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_msg(&self, message: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
    /// Decrypts data with a passphrase and ciphertext, returning the decrypted data.
    fn decrypt_data(&self, data: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
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

/// Kyber512: Kyber<ProcessStatus, **KeySize: (used here)**, ContentStatus, AlgorithmParam>
pub struct Kyber512;
/// Kyber768: Kyber<ProcessStatus, **KeySize: (used here)**, ContentStatus, AlgorithmParam>
pub struct Kyber768;
/// Kyber1024: Kyber<ProcessStatus, **KeySize: (used here)**, ContentStatus, AlgorithmParam>
pub struct Kyber1024;

/// AES: Kyber<ProcessStatus, KeySize, ContentStatus, **AlgorithmParam: (used here)**>
pub struct AES;

/// AES-CBC: Kyber<ProcessStatus, KeySize, ContentStatus, **AlgorithmParam: (used here)**>
pub struct AES_GCM_SIV;

/// AES-CTR: Kyber<ProcessStatus, KeySize, ContentStatus, **AlgorithmParam: (used here)**>
pub struct AES_CTR;

/// XChaCha20: Kyber<ProcessStatus, KeySize, ContentStatus, **AlgorithmParam: (used here)**>
pub struct XChaCha20;

/// Encryption: Kyber<**ProcessStatus: (used here)**, KeySize, ContentStatus, AlgorithmParam>
pub struct Encryption;
/// Decryption: Kyber<**ProcessStatus: (used here)**, KeySize, ContentStatus, AlgorithmParam>
pub struct Decryption;

/// Files: Kyber<ProcessStatus, KeySize, **ContentStatus: (used here)**, AlgorithmParam>
pub struct Files;
/// Message: Kyber<ProcessStatus, KeySize, **ContentStatus: (used here)**, AlgorithmParam>
pub struct Message;
/// Data: Kyber<ProcessStatus, KeySize, **ContentStatus: (used here)**, AlgorithmParam>
pub struct Data;


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
pub struct Kyber<ProcessStatus = Encryption, KyberSize=Kyber1024, ContentStatus=Files, AlgorithmParam=AES> 
where
    KyberSize: KyberSizeVariant,
{
	kyber_data: KyberData,
    hmac_size: usize,
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
            hmac_size: 512,
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

    pub fn hmac_sha256(&mut self) -> Result<(), CryptError> {
        self.hmac_size = 256;
        Ok(())
    }
}

/// Usable when KyberSize = Kyber1024
impl Kyber<Encryption, Kyber1024, Files, AES> {
	pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber768, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
	pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber512, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
}

/// Usable when KyberSize = Kyber768
impl Kyber<Encryption, Kyber768, Files, AES> {
	pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber1024, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
	pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber512, Files, AES>  {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
}

/// Usable when KyberSize = Kyber512
impl Kyber<Encryption, Kyber512, Files, AES> {
	pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber1024, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
	pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES>, CryptError> {
		Ok(Kyber::<Encryption, Kyber768, Files, AES> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
	}
}

/// Usable when KyberSize = Kyber1024
impl Kyber<Encryption, Kyber1024, Files, AES_GCM_SIV> {
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES_GCM_SIV>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AES_GCM_SIV> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES_GCM_SIV>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AES_GCM_SIV> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber768
impl Kyber<Encryption, Kyber768, Files, AES_GCM_SIV> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES_GCM_SIV>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AES_GCM_SIV> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES_GCM_SIV>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AES_GCM_SIV>  {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber512
impl Kyber<Encryption, Kyber512, Files, AES_GCM_SIV> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES_GCM_SIV>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AES_GCM_SIV> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES_GCM_SIV>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AES_GCM_SIV> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber1024
impl Kyber<Encryption, Kyber1024, Files, AES_CTR> {
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES_CTR>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AES_CTR> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES_CTR>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AES_CTR> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber768
impl Kyber<Encryption, Kyber768, Files, AES_CTR> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES_CTR>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AES_CTR> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber512(self) -> Result<Kyber<Encryption, Kyber512, Files, AES_CTR>, CryptError> {
        Ok(Kyber::<Encryption, Kyber512, Files, AES_CTR>  {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber512>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when KyberSize = Kyber512
impl Kyber<Encryption, Kyber512, Files, AES_CTR> {
    pub fn kyber1024(self) -> Result<Kyber<Encryption, Kyber1024, Files, AES_CTR>, CryptError> {
        Ok(Kyber::<Encryption, Kyber1024, Files, AES_CTR> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber1024>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
    pub fn kyber768(self) -> Result<Kyber<Encryption, Kyber768, Files, AES_CTR>, CryptError> {
        Ok(Kyber::<Encryption, Kyber768, Files, AES_CTR> {kyber_data: self.kyber_data, hmac_size: self.hmac_size, process_state: self.process_state, kyber_state: PhantomData::<Kyber768>, content_state: self.content_state, algorithm_state: self.algorithm_state})
    }
}

/// Usable when AlgorithmParam = AES
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_GCM_SIV> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }

    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_CTR> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
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
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_GCM_SIV> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_CTR> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}
/// Usable when AlgorithmParam = AES
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_GCM_SIV> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }

    pub fn aes_ctr(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_CTR> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}
/// Usable when AlgorithmParam = AES
impl<ProcessStatus, KyberSize: KyberSizeVariant, ContentStatus> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_CTR> {
    pub fn xchacha20(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, XChaCha20> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn aes(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    
    pub fn aes_gcm_siv(self) -> Kyber<ProcessStatus, KyberSize, ContentStatus, AES_GCM_SIV> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}

/// Usable when ContentStatus = Files
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, Files, AlgorithmParam> {
    pub fn message(self) -> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn data(self) -> Kyber<ProcessStatus, KyberSize, Data, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn is_file(self) -> bool {
        true
    }
    
    pub fn is_message(self) -> bool {
        false
    }
    
    pub fn is_data(self) -> bool {
        false
    }

}

/// Usable when ContentStatus = Message
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
    pub fn file(self) -> Kyber<ProcessStatus, KyberSize, Files, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn data(self) -> Kyber<ProcessStatus, KyberSize, Data, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn is_file(self) -> bool {
        false
    }
    
    pub fn is_message(self) -> bool {
        true
    }
    
    pub fn is_data(self) -> bool {
        false
    }

}
/// Usable when ContentStatus = Message
impl<ProcessStatus, KyberSize: KyberSizeVariant, AlgorithmParam> Kyber<ProcessStatus, KyberSize, Data, AlgorithmParam> {
    pub fn file(self) -> Kyber<ProcessStatus, KyberSize, Files, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn message(self) -> Kyber<ProcessStatus, KyberSize, Message, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
    pub fn is_file(self) -> bool {
        false
    }
    
    pub fn is_message(self) -> bool {
        false
    }
    
    pub fn is_data(self) -> bool {
        true
    }

}

/// Usable when ProcessStatus = Encryption
impl<KyberSize: KyberSizeVariant, ContentStatus, AlgorithmParam> Kyber<Encryption, KyberSize, ContentStatus, AlgorithmParam> {
    pub fn decryption(self) -> Kyber<Decryption, KyberSize, Message, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}

/// Usable when ProcessStatus = Decryption
impl<KyberSize: KyberSizeVariant, ContentStatus, AlgorithmParam> Kyber<Decryption, KyberSize, ContentStatus, AlgorithmParam> {
    pub fn encryption(self) -> Kyber<Encryption, KyberSize, Files, AlgorithmParam> {
        Kyber {
            kyber_data: self.kyber_data,
            hmac_size: self.hmac_size,
            content_state: PhantomData,
            kyber_state: PhantomData, 
            algorithm_state: PhantomData,            
            process_state: PhantomData,
        }
    }
}

