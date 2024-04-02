use super::*;

/// Trait for implementing key management functions. This trait provides
/// an interface for key pair generation, encapsulation/decapsulation of secrets,
/// and key manipulation (such as setting and getting key values).
pub trait KyberKeyFunctions {
    /// Generates a new key pair.
    fn keypair() -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Encapsulates a secret using a public key.
    fn encap(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptError>;
    /// Decapsulates a secret using a secret key and a ciphertext.
    fn decap(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptError>;
}
/// Implementation for Kyber 1024 variant.
pub struct KeyControKyber1024;
impl KyberKeyFunctions for KeyControKyber1024{
    /// Generates a public and secret key pair using the Kyber1024 algorithm.
	fn keypair() -> Result<(Vec<u8>,Vec<u8>), CryptError> {
		use pqcrypto_kyber::kyber1024::*;

        let (pk, sk) = keypair();
        let public_key = pk.as_bytes().to_owned();
        let secret_key = sk.as_bytes().to_owned();

        Ok((public_key, secret_key))
	}

    /// Encapsulates a secret using a public key to produce a shared secret and a ciphertext.
	fn encap(public: &[u8]) -> Result<(Vec<u8>,Vec<u8>), CryptError> {
		use pqcrypto_kyber::kyber1024::*;

		let pk = PublicKey::from_bytes(&public).unwrap();
        let (ss, ct) = encapsulate(&pk);

		let ciphertext = ct.as_bytes().to_vec();
		let shared_secret = ss.as_bytes().to_vec();

		Ok((shared_secret, ciphertext))
	}

    /// Decapsulates the ciphertext using a secret key to retrieve the shared secret.
	fn decap(sec: &[u8], cipher: &[u8]) -> Result<Vec<u8>, CryptError> {
		use pqcrypto_kyber::kyber1024::*;

        let ct = Ciphertext::from_bytes(&cipher).unwrap();        
        let sk = SecretKey::from_bytes(&sec).unwrap();
        let ss2 = decapsulate(&ct, &sk);
		let shared_secret = ss2.as_bytes().to_vec();

		Ok(shared_secret)
	}
}

/// Implementation for Kyber 768 variant.
pub struct KeyControKyber768;
impl KyberKeyFunctions for KeyControKyber768 {
    /// Generates a public and secret key pair using the Kyber768 algorithm.
	fn keypair() -> Result<(Vec<u8>,Vec<u8>), CryptError> {
		use pqcrypto_kyber::kyber768::*;

        let (pk, sk) = keypair();
        let public_key = pk.as_bytes().to_vec();
        let secret_key = sk.as_bytes().to_vec();

        Ok((public_key, secret_key))
	}

    /// Encapsulates a secret using a public key to produce a shared secret and a ciphertext.
	fn encap(public: &[u8]) -> Result<(Vec<u8>,Vec<u8>), CryptError> {
		use pqcrypto_kyber::kyber768::*;

		let pk = PublicKey::from_bytes(&public).unwrap();
        let (ss, ct) = encapsulate(&pk);

		let ciphertext = ct.as_bytes().to_vec();
		let shared_secret = ss.as_bytes().to_vec();

		Ok((shared_secret, ciphertext))
	}

    /// Decapsulates the ciphertext using a secret key to retrieve the shared secret.
	fn decap(sec: &[u8], cipher: &[u8]) -> Result<Vec<u8>, CryptError> {
		use pqcrypto_kyber::kyber768::*;
		
        let ct = Ciphertext::from_bytes(&cipher).unwrap();        
        let sk = SecretKey::from_bytes(&sec).unwrap();
        let ss2 = decapsulate(&ct, &sk);
		let shared_secret = ss2.as_bytes().to_vec();

		Ok(shared_secret)
	}
}

/// Implementation for Kyber 512 variant.
pub struct KeyControKyber512;
impl KyberKeyFunctions for KeyControKyber512 {
    /// Generates a public and secret key pair using the Kyber512 algorithm.
	fn keypair() -> Result<(Vec<u8>,Vec<u8>), CryptError> {
		use pqcrypto_kyber::kyber512::*;

        let (pk, sk) = keypair();
        let public_key = pk.as_bytes().to_vec();
        let secret_key = sk.as_bytes().to_vec();

        Ok((public_key, secret_key))
	}

    /// Encapsulates a secret using a public key to produce a shared secret and a ciphertext.
	fn encap(public: &[u8]) -> Result<(Vec<u8>,Vec<u8>), CryptError> {
		use pqcrypto_kyber::kyber512::*;

		let pk = PublicKey::from_bytes(&public).unwrap();
        let (ss, ct) = encapsulate(&pk);

		let ciphertext = ct.as_bytes().to_vec();
		let shared_secret = ss.as_bytes().to_vec();

		Ok((shared_secret, ciphertext))
	}

    /// Decapsulates the ciphertext using a secret key to retrieve the shared secret.
	fn decap(sec: &[u8], cipher: &[u8]) -> Result<Vec<u8>, CryptError> {
		use pqcrypto_kyber::kyber512::*;
		
        let ct = Ciphertext::from_bytes(&cipher).unwrap();        
        let sk = SecretKey::from_bytes(&sec).unwrap();
        let ss2 = decapsulate(&ct, &sk);
		let shared_secret = ss2.as_bytes().to_vec();

		Ok(shared_secret)
	}
}

/// A structure to manage cryptographic keys and operations for the Kyber algorithm.
/// It encapsulates the public key, secret key, ciphertext, and shared secret.
pub struct KeyControl<T: KyberKeyFunctions> {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
    _marker: std::marker::PhantomData<T>, 
}

impl<T: KyberKeyFunctions> KeyControl<T> {
    /// Constructs a new instance of `KeyControl`.
    pub fn new() -> Self {
        KeyControl {
            public_key: Vec::new(),
            secret_key: Vec::new(),
            ciphertext: Vec::new(),
            shared_secret: Vec::new(),
            _marker: PhantomData,
        }
    }
    /// Sets the ciphertext for the `KeyControl` instance.
	pub fn set_ciphertext(&mut self, cipher: Vec<u8>) -> Result<(), CryptError> {
		Ok(self.ciphertext = cipher)
	}

    /// Sets the public key for the `KeyControl` instance.
	pub fn set_public_key(&mut self, public: Vec<u8>) -> Result<(), CryptError> {
		Ok(self.public_key = public)

	}

    /// Sets the secret key for the `KeyControl` instance.
	pub fn set_secret_key(&mut self, sec: Vec<u8>) -> Result<(), CryptError> {
		Ok(self.secret_key = sec)

	}

    /// Retrieves a specified key based on `KeyTypes`.
	pub fn get_key(&self, key: KeyTypes) -> Result<Key, CryptError> {
		let key = match key {
			KeyTypes::None => unimplemented!(),
			KeyTypes::PublicKey => {
				Key::new(KeyTypes::PublicKey, self.public_key.to_vec())
			}
			KeyTypes::SecretKey => {
				Key::new(KeyTypes::SecretKey, self.secret_key.to_vec())
			}
			KeyTypes::Ciphertext => {
				Key::new(KeyTypes::Ciphertext, self.ciphertext.to_vec())
			}
			KeyTypes::SharedSecret => {
				Key::new(KeyTypes::SharedSecret, self.shared_secret.to_vec())
			}
		};
		Ok(key)
	}

    /// Saves a specified key to a file at the given base path.
	pub fn save(&self, key: KeyTypes, base_path: PathBuf) -> Result<(), CryptError> {
		let key = match key {
			KeyTypes::None => unimplemented!(),
			KeyTypes::PublicKey => {
				Key::new(KeyTypes::PublicKey, self.public_key.to_vec())
			}
			KeyTypes::SecretKey => {
				Key::new(KeyTypes::SecretKey, self.secret_key.to_vec())
			}
			KeyTypes::Ciphertext => {
				Key::new(KeyTypes::Ciphertext, self.ciphertext.to_vec())
			}
			KeyTypes::SharedSecret => unimplemented!(),
		};
		key.save(base_path)
	}
    /// Loads a specified key from a file.
	pub fn load(&self, key: KeyTypes, path: &Path) -> Result<Vec<u8>, CryptError> {
		let key = match key {
			KeyTypes::None => unimplemented!(),
			KeyTypes::PublicKey => {
		        FileMetadata::from(
		            PathBuf::from(path),
		            FileTypes::PublicKey,
		            FileState::Other
		        )
			}
			KeyTypes::SecretKey => {
		        FileMetadata::from(
		            PathBuf::from(path),
		            FileTypes::SecretKey,
		            FileState::Other
		        )
			}
			KeyTypes::Ciphertext => {
		        FileMetadata::from(
		            PathBuf::from(path),
		            FileTypes::Ciphertext,
		            FileState::Other
		        )
			}
			KeyTypes::SharedSecret => unimplemented!(),
		};
		Ok(key.load().unwrap())
	}


    /// Getter methods for public_key, secret_key, ciphertext, and shared_secret.

	pub fn public_key(&self) -> Result<Vec<u8>, CryptError> {
		let key = &self.public_key;
		Ok(key.to_vec())
	}
	pub fn secret_key(&self) -> Result<Vec<u8>, CryptError> {
		let key = &self.secret_key;
		Ok(key.to_vec())
	}
	pub fn ciphertext(&self) -> Result<Vec<u8>, CryptError> {
		let key = &self.ciphertext;
		Ok(key.to_vec())
	}
	pub fn shared_secret(&self) -> Result<Vec<u8>, CryptError> {
		let key = &self.shared_secret;
		Ok(key.to_vec())
	}
	
    /// Encapsulates a secret using a public key.
	pub fn encap(&self, public: &[u8]) -> Result<(Vec<u8>,Vec<u8>), CryptError> {
		T::encap(public)
	}
    /// Decapsulates the ciphertext using a secret key to retrieve the shared secret.
    pub fn decap(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptError> {
        // Call the `decap` method on the type `T` that `KeyControl` wraps around
        T::decap(secret_key, ciphertext)
    }

}