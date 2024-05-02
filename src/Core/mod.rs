use crate::{cryptography::*, error::CryptError, cryptography::hmac_sign::*};

/// Functions for usage of falcon and dilithium
pub mod KDF;
/// Functions for usage of kyber for key generation
pub mod kyber;
pub use kyber::KeyControler::*;

/// The `cipher_aes` module implements the AES (Advanced Encryption Standard) algorithm for secure data encryption and decryption, providing a robust symmetric key cryptography solution.
pub mod cipher_aes; 
/// The `cipher_xchacha` module offers encryption and decryption functionalities using the XChaCha20 algorithm, extending ChaCha for higher nonce sizes and additional security.
pub mod cipher_xchacha; 

pub enum KeyControlVariant {
    Kyber1024(KeyControl<KeyControKyber1024>),
    Kyber768(KeyControl<KeyControKyber768>),
    Kyber512(KeyControl<KeyControKyber512>),
}

impl KeyControlVariant {
    // Encapsulates the logic to create different KeyControl variants
    pub fn new(keytype: KeyEncapMechanism) -> Self {
        match keytype {
            KeyEncapMechanism::Kyber1024 => Self::Kyber1024(KeyControl::<KeyControKyber1024>::new()),
            KeyEncapMechanism::Kyber768 => Self::Kyber768(KeyControl::<KeyControKyber768>::new()),
            KeyEncapMechanism::Kyber512 => Self::Kyber512(KeyControl::<KeyControKyber512>::new()),
        }
    }
    pub fn encap(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        match self {
            KeyControlVariant::Kyber1024(k) => k.encap(public_key),
            KeyControlVariant::Kyber768(k) => k.encap(public_key),
            KeyControlVariant::Kyber512(k) => k.encap(public_key),
        }
    }

    pub fn decap(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptError> {
        match self {
            KeyControlVariant::Kyber1024(k) => k.decap(secret_key, ciphertext),
            KeyControlVariant::Kyber768(k) => k.decap(secret_key, ciphertext),
            KeyControlVariant::Kyber512(k) => k.decap(secret_key, ciphertext),
        }
    }
}

/// Defines the functionalities for cryptographic operations, providing abstract methods for
/// encryption and decryption that need to be implemented by specific cryptographic algorithms.
pub trait CryptographicFunctions {
    /// Encrypts data using a public key, returning the encrypted data and potentially a new key.
    ///
    /// # Parameters
    /// - `public_key`: The public key used for encryption.
    ///
    /// # Returns
    /// A result containing the encrypted data and a new key on success, or a `CryptError` on failure.
    fn encrypt(&mut self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), CryptError>;

    /// Decrypts data using a secret key and a given ciphertext.
    ///
    /// # Parameters
    /// - `secret_key`: The secret key used for decryption.
    /// - `ciphertext`: The ciphertext to be decrypted.
    ///
    /// # Returns
    /// A result containing the decrypted data on success, or a `CryptError` on failure.
    fn decrypt(&mut self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError>;
}
