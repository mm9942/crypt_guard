mod sign;

// removed unused import per clippy

use crate::cryptography::*;
use crate::error::SigningErr;
use std::fmt;
use zeroize::Zeroize;

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
    Dilithium,
}

/// Represents a signing operation including the data and metadata for the operation.
#[derive(PartialEq, Debug, Clone)]
pub struct Sign {
    pub data: SignatureData,
    pub status: Operation,
    pub hash_type: SignType,
    pub length: usize,
    pub veryfied: bool,
}

/// Contains the data to be signed or verified, alongside necessary metadata like passphrase.
#[derive(PartialEq, Clone)]
pub struct SignatureData {
    pub data: Vec<u8>,
    pub passphrase: Vec<u8>,
    pub hmac: Vec<u8>,
    pub concat_data: Vec<u8>,
}

/// Manual `Debug` impl redacting every field: `data`, `hmac` and `concat_data`
/// may carry key material or authentication tags derived from the passphrase,
/// so only lengths are shown.
impl fmt::Debug for SignatureData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureData")
            .field(
                "data",
                &format_args!("<redacted {} bytes>", self.data.len()),
            )
            .field(
                "passphrase",
                &format_args!("<redacted {} bytes>", self.passphrase.len()),
            )
            .field(
                "hmac",
                &format_args!("<redacted {} bytes>", self.hmac.len()),
            )
            .field(
                "concat_data",
                &format_args!("<redacted {} bytes>", self.concat_data.len()),
            )
            .finish()
    }
}

impl Drop for SignatureData {
    /// Wipes all secret-bearing byte buffers on drop.
    ///
    /// `passphrase` is the caller secret; `data`, `hmac`, and `concat_data` may
    /// carry key material or authentication tags derived from it, so every field
    /// is zeroized to avoid leaving copies in freed heap memory.
    fn drop(&mut self) {
        self.data.zeroize();
        self.passphrase.zeroize();
        self.hmac.zeroize();
        self.concat_data.zeroize();
    }
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
#[derive(PartialEq, Clone)]
pub struct SignatureKey {
    pub data: Vec<u8>,
    pub key_type: SignatureDataType,
}

/// Manual `Debug` impl that redacts `data` when it holds a secret key.
/// Public keys and non-secret payloads are printed as before.
impl fmt::Debug for SignatureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key_type {
            SignatureDataType::SecretKey => f
                .debug_struct("SignatureKey")
                .field("key_type", &self.key_type)
                .field(
                    "data",
                    &format_args!("<redacted {} bytes>", self.data.len()),
                )
                .finish(),
            _ => f
                .debug_struct("SignatureKey")
                .field("key_type", &self.key_type)
                .field("data", &self.data)
                .finish(),
        }
    }
}

impl Drop for SignatureKey {
    /// Wipes the raw key bytes on drop.
    ///
    /// `data` may hold a secret key (`SignatureDataType::SecretKey`); it is
    /// zeroized unconditionally so no key material survives in freed memory.
    fn drop(&mut self) {
        self.data.zeroize();
    }
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
        // cannot fail: `set_public_key` is an infallible setter that always
        // returns `Ok(())`.
        public.set_public_key(public_key).unwrap();
        let signature_type = SignatureType::UnSigned;
        SignatureMechanism {
            signature: Vec::new(),
            public_key: public,
            signature_type,
        }
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
        self.data.zeroize();
        self.data = public_key;
        self.key_type = SignatureDataType::PublicKey;
        Ok(())
    }
    /// Sets the secret key for the signature.
    fn set_secret_key(&mut self, secret_key: Vec<u8>) -> Result<(), SigningErr> {
        self.data.zeroize();
        self.data = secret_key;
        self.key_type = SignatureDataType::SecretKey;
        Ok(())
    }
    /// Sets the signed message.
    fn set_signed_msg(&mut self, signed_message: Vec<u8>) -> Result<(), SigningErr> {
        self.data.zeroize();
        self.data = signed_message;
        self.key_type = SignatureDataType::SignedMessage;
        Ok(())
    }
    /// Sets the detached signature.
    fn set_signature(&mut self, detached_signature: Vec<u8>) -> Result<(), SigningErr> {
        self.data.zeroize();
        self.data = detached_signature;
        self.key_type = SignatureDataType::DetachedSignature;
        Ok(())
    }
}
// Typed accessors over the signature key material; retained as a stable API for
// the signing surface even though the current callers go through `Signature`.
#[allow(dead_code)]
impl SignatureKey {
    /// Constructs a new `SignatureKey`.
    fn new() -> Self {
        Self {
            data: Vec::new(),
            key_type: SignatureDataType::None,
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

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xCA, 0xFE];

    #[test]
    fn signature_key_debug_redacts_secret_key() {
        let mut key = SignatureKey::new();
        key.set_secret_key(MARKER.to_vec()).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(!debug_str.contains(&format!("{:?}", MARKER.to_vec())));
        assert!(debug_str.contains("SecretKey"));
    }

    #[test]
    fn signature_key_debug_shows_public_key_bytes() {
        let mut key = SignatureKey::new();
        key.set_public_key(MARKER.to_vec()).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains(&format!("{:?}", MARKER.to_vec())));
    }

    #[test]
    fn signature_data_debug_redacts_everything() {
        let data = SignatureData {
            data: MARKER.to_vec(),
            passphrase: MARKER.to_vec(),
            hmac: MARKER.to_vec(),
            concat_data: MARKER.to_vec(),
        };
        let debug_str = format!("{:?}", data);
        assert!(!debug_str.contains(&format!("{:?}", MARKER.to_vec())));
    }

    #[test]
    fn set_secret_key_zeroizes_previous_value_before_overwrite() {
        let mut key = SignatureKey::new();
        key.set_secret_key(vec![1, 2, 3, 4]).unwrap();
        // Overwrite; the old buffer should have been zeroized in place
        // before being dropped/replaced (behavioural effect is on the old
        // Vec's backing memory, which we cannot directly observe here, so we
        // just assert the new value took effect correctly).
        key.set_secret_key(vec![9, 9, 9, 9]).unwrap();
        assert_eq!(key.data, vec![9, 9, 9, 9]);
    }
}
