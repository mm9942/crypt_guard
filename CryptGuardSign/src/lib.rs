#[cfg(feature = "default")]
mod sign_falcon;

#[cfg(feature = "dilithium")]
mod sign_dilithium;

#[cfg(feature = "default")]
pub use crate::sign_falcon::*;

#[cfg(feature="dilithium")]
pub use crate::sign_dilithium::*;
#[cfg(feature="dilithium")]
use pqcrypto_dilithium;

use std::{
    error::Error,
    fmt::{self, *},
    io,
};

#[derive(Debug)]
pub enum SigningErr {
    SecretKeyMissing,
    PublicKeyMissing,
    SignatureVerificationFailed,
    SigningMessageFailed,
    IOError(io::Error),
}

impl Display for SigningErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SigningErr::SecretKeyMissing => write!(f, "Secret key is missing"),
            SigningErr::PublicKeyMissing => write!(f, "Public key is missing"),
            SigningErr::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            SigningErr::SigningMessageFailed => write!(f, "Failed to sign message"),
            SigningErr::IOError(err) => write!(f, "IOError occurred: {}", err),
        }
    }
}

impl PartialEq for SigningErr {
    fn eq(&self, other: &Self) -> bool {
        use SigningErr::*;
        match (self, other) {
            (SecretKeyMissing, SecretKeyMissing)
            | (PublicKeyMissing, PublicKeyMissing)
            | (SignatureVerificationFailed, SignatureVerificationFailed)
            | (SigningMessageFailed, SigningMessageFailed) => true,
            (IOError(_), IOError(_)) => false,
            _ => false,
        }
    }
}

impl From<pqcrypto_traits::Error> for SigningErr {
    fn from(_: pqcrypto_traits::Error) -> Self {
        SigningErr::SignatureVerificationFailed
    }
}

impl Error for SigningErr {}

impl From<io::Error> for SigningErr {
    fn from(err: io::Error) -> Self {
        SigningErr::IOError(err)
    }
}

pub fn generate_unique_filename(base_path: &str, extension: &str) -> String {
    let mut counter = 1;
    let mut unique_path = format!("{}.{}", base_path, extension);
    while std::path::Path::new(&unique_path).exists() {
        unique_path = format!("{}_{}.{}", base_path, counter, extension);
        counter += 1;
    }
    unique_path
}

#[cfg(test)]
mod tests {
    extern crate tempfile;
    use super::*;
        
    use crate::{
        sign_falcon::*,
    };
    use std::{
        path::{PathBuf, Path},
        fs,
        env::current_dir,
        io::Write,
        ffi::OsStr
    };
    use pqcrypto_falcon::falcon1024;
    use pqcrypto_traits::kem::{SharedSecret as SharedSecretTrait, SecretKey as SecretKeyTrait};
    use hex;
    use tempfile::{NamedTempFile, tempdir};
    use pqcrypto_traits::sign::{SignedMessage as SignedMessageSign, SecretKey as SecretKeySign, PublicKey as PublicKeySign, DetachedSignature as DetachedSignatureSign};

    #[cfg(feature="dilithium")]
    use crate::sign_dilithium::{self, *};
    #[cfg(feature="dilithium")]
    use pqcrypto_dilithium;

    #[tokio::test]
    async fn test_sign_msg() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        let result = sign.sign_msg(message).await;
        println!("{:?}", result);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_signing_detached() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        let result = sign.signing_detached(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_msg() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        sign.sign_msg(message).await.unwrap();
        let result = sign.verify_msg(message).await;
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_detached() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        let detached_signature = sign.signing_detached(message).await.unwrap();
        let result = sign.verify_detached(message).await;
        println!("{:?}", result);
        assert_eq!(result, Ok(true));
    }


    #[tokio::test]
    async fn test_sign_file() {
        // Initialize Signature struct
        let mut sign = Sign::new().unwrap();
        let _ = sign.save_keys("keychain", "sign").await;

        // Perform the sign_file operation
        let file_path = PathBuf::from("./README.md");
        let sign_result = sign.sign_file(file_path.clone()).await;
        assert!(sign_result.is_ok(), "Signing the file failed");

        // Reading the file content for verification
        let file_content = fs::read(&file_path).expect("Failed to read the file");
        
        // Verify the signature
        let verify_result = sign.verify_detached(&file_content).await;
        assert!(verify_result.is_ok(), "Signature verification failed");
        assert_eq!(verify_result.unwrap(), true, "The file signature verification failed");
    }

    #[tokio::test]
    async fn test_key_validation() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message for key validation";

        // Sign a message
        let signature = sign.signing_detached(message).await.expect("Signing failed");

        // Verify the signature using the same Sign object (which should contain the correct public key)
        let verification_result = sign.verify_detached(message).await.expect("Verification failed");

        assert!(verification_result, "Signature verification failed with the original key pair");
    }

    #[tokio::test]
    #[cfg(feature = "dilithium")]
    async fn test_sign_msg_dilithium() {
        let mut sign = SignDilithium::new().unwrap();
        let message = b"Test message";
        let result = sign.sign_msg(message).await;
        println!("{:?}", result);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "dilithium")]
    async fn test_signing_detached_dilithium() {
        let mut sign = SignDilithium::new().unwrap();
        let message = b"Test message";
        let result = sign.signing_detached(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "dilithium")]
    async fn test_verify_msg_dilithium() {
        let mut sign = SignDilithium::new().unwrap();
        let message = b"Test message";
        sign.sign_msg(message).await.unwrap();
        let result = sign.verify_msg(message).await;
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "dilithium")]
    async fn test_verify_detached_dilithium() {
        let mut sign = SignDilithium::new().unwrap();
        let message = b"Test message";
        let detached_signature = sign.signing_detached(message).await.unwrap();
        let result = sign.verify_detached(message).await;
        println!("{:?}", result);
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    #[cfg(feature = "dilithium")]
    async fn test_sign_file_dilithium() {
        // Initialize Signature struct
        let mut sign = SignDilithium::new().unwrap();
        let _ = sign.save_keys("keychain", "sign");

        // Perform the sign_file operation
        let file_path = PathBuf::from("./README.md");
        let sign_result = sign.sign_file(file_path.clone()).await;
        assert!(sign_result.is_ok(), "Signing the file failed");

        // Reading the file content for verification
        let file_content = fs::read(&file_path).expect("Failed to read the file");
        
        // Verify the signature
        let verify_result = sign.verify_detached(&file_content).await;
        assert!(verify_result.is_ok(), "Signature verification failed");
        assert_eq!(verify_result.unwrap(), true, "The file signature verification failed");
    }

    #[tokio::test]
    #[cfg(feature = "dilithium")]
    async fn test_key_validation_dilithium() {
        let mut sign = SignDilithium::new().unwrap();
        let message = b"Test message for key validation";

        // Sign a message
        let signature = sign.signing_detached(message).await.expect("Signing failed");

        // Verify the signature using the same Sign object (which should contain the correct public key)
        let verification_result = sign.verify_detached(message).await.expect("Verification failed");

        assert!(verification_result, "Signature verification failed with the original key pair");
    }
}