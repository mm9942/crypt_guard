use std::{fmt::{self, Display, Formatter}, error::Error, io, };

#[derive(Debug)]
pub enum CryptError {
    IOError,
    MessageExtractionError,
    InvalidMessageFormat,
    HexError(hex::FromHexError),
    EncapsulationError,
    DecapsulationError,
    WriteError,
    HmacVerificationError,
    HmacShortData,
    HmacKeyErr,
    HexDecodingError(String),
    UniqueFilenameFailed,
    MissingSecretKey,
    MissingPublicKey,
    MissingCiphertext,
    MissingSharedSecret,
    MissingData,
    InvalidParameters,
    PathError,
    Utf8Error,
    SigningFailed,
    SignatureVerificationFailed,
    InvalidSignatureLength,
    InvalidSignature,
    InvalidDataLength,
    UnsupportedOperation,
    InvalidKeyType, 
}

impl fmt::Display for CryptError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
       match self {
           CryptError::IOError => write!(f, "IO error occurred"),
           CryptError::MessageExtractionError => write!(f, "Error extracting message"),
           CryptError::InvalidMessageFormat => write!(f, "Invalid message format"),
           CryptError::HexError(err) => write!(f, "Hex error: {}", err),
           CryptError::EncapsulationError => write!(f, "Encapsulation error"),
           CryptError::DecapsulationError => write!(f, "Decapsulation error"),
           CryptError::WriteError => write!(f, "Write error"),
           CryptError::HmacVerificationError => write!(f, "HMAC verification error"),
           CryptError::HmacShortData => write!(f, "Data is too short for HMAC verification"),
           CryptError::HmacKeyErr => write!(f, "HMAC can take key of any size"),
           CryptError::HexDecodingError(err) => write!(f, "Hex decoding error: {}", err),
           CryptError::UniqueFilenameFailed => write!(f, "Unique filename failed"),
           CryptError::MissingSecretKey => write!(f, "Missing secret key"),
           CryptError::MissingPublicKey => write!(f, "Missing public key"),
           CryptError::MissingCiphertext => write!(f, "Missing ciphertext"),
           CryptError::MissingSharedSecret => write!(f, "Missing shared secret"),
           CryptError::MissingData => write!(f, "Missing data"),
           CryptError::InvalidParameters => write!(f, "You provided Invalid parameters"),
           CryptError::PathError => write!(f, "The provided path does not exist!"),
           CryptError::Utf8Error => write!(f, "UTF-8 conversion error"),
           CryptError::SigningFailed => write!(f, "Signing file using falcon 1024 failed!"),
           CryptError::SignatureVerificationFailed => write!(f, "verification of signature using falcon 1024 failed!"),
           CryptError::InvalidSignature => write!(f, "Signature not valid!"),
           CryptError::InvalidSignatureLength => write!(f, "Data is too short for HMAC verification"),
           CryptError::InvalidDataLength => write!(f, "Data size of encrypted data isn't multiple of the block size!"),
           CryptError::UnsupportedOperation => write!(f, "Unsupported operation"),
           CryptError::InvalidKeyType => write!(f, "Invalid or unsupported key type"),
       }
   }
}

impl Error for CryptError {}

impl From<hex::FromHexError> for CryptError {
    fn from(error: hex::FromHexError) -> Self {
        CryptError::HexError(error)
    }
}

#[derive(Debug)]
pub enum SigningErr {
    SecretKeyMissing,
    PublicKeyMissing,
    SignatureVerificationFailed,
    SigningMessageFailed,
    SignatureMissing,
    FileCreationFailed,
    FileWriteFailed,
    IOError(io::Error),
}

impl Display for SigningErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SigningErr::SecretKeyMissing => write!(f, "Secret key is missing"),
            SigningErr::PublicKeyMissing => write!(f, "Public key is missing"),
            SigningErr::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            SigningErr::SigningMessageFailed => write!(f, "Failed to sign message"),
            SigningErr::SignatureMissing => write!(f, "Signature is missing"),
            SigningErr::FileCreationFailed => write!(f, "Failed to create file"),
            SigningErr::FileWriteFailed => write!(f, "Failed to write to file"),
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