//! Crate-wide error types for `crypt_guard`.
//!
//! # Responsibility scope
//! This module owns the two public error enums — [`CryptError`] and [`SigningErr`] — and all
//! their `impl` blocks. No other module may define a crate-level error; per-operation failures
//! are expressed as variants here.
//!
//! # Key types exported
//! - [`CryptError`] — primary error type for KEM, AEAD, KDF, and I/O failures.
//! - [`SigningErr`] — digital signature error type (identity preserved via
//!   [`CryptError::Signing`]; not String-flattened).
//!
//! # Concurrency
//! [`CryptError`] is `Clone` and `Send + Sync` (`io::Error` is wrapped in `Arc`).
//! [`SigningErr`] is `Clone` and `Send + Sync` (ditto).
//!
//! # Errors
//! This module produces no errors; it only defines them.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::error::CryptError;
//! let e = CryptError::new("custom failure");
//! println!("{}", e);
//! ```

pub use zeroize::Zeroize;
use std::{
    fmt::{self, Display, Formatter},
    error::Error,
    io,
    sync::Arc,
};

/// Primary error type for all crypt_guard operations.
///
/// # Description
/// Exhaustively covers KEM, AEAD, KDF, signature, I/O, and format failures. Every variant
/// carries enough context to write a useful error message without consulting source code.
/// Variants that wrap foreign errors retain the original type for `source()` chain walking.
///
/// # Clone semantics
/// `io::Error` is wrapped in `Arc` to make `Clone` work without copying OS error state.
///
/// # Concurrency
/// `Clone + Send + Sync`.
#[derive(Debug)]
pub enum CryptError {
    // ── I/O ──────────────────────────────────────────────────────────────────
    /// An I/O operation failed; the original `io::Error` is preserved for `source()`.
    IOError(Arc<io::Error>),
    /// A write operation failed without a specific I/O error available.
    WriteError,
    /// A requested file was not found at the specified path.
    FileNotFound,
    /// The filesystem path provided is invalid or does not exist.
    PathError,
    /// Generating a unique filename for an output file failed.
    UniqueFilenameFailed,

    // ── Message / format ─────────────────────────────────────────────────────
    /// The data does not match the expected message format (missing tags, wrong structure).
    MessageExtractionError,
    /// The message format is invalid or unrecognised.
    InvalidMessageFormat,
    /// A UTF-8 conversion failed.
    Utf8Error,

    // ── Hex ──────────────────────────────────────────────────────────────────
    /// A hex-encode or hex-decode operation failed; the underlying error is preserved.
    HexError(hex::FromHexError),
    /// A hex-decode operation failed; the error string describes the position/cause.
    HexDecodingError(String),

    // ── KEM ───────────────────────────────────────────────────────────────────
    /// Key encapsulation failed (RNG failure or malformed public key).
    EncapsulationError,
    /// Key decapsulation failed (malformed ciphertext or secret key).
    DecapsulationError,
    /// The KEM public key bytes are malformed or have the wrong length.
    InvalidKemPublicKey,
    /// The KEM secret key bytes are malformed or have the wrong length.
    InvalidKemSecretKey,
    /// The KEM ciphertext bytes are malformed or have the wrong length.
    InvalidKemCiphertext,

    // ── HMAC / authentication ─────────────────────────────────────────────────
    /// HMAC verification failed; the ciphertext may have been tampered with.
    HmacVerificationError,
    /// The data is too short to contain a valid HMAC tag.
    HmacShortData,
    /// HMAC key initialisation failed.
    HmacKeyErr,

    // ── Key material ──────────────────────────────────────────────────────────
    /// A required secret key was not provided.
    MissingSecretKey,
    /// A required public key was not provided.
    MissingPublicKey,
    /// A required ciphertext was not provided.
    MissingCiphertext,
    /// A required shared secret was not provided.
    MissingSharedSecret,
    /// Required input data was not provided.
    MissingData,
    /// The provided parameters are invalid for this operation.
    InvalidParameters,
    /// The key type is not valid or not supported for this operation.
    InvalidKeyType,
    /// The data length is invalid for this operation (e.g. not a multiple of block size).
    InvalidDataLength,

    // ── Encryption / decryption ───────────────────────────────────────────────
    /// An encryption operation failed; inspect `source()` or RUST_BACKTRACE for details.
    EncryptionFailed,
    /// A decryption operation failed; inspect `source()` or RUST_BACKTRACE for details.
    DecryptionFailed,
    /// The nonce value is invalid (wrong length, reused, or missing for nonce-bearing cipher).
    InvalidNonce,
    /// An authentication tag (AEAD or HMAC) verification failed; the data may be tampered.
    AuthenticationFailed,

    // ── Envelope / protocol ───────────────────────────────────────────────────
    /// The serialized envelope is malformed or cannot be parsed.
    InvalidEnvelope,
    /// The envelope header declares an unsupported version number.
    UnsupportedEnvelopeVersion,

    // ── Algorithm ────────────────────────────────────────────────────────────
    /// The requested algorithm is not supported by this build configuration.
    UnsupportedAlgorithm,
    /// The operation is not supported for the current key type or configuration.
    UnsupportedOperation,

    // ── Signatures ────────────────────────────────────────────────────────────
    /// A digital signature operation failed.
    SigningFailed,
    /// Signature verification produced a mismatch.
    SignatureVerificationFailed,
    /// The signature bytes have an invalid length.
    InvalidSignatureLength,
    /// The signature is structurally invalid (cannot be parsed).
    InvalidSignature,

    // ── Wrapped sub-errors ────────────────────────────────────────────────────
    /// A signing subsystem error; preserves `SigningErr` variant identity for typed matching.
    ///
    /// Use the variant directly rather than comparing `Display` strings.
    Signing(Arc<SigningErr>),

    // ── Fallback ──────────────────────────────────────────────────────────────
    /// A custom error message for cases not covered by the typed variants above.
    ///
    /// Prefer adding a typed variant over using `CustomError` in new code.
    CustomError(String),
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptError::IOError(e) => write!(f, "I/O error: {}", e),
            CryptError::WriteError => write!(f, "write operation failed"),
            CryptError::FileNotFound => write!(f, "file not found"),
            CryptError::PathError => write!(f, "provided path does not exist"),
            CryptError::UniqueFilenameFailed => write!(f, "failed to generate a unique filename"),

            CryptError::MessageExtractionError => write!(f, "failed to extract message from data"),
            CryptError::InvalidMessageFormat => write!(f, "invalid message format"),
            CryptError::Utf8Error => write!(f, "UTF-8 conversion error"),

            CryptError::HexError(e) => write!(f, "hex error: {}", e),
            CryptError::HexDecodingError(msg) => write!(f, "hex decoding error: {}", msg),

            CryptError::EncapsulationError => write!(f, "KEM encapsulation failed"),
            CryptError::DecapsulationError => write!(f, "KEM decapsulation failed"),
            CryptError::InvalidKemPublicKey => write!(f, "KEM public key is malformed or has wrong length"),
            CryptError::InvalidKemSecretKey => write!(f, "KEM secret key is malformed or has wrong length"),
            CryptError::InvalidKemCiphertext => write!(f, "KEM ciphertext is malformed or has wrong length"),

            CryptError::HmacVerificationError => write!(f, "HMAC verification failed"),
            CryptError::HmacShortData => write!(f, "data is too short to contain a valid HMAC tag"),
            CryptError::HmacKeyErr => write!(f, "HMAC key initialisation failed"),

            CryptError::MissingSecretKey => write!(f, "required secret key not provided"),
            CryptError::MissingPublicKey => write!(f, "required public key not provided"),
            CryptError::MissingCiphertext => write!(f, "required ciphertext not provided"),
            CryptError::MissingSharedSecret => write!(f, "required shared secret not provided"),
            CryptError::MissingData => write!(f, "required data not provided"),
            CryptError::InvalidParameters => write!(f, "invalid parameters provided"),
            CryptError::InvalidKeyType => write!(f, "invalid or unsupported key type"),
            CryptError::InvalidDataLength => write!(f, "data length is invalid for this operation"),

            CryptError::EncryptionFailed => write!(f, "encryption failed"),
            CryptError::DecryptionFailed => write!(f, "decryption failed"),
            CryptError::InvalidNonce => write!(f, "nonce is invalid or missing"),
            CryptError::AuthenticationFailed => write!(f, "authentication tag verification failed"),

            CryptError::InvalidEnvelope => write!(f, "envelope is malformed or cannot be parsed"),
            CryptError::UnsupportedEnvelopeVersion => write!(f, "unsupported envelope version"),

            CryptError::UnsupportedAlgorithm => write!(f, "algorithm is not supported"),
            CryptError::UnsupportedOperation => write!(f, "operation is not supported"),

            CryptError::SigningFailed => write!(f, "digital signing operation failed"),
            CryptError::SignatureVerificationFailed => write!(f, "signature verification failed"),
            CryptError::InvalidSignatureLength => write!(f, "signature has invalid length"),
            CryptError::InvalidSignature => write!(f, "signature is structurally invalid"),

            CryptError::Signing(e) => write!(f, "signing error: {}", e),
            CryptError::CustomError(msg) => write!(f, "{}", msg),
        }
    }
}

impl Clone for CryptError {
    fn clone(&self) -> Self {
        match self {
            CryptError::IOError(e) => CryptError::IOError(Arc::clone(e)),
            CryptError::WriteError => CryptError::WriteError,
            CryptError::FileNotFound => CryptError::FileNotFound,
            CryptError::PathError => CryptError::PathError,
            CryptError::UniqueFilenameFailed => CryptError::UniqueFilenameFailed,
            CryptError::MessageExtractionError => CryptError::MessageExtractionError,
            CryptError::InvalidMessageFormat => CryptError::InvalidMessageFormat,
            CryptError::Utf8Error => CryptError::Utf8Error,
            CryptError::HexError(e) => CryptError::HexError(e.clone()),
            CryptError::HexDecodingError(s) => CryptError::HexDecodingError(s.clone()),
            CryptError::EncapsulationError => CryptError::EncapsulationError,
            CryptError::DecapsulationError => CryptError::DecapsulationError,
            CryptError::InvalidKemPublicKey => CryptError::InvalidKemPublicKey,
            CryptError::InvalidKemSecretKey => CryptError::InvalidKemSecretKey,
            CryptError::InvalidKemCiphertext => CryptError::InvalidKemCiphertext,
            CryptError::HmacVerificationError => CryptError::HmacVerificationError,
            CryptError::HmacShortData => CryptError::HmacShortData,
            CryptError::HmacKeyErr => CryptError::HmacKeyErr,
            CryptError::MissingSecretKey => CryptError::MissingSecretKey,
            CryptError::MissingPublicKey => CryptError::MissingPublicKey,
            CryptError::MissingCiphertext => CryptError::MissingCiphertext,
            CryptError::MissingSharedSecret => CryptError::MissingSharedSecret,
            CryptError::MissingData => CryptError::MissingData,
            CryptError::InvalidParameters => CryptError::InvalidParameters,
            CryptError::InvalidKeyType => CryptError::InvalidKeyType,
            CryptError::InvalidDataLength => CryptError::InvalidDataLength,
            CryptError::EncryptionFailed => CryptError::EncryptionFailed,
            CryptError::DecryptionFailed => CryptError::DecryptionFailed,
            CryptError::InvalidNonce => CryptError::InvalidNonce,
            CryptError::AuthenticationFailed => CryptError::AuthenticationFailed,
            CryptError::InvalidEnvelope => CryptError::InvalidEnvelope,
            CryptError::UnsupportedEnvelopeVersion => CryptError::UnsupportedEnvelopeVersion,
            CryptError::UnsupportedAlgorithm => CryptError::UnsupportedAlgorithm,
            CryptError::UnsupportedOperation => CryptError::UnsupportedOperation,
            CryptError::SigningFailed => CryptError::SigningFailed,
            CryptError::SignatureVerificationFailed => CryptError::SignatureVerificationFailed,
            CryptError::InvalidSignatureLength => CryptError::InvalidSignatureLength,
            CryptError::InvalidSignature => CryptError::InvalidSignature,
            CryptError::Signing(e) => CryptError::Signing(Arc::clone(e)),
            CryptError::CustomError(s) => CryptError::CustomError(s.clone()),
        }
    }
}

impl CryptError {
    /// Construct a [`CryptError::CustomError`] from a string message.
    ///
    /// # Arguments
    /// - `msg` (`&str`): the custom error message.
    ///
    /// # Returns
    /// A new `CryptError::CustomError`.
    ///
    /// # Panics
    /// Never panics.
    pub fn new(msg: &str) -> Self {
        CryptError::CustomError(msg.to_owned())
    }
}

impl Error for CryptError {
    /// Return the underlying cause of this error, if any.
    ///
    /// # Description
    /// Variants that wrap foreign errors return a reference to the inner error so that
    /// diagnostic tools and `tracing`'s `%error` formatter can walk the full causal chain.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CryptError::IOError(e)  => Some(e.as_ref()),
            CryptError::HexError(e) => Some(e),
            CryptError::Signing(e)  => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for CryptError {
    fn from(error: io::Error) -> Self {
        CryptError::IOError(Arc::new(error))
    }
}

impl From<hex::FromHexError> for CryptError {
    fn from(error: hex::FromHexError) -> Self {
        CryptError::HexError(error)
    }
}

impl From<SigningErr> for CryptError {
    /// Wrap a [`SigningErr`] into [`CryptError::Signing`], preserving variant identity.
    ///
    /// # Description
    /// This replaces the previous `String`-flattening pattern so that callers can still
    /// `match` on the inner `SigningErr` variant by unwrapping `CryptError::Signing(arc)`.
    fn from(err: SigningErr) -> Self {
        CryptError::Signing(Arc::new(err))
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Digital signature subsystem error type.
///
/// # Description
/// Covers all failure modes from keypair generation, message signing, signature
/// verification, and file-based signing operations. Preserved as a distinct type
/// (not flattened to a String) so callers can match specific variants.
///
/// # Concurrency
/// `Clone + Send + Sync` — `io::Error` wrapped in `Arc`.
#[derive(Debug)]
pub enum SigningErr {
    /// The secret (signing) key is missing.
    SecretKeyMissing,
    /// The public (verifying) key is missing.
    PublicKeyMissing,
    /// Signature verification failed; the signature does not match the message.
    SignatureVerificationFailed,
    /// Signing the message failed (RNG failure or invalid key).
    SigningMessageFailed,
    /// No signature bytes were provided for verification.
    SignatureMissing,
    /// Creating an output file for a signature or key failed.
    FileCreationFailed,
    /// Writing a signature or key to a file failed.
    FileWriteFailed,
    /// The file has an unsupported extension for this signing operation.
    UnsupportedFileType(String),
    /// A custom error message for cases not covered by the typed variants.
    CustomError(String),
    /// An I/O error; the original `io::Error` is wrapped in `Arc` for cloneability.
    IOError(Arc<io::Error>),
}

impl SigningErr {
    /// Construct a [`SigningErr::CustomError`] from a string message.
    ///
    /// # Arguments
    /// - `msg` (`&str`): the custom error message.
    ///
    /// # Returns
    /// A new `SigningErr::CustomError`.
    pub fn new(msg: &str) -> Self {
        SigningErr::CustomError(msg.to_owned())
    }
}

impl Display for SigningErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SigningErr::SecretKeyMissing => write!(f, "secret key is missing"),
            SigningErr::PublicKeyMissing => write!(f, "public key is missing"),
            SigningErr::SignatureVerificationFailed => write!(f, "signature verification failed"),
            SigningErr::SigningMessageFailed => write!(f, "failed to sign message"),
            SigningErr::SignatureMissing => write!(f, "signature is missing"),
            SigningErr::FileCreationFailed => write!(f, "failed to create output file"),
            SigningErr::FileWriteFailed => write!(f, "failed to write to file"),
            SigningErr::UnsupportedFileType(ext) => {
                write!(f, "unsupported file extension: .{}", ext)
            }
            SigningErr::CustomError(message) => write!(f, "{}", message),
            SigningErr::IOError(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl Clone for SigningErr {
    fn clone(&self) -> Self {
        match self {
            SigningErr::SecretKeyMissing => SigningErr::SecretKeyMissing,
            SigningErr::PublicKeyMissing => SigningErr::PublicKeyMissing,
            SigningErr::SignatureVerificationFailed => SigningErr::SignatureVerificationFailed,
            SigningErr::SigningMessageFailed => SigningErr::SigningMessageFailed,
            SigningErr::SignatureMissing => SigningErr::SignatureMissing,
            SigningErr::FileCreationFailed => SigningErr::FileCreationFailed,
            SigningErr::FileWriteFailed => SigningErr::FileWriteFailed,
            SigningErr::UnsupportedFileType(s) => SigningErr::UnsupportedFileType(s.clone()),
            SigningErr::CustomError(s) => SigningErr::CustomError(s.clone()),
            SigningErr::IOError(e) => SigningErr::IOError(Arc::clone(e)),
        }
    }
}

impl PartialEq for SigningErr {
    fn eq(&self, other: &Self) -> bool {
        use SigningErr::*;
        matches!(
            (self, other),
            (SecretKeyMissing, SecretKeyMissing)
            | (PublicKeyMissing, PublicKeyMissing)
            | (SignatureVerificationFailed, SignatureVerificationFailed)
            | (SigningMessageFailed, SigningMessageFailed)
            | (SignatureMissing, SignatureMissing)
            | (FileCreationFailed, FileCreationFailed)
            | (FileWriteFailed, FileWriteFailed)
        )
    }
}

impl Error for SigningErr {
    /// Return the underlying I/O cause if this is an `IOError` variant.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SigningErr::IOError(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for SigningErr {
    fn from(err: io::Error) -> Self {
        SigningErr::IOError(Arc::new(err))
    }
}

// Gate the pqcrypto_traits From impl behind the legacy feature.
#[cfg(feature = "legacy-pqclean")]
impl From<pqcrypto_traits::Error> for SigningErr {
    fn from(_: pqcrypto_traits::Error) -> Self {
        SigningErr::SignatureVerificationFailed
    }
}
