//! Service-level errors.
//!
//! Errors are deliberately coarse and carry no backend detail, so a transport
//! adapter can expose them without creating an oracle. In particular every
//! decryption failure caused by tampering or a wrong `info`/`aad` is the same
//! opaque [`CryptoServiceError::AuthenticationFailed`].

use core::fmt;

use crypt_guard_core::pq_hpke::{EnvelopeError, Error as HpkeError};

/// Errors returned by the crypto service and its providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoServiceError {
    /// The provider does not implement this operation or algorithm.
    Unsupported,
    /// The key does not exist or is not visible to the caller.
    NotFound,
    /// The caller may not perform this operation on this key.
    Forbidden,
    /// Lifecycle or version conflict (e.g. key disabled, already exists).
    Conflict,
    /// Malformed request or cryptographic input.
    Malformed,
    /// Authentication of a ciphertext failed. Intentionally opaque.
    AuthenticationFailed,
    /// The provider is temporarily unavailable.
    Unavailable,
    /// Capacity exhausted; the request was not executed.
    Overloaded,
    /// An internal invariant failed.
    Internal,
}

impl CryptoServiceError {
    /// Stable, non-secret error class name for logs and metrics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::Conflict => "conflict",
            Self::Malformed => "malformed",
            Self::AuthenticationFailed => "authentication_failed",
            Self::Unavailable => "unavailable",
            Self::Overloaded => "overloaded",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for CryptoServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "operation not supported",
            Self::NotFound => "key not found",
            Self::Forbidden => "operation not permitted",
            Self::Conflict => "key state conflict",
            Self::Malformed => "malformed request",
            Self::AuthenticationFailed => "authentication failed",
            Self::Unavailable => "crypto provider unavailable",
            Self::Overloaded => "crypto service overloaded",
            Self::Internal => "internal error",
        })
    }
}

impl std::error::Error for CryptoServiceError {}

impl From<HpkeError> for CryptoServiceError {
    fn from(err: HpkeError) -> Self {
        match err {
            HpkeError::AuthenticationFailed => Self::AuthenticationFailed,
            HpkeError::UnavailableCapability { .. } | HpkeError::ExportOnlyAead => {
                Self::Unsupported
            }
            HpkeError::KemMismatch { .. }
            | HpkeError::InvalidRecipientPublicKey
            | HpkeError::InvalidEncapsulation
            | HpkeError::InvalidPskInputs { .. }
            | HpkeError::OutputLengthTooLarge { .. }
            | HpkeError::InputLengthTooLarge { .. } => Self::Malformed,
            HpkeError::MessageLimitReached
            | HpkeError::InvalidRecipientPrivateKey
            | HpkeError::InternalInvariant => Self::Internal,
        }
    }
}

impl From<EnvelopeError> for CryptoServiceError {
    fn from(_: EnvelopeError) -> Self {
        Self::Malformed
    }
}
