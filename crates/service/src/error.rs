//! Service-level errors.
//!
//! Errors are deliberately coarse and carry no backend detail, so a transport
//! adapter can expose them without creating an oracle. In particular every
//! decryption failure caused by tampering or a wrong `info`/`aad` is the same
//! opaque [`CryptoServiceError::AuthenticationFailed`].

use core::fmt;

use crypt_guard_core::error::ErrorKind;
use crypt_guard_core::pq_hpke::{EnvelopeError, Error as HpkeError};

/// Result alias for fallible operations in this crate.
///
/// Defaults the error type to [`CryptoServiceError`] so most call sites can
/// write `Result<T>`; a caller that needs a different error type still names
/// it explicitly (`Result<T, OtherError>`).
pub type Result<T, E = CryptoServiceError> = core::result::Result<T, E>;

/// Errors returned by the crypto service and its providers.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoServiceError {
    /// The provider does not implement this operation or algorithm.
    Unsupported,
    /// The caller presented no valid credentials.
    Unauthenticated,
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
            Self::Unauthenticated => "unauthenticated",
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
            Self::Unauthenticated => "not authenticated",
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

impl fmt::Debug for CryptoServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoServiceError({self})")
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

impl From<ErrorKind> for CryptoServiceError {
    /// Map a core [`ErrorKind`] onto the coarser service error classes.
    ///
    /// `ErrorKind` is `#[non_exhaustive]` from this crate's point of view, so
    /// this match keeps a wildcard arm even though every current variant is
    /// listed explicitly.
    fn from(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::Authentication => Self::AuthenticationFailed,
            ErrorKind::InvalidInput | ErrorKind::InvalidKey | ErrorKind::Encoding => {
                Self::Malformed
            }
            ErrorKind::Unsupported => Self::Unsupported,
            ErrorKind::Io | ErrorKind::Randomness => Self::Unavailable,
            ErrorKind::Limit | ErrorKind::Internal => Self::Internal,
            _ => Self::Internal,
        }
    }
}

impl From<crypt_guard_core::error::CryptError> for CryptoServiceError {
    /// Map a core [`crypt_guard_core::error::CryptError`] onto the service's
    /// coarse error classes via its [`ErrorKind`] classification.
    fn from(err: crypt_guard_core::error::CryptError) -> Self {
        err.kind().into()
    }
}

impl CryptoServiceError {
    /// The subset of [`ErrorKind`] that this error's *crypto-derived* classes
    /// map back onto, or `None` when this error is not derived from a
    /// cryptographic-primitive failure at all.
    ///
    /// This is intentionally partial: [`Self::Unauthenticated`],
    /// [`Self::NotFound`], [`Self::Forbidden`] and [`Self::Conflict`] are
    /// authorization and key-lifecycle classes, not cryptographic-primitive
    /// classes, so they have no faithful [`ErrorKind`] and return `None`
    /// rather than being forced onto an unrelated variant (in particular,
    /// mapping [`Self::Unauthenticated`] onto [`ErrorKind::Authentication`]
    /// would conflate "no credentials presented" with "ciphertext
    /// authentication failed", reintroducing exactly the kind of oracle this
    /// crate's opaque errors are meant to avoid). [`Self::Unavailable`] and
    /// [`Self::Overloaded`] are transport/capacity conditions, not crypto
    /// failures, so they also return `None`.
    pub fn crypto_kind(self) -> Option<ErrorKind> {
        match self {
            Self::AuthenticationFailed => Some(ErrorKind::Authentication),
            Self::Malformed => Some(ErrorKind::InvalidInput),
            Self::Unsupported => Some(ErrorKind::Unsupported),
            Self::Internal => Some(ErrorKind::Internal),
            Self::Unauthenticated
            | Self::NotFound
            | Self::Forbidden
            | Self::Conflict
            | Self::Unavailable
            | Self::Overloaded => None,
        }
    }

    /// Whether the caller may retry the same request unchanged and expect it
    /// to potentially succeed.
    ///
    /// Only [`Self::Unavailable`] and [`Self::Overloaded`] are retryable: both
    /// describe a transient condition in the provider or transport, not a
    /// property of the request itself.
    ///
    /// A retry must be idempotent. Never auto-retry a mutating operation
    /// (generate, rotate, disable, enable, destroy — see `OpKind::is_mutation`)
    /// on the strength of this flag alone: retrying `Unavailable`/`Overloaded`
    /// is only safe for operations whose effect does not compound when
    /// applied twice (or where the caller itself de-duplicates), so a caller
    /// that automatically retries mutations must check that separately.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Unavailable | Self::Overloaded)
    }
}
