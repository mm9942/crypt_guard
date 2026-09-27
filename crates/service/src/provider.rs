//! Crypto providers.
//!
//! A provider executes operations against keys it owns. It never hands out
//! private key bytes: "the private key never leaves the provider" is a
//! property of this trait, not a convention. In-process keys, an encrypted
//! file store, a TPM, PKCS#11/HSM or a remote KMS all implement the same
//! contract.

use core::task::{Context, Poll};

use crate::{
    error::CryptoServiceError,
    op::{CryptoRequest, CryptoResponse},
};

/// Executes crypto operations. Owned by exactly one [`CryptoService`].
///
/// [`CryptoService`]: crate::CryptoService
pub trait CryptoProvider: Send + 'static {
    /// Report whether the provider can accept a request now.
    ///
    /// Return `Pending` (and arrange a wake-up) while e.g. an HSM queue is
    /// full, or an error while the key store is unavailable. The default is
    /// always ready.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), CryptoServiceError>> {
        Poll::Ready(Ok(()))
    }

    /// Execute one request. The request, including any secret input, is moved
    /// in and dropped (zeroized) when execution finishes.
    fn execute(&mut self, request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError>;
}

/// A provider that supports nothing. Useful for wiring and tests.
#[derive(Debug, Default)]
pub struct NullProvider;

impl CryptoProvider for NullProvider {
    fn execute(&mut self, _request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        Err(CryptoServiceError::Unsupported)
    }
}
