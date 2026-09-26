//! The Tower crypto service.

use core::{
    future::{ready, Ready},
    task::{Context, Poll},
};

use tower_service::Service;

use crate::{
    error::CryptoServiceError,
    op::{CryptoRequest, CryptoResponse},
    provider::CryptoProvider,
};

/// Future returned by [`CryptoService`].
///
/// Operations are CPU-bound and synchronous, so the result is ready as soon as
/// `call` returns; no runtime or boxing is involved.
pub type CryptoFuture = Ready<Result<CryptoResponse, CryptoServiceError>>;

/// The crypto service: a Tower [`Service`] over [`CryptoRequest`].
///
/// It owns its provider and is intentionally **not** `Clone`: cloning it would
/// clone key state or force shared ownership of cryptographic state. To hand
/// it to a transport that needs a cloneable service (Hyper's
/// `TowerToHyperService`), wrap it in the bounded buffer stack
/// (`network_handle`, feature `buffer`), which clones only a channel handle.
pub struct CryptoService<P> {
    provider: P,
}

impl<P: CryptoProvider> CryptoService<P> {
    /// Wrap a provider.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Borrow the provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

impl<P> core::fmt::Debug for CryptoService<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoService").finish_non_exhaustive()
    }
}

impl<P: CryptoProvider> Service<CryptoRequest> for CryptoService<P> {
    type Response = CryptoResponse;
    type Error = CryptoServiceError;
    type Future = CryptoFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.provider.poll_ready(cx)
    }

    fn call(&mut self, request: CryptoRequest) -> Self::Future {
        ready(self.provider.execute(request))
    }
}
