//! The clone boundary between crypto state and the network.

use tower::{
    buffer::Buffer,
    limit::{concurrency::future::ResponseFuture, ConcurrencyLimit},
    BoxError,
};

use crate::{
    op::CryptoRequest,
    provider::CryptoProvider,
    service::{CryptoFuture, CryptoService},
};

/// Cloneable handle to a [`CryptoService`] running behind a bounded queue.
///
/// Cloning it clones only the channel sender; the service, its provider and
/// all key state stay owned by the single buffer worker. Requests are moved
/// through the channel, never cloned.
///
/// Errors are [`BoxError`]: either the inner
/// [`CryptoServiceError`](crate::CryptoServiceError) (downcast to recover it)
/// or a buffer error when the worker has shut down.
pub type NetworkHandle = Buffer<CryptoRequest, ResponseFuture<CryptoFuture>>;

/// Capacities of the network stack. Queue depth and execution concurrency are
/// deliberately separate knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackConfig {
    /// Requests that may wait in the queue before callers see backpressure.
    pub queue_bound: usize,
    /// Requests that may be in flight inside the service at once.
    pub max_in_flight: usize,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            queue_bound: 128,
            max_in_flight: 32,
        }
    }
}

/// Build `Buffer(ConcurrencyLimit(service))` and return the cloneable handle.
///
/// # Panics
///
/// Must be called within a Tokio runtime: the buffer worker is spawned with
/// `tokio::spawn`. Also panics if `queue_bound` is zero.
pub fn network_handle<P: CryptoProvider>(
    service: CryptoService<P>,
    config: StackConfig,
) -> NetworkHandle {
    let limited = ConcurrencyLimit::new(service, config.max_in_flight);
    Buffer::new(limited, config.queue_bound)
}

/// Recover the typed service error from a [`NetworkHandle`] error.
///
/// Buffer-level failures (worker gone) map to
/// [`Unavailable`](crate::CryptoServiceError::Unavailable).
pub fn service_error(err: BoxError) -> crate::CryptoServiceError {
    match err.downcast::<crate::CryptoServiceError>() {
        Ok(err) => *err,
        Err(_) => crate::CryptoServiceError::Unavailable,
    }
}
