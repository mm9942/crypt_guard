//! The clone boundary between crypto state and the network.
//!
//! [`network_handle`] and its panic-free variant [`try_network_handle`] wrap
//! a non-`Clone` [`CryptoService`] in `Buffer(ConcurrencyLimit(service))` and
//! return the cloneable [`NetworkHandle`]. Prefer [`try_network_handle`]: it
//! reports a missing Tokio runtime or an unusable [`StackConfig`] as a typed
//! [`CryptoServiceError`] instead of panicking.

use tower::{
    buffer::Buffer,
    limit::{concurrency::future::ResponseFuture, ConcurrencyLimit},
    BoxError,
};

use crate::{
    error::CryptoServiceError,
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
///
/// Both must be in `1..=tokio::sync::Semaphore::MAX_PERMITS`
/// (`usize::MAX >> 3`); [`try_network_handle`] rejects anything else with
/// [`CryptoServiceError::Malformed`].
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

/// Largest capacity Tokio's channel and semaphore accept without panicking.
const MAX_CAPACITY: usize = tokio::sync::Semaphore::MAX_PERMITS;

/// Whether `capacity` is accepted by both `tokio::sync::mpsc::channel` (queue)
/// and `tokio::sync::Semaphore::new` (in-flight limit) and is usable: a zero
/// queue panics, a zero in-flight limit never becomes ready.
const fn capacity_is_valid(capacity: usize) -> bool {
    capacity != 0 && capacity <= MAX_CAPACITY
}

/// Build `Buffer(ConcurrencyLimit(service))` and return the cloneable handle.
///
/// This is the original, panicking constructor and is kept unchanged for
/// compatibility; [`try_network_handle`] is the panic-free variant and should
/// be preferred in new code.
///
/// # Panics
///
/// Must be called within a Tokio runtime: the buffer worker is spawned with
/// `tokio::spawn`. Also panics if `queue_bound` is zero, or if `queue_bound`
/// or `max_in_flight` exceeds `tokio::sync::Semaphore::MAX_PERMITS`. A
/// `max_in_flight` of zero does not panic, but the handle then never becomes
/// ready.
pub fn network_handle<P: CryptoProvider>(
    service: CryptoService<P>,
    config: StackConfig,
) -> NetworkHandle {
    let limited = ConcurrencyLimit::new(service, config.max_in_flight);
    Buffer::new(limited, config.queue_bound)
}

/// Panic-free [`network_handle`]: build `Buffer(ConcurrencyLimit(service))`
/// and return the cloneable handle, or a typed error.
///
/// The buffer worker is spawned on the Tokio runtime of the calling context
/// (`tokio::runtime::Handle::try_current`), exactly where [`network_handle`]
/// would spawn it with `tokio::spawn`.
///
/// # Errors
///
/// Checked in this order, before anything is built or spawned:
///
/// - [`CryptoServiceError::Malformed`]: `config.queue_bound` or
///   `config.max_in_flight` is zero or exceeds
///   `tokio::sync::Semaphore::MAX_PERMITS`.
/// - [`CryptoServiceError::Unavailable`]: no Tokio runtime is present in the
///   calling context.
///
/// On error `service` is dropped (an [`InMemoryProvider`](crate::InMemoryProvider)
/// zeroizes its key material on drop). If the runtime is already shutting
/// down, the handle is returned but every call fails; [`service_error`] maps
/// that to [`CryptoServiceError::Unavailable`].
pub fn try_network_handle<P: CryptoProvider>(
    service: CryptoService<P>,
    config: StackConfig,
) -> Result<NetworkHandle, CryptoServiceError> {
    if !capacity_is_valid(config.queue_bound) || !capacity_is_valid(config.max_in_flight) {
        return Err(CryptoServiceError::Malformed);
    }
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| CryptoServiceError::Unavailable)?;

    let limited = ConcurrencyLimit::new(service, config.max_in_flight);
    // `Buffer::pair` is `Buffer::new` without the panicking `tokio::spawn`.
    let (handle, worker) = NetworkHandle::pair(limited, config.queue_bound);
    // Detach the worker: it runs until every clone of the handle is dropped.
    drop(runtime.spawn(worker));
    Ok(handle)
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
