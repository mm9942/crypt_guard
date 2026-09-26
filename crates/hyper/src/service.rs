//! The cloneable HTTP-facing service.

use core::{
    convert::Infallible,
    future::{poll_fn, Future},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use std::sync::Arc;

use bytes::Bytes;
use http::{header, HeaderValue, Request, Response};
use http_body::Body;
use http_body_util::Full;
use tower_service::Service;

use crypt_guard_service::{
    service_error, CryptoRequest, CryptoResponse, RequestContext, RequestId,
};

use crate::{
    auth::{Anonymous, Authenticator},
    body::collect_secret,
    codec::{decode_request, encode_response},
    config::HttpConfig,
    error::AdapterError,
    route,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Response body of [`CryptoHttpService`].
pub type ResponseBody = Full<Bytes>;

/// HTTP adapter over a cloneable crypto service handle.
///
/// `Clone` is required by Hyper's `TowerToHyperService`. Cloning copies only
/// the inner **network handle** (normally a
/// [`NetworkHandle`](crypt_guard_service::NetworkHandle), i.e. a channel
/// sender), shared configuration and the shared authenticator; no key
/// material and no cryptographic context is ever reachable from this type.
pub struct CryptoHttpService<S, A = Anonymous> {
    inner: S,
    config: Arc<HttpConfig>,
    authenticator: Arc<A>,
    next_request_id: Arc<AtomicU64>,
}

impl<S: Clone, A> Clone for CryptoHttpService<S, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: Arc::clone(&self.config),
            authenticator: Arc::clone(&self.authenticator),
            next_request_id: Arc::clone(&self.next_request_id),
        }
    }
}

impl<S> CryptoHttpService<S, Anonymous> {
    /// Wrap a cloneable crypto service handle; every request is anonymous
    /// until an authenticator is set with [`with_authenticator`](Self::with_authenticator).
    pub fn new(inner: S, config: HttpConfig) -> Self {
        Self {
            inner,
            config: Arc::new(config),
            authenticator: Arc::new(Anonymous),
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl<S, A> CryptoHttpService<S, A> {
    /// Replace the authenticator.
    pub fn with_authenticator<A2: Authenticator>(
        self,
        authenticator: A2,
    ) -> CryptoHttpService<S, A2> {
        CryptoHttpService {
            inner: self.inner,
            config: self.config,
            authenticator: Arc::new(authenticator),
            next_request_id: self.next_request_id,
        }
    }

    /// The adapter configuration.
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }
}

impl<S, A> core::fmt::Debug for CryptoHttpService<S, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoHttpService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<S, A, B> Service<Request<B>> for CryptoHttpService<S, A>
where
    S: Service<CryptoRequest, Response = CryptoResponse> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send,
    A: Authenticator,
    B: Body<Data = Bytes> + Send + 'static,
{
    type Response = Response<ResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Backpressure is applied per request on the cloned inner handle, so
        // the HTTP connection itself is always ready.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let config = Arc::clone(&self.config);
        let authenticator = Arc::clone(&self.authenticator);
        let request_id = RequestId(u128::from(
            self.next_request_id.fetch_add(1, Ordering::Relaxed),
        ));
        Box::pin(async move {
            let response = handle(inner, &config, &*authenticator, request_id, request).await;
            Ok(finalize(response, request_id))
        })
    }
}

async fn handle<S, A, B>(
    inner: S,
    config: &HttpConfig,
    authenticator: &A,
    request_id: RequestId,
    request: Request<B>,
) -> Response<ResponseBody>
where
    S: Service<CryptoRequest, Response = CryptoResponse>,
    S::Error: Into<BoxError>,
    A: Authenticator,
    B: Body<Data = Bytes>,
{
    try_handle(inner, config, authenticator, request_id, request)
        .await
        .unwrap_or_else(|err| err.into_response(config))
}

/// The fallible core of [`handle`].
///
/// Every failure mode reports through [`AdapterError`] via `?`, and
/// [`handle`] turns whichever one comes back into a response with
/// [`AdapterError::into_response`]. This must stay behaviorally identical to
/// the error handling `handle` used to do inline: same ordering
/// (authenticate before reading the body), same `drop(body)` right after
/// decoding, and the same mapping from a `poll_ready`/`call` failure through
/// [`service_error`] into [`AdapterError::Service`].
///
/// # Errors
///
/// Returns [`AdapterError::Route`] when the request does not match a route,
/// [`AdapterError::Body`] when the request body cannot be collected,
/// [`AdapterError::Codec`] when the body cannot be decoded into an
/// operation, and [`AdapterError::Service`] when authentication or the
/// crypto service itself reports an error.
async fn try_handle<S, A, B>(
    mut inner: S,
    config: &HttpConfig,
    authenticator: &A,
    request_id: RequestId,
    request: Request<B>,
) -> Result<Response<ResponseBody>, AdapterError>
where
    S: Service<CryptoRequest, Response = CryptoResponse>,
    S::Error: Into<BoxError>,
    A: Authenticator,
    B: Body<Data = Bytes>,
{
    let (parts, body) = request.into_parts();

    let route = route::parse(&parts.method, parts.uri.path())?;

    // Authenticate before reading the body, so unauthenticated callers cannot
    // make the server buffer (and copy) request payloads.
    let principal = authenticator.authenticate(&parts)?;

    let limit = route.op.body_limit(&config.max_body);
    let body = collect_secret(body, limit).await?;

    // The body (possibly plaintext) is dropped, zeroized, right after
    // decoding; secret fields have been copied into their own `SecretBytes`.
    let operation = decode_request(route.op, route.key, &body)?;
    drop(body);

    let context = RequestContext {
        request_id,
        principal,
    };
    poll_fn(|cx| inner.poll_ready(cx))
        .await
        .map_err(|err| service_error(err.into()))?;
    let response = inner
        .call(CryptoRequest::with_context(context, operation))
        .await
        .map_err(|err| service_error(err.into()))?;
    Ok(encode_response(response))
}

/// The name of the request-id header attached to every response.
const REQUEST_ID_HEADER: &str = "x-request-id";

fn finalize(mut response: Response<ResponseBody>, request_id: RequestId) -> Response<ResponseBody> {
    // KMS responses (including public keys and errors) must never be cached
    // by intermediaries.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    // Every response, success or error, carries the id of the request that
    // produced it: lowercase hex, no padding. This lets a caller correlate a
    // logged failure with a specific request without exposing any backend or
    // cryptographic detail.
    if let Ok(name) = header::HeaderName::from_bytes(REQUEST_ID_HEADER.as_bytes()) {
        if let Ok(value) = HeaderValue::from_str(&format!("{:x}", request_id.0)) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
