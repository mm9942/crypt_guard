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
use http::{header, HeaderValue, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::Full;
use tower_service::Service;

use crypt_guard_service::{
    service_error, CryptoRequest, CryptoResponse, RequestContext, RequestId,
};

use crate::{
    auth::{Anonymous, Authenticator},
    body::{collect_secret, BodyError},
    codec::{decode_request, encode_response},
    config::HttpConfig,
    error::{error_response, status_response},
    route::{self, RouteError},
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
    pub fn with_authenticator<A2: Authenticator>(self, authenticator: A2) -> CryptoHttpService<S, A2> {
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
            Ok(finalize(response))
        })
    }
}

async fn handle<S, A, B>(
    mut inner: S,
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
    let (parts, body) = request.into_parts();

    let route = match route::parse(&parts.method, parts.uri.path()) {
        Ok(route) => route,
        Err(RouteError::NotFound) => return status_response(StatusCode::NOT_FOUND),
        Err(RouteError::MethodNotAllowed) => {
            return status_response(StatusCode::METHOD_NOT_ALLOWED)
        }
        Err(RouteError::InvalidKey) => return status_response(StatusCode::BAD_REQUEST),
    };

    // Authenticate before reading the body, so unauthenticated callers cannot
    // make the server buffer (and copy) request payloads.
    let principal = match authenticator.authenticate(&parts) {
        Ok(principal) => principal,
        Err(err) => return error_response(err, config),
    };

    let limit = route.op.body_limit(&config.max_body);
    let body = match collect_secret(body, limit).await {
        Ok(body) => body,
        Err(BodyError::TooLarge) => return status_response(StatusCode::PAYLOAD_TOO_LARGE),
        Err(BodyError::Invalid) => return status_response(StatusCode::BAD_REQUEST),
    };

    // The body (possibly plaintext) is dropped, zeroized, right after
    // decoding; secret fields have been copied into their own `SecretBytes`.
    let operation = match decode_request(route.op, route.key, &body) {
        Ok(operation) => operation,
        Err(_) => return status_response(StatusCode::BAD_REQUEST),
    };
    drop(body);

    let context = RequestContext {
        request_id,
        principal,
    };
    if let Err(err) = poll_fn(|cx| inner.poll_ready(cx)).await {
        return error_response(service_error(err.into()), config);
    }
    match inner.call(CryptoRequest::with_context(context, operation)).await {
        Ok(response) => encode_response(response),
        Err(err) => error_response(service_error(err.into()), config),
    }
}

fn finalize(mut response: Response<ResponseBody>) -> Response<ResponseBody> {
    // KMS responses (including public keys and errors) must never be cached
    // by intermediaries.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
