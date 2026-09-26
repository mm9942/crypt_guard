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
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use tower_service::Service;

use crypt_guard_service::{
    service_error, CryptoOperation, CryptoRequest, CryptoResponse, DescribeKey, GetPublicKey,
    RequestId, VerificationResult,
};

use crate::{
    config::HttpConfig,
    error::{error_response, status_response},
    route::{self, Route, RouteError, RouteOp},
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Response body of [`CryptoHttpService`].
pub type ResponseBody = Full<Bytes>;

/// HTTP adapter over a cloneable crypto service handle.
///
/// `Clone` is required by Hyper's `TowerToHyperService`. Cloning copies only
/// the inner **network handle** (normally a
/// [`NetworkHandle`](crypt_guard_service::NetworkHandle), i.e. a channel
/// sender) and shared configuration; no key material and no cryptographic
/// context is ever reachable from this type.
#[derive(Clone)]
pub struct CryptoHttpService<S> {
    inner: S,
    config: Arc<HttpConfig>,
    next_request_id: Arc<AtomicU64>,
}

impl<S> CryptoHttpService<S> {
    /// Wrap a cloneable crypto service handle.
    pub fn new(inner: S, config: HttpConfig) -> Self {
        Self {
            inner,
            config: Arc::new(config),
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// The adapter configuration.
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }
}

impl<S> core::fmt::Debug for CryptoHttpService<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoHttpService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<S, B> Service<Request<B>> for CryptoHttpService<S>
where
    S: Service<CryptoRequest, Response = CryptoResponse> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
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
        let request_id = RequestId(u128::from(
            self.next_request_id.fetch_add(1, Ordering::Relaxed),
        ));
        Box::pin(async move {
            let response = handle(inner, &config, request_id, request).await;
            Ok(finalize(response))
        })
    }
}

async fn handle<S, B>(
    mut inner: S,
    config: &HttpConfig,
    request_id: RequestId,
    request: Request<B>,
) -> Response<ResponseBody>
where
    S: Service<CryptoRequest, Response = CryptoResponse>,
    S::Error: Into<BoxError>,
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let route = match route::parse(request.method(), request.uri().path()) {
        Ok(route) => route,
        Err(RouteError::NotFound) => return status_response(StatusCode::NOT_FOUND),
        Err(RouteError::MethodNotAllowed) => {
            return status_response(StatusCode::METHOD_NOT_ALLOWED)
        }
        Err(RouteError::InvalidKey) => return status_response(StatusCode::BAD_REQUEST),
    };

    let limit = route.op.body_limit(&config.max_body);
    let body = match Limited::new(request.into_body(), limit).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) if err.is::<LengthLimitError>() => {
            return status_response(StatusCode::PAYLOAD_TOO_LARGE)
        }
        Err(_) => return status_response(StatusCode::BAD_REQUEST),
    };

    let operation = match decode(route, body) {
        Some(operation) => operation,
        // The request codecs for body-carrying operations are not part of
        // this skeleton yet.
        None => return status_response(StatusCode::NOT_IMPLEMENTED),
    };

    if let Err(err) = poll_fn(|cx| inner.poll_ready(cx)).await {
        return error_response(service_error(err.into()), config);
    }
    match inner.call(CryptoRequest::new(request_id, operation)).await {
        Ok(response) => encode(response),
        Err(err) => error_response(service_error(err.into()), config),
    }
}

/// Decode a routed request into a service operation.
///
/// Returns `None` for operations whose request codec is not implemented yet.
fn decode(route: Route, _body: Bytes) -> Option<CryptoOperation> {
    let key = route.key?;
    match route.op {
        RouteOp::Describe => Some(CryptoOperation::Describe(DescribeKey { key })),
        RouteOp::PublicKey => Some(CryptoOperation::PublicKey(GetPublicKey { key })),
        _ => None,
    }
}

fn octet_stream(body: Bytes) -> Response<ResponseBody> {
    let mut response = Response::new(Full::new(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
}

/// Encode a service response.
fn encode(response: CryptoResponse) -> Response<ResponseBody> {
    match response {
        CryptoResponse::PublicKey(blob) => octet_stream(Bytes::from(blob.into_inner())),
        CryptoResponse::Ciphertext(blob) => octet_stream(Bytes::from(blob.into_inner())),
        CryptoResponse::Signature(blob) => octet_stream(Bytes::from(blob.into_inner())),
        // One-way secret egress: every network clone of these `Bytes` shares
        // the single zeroizing owner, which is erased when the last clone
        // drops. Copies made by TLS or the kernel are outside that guarantee.
        CryptoResponse::Plaintext(secret) => octet_stream(Bytes::from_owner(secret.into_egress())),
        CryptoResponse::Verification(result) => {
            let text: &'static [u8] = match result {
                VerificationResult::Valid => b"valid",
                VerificationResult::Invalid => b"invalid",
            };
            let mut response = Response::new(Full::new(Bytes::from_static(text)));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        }
        // Metadata / key-creation codecs are not part of this skeleton yet.
        _ => status_response(StatusCode::NOT_IMPLEMENTED),
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
