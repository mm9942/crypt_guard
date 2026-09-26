//! Mapping of service errors to HTTP responses.
//!
//! Responses carry only a status and a fixed, generic reason. No backend or
//! cryptographic detail is exposed, so e.g. a tampered ciphertext and a wrong
//! `aad` are indistinguishable to the caller.

use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::Full;

use crypt_guard_service::CryptoServiceError;

use crate::codec::CodecError;
use crate::config::HttpConfig;
use crate::route::RouteError;
use crate::{body::BodyError, service::ResponseBody};

/// HTTP status for a service error.
pub fn status_for(err: CryptoServiceError, config: &HttpConfig) -> StatusCode {
    match err {
        CryptoServiceError::Malformed => StatusCode::BAD_REQUEST,
        CryptoServiceError::AuthenticationFailed => StatusCode::UNPROCESSABLE_ENTITY,
        CryptoServiceError::Unauthenticated => StatusCode::UNAUTHORIZED,
        CryptoServiceError::NotFound => StatusCode::NOT_FOUND,
        CryptoServiceError::Forbidden if config.hide_forbidden_keys => StatusCode::NOT_FOUND,
        CryptoServiceError::Forbidden => StatusCode::FORBIDDEN,
        CryptoServiceError::Conflict => StatusCode::CONFLICT,
        CryptoServiceError::Unsupported => StatusCode::NOT_IMPLEMENTED,
        CryptoServiceError::Unavailable | CryptoServiceError::Overloaded => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        // `CryptoServiceError` is `#[non_exhaustive]` from this crate's point
        // of view, so this wildcard is required even though every variant
        // known today is listed explicitly above.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Result alias for fallible operations in this crate.
///
/// Defaults the error type to [`AdapterError`] so most call sites can write
/// `Result<T>`; a caller that needs a different error type still names it
/// explicitly (`Result<T, OtherError>`).
pub type Result<T, E = AdapterError> = core::result::Result<T, E>;

/// Central transport-level error for the hyper adapter.
///
/// Every fallible step of request handling — routing, body collection,
/// frame decoding and the crypto service call itself — reports through this
/// type, so [`crate::service::CryptoHttpService`] can turn any failure into
/// a response with one call to [`AdapterError::into_response`].
#[non_exhaustive]
pub enum AdapterError {
    /// The request did not match a route.
    Route(RouteError),
    /// The request body could not be collected.
    Body(BodyError),
    /// The request or response frame could not be decoded or encoded.
    Codec(CodecError),
    /// The crypto service reported an error.
    Service(CryptoServiceError),
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Route(_) => f.write_str("invalid route"),
            Self::Body(_) => f.write_str("invalid request body"),
            Self::Codec(_) => f.write_str("malformed request"),
            Self::Service(err) => core::fmt::Display::fmt(err, f),
        }
    }
}

impl core::fmt::Debug for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AdapterError({self})")
    }
}

impl std::error::Error for AdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Route(err) => Some(err),
            Self::Body(err) => Some(err),
            Self::Codec(err) => Some(err),
            Self::Service(err) => Some(err),
        }
    }
}

impl From<RouteError> for AdapterError {
    fn from(err: RouteError) -> Self {
        Self::Route(err)
    }
}

impl From<BodyError> for AdapterError {
    fn from(err: BodyError) -> Self {
        Self::Body(err)
    }
}

impl From<CodecError> for AdapterError {
    fn from(err: CodecError) -> Self {
        Self::Codec(err)
    }
}

impl From<CryptoServiceError> for AdapterError {
    fn from(err: CryptoServiceError) -> Self {
        Self::Service(err)
    }
}

impl AdapterError {
    /// HTTP status for this error, reproducing exactly the mapping
    /// `handle()` used before errors were centralized here.
    pub fn status(&self, config: &HttpConfig) -> StatusCode {
        match self {
            Self::Route(RouteError::NotFound) => StatusCode::NOT_FOUND,
            Self::Route(RouteError::MethodNotAllowed) => StatusCode::METHOD_NOT_ALLOWED,
            Self::Route(RouteError::InvalidKey) => StatusCode::BAD_REQUEST,
            Self::Body(BodyError::TooLarge) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Body(BodyError::Invalid) => StatusCode::BAD_REQUEST,
            Self::Codec(_) => StatusCode::BAD_REQUEST,
            Self::Service(err) => status_for(*err, config),
        }
    }

    /// Turn this error into a response.
    ///
    /// A [`Self::Service`] error goes through [`error_response`], so a
    /// retryable error still carries its `Retry-After` header; every other
    /// variant maps to a plain status response with no headers beyond the
    /// ones [`crate::service::CryptoHttpService`] adds to every response.
    pub fn into_response(self, config: &HttpConfig) -> Response<ResponseBody> {
        match self {
            Self::Service(err) => error_response(err, config),
            other => status_response(other.status(config)),
        }
    }
}

/// Build a plain-text response whose body is only the canonical status reason.
pub fn status_response(status: StatusCode) -> Response<Full<Bytes>> {
    let reason = status.canonical_reason().unwrap_or("error");
    let mut response = Response::new(Full::new(Bytes::from_static(reason.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Response for a service error.
///
/// A retryable error ([`CryptoServiceError::is_retryable`]) additionally carries a
/// `Retry-After` header, so every `503` produced through this function has
/// one regardless of call site.
pub fn error_response(err: CryptoServiceError, config: &HttpConfig) -> Response<Full<Bytes>> {
    let mut response = status_response(status_for(err, config));
    if let Some(retry_after) = retry_after_for(err) {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            header::HeaderValue::from_static(retry_after),
        );
    }
    response
}

/// The `Retry-After` header value for a service error, or `None` when the
/// error is not retryable.
///
/// Every error for which this returns `Some` describes a transient
/// provider/transport condition ([`CryptoServiceError::is_retryable`]); the
/// caller may retry the same request, provided the operation it sent is
/// idempotent (never auto-retry a mutation such as generate, rotate,
/// disable, enable or destroy on the strength of this alone).
pub fn retry_after_for(err: CryptoServiceError) -> Option<&'static str> {
    err.is_retryable().then_some("1")
}
