//! Mapping of service errors to HTTP responses.
//!
//! Responses carry only a status and a fixed, generic reason. No backend or
//! cryptographic detail is exposed, so e.g. a tampered ciphertext and a wrong
//! `aad` are indistinguishable to the caller.

use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::Full;

use crypt_guard_service::CryptoServiceError;

use crate::config::HttpConfig;

/// HTTP status for a service error.
pub fn status_for(err: CryptoServiceError, config: &HttpConfig) -> StatusCode {
    match err {
        CryptoServiceError::Malformed => StatusCode::BAD_REQUEST,
        CryptoServiceError::AuthenticationFailed => StatusCode::UNPROCESSABLE_ENTITY,
        CryptoServiceError::NotFound => StatusCode::NOT_FOUND,
        CryptoServiceError::Forbidden if config.hide_forbidden_keys => StatusCode::NOT_FOUND,
        CryptoServiceError::Forbidden => StatusCode::FORBIDDEN,
        CryptoServiceError::Conflict => StatusCode::CONFLICT,
        CryptoServiceError::Unsupported => StatusCode::NOT_IMPLEMENTED,
        CryptoServiceError::Unavailable | CryptoServiceError::Overloaded => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
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
pub fn error_response(err: CryptoServiceError, config: &HttpConfig) -> Response<Full<Bytes>> {
    status_response(status_for(err, config))
}
