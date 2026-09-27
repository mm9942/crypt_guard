//! # crypt_guard_hyper
//!
//! Hyper/HTTP adapter for the CryptGuard crypto service. It owns only the
//! transport mapping: routing, bounded bodies, response encoding and error
//! mapping. All cryptographic state stays in `crypt_guard_service`.
//!
//! Use it through the facade: `crypt_guard = { features = ["hyper"] }`, then
//! `crypt_guard::hyper::…`.
//!
//! ## The clone boundary
//!
//! ```text
//! CryptoService (non-Clone, owns provider/keys)
//!   └─ ConcurrencyLimit
//!       └─ Buffer ── NetworkHandle (Clone: channel sender only)
//!           └─ CryptoHttpService (Clone: handle + config)
//!               └─ TowerToHyperService ── Hyper
//! ```
//!
//! ```no_run
//! use crypt_guard_hyper::{into_hyper, CryptoHttpService, HttpConfig};
//! use crypt_guard_service::{network_handle, CryptoService, NullProvider, StackConfig};
//!
//! # async fn run() {
//! // Inside a Tokio runtime:
//! let handle = network_handle(CryptoService::new(NullProvider), StackConfig::default());
//! let hyper_service = into_hyper(CryptoHttpService::new(handle, HttpConfig::default()));
//! // Pass `hyper_service` to `hyper::server::conn::http1::Builder::serve_connection`.
//! # let _ = hyper_service;
//! # }
//! ```
//!
//! ## Status
//!
//! All reference routes are decoded ([`codec`]), authenticated
//! ([`Authenticator`]) and forwarded to the service. Request bodies are
//! bounded and collected into zeroizing memory ([`collect_secret`]).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]

pub mod auth;
pub mod body;
pub mod codec;
mod config;
mod error;
pub mod route;
mod service;

pub use auth::{Anonymous, Authenticator, BearerTokens};
pub use body::{collect_secret, BodyError, SecretBody};
pub use config::{BodyLimits, HttpConfig};
pub use error::{error_response, status_for, AdapterError, Result};
pub use hyper_util::service::TowerToHyperService;
pub use service::{CryptoHttpService, ResponseBody};

/// Bridge a [`CryptoHttpService`] into Hyper's service trait using the
/// official `hyper_util` adapter.
pub fn into_hyper<S, A>(
    service: CryptoHttpService<S, A>,
) -> TowerToHyperService<CryptoHttpService<S, A>> {
    TowerToHyperService::new(service)
}
