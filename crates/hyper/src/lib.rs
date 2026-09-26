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
//! Skeleton: the reference routes are matched and bounded, `describe` and
//! `public` are forwarded to the service, and the request codecs of the
//! remaining operations answer `501 Not Implemented` for now.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod error;
pub mod route;
mod service;

pub use config::{BodyLimits, HttpConfig};
pub use error::{error_response, status_for};
pub use hyper_util::service::TowerToHyperService;
pub use service::{CryptoHttpService, ResponseBody};

/// Bridge a [`CryptoHttpService`] into Hyper's service trait using the
/// official `hyper_util` adapter.
pub fn into_hyper<S>(service: CryptoHttpService<S>) -> TowerToHyperService<CryptoHttpService<S>> {
    TowerToHyperService::new(service)
}
