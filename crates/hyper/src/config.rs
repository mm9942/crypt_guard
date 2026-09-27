//! HTTP adapter configuration.

/// Maximum request body size per operation class, in bytes.
///
/// Bodies are limited *before* they are collected; an unbounded body is never
/// buffered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyLimits {
    /// Key lifecycle and metadata requests (generate, rotate, describe, …).
    pub metadata: usize,
    /// Sign and verify requests.
    pub sign: usize,
    /// Encrypt and decrypt requests.
    pub crypt: usize,
    /// Wrap, unwrap and rewrap requests (key material; kept strict).
    pub import: usize,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            metadata: 4 * 1024,
            sign: 64 * 1024,
            crypt: 1024 * 1024,
            import: 16 * 1024,
        }
    }
}

/// Configuration of [`CryptoHttpService`](crate::CryptoHttpService).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpConfig {
    /// Body limits per operation class.
    pub max_body: BodyLimits,
    /// Report `Forbidden` as `404 Not Found`, so callers cannot tell a key
    /// they may not use from one that does not exist (reduces enumeration).
    pub hide_forbidden_keys: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            max_body: BodyLimits::default(),
            hide_forbidden_keys: true,
        }
    }
}
