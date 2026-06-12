//! HKDF-based key schedule with domain separation (Phase 2 — always compiled).
//!
//! # Responsibility scope
//! This module provides a typed, domain-separated key derivation function built on top
//! of HKDF-SHA256/512 (RFC 5869). It transforms a raw KEM shared secret and an optional
//! salt into a named `SessionKey` suitable for direct use with AEAD cipher backends.
//!
//! # Key types exported
//! - [`derive_session_key`] — primary derivation function (SHA-256)
//! - [`derive_session_key_sha512`] — SHA-512 variant
//! - Label constants: [`LABEL_XCHACHA20POLY1305`], [`LABEL_AESGCMSIV`], [`LABEL_AES`],
//!   [`LABEL_XCHACHA20`], [`LABEL_GENERIC`]
//! - [`types::HkdfSalt`], [`types::HmacKey`], [`types::SessionKey`]
//!
//! # Concurrency
//! All functions are pure; no shared mutable state.
//!
//! # Errors
//! See [`crate::error::CryptError`]: `CustomError` if HKDF output length is invalid
//! (cannot occur in practice with 32-byte output).
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::kdf::{derive_session_key, LABEL_XCHACHA20POLY1305, types::HkdfSalt};
//! let key = derive_session_key(&[0u8; 32], &HkdfSalt::zero(32), LABEL_XCHACHA20POLY1305).unwrap();
//! assert_eq!(key.as_ref().len(), 32);
//! ```

pub mod types;
pub mod hkdf;

pub use hkdf::{
    derive_session_key,
    derive_session_key_sha512,
    LABEL_XCHACHA20POLY1305,
    LABEL_AESGCMSIV,
    LABEL_AES,
    LABEL_XCHACHA20,
    LABEL_GENERIC,
};
pub use types::{HkdfSalt, HmacKey, SessionKey};

// ── Legacy compatibility re-exports ───────────────────────────────────────────
// These types previously lived in `crate::core::kdf` and were imported by
// tests via `use crate::kdf::*`. They are re-exported here for backward
// compatibility so the test suite compiles without modification.
#[cfg(feature = "legacy-pqclean")]
pub use crate::core::kdf::{Signature, Detached, Message, Falcon512, Falcon1024, Dilithium2, Dilithium3, Dilithium5};
