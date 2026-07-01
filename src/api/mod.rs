//! Safe public API over the Phase 3 CGv2 envelope protocol.
//!
//! This module exposes the small safe surface from the redesign plan:
//! typed `Encryptor` / `Decryptor` entry points with staged builders and no
//! manual nonce handling in the default flow.
//!
//! It additionally exposes the HPKE-style (RFC 9180) single-shot [`seal`] /
//! [`open`] functions (see [`hpke`]), which mirror `SealBase` / `OpenBase` over
//! the same envelope path while binding caller-supplied `info` and `aad`.

pub mod hpke;
mod open;
mod seal;

use crate::markers::{AesGcmSiv, XChaCha20Poly1305};

pub use open::{Decryptor, DecryptorBuilder, MissingSecretKey, WithSecretKey};
pub use seal::{
    Encryptor, EncryptorBuilder, MissingPlaintext, MissingRecipient, WithPlaintext, WithRecipient,
};

// HPKE-style single-shot entry points. `src/lib.rs` is owned by another agent;
// once it adds `pub use api::{seal as hpke_seal, open as hpke_open};` these
// become crate-root accessible. Until then they are reachable as
// `crypt_guard::api::{seal, open}` and `crypt_guard::api::hpke::{seal, open}`.
pub use hpke::{open, seal};

mod private {
    pub trait Sealed {}
}

/// Marker trait for algorithms allowed in the safe default API.
///
/// Only authenticated AEAD markers are supported here. Non-AEAD and legacy cipher
/// markers remain available through the lower-level APIs.
pub trait AuthenticatedAead: private::Sealed {}

impl private::Sealed for XChaCha20Poly1305 {}
impl AuthenticatedAead for XChaCha20Poly1305 {}

impl private::Sealed for AesGcmSiv {}
impl AuthenticatedAead for AesGcmSiv {}
