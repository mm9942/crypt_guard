//! Safe public API over the Phase 3 CGv2 envelope protocol.
//!
//! This module exposes the small safe surface from the redesign plan:
//! typed `Encryptor` / `Decryptor` entry points with staged builders and no
//! manual nonce handling in the default flow.
//!
//! It additionally exposes the legacy [`hpke`] compatibility module. Its
//! single-shot [`seal`] / [`open`] helpers use CGv2/HFv1 framing and retain
//! historical names for source compatibility; they are not RFC 9180 HPKE.

pub mod hpke;
mod open;
mod seal;

use crate::markers::{AesGcmSiv, XChaCha20Poly1305};

pub use open::{Decryptor, DecryptorBuilder, MissingSecretKey, WithSecretKey};
pub use seal::{
    Encryptor, EncryptorBuilder, MissingPlaintext, MissingRecipient, WithPlaintext, WithRecipient,
};

// Legacy CGv2/HFv1 compatibility entry points. They are also re-exported at the
// crate root with historical `hpke_` names, but do not implement RFC 9180 HPKE.
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
