//! Legacy Kyber KEM key-control and cipher implementations backed by `pqcrypto-kyber`.
//!
//! This module is gated behind the `legacy-pqclean` feature. It contains the
//! verbatim pqcrypto-backed code moved wholesale from `src/core/kyber/` in Phase 1.
//! No crypto logic was changed during the move.
//!
//! # Key types exported
//! - [`KeyControKyber1024`], [`KeyControKyber768`], [`KeyControKyber512`] — KEM wrappers
//! - [`KeyControl<T>`] — generic key-control struct
//! - [`KyberKeyFunctions`] — trait for KEM operations
//! - [`Kyber512`], [`Kyber768`], [`Kyber1024`] — legacy size markers
//!
//! # Feature gate
//! Compiled only when `cfg(feature = "legacy-pqclean")` is active.

pub mod key_controler;

mod kyber_crypto_aes;
mod kyber_crypto_aes_ctr;
mod kyber_crypto_aes_gcm_siv;
mod kyber_crypto_aes_xts;
mod kyber_crypto_xchacha;
mod kyber_crypto_xchacha_poly;

pub use key_controler::*;

// Legacy size markers for the pqcrypto-backed Kyber KEM variants.
// These re-export the definitions from crate::core::kyber so that legacy call sites
// using `Kyber512` etc. keep resolving to the same types already used in the hub.
pub use crate::core::kyber::{Kyber1024, Kyber512, Kyber768};
