//! Legacy signature implementations backed by `pqcrypto-falcon` and `pqcrypto-dilithium`.
//!
//! This module re-exports the pqcrypto-backed Falcon and Dilithium types from
//! `crate::core::kdf` for source compatibility. In Phase 3 the implementations
//! will be moved here verbatim; for Phase 1 this shim keeps the public API stable.
//!
//! # Key types re-exported
//! - [`Falcon1024`], [`Falcon512`]
//! - [`Dilithium2`], [`Dilithium3`], [`Dilithium5`]
//! - [`Signature`], [`Detached`], [`Message`] (re-export from kdf)
//! - Traits: [`SignatureFunctions`], [`KeyOperations`]
//!
//! # Feature gate
//! Compiled only when `cfg(feature = "legacy-pqclean")` is active.

pub use crate::core::kdf::{
    Detached, Dilithium2, Dilithium3, Dilithium5, Falcon1024, Falcon512, KeyOperations, KeyVariant,
    Message, Signature, SignatureFunctions,
};
