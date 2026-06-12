//! Digital signature backend trait and FIPS 204/205 implementations.
//!
//! # Responsibility scope
//! This module owns the abstract [`SignAlgorithm`] trait, the [`SignatureMode`] markers,
//! the generic [`hub::Signature<A, S>`] struct, and the concrete algorithm implementations:
//! - ML-DSA 44/65/87 (FIPS 204, behind `ml-dsa-backend` feature)
//! - SLH-DSA Shake128f/s, 192f/s, 256f/s (FIPS 205, behind `sign-slhdsa` feature)
//!
//! # Feature gates
//! | Feature          | Module       | Types added                              |
//! |---|---|---|
//! | `ml-dsa-backend` | `ml_dsa`     | `MlDsa44Impl`, `MlDsa65Impl`, `MlDsa87Impl` |
//! | `sign-slhdsa`    | `slh_dsa`    | `SlhDsaShake128fImpl`, … (6 variants)   |
//!
//! The `algorithm` and `hub` modules are unconditionally compiled.
//!
//! # Key types exported
//! - [`SignAlgorithm`] — core trait
//! - [`algorithm::Detached`], [`algorithm::MessageMode`] — mode markers
//! - [`hub::Signature`] — generic container
//!
//! # Concurrency
//! All types are `Send + Sync`.
//!
//! # Examples
//! ```rust,no_run
//! #[cfg(feature = "ml-dsa-backend")]
//! {
//!     use crypt_guard::sign::{SignAlgorithm, ml_dsa::MlDsa65Impl};
//!     use crypt_guard::kem::backend::OsRng;
//!     let mut rng = OsRng;
//!     let (sk, vk) = MlDsa65Impl::keypair(&mut rng).unwrap();
//!     let sig = MlDsa65Impl::sign(&sk, b"hello").unwrap();
//!     MlDsa65Impl::verify(&vk, b"hello", &sig).unwrap();
//! }
//! ```

pub mod algorithm;
pub mod hub;

#[cfg(feature = "ml-dsa-backend")]
pub mod ml_dsa;

#[cfg(feature = "sign-slhdsa")]
pub mod slh_dsa;

pub use algorithm::{SignAlgorithm, SignatureMode, Detached, MessageMode, Keypair};
pub use hub::Signature as NewSignature;
