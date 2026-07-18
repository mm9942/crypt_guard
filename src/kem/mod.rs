//! KEM (Key Encapsulation Mechanism) backend trait and ML-KEM implementations.
//!
//! # Responsibility scope
//! This module owns the abstract [`KemBackend`] trait, the stable [`KemId`] identifier enum,
//! and the concrete ML-KEM-512/768/1024 implementations backed by the RustCrypto `ml-kem`
//! crate (FIPS 203). Typed newtypes for key material live in [`types`].
//!
//! Size markers and KEM-specific newtypes are NOT re-exported through `crate::*`; callers
//! import them directly from `crypt_guard::kem`.
//!
//! # Key types exported
//! - [`KemBackend`] — core trait
//! - [`KemId`] — algorithm identifier
//! - [`types::MlKemPublicKey`], [`types::MlKemSecretKey`], [`types::KemCiphertext`],
//!   [`types::KemSharedSecret`]
//! - (behind `ml-kem-backend`) [`ml_kem::MlKem512Impl`], [`ml_kem::MlKem768Impl`],
//!   [`ml_kem::MlKem1024Impl`]
//!
//! # Concurrency
//! All types are `Send + Sync`. The trait requires `Send + Sync + 'static` on implementors.
//!
//! # Errors
//! See [`crate::error::CryptError`]: `EncapsulationError`, `DecapsulationError`,
//! `InvalidKemPublicKey`, `InvalidKemSecretKey`, `InvalidKemCiphertext`.
//!
//! # Examples
//! ```rust,no_run
//! #[cfg(feature = "ml-kem-backend")]
//! {
//!     use crypt_guard::kem::{KemBackend, backend::KemId, ml_kem::MlKem768Impl};
//! }
//! ```

pub mod backend;
pub mod types;

#[cfg(feature = "ml-kem-backend")]
pub mod ml_kem;

pub use backend::{KemBackend, KemId};
pub use types::{KemCiphertext, KemSharedSecret, KemSize, MlKemPublicKey, MlKemSecretKey};
