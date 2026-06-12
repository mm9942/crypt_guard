//! Legacy pqcrypto-backed cryptographic primitives, gated behind `legacy-pqclean`.
//!
//! This module houses the entire original Kyber (KEM), Falcon, and Dilithium (signature)
//! code path that relies on C-backed `pqcrypto-*` FFI wrappers. It was moved wholesale
//! from `src/core/kyber/` and `src/core/kdf.rs` in Phase 1 of the v2.0 modernisation.
//! No crypto logic was changed during the move.
//!
//! # Purpose
//! Preserving this code allows existing ciphertext produced with Kyber-r3 / Dilithium /
//! Falcon to be decrypted via the `legacy-pqclean` feature even after the primary path
//! migrates to FIPS-aligned `ml-kem` / `ml-dsa` / `slh-dsa` in Phase 2+.
//!
//! # Key types re-exported
//! - [`Kyber512`], [`Kyber768`], [`Kyber1024`] — legacy size markers (deprecated aliases)
//! - [`Falcon512`], [`Falcon1024`] — legacy Falcon signing keys
//! - [`Dilithium2`], [`Dilithium3`], [`Dilithium5`] — legacy Dilithium signing keys
//! - [`KeyControl`], [`KeyControKyber1024`], etc. — KEM key management
//!
//! # Feature gate
//! Compiled only when `cfg(feature = "legacy-pqclean")` is active.
//!
//! # TODO(phase4): remove `legacy-pqclean` from the `default` feature set once the
//! ml-kem primary path lands in Phase 2.

pub mod kyber_crypto;
pub mod sign;

// Re-export size markers as #[deprecated] aliases at the crate root level.
// These point to the definitions in core::kyber so the same type identity is preserved.
#[deprecated(note = "use MlKem512 (FIPS 203) once the ml-kem feature is active")]
pub use crate::core::kyber::Kyber512;
#[deprecated(note = "use MlKem768 (FIPS 203) once the ml-kem feature is active")]
pub use crate::core::kyber::Kyber768;
#[deprecated(note = "use MlKem1024 (FIPS 203) once the ml-kem feature is active")]
pub use crate::core::kyber::Kyber1024;

// Falcon
#[deprecated(note = "use FnDsa512 (FIPS 206 draft) behind the `preview` feature")]
pub use crate::core::kdf::Falcon512;
#[deprecated(note = "use FnDsa1024 (FIPS 206 draft) behind the `preview` feature")]
pub use crate::core::kdf::Falcon1024;

// Dilithium
#[deprecated(note = "use MlDsa44 (FIPS 204) once the ml-dsa feature is active")]
pub use crate::core::kdf::Dilithium2;
#[deprecated(note = "use MlDsa65 (FIPS 204) once the ml-dsa feature is active")]
pub use crate::core::kdf::Dilithium3;
#[deprecated(note = "use MlDsa87 (FIPS 204) once the ml-dsa feature is active")]
pub use crate::core::kdf::Dilithium5;
