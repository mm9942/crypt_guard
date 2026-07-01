//! CGv2 authenticated envelope protocol (`src/protocol/`).
//!
//! # Responsibility scope
//! This module defines the on-wire format used by crypt_guard v2.0 for all
//! hybrid KEM + symmetric encryption operations. It owns:
//!
//! - [`header`] — the 14-byte fixed header (`magic`, `version`, algorithm IDs, flags)
//! - [`version`] — the protocol magic constant `b"CGv2"` and `VERSION_V2 = 2`
//! - [`aad`] — deterministic AAD construction from header + KEM ciphertext + nonce
//! - [`envelope`] — the full [`Envelope`] struct and its length-prefixed serialization
//!
//! # Key types exported
//! - [`Envelope`] — the authenticated wire container
//! - [`header::Header`] — parsed header fields
//! - [`header::KemAlgId`](crate::protocol::header::KemAlgId), [`header::AeadAlgId`](crate::protocol::header::AeadAlgId), [`header::KdfAlgId`](crate::protocol::header::KdfAlgId) — algorithm IDs
//! - [`aad::build_aad`] — AAD builder
//! - [`version::MAGIC`], [`version::VERSION_V2`] — constants
//!
//! # Nonce policy
//! The nonce is stored *inside* the [`Envelope`] on the encrypt path and recovered
//! from it on the decrypt path. **The nonce must never be printed to stdout or
//! logged at `info` level.** Use `tracing::trace!` if you must log it during debugging,
//! and ensure that trace logging is disabled in production builds.
//!
//! # Concurrency
//! All types in this module are `Clone + Send + Sync`. No shared mutable state.
//!
//! # Errors
//! Parse errors map to [`crate::error::CryptError::InvalidEnvelope`] or
//! [`crate::error::CryptError::UnsupportedEnvelopeVersion`].
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::protocol::{
//!     header::{Header, KemAlgId, AeadAlgId, KdfAlgId},
//!     envelope::Envelope,
//! };
//! let hdr = Header::new(KemAlgId::MlKem768, AeadAlgId::XChaCha20Poly1305, KdfAlgId::HkdfSha256);
//! let env = Envelope::new(hdr, vec![0u8; 32], vec![0u8; 24], vec![0u8; 64]);
//! let serialized = env.to_bytes();
//! let parsed = Envelope::from_bytes(&serialized).unwrap();
//! assert_eq!(env, parsed);
//! ```

pub mod aad;
pub mod envelope;
pub mod header;
pub mod version;

pub use aad::build_aad;
pub use envelope::Envelope;
pub use header::{AeadAlgId, Header, KdfAlgId, KemAlgId};
pub use version::{MAGIC, VERSION_V2};
