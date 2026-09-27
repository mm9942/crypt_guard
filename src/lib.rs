//! # CryptGuard v3.1.0
//!
//! CryptGuard v3 makes [`pq_hpke`] the default post-quantum encryption
//! transport. Its default profile is ML-KEM-1024/P-384, SHAKE256, and
//! ChaCha20-Poly1305. The pure-Rust KEM adapter is revision-pinned to
//! `draft-ietf-hpke-pq-05`; it must not be represented as a final IANA PQ HPKE
//! registration.
//!
//! ## Default transport
//!
//! [`pq_hpke::HpkeEnvelope`] is the versioned crypt_guard `CGH3` container. It
//! stores a suite, encapsulation, and ciphertext. Applications always supply
//! HPKE setup `info` and per-message AEAD AAD separately when opening a record.
//!
//! ```rust
//! use crypt_guard::pq_hpke::{generate_recipient_key_pair, HpkeEnvelope, DEFAULT_SUITE};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem())?;
//! let envelope = HpkeEnvelope::seal(
//!     DEFAULT_SUITE, keys.public_key(), b"service=v1", b"record=1", b"payload",
//! )?;
//! let plaintext = envelope.open(keys.private_key(), b"service=v1", b"record=1")?;
//! assert_eq!(plaintext, b"payload");
//! # Ok(())
//! # }
//! ```
//!
//! Raw Base and PSK transport APIs return a separate HPKE encapsulation (`enc`)
//! and ciphertext for RFC-style transport. The three standardized AEADs are
//! accepted by these APIs. AES-256-GCM-SIV and XChaCha20-Poly1305 are explicit
//! crypt_guard private extensions and require [`pq_hpke::HpkeEnvelope`].
//!
//! ## CGv2 migration
//!
//! CGv2 is not a v3 default API or transport. Enable `cgv2-compat` only to read
//! and migrate existing CGv2 records, then remove it. Default v3 builds neither
//! expose the legacy builders nor silently accept CGv2 ciphertext.
//!
//! ## Other cryptography
//!
//! ML-DSA and optional SLH-DSA signing remain available. `legacy-pqclean`
//! retains the historical Kyber/Falcon/Dilithium path for compatibility work.
//!
//! ## References
//!
//! - [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
//! - [RFC 9180 — HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
//! - [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq-05/)
//!
//! ## Workspace layout and features
//!
//! `crypt_guard` is a facade. The cryptography lives in `crypt_guard_core`
//! and is re-exported here unchanged, so every `crypt_guard::…` path keeps
//! working. Optional layers are enabled through features:
//!
//! | Feature   | Adds                                                        |
//! |-----------|-------------------------------------------------------------|
//! | (default) | the cryptographic core only — no Tower, Hyper or Tokio      |
//! | `service` | [`service`]: typed, non-`Clone` Tower crypto/KMS service    |
//! | `hyper`   | [`hyper`](mod@hyper): HTTP adapter, `TowerToHyperService` bridge |

pub use crypt_guard_core::*;

/// Typed crypto/KMS service layer (Tower, no HTTP). See `crypt_guard_service`.
#[cfg(feature = "service")]
pub mod service {
    pub use crypt_guard_service::*;
}

/// Hyper/HTTP adapter for the service layer. See `crypt_guard_hyper`.
#[cfg(feature = "hyper")]
pub mod hyper {
    pub use crypt_guard_hyper::*;
}

/// Compiles every Rust example in `README.md` as a doctest, so the README
/// cannot drift from the real API. Examples that need an optional feature are
/// wrapped in `#[cfg(feature = "...")]` and run in the matching CI lane.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
