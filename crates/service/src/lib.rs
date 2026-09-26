//! # crypt_guard_service
//!
//! Typed crypto/KMS service semantics on top of `crypt_guard_core`, exposed
//! as a Tower [`Service`]. No HTTP, no Hyper, no
//! `bytes`: transports live in `crypt_guard_hyper`.
//!
//! Use it through the facade: `crypt_guard = { features = ["service"] }`,
//! then `crypt_guard::service::…`.
//!
//! ## Ownership invariants
//!
//! | Type | `Clone` |
//! |------|---------|
//! | [`SecretBytes`], [`SecretEgress`] | no |
//! | [`CryptoRequest`], [`CryptoResponse`], [`CryptoOperation`] | no |
//! | [`CryptoService`] | no |
//! | `NetworkHandle` (feature `buffer`) | **yes**: channel handle only |
//! | [`KeyRef`], blobs, [`CryptoContext`] | yes: not secret |
//!
//! These are checked at compile time by the crate's invariant tests.
//!
//! ## Status
//!
//! Providers: [`InMemoryProvider`] (reference, in-process keys) and
//! [`NullProvider`]. Wrap any provider in [`PolicyProvider`] with an
//! [`Authorizer`] such as [`NamespacePolicy`] to enforce per-caller grants.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod blob;
mod error;
mod key;
mod memory;
mod op;
mod policy;
mod provider;
mod secret;
mod service;
#[cfg(feature = "buffer")]
mod stack;

pub use blob::{CiphertextBlob, MessageBlob, PublicBlob, SignatureBlob};
pub use error::CryptoServiceError;
pub use key::{
    KeyAlgorithm, KeyId, KeyMetadata, KeyNamespace, KeyRef, KeyState, KeyVersion,
    SignatureAlgorithm, MAX_NAME_LEN,
};
pub use op::{
    CryptoContext, CryptoOperation, CryptoRequest, CryptoResponse, Decrypt, DescribeKey,
    DestroyKey, DisableKey, EnableKey, Encrypt, GenerateKey, GetPublicKey, OpKind, Principal,
    RequestContext, RequestId, RewrapKey, RotateKey, Sign, UnwrapKey, VerificationResult, Verify,
    WrapKey,
};
pub use memory::InMemoryProvider;
pub use policy::{AllowAll, Authorizer, NamespacePolicy, OpSet, PolicyProvider};
pub use provider::{CryptoProvider, NullProvider};
pub use secret::{SecretBytes, SecretEgress};
pub use service::{CryptoFuture, CryptoService};
#[cfg(feature = "buffer")]
pub use stack::{network_handle, service_error, NetworkHandle, StackConfig};

/// Re-export of the core PQ HPKE module, whose `Suite` appears in
/// [`KeyAlgorithm::Hpke`].
pub use crypt_guard_core::pq_hpke;

/// Re-export of the Tower service trait this crate implements.
pub use tower_service::Service;
