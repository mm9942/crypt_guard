//! Compile-time ownership invariants of the service layer.
//!
//! These are part of the security contract: secret-bearing and stateful types
//! must never become `Clone`; only the network handle may be cloned.

use static_assertions::{assert_impl_all, assert_not_impl_any};

use crypt_guard_core::pq_hpke::{RecipientContext, RecipientPrivateKey, SenderContext};
use crypt_guard_service::{
    CryptoOperation, CryptoRequest, CryptoResponse, CryptoService, Decrypt, DescribeKey,
    DestroyKey, DisableKey, EnableKey, Encrypt, GenerateKey, GetPublicKey, InMemoryProvider,
    NamespacePolicy, NullProvider, OpSet, PolicyProvider, Principal, RequestContext, RewrapKey,
    RotateKey, SecretBytes, SecretEgress, Sign, UnwrapKey, Verify, WrapKey,
};

// Secret containers.
assert_not_impl_any!(SecretBytes: Clone, Copy);
assert_not_impl_any!(SecretEgress: Clone, Copy);
assert_impl_all!(SecretBytes: Send, Sync);
assert_impl_all!(SecretEgress: AsRef<[u8]>, Send, Sync);

// Requests, operations and responses may carry secrets.
assert_not_impl_any!(CryptoRequest: Clone);
assert_not_impl_any!(CryptoOperation: Clone);
assert_not_impl_any!(CryptoResponse: Clone);
assert_not_impl_any!(Encrypt: Clone);
assert_not_impl_any!(Decrypt: Clone);
assert_not_impl_any!(Sign: Clone);
assert_not_impl_any!(WrapKey: Clone);
assert_not_impl_any!(UnwrapKey: Clone);
assert_impl_all!(CryptoRequest: Send);
assert_impl_all!(CryptoResponse: Send);

// The other request-payload structs carry no secrets directly, but are kept
// non-`Clone` too: a request is moved through the service exactly once, never
// silently duplicated.
assert_not_impl_any!(GenerateKey: Clone);
assert_not_impl_any!(RotateKey: Clone);
assert_not_impl_any!(DisableKey: Clone);
assert_not_impl_any!(EnableKey: Clone);
assert_not_impl_any!(DestroyKey: Clone);
assert_not_impl_any!(DescribeKey: Clone);
assert_not_impl_any!(GetPublicKey: Clone);
assert_not_impl_any!(Verify: Clone);
assert_not_impl_any!(RewrapKey: Clone);

// The crypto service owns provider state.
assert_not_impl_any!(CryptoService<NullProvider>: Clone);
assert_impl_all!(CryptoService<NullProvider>: Send);

// The in-memory provider owns all key material; it must never be cloned,
// but must be movable across threads.
assert_not_impl_any!(InMemoryProvider: Clone);
assert_impl_all!(InMemoryProvider: Send);

// A policy-guarded provider is likewise linear: cloning it would duplicate
// the guarded provider's owned state.
assert_not_impl_any!(PolicyProvider<InMemoryProvider, NamespacePolicy>: Clone);
assert_impl_all!(PolicyProvider<InMemoryProvider, NamespacePolicy>: Send);

// Identity and grant types are not secret, so they may be freely cloned.
assert_impl_all!(Principal: Clone);
assert_impl_all!(RequestContext: Clone);
assert_impl_all!(OpSet: Clone);

// Core stateful HPKE contexts and private keys stay linear.
assert_not_impl_any!(SenderContext: Clone);
assert_not_impl_any!(RecipientContext: Clone);
assert_not_impl_any!(RecipientPrivateKey: Clone);
assert_impl_all!(SenderContext: Send);
assert_impl_all!(RecipientContext: Send);
assert_impl_all!(RecipientPrivateKey: Send, Sync);

// The network handle is the one cloneable element.
#[cfg(feature = "buffer")]
assert_impl_all!(crypt_guard_service::NetworkHandle: Clone, Send, Sync);

#[test]
fn secret_debug_is_redacted() {
    let secret = SecretBytes::copy_from_slice(b"top secret plaintext");
    let rendered = format!("{secret:?}");
    assert_eq!(rendered, "SecretBytes([REDACTED; 20])");
    assert!(!rendered.contains("secret plaintext"));

    let egress = secret.into_egress();
    assert_eq!(format!("{egress:?}"), "SecretEgress([REDACTED; 20])");
    assert_eq!(egress.as_ref(), b"top secret plaintext");
}

#[test]
fn secret_bytes_from_vec_with_spare_capacity_keeps_exact_content() {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"0123456789");
    assert_eq!(v.len(), 10);
    assert!(v.capacity() >= 64);

    let secret = SecretBytes::from_vec(v);
    assert_eq!(secret.len(), 10);
    assert_eq!(secret.as_ref(), b"0123456789");
}

#[test]
fn secret_bytes_from_vec_with_exact_capacity_keeps_exact_content() {
    let mut v = Vec::with_capacity(10);
    v.extend_from_slice(b"0123456789");
    assert_eq!(v.capacity(), 10);

    let secret = SecretBytes::from_vec(v);
    assert_eq!(secret.len(), 10);
    assert_eq!(secret.as_ref(), b"0123456789");
}

#[test]
fn secret_bytes_concat_matches_concatenation() {
    let chunks: [&[u8]; 3] = [b"foo", b"bar", b"baz"];
    let secret = SecretBytes::concat(&chunks).unwrap();
    assert_eq!(secret.len(), 9);
    assert_eq!(secret.as_ref(), b"foobarbaz");
}

#[test]
fn secret_bytes_concat_of_empty_slice_is_empty() {
    let chunks: [&[u8]; 0] = [];
    let secret = SecretBytes::concat(&chunks).unwrap();
    assert!(secret.is_empty());
    assert_eq!(secret.len(), 0);
}
