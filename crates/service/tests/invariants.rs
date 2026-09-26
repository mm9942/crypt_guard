//! Compile-time ownership invariants of the service layer.
//!
//! These are part of the security contract: secret-bearing and stateful types
//! must never become `Clone`; only the network handle may be cloned.

use static_assertions::{assert_impl_all, assert_not_impl_any};

use crypt_guard_core::pq_hpke::{RecipientContext, RecipientPrivateKey, SenderContext};
use crypt_guard_service::{
    CryptoOperation, CryptoRequest, CryptoResponse, CryptoService, Decrypt, Encrypt, NullProvider,
    SecretBytes, SecretEgress, Sign, UnwrapKey, WrapKey,
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

// The crypto service owns provider state.
assert_not_impl_any!(CryptoService<NullProvider>: Clone);
assert_impl_all!(CryptoService<NullProvider>: Send);

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
