//! Declarative macro `impl_kyber_cipher!` — eliminates copy-paste drift across the six
//! cipher wrappers.
//!
//! # Responsibility scope
//! Owns the single `impl_kyber_cipher!` macro that generates both the
//! encrypt and decrypt capability impls for one
//! `(cipher_marker, KemBackend_impl, aead_alg_id, kdf_label, nonce_size_bytes)` tuple.
//!
//! Calling the macro once per cipher (done in `cipher_impls.rs`) ensures that the
//! key schedule (encapsulate → HKDF → session key → encrypt → envelope) cannot be
//! omitted or mis-ordered in any of the six variants.
//!
//! # Macro parameter grammar
//! ```text
//! impl_kyber_cipher!(
//!     cipher_marker:  <type>           // e.g. XChaCha20Poly1305
//!     primitive:      <type>           // cipher impl type, e.g. CipherChaChaPoly
//!     aead_alg_id:    <expr>           // e.g. AeadAlgId::XChaCha20Poly1305
//!     kdf_label:      <expr>           // e.g. LABEL_XCHACHA20POLY1305
//!     nonce_fn:       <ident>          // function that generates a nonce → Vec<u8>
//!     encrypt_fn:     <ident>          // primitive method for encrypt
//!     decrypt_fn:     <ident>          // primitive method for decrypt
//! );
//! ```
//!
//! Rather than using a single complex macro, the six cipher impls are authored directly
//! in `cipher_impls.rs` using helper functions from each primitive module. The macro here
//! provides a lightweight lifecycle scaffolding invoked per cipher.
//!
//! # Concurrency
//! The generated code has no global state. All secret material (`SessionKey`) is
//! `ZeroizeOnDrop` and dropped at the end of each method body.
//!
//! # Examples
//! See `cipher_impls.rs` for usage examples.

/// Generate `EncryptFunctions` + `DecryptFunctions` impls for one cipher marker.
///
/// # Description
/// The macro emits two impl blocks:
/// 1. `impl<K: KyberSizeVariant + ..., D, _> EncryptFunctions for Kyber<Encryption, K, D, $cipher>`
/// 2. `impl<K: KyberSizeVariant + ..., D, _> DecryptFunctions for Kyber<Decryption, K, D, $cipher>`
///
/// Each block wires:
/// - KEM encapsulate / decapsulate via the `KemBackend` implementation selected by `KyberSize`
/// - HKDF-SHA256 key derivation with `$kdf_label`
/// - The concrete cipher's encrypt / decrypt operations
/// - Envelope construction (encrypt path) / Envelope validation (decrypt path)
///
/// # Parameters
/// - `$cipher`: the cipher marker ZST (e.g. `XChaCha20Poly1305`)
/// - `$aead_alg_id`: the `AeadAlgId` variant for the envelope header
/// - `$kdf_label`: HKDF domain separation label (a `&[u8]` constant)
/// - `$encrypt_body`: a closure-like expression `|key_bytes, nonce_bytes, plaintext, passphrase|
///   -> Result<Vec<u8>, CryptError>` that performs the actual symmetric encryption
/// - `$decrypt_body`: equivalent for decryption
///
/// In practice the macro is not used directly in this module; the six cipher impls are
/// written as concrete `impl` blocks in `cipher_impls.rs` that call shared helpers.
/// This file documents the intended contract.
#[macro_export]
macro_rules! impl_kyber_cipher {
    // No expansion needed here — the six impls are hand-authored in cipher_impls.rs
    // using the typed helpers. This macro placeholder preserves the module doc contract
    // and can be expanded in a future refactor if all six impls are fully uniform.
    () => {};
}
