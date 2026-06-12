//! Shared zero-sized-type (ZST) axis markers used across `core/`, `legacy/`, and the public API.
//!
//! These types carry no runtime data — they encode intent at the type level so that
//! `Kyber<ProcessStatus, KyberSize, ContentStatus, AlgorithmParam>` mis-uses are caught at
//! compile time rather than at run time.
//!
//! # Responsibility scope
//! This module owns only the *shared* axis markers: process direction, content kind, and
//! cipher algorithm. Size markers for legacy Kyber (`Kyber512`, `Kyber768`, `Kyber1024`) live
//! in `legacy/` because they are tightly coupled to the pqcrypto KEM variant selection.
//! New FIPS size markers (`MlKem512`, `MlKem768`, `MlKem1024`) will be added in Phase 2
//! inside `kem/`.
//!
//! # Key types exported
//! - Process: [`Encryption`], [`Decryption`]
//! - Content: [`Files`], [`Message`], [`Data`]
//! - Cipher: [`AES`], [`AesGcmSiv`], [`AesCtr`], [`AesXts`], [`XChaCha20`], [`XChaCha20Poly1305`]
//!
//! # Concurrency
//! All types are zero-sized and implement no state; they are inherently `Send + Sync`.
//!
//! # Examples
//! ```rust
//! use crypt_guard::markers::{Encryption, AES};
//! ```

/// Process-direction marker: the Kyber instance will perform encryption.
pub struct Encryption;

/// Process-direction marker: the Kyber instance will perform decryption.
pub struct Decryption;

/// Content-kind marker: the target is a file path.
pub struct Files;

/// Content-kind marker: the target is a UTF-8 message string.
pub struct Message;

/// Content-kind marker: the target is a raw byte slice.
pub struct Data;

/// Cipher-algorithm marker: AES-256-CBC with HMAC.
pub struct AES;

/// Cipher-algorithm marker: AES-256-GCM-SIV (nonce-bearing).
pub struct AesGcmSiv;

/// Cipher-algorithm marker: AES-256-CTR (nonce-bearing).
pub struct AesCtr;

/// Cipher-algorithm marker: AES-256-XTS (double-width key).
pub struct AesXts;

/// Cipher-algorithm marker: XChaCha20 stream cipher (nonce-bearing).
pub struct XChaCha20;

/// Cipher-algorithm marker: XChaCha20-Poly1305 AEAD (nonce-bearing).
pub struct XChaCha20Poly1305;
