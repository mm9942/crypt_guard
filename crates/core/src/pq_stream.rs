//! STREAM chunked authenticated encryption with ChaCha20-Poly1305.
//!
//! # Responsibility scope
//! Encrypts a long message (a file, an attachment) as a sequence of
//! independently authenticated chunks with the STREAM construction of
//! Hoang, Reyhanitabar, Rogaway and Vizár ("Online Authenticated-Encryption
//! and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015). Each chunk is sealed
//! under the nonce
//!
//! ```text
//! nonce = prefix (7 bytes) ‖ counter (u32, big-endian) ‖ last_flag (0x00 | 0x01)
//! ```
//!
//! so chunks cannot be reordered, dropped, duplicated or appended, and a
//! stream cut short is detected because only the final chunk carries
//! `last_flag = 0x01`. This module is a building block; it does not frame
//! chunks on the wire and holds no I/O.
//!
//! # Key types exported
//! - [`StreamEncryptor`] — `encrypt_next` per chunk, `encrypt_last` consumes it.
//! - [`StreamDecryptor`] — `decrypt_next` per chunk, `decrypt_last` consumes it.
//! - [`derive_stream_key`] — per-file key from a file key and a file id.
//! - [`random_prefix`] — a fresh non-zero nonce prefix from [`TryOsRng`].
//!
//! # Nonce discipline
//! A `(key, prefix)` pair must encrypt **one** stream only. Either derive a
//! fresh key per stream with [`derive_stream_key`], or draw a fresh prefix per
//! stream with [`random_prefix`] and send it with the stream. The all-zero
//! prefix is rejected so an uninitialised buffer cannot be used by accident.
//!
//! # Truncation
//! A stream is complete only when `decrypt_last` returns `Ok`. Plaintext from
//! `decrypt_next` is authentic chunk data, but the stream may still be cut
//! short: do not act on it (or expose it as a finished file) before the final
//! chunk verifies.
//!
//! # Concurrency
//! Encryptor and decryptor are single-stream state machines (`&mut self`);
//! they are `Send` and may be moved between threads, but not shared.
//!
//! # Errors
//! - [`CryptError::InvalidNonce`]: all-zero prefix, or the 2^32 chunk counter
//!   is exhausted (the final chunk can still be sealed).
//! - [`CryptError::AuthenticationFailed`]: any chunk that does not verify
//!   (wrong key, AAD, position, final flag, or modified bytes). Opaque by design.
//! - [`CryptError::EncryptionFailed`]: the AEAD refused the input (chunk too large).
//! - [`CryptError::UnsupportedOperation`]: the stream is poisoned by an earlier error.
//!
//! # Examples
//! ```rust
//! use crypt_guard_core::pq_stream::{random_prefix, StreamDecryptor, StreamEncryptor};
//!
//! # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
//! let key = [0x11u8; 32];
//! let prefix = random_prefix()?;
//!
//! let mut enc = StreamEncryptor::new(&key, prefix)?;
//! let c0 = enc.encrypt_next(b"first chunk", b"file-42")?;
//! let c1 = enc.encrypt_last(b"last chunk", b"file-42")?;
//!
//! let mut dec = StreamDecryptor::new(&key, prefix)?;
//! assert_eq!(&dec.decrypt_next(&c0, b"file-42")?[..], b"first chunk");
//! assert_eq!(&dec.decrypt_last(&c1, b"file-42")?[..], b"last chunk");
//! # Ok(())
//! # }
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use zeroize::Zeroizing;

use crate::error::CryptError;
use crate::kem::backend::rand_core_010::TryRng;
use crate::kem::backend::TryOsRng;
use crate::prf::prf32;

/// Length in bytes of a stream key.
pub const STREAM_KEY_LEN: usize = 32;

/// Length in bytes of the per-stream nonce prefix.
pub const STREAM_PREFIX_LEN: usize = 7;

/// Bytes added to every chunk by the Poly1305 tag.
pub const STREAM_TAG_LEN: usize = 16;

/// PRF label of [`derive_stream_key`].
const STREAM_KEY_LABEL: &[u8] = b"pq_stream/file-key";

/// Fixed error text for an unavailable OS entropy source (no secret data).
const ENTROPY_UNAVAILABLE: &str = "os entropy source unavailable";

/// Build the 12-byte STREAM nonce without any indexing.
fn stream_nonce(prefix: &[u8; STREAM_PREFIX_LEN], counter: u32, last: bool) -> [u8; 12] {
    let counter = counter.to_be_bytes();
    let flag = [u8::from(last)];
    let mut nonce = [0u8; 12];
    for (dst, src) in nonce
        .iter_mut()
        .zip(prefix.iter().chain(counter.iter()).chain(flag.iter()))
    {
        *dst = *src;
    }
    nonce
}

fn validate_prefix(prefix: &[u8; STREAM_PREFIX_LEN]) -> Result<(), CryptError> {
    if prefix.iter().all(|b| *b == 0) {
        return Err(CryptError::InvalidNonce);
    }
    Ok(())
}

fn seal_chunk(
    key: &[u8; STREAM_KEY_LEN],
    nonce: &[u8; 12],
    chunk: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptError> {
    let key: &Key = key.into();
    let nonce: &Nonce = nonce.into();
    ChaCha20Poly1305::new(key)
        .encrypt(nonce, Payload { msg: chunk, aad })
        .map_err(|_| CryptError::EncryptionFailed)
}

fn open_chunk(
    key: &[u8; STREAM_KEY_LEN],
    nonce: &[u8; 12],
    chunk: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    let key: &Key = key.into();
    let nonce: &Nonce = nonce.into();
    ChaCha20Poly1305::new(key)
        .decrypt(nonce, Payload { msg: chunk, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptError::AuthenticationFailed)
}

/// Draw a fresh, non-zero nonce prefix from [`TryOsRng`].
///
/// # Description
/// Use a new prefix for every stream encrypted under the same key and transmit
/// it alongside the stream (it is not secret).
///
/// # Errors
/// - [`CryptError::CustomError`] with a fixed text if the OS entropy source fails.
pub fn random_prefix() -> Result<[u8; STREAM_PREFIX_LEN], CryptError> {
    let mut prefix = [0u8; STREAM_PREFIX_LEN];
    TryRng::try_fill_bytes(&mut TryOsRng, &mut prefix)
        .map_err(|_| CryptError::CustomError(ENTROPY_UNAVAILABLE.to_owned()))?;
    // A zero prefix has probability 2^-56; fix it up instead of failing.
    if prefix.iter().all(|b| *b == 0) {
        prefix = [0, 0, 0, 0, 0, 0, 1];
    }
    Ok(prefix)
}

/// Derive the stream key for one file from a file key and a file id.
///
/// # Description
/// `prf32(file_key, "pq_stream/file-key", file_id)` (see [`crate::prf`]).
/// Distinct file ids give independent keys, so each file may use any fixed
/// non-zero prefix.
///
/// # Errors
/// - [`CryptError::InvalidDataLength`]: `file_id` longer than `u32::MAX` bytes.
pub fn derive_stream_key(
    file_key: &[u8; STREAM_KEY_LEN],
    file_id: &[u8],
) -> Result<Zeroizing<[u8; STREAM_KEY_LEN]>, CryptError> {
    prf32(file_key, STREAM_KEY_LABEL, file_id)
}

/// Sender half of a STREAM: seals chunks in order.
///
/// # Description
/// `encrypt_next` seals a non-final chunk; `encrypt_last` seals the final
/// chunk and consumes the encryptor, so nothing can follow it. The key is
/// held in zeroizing memory. After a failed AEAD call the encryptor is
/// poisoned and refuses further chunks.
pub struct StreamEncryptor {
    key: Zeroizing<[u8; STREAM_KEY_LEN]>,
    prefix: [u8; STREAM_PREFIX_LEN],
    counter: u32,
    finished: bool,
}

impl StreamEncryptor {
    /// Start a stream under `key` and `prefix`.
    ///
    /// # Errors
    /// - [`CryptError::InvalidNonce`]: `prefix` is all zero.
    pub fn new(
        key: &[u8; STREAM_KEY_LEN],
        prefix: [u8; STREAM_PREFIX_LEN],
    ) -> Result<Self, CryptError> {
        validate_prefix(&prefix)?;
        Ok(Self {
            key: Zeroizing::new(*key),
            prefix,
            counter: 0,
            finished: false,
        })
    }

    /// Seal the next non-final chunk; the output is `chunk.len() + 16` bytes.
    ///
    /// # Errors
    /// - [`CryptError::InvalidNonce`]: 2^32 - 1 chunks were already sealed;
    ///   only [`Self::encrypt_last`] is still possible.
    /// - [`CryptError::EncryptionFailed`]: the chunk is too large for the AEAD.
    /// - [`CryptError::UnsupportedOperation`]: the encryptor is poisoned.
    pub fn encrypt_next(&mut self, chunk: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptError> {
        if self.finished {
            return Err(CryptError::UnsupportedOperation);
        }
        // Keep one counter value in reserve for the final chunk.
        let next = self
            .counter
            .checked_add(1)
            .ok_or(CryptError::InvalidNonce)?;
        let nonce = stream_nonce(&self.prefix, self.counter, false);
        match seal_chunk(&self.key, &nonce, chunk, aad) {
            Ok(sealed) => {
                self.counter = next;
                Ok(sealed)
            }
            Err(err) => {
                self.finished = true;
                Err(err)
            }
        }
    }

    /// Seal the final chunk (may be empty) and end the stream.
    ///
    /// # Errors
    /// - [`CryptError::EncryptionFailed`]: the chunk is too large for the AEAD.
    /// - [`CryptError::UnsupportedOperation`]: the encryptor is poisoned.
    pub fn encrypt_last(self, chunk: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptError> {
        if self.finished {
            return Err(CryptError::UnsupportedOperation);
        }
        let nonce = stream_nonce(&self.prefix, self.counter, true);
        seal_chunk(&self.key, &nonce, chunk, aad)
    }

    /// Number of non-final chunks sealed so far.
    pub const fn chunks_sealed(&self) -> u32 {
        self.counter
    }
}

impl fmt::Debug for StreamEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamEncryptor")
            .field("counter", &self.counter)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

/// Receiver half of a STREAM: opens chunks in order.
///
/// # Description
/// `decrypt_next` opens a non-final chunk; `decrypt_last` opens the final
/// chunk and consumes the decryptor. A non-final chunk presented to
/// `decrypt_last` (truncation) or a final chunk presented to `decrypt_next`
/// (extension) fails authentication. After any failure the decryptor is
/// poisoned, so a stream with one bad chunk can never be completed.
pub struct StreamDecryptor {
    key: Zeroizing<[u8; STREAM_KEY_LEN]>,
    prefix: [u8; STREAM_PREFIX_LEN],
    counter: u32,
    finished: bool,
}

impl StreamDecryptor {
    /// Start opening a stream sealed under `key` and `prefix`.
    ///
    /// # Errors
    /// - [`CryptError::InvalidNonce`]: `prefix` is all zero.
    pub fn new(
        key: &[u8; STREAM_KEY_LEN],
        prefix: [u8; STREAM_PREFIX_LEN],
    ) -> Result<Self, CryptError> {
        validate_prefix(&prefix)?;
        Ok(Self {
            key: Zeroizing::new(*key),
            prefix,
            counter: 0,
            finished: false,
        })
    }

    /// Open the next non-final chunk.
    ///
    /// # Errors
    /// - [`CryptError::AuthenticationFailed`]: the chunk does not verify at this
    ///   position (the decryptor is then poisoned).
    /// - [`CryptError::InvalidNonce`]: the chunk counter is exhausted.
    /// - [`CryptError::UnsupportedOperation`]: the decryptor is poisoned.
    pub fn decrypt_next(
        &mut self,
        chunk: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        if self.finished {
            return Err(CryptError::UnsupportedOperation);
        }
        let next = self
            .counter
            .checked_add(1)
            .ok_or(CryptError::InvalidNonce)?;
        let nonce = stream_nonce(&self.prefix, self.counter, false);
        match open_chunk(&self.key, &nonce, chunk, aad) {
            Ok(plaintext) => {
                self.counter = next;
                Ok(plaintext)
            }
            Err(err) => {
                self.finished = true;
                Err(err)
            }
        }
    }

    /// Open the final chunk; on success the whole stream is authentic and complete.
    ///
    /// # Errors
    /// - [`CryptError::AuthenticationFailed`]: the chunk is not the authentic
    ///   final chunk at this position (truncated, reordered or modified stream).
    /// - [`CryptError::UnsupportedOperation`]: the decryptor is poisoned.
    pub fn decrypt_last(self, chunk: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        if self.finished {
            return Err(CryptError::UnsupportedOperation);
        }
        let nonce = stream_nonce(&self.prefix, self.counter, true);
        open_chunk(&self.key, &nonce, chunk, aad)
    }

    /// Number of non-final chunks opened so far.
    pub const fn chunks_opened(&self) -> u32 {
        self.counter
    }
}

impl fmt::Debug for StreamDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamDecryptor")
            .field("counter", &self.counter)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), CryptError>;

    #[test]
    fn nonce_layout_is_prefix_counter_flag() {
        let n = stream_nonce(&[1, 2, 3, 4, 5, 6, 7], 0x0A0B_0C0D, true);
        assert_eq!(n, [1, 2, 3, 4, 5, 6, 7, 0x0A, 0x0B, 0x0C, 0x0D, 0x01]);
        let n = stream_nonce(&[9; 7], 0, false);
        assert_eq!(n, [9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 0, 0x00]);
    }

    #[test]
    fn counter_exhaustion_still_allows_the_final_chunk() -> TestResult {
        let key = [5u8; 32];
        let prefix = [1u8; 7];
        let mut enc = StreamEncryptor::new(&key, prefix)?;
        enc.counter = u32::MAX;
        assert!(matches!(
            enc.encrypt_next(b"x", b""),
            Err(CryptError::InvalidNonce)
        ));
        let last = enc.encrypt_last(b"end", b"")?;

        let mut dec = StreamDecryptor::new(&key, prefix)?;
        dec.counter = u32::MAX;
        assert_eq!(&dec.decrypt_last(&last, b"")?[..], b"end");
        Ok(())
    }

    #[test]
    fn known_answer_stream_key() -> TestResult {
        // python3: shake_256(b"crypt_guard/v3/prf" + lp32(b"pq_stream/file-key")
        //   + lp32(b"\x42"*32) + lp32(b"file-0001") + be32(32)).digest(32)
        let key = derive_stream_key(&[0x42; 32], b"file-0001")?;
        assert_eq!(
            hex::encode(&key[..]),
            "e0600970fa879c43b2cf8825bbb98b2b9f13077a752e4e9c1a947ce6463da6df"
        );
        Ok(())
    }
}
