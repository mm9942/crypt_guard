//! Labelled pseudorandom function / key derivation on SHAKE256.
//!
//! # Responsibility scope
//! Derives identifiers, capability tokens and sub-keys from a secret key with
//! strict domain separation. This module owns only the PRF construction; it
//! holds no state and performs no I/O. Typical uses are mailbox ids, per-file
//! stream keys ([`crate::pq_stream::derive_stream_key`]) and capability
//! secrets, where one root key must yield many unrelated outputs.
//!
//! # Construction
//! ```text
//! out = SHAKE256( "crypt_guard/v3/prf"
//!               ‖ lp32(label) ‖ lp32(key) ‖ lp32(input)
//!               ‖ u32_be(out.len()) )[..out.len()]
//! lp32(x) = u32_be(len(x)) ‖ x
//! ```
//! Every variable field is length-prefixed, so no two distinct
//! `(label, key, input)` triples share an encoding. Like KMAC, the requested
//! output length is bound into the input: a 16-byte and a 32-byte output for
//! the same triple are unrelated, never prefixes of one another.
//!
//! # Key types exported
//! - [`prf`] — fill a caller buffer of 1..=[`PRF_MAX_OUTPUT_LEN`] bytes.
//! - [`prf32`] — convenience 32-byte output in zeroizing memory.
//! - Limits: [`PRF_MIN_KEY_LEN`], [`PRF_MAX_LABEL_LEN`], [`PRF_MAX_OUTPUT_LEN`].
//!
//! # Concurrency
//! Pure functions over borrowed inputs; callable from any thread.
//!
//! # Errors
//! - [`CryptError::InvalidParameters`]: key shorter than [`PRF_MIN_KEY_LEN`],
//!   empty label, label longer than [`PRF_MAX_LABEL_LEN`], or an output
//!   length outside `1..=PRF_MAX_OUTPUT_LEN`.
//! - [`CryptError::InvalidDataLength`]: `input` longer than `u32::MAX` bytes.
//!
//! Errors carry no key or input bytes.
//!
//! # Examples
//! ```rust
//! use crypt_guard_core::prf::{prf, prf32};
//!
//! # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
//! let root_key = [7u8; 32];
//! let mailbox_id = prf32(&root_key, b"comnet/mailbox-id", b"alice")?;
//! let mut token = [0u8; 16];
//! prf(&root_key, b"comnet/capability", b"upload", &mut token)?;
//! assert_ne!(&mailbox_id[..16], &token[..]);
//! # Ok(())
//! # }
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroizing;

use crate::error::CryptError;

/// Fixed domain prefix absorbed before every PRF input.
const PRF_DOMAIN: &[u8] = b"crypt_guard/v3/prf";

/// Minimum accepted key length in bytes (128-bit security floor).
pub const PRF_MIN_KEY_LEN: usize = 16;

/// Maximum accepted label length in bytes.
pub const PRF_MAX_LABEL_LEN: usize = 255;

/// Maximum output length in bytes of a single [`prf`] call.
pub const PRF_MAX_OUTPUT_LEN: usize = 1024;

/// Encode a length as a big-endian `u32`, rejecting anything larger.
fn len_u32(len: usize, err: CryptError) -> Result<[u8; 4], CryptError> {
    u32::try_from(len).map(u32::to_be_bytes).map_err(|_| err)
}

/// Compute the labelled SHAKE256 PRF of `(key, label, input)` into `out`.
///
/// # Description
/// Fills all of `out` with
/// `SHAKE256("crypt_guard/v3/prf" ‖ lp32(label) ‖ lp32(key) ‖ lp32(input) ‖ u32_be(out.len()))`.
/// Use a distinct, constant `label` per purpose (for example
/// `b"comnet/mailbox-id"`); the label is the domain separator. `out` is left
/// untouched when an error is returned.
///
/// # Arguments
/// - `key` (`&[u8]`): secret key, at least [`PRF_MIN_KEY_LEN`] bytes.
/// - `label` (`&[u8]`): purpose label, 1..=[`PRF_MAX_LABEL_LEN`] bytes.
/// - `input` (`&[u8]`): public or secret context input, any length up to `u32::MAX`.
/// - `out` (`&mut [u8]`): output buffer, 1..=[`PRF_MAX_OUTPUT_LEN`] bytes.
///
/// # Errors
/// - [`CryptError::InvalidParameters`]: key too short, label empty or too long,
///   or `out.len()` outside `1..=PRF_MAX_OUTPUT_LEN`.
/// - [`CryptError::InvalidDataLength`]: `input` longer than `u32::MAX` bytes.
///
/// # Concurrency
/// Pure function; callable from any thread.
///
/// # Examples
/// ```rust
/// use crypt_guard_core::prf::prf;
///
/// # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
/// let mut id = [0u8; 24];
/// prf(&[1u8; 32], b"example/id", b"context", &mut id)?;
/// # Ok(())
/// # }
/// ```
pub fn prf(key: &[u8], label: &[u8], input: &[u8], out: &mut [u8]) -> Result<(), CryptError> {
    if key.len() < PRF_MIN_KEY_LEN {
        return Err(CryptError::InvalidParameters);
    }
    if label.is_empty() || label.len() > PRF_MAX_LABEL_LEN {
        return Err(CryptError::InvalidParameters);
    }
    if out.is_empty() || out.len() > PRF_MAX_OUTPUT_LEN {
        return Err(CryptError::InvalidParameters);
    }
    let label_len = len_u32(label.len(), CryptError::InvalidParameters)?;
    let key_len = len_u32(key.len(), CryptError::InvalidParameters)?;
    let input_len = len_u32(input.len(), CryptError::InvalidDataLength)?;
    let out_len = len_u32(out.len(), CryptError::InvalidParameters)?;

    let mut xof = Shake256::default();
    xof.update(PRF_DOMAIN);
    xof.update(&label_len);
    xof.update(label);
    xof.update(&key_len);
    xof.update(key);
    xof.update(&input_len);
    xof.update(input);
    xof.update(&out_len);
    xof.finalize_xof().read(out);
    Ok(())
}

/// Compute a 32-byte [`prf`] output in zeroizing memory.
///
/// # Description
/// Equivalent to calling [`prf`] with a 32-byte buffer. The result is wiped
/// on drop, so it is suitable as a derived key.
///
/// # Arguments
/// - `key` (`&[u8]`): secret key, at least [`PRF_MIN_KEY_LEN`] bytes.
/// - `label` (`&[u8]`): purpose label, 1..=[`PRF_MAX_LABEL_LEN`] bytes.
/// - `input` (`&[u8]`): context input.
///
/// # Returns
/// `Ok(Zeroizing<[u8; 32]>)` with the derived bytes.
///
/// # Errors
/// Same as [`prf`].
///
/// # Examples
/// ```rust
/// use crypt_guard_core::prf::prf32;
///
/// # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
/// let sub_key = prf32(&[9u8; 32], b"example/sub-key", b"v1")?;
/// assert_eq!(sub_key.len(), 32);
/// # Ok(())
/// # }
/// ```
pub fn prf32(key: &[u8], label: &[u8], input: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptError> {
    let mut out = Zeroizing::new([0u8; 32]);
    prf(key, label, input, out.as_mut_slice())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), CryptError>;

    #[test]
    fn known_answer_matches_independent_python_computation() -> TestResult {
        // python3: shake_256(b"crypt_guard/v3/prf" + lp32(label) + lp32(key)
        //                    + lp32(input) + be32(n)).digest(n)
        let key: Vec<u8> = (0u8..32).collect();
        let out = prf32(&key, b"mailbox-id", b"alice@example")?;
        assert_eq!(
            hex::encode(&out[..]),
            "86124c8b9d90980fc84e7f8a9c31a11318e1ed7439ab4dae5d6b9eefb60b487b"
        );
        Ok(())
    }

    #[test]
    fn output_length_is_bound_into_the_derivation() -> TestResult {
        let key = [3u8; 32];
        let short = prf32(&key, b"label", b"input")?;
        let mut long = [0u8; 64];
        prf(&key, b"label", b"input", &mut long)?;
        assert_ne!(&short[..], &long[..32]);
        Ok(())
    }

    #[test]
    fn rejects_out_of_range_parameters() {
        let mut out = [0u8; 32];
        assert!(matches!(
            prf(&[0u8; 15], b"l", b"", &mut out),
            Err(CryptError::InvalidParameters)
        ));
        assert!(matches!(
            prf(&[0u8; 16], b"", b"", &mut out),
            Err(CryptError::InvalidParameters)
        ));
        assert!(matches!(
            prf(&[0u8; 16], &[b'a'; 256], b"", &mut out),
            Err(CryptError::InvalidParameters)
        ));
        let mut empty = [0u8; 0];
        assert!(matches!(
            prf(&[0u8; 16], b"l", b"", &mut empty),
            Err(CryptError::InvalidParameters)
        ));
        let mut too_long = vec![0u8; PRF_MAX_OUTPUT_LEN + 1];
        assert!(matches!(
            prf(&[0u8; 16], b"l", b"", &mut too_long),
            Err(CryptError::InvalidParameters)
        ));
        assert_eq!(out, [0u8; 32], "out must stay untouched on error");
    }
}
