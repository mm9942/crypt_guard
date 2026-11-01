//! Shamir secret sharing over GF(2^8) with attributable share commitments.
//!
//! # Responsibility scope
//! Splits a secret of 1..=[`MAX_SECRET_LEN`] bytes into `n` shares so that any
//! `t` of them reconstruct it and any `t - 1` reveal nothing about it
//! (information-theoretic secrecy). Each secret byte is shared independently
//! with a random polynomial of degree `t - 1` over GF(2^8) with the AES
//! reduction polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11B`); share `i` is the
//! evaluation at `x = i` (`1..=255`) and [`combine`] interpolates at `x = 0`.
//!
//! [`commitment`] binds a share to a context with SHA3-256 so a holder who
//! later presents a wrong share can be identified ([`check_commitment`]).
//!
//! # Side channels
//! Field multiplication is bitwise with masks (no lookup tables, no
//! secret-dependent branches or indices). Inversion is the fixed exponentiation
//! `a^254`. Commitment comparison is constant-time. Share indices, share
//! counts and lengths are public and may influence control flow.
//!
//! # Key types exported
//! - [`Share`] — one share (`index` + zeroizing `value`), redacted `Debug`.
//! - [`split`], [`combine`] — share and reconstruct.
//! - [`commitment`], [`verify_commitment`], [`check_commitment`] — attributable shares.
//! - [`SharingError`] — typed failures, convertible into [`crate::error::CryptError`].
//!
//! # Concurrency
//! All functions are pure apart from drawing randomness from
//! [`crate::kem::backend::TryOsRng`]; callable from any thread.
//!
//! # Errors
//! Every failure is a [`SharingError`]; none carries share or secret bytes.
//! An OS entropy failure is [`SharingError::EntropyUnavailable`], never a panic.
//!
//! # Security notes
//! - [`combine`] cannot detect too few shares: `t - 1` shares interpolate to an
//!   unrelated value. Persist the threshold next to the shares, and verify the
//!   result (for example with a MAC or a key fingerprint) where it matters.
//! - Commitments are deterministic. They hide a share only if its value has
//!   enough entropy (secrets of 16 bytes or more). For shorter secrets put a
//!   random salt into `context`, or do not publish commitments to other
//!   share holders.
//!
//! # Examples
//! ```rust
//! use crypt_guard_core::sharing::{combine, commitment, split, verify_commitment};
//!
//! # fn main() -> Result<(), crypt_guard_core::sharing::SharingError> {
//! let shares = split(b"thirty-two byte recovery secret!", 2, 3)?;
//! let receipt = commitment(&shares[0], b"backup/v1");
//! assert!(verify_commitment(&shares[0], b"backup/v1", &receipt));
//! let secret = combine(&shares[1..])?;
//! assert_eq!(&secret[..], b"thirty-two byte recovery secret!");
//! # Ok(())
//! # }
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::{error::Error as StdError, fmt};

use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::kem::backend::rand_core_010::{TryCryptoRng, TryRng};
use crate::kem::backend::TryOsRng;

/// Maximum secret length in bytes accepted by [`split`].
pub const MAX_SECRET_LEN: usize = 4096;

/// Smallest supported reconstruction threshold.
pub const MIN_THRESHOLD: u8 = 2;

/// Length in bytes of a share commitment.
pub const COMMITMENT_LEN: usize = 32;

/// Domain label of [`commitment`].
const COMMITMENT_LABEL: &[u8] = b"crypt_guard/v3/share-commitment";

// ── Errors ────────────────────────────────────────────────────────────────────

/// Failures of [`split`], [`combine`] and the share helpers.
///
/// # Description
/// Variants carry only public metadata (counts, indices, lengths), never share
/// or secret bytes. Converts into [`crate::error::CryptError`] via `From`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SharingError {
    /// `threshold` must satisfy `2 <= threshold <= shares`.
    InvalidThreshold {
        /// Requested threshold.
        threshold: u8,
        /// Requested number of shares.
        shares: u8,
    },
    /// A secret or share value must be 1..=[`MAX_SECRET_LEN`] bytes long.
    InvalidSecretLength {
        /// Offending length in bytes.
        actual: usize,
    },
    /// Share index 0 is reserved for the secret itself.
    InvalidShareIndex,
    /// Two shares passed to [`combine`] have the same index.
    DuplicateShareIndex {
        /// The repeated index.
        index: u8,
    },
    /// Shares passed to [`combine`] have different value lengths.
    ShareLengthMismatch {
        /// Length of the first share.
        expected: usize,
        /// Length of the offending share.
        actual: usize,
    },
    /// [`combine`] needs at least two shares.
    TooFewShares {
        /// Number of shares supplied.
        actual: usize,
    },
    /// At most 255 distinct shares exist.
    TooManyShares {
        /// Number of shares supplied.
        actual: usize,
    },
    /// A share does not match its recorded commitment.
    CommitmentMismatch {
        /// Index of the share that failed verification.
        index: u8,
    },
    /// The operating-system entropy source failed.
    EntropyUnavailable,
}

impl fmt::Display for SharingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold { threshold, shares } => write!(
                f,
                "invalid sharing threshold {threshold} for {shares} shares (need 2 <= t <= n)"
            ),
            Self::InvalidSecretLength { actual } => write!(
                f,
                "secret length {actual} is outside 1..={MAX_SECRET_LEN} bytes"
            ),
            Self::InvalidShareIndex => f.write_str("share index 0 is invalid"),
            Self::DuplicateShareIndex { index } => write!(f, "duplicate share index {index}"),
            Self::ShareLengthMismatch { expected, actual } => write!(
                f,
                "share length mismatch: expected {expected} bytes, got {actual}"
            ),
            Self::TooFewShares { actual } => {
                write!(f, "at least 2 shares are required, got {actual}")
            }
            Self::TooManyShares { actual } => {
                write!(f, "at most 255 shares are supported, got {actual}")
            }
            Self::CommitmentMismatch { index } => {
                write!(f, "share {index} does not match its commitment")
            }
            Self::EntropyUnavailable => f.write_str("os entropy source unavailable"),
        }
    }
}

impl StdError for SharingError {}

impl SharingError {
    /// Coarse error classification; see [`crate::error::ErrorKind`].
    pub fn kind(&self) -> crate::error::ErrorKind {
        use crate::error::ErrorKind;
        match self {
            Self::InvalidThreshold { .. }
            | Self::InvalidSecretLength { .. }
            | Self::InvalidShareIndex
            | Self::DuplicateShareIndex { .. }
            | Self::ShareLengthMismatch { .. }
            | Self::TooFewShares { .. }
            | Self::TooManyShares { .. } => ErrorKind::InvalidInput,
            Self::CommitmentMismatch { .. } => ErrorKind::Authentication,
            Self::EntropyUnavailable => ErrorKind::Randomness,
        }
    }
}

// ── GF(2^8) arithmetic (constant time) ────────────────────────────────────────

/// Multiply in GF(2^8) modulo `x^8 + x^4 + x^3 + x + 1`.
///
/// Eight fixed iterations; the conditional add and the reduction use masks
/// derived from single bits, so timing is independent of both operands.
#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut product = 0u8;
    for _ in 0..8 {
        let take = 0u8.wrapping_sub(b & 1);
        product ^= a & take;
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & carry);
        b >>= 1;
    }
    product
}

/// Invert in GF(2^8) as `a^254` (fixed square-and-multiply chain).
///
/// Returns 0 for `a == 0`; callers never invert zero because share indices
/// are distinct and non-zero.
#[inline]
fn gf_inv(a: u8) -> u8 {
    let a2 = gf_mul(a, a);
    let a4 = gf_mul(a2, a2);
    let a8 = gf_mul(a4, a4);
    let a16 = gf_mul(a8, a8);
    let a32 = gf_mul(a16, a16);
    let a64 = gf_mul(a32, a32);
    let a128 = gf_mul(a64, a64);
    // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2
    let mut r = gf_mul(a128, a64);
    r = gf_mul(r, a32);
    r = gf_mul(r, a16);
    r = gf_mul(r, a8);
    r = gf_mul(r, a4);
    gf_mul(r, a2)
}

/// Constant-time equality of two 32-byte values.
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff = std::hint::black_box(diff | (x ^ y));
    }
    std::hint::black_box(diff) == 0
}

// ── Share ─────────────────────────────────────────────────────────────────────

/// One Shamir share: the evaluation point `index` (1..=255) and the value.
///
/// # Description
/// The value is held in [`Zeroizing`] memory and wiped on drop. `Debug` prints
/// only the index and the value length. The wire form of [`Share::to_bytes`]
/// is `index ‖ value`.
#[derive(Clone)]
pub struct Share {
    index: u8,
    value: Zeroizing<Vec<u8>>,
}

impl Share {
    /// Build a share from an index and a value, for example after storage.
    ///
    /// # Arguments
    /// - `index` (`u8`): evaluation point, 1..=255.
    /// - `value` (`Vec<u8>`): share bytes, 1..=[`MAX_SECRET_LEN`]; moved into
    ///   zeroizing memory before validation, so it is wiped even on error.
    ///
    /// # Errors
    /// - [`SharingError::InvalidShareIndex`]: `index == 0`.
    /// - [`SharingError::InvalidSecretLength`]: empty or too long value.
    pub fn new(index: u8, value: Vec<u8>) -> Result<Self, SharingError> {
        let value = Zeroizing::new(value);
        if index == 0 {
            return Err(SharingError::InvalidShareIndex);
        }
        if value.is_empty() || value.len() > MAX_SECRET_LEN {
            return Err(SharingError::InvalidSecretLength {
                actual: value.len(),
            });
        }
        Ok(Self { index, value })
    }

    /// Parse the `index ‖ value` encoding produced by [`Share::to_bytes`].
    ///
    /// # Errors
    /// Same as [`Share::new`]; an empty input is
    /// [`SharingError::InvalidSecretLength`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SharingError> {
        let (index, value) = bytes
            .split_first()
            .ok_or(SharingError::InvalidSecretLength { actual: 0 })?;
        Self::new(*index, value.to_vec())
    }

    /// Encode as `index ‖ value` in zeroizing memory.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.value.len().saturating_add(1)));
        out.push(self.index);
        out.extend_from_slice(&self.value);
        out
    }

    /// The evaluation point of this share (1..=255).
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// Borrow the share value. Treat it as secret.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("value_len", &self.value.len())
            .finish_non_exhaustive()
    }
}

// ── Split / combine ───────────────────────────────────────────────────────────

/// Split `secret` into `shares` shares, any `threshold` of which reconstruct it.
///
/// # Description
/// Draws `secret.len() * (threshold - 1)` random coefficient bytes from
/// [`TryOsRng`] (held in zeroizing memory) and returns shares with indices
/// `1..=shares`, in order.
///
/// # Arguments
/// - `secret` (`&[u8]`): 1..=[`MAX_SECRET_LEN`] bytes.
/// - `threshold` (`u8`): shares needed to reconstruct, `2..=shares`.
/// - `shares` (`u8`): shares to produce, `threshold..=255`.
///
/// # Errors
/// - [`SharingError::InvalidThreshold`]: `threshold < 2` or `threshold > shares`.
/// - [`SharingError::InvalidSecretLength`]: empty or too long secret.
/// - [`SharingError::EntropyUnavailable`]: the OS entropy source failed.
///
/// # Examples
/// ```rust
/// use crypt_guard_core::sharing::split;
///
/// # fn main() -> Result<(), crypt_guard_core::sharing::SharingError> {
/// let shares = split(&[0x42; 32], 3, 5)?;
/// assert_eq!(shares.len(), 5);
/// assert_eq!(shares[4].index(), 5);
/// # Ok(())
/// # }
/// ```
pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>, SharingError> {
    split_with_rng(secret, threshold, shares, &mut TryOsRng)
}

/// [`split`] with an explicit RNG, for deterministic known-answer tests.
///
/// The coefficient bytes are drawn in one `try_fill_bytes` call; the
/// coefficients of secret byte `j` are `buf[j*(t-1) .. (j+1)*(t-1)]`, lowest
/// degree first.
pub(crate) fn split_with_rng<R: TryCryptoRng + ?Sized>(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    rng: &mut R,
) -> Result<Vec<Share>, SharingError> {
    let invalid_threshold = SharingError::InvalidThreshold { threshold, shares };
    if threshold < MIN_THRESHOLD || threshold > shares {
        return Err(invalid_threshold);
    }
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(SharingError::InvalidSecretLength {
            actual: secret.len(),
        });
    }
    let degree = usize::from(threshold)
        .checked_sub(1)
        .filter(|d| *d > 0)
        .ok_or(invalid_threshold)?;
    let coefficient_len =
        secret
            .len()
            .checked_mul(degree)
            .ok_or(SharingError::InvalidSecretLength {
                actual: secret.len(),
            })?;

    let mut coefficients = Zeroizing::new(vec![0u8; coefficient_len]);
    TryRng::try_fill_bytes(rng, coefficients.as_mut_slice())
        .map_err(|_| SharingError::EntropyUnavailable)?;

    let mut out = Vec::with_capacity(usize::from(shares));
    for x in 1..=shares {
        let mut value = Zeroizing::new(vec![0u8; secret.len()]);
        for ((slot, secret_byte), coeffs) in value
            .iter_mut()
            .zip(secret.iter())
            .zip(coefficients.chunks_exact(degree))
        {
            // Horner: f(x) = s + x * (c1 + x * (c2 + ... + x * c_d))
            let mut acc = 0u8;
            for c in coeffs.iter().rev() {
                acc = gf_mul(acc, x) ^ c;
            }
            *slot = gf_mul(acc, x) ^ secret_byte;
        }
        out.push(Share { index: x, value });
    }
    Ok(out)
}

/// Reconstruct the secret from shares by Lagrange interpolation at `x = 0`.
///
/// # Description
/// Uses every supplied share. Supplying fewer shares than the threshold used
/// at [`split`] time is not detectable and yields an unrelated value.
///
/// # Arguments
/// - `shares` (`&[Share]`): 2..=255 shares with distinct non-zero indices and
///   equal value lengths.
///
/// # Returns
/// The secret in zeroizing memory.
///
/// # Errors
/// - [`SharingError::TooFewShares`] / [`SharingError::TooManyShares`].
/// - [`SharingError::InvalidShareIndex`]: a share has index 0.
/// - [`SharingError::DuplicateShareIndex`]: two shares share an index.
/// - [`SharingError::ShareLengthMismatch`]: value lengths differ.
/// - [`SharingError::InvalidSecretLength`]: value length outside 1..=[`MAX_SECRET_LEN`].
pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, SharingError> {
    if shares.len() < 2 {
        return Err(SharingError::TooFewShares {
            actual: shares.len(),
        });
    }
    if shares.len() > 255 {
        return Err(SharingError::TooManyShares {
            actual: shares.len(),
        });
    }
    let len = shares.first().map(|s| s.value.len()).unwrap_or(0);
    if len == 0 || len > MAX_SECRET_LEN {
        return Err(SharingError::InvalidSecretLength { actual: len });
    }
    let mut seen = [false; 256];
    for share in shares {
        if share.index == 0 {
            return Err(SharingError::InvalidShareIndex);
        }
        let slot = seen
            .get_mut(usize::from(share.index))
            .ok_or(SharingError::InvalidShareIndex)?;
        if *slot {
            return Err(SharingError::DuplicateShareIndex { index: share.index });
        }
        *slot = true;
        if share.value.len() != len {
            return Err(SharingError::ShareLengthMismatch {
                expected: len,
                actual: share.value.len(),
            });
        }
    }

    let mut secret = Zeroizing::new(vec![0u8; len]);
    for (i, share_i) in shares.iter().enumerate() {
        // l_i(0) = prod_{j != i} x_j / (x_i - x_j); subtraction is XOR here.
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (j, share_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = gf_mul(numerator, share_j.index);
            denominator = gf_mul(denominator, share_i.index ^ share_j.index);
        }
        let basis = gf_mul(numerator, gf_inv(denominator));
        for (out, y) in secret.iter_mut().zip(share_i.value.iter()) {
            *out ^= gf_mul(basis, *y);
        }
    }
    Ok(secret)
}

// ── Commitments ───────────────────────────────────────────────────────────────

/// Commit to a share under a context, so a bad share is attributable later.
///
/// # Description
/// ```text
/// SHA3-256("crypt_guard/v3/share-commitment"
///          ‖ u64_be(len(context)) ‖ context
///          ‖ index
///          ‖ u64_be(len(value)) ‖ value)
/// ```
/// Publish the commitments when distributing shares (for example signed by
/// the dealer); at reconstruction time [`check_commitment`] names the holder
/// whose share does not match. See the module security notes on short secrets.
///
/// # Arguments
/// - `share` (`&Share`): the share to commit to.
/// - `context` (`&[u8]`): binds the commitment to one sharing (e.g. group id ‖ epoch).
///
/// # Concurrency
/// Pure function; callable from any thread.
pub fn commitment(share: &Share, context: &[u8]) -> [u8; COMMITMENT_LEN] {
    // usize always fits in u64 on supported targets; saturate rather than panic.
    let context_len = u64::try_from(context.len()).unwrap_or(u64::MAX);
    let value_len = u64::try_from(share.value.len()).unwrap_or(u64::MAX);
    let mut h = Sha3_256::new();
    Digest::update(&mut h, COMMITMENT_LABEL);
    Digest::update(&mut h, context_len.to_be_bytes());
    Digest::update(&mut h, context);
    Digest::update(&mut h, [share.index]);
    Digest::update(&mut h, value_len.to_be_bytes());
    Digest::update(&mut h, share.value.as_slice());
    h.finalize().into()
}

/// Check a share against a commitment in constant time.
///
/// # Returns
/// `true` if `expected == commitment(share, context)`.
pub fn verify_commitment(share: &Share, context: &[u8], expected: &[u8; COMMITMENT_LEN]) -> bool {
    ct_eq_32(&commitment(share, context), expected)
}

/// Like [`verify_commitment`], but returns a typed, attributable error.
///
/// # Errors
/// - [`SharingError::CommitmentMismatch`] naming the share index.
pub fn check_commitment(
    share: &Share,
    context: &[u8],
    expected: &[u8; COMMITMENT_LEN],
) -> Result<(), SharingError> {
    if verify_commitment(share, context, expected) {
        Ok(())
    } else {
        Err(SharingError::CommitmentMismatch { index: share.index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256, Shake256Reader,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Deterministic test RNG: the SHAKE256 output stream of a fixed seed.
    struct ShakeRng(Shake256Reader);

    impl ShakeRng {
        fn new(seed: &[u8]) -> Self {
            let mut xof = Shake256::default();
            xof.update(seed);
            Self(xof.finalize_xof())
        }
    }

    impl TryRng for ShakeRng {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.0.read(&mut b);
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.0.read(&mut b);
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read(dst);
            Ok(())
        }
    }

    impl TryCryptoRng for ShakeRng {}

    /// Branchy reference multiplication ("Russian peasant"), test only.
    fn gf_mul_reference(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        while b != 0 {
            if b & 1 == 1 {
                p ^= a;
            }
            let hi = a & 0x80 != 0;
            a <<= 1;
            if hi {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    #[test]
    fn gf_mul_matches_fips197_examples() {
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf_mul(0x57, 0x13), 0xFE);
        assert_eq!(gf_inv(0x53), 0xCA);
    }

    #[test]
    fn gf_mul_matches_reference_for_all_pairs() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), gf_mul_reference(a, b), "{a:#04x} * {b:#04x}");
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
    }

    #[test]
    fn gf_identities_and_inverse_for_all_elements() {
        assert_eq!(gf_inv(0), 0);
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(a, 0), 0);
            if a != 0 {
                assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a:#04x}");
                assert_eq!(gf_inv(gf_inv(a)), a);
            }
        }
    }

    #[test]
    fn gf_mul_distributes_over_xor() {
        for a in (0..=255u8).step_by(7) {
            for b in (0..=255u8).step_by(5) {
                for c in (0..=255u8).step_by(11) {
                    assert_eq!(gf_mul(a, b ^ c), gf_mul(a, b) ^ gf_mul(a, c));
                }
            }
        }
    }

    /// Shares computed independently with a Python reference implementation
    /// of the same layout (SHAKE256 coefficient stream, Horner evaluation).
    #[test]
    fn split_known_answer() -> TestResult {
        let mut rng = ShakeRng::new(b"crypt_guard/test/sharing-rng");
        let shares = split_with_rng(b"0123456789abcdef", 3, 5, &mut rng)?;
        let expected = [
            "8928574f0e6c751549ce2e6d49b4d2a6",
            "03a2cf1cb2b5f0cc4dd51cfdb8fcabc8",
            "babbaa6088ecb3ee3c2253f2922c1c08",
            "25be0f1cc6e6ba10b89e3a75c4c338f5",
            "9ca76a60fcbff932c969757aee138f35",
        ];
        assert_eq!(shares.len(), expected.len());
        for (i, (share, want)) in shares.iter().zip(expected.iter()).enumerate() {
            assert_eq!(usize::from(share.index()), i + 1);
            assert_eq!(hex::encode(share.value()), *want);
        }
        let subset = [shares[0].clone(), shares[2].clone(), shares[4].clone()];
        assert_eq!(&combine(&subset)?[..], b"0123456789abcdef");
        Ok(())
    }

    #[test]
    fn ct_eq_detects_every_single_byte_difference() {
        let a = [0x5Au8; 32];
        assert!(ct_eq_32(&a, &a));
        for i in 0..32 {
            let mut b = a;
            if let Some(byte) = b.get_mut(i) {
                *byte ^= 0x01;
            }
            assert!(!ct_eq_32(&a, &b), "difference at byte {i}");
        }
    }
}
