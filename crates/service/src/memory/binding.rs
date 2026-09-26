//! KMS ciphertext framing and key binding.
//!
//! Every ciphertext produced by the in-memory provider is a `CGKC` frame:
//!
//! ```text
//! magic "CGKC" (4) | format version u8 = 1 | purpose u8 | key version u32 BE | CGH3 envelope
//! ```
//!
//! The HPKE `info` is not the caller's `info` alone but a length-prefixed
//! binding of domain label, purpose, namespace, key id, key version, suite id
//! and caller info (see [`bind_info`]). A ciphertext therefore only opens
//! under the exact key version and purpose it was made for; any mismatch is
//! an ordinary, opaque authentication failure.

use zeroize::Zeroizing;

use crypt_guard_core::pq_hpke::Suite;

use crate::{
    error::CryptoServiceError,
    key::{KeyId, KeyNamespace, KeyVersion},
};

/// Frame magic.
pub(crate) const FRAME_MAGIC: [u8; 4] = *b"CGKC";
/// Frame format version.
pub(crate) const FRAME_VERSION: u8 = 1;
/// Fixed header length: magic + format version + purpose + key version.
pub(crate) const FRAME_HEADER_LEN: usize = 10;
/// Domain label bound into every HPKE `info`.
pub(crate) const DOMAIN_LABEL: &[u8] = b"crypt_guard/kms/v1";

/// What a ciphertext is for. Encrypt and wrap ciphertexts are not
/// interchangeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Purpose {
    /// Data encryption (`Encrypt` / `Decrypt`).
    Encrypt = 1,
    /// Key wrapping (`WrapKey` / `UnwrapKey` / `RewrapKey`).
    Wrap = 2,
}

impl Purpose {
    /// Decode from the frame's purpose byte.
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Encrypt),
            2 => Some(Self::Wrap),
            _ => None,
        }
    }
}

/// A decoded frame, borrowing the envelope bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Frame<'a> {
    /// Purpose byte.
    pub(crate) purpose: Purpose,
    /// Key version the ciphertext was made under.
    pub(crate) key_version: KeyVersion,
    /// Encoded `CGH3` envelope.
    pub(crate) envelope: &'a [u8],
}

/// Encode a frame. Allocates exactly `FRAME_HEADER_LEN + envelope.len()`.
pub(crate) fn encode_frame(purpose: Purpose, key_version: KeyVersion, envelope: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + envelope.len());
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.push(purpose as u8);
    out.extend_from_slice(&key_version.get().to_be_bytes());
    out.extend_from_slice(envelope);
    out
}

/// Decode a frame. Never panics. Every error (short input, bad magic,
/// unknown format version or purpose, version 0) is
/// [`CryptoServiceError::AuthenticationFailed`], so malformed and tampered
/// ciphertexts are indistinguishable.
pub(crate) fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, CryptoServiceError> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(CryptoServiceError::AuthenticationFailed);
    }

    let (header, envelope) = bytes
        .split_at_checked(FRAME_HEADER_LEN)
        .ok_or(CryptoServiceError::AuthenticationFailed)?;

    let magic = header
        .get(0..4)
        .ok_or(CryptoServiceError::AuthenticationFailed)?;
    if magic != FRAME_MAGIC {
        return Err(CryptoServiceError::AuthenticationFailed);
    }

    let version = header
        .get(4)
        .ok_or(CryptoServiceError::AuthenticationFailed)?;
    if *version != FRAME_VERSION {
        return Err(CryptoServiceError::AuthenticationFailed);
    }

    let purpose_byte = header
        .get(5)
        .ok_or(CryptoServiceError::AuthenticationFailed)?;
    let purpose =
        Purpose::from_byte(*purpose_byte).ok_or(CryptoServiceError::AuthenticationFailed)?;

    let version_bytes: [u8; 4] = header
        .get(6..10)
        .ok_or(CryptoServiceError::AuthenticationFailed)?
        .try_into()
        .map_err(|_| CryptoServiceError::AuthenticationFailed)?;
    let key_version = KeyVersion::new(u32::from_be_bytes(version_bytes))
        .map_err(|_| CryptoServiceError::AuthenticationFailed)?;

    Ok(Frame {
        purpose,
        key_version,
        envelope,
    })
}

/// Append `lp32(bytes)` (`len(bytes)` as u32 BE, then `bytes`) to `out`.
///
/// `len` must already be known to fit in `u32` (checked by the caller when
/// computing the exact capacity), but this still validates defensively.
fn push_lp32(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CryptoServiceError> {
    let len = u32::try_from(bytes.len()).map_err(|_| CryptoServiceError::Malformed)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Exact encoded length of `lp32(bytes)`: `4 + bytes.len()`, checked.
fn lp32_len(bytes: &[u8]) -> Result<usize, CryptoServiceError> {
    // Also ensure the length itself fits in u32, as `push_lp32` requires.
    let _: u32 = u32::try_from(bytes.len()).map_err(|_| CryptoServiceError::Malformed)?;
    4usize
        .checked_add(bytes.len())
        .ok_or(CryptoServiceError::Malformed)
}

/// Build the HPKE `info` binding:
///
/// ```text
/// lp32(DOMAIN_LABEL) | purpose u8 | lp32(namespace) | lp32(id) | version u32 BE
///   | suite.suite_id() (10 bytes) | lp32(user_info)
/// ```
///
/// (`lp32(x)` = `len(x)` as u32 BE, then `x`.) The buffer is allocated with its
/// exact final capacity. Errors: any length overflow → `Malformed`.
pub(crate) fn bind_info(
    purpose: Purpose,
    namespace: &KeyNamespace,
    id: &KeyId,
    version: KeyVersion,
    suite: Suite,
    user_info: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoServiceError> {
    let namespace_bytes = namespace.as_str().as_bytes();
    let id_bytes = id.as_str().as_bytes();
    let suite_id = suite.suite_id();

    let domain_len = lp32_len(DOMAIN_LABEL)?;
    let namespace_len = lp32_len(namespace_bytes)?;
    let id_len = lp32_len(id_bytes)?;
    let info_len = lp32_len(user_info)?;

    let exact_total = domain_len
        .checked_add(1) // purpose byte
        .and_then(|n| n.checked_add(namespace_len))
        .and_then(|n| n.checked_add(id_len))
        .and_then(|n| n.checked_add(4)) // version u32 BE
        .and_then(|n| n.checked_add(suite_id.len()))
        .and_then(|n| n.checked_add(info_len))
        .ok_or(CryptoServiceError::Malformed)?;

    // The buffer length itself must also fit in u32, per contract.
    let _: u32 = u32::try_from(exact_total).map_err(|_| CryptoServiceError::Malformed)?;

    let mut out = Zeroizing::new(Vec::with_capacity(exact_total));

    push_lp32(&mut out, DOMAIN_LABEL)?;
    out.push(purpose as u8);
    push_lp32(&mut out, namespace_bytes)?;
    push_lp32(&mut out, id_bytes)?;
    out.extend_from_slice(&version.get().to_be_bytes());
    out.extend_from_slice(&suite_id);
    push_lp32(&mut out, user_info)?;

    if out.len() != exact_total {
        return Err(CryptoServiceError::Malformed);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypt_guard_core::pq_hpke::DEFAULT_SUITE;

    fn ns(s: &str) -> KeyNamespace {
        KeyNamespace::new(s).unwrap()
    }

    fn id(s: &str) -> KeyId {
        KeyId::new(s).unwrap()
    }

    #[test]
    fn frame_round_trip() {
        let envelope = b"some-envelope-bytes".to_vec();
        let key_version = KeyVersion::new(7).unwrap();
        let encoded = encode_frame(Purpose::Wrap, key_version, &envelope);
        assert_eq!(encoded.len(), FRAME_HEADER_LEN + envelope.len());

        let decoded = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.purpose, Purpose::Wrap);
        assert_eq!(decoded.key_version, key_version);
        assert_eq!(decoded.envelope, envelope.as_slice());
    }

    #[test]
    fn frame_round_trip_empty_envelope() {
        let key_version = KeyVersion::new(1).unwrap();
        let encoded = encode_frame(Purpose::Encrypt, key_version, &[]);
        let decoded = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.purpose, Purpose::Encrypt);
        assert_eq!(decoded.key_version, key_version);
        assert!(decoded.envelope.is_empty());
    }

    #[test]
    fn decode_frame_too_short_is_authentication_failed() {
        for len in 0..FRAME_HEADER_LEN {
            let bytes = vec![0u8; len];
            assert_eq!(
                decode_frame(&bytes).unwrap_err(),
                CryptoServiceError::AuthenticationFailed
            );
        }
    }

    #[test]
    fn decode_frame_bad_magic_is_authentication_failed() {
        let key_version = KeyVersion::new(1).unwrap();
        let mut encoded = encode_frame(Purpose::Encrypt, key_version, b"env");
        encoded[0] = b'X';
        assert_eq!(
            decode_frame(&encoded).unwrap_err(),
            CryptoServiceError::AuthenticationFailed
        );
    }

    #[test]
    fn decode_frame_bad_version_is_authentication_failed() {
        let key_version = KeyVersion::new(1).unwrap();
        let mut encoded = encode_frame(Purpose::Encrypt, key_version, b"env");
        encoded[4] = FRAME_VERSION.wrapping_add(1);
        assert_eq!(
            decode_frame(&encoded).unwrap_err(),
            CryptoServiceError::AuthenticationFailed
        );
    }

    #[test]
    fn decode_frame_bad_purpose_is_authentication_failed() {
        let key_version = KeyVersion::new(1).unwrap();
        let mut encoded = encode_frame(Purpose::Encrypt, key_version, b"env");
        encoded[5] = 99;
        assert_eq!(
            decode_frame(&encoded).unwrap_err(),
            CryptoServiceError::AuthenticationFailed
        );
    }

    #[test]
    fn decode_frame_zero_key_version_is_authentication_failed() {
        let key_version = KeyVersion::new(1).unwrap();
        let mut encoded = encode_frame(Purpose::Encrypt, key_version, b"env");
        // Overwrite the big-endian key version field (bytes 6..10) with 0.
        encoded[6] = 0;
        encoded[7] = 0;
        encoded[8] = 0;
        encoded[9] = 0;
        assert_eq!(
            decode_frame(&encoded).unwrap_err(),
            CryptoServiceError::AuthenticationFailed
        );
    }

    #[test]
    fn bind_info_len_equals_capacity() {
        let out = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"caller-info",
        )
        .unwrap();
        assert_eq!(out.len(), out.capacity());
    }

    #[test]
    fn bind_info_is_injective_over_purpose() {
        let a = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        let b = bind_info(
            Purpose::Wrap,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn bind_info_is_injective_over_namespace() {
        let a = bind_info(
            Purpose::Encrypt,
            &ns("tenant-a"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        let b = bind_info(
            Purpose::Encrypt,
            &ns("tenant-b"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn bind_info_is_injective_over_id() {
        let a = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        let b = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-2"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn bind_info_is_injective_over_version() {
        let a = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        let b = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(2).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn bind_info_is_injective_over_user_info() {
        let a = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info-a",
        )
        .unwrap();
        let b = bind_info(
            Purpose::Encrypt,
            &ns("tenant"),
            &id("key-1"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info-b",
        )
        .unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn bind_info_length_prefixing_disambiguates_namespace_id_split() {
        // ("ab", "c") must differ from ("a", "bc"): without length prefixes
        // the concatenation of namespace||id would collide.
        let a = bind_info(
            Purpose::Encrypt,
            &ns("ab"),
            &id("c"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        let b = bind_info(
            Purpose::Encrypt,
            &ns("a"),
            &id("bc"),
            KeyVersion::new(1).unwrap(),
            DEFAULT_SUITE,
            b"info",
        )
        .unwrap();
        assert_ne!(*a, *b);
    }
}
