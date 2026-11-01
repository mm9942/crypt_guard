//! M0-ext building blocks for messengers: `prf`, `sharing`, `pq_stream`,
//! `pq_multi` and `HpkeEnvelope::open_pinned_zeroizing`.
//!
//! # Responsibility scope
//! Integration tests of the additive 3.2.0 primitives through the facade
//! paths `crypt_guard::{prf, sharing, pq_stream, pq_multi, pq_hpke}`:
//! - Known-answer tests computed independently with Python `hashlib`
//!   (`shake_256`, `sha3_256`).
//! - Shamir: every threshold subset reconstructs, `t - 1` shares do not,
//!   malformed share sets are rejected, commitments attribute bad shares.
//! - STREAM: round trip, reorder, truncation, extension, tamper, wrong AAD.
//! - Multi-recipient seal: every recipient opens, outsiders and any binding
//!   change (header, body, recipient set, fingerprint, suite) fail.
//!
//! No test uses `unwrap` or `expect`; failures surface through `TestResult`.
//!
//! # Examples
//! ```text
//! cargo test -p crypt_guard --test m0_ext_primitives
//! ```

use crypt_guard::error::CryptError;
use crypt_guard::pq_stream::{
    derive_stream_key, random_prefix, StreamDecryptor, StreamEncryptor, STREAM_TAG_LEN,
};
use crypt_guard::prf::{prf, prf32, PRF_MAX_OUTPUT_LEN};
use crypt_guard::sharing::{
    check_commitment, combine, commitment, split, verify_commitment, Share, SharingError,
    MAX_SECRET_LEN,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Select shares by position; errors instead of panicking on a bad position.
fn pick(shares: &[Share], positions: &[usize]) -> Result<Vec<Share>, Box<dyn std::error::Error>> {
    positions
        .iter()
        .map(|p| {
            shares
                .get(*p)
                .cloned()
                .ok_or_else(|| Box::<dyn std::error::Error>::from("share position out of range"))
        })
        .collect()
}

/// All `k`-element subsets of `0..n`, in lexicographic order.
fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn go(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            go(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    go(0, n, k, &mut Vec::new(), &mut out);
    out
}

// ── prf ──────────────────────────────────────────────────────────────────────

#[test]
fn prf_known_answers_match_python_hashlib() -> TestResult {
    // shake_256(b"crypt_guard/v3/prf" + lp32(label) + lp32(key) + lp32(input)
    //           + be32(n)).digest(n), lp32(x) = be32(len(x)) + x
    let key: Vec<u8> = (0u8..32).collect();
    let out32 = prf32(&key, b"mailbox-id", b"alice@example")?;
    assert_eq!(
        hex::encode(&out32[..]),
        "86124c8b9d90980fc84e7f8a9c31a11318e1ed7439ab4dae5d6b9eefb60b487b"
    );

    let mut out64 = [0u8; 64];
    prf(&key, b"mailbox-id", b"alice@example", &mut out64)?;
    assert_eq!(
        hex::encode(out64),
        "dfcb583e9583ff37a39f0bdc5dfc0005aa233b2785134a670f7eb9331e317319\
         f2cc8497f7460aecbe515085c3f9de47cca79e241518043707f24f0806c6ce75"
    );

    let short_key: Vec<u8> = (0u8..16).collect();
    let mut out16 = [0u8; 16];
    prf(&short_key, b"capability", b"", &mut out16)?;
    assert_eq!(hex::encode(out16), "174903a8cb366dce9b2c6baaed2ac6cc");
    Ok(())
}

#[test]
fn prf_separates_labels_keys_and_inputs() -> TestResult {
    let base = prf32(&[1u8; 32], b"label-a", b"input")?;
    assert_ne!(*base, *prf32(&[1u8; 32], b"label-b", b"input")?);
    assert_ne!(*base, *prf32(&[2u8; 32], b"label-a", b"input")?);
    assert_ne!(*base, *prf32(&[1u8; 32], b"label-a", b"input2")?);
    // Moving bytes between fields must not collide (length prefixes).
    assert_ne!(
        *prf32(&[1u8; 32], b"ab", b"c")?,
        *prf32(&[1u8; 32], b"a", b"bc")?
    );
    Ok(())
}

#[test]
fn prf_rejects_invalid_parameters() {
    let mut out = [0u8; 32];
    assert!(matches!(
        prf(&[0u8; 15], b"label", b"", &mut out),
        Err(CryptError::InvalidParameters)
    ));
    assert!(matches!(
        prf(&[0u8; 32], b"", b"", &mut out),
        Err(CryptError::InvalidParameters)
    ));
    assert!(matches!(
        prf(&[0u8; 32], &[b'x'; 256], b"", &mut out),
        Err(CryptError::InvalidParameters)
    ));
    let mut empty = [0u8; 0];
    assert!(matches!(
        prf(&[0u8; 32], b"label", b"", &mut empty),
        Err(CryptError::InvalidParameters)
    ));
    let mut too_long = vec![0u8; PRF_MAX_OUTPUT_LEN + 1];
    assert!(matches!(
        prf(&[0u8; 32], b"label", b"", &mut too_long),
        Err(CryptError::InvalidParameters)
    ));
    let mut max = vec![0u8; PRF_MAX_OUTPUT_LEN];
    assert!(prf(&[0u8; 32], &[b'x'; 255], b"", &mut max).is_ok());
}

// ── sharing ──────────────────────────────────────────────────────────────────

#[test]
fn sharing_every_threshold_subset_reconstructs() -> TestResult {
    let secret: Vec<u8> = (0u8..32).map(|b| b.wrapping_mul(37) ^ 0x5A).collect();
    let shares = split(&secret, 3, 5)?;
    assert_eq!(shares.len(), 5);
    for (i, share) in shares.iter().enumerate() {
        assert_eq!(usize::from(share.index()), i + 1);
        assert_eq!(share.value().len(), secret.len());
    }
    for k in 3..=5 {
        for positions in subsets(5, k) {
            let subset = pick(&shares, &positions)?;
            assert_eq!(&combine(&subset)?[..], &secret[..], "subset {positions:?}");
            // Order of the shares does not matter.
            let reversed: Vec<Share> = subset.into_iter().rev().collect();
            assert_eq!(&combine(&reversed)?[..], &secret[..]);
        }
    }
    Ok(())
}

#[test]
fn sharing_below_threshold_does_not_reconstruct() -> TestResult {
    let secret = [0xC3u8; 32];
    let shares = split(&secret, 3, 5)?;
    // Two points of a degree-2 polynomial interpolate to s + c2*x1*x2 at 0,
    // so equality would need all 32 top coefficients to be zero (2^-256).
    for positions in subsets(5, 2) {
        let subset = pick(&shares, &positions)?;
        assert_ne!(&combine(&subset)?[..], &secret[..], "subset {positions:?}");
    }
    // A single share is rejected outright.
    let one = pick(&shares, &[0])?;
    assert!(matches!(
        combine(&one),
        Err(SharingError::TooFewShares { actual: 1 })
    ));
    Ok(())
}

#[test]
fn sharing_maximum_parameters_round_trip() -> TestResult {
    let secret = [0x7Eu8; 16];
    let shares = split(&secret, 255, 255)?;
    assert_eq!(shares.len(), 255);
    assert_eq!(&combine(&shares)?[..], &secret[..]);

    let big = vec![0xA5u8; MAX_SECRET_LEN];
    let shares = split(&big, 2, 2)?;
    assert_eq!(&combine(&shares)?[..], &big[..]);
    Ok(())
}

#[test]
fn sharing_rejects_invalid_split_parameters() {
    assert!(matches!(
        split(b"secret", 1, 3),
        Err(SharingError::InvalidThreshold {
            threshold: 1,
            shares: 3
        })
    ));
    assert!(matches!(
        split(b"secret", 4, 3),
        Err(SharingError::InvalidThreshold { .. })
    ));
    assert!(matches!(
        split(b"", 2, 3),
        Err(SharingError::InvalidSecretLength { actual: 0 })
    ));
    let too_big = vec![0u8; MAX_SECRET_LEN + 1];
    assert!(matches!(
        split(&too_big, 2, 3),
        Err(SharingError::InvalidSecretLength { .. })
    ));
}

#[test]
fn sharing_rejects_duplicate_zero_and_mismatched_shares() -> TestResult {
    let shares = split(b"0123456789abcdef", 2, 3)?;
    let a = pick(&shares, &[0])?;
    let duplicate = pick(&shares, &[0, 1, 0])?;
    assert!(matches!(
        combine(&duplicate),
        Err(SharingError::DuplicateShareIndex { index: 1 })
    ));

    assert!(matches!(
        Share::new(0, vec![1, 2, 3]),
        Err(SharingError::InvalidShareIndex)
    ));
    assert!(matches!(
        Share::new(1, Vec::new()),
        Err(SharingError::InvalidSecretLength { actual: 0 })
    ));
    assert!(matches!(
        Share::from_bytes(&[]),
        Err(SharingError::InvalidSecretLength { actual: 0 })
    ));
    assert!(matches!(
        Share::from_bytes(&[0, 9, 9]),
        Err(SharingError::InvalidShareIndex)
    ));

    let short = Share::new(9, vec![0u8; 15])?;
    let mut mismatched = a;
    mismatched.push(short);
    assert!(matches!(
        combine(&mismatched),
        Err(SharingError::ShareLengthMismatch {
            expected: 16,
            actual: 15
        })
    ));
    Ok(())
}

#[test]
fn share_encoding_round_trips_and_debug_is_redacted() -> TestResult {
    let share = Share::new(7, vec![201, 202, 203, 204])?;
    let bytes = share.to_bytes();
    assert_eq!(&bytes[..], &[7, 201, 202, 203, 204]);
    let parsed = Share::from_bytes(&bytes)?;
    assert_eq!(parsed.index(), 7);
    assert_eq!(parsed.value(), share.value());

    let debug = format!("{share:?}");
    assert!(debug.contains("index: 7"));
    assert!(!debug.contains("201"), "share bytes leaked: {debug}");
    assert!(!debug.contains("cb"), "share bytes leaked: {debug}");
    Ok(())
}

#[test]
fn sharing_commitment_known_answer() -> TestResult {
    // sha3_256(b"crypt_guard/v3/share-commitment" + be64(len(ctx)) + ctx
    //          + bytes([index]) + be64(len(value)) + value)
    let share = Share::new(3, (0xA0u8..0xC0).collect())?;
    let c = commitment(&share, b"group-42/epoch-7");
    assert_eq!(
        hex::encode(c),
        "7489c4d3eb16f218d836912349c604c96d0ee4452834445200d454b20d55a690"
    );
    Ok(())
}

#[test]
fn sharing_commitments_attribute_a_bad_share() -> TestResult {
    let context = b"group-42/epoch-7";
    let shares = split(&[0x11u8; 32], 2, 3)?;
    let commitments: Vec<[u8; 32]> = shares.iter().map(|s| commitment(s, context)).collect();
    for (share, c) in shares.iter().zip(commitments.iter()) {
        assert!(verify_commitment(share, context, c));
        check_commitment(share, context, c)?;
        assert!(!verify_commitment(share, b"other-context", c));
    }

    // Holder 2 presents a modified share: its commitment names it.
    let honest = pick(&shares, &[1])?;
    let honest = honest.first().ok_or("missing share")?;
    let mut forged_value = honest.value().to_vec();
    if let Some(byte) = forged_value.first_mut() {
        *byte ^= 0x01;
    }
    let forged = Share::new(honest.index(), forged_value)?;
    let recorded = commitments.get(1).ok_or("missing commitment")?;
    assert!(matches!(
        check_commitment(&forged, context, recorded),
        Err(SharingError::CommitmentMismatch { index: 2 })
    ));
    // A share presented under another holder's commitment is rejected too.
    let other = commitments.first().ok_or("missing commitment")?;
    assert!(!verify_commitment(honest, context, other));
    Ok(())
}

#[test]
fn sharing_error_converts_into_crypt_error() {
    assert!(matches!(
        CryptError::from(SharingError::DuplicateShareIndex { index: 3 }),
        CryptError::InvalidParameters
    ));
    assert!(matches!(
        CryptError::from(SharingError::ShareLengthMismatch {
            expected: 1,
            actual: 2
        }),
        CryptError::InvalidDataLength
    ));
    assert!(matches!(
        CryptError::from(SharingError::CommitmentMismatch { index: 1 }),
        CryptError::AuthenticationFailed
    ));
    assert_eq!(
        SharingError::CommitmentMismatch { index: 1 }.kind(),
        crypt_guard::error::ErrorKind::Authentication
    );
    assert_eq!(
        SharingError::EntropyUnavailable.kind(),
        crypt_guard::error::ErrorKind::Randomness
    );
}

// ── pq_stream ────────────────────────────────────────────────────────────────

const STREAM_KEY: [u8; 32] = [0x24; 32];
const PREFIX: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
const AAD: &[u8] = b"file=report.pdf";

/// Seal `chunks` (the last one as the final chunk) into a ciphertext stream.
fn seal_stream(chunks: &[&[u8]]) -> Result<Vec<Vec<u8>>, CryptError> {
    let mut enc = StreamEncryptor::new(&STREAM_KEY, PREFIX)?;
    let mut out = Vec::new();
    let (last, rest) = chunks.split_last().ok_or(CryptError::InvalidParameters)?;
    for chunk in rest {
        out.push(enc.encrypt_next(chunk, AAD)?);
    }
    out.push(enc.encrypt_last(last, AAD)?);
    Ok(out)
}

fn three_chunk_stream() -> Result<Vec<Vec<u8>>, CryptError> {
    let chunks: [&[u8]; 3] = [b"chunk zero ", b"chunk one ", b"final chunk"];
    seal_stream(&chunks)
}

fn get(stream: &[Vec<u8>], i: usize) -> Result<&[u8], Box<dyn std::error::Error>> {
    Ok(stream.get(i).ok_or("chunk index out of range")?.as_slice())
}

#[test]
fn stream_round_trip() -> TestResult {
    let stream = three_chunk_stream()?;
    assert_eq!(stream.len(), 3);
    assert_eq!(
        get(&stream, 0)?.len(),
        b"chunk zero ".len() + STREAM_TAG_LEN
    );

    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    let mut plain = Vec::new();
    plain.extend_from_slice(&dec.decrypt_next(get(&stream, 0)?, AAD)?);
    plain.extend_from_slice(&dec.decrypt_next(get(&stream, 1)?, AAD)?);
    assert_eq!(dec.chunks_opened(), 2);
    plain.extend_from_slice(&dec.decrypt_last(get(&stream, 2)?, AAD)?);
    assert_eq!(plain, b"chunk zero chunk one final chunk");

    // A single, empty final chunk is a valid stream.
    let empty = StreamEncryptor::new(&STREAM_KEY, PREFIX)?.encrypt_last(b"", AAD)?;
    assert_eq!(empty.len(), STREAM_TAG_LEN);
    let opened = StreamDecryptor::new(&STREAM_KEY, PREFIX)?.decrypt_last(&empty, AAD)?;
    assert!(opened.is_empty());
    Ok(())
}

#[test]
fn stream_detects_reordering() -> TestResult {
    let stream = three_chunk_stream()?;
    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    assert!(matches!(
        dec.decrypt_next(get(&stream, 1)?, AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    Ok(())
}

#[test]
fn stream_detects_truncation() -> TestResult {
    let stream = three_chunk_stream()?;

    // Final chunk dropped: the receiver hits EOF after chunk 1 and treats it
    // as final. It was sealed as non-final, so the stream never completes.
    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    dec.decrypt_next(get(&stream, 0)?, AAD)?;
    assert!(matches!(
        dec.decrypt_last(get(&stream, 1)?, AAD),
        Err(CryptError::AuthenticationFailed)
    ));

    // Cut after the first chunk.
    let dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    assert!(matches!(
        dec.decrypt_last(get(&stream, 0)?, AAD),
        Err(CryptError::AuthenticationFailed)
    ));

    // All non-final chunks verify, but without the final chunk there is no
    // successful `decrypt_last`: an empty or garbage tail never completes.
    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    dec.decrypt_next(get(&stream, 0)?, AAD)?;
    dec.decrypt_next(get(&stream, 1)?, AAD)?;
    assert!(matches!(
        dec.decrypt_last(&[], AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    Ok(())
}

#[test]
fn stream_detects_extension_after_the_final_chunk() -> TestResult {
    let stream = three_chunk_stream()?;
    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    dec.decrypt_next(get(&stream, 0)?, AAD)?;
    dec.decrypt_next(get(&stream, 1)?, AAD)?;
    // The final chunk presented as a non-final one (more data claimed to follow).
    assert!(matches!(
        dec.decrypt_next(get(&stream, 2)?, AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    Ok(())
}

#[test]
fn stream_detects_tampering_and_poisons_the_decryptor() -> TestResult {
    let stream = three_chunk_stream()?;
    let mut tampered = get(&stream, 0)?.to_vec();
    if let Some(byte) = tampered.first_mut() {
        *byte ^= 0x80;
    }
    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    assert!(matches!(
        dec.decrypt_next(&tampered, AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    // Poisoned: even the authentic chunk is refused now.
    assert!(matches!(
        dec.decrypt_next(get(&stream, 0)?, AAD),
        Err(CryptError::UnsupportedOperation)
    ));
    assert!(matches!(
        dec.decrypt_last(get(&stream, 2)?, AAD),
        Err(CryptError::UnsupportedOperation)
    ));

    // A modified tag is detected as well.
    let mut bad_tag = get(&stream, 2)?.to_vec();
    if let Some(byte) = bad_tag.last_mut() {
        *byte ^= 0x01;
    }
    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    dec.decrypt_next(get(&stream, 0)?, AAD)?;
    dec.decrypt_next(get(&stream, 1)?, AAD)?;
    assert!(matches!(
        dec.decrypt_last(&bad_tag, AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    Ok(())
}

#[test]
fn stream_rejects_wrong_aad_key_and_prefix() -> TestResult {
    let stream = three_chunk_stream()?;
    let mut dec = StreamDecryptor::new(&STREAM_KEY, PREFIX)?;
    assert!(matches!(
        dec.decrypt_next(get(&stream, 0)?, b"file=other.pdf"),
        Err(CryptError::AuthenticationFailed)
    ));
    let mut dec = StreamDecryptor::new(&[0x25; 32], PREFIX)?;
    assert!(matches!(
        dec.decrypt_next(get(&stream, 0)?, AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    let mut dec = StreamDecryptor::new(&STREAM_KEY, [1, 2, 3, 4, 5, 6, 8])?;
    assert!(matches!(
        dec.decrypt_next(get(&stream, 0)?, AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    Ok(())
}

#[test]
fn stream_rejects_zero_prefix_and_random_prefix_is_non_zero() -> TestResult {
    assert!(matches!(
        StreamEncryptor::new(&STREAM_KEY, [0; 7]),
        Err(CryptError::InvalidNonce)
    ));
    assert!(matches!(
        StreamDecryptor::new(&STREAM_KEY, [0; 7]),
        Err(CryptError::InvalidNonce)
    ));
    let a = random_prefix()?;
    let b = random_prefix()?;
    assert_ne!(a, [0; 7]);
    assert_ne!(
        a, b,
        "two 56-bit random prefixes collide with probability 2^-56"
    );
    Ok(())
}

#[test]
fn stream_key_derivation_known_answer_and_separation() -> TestResult {
    // shake_256(b"crypt_guard/v3/prf" + lp32(b"pq_stream/file-key")
    //           + lp32(b"\x42"*32) + lp32(b"file-0001") + be32(32)).digest(32)
    let key = derive_stream_key(&[0x42; 32], b"file-0001")?;
    assert_eq!(
        hex::encode(&key[..]),
        "e0600970fa879c43b2cf8825bbb98b2b9f13077a752e4e9c1a947ce6463da6df"
    );
    let other = derive_stream_key(&[0x42; 32], b"file-0002")?;
    assert_ne!(*key, *other);

    // Streams under the two derived keys do not cross-decrypt.
    let sealed = StreamEncryptor::new(&key, PREFIX)?.encrypt_last(b"data", AAD)?;
    assert!(matches!(
        StreamDecryptor::new(&other, PREFIX)?.decrypt_last(&sealed, AAD),
        Err(CryptError::AuthenticationFailed)
    ));
    Ok(())
}

// ── open_pinned ──────────────────────────────────────────────────────────────

#[test]
fn open_pinned_rejects_a_substituted_wire_suite() -> TestResult {
    use crypt_guard::pq_hpke::{
        derive_recipient_key_pair, Aead, Error, HpkeEnvelope, Kdf, Kem, Suite, DEFAULT_SUITE,
    };

    let keys = derive_recipient_key_pair(DEFAULT_SUITE.kem(), &[0x31; 32])?;
    let record = HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), b"i", b"a", b"msg")?;
    let opened = record.open_pinned_zeroizing(DEFAULT_SUITE, keys.private_key(), b"i", b"a")?;
    assert_eq!(&opened[..], b"msg");

    // Same KEM, different AEAD: the unpinned open accepts it, the pinned one
    // refuses before any decapsulation.
    let other = Suite::new(Kem::MlKem1024P384, Kdf::Shake256, Aead::Aes256Gcm);
    let substituted = HpkeEnvelope::seal(other, keys.public_key(), b"i", b"a", b"msg")?;
    assert_eq!(
        &substituted.open_zeroizing(keys.private_key(), b"i", b"a")?[..],
        b"msg"
    );
    assert!(matches!(
        substituted.open_pinned_zeroizing(DEFAULT_SUITE, keys.private_key(), b"i", b"a"),
        Err(Error::UnavailableCapability { suite, .. }) if suite == other
    ));
    assert!(matches!(
        CryptError::from(Error::UnavailableCapability {
            suite: other,
            reason: "pinned"
        }),
        CryptError::UnsupportedAlgorithm
    ));
    Ok(())
}

// ── pq_multi ─────────────────────────────────────────────────────────────────

#[cfg(feature = "ml-kem-backend")]
mod multi {
    use super::TestResult;
    use crypt_guard::error::CryptError;
    use crypt_guard::pq_hpke::{
        derive_recipient_key_pair, Aead, Kdf, Kem, RecipientKeyPair, Suite, DEFAULT_SUITE,
    };
    use crypt_guard::pq_multi::{
        dummy_wrap, open_multi, recipient_set_hash, seal_multi, MultiRecipientCiphertext,
    };

    const HEADER: &[u8] = b"group=7;epoch=3;msg=42";
    const INFO: &[u8] = b"comnet/group-message/v1";
    const PAYLOAD: &[u8] = b"hello, group";

    fn member(seed: u8) -> Result<RecipientKeyPair, Box<dyn std::error::Error>> {
        Ok(derive_recipient_key_pair(DEFAULT_SUITE.kem(), &[seed; 32])?)
    }

    fn members() -> Result<Vec<RecipientKeyPair>, Box<dyn std::error::Error>> {
        (1u8..=3).map(member).collect()
    }

    fn seal_for(keys: &[RecipientKeyPair]) -> Result<MultiRecipientCiphertext, CryptError> {
        let public: Vec<_> = keys.iter().map(RecipientKeyPair::public_key).collect();
        seal_multi(DEFAULT_SUITE, &public, HEADER, INFO, PAYLOAD)
    }

    fn open_as(
        keys: &RecipientKeyPair,
        ct: &MultiRecipientCiphertext,
        index: usize,
        header: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptError> {
        let fp = keys.public_key().fingerprint();
        open_multi(
            DEFAULT_SUITE,
            keys.private_key(),
            &fp,
            ct,
            index,
            header,
            INFO,
        )
    }

    #[test]
    fn three_recipients_each_open() -> TestResult {
        let keys = members()?;
        let ct = seal_for(&keys)?;
        assert_eq!(ct.wraps.len(), 3);
        for (index, k) in keys.iter().enumerate() {
            assert_eq!(&open_as(k, &ct, index, HEADER)?[..], PAYLOAD);
        }
        let fps: Vec<[u8; 32]> = keys.iter().map(|k| k.public_key().fingerprint()).collect();
        assert_eq!(ct.recipient_set_hash, recipient_set_hash(&fps)?);
        ct.check_recipient_set(&fps)?;
        Ok(())
    }

    #[test]
    fn outsider_cannot_open_any_wrap() -> TestResult {
        let keys = members()?;
        let ct = seal_for(&keys)?;
        let outsider = member(99)?;
        for index in 0..ct.wraps.len() {
            assert!(matches!(
                open_as(&outsider, &ct, index, HEADER),
                Err(CryptError::AuthenticationFailed)
            ));
        }
        Ok(())
    }

    #[test]
    fn member_cannot_open_another_members_wrap() -> TestResult {
        let keys = members()?;
        let ct = seal_for(&keys)?;
        let first = keys.first().ok_or("missing member")?;
        assert!(matches!(
            open_as(first, &ct, 1, HEADER),
            Err(CryptError::AuthenticationFailed)
        ));
        assert!(matches!(
            open_as(first, &ct, 3, HEADER),
            Err(CryptError::InvalidParameters)
        ));
        Ok(())
    }

    #[test]
    fn swapped_header_aad_fails() -> TestResult {
        let keys = members()?;
        let ct = seal_for(&keys)?;
        let first = keys.first().ok_or("missing member")?;
        assert!(matches!(
            open_as(first, &ct, 0, b"group=7;epoch=4;msg=42"),
            Err(CryptError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn tampered_body_fails() -> TestResult {
        let keys = members()?;
        let mut ct = seal_for(&keys)?;
        if let Some(byte) = ct.body.first_mut() {
            *byte ^= 0x01;
        }
        let first = keys.first().ok_or("missing member")?;
        assert!(matches!(
            open_as(first, &ct, 0, HEADER),
            Err(CryptError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn tampered_wrap_fails() -> TestResult {
        let keys = members()?;
        let mut ct = seal_for(&keys)?;
        if let Some(byte) = ct.wraps.first_mut().and_then(|w| w.last_mut()) {
            *byte ^= 0x01;
        }
        let first = keys.first().ok_or("missing member")?;
        assert!(matches!(
            open_as(first, &ct, 0, HEADER),
            Err(CryptError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn recipient_set_hash_is_a_set_hash_bound_to_membership() -> TestResult {
        let keys = members()?;
        let fps: Vec<[u8; 32]> = keys.iter().map(|k| k.public_key().fingerprint()).collect();
        let mut reordered = fps.clone();
        reordered.reverse();
        // Reordering the recipients keeps the set (every member recomputes
        // the same hash from its own membership view) ...
        assert_eq!(recipient_set_hash(&fps)?, recipient_set_hash(&reordered)?);
        // ... while any change of membership changes it.
        let fewer = fps.get(..2).ok_or("missing fingerprints")?;
        assert_ne!(recipient_set_hash(&fps)?, recipient_set_hash(fewer)?);
        let mut swapped = fps.clone();
        swapped.push(member(4)?.public_key().fingerprint());
        assert_ne!(recipient_set_hash(&fps)?, recipient_set_hash(&swapped)?);

        let ct = seal_for(&keys)?;
        assert!(matches!(
            ct.check_recipient_set(fewer),
            Err(CryptError::AuthenticationFailed)
        ));
        // Duplicates are rejected, so "Alice twice" cannot pose as two members.
        let first = fps.first().ok_or("missing fingerprint")?;
        assert!(matches!(
            recipient_set_hash(&[*first, *first]),
            Err(CryptError::InvalidParameters)
        ));
        Ok(())
    }

    #[test]
    fn substituted_recipient_set_hash_fails() -> TestResult {
        let keys = members()?;
        let mut ct = seal_for(&keys)?;
        let pair = keys.get(..2).ok_or("missing members")?;
        let other = seal_for(pair)?;
        // Claim the ciphertext was for the two-member set.
        ct.recipient_set_hash = other.recipient_set_hash;
        let first = keys.first().ok_or("missing member")?;
        assert!(matches!(
            open_as(first, &ct, 0, HEADER),
            Err(CryptError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn wrong_fingerprint_fails() -> TestResult {
        let keys = members()?;
        let ct = seal_for(&keys)?;
        let first = keys.first().ok_or("missing member")?;
        let second = keys.get(1).ok_or("missing member")?;
        let wrong_fp = second.public_key().fingerprint();
        assert!(matches!(
            open_multi(
                DEFAULT_SUITE,
                first.private_key(),
                &wrong_fp,
                &ct,
                0,
                HEADER,
                INFO
            ),
            Err(CryptError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn wraps_can_be_shuffled_and_padded_with_dummies() -> TestResult {
        let keys = members()?;
        let mut ct = seal_for(&keys)?;
        let dummy = dummy_wrap(DEFAULT_SUITE)?;
        let real_len = ct.wraps.first().ok_or("missing wrap")?.len();
        assert_eq!(dummy.len(), real_len);
        assert!(ct.wraps.iter().all(|w| w.len() == real_len));

        // Pad to five wraps and move the dummies to the front.
        ct.wraps.insert(0, dummy);
        ct.wraps.insert(0, dummy_wrap(DEFAULT_SUITE)?);
        for (index, k) in keys.iter().enumerate() {
            assert_eq!(&open_as(k, &ct, index + 2, HEADER)?[..], PAYLOAD);
            for dummy_index in 0..2 {
                assert!(matches!(
                    open_as(k, &ct, dummy_index, HEADER),
                    Err(CryptError::AuthenticationFailed)
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn rejects_empty_duplicate_and_mismatched_recipients() -> TestResult {
        assert!(matches!(
            seal_multi(DEFAULT_SUITE, &[], HEADER, INFO, PAYLOAD),
            Err(CryptError::InvalidParameters)
        ));
        let a = member(1)?;
        assert!(matches!(
            seal_multi(
                DEFAULT_SUITE,
                &[a.public_key(), a.public_key()],
                HEADER,
                INFO,
                PAYLOAD
            ),
            Err(CryptError::InvalidParameters)
        ));
        let other_kem = derive_recipient_key_pair(Kem::MlKem768, &[5; 32])?;
        assert!(matches!(
            seal_multi(
                DEFAULT_SUITE,
                &[a.public_key(), other_kem.public_key()],
                HEADER,
                INFO,
                PAYLOAD
            ),
            Err(CryptError::InvalidKeyType)
        ));
        Ok(())
    }

    #[test]
    fn open_enforces_the_pinned_suite() -> TestResult {
        let keys = members()?;
        let first = keys.first().ok_or("missing member")?;
        let other = Suite::new(Kem::MlKem1024P384, Kdf::Shake256, Aead::Aes256Gcm);
        let ct = seal_multi(other, &[first.public_key()], HEADER, INFO, PAYLOAD)?;
        // Opening under the suite actually used works ...
        let fp = first.public_key().fingerprint();
        let plain = open_multi(other, first.private_key(), &fp, &ct, 0, HEADER, INFO)?;
        assert_eq!(&plain[..], PAYLOAD);
        // ... but a receiver pinned to the default suite refuses it.
        assert!(matches!(
            open_as(first, &ct, 0, HEADER),
            Err(CryptError::UnsupportedAlgorithm)
        ));
        Ok(())
    }
}
