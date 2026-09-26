//! Behaviour and security invariants of `InMemoryProvider`: key lifecycle,
//! encrypt/decrypt and wrap/unwrap round trips, opaque authentication
//! failures on tampering, and domain separation between purposes and key
//! versions.
//!
//! The provider is driven directly and synchronously through
//! `CryptoProvider::execute`; no Tokio runtime or `CryptoService` wrapper is
//! needed for these tests.

use crypt_guard_service::{
    pq_hpke::DEFAULT_SUITE, CiphertextBlob, CryptoContext, CryptoOperation, CryptoProvider,
    CryptoRequest, CryptoResponse, CryptoServiceError, Decrypt, DescribeKey, DestroyKey,
    DisableKey, EnableKey, Encrypt, GenerateKey, GetPublicKey, InMemoryProvider, KeyAlgorithm,
    KeyId, KeyNamespace, KeyRef, KeyState, KeyVersion, PublicBlob, RequestId, RewrapKey, RotateKey,
    SecretBytes, SignatureAlgorithm, UnwrapKey, WrapKey,
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn ns(s: &str) -> KeyNamespace {
    KeyNamespace::new(s).unwrap()
}

fn kid(s: &str) -> KeyId {
    KeyId::new(s).unwrap()
}

fn ctx(info: &[u8], aad: &[u8]) -> CryptoContext {
    CryptoContext {
        info: Box::from(info),
        aad: Box::from(aad),
    }
}

/// Execute one operation against the provider with an explicit, distinct
/// request id (ids need not be sequential; each test just picks fresh ones).
fn run(
    provider: &mut InMemoryProvider,
    id: u128,
    op: CryptoOperation,
) -> Result<CryptoResponse, CryptoServiceError> {
    CryptoProvider::execute(provider, CryptoRequest::new(RequestId(id), op))
}

fn hpke_algorithm() -> KeyAlgorithm {
    KeyAlgorithm::Hpke {
        suite: DEFAULT_SUITE,
    }
}

/// Generate a fresh HPKE key, asserting it comes back as version 1 with a
/// public key, and return both.
fn generate_hpke(
    provider: &mut InMemoryProvider,
    id: u128,
    namespace: &str,
    key_id: &str,
) -> (KeyRef, PublicBlob) {
    let op = CryptoOperation::Generate(GenerateKey {
        namespace: ns(namespace),
        id: kid(key_id),
        algorithm: hpke_algorithm(),
    });
    match run(provider, id, op).unwrap() {
        CryptoResponse::KeyCreated { key, public } => {
            assert_eq!(key.version, Some(KeyVersion::new(1).unwrap()));
            let public = public.expect("HPKE key must have a public key");
            (key, public)
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

fn encrypt(
    provider: &mut InMemoryProvider,
    id: u128,
    key: &KeyRef,
    plaintext: &[u8],
    context: CryptoContext,
) -> CiphertextBlob {
    let op = CryptoOperation::Encrypt(Encrypt {
        key: key.clone(),
        plaintext: SecretBytes::copy_from_slice(plaintext),
        context,
    });
    match run(provider, id, op).unwrap() {
        CryptoResponse::Ciphertext(blob) => blob,
        other => panic!("unexpected response: {other:?}"),
    }
}

fn decrypt(
    provider: &mut InMemoryProvider,
    id: u128,
    key: &KeyRef,
    ciphertext: CiphertextBlob,
    context: CryptoContext,
) -> Result<SecretBytes, CryptoServiceError> {
    let op = CryptoOperation::Decrypt(Decrypt {
        key: key.clone(),
        ciphertext,
        context,
    });
    run(provider, id, op).map(|resp| match resp {
        CryptoResponse::Plaintext(secret) => secret,
        other => panic!("unexpected response: {other:?}"),
    })
}

fn wrap(
    provider: &mut InMemoryProvider,
    id: u128,
    key: &KeyRef,
    material: &[u8],
    context: CryptoContext,
) -> CiphertextBlob {
    let op = CryptoOperation::WrapKey(WrapKey {
        key: key.clone(),
        material: SecretBytes::copy_from_slice(material),
        context,
    });
    match run(provider, id, op).unwrap() {
        CryptoResponse::Ciphertext(blob) => blob,
        other => panic!("unexpected response: {other:?}"),
    }
}

fn unwrap(
    provider: &mut InMemoryProvider,
    id: u128,
    key: &KeyRef,
    wrapped: CiphertextBlob,
    context: CryptoContext,
) -> Result<SecretBytes, CryptoServiceError> {
    let op = CryptoOperation::UnwrapKey(UnwrapKey {
        key: key.clone(),
        wrapped,
        context,
    });
    run(provider, id, op).map(|resp| match resp {
        CryptoResponse::Plaintext(secret) => secret,
        other => panic!("unexpected response: {other:?}"),
    })
}

// ---------------------------------------------------------------------------
// 1. Generate / describe / public key
// ---------------------------------------------------------------------------

#[test]
fn generate_describe_and_public_key_agree() {
    let mut provider = InMemoryProvider::new();
    let (key, created_public) = generate_hpke(&mut provider, 1, "app", "k1");

    let meta = match run(
        &mut provider,
        2,
        CryptoOperation::Describe(DescribeKey { key: key.clone() }),
    )
    .unwrap()
    {
        CryptoResponse::Metadata(meta) => meta,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(meta.state, KeyState::Enabled);
    assert_eq!(meta.key.version, Some(KeyVersion::new(1).unwrap()));

    let fetched_public = match run(
        &mut provider,
        3,
        CryptoOperation::PublicKey(GetPublicKey { key: key.clone() }),
    )
    .unwrap()
    {
        CryptoResponse::PublicKey(blob) => blob,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(fetched_public.as_bytes(), created_public.as_bytes());
}

// ---------------------------------------------------------------------------
// 2. Encrypt / decrypt round trip
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_roundtrip_latest_and_versioned() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let latest = KeyRef::latest(ns("app"), kid("k1"));
    let context = ctx(b"round-trip-info", b"round-trip-aad");
    let plaintext = b"the quick brown fox jumps over the lazy dog";

    let ciphertext = encrypt(&mut provider, 2, &latest, plaintext, context.clone());

    let recovered = decrypt(
        &mut provider,
        3,
        &latest,
        ciphertext.clone(),
        context.clone(),
    )
    .unwrap();
    assert_eq!(recovered.as_ref(), plaintext);

    // Same ciphertext, explicit version.
    let recovered_versioned = decrypt(&mut provider, 4, &key, ciphertext, context).unwrap();
    assert_eq!(recovered_versioned.as_ref(), plaintext);
}

// ---------------------------------------------------------------------------
// 3. Opaqueness of decryption failures
// ---------------------------------------------------------------------------

#[test]
fn decrypt_wrong_aad_is_authentication_failed() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let seal_ctx = ctx(b"info", b"aad");
    let open_ctx = ctx(b"info", b"different-aad");

    let ciphertext = encrypt(&mut provider, 2, &key, b"secret payload", seal_ctx);
    let err = decrypt(&mut provider, 3, &key, ciphertext, open_ctx).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

#[test]
fn decrypt_wrong_info_is_authentication_failed() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let seal_ctx = ctx(b"info", b"aad");
    let open_ctx = ctx(b"different-info", b"aad");

    let ciphertext = encrypt(&mut provider, 2, &key, b"secret payload", seal_ctx);
    let err = decrypt(&mut provider, 3, &key, ciphertext, open_ctx).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

#[test]
fn decrypt_flipped_byte_at_any_position_is_authentication_failed() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let context = ctx(b"info", b"aad");

    let ciphertext = encrypt(
        &mut provider,
        2,
        &key,
        b"a reasonably long plaintext so the ciphertext has plenty of bytes",
        context.clone(),
    );
    let bytes = ciphertext.as_bytes().to_vec();
    assert!(
        bytes.len() > 16,
        "ciphertext should be well beyond the header"
    );

    let mut positions: Vec<usize> = vec![
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        bytes.len() / 2,
        bytes.len() - 1,
    ];
    positions.retain(|&p| p < bytes.len());
    positions.sort_unstable();
    positions.dedup();

    for (next_id, pos) in (100u128..).zip(positions) {
        let mut tampered = bytes.clone();
        tampered[pos] ^= 0x01;
        let err = decrypt(
            &mut provider,
            next_id,
            &key,
            CiphertextBlob::new(tampered),
            context.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            CryptoServiceError::AuthenticationFailed,
            "flipping byte at position {pos} should be an opaque auth failure"
        );
    }
}

#[test]
fn decrypt_truncated_ciphertext_is_authentication_failed() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let context = ctx(b"info", b"aad");

    let ciphertext = encrypt(
        &mut provider,
        2,
        &key,
        b"plaintext long enough to truncate meaningfully",
        context.clone(),
    );
    let bytes = ciphertext.as_bytes().to_vec();

    for (next_id, len) in (200u128..).zip([1usize, 5, 9, bytes.len() / 2, bytes.len() - 1]) {
        let truncated = bytes[..len].to_vec();
        let err = decrypt(
            &mut provider,
            next_id,
            &key,
            CiphertextBlob::new(truncated),
            context.clone(),
        )
        .unwrap_err();
        assert_eq!(err, CryptoServiceError::AuthenticationFailed, "len {len}");
    }
}

#[test]
fn decrypt_empty_ciphertext_is_authentication_failed() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let context = ctx(b"info", b"aad");

    let err = decrypt(
        &mut provider,
        2,
        &key,
        CiphertextBlob::new(Vec::new()),
        context,
    )
    .unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

#[test]
fn decrypt_ciphertext_from_another_key_is_authentication_failed() {
    let mut provider = InMemoryProvider::new();
    let (key_a, _) = generate_hpke(&mut provider, 1, "app", "k1");
    let (key_b, _) = generate_hpke(&mut provider, 2, "app", "k2");
    let context = ctx(b"info", b"aad");

    let ciphertext = encrypt(&mut provider, 3, &key_a, b"only for key a", context.clone());
    let err = decrypt(&mut provider, 4, &key_b, ciphertext, context).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

#[test]
fn decrypt_explicit_wrong_version_is_authentication_failed() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let context = ctx(b"info", b"aad");

    let ciphertext = encrypt(&mut provider, 2, &key, b"payload", context.clone());
    let wrong_version = KeyRef::versioned(ns("app"), kid("k1"), KeyVersion::new(2).unwrap());
    let err = decrypt(&mut provider, 3, &wrong_version, ciphertext, context).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

#[test]
fn decrypt_unknown_key_is_not_found() {
    let mut provider = InMemoryProvider::new();
    let context = ctx(b"info", b"aad");
    let unknown = KeyRef::latest(ns("app"), kid("does-not-exist"));

    let err = decrypt(
        &mut provider,
        1,
        &unknown,
        CiphertextBlob::new(vec![0u8; 32]),
        context,
    )
    .unwrap_err();
    assert_eq!(err, CryptoServiceError::NotFound);
}

// ---------------------------------------------------------------------------
// 4. Domain separation between purposes
// ---------------------------------------------------------------------------

#[test]
fn encrypt_ciphertext_cannot_be_unwrapped() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let context = ctx(b"info", b"aad");

    let encrypted = encrypt(&mut provider, 2, &key, b"plain data", context.clone());
    let err = unwrap(&mut provider, 3, &key, encrypted, context).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

#[test]
fn wrap_output_cannot_be_decrypted() {
    let mut provider = InMemoryProvider::new();
    let (key, _public) = generate_hpke(&mut provider, 1, "app", "k1");
    let context = ctx(b"info", b"aad");

    let wrapped = wrap(
        &mut provider,
        2,
        &key,
        b"key material bytes",
        context.clone(),
    );
    let err = decrypt(&mut provider, 3, &key, wrapped, context).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

// ---------------------------------------------------------------------------
// 5. Wrap / unwrap / rewrap
// ---------------------------------------------------------------------------

#[test]
fn wrap_unwrap_roundtrip_and_rewrap_between_keys() {
    let mut provider = InMemoryProvider::new();
    let (key_a, _) = generate_hpke(&mut provider, 1, "app", "wrap-a");
    let (key_b, _) = generate_hpke(&mut provider, 2, "app", "wrap-b");
    let from_ctx = ctx(b"from-info", b"from-aad");
    let to_ctx = ctx(b"to-info", b"to-aad");
    let material = b"top secret key material to be wrapped";

    let wrapped_a = wrap(&mut provider, 3, &key_a, material, from_ctx.clone());
    let unwrapped = unwrap(
        &mut provider,
        4,
        &key_a,
        wrapped_a.clone(),
        from_ctx.clone(),
    )
    .unwrap();
    assert_eq!(unwrapped.as_ref(), material);

    let rewrapped = match run(
        &mut provider,
        5,
        CryptoOperation::RewrapKey(RewrapKey {
            from: key_a.clone(),
            from_context: from_ctx.clone(),
            to: key_b.clone(),
            to_context: to_ctx.clone(),
            wrapped: wrapped_a,
        }),
    )
    .unwrap()
    {
        CryptoResponse::Ciphertext(blob) => blob,
        other => panic!("unexpected response: {other:?}"),
    };

    let unwrapped_b = unwrap(&mut provider, 6, &key_b, rewrapped.clone(), to_ctx.clone()).unwrap();
    assert_eq!(unwrapped_b.as_ref(), material);

    // The rewrapped blob is bound to key B; key A can no longer open it.
    let err = unwrap(&mut provider, 7, &key_a, rewrapped, from_ctx).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);
}

// ---------------------------------------------------------------------------
// 6. Key lifecycle
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_rotate_disable_enable_destroy() {
    let mut provider = InMemoryProvider::new();
    let (key_v1, _) = generate_hpke(&mut provider, 1, "app", "life");
    let latest = KeyRef::latest(ns("app"), kid("life"));
    let context = ctx(b"info", b"aad");

    let ciphertext_v1 = encrypt(&mut provider, 2, &key_v1, b"v1 secret", context.clone());

    // Rotate -> version 2 becomes primary.
    let key_v2 = match run(
        &mut provider,
        3,
        CryptoOperation::Rotate(RotateKey {
            key: latest.clone(),
        }),
    )
    .unwrap()
    {
        CryptoResponse::KeyCreated { key, public } => {
            assert!(public.is_some());
            key
        }
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(key_v2.version, Some(KeyVersion::new(2).unwrap()));

    // The old (v1) ciphertext still decrypts through the unversioned ref.
    let recovered = decrypt(
        &mut provider,
        4,
        &latest,
        ciphertext_v1.clone(),
        context.clone(),
    )
    .unwrap();
    assert_eq!(recovered.as_ref(), b"v1 secret");

    // A fresh encrypt now uses v2: it cannot be opened by pinning v1.
    let ciphertext_v2 = encrypt(&mut provider, 5, &latest, b"v2 secret", context.clone());
    let err = decrypt(&mut provider, 6, &key_v1, ciphertext_v2, context.clone()).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);

    // Disable v1 -> decrypting the v1 ciphertext is now a lifecycle Conflict.
    let disabled = match run(
        &mut provider,
        7,
        CryptoOperation::Disable(DisableKey {
            key: key_v1.clone(),
        }),
    )
    .unwrap()
    {
        CryptoResponse::Metadata(meta) => meta,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(disabled.state, KeyState::Disabled);

    let err = decrypt(
        &mut provider,
        8,
        &key_v1,
        ciphertext_v1.clone(),
        context.clone(),
    )
    .unwrap_err();
    assert_eq!(err, CryptoServiceError::Conflict);

    // Enable v1 again -> it works again.
    let enabled = match run(
        &mut provider,
        9,
        CryptoOperation::Enable(EnableKey {
            key: key_v1.clone(),
        }),
    )
    .unwrap()
    {
        CryptoResponse::Metadata(meta) => meta,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(enabled.state, KeyState::Enabled);

    let recovered_again = decrypt(
        &mut provider,
        10,
        &key_v1,
        ciphertext_v1.clone(),
        context.clone(),
    )
    .unwrap();
    assert_eq!(recovered_again.as_ref(), b"v1 secret");

    // Destroy without a version is Malformed (destruction must name one).
    let err = run(
        &mut provider,
        11,
        CryptoOperation::Destroy(DestroyKey {
            key: latest.clone(),
        }),
    )
    .unwrap_err();
    assert_eq!(err, CryptoServiceError::Malformed);

    // Destroy v1 -> Metadata Destroyed.
    let destroyed = match run(
        &mut provider,
        12,
        CryptoOperation::Destroy(DestroyKey {
            key: key_v1.clone(),
        }),
    )
    .unwrap()
    {
        CryptoResponse::Metadata(meta) => meta,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(destroyed.state, KeyState::Destroyed);

    // Decrypting the v1 ciphertext afterwards is an opaque auth failure, not
    // a "key destroyed" oracle.
    let err = decrypt(&mut provider, 13, &key_v1, ciphertext_v1, context).unwrap_err();
    assert_eq!(err, CryptoServiceError::AuthenticationFailed);

    // Destroying v1 again is a Conflict (terminal state).
    let err = run(
        &mut provider,
        14,
        CryptoOperation::Destroy(DestroyKey {
            key: key_v1.clone(),
        }),
    )
    .unwrap_err();
    assert_eq!(err, CryptoServiceError::Conflict);

    // Generating over the same id again is a Conflict.
    let err = run(
        &mut provider,
        15,
        CryptoOperation::Generate(GenerateKey {
            namespace: ns("app"),
            id: kid("life"),
            algorithm: hpke_algorithm(),
        }),
    )
    .unwrap_err();
    assert_eq!(err, CryptoServiceError::Conflict);
}

// ---------------------------------------------------------------------------
// 7 / 8. ML-DSA signing (feature-gated both ways)
// ---------------------------------------------------------------------------

#[cfg(feature = "ml-dsa")]
mod ml_dsa_enabled {
    use super::*;
    use crypt_guard_service::{MessageBlob, Sign, SignatureBlob, VerificationResult, Verify};

    fn generate_signing_key(
        provider: &mut InMemoryProvider,
        id: u128,
        namespace: &str,
        key_id: &str,
    ) -> KeyRef {
        let op = CryptoOperation::Generate(GenerateKey {
            namespace: ns(namespace),
            id: kid(key_id),
            algorithm: KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
        });
        match run(provider, id, op).unwrap() {
            CryptoResponse::KeyCreated { key, public } => {
                assert!(public.is_some());
                key
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn sign(
        provider: &mut InMemoryProvider,
        id: u128,
        key: &KeyRef,
        message: &[u8],
    ) -> Result<SignatureBlob, CryptoServiceError> {
        let op = CryptoOperation::Sign(Sign {
            key: key.clone(),
            message: SecretBytes::copy_from_slice(message),
        });
        run(provider, id, op).map(|resp| match resp {
            CryptoResponse::Signature(sig) => sig,
            other => panic!("unexpected response: {other:?}"),
        })
    }

    fn verify(
        provider: &mut InMemoryProvider,
        id: u128,
        key: &KeyRef,
        message: &[u8],
        signature: SignatureBlob,
    ) -> VerificationResult {
        let op = CryptoOperation::Verify(Verify {
            key: key.clone(),
            message: MessageBlob::new(message.to_vec()),
            signature,
        });
        match run(provider, id, op).unwrap() {
            CryptoResponse::Verification(result) => result,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn sign_verify_and_unsupported_combinations() {
        let mut provider = InMemoryProvider::new();
        let sign_key = generate_signing_key(&mut provider, 1, "app", "signer");
        let message = b"message to be signed".to_vec();

        let signature = sign(&mut provider, 2, &sign_key, &message).unwrap();

        let result = verify(&mut provider, 3, &sign_key, &message, signature.clone());
        assert_eq!(result, VerificationResult::Valid);

        let mut modified = message.clone();
        modified[0] ^= 0xFF;
        let result = verify(&mut provider, 4, &sign_key, &modified, signature);
        assert_eq!(result, VerificationResult::Invalid);

        // Signing with an HPKE key is Unsupported: it is not a signing key.
        let (hpke_key, _) = generate_hpke(&mut provider, 5, "app", "hpke-for-sign");
        let err = sign(&mut provider, 6, &hpke_key, b"anything").unwrap_err();
        assert_eq!(err, CryptoServiceError::Unsupported);

        // Encrypting with a signing key is Unsupported: it is not an HPKE key.
        let err = run(
            &mut provider,
            7,
            CryptoOperation::Encrypt(Encrypt {
                key: sign_key,
                plaintext: SecretBytes::copy_from_slice(b"anything"),
                context: CryptoContext::default(),
            }),
        )
        .unwrap_err();
        assert_eq!(err, CryptoServiceError::Unsupported);
    }
}

#[cfg(not(feature = "ml-dsa"))]
#[test]
fn generate_signature_key_without_ml_dsa_feature_is_unsupported() {
    let mut provider = InMemoryProvider::new();
    let err = run(
        &mut provider,
        1,
        CryptoOperation::Generate(GenerateKey {
            namespace: ns("app"),
            id: kid("signer"),
            algorithm: KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
        }),
    )
    .unwrap_err();
    assert_eq!(err, CryptoServiceError::Unsupported);
}
