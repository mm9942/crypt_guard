//! Integration tests for the policy layer end to end: a real
//! `InMemoryProvider` guarded by `PolicyProvider<InMemoryProvider,
//! NamespacePolicy>`, driven only through `CryptoProvider::execute`.

use crypt_guard_service::{
    pq_hpke::DEFAULT_SUITE, CiphertextBlob, CryptoContext, CryptoOperation, CryptoProvider,
    CryptoRequest, CryptoResponse, CryptoServiceError, Decrypt, Encrypt, GenerateKey,
    InMemoryProvider, KeyAlgorithm, KeyId, KeyNamespace, KeyRef, NamespacePolicy, OpKind, OpSet,
    PolicyProvider, Principal, RequestContext, RequestId, RewrapKey, SecretBytes, UnwrapKey,
    WrapKey,
};

fn ns(name: &str) -> KeyNamespace {
    KeyNamespace::new(name).unwrap()
}

fn key(namespace: &str, id: &str) -> KeyRef {
    KeyRef::latest(ns(namespace), KeyId::new(id).unwrap())
}

fn ctx(principal: &str, request_id: u128) -> RequestContext {
    RequestContext {
        request_id: RequestId(request_id),
        principal: Some(Principal::new(principal)),
    }
}

fn generate_op(namespace: &str, id: &str) -> CryptoOperation {
    CryptoOperation::Generate(GenerateKey {
        namespace: ns(namespace),
        id: KeyId::new(id).unwrap(),
        algorithm: KeyAlgorithm::Hpke {
            suite: DEFAULT_SUITE,
        },
    })
}

fn encrypt_op(namespace: &str, id: &str, plaintext: &[u8]) -> CryptoOperation {
    CryptoOperation::Encrypt(Encrypt {
        key: key(namespace, id),
        plaintext: SecretBytes::copy_from_slice(plaintext),
        context: CryptoContext::default(),
    })
}

fn decrypt_op(namespace: &str, id: &str, ciphertext: CiphertextBlob) -> CryptoOperation {
    CryptoOperation::Decrypt(Decrypt {
        key: key(namespace, id),
        ciphertext,
        context: CryptoContext::default(),
    })
}

fn as_ciphertext(resp: CryptoResponse) -> CiphertextBlob {
    match resp {
        CryptoResponse::Ciphertext(blob) => blob,
        other => panic!("expected Ciphertext, got {other:?}"),
    }
}

#[test]
fn admin_can_generate_key_with_admin_grant() {
    let mut policy = NamespacePolicy::new();
    policy.grant(Principal::new("admin"), ns("app"), OpSet::ADMIN);
    let mut provider = PolicyProvider::new(InMemoryProvider::new(), policy);

    let resp = provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 1),
            generate_op("app", "k1"),
        ))
        .unwrap();
    assert!(matches!(resp, CryptoResponse::KeyCreated { .. }));
}

#[test]
fn encrypt_only_grant_allows_encrypt_but_forbids_decrypt() {
    let mut policy = NamespacePolicy::new();
    policy.grant(Principal::new("admin"), ns("app"), OpSet::ADMIN);
    policy.grant(Principal::new("app"), ns("app"), OpSet::ENCRYPT);
    let mut provider = PolicyProvider::new(InMemoryProvider::new(), policy);

    provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 1),
            generate_op("app", "k1"),
        ))
        .unwrap();

    let resp = provider
        .execute(CryptoRequest::with_context(
            ctx("app", 2),
            encrypt_op("app", "k1", b"secret data"),
        ))
        .unwrap();
    let ciphertext = as_ciphertext(resp);

    // Encrypt-only grant does not cover secret egress: decrypt is forbidden.
    let err = provider
        .execute(CryptoRequest::with_context(
            ctx("app", 3),
            decrypt_op("app", "k1", ciphertext),
        ))
        .unwrap_err();
    assert_eq!(err, CryptoServiceError::Forbidden);
}

#[test]
fn secret_egress_grant_allows_decrypt() {
    let mut policy = NamespacePolicy::new();
    policy.grant(Principal::new("admin"), ns("app"), OpSet::ADMIN);
    policy.grant(
        Principal::new("app"),
        ns("app"),
        OpSet::ENCRYPT.union(OpSet::SECRET_EGRESS),
    );
    let mut provider = PolicyProvider::new(InMemoryProvider::new(), policy);

    provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 1),
            generate_op("app", "k1"),
        ))
        .unwrap();

    let resp = provider
        .execute(CryptoRequest::with_context(
            ctx("app", 2),
            encrypt_op("app", "k1", b"secret data"),
        ))
        .unwrap();
    let ciphertext = as_ciphertext(resp);

    let resp = provider
        .execute(CryptoRequest::with_context(
            ctx("app", 3),
            decrypt_op("app", "k1", ciphertext),
        ))
        .unwrap();
    match resp {
        CryptoResponse::Plaintext(secret) => assert_eq!(secret.as_ref(), b"secret data"),
        other => panic!("expected Plaintext, got {other:?}"),
    }
}

#[test]
fn anonymous_is_unauthenticated_for_every_operation() {
    let mut policy = NamespacePolicy::new();
    policy.grant(Principal::new("admin"), ns("app"), OpSet::ALL);
    let mut provider = PolicyProvider::new(InMemoryProvider::new(), policy);

    let err = provider
        .execute(CryptoRequest::new(RequestId(1), generate_op("app", "k1")))
        .unwrap_err();
    assert_eq!(err, CryptoServiceError::Unauthenticated);
}

#[test]
fn grant_in_one_namespace_does_not_authorize_another() {
    let mut policy = NamespacePolicy::new();
    policy.grant(Principal::new("app"), ns("app"), OpSet::ADMIN);
    let mut provider = PolicyProvider::new(InMemoryProvider::new(), policy);

    let err = provider
        .execute(CryptoRequest::with_context(
            ctx("app", 1),
            generate_op("other", "k1"),
        ))
        .unwrap_err();
    assert_eq!(err, CryptoServiceError::Forbidden);
}

#[test]
fn rewrap_forbidden_without_grant_in_target_namespace() {
    let mut policy = NamespacePolicy::new();
    policy.grant(
        Principal::new("admin"),
        ns("ns1"),
        OpSet::ADMIN.union(OpSet::ENCRYPT),
    );
    policy.grant(Principal::new("admin"), ns("ns2"), OpSet::ADMIN);
    policy.grant(Principal::new("rewrapper"), ns("ns1"), OpSet::REWRAP);
    // Deliberately no REWRAP grant for "rewrapper" in ns2.
    let mut provider = PolicyProvider::new(InMemoryProvider::new(), policy);

    provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 1),
            generate_op("ns1", "k1"),
        ))
        .unwrap();
    provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 2),
            generate_op("ns2", "k2"),
        ))
        .unwrap();

    let wrap_resp = provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 3),
            CryptoOperation::WrapKey(WrapKey {
                key: key("ns1", "k1"),
                material: SecretBytes::copy_from_slice(b"key material"),
                context: CryptoContext::default(),
            }),
        ))
        .unwrap();
    let wrapped = as_ciphertext(wrap_resp);

    let rewrap_op = CryptoOperation::RewrapKey(RewrapKey {
        from: key("ns1", "k1"),
        from_context: CryptoContext::default(),
        to: key("ns2", "k2"),
        to_context: CryptoContext::default(),
        wrapped,
    });
    let err = provider
        .execute(CryptoRequest::with_context(ctx("rewrapper", 4), rewrap_op))
        .unwrap_err();
    assert_eq!(err, CryptoServiceError::Forbidden);
}

#[test]
fn rewrap_succeeds_with_grant_in_both_namespaces() {
    let mut policy = NamespacePolicy::new();
    policy.grant(
        Principal::new("admin"),
        ns("ns1"),
        OpSet::ADMIN.union(OpSet::ENCRYPT),
    );
    policy.grant(
        Principal::new("admin"),
        ns("ns2"),
        OpSet::ADMIN.union(OpSet::SECRET_EGRESS),
    );
    policy.grant(Principal::new("rewrapper"), ns("ns1"), OpSet::REWRAP);
    policy.grant(Principal::new("rewrapper"), ns("ns2"), OpSet::REWRAP);
    let mut provider = PolicyProvider::new(InMemoryProvider::new(), policy);

    provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 1),
            generate_op("ns1", "k1"),
        ))
        .unwrap();
    provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 2),
            generate_op("ns2", "k2"),
        ))
        .unwrap();

    let wrap_resp = provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 3),
            CryptoOperation::WrapKey(WrapKey {
                key: key("ns1", "k1"),
                material: SecretBytes::copy_from_slice(b"key material"),
                context: CryptoContext::default(),
            }),
        ))
        .unwrap();
    let wrapped = as_ciphertext(wrap_resp);

    let rewrap_op = CryptoOperation::RewrapKey(RewrapKey {
        from: key("ns1", "k1"),
        from_context: CryptoContext::default(),
        to: key("ns2", "k2"),
        to_context: CryptoContext::default(),
        wrapped,
    });
    let resp = provider
        .execute(CryptoRequest::with_context(ctx("rewrapper", 4), rewrap_op))
        .unwrap();
    let rewrapped = as_ciphertext(resp);

    // Round-trip: unwrapping the rewrapped material under the target key
    // recovers the original bytes.
    let unwrap_resp = provider
        .execute(CryptoRequest::with_context(
            ctx("admin", 5),
            CryptoOperation::UnwrapKey(UnwrapKey {
                key: key("ns2", "k2"),
                wrapped: rewrapped,
                context: CryptoContext::default(),
            }),
        ))
        .unwrap();
    match unwrap_resp {
        CryptoResponse::Plaintext(secret) => assert_eq!(secret.as_ref(), b"key material"),
        other => panic!("expected Plaintext, got {other:?}"),
    }
}

#[test]
fn op_kind_is_secret_egress_exactly_for_decrypt_and_unwrap() {
    for kind in [
        OpKind::Generate,
        OpKind::Rotate,
        OpKind::Disable,
        OpKind::Enable,
        OpKind::Destroy,
        OpKind::Describe,
        OpKind::PublicKey,
        OpKind::Encrypt,
        OpKind::Sign,
        OpKind::Verify,
        OpKind::WrapKey,
        OpKind::RewrapKey,
    ] {
        assert!(
            !kind.is_secret_egress(),
            "{kind:?} should not be secret egress"
        );
    }
    assert!(OpKind::Decrypt.is_secret_egress());
    assert!(OpKind::UnwrapKey.is_secret_egress());
}

#[test]
fn op_kind_is_mutation_exactly_for_lifecycle_ops() {
    for kind in [
        OpKind::Generate,
        OpKind::Rotate,
        OpKind::Disable,
        OpKind::Enable,
        OpKind::Destroy,
    ] {
        assert!(kind.is_mutation(), "{kind:?} should be a mutation");
    }
    for kind in [
        OpKind::Describe,
        OpKind::PublicKey,
        OpKind::Encrypt,
        OpKind::Decrypt,
        OpKind::Sign,
        OpKind::Verify,
        OpKind::WrapKey,
        OpKind::UnwrapKey,
        OpKind::RewrapKey,
    ] {
        assert!(!kind.is_mutation(), "{kind:?} should not be a mutation");
    }
}

#[test]
fn rewrap_operation_reports_both_namespaces() {
    let op = CryptoOperation::RewrapKey(RewrapKey {
        from: key("ns1", "k1"),
        from_context: CryptoContext::default(),
        to: key("ns2", "k2"),
        to_context: CryptoContext::default(),
        wrapped: CiphertextBlob::new(Vec::new()),
    });
    let namespaces = op.namespaces();
    assert_eq!(namespaces[0].map(KeyNamespace::as_str), Some("ns1"));
    assert_eq!(namespaces[1].map(KeyNamespace::as_str), Some("ns2"));
}
