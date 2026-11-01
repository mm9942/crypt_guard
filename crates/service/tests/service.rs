//! Behaviour of `CryptoService` and the buffered network handle.

use core::task::{Context, Poll};

use tower::ServiceExt;

use crypt_guard_core::error::CryptError;
use crypt_guard_core::pq_hpke::{EnvelopeError, Error as HpkeError};
use crypt_guard_service::{
    CryptoContext, CryptoOperation, CryptoProvider, CryptoRequest, CryptoResponse, CryptoService,
    CryptoServiceError, DescribeKey, DescribeLifecycle, Encrypt, ErrorKind, KeyId, KeyNamespace,
    KeyRef, NullProvider, PublicBlob, RequestId, SecretBytes,
};

fn key() -> KeyRef {
    KeyRef::latest(KeyNamespace::new("app").unwrap(), KeyId::new("k1").unwrap())
}

fn describe() -> CryptoRequest {
    CryptoRequest::new(
        RequestId(1),
        CryptoOperation::Describe(DescribeKey { key: key() }),
    )
}

/// Answers every request with a fixed public key and records request ids.
struct EchoProvider {
    seen: Vec<RequestId>,
}

impl CryptoProvider for EchoProvider {
    fn execute(&mut self, request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        self.seen.push(request.context.request_id);
        Ok(CryptoResponse::PublicKey(PublicBlob::new(vec![1, 2, 3])))
    }
}

/// Never ready.
struct UnavailableProvider;

impl CryptoProvider for UnavailableProvider {
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), CryptoServiceError>> {
        Poll::Ready(Err(CryptoServiceError::Unavailable))
    }

    fn execute(&mut self, _request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        unreachable!("never ready")
    }
}

#[tokio::test]
async fn service_moves_requests_to_the_provider() {
    let mut service = CryptoService::new(EchoProvider { seen: Vec::new() });
    let response = (&mut service).oneshot(describe()).await.unwrap();
    assert!(
        matches!(response, CryptoResponse::PublicKey(ref blob) if blob.as_bytes() == [1, 2, 3])
    );
    assert_eq!(service.provider().seen, vec![RequestId(1)]);
}

#[tokio::test]
async fn provider_readiness_is_propagated() {
    let service = CryptoService::new(UnavailableProvider);
    let err = service.oneshot(describe()).await.unwrap_err();
    assert_eq!(err, CryptoServiceError::Unavailable);
}

#[tokio::test]
async fn null_provider_is_unsupported() {
    let request = CryptoRequest::new(
        RequestId(2),
        CryptoOperation::Encrypt(Encrypt {
            key: key(),
            plaintext: SecretBytes::copy_from_slice(b"pt"),
            context: CryptoContext::default(),
        }),
    );
    let err = CryptoService::new(NullProvider)
        .oneshot(request)
        .await
        .unwrap_err();
    assert_eq!(err, CryptoServiceError::Unsupported);
}

#[tokio::test]
async fn null_provider_does_not_describe_lifecycles() {
    let request = CryptoRequest::new(
        RequestId(3),
        CryptoOperation::DescribeLifecycle(DescribeLifecycle { key: key() }),
    );
    let err = CryptoService::new(NullProvider)
        .oneshot(request)
        .await
        .unwrap_err();
    assert_eq!(err, CryptoServiceError::Unsupported);
}

#[cfg(feature = "buffer")]
#[tokio::test]
async fn network_handle_clones_share_one_service() {
    use crypt_guard_service::{network_handle, service_error, StackConfig};

    let handle = network_handle(
        CryptoService::new(NullProvider),
        StackConfig {
            queue_bound: 4,
            max_in_flight: 2,
        },
    );
    let clone = handle.clone();
    for h in [handle, clone] {
        let err = h.oneshot(describe()).await.unwrap_err();
        assert_eq!(service_error(err), CryptoServiceError::Unsupported);
    }
}

#[cfg(feature = "buffer")]
mod fallible_stack {
    //! `try_network_handle`: typed errors instead of the panics of
    //! `network_handle`.

    use super::*;
    use crypt_guard_service::{service_error, try_network_handle, StackConfig};

    /// `tokio::sync::Semaphore::MAX_PERMITS`.
    const MAX_CAPACITY: usize = usize::MAX >> 3;

    fn stack_config(queue_bound: usize, max_in_flight: usize) -> StackConfig {
        StackConfig {
            queue_bound,
            max_in_flight,
        }
    }

    fn unusable_configs() -> [StackConfig; 6] {
        [
            stack_config(0, 2),
            stack_config(4, 0),
            stack_config(0, 0),
            stack_config(MAX_CAPACITY + 1, 2),
            stack_config(4, MAX_CAPACITY + 1),
            stack_config(usize::MAX, usize::MAX),
        ]
    }

    /// Plain `#[test]`: no Tokio runtime in this context.
    #[test]
    fn without_a_runtime_is_unavailable() {
        let result = try_network_handle(CryptoService::new(NullProvider), StackConfig::default());
        assert_eq!(result.err(), Some(CryptoServiceError::Unavailable));
    }

    /// Plain `#[test]`: the configuration is checked before the runtime.
    #[test]
    fn unusable_config_is_malformed_even_without_a_runtime() {
        for config in unusable_configs() {
            let result = try_network_handle(CryptoService::new(NullProvider), config);
            assert_eq!(
                result.err(),
                Some(CryptoServiceError::Malformed),
                "{config:?}"
            );
        }
    }

    #[tokio::test]
    async fn unusable_config_is_malformed_inside_a_runtime() {
        for config in unusable_configs() {
            let result = try_network_handle(CryptoService::new(NullProvider), config);
            assert_eq!(
                result.err(),
                Some(CryptoServiceError::Malformed),
                "{config:?}"
            );
        }
    }

    #[tokio::test]
    async fn inside_a_runtime_clones_share_one_service() {
        let Ok(handle) = try_network_handle(CryptoService::new(NullProvider), stack_config(4, 2))
        else {
            panic!("a runtime is present and the config is valid");
        };
        let clone = handle.clone();
        for h in [handle, clone] {
            let err = h.oneshot(describe()).await.unwrap_err();
            assert_eq!(service_error(err), CryptoServiceError::Unsupported);
        }
    }

    #[tokio::test]
    async fn smallest_valid_config_serves_sequential_requests() {
        let Ok(mut handle) = try_network_handle(
            CryptoService::new(EchoProvider { seen: Vec::new() }),
            stack_config(1, 1),
        ) else {
            panic!("a runtime is present and the config is valid");
        };
        for _ in 0..3 {
            let response = (&mut handle).oneshot(describe()).await.unwrap();
            assert!(matches!(response, CryptoResponse::PublicKey(_)));
        }
    }
}

#[test]
fn hpke_errors_map_opaquely() {
    assert_eq!(
        CryptoServiceError::from(HpkeError::AuthenticationFailed),
        CryptoServiceError::AuthenticationFailed
    );
    assert_eq!(
        CryptoServiceError::from(HpkeError::InvalidEncapsulation),
        CryptoServiceError::Malformed
    );
    assert_eq!(
        CryptoServiceError::from(HpkeError::InternalInvariant),
        CryptoServiceError::Internal
    );
    assert_eq!(
        CryptoServiceError::from(EnvelopeError::InvalidMagic),
        CryptoServiceError::Malformed
    );
}

#[test]
fn key_names_are_validated() {
    assert!(KeyId::new("tenant-1.key_A").is_ok());
    for bad in [
        "",
        ".hidden",
        "a/b",
        "a@1",
        "a:b",
        "sp ace",
        &"x".repeat(129),
    ] {
        assert_eq!(
            KeyId::new(bad),
            Err(CryptoServiceError::Malformed),
            "{bad:?}"
        );
    }
    assert_eq!(key().to_string(), "app/k1");
}

#[test]
fn error_kind_maps_onto_service_error_classes() {
    assert_eq!(
        CryptoServiceError::from(ErrorKind::Authentication),
        CryptoServiceError::AuthenticationFailed
    );
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::InvalidKey,
        ErrorKind::Encoding,
    ] {
        assert_eq!(
            CryptoServiceError::from(kind),
            CryptoServiceError::Malformed,
            "{kind:?}"
        );
    }
    assert_eq!(
        CryptoServiceError::from(ErrorKind::Unsupported),
        CryptoServiceError::Unsupported
    );
    for kind in [ErrorKind::Io, ErrorKind::Randomness] {
        assert_eq!(
            CryptoServiceError::from(kind),
            CryptoServiceError::Unavailable,
            "{kind:?}"
        );
    }
    for kind in [ErrorKind::Limit, ErrorKind::Internal] {
        assert_eq!(
            CryptoServiceError::from(kind),
            CryptoServiceError::Internal,
            "{kind:?}"
        );
    }
}

#[test]
fn crypt_error_maps_via_its_kind() {
    // Authentication-class core error -> opaque AuthenticationFailed.
    assert_eq!(
        CryptoServiceError::from(CryptError::AuthenticationFailed),
        CryptoServiceError::AuthenticationFailed
    );
    // I/O-class core error -> Unavailable (transient, not the caller's fault).
    assert_eq!(
        CryptoServiceError::from(CryptError::FileNotFound),
        CryptoServiceError::Unavailable
    );
    // Malformed-input-class core error -> Malformed.
    assert_eq!(
        CryptoServiceError::from(CryptError::InvalidKemPublicKey),
        CryptoServiceError::Malformed
    );
    // Unsupported-class core error -> Unsupported.
    assert_eq!(
        CryptoServiceError::from(CryptError::UnsupportedAlgorithm),
        CryptoServiceError::Unsupported
    );
}

#[test]
fn is_retryable_is_true_only_for_transient_conditions() {
    assert!(CryptoServiceError::Unavailable.is_retryable());
    assert!(CryptoServiceError::Overloaded.is_retryable());
    for err in [
        CryptoServiceError::Unsupported,
        CryptoServiceError::Unauthenticated,
        CryptoServiceError::NotFound,
        CryptoServiceError::Forbidden,
        CryptoServiceError::Conflict,
        CryptoServiceError::Malformed,
        CryptoServiceError::AuthenticationFailed,
        CryptoServiceError::Internal,
    ] {
        assert!(!err.is_retryable(), "{err:?} must not be retryable");
    }
}

#[test]
fn crypto_kind_is_some_only_for_crypto_derived_classes() {
    assert_eq!(
        CryptoServiceError::AuthenticationFailed.crypto_kind(),
        Some(ErrorKind::Authentication)
    );
    assert_eq!(
        CryptoServiceError::Malformed.crypto_kind(),
        Some(ErrorKind::InvalidInput)
    );
    assert_eq!(
        CryptoServiceError::Unsupported.crypto_kind(),
        Some(ErrorKind::Unsupported)
    );
    assert_eq!(
        CryptoServiceError::Internal.crypto_kind(),
        Some(ErrorKind::Internal)
    );
    // Authorization/lifecycle/transport classes are not crypto failures.
    for err in [
        CryptoServiceError::Unauthenticated,
        CryptoServiceError::NotFound,
        CryptoServiceError::Forbidden,
        CryptoServiceError::Conflict,
        CryptoServiceError::Unavailable,
        CryptoServiceError::Overloaded,
    ] {
        assert_eq!(err.crypto_kind(), None, "{err:?}");
    }
}
