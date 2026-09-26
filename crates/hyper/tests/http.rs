//! End-to-end: Hyper server over an in-memory duplex connection, backed by the
//! buffered crypto service.

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use static_assertions::assert_impl_all;

use crypt_guard_hyper::{into_hyper, BodyLimits, CryptoHttpService, HttpConfig};
use crypt_guard_service::{
    network_handle, CryptoProvider, CryptoRequest, CryptoResponse, CryptoService,
    CryptoServiceError, NetworkHandle, NullProvider, PublicBlob, SecretBytes, StackConfig,
};

// The HTTP adapter is the cloneable network element.
assert_impl_all!(CryptoHttpService<NetworkHandle>: Clone, Send, Sync);

/// Returns a fixed public key for every request.
struct FixedKeyProvider;

impl CryptoProvider for FixedKeyProvider {
    fn execute(&mut self, _request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        Ok(CryptoResponse::PublicKey(PublicBlob::new(vec![0xAB; 4])))
    }
}

/// Returns secret output for every request.
struct PlaintextProvider;

impl CryptoProvider for PlaintextProvider {
    fn execute(&mut self, _request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        Ok(CryptoResponse::Plaintext(SecretBytes::copy_from_slice(
            b"secret",
        )))
    }
}

/// Always answers with a fixed error.
struct FailingProvider(CryptoServiceError);

impl CryptoProvider for FailingProvider {
    fn execute(&mut self, _request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        Err(self.0)
    }
}

fn config() -> HttpConfig {
    HttpConfig {
        max_body: BodyLimits {
            metadata: 8,
            sign: 8,
            crypt: 16,
            import: 8,
        },
        ..HttpConfig::default()
    }
}

/// Serve one HTTP/1 connection over a duplex pipe and send `requests` on it.
async fn roundtrip<P: CryptoProvider>(
    provider: P,
    requests: Vec<Request<Full<Bytes>>>,
) -> Vec<(StatusCode, Bytes)> {
    let handle = network_handle(CryptoService::new(provider), StackConfig::default());
    let service = into_hyper(CryptoHttpService::new(handle, config()));

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server_io), service)
            .await
    });

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .unwrap();
    tokio::spawn(connection);

    let mut results = Vec::new();
    for request in requests {
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        results.push((status, body));
    }
    drop(sender);
    server.await.unwrap().unwrap();
    results
}

fn req(method: Method, path: &str, body: &'static [u8]) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "kms.test")
        .body(Full::new(Bytes::from_static(body)))
        .unwrap()
}

#[tokio::test]
async fn routing_limits_and_error_mapping() {
    let results = roundtrip(
        NullProvider,
        vec![
            // Forwarded to the service; NullProvider -> Unsupported -> 501.
            req(Method::GET, "/v1/keys/app/k1", b""),
            req(Method::GET, "/nope", b""),
            req(Method::DELETE, "/v1/keys/app/k1", b""),
            req(Method::GET, "/v1/keys/app/bad%24name", b""),
            // Over the 16-byte crypt limit.
            req(
                Method::POST,
                "/v1/keys/app/k1:encrypt",
                b"0123456789abcdefXX",
            ),
            // Within the limit but not a CGK1 frame.
            req(Method::POST, "/v1/keys/app/k1:encrypt", b"small"),
        ],
    )
    .await;
    let statuses: Vec<_> = results.iter().map(|(s, _)| *s).collect();
    assert_eq!(
        statuses,
        [
            StatusCode::NOT_IMPLEMENTED,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::BAD_REQUEST,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::BAD_REQUEST,
        ]
    );
}

#[tokio::test]
async fn public_key_is_served_as_octets() {
    let results = roundtrip(
        FixedKeyProvider,
        vec![req(Method::GET, "/v1/keys/app/k1@2/public", b"")],
    )
    .await;
    assert_eq!(results[0], (StatusCode::OK, Bytes::from_static(&[0xAB; 4])));
}

#[tokio::test]
async fn secret_output_is_egressed() {
    let results = roundtrip(
        PlaintextProvider,
        vec![req(Method::GET, "/v1/keys/app/k1", b"")],
    )
    .await;
    assert_eq!(results[0], (StatusCode::OK, Bytes::from_static(b"secret")));
}

#[tokio::test]
async fn errors_are_opaque() {
    for (err, status) in [
        (
            CryptoServiceError::AuthenticationFailed,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (CryptoServiceError::Forbidden, StatusCode::NOT_FOUND),
        (CryptoServiceError::NotFound, StatusCode::NOT_FOUND),
        (
            CryptoServiceError::Overloaded,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let results = roundtrip(
            FailingProvider(err),
            vec![req(Method::GET, "/v1/keys/app/k1", b"")],
        )
        .await;
        assert_eq!(results[0].0, status, "{err:?}");
        assert_eq!(
            results[0].1,
            Bytes::from_static(status.canonical_reason().unwrap().as_bytes())
        );
    }
}
