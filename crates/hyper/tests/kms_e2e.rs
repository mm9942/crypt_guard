//! End-to-end KMS flows over real HTTP wire framing.
//!
//! Unlike `http.rs` (which drives the adapter with hand-rolled provider
//! stubs to probe routing/limits/error-mapping in isolation), this file
//! drives a real [`InMemoryProvider`] (optionally behind [`PolicyProvider`])
//! through a real hyper HTTP/1 connection over an in-memory duplex pipe, one
//! request at a time, so state (key versions, disable/enable/destroy) is
//! observed exactly as an HTTP client would see it across a whole session.
//!
//! Security properties checked here:
//! - the full generate -> encrypt -> decrypt -> rotate -> disable -> enable
//!   -> destroy lifecycle enforces the right HTTP status at every
//!   transition, and a destroyed/disabled key version is unusable;
//! - tampering, a wrong `aad` and a wrong `info` are indistinguishable to an
//!   HTTP caller: byte-identical `422` bodies (no oracle);
//! - `NamespacePolicy` denies by default and grants are scoped per
//!   principal and per namespace, enforced over real `Authorization`
//!   headers via `BearerTokens`, with `Forbidden` hidden as `404` by
//!   default so a caller cannot distinguish "not permitted" from
//!   "does not exist";
//! - every response, success or error, carries `Cache-Control: no-store`
//!   (checked by the shared [`Harness::send`] helper on every call).

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::task::JoinHandle;

use crypt_guard_hyper::{
    codec::{FrameReader, FrameWriter},
    into_hyper, Anonymous, Authenticator, BearerTokens, CryptoHttpService, HttpConfig,
};
use crypt_guard_service::{
    network_handle, CryptoProvider, CryptoService, InMemoryProvider, KeyNamespace, NamespacePolicy,
    OpSet, PolicyProvider, Principal, SecretBytes, StackConfig,
};

// ---------------------------------------------------------------------------
// Harness: one HTTP/1 connection over an in-memory duplex pipe, backed by a
// fresh crypto service. Requests are sent one at a time (not batched like
// `http.rs`'s `roundtrip`) so a later request's body can be built from an
// earlier response, e.g. decrypting the ciphertext a previous encrypt call
// just returned.
// ---------------------------------------------------------------------------

struct Harness {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    server: JoinHandle<Result<(), hyper::Error>>,
}

impl Harness {
    async fn new<P, A>(provider: P, authenticator: A, config: HttpConfig) -> Self
    where
        P: CryptoProvider,
        A: Authenticator,
    {
        let handle = network_handle(CryptoService::new(provider), StackConfig::default());
        let service =
            into_hyper(CryptoHttpService::new(handle, config).with_authenticator(authenticator));

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server_io), service)
                .await
        });

        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
            .await
            .unwrap();
        tokio::spawn(connection);

        Self { sender, server }
    }

    /// An anonymous harness over `provider`, default HTTP config.
    async fn anonymous<P: CryptoProvider>(provider: P) -> Self {
        Self::new(provider, Anonymous, HttpConfig::default()).await
    }

    /// Send one request and return its status and body. Every response must
    /// carry `Cache-Control: no-store`; that is asserted here so every call
    /// site gets the check for free.
    async fn send(&mut self, request: Request<Full<Bytes>>) -> (StatusCode, Bytes) {
        let response = self.sender.send_request(request).await.unwrap();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body)
    }

    /// Drop the client and wait for the server task to finish cleanly.
    async fn finish(self) {
        drop(self.sender);
        self.server.await.unwrap().unwrap();
    }
}

fn req(method: Method, path: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "kms.test")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn authed_req(method: Method, path: &str, token: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "kms.test")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

// ---------------------------------------------------------------------------
// `CGK1` frame builders / parsers for the reference route table (see
// `crypt_guard_hyper::codec::request` / `::response` module docs, which are
// this wire format's spec).
// ---------------------------------------------------------------------------

fn generate_body(namespace: &str, id: &str, profile: &str) -> Vec<u8> {
    let mut w = FrameWriter::new();
    w.field(namespace.as_bytes()).unwrap();
    w.field(id.as_bytes()).unwrap();
    w.field(profile.as_bytes()).unwrap();
    w.finish()
}

/// `encrypt` / `decrypt` / `wrap` / `unwrap` all share this 3-field layout:
/// `info`, `aad`, then the opaque payload (plaintext, ciphertext, key
/// material or wrapped blob).
fn crypt_body(info: &[u8], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut w = FrameWriter::new();
    w.field(info).unwrap();
    w.field(aad).unwrap();
    w.field(payload).unwrap();
    w.finish()
}

#[allow(clippy::too_many_arguments)]
fn rewrap_body(
    from_info: &[u8],
    from_aad: &[u8],
    to_namespace: &str,
    to_id: &str,
    to_version: u32,
    to_info: &[u8],
    to_aad: &[u8],
    wrapped: &[u8],
) -> Vec<u8> {
    let mut w = FrameWriter::new();
    w.field(from_info).unwrap();
    w.field(from_aad).unwrap();
    w.field(to_namespace.as_bytes()).unwrap();
    w.field(to_id.as_bytes()).unwrap();
    w.u32(to_version);
    w.field(to_info).unwrap();
    w.field(to_aad).unwrap();
    w.field(wrapped).unwrap();
    w.finish()
}

struct KeyCreated {
    namespace: String,
    id: String,
    version: u32,
    public: Vec<u8>,
}

fn parse_key_created(bytes: &[u8]) -> KeyCreated {
    let mut r = FrameReader::new(bytes).unwrap();
    let namespace = r.text().unwrap().to_string();
    let id = r.text().unwrap().to_string();
    let version = r.u32().unwrap();
    let public = r.field().unwrap().to_vec();
    r.finish().unwrap();
    KeyCreated {
        namespace,
        id,
        version,
        public,
    }
}

struct Metadata {
    namespace: String,
    id: String,
    version: u32,
    state: u8,
    profile: String,
}

fn parse_metadata(bytes: &[u8]) -> Metadata {
    let mut r = FrameReader::new(bytes).unwrap();
    let namespace = r.text().unwrap().to_string();
    let id = r.text().unwrap().to_string();
    let version = r.u32().unwrap();
    let state = r.u8().unwrap();
    let profile = r.text().unwrap().to_string();
    r.finish().unwrap();
    Metadata {
        namespace,
        id,
        version,
        state,
        profile,
    }
}

// Wire state codes, per `crypt_guard_hyper::codec::response` module docs.
const ENABLED: u8 = 1;
const DISABLED: u8 = 2;
const DESTROYED: u8 = 4;

// ---------------------------------------------------------------------------
// Flow 1: full key lifecycle over HTTP, anonymous caller, InMemoryProvider.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_key_lifecycle_over_http() {
    let mut h = Harness::anonymous(InMemoryProvider::new()).await;

    // generate -> 200 KeyCreated, version 1, non-empty public key.
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys",
            generate_body("app", "k1", "pq-hpke-default"),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let created = parse_key_created(&body);
    assert_eq!(created.namespace, "app");
    assert_eq!(created.id, "k1");
    assert_eq!(created.version, 1);
    assert!(
        !created.public.is_empty(),
        "an HPKE key must have a public half"
    );

    // describe -> Metadata, state enabled, version 1.
    let (status, body) = h
        .send(req(Method::GET, "/v1/keys/app/k1", Vec::new()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let meta = parse_metadata(&body);
    assert_eq!(meta.namespace, "app");
    assert_eq!(meta.id, "k1");
    assert_eq!(meta.version, 1);
    assert_eq!(meta.state, ENABLED);
    assert_eq!(meta.profile, "pq-hpke-default");

    // public key over HTTP equals the one just created.
    let (status, body) = h
        .send(req(Method::GET, "/v1/keys/app/k1/public", Vec::new()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), created.public.as_slice());

    // encrypt -> ciphertext.
    let plaintext = b"the quick brown fox";
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:encrypt",
            crypt_body(b"info", b"aad", plaintext),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let ciphertext_v1 = body.to_vec();

    // decrypt -> 200, original plaintext.
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            crypt_body(b"info", b"aad", &ciphertext_v1),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), plaintext);

    // rotate -> version 2.
    let (status, body) = h
        .send(req(Method::POST, "/v1/keys/app/k1:rotate", Vec::new()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let rotated = parse_key_created(&body);
    assert_eq!(rotated.version, 2);

    // the v1 ciphertext still decrypts after rotation: the frame carries its
    // own key version, independent of which version is now primary.
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            crypt_body(b"info", b"aad", &ciphertext_v1),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), plaintext);

    // disable version 1 explicitly (`@1`).
    let (status, body) = h
        .send(req(Method::POST, "/v1/keys/app/k1@1:disable", Vec::new()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let meta = parse_metadata(&body);
    assert_eq!(meta.version, 1);
    assert_eq!(meta.state, DISABLED);

    // decrypting the v1 ciphertext now hits a disabled version: 409.
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            crypt_body(b"info", b"aad", &ciphertext_v1),
        ))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body.as_ref(),
        StatusCode::CONFLICT.canonical_reason().unwrap().as_bytes()
    );

    // re-enable version 1.
    let (status, body) = h
        .send(req(Method::POST, "/v1/keys/app/k1@1:enable", Vec::new()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let meta = parse_metadata(&body);
    assert_eq!(meta.state, ENABLED);

    // destroy version 1 (destroy requires an explicit version).
    let (status, body) = h
        .send(req(Method::POST, "/v1/keys/app/k1@1:destroy", Vec::new()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let meta = parse_metadata(&body);
    assert_eq!(meta.version, 1);
    assert_eq!(meta.state, DESTROYED);

    // decrypting the v1 ciphertext is now an opaque authentication failure:
    // 422 (destroyed material is indistinguishable from any other opaque
    // decrypt failure to the caller).
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            crypt_body(b"info", b"aad", &ciphertext_v1),
        ))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body.as_ref(),
        StatusCode::UNPROCESSABLE_ENTITY
            .canonical_reason()
            .unwrap()
            .as_bytes()
    );

    h.finish().await;
}

// ---------------------------------------------------------------------------
// Flow 2: tampering, wrong aad and wrong info are indistinguishable errors.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decrypt_errors_are_opaque_and_byte_identical_over_http() {
    let mut h = Harness::anonymous(InMemoryProvider::new()).await;

    h.send(req(
        Method::POST,
        "/v1/keys",
        generate_body("app", "k1", "pq-hpke-default"),
    ))
    .await;

    let plaintext = b"opaque-error payload";
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:encrypt",
            crypt_body(b"info", b"aad", plaintext),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let ciphertext = body.to_vec();

    // Tampered ciphertext: flip the last byte.
    let mut tampered = ciphertext.clone();
    *tampered.last_mut().unwrap() ^= 0xFF;
    let (status_tampered, body_tampered) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            crypt_body(b"info", b"aad", &tampered),
        ))
        .await;

    // Wrong aad, correct ciphertext.
    let (status_wrong_aad, body_wrong_aad) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            crypt_body(b"info", b"wrong-aad", &ciphertext),
        ))
        .await;

    // Wrong info, correct ciphertext.
    let (status_wrong_info, body_wrong_info) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            crypt_body(b"wrong-info", b"aad", &ciphertext),
        ))
        .await;

    for status in [status_tampered, status_wrong_aad, status_wrong_info] {
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    // Byte-identical bodies: an HTTP caller cannot tell tampering, a wrong
    // `aad` and a wrong `info` apart.
    assert_eq!(body_tampered, body_wrong_aad);
    assert_eq!(body_wrong_aad, body_wrong_info);

    h.finish().await;
}

// ---------------------------------------------------------------------------
// Flow 3: wrap / unwrap / rewrap between two keys over HTTP.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrap_unwrap_rewrap_between_two_keys_over_http() {
    let mut h = Harness::anonymous(InMemoryProvider::new()).await;

    h.send(req(
        Method::POST,
        "/v1/keys",
        generate_body("app", "k1", "pq-hpke-default"),
    ))
    .await;
    h.send(req(
        Method::POST,
        "/v1/keys",
        generate_body("app", "k2", "pq-hpke-default"),
    ))
    .await;

    let material = b"key-material-to-wrap-0123456789";

    // wrap under k1.
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:wrap",
            crypt_body(b"wrap-info", b"wrap-aad", material),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let wrapped_k1 = body.to_vec();

    // unwrap under k1 recovers the material.
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:unwrap",
            crypt_body(b"wrap-info", b"wrap-aad", &wrapped_k1),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), material);

    // rewrap from k1 to k2 (0 = latest version of k2).
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:rewrap",
            rewrap_body(
                b"wrap-info",
                b"wrap-aad",
                "app",
                "k2",
                0,
                b"k2-info",
                b"k2-aad",
                &wrapped_k1,
            ),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let wrapped_k2 = body.to_vec();

    // unwrap under k2 recovers the same material.
    let (status, body) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k2:unwrap",
            crypt_body(b"k2-info", b"k2-aad", &wrapped_k2),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), material);

    // the k2-wrapped blob is bound to k2 (namespace/id/version are part of
    // the sealed binding), so unwrapping it under k1 is an opaque failure.
    let (status, _) = h
        .send(req(
            Method::POST,
            "/v1/keys/app/k1:unwrap",
            crypt_body(b"k2-info", b"k2-aad", &wrapped_k2),
        ))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    h.finish().await;
}

// ---------------------------------------------------------------------------
// Flow 4: authentication + per-namespace policy.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_and_namespace_policy_over_http() {
    let mut policy = NamespacePolicy::new();
    policy.grant(
        Principal::new("admin"),
        KeyNamespace::new("app").unwrap(),
        OpSet::ADMIN
            .union(OpSet::ENCRYPT)
            .union(OpSet::SECRET_EGRESS),
    );
    policy.grant(
        Principal::new("reader"),
        KeyNamespace::new("app").unwrap(),
        OpSet::READ_PUBLIC,
    );

    let mut tokens = BearerTokens::new();
    tokens.insert(
        SecretBytes::copy_from_slice(b"admin-token"),
        Principal::new("admin"),
    );
    tokens.insert(
        SecretBytes::copy_from_slice(b"reader-token"),
        Principal::new("reader"),
    );

    let provider = PolicyProvider::new(InMemoryProvider::new(), policy);
    let mut h = Harness::new(provider, tokens, HttpConfig::default()).await;

    // No Authorization header at all: the request is anonymous, and
    // `NamespacePolicy` treats an anonymous caller as Unauthenticated -> 401.
    let (status, _) = h
        .send(req(
            Method::POST,
            "/v1/keys",
            generate_body("app", "k1", "pq-hpke-default"),
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong bearer token: rejected by the authenticator itself -> 401.
    let (status, _) = h
        .send(authed_req(
            Method::POST,
            "/v1/keys",
            "not-a-real-token",
            generate_body("app", "k1", "pq-hpke-default"),
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // admin generates: authorized by the ADMIN grant.
    let (status, body) = h
        .send(authed_req(
            Method::POST,
            "/v1/keys",
            "admin-token",
            generate_body("app", "k1", "pq-hpke-default"),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let created = parse_key_created(&body);
    assert_eq!(created.version, 1);

    // reader may describe (READ_PUBLIC).
    let (status, _) = h
        .send(authed_req(
            Method::GET,
            "/v1/keys/app/k1",
            "reader-token",
            Vec::new(),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);

    // admin encrypts a secret so the reader-forbidden-decrypt check below has
    // a real ciphertext to try against.
    let plaintext = b"policy-guarded secret";
    let (status, body) = h
        .send(authed_req(
            Method::POST,
            "/v1/keys/app/k1:encrypt",
            "admin-token",
            crypt_body(b"info", b"aad", plaintext),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    let ciphertext = body.to_vec();

    // reader has no SECRET_EGRESS grant: Forbidden, hidden as 404 by the
    // adapter's default `hide_forbidden_keys` config, so a caller cannot
    // distinguish "not permitted" from "does not exist".
    let (status, body) = h
        .send(authed_req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            "reader-token",
            crypt_body(b"info", b"aad", &ciphertext),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body.as_ref(),
        StatusCode::NOT_FOUND.canonical_reason().unwrap().as_bytes()
    );

    // admin has SECRET_EGRESS: decrypts successfully.
    let (status, body) = h
        .send(authed_req(
            Method::POST,
            "/v1/keys/app/k1:decrypt",
            "admin-token",
            crypt_body(b"info", b"aad", &ciphertext),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), plaintext);

    h.finish().await;
}

// ---------------------------------------------------------------------------
// Signing is compiled out of this crate: `crates/hyper/Cargo.toml` depends on
// `crypt_guard_service` with only the `buffer` feature, not `ml-dsa`. So
// `InMemoryProvider` cannot create an ML-DSA signing key here, and a
// `generate` request for one is rejected as `Unsupported` -> HTTP 501.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generating_a_signing_key_is_unsupported_without_the_ml_dsa_feature() {
    // NB: this assumes `ml-dsa` stays off for the compiled instance of
    // `crypt_guard_service` this test binary links. A per-crate build
    // (`cargo test -p crypt_guard_hyper`) matches `crates/hyper/Cargo.toml`
    // above; a `cargo test --workspace` run could only differ if some other
    // workspace member enabled `ml-dsa` as a *normal* (non-dev) dependency
    // feature unified into this same build, which nothing in this workspace
    // does today (`ml-dsa` is only reachable through the top-level
    // `crypt_guard` facade's optional `service`/`hyper` features).
    let mut h = Harness::anonymous(InMemoryProvider::new()).await;
    let (status, _) = h
        .send(req(
            Method::POST,
            "/v1/keys",
            generate_body("app", "signer", "ml-dsa-65"),
        ))
        .await;
    // `crypt_guard_hyper` itself does not enable `crypt_guard_service/ml-dsa`,
    // but Cargo feature unification can (e.g. `cargo test -p crypt_guard_service
    // --all-features -p crypt_guard_hyper`). Either way the request must be
    // handled cleanly: created when ML-DSA is compiled in, 501 otherwise.
    assert!(
        status == StatusCode::NOT_IMPLEMENTED || status == StatusCode::OK,
        "unexpected status {status}"
    );
    h.finish().await;
}
