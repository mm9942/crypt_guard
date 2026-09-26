//! Minimal KMS HTTP server, wired the same way as
//! `crates/hyper/tests/http.rs`: `CryptoService` (non-`Clone`, owns all key
//! state) behind a bounded `Buffer` (`network_handle`), whose cloneable
//! `NetworkHandle` is the only thing `CryptoHttpService` ever clones per
//! connection.
//!
//! Run it with an admin bearer token already set in the environment (the
//! server never generates or prints one):
//!
//! ```text
//! CG_KMS_ADMIN_TOKEN=$(openssl rand -hex 32) \
//!     cargo run -p crypt_guard_hyper --example kms_server
//! ```
//!
//! Optional overrides: `CG_KMS_ADDR` (default `127.0.0.1:8750`) and
//! `CG_KMS_NAMESPACE` (default `default`).
//!
//! ## Wire format
//!
//! Request and response bodies are the framed encodings documented on
//! [`crypt_guard_hyper::codec`], not plain JSON or curl-friendly text; see
//! that module's docs for the exact frame layout. The route table served
//! here (from [`crypt_guard_hyper::route`]) is:
//!
//! ```text
//! POST /v1/keys                                  generate
//! GET  /v1/keys/{namespace}/{id}[@version]         describe
//! GET  /v1/keys/{namespace}/{id}[@version]/public  public key
//! POST /v1/keys/{namespace}/{id}[@version]:{op}    encrypt | decrypt | sign | verify |
//!                                                rotate | disable | enable | destroy |
//!                                                wrap | unwrap | rewrap
//! ```
//!
//! ## Security notes
//!
//! - This binds plain HTTP. It is meant for local testing only: put TLS in
//!   front of it (a reverse proxy, or a TLS acceptor wrapping the accepted
//!   `TcpStream` before it reaches Hyper) before exposing it beyond
//!   `localhost`.
//! - Keys live only in the in-process `InMemoryProvider` and are lost when
//!   the process exits; nothing is persisted.
//! - Only the listen address is logged. Request/response bodies and the
//!   admin token are never logged.

use std::env;

use crypt_guard_hyper::{into_hyper, CryptoHttpService, HttpConfig};
use crypt_guard_service::{
    network_handle, CryptoService, InMemoryProvider, KeyNamespace, NamespacePolicy, OpSet,
    PolicyProvider, Principal, SecretBytes, StackConfig,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

const DEFAULT_ADDR: &str = "127.0.0.1:8750";
const DEFAULT_NAMESPACE: &str = "default";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let addr = env::var("CG_KMS_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let namespace_name =
        env::var("CG_KMS_NAMESPACE").unwrap_or_else(|_| DEFAULT_NAMESPACE.to_string());

    // The admin token must come from the environment. It is copied once into
    // `SecretBytes` (zeroizing, non-`Clone`); the `String` the environment
    // handed us is *not* zeroized (the standard library gives no way to do
    // that for `env::var`'s output), so keep the surrounding environment
    // itself trusted.
    let admin_token = match env::var("CG_KMS_ADMIN_TOKEN") {
        Ok(token) if !token.is_empty() => token,
        Ok(_) => {
            eprintln!("CG_KMS_ADMIN_TOKEN is set but empty; refusing to start.");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!(
                "CG_KMS_ADMIN_TOKEN is not set; refusing to start without an admin credential.\n\
                 Set it to a high-entropy secret, e.g.:\n\
                 \n    CG_KMS_ADMIN_TOKEN=$(openssl rand -hex 32) cargo run -p crypt_guard_hyper --example kms_server\n"
            );
            std::process::exit(1);
        }
    };

    let namespace = match KeyNamespace::new(&namespace_name) {
        Ok(namespace) => namespace,
        Err(err) => {
            eprintln!("invalid CG_KMS_NAMESPACE {namespace_name:?}: {err:?}");
            std::process::exit(1);
        }
    };

    let admin = Principal::new("admin");
    let mut tokens = crypt_guard_hyper::BearerTokens::new();
    tokens.insert(
        SecretBytes::copy_from_slice(admin_token.as_bytes()),
        admin.clone(),
    );
    drop(admin_token);

    let mut policy = NamespacePolicy::new();
    policy.grant(admin, namespace, OpSet::ALL);

    let provider = PolicyProvider::new(InMemoryProvider::new(), policy);
    let service = CryptoService::new(provider);
    let handle = network_handle(service, StackConfig::default());
    let http_service = into_hyper(
        CryptoHttpService::new(handle, HttpConfig::default()).with_authenticator(tokens),
    );

    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("failed to bind {addr}: {err}");
            std::process::exit(1);
        }
    };
    println!("crypt_guard_hyper KMS example listening on http://{addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                eprintln!("accept error: {err}");
                continue;
            }
        };
        let http_service = http_service.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, http_service)
                .await
            {
                eprintln!("connection error: {err}");
            }
        });
    }
}
