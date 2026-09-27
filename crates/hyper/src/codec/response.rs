//! Response encoding.
//!
//! | Response | Body |
//! |----------|------|
//! | `PublicKey`, `Ciphertext`, `Signature` | raw bytes, `application/octet-stream` |
//! | `Plaintext` | raw bytes via `Bytes::from_owner(secret.into_egress())` (one-way, zeroizing owner) |
//! | `KeyCreated` | `CGK1`: `namespace` `id` `version`(u32) `public`(field; empty if none) |
//! | `Metadata` | `CGK1`: `namespace` `id` `version`(u32) `state`(u8: 1 enabled, 2 disabled, 3 pending destruction, 4 destroyed) `profile`(text; empty if unnamed) |
//! | `Verification` | `CGK1`: `valid`(u8: 1 valid, 0 invalid) |
//! | anything else | `500` via `crate::error::status_response` |
//!
//! Status is always `200` here; errors are mapped elsewhere. The caller adds
//! `Cache-Control: no-store`.

use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::Full;

use crypt_guard_service::{CryptoResponse, KeyState, VerificationResult};

use super::frame::{CodecError, FrameWriter, CONTENT_TYPE};
use super::profile;

/// Encode a successful service response.
pub fn encode_response(response: CryptoResponse) -> Response<Full<Bytes>> {
    match response {
        CryptoResponse::PublicKey(blob) => octet_response(blob.into_inner()),
        CryptoResponse::Ciphertext(blob) => octet_response(blob.into_inner()),
        CryptoResponse::Signature(blob) => octet_response(blob.into_inner()),
        CryptoResponse::Plaintext(secret) => {
            let bytes = Bytes::from_owner(secret.into_egress());
            let mut response = Response::new(Full::new(bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            response
        }
        CryptoResponse::KeyCreated { key, public } => build_frame(|w| {
            w.field(key.namespace.as_str().as_bytes())?;
            w.field(key.id.as_str().as_bytes())?;
            w.u32(key.version.map_or(0, |v| v.get()));
            let public_bytes: &[u8] = public.as_ref().map_or(b"".as_slice(), |p| p.as_bytes());
            w.field(public_bytes)?;
            Ok(())
        }),
        CryptoResponse::Metadata(meta) => build_frame(|w| {
            w.field(meta.key.namespace.as_str().as_bytes())?;
            w.field(meta.key.id.as_str().as_bytes())?;
            w.u32(meta.key.version.map_or(0, |v| v.get()));
            w.u8(state_code(meta.state));
            let profile_name = profile::name(meta.algorithm).unwrap_or("");
            w.field(profile_name.as_bytes())?;
            Ok(())
        }),
        CryptoResponse::Verification(result) => build_frame(|w| {
            w.u8(match result {
                VerificationResult::Valid => 1,
                VerificationResult::Invalid => 0,
            });
            Ok(())
        }),
        _ => crate::error::status_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn state_code(state: KeyState) -> u8 {
    match state {
        KeyState::Enabled => 1,
        KeyState::Disabled => 2,
        KeyState::PendingDestruction => 3,
        KeyState::Destroyed => 4,
        _ => 0,
    }
}

/// Build a `CGK1` response, mapping the (practically unreachable) writer
/// error to `500` instead of panicking or leaking encoding details.
fn build_frame(
    build: impl FnOnce(&mut FrameWriter) -> Result<(), CodecError>,
) -> Response<Full<Bytes>> {
    let mut writer = FrameWriter::new();
    match build(&mut writer) {
        Ok(()) => frame_response(writer.finish()),
        Err(_) => crate::error::status_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn frame_response(bytes: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(CONTENT_TYPE),
    );
    response
}

fn octet_response(bytes: Box<[u8]>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    response
}
