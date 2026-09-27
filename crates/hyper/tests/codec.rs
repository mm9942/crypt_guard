//! Integration tests for the `CGK1` wire codec: request decoding, response
//! encoding and profile names.
//!
//! Priority is security: no panics on hostile input (magic/version/length
//! confusion, truncation, huge declared lengths) and no secret leakage
//! (matching only on shape/lengths of secret fields, never printing them).

use bytes::Bytes;
use http::header;
use http_body_util::BodyExt;

use crypt_guard_hyper::body::SecretBody;
use crypt_guard_hyper::codec::{self, profile, CodecError, FrameReader, FrameWriter, CONTENT_TYPE};
use crypt_guard_hyper::route::RouteOp;
use crypt_guard_service::{
    CryptoOperation, CryptoResponse, KeyAlgorithm, KeyId, KeyMetadata, KeyNamespace, KeyRef,
    KeyState, KeyVersion, PublicBlob, SecretBytes, SignatureAlgorithm, VerificationResult,
};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn body_of(bytes: Vec<u8>) -> SecretBody {
    SecretBody::new(SecretBytes::copy_from_slice(&bytes))
}

fn empty() -> SecretBody {
    body_of(Vec::new())
}

fn key(namespace: &str, id: &str) -> KeyRef {
    KeyRef::latest(
        KeyNamespace::new(namespace).unwrap(),
        KeyId::new(id).unwrap(),
    )
}

fn some_key() -> KeyRef {
    key("app", "k1")
}

/// One piece of a `CGK1` frame, used to build canonical frames and their
/// "one field short" / "one field extra" variants generically.
enum Piece<'a> {
    Field(&'a [u8]),
    U32(u32),
}

fn build(pieces: &[Piece<'_>]) -> Vec<u8> {
    let mut w = FrameWriter::new();
    for piece in pieces {
        match piece {
            Piece::Field(bytes) => {
                w.field(bytes).unwrap();
            }
            Piece::U32(value) => {
                w.u32(*value);
            }
        }
    }
    w.finish()
}

/// All routed operations, fielded and empty-bodied alike.
const ALL_OPS: [RouteOp; 14] = [
    RouteOp::Generate,
    RouteOp::Describe,
    RouteOp::PublicKey,
    RouteOp::Encrypt,
    RouteOp::Decrypt,
    RouteOp::Sign,
    RouteOp::Verify,
    RouteOp::Rotate,
    RouteOp::Disable,
    RouteOp::Enable,
    RouteOp::Destroy,
    RouteOp::Wrap,
    RouteOp::Unwrap,
    RouteOp::Rewrap,
];

const EMPTY_BODY_OPS: [RouteOp; 6] = [
    RouteOp::Describe,
    RouteOp::PublicKey,
    RouteOp::Rotate,
    RouteOp::Disable,
    RouteOp::Enable,
    RouteOp::Destroy,
];

/// Field lists for every fielded operation, per the module doc table in
/// `codec::request`.
fn generate_pieces() -> Vec<Piece<'static>> {
    vec![
        Piece::Field(b"app"),
        Piece::Field(b"k1"),
        Piece::Field(b"pq-hpke-default"),
    ]
}

fn encrypt_pieces() -> Vec<Piece<'static>> {
    vec![
        Piece::Field(b"info"),
        Piece::Field(b"aad"),
        Piece::Field(b"secret-plaintext"),
    ]
}

fn decrypt_pieces() -> Vec<Piece<'static>> {
    vec![
        Piece::Field(b"info"),
        Piece::Field(b"aad"),
        Piece::Field(b"cipher-bytes"),
    ]
}

fn sign_pieces() -> Vec<Piece<'static>> {
    vec![Piece::Field(b"message-bytes")]
}

fn verify_pieces() -> Vec<Piece<'static>> {
    vec![Piece::Field(b"message-bytes"), Piece::Field(b"sig-bytes")]
}

fn wrap_pieces() -> Vec<Piece<'static>> {
    vec![
        Piece::Field(b"info"),
        Piece::Field(b"aad"),
        Piece::Field(b"material-bytes"),
    ]
}

fn unwrap_pieces() -> Vec<Piece<'static>> {
    vec![
        Piece::Field(b"info"),
        Piece::Field(b"aad"),
        Piece::Field(b"wrapped-bytes"),
    ]
}

fn rewrap_pieces() -> Vec<Piece<'static>> {
    vec![
        Piece::Field(b"from-info"),
        Piece::Field(b"from-aad"),
        Piece::Field(b"other"),
        Piece::Field(b"k2"),
        Piece::U32(0),
        Piece::Field(b"to-info"),
        Piece::Field(b"to-aad"),
        Piece::Field(b"wrapped-bytes"),
    ]
}

/// (op, key-required, canonical pieces) for every fielded operation.
fn fielded_ops() -> Vec<(RouteOp, Vec<Piece<'static>>)> {
    vec![
        (RouteOp::Generate, generate_pieces()),
        (RouteOp::Encrypt, encrypt_pieces()),
        (RouteOp::Decrypt, decrypt_pieces()),
        (RouteOp::Sign, sign_pieces()),
        (RouteOp::Verify, verify_pieces()),
        (RouteOp::Wrap, wrap_pieces()),
        (RouteOp::Unwrap, unwrap_pieces()),
        (RouteOp::Rewrap, rewrap_pieces()),
    ]
}

fn key_for(op: RouteOp) -> Option<KeyRef> {
    if op == RouteOp::Generate {
        None
    } else {
        Some(some_key())
    }
}

// ---------------------------------------------------------------------
// 1. Round-trip every fielded RouteOp exactly per the wire table.
// ---------------------------------------------------------------------

#[test]
fn generate_round_trips_fields() {
    let body = body_of(build(&generate_pieces()));
    let op = codec::decode_request(RouteOp::Generate, None, &body).unwrap();
    match op {
        CryptoOperation::Generate(g) => {
            assert_eq!(g.namespace.as_str(), "app");
            assert_eq!(g.id.as_str(), "k1");
            assert!(matches!(g.algorithm, KeyAlgorithm::Hpke { .. }));
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn encrypt_round_trips_fields() {
    let body = body_of(build(&encrypt_pieces()));
    let op = codec::decode_request(RouteOp::Encrypt, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::Encrypt(e) => {
            assert_eq!(&*e.context.info, b"info");
            assert_eq!(&*e.context.aad, b"aad");
            assert_eq!(e.plaintext.as_ref(), b"secret-plaintext");
            assert_eq!(e.key, some_key());
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn decrypt_round_trips_fields() {
    let body = body_of(build(&decrypt_pieces()));
    let op = codec::decode_request(RouteOp::Decrypt, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::Decrypt(d) => {
            assert_eq!(&*d.context.info, b"info");
            assert_eq!(&*d.context.aad, b"aad");
            assert_eq!(d.ciphertext.as_bytes(), b"cipher-bytes");
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn sign_round_trips_fields() {
    let body = body_of(build(&sign_pieces()));
    let op = codec::decode_request(RouteOp::Sign, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::Sign(s) => {
            assert_eq!(s.message.as_ref(), b"message-bytes");
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn verify_round_trips_fields() {
    let body = body_of(build(&verify_pieces()));
    let op = codec::decode_request(RouteOp::Verify, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::Verify(v) => {
            assert_eq!(v.message.as_bytes(), b"message-bytes");
            assert_eq!(v.signature.as_bytes(), b"sig-bytes");
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn wrap_round_trips_fields() {
    let body = body_of(build(&wrap_pieces()));
    let op = codec::decode_request(RouteOp::Wrap, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::WrapKey(w) => {
            assert_eq!(&*w.context.info, b"info");
            assert_eq!(&*w.context.aad, b"aad");
            assert_eq!(w.material.as_ref(), b"material-bytes");
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn unwrap_round_trips_fields() {
    let body = body_of(build(&unwrap_pieces()));
    let op = codec::decode_request(RouteOp::Unwrap, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::UnwrapKey(u) => {
            assert_eq!(&*u.context.info, b"info");
            assert_eq!(&*u.context.aad, b"aad");
            assert_eq!(u.wrapped.as_bytes(), b"wrapped-bytes");
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn rewrap_round_trips_fields_and_zero_version_is_latest() {
    let body = body_of(build(&rewrap_pieces()));
    let op = codec::decode_request(RouteOp::Rewrap, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::RewrapKey(r) => {
            assert_eq!(&*r.from_context.info, b"from-info");
            assert_eq!(&*r.from_context.aad, b"from-aad");
            assert_eq!(r.to.namespace.as_str(), "other");
            assert_eq!(r.to.id.as_str(), "k2");
            assert_eq!(r.to.version, None);
            assert_eq!(&*r.to_context.info, b"to-info");
            assert_eq!(&*r.to_context.aad, b"to-aad");
            assert_eq!(r.wrapped.as_bytes(), b"wrapped-bytes");
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn rewrap_nonzero_version_is_some() {
    let pieces = vec![
        Piece::Field(b"from-info"),
        Piece::Field(b"from-aad"),
        Piece::Field(b"other"),
        Piece::Field(b"k2"),
        Piece::U32(3),
        Piece::Field(b"to-info"),
        Piece::Field(b"to-aad"),
        Piece::Field(b"wrapped-bytes"),
    ];
    let body = body_of(build(&pieces));
    let op = codec::decode_request(RouteOp::Rewrap, Some(some_key()), &body).unwrap();
    match op {
        CryptoOperation::RewrapKey(r) => {
            assert_eq!(r.to.version, Some(KeyVersion::new(3).unwrap()));
        }
        _ => panic!("wrong operation"),
    }
}

#[test]
fn empty_body_ops_decode_with_a_key() {
    for op in EMPTY_BODY_OPS {
        let body = empty();
        let decoded = codec::decode_request(op, Some(some_key()), &body).unwrap();
        match (op, decoded) {
            (RouteOp::Describe, CryptoOperation::Describe(d)) => assert_eq!(d.key, some_key()),
            (RouteOp::PublicKey, CryptoOperation::PublicKey(p)) => assert_eq!(p.key, some_key()),
            (RouteOp::Rotate, CryptoOperation::Rotate(r)) => assert_eq!(r.key, some_key()),
            (RouteOp::Disable, CryptoOperation::Disable(d)) => assert_eq!(d.key, some_key()),
            (RouteOp::Enable, CryptoOperation::Enable(e)) => assert_eq!(e.key, some_key()),
            (RouteOp::Destroy, CryptoOperation::Destroy(d)) => assert_eq!(d.key, some_key()),
            (op, _) => panic!("wrong operation for {op:?}"),
        }
    }
}

// ---------------------------------------------------------------------
// 2. Structural errors: wrong field counts, magic, version, empty/non-empty
//    bodies, invalid names, unknown profile.
// ---------------------------------------------------------------------

#[test]
fn missing_last_field_is_truncated() {
    for (op, pieces) in fielded_ops() {
        let short = &pieces[..pieces.len() - 1];
        let body = body_of(build(short));
        let err = codec::decode_request(op, key_for(op), &body).unwrap_err();
        assert_eq!(err, CodecError::Truncated, "{op:?}");
    }
}

#[test]
fn extra_trailing_field_is_trailing() {
    for (op, mut pieces) in fielded_ops() {
        pieces.push(Piece::Field(b"unexpected-extra-field"));
        let body = body_of(build(&pieces));
        let err = codec::decode_request(op, key_for(op), &body).unwrap_err();
        assert_eq!(err, CodecError::Trailing, "{op:?}");
    }
}

#[test]
fn wrong_magic_is_bad_magic() {
    for (op, pieces) in fielded_ops() {
        let mut bytes = build(&pieces);
        bytes[0] = b'X';
        let body = body_of(bytes);
        let err = codec::decode_request(op, key_for(op), &body).unwrap_err();
        assert_eq!(err, CodecError::BadMagic, "{op:?}");
    }
}

#[test]
fn wrong_version_is_unsupported() {
    for (op, pieces) in fielded_ops() {
        let mut bytes = build(&pieces);
        bytes[4] = 0xFF;
        let body = body_of(bytes);
        let err = codec::decode_request(op, key_for(op), &body).unwrap_err();
        assert_eq!(err, CodecError::UnsupportedVersion, "{op:?}");
    }
}

#[test]
fn empty_body_for_fielded_ops_is_an_error() {
    for (op, _) in fielded_ops() {
        let body = empty();
        let err = codec::decode_request(op, key_for(op), &body).unwrap_err();
        // No magic at all to read.
        assert_eq!(err, CodecError::Truncated, "{op:?}");
    }
}

#[test]
fn non_empty_body_for_empty_ops_is_invalid() {
    for op in EMPTY_BODY_OPS {
        let body = body_of(vec![0]);
        let err = codec::decode_request(op, Some(some_key()), &body).unwrap_err();
        assert_eq!(err, CodecError::Invalid, "{op:?}");
    }
}

#[test]
fn missing_key_is_invalid_for_non_generate_ops() {
    for op in ALL_OPS {
        if op == RouteOp::Generate {
            continue;
        }
        let pieces_body = match op {
            RouteOp::Encrypt => body_of(build(&encrypt_pieces())),
            RouteOp::Decrypt => body_of(build(&decrypt_pieces())),
            RouteOp::Sign => body_of(build(&sign_pieces())),
            RouteOp::Verify => body_of(build(&verify_pieces())),
            RouteOp::Wrap => body_of(build(&wrap_pieces())),
            RouteOp::Unwrap => body_of(build(&unwrap_pieces())),
            RouteOp::Rewrap => body_of(build(&rewrap_pieces())),
            _ => empty(),
        };
        let err = codec::decode_request(op, None, &pieces_body).unwrap_err();
        assert_eq!(err, CodecError::Invalid, "{op:?}");
    }
}

#[test]
fn generate_rejects_a_key() {
    let body = body_of(build(&generate_pieces()));
    let err = codec::decode_request(RouteOp::Generate, Some(some_key()), &body).unwrap_err();
    assert_eq!(err, CodecError::Invalid);
}

#[test]
fn generate_rejects_invalid_namespace_and_id() {
    for pieces in [
        vec![
            Piece::Field(b"bad name"),
            Piece::Field(b"k1"),
            Piece::Field(b"pq-hpke-default"),
        ],
        vec![
            Piece::Field(b"app"),
            Piece::Field(b""),
            Piece::Field(b"pq-hpke-default"),
        ],
        vec![
            Piece::Field(b"app"),
            Piece::Field(b".hidden"),
            Piece::Field(b"pq-hpke-default"),
        ],
    ] {
        let body = body_of(build(&pieces));
        let err = codec::decode_request(RouteOp::Generate, None, &body).unwrap_err();
        assert_eq!(err, CodecError::Invalid);
    }
}

#[test]
fn generate_rejects_unknown_profile() {
    let pieces = vec![
        Piece::Field(b"app"),
        Piece::Field(b"k1"),
        Piece::Field(b"not-a-real-profile"),
    ];
    let body = body_of(build(&pieces));
    let err = codec::decode_request(RouteOp::Generate, None, &body).unwrap_err();
    assert_eq!(err, CodecError::Invalid);
}

#[test]
fn rewrap_rejects_invalid_to_names() {
    let pieces = vec![
        Piece::Field(b"from-info"),
        Piece::Field(b"from-aad"),
        Piece::Field(b"bad name"),
        Piece::Field(b"k2"),
        Piece::U32(0),
        Piece::Field(b"to-info"),
        Piece::Field(b"to-aad"),
        Piece::Field(b"wrapped-bytes"),
    ];
    let body = body_of(build(&pieces));
    let err = codec::decode_request(RouteOp::Rewrap, Some(some_key()), &body).unwrap_err();
    assert_eq!(err, CodecError::Invalid);

    let pieces = vec![
        Piece::Field(b"from-info"),
        Piece::Field(b"from-aad"),
        Piece::Field(b"other"),
        Piece::Field(b""),
        Piece::U32(0),
        Piece::Field(b"to-info"),
        Piece::Field(b"to-aad"),
        Piece::Field(b"wrapped-bytes"),
    ];
    let body = body_of(build(&pieces));
    let err = codec::decode_request(RouteOp::Rewrap, Some(some_key()), &body).unwrap_err();
    assert_eq!(err, CodecError::Invalid);
}

// ---------------------------------------------------------------------
// 3. Deterministic fuzz loop: no panics on hostile input.
// ---------------------------------------------------------------------

/// Deterministic xorshift64 PRNG; no external dependency needed.
fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn decode_request_never_panics_on_arbitrary_input() {
    let mut state: u64 = 0xD1CE_5EED_u64.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let key = Some(some_key());

    for _ in 0..20_000 {
        let use_real_prefix = xorshift(&mut state).is_multiple_of(2);
        let len = (xorshift(&mut state) % 256) as usize;

        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        if use_real_prefix {
            bytes.extend_from_slice(b"CGK1\x01");
        }
        while bytes.len() < len {
            bytes.push((xorshift(&mut state) % 256) as u8);
        }
        bytes.truncate(len);

        let body = body_of(bytes);
        for op in ALL_OPS {
            let _ = codec::decode_request(op, key.clone(), &body);
            let _ = codec::decode_request(op, None, &body);
        }
    }
}

// ---------------------------------------------------------------------
// 4. Response encoding.
// ---------------------------------------------------------------------

fn frame_body_bytes(bytes: &[u8]) -> FrameReader<'_> {
    FrameReader::new(bytes).unwrap()
}

#[tokio::test]
async fn key_created_encodes_as_cgk1_frame() {
    let response = codec::encode_response(CryptoResponse::KeyCreated {
        key: KeyRef::versioned(
            KeyNamespace::new("app").unwrap(),
            KeyId::new("k1").unwrap(),
            KeyVersion::new(2).unwrap(),
        ),
        public: Some(PublicBlob::new(vec![0xAB, 0xCD])),
    });
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        CONTENT_TYPE
    );
    let bytes = collect(response).await;
    let mut r = frame_body_bytes(&bytes);
    assert_eq!(r.text().unwrap(), "app");
    assert_eq!(r.text().unwrap(), "k1");
    assert_eq!(r.u32().unwrap(), 2);
    assert_eq!(r.field().unwrap(), &[0xAB, 0xCD]);
    r.finish().unwrap();
}

#[tokio::test]
async fn key_created_with_no_public_key_has_empty_public_field() {
    let response = codec::encode_response(CryptoResponse::KeyCreated {
        key: KeyRef::latest(KeyNamespace::new("app").unwrap(), KeyId::new("k1").unwrap()),
        public: None,
    });
    let bytes = collect(response).await;
    let mut r = frame_body_bytes(&bytes);
    assert_eq!(r.text().unwrap(), "app");
    assert_eq!(r.text().unwrap(), "k1");
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.field().unwrap(), b"");
    r.finish().unwrap();
}

#[tokio::test]
async fn metadata_encodes_as_cgk1_frame() {
    for (state, code) in [
        (KeyState::Enabled, 1u8),
        (KeyState::Disabled, 2),
        (KeyState::PendingDestruction, 3),
        (KeyState::Destroyed, 4),
    ] {
        let response = codec::encode_response(CryptoResponse::Metadata(KeyMetadata {
            key: KeyRef::versioned(
                KeyNamespace::new("app").unwrap(),
                KeyId::new("k1").unwrap(),
                KeyVersion::new(1).unwrap(),
            ),
            algorithm: KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
            state,
        }));
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            CONTENT_TYPE
        );
        let bytes = collect(response).await;
        let mut r = frame_body_bytes(&bytes);
        assert_eq!(r.text().unwrap(), "app");
        assert_eq!(r.text().unwrap(), "k1");
        assert_eq!(r.u32().unwrap(), 1);
        assert_eq!(r.u8().unwrap(), code);
        assert_eq!(r.text().unwrap(), "ml-dsa-65");
        r.finish().unwrap();
    }
}

#[tokio::test]
async fn verification_encodes_as_cgk1_frame() {
    for (result, code) in [
        (VerificationResult::Valid, 1u8),
        (VerificationResult::Invalid, 0u8),
    ] {
        let response = codec::encode_response(CryptoResponse::Verification(result));
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            CONTENT_TYPE
        );
        let bytes = collect(response).await;
        let mut r = frame_body_bytes(&bytes);
        assert_eq!(r.u8().unwrap(), code);
        r.finish().unwrap();
    }
}

#[tokio::test]
async fn public_key_ciphertext_signature_are_raw_octets() {
    let response =
        codec::encode_response(CryptoResponse::PublicKey(PublicBlob::new(vec![1, 2, 3])));
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(collect(response).await, Bytes::from_static(&[1, 2, 3]));

    let response = codec::encode_response(CryptoResponse::Ciphertext(
        crypt_guard_service::CiphertextBlob::new(vec![4, 5]),
    ));
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(collect(response).await, Bytes::from_static(&[4, 5]));

    let response = codec::encode_response(CryptoResponse::Signature(
        crypt_guard_service::SignatureBlob::new(vec![6]),
    ));
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(collect(response).await, Bytes::from_static(&[6]));
}

#[tokio::test]
async fn plaintext_is_raw_octets_with_identical_bytes() {
    let secret = SecretBytes::copy_from_slice(b"the-plaintext");
    let response = codec::encode_response(CryptoResponse::Plaintext(secret));
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        collect(response).await,
        Bytes::from_static(b"the-plaintext")
    );
}

async fn collect(response: http::Response<http_body_util::Full<Bytes>>) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

// ---------------------------------------------------------------------
// 5. Profile name/parse round trip.
// ---------------------------------------------------------------------

#[test]
fn profile_names_round_trip() {
    for name in ["pq-hpke-default", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] {
        let algorithm = profile::parse(name).unwrap_or_else(|| panic!("{name} should parse"));
        let round_tripped =
            profile::name(algorithm).unwrap_or_else(|| panic!("{name} should have a name"));
        assert_eq!(round_tripped, name);
    }
}

#[test]
fn unknown_profile_name_is_none() {
    assert_eq!(profile::parse(""), None);
    assert_eq!(profile::parse("pq-hpke-default "), None);
    assert_eq!(profile::parse("ML-DSA-44"), None);
    assert_eq!(profile::parse("totally-unknown"), None);
}
