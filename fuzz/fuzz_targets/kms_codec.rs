//! The `CGK1` request codec of the KMS HTTP adapter must decode arbitrary
//! bodies for every route without panicking.
#![no_main]

use crypt_guard_hyper::{
    body::SecretBody,
    codec::{decode_request, FrameReader},
    route::RouteOp,
};
use crypt_guard_service::{KeyId, KeyNamespace, KeyRef, SecretBytes};
use libfuzzer_sys::fuzz_target;

const OPS: [RouteOp; 14] = [
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

fuzz_target!(|data: &[u8]| {
    if let Ok(mut reader) = FrameReader::new(data) {
        while reader.field().is_ok() {}
        let _ = reader.finish();
    }

    let body = SecretBody::new(SecretBytes::copy_from_slice(data));
    let key = KeyRef::latest(
        KeyNamespace::new("fuzz").unwrap(),
        KeyId::new("key").unwrap(),
    );
    for op in OPS {
        let _ = decode_request(op, Some(key.clone()), &body);
        let _ = decode_request(op, None, &body);
    }
});
