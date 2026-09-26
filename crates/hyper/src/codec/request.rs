//! Request decoding per operation.
//!
//! Operations without fields accept an **empty** body (no frame at all); a
//! non-empty body there is `Invalid`. All others take one `CGK1` frame
//! with exactly these fields, in this order, and nothing after them:
//!
//! | Operation | Fields |
//! |-----------|--------|
//! | generate | `namespace`(text) `id`(text) `profile`(text, see [`super::profile`]) |
//! | describe, public, rotate, disable, enable, destroy | — (empty body) |
//! | encrypt | `info` `aad` `plaintext`🔒 |
//! | decrypt | `info` `aad` `ciphertext` |
//! | sign | `message`🔒 |
//! | verify | `message` `signature` |
//! | wrap | `info` `aad` `material`🔒 |
//! | unwrap | `info` `aad` `wrapped` |
//! | rewrap | `from_info` `from_aad` `to_namespace`(text) `to_id`(text) `to_version`(u32, 0 = latest) `to_info` `to_aad` `wrapped` |
//!
//! 🔒 fields are copied exactly once into `SecretBytes::copy_from_slice`; no
//! other copy of them is made. Names are validated with
//! `KeyNamespace::new` / `KeyId::new` (failure → `Invalid`).

use crypt_guard_service::{
    CiphertextBlob, CryptoContext, CryptoOperation, Decrypt, DescribeKey, DestroyKey, DisableKey,
    EnableKey, Encrypt, GenerateKey, GetPublicKey, KeyId, KeyNamespace, KeyRef, KeyVersion,
    MessageBlob, RewrapKey, RotateKey, SecretBytes, Sign, SignatureBlob, UnwrapKey, Verify,
    WrapKey,
};

use crate::{body::SecretBody, route::RouteOp};

use super::{frame::CodecError, frame::FrameReader, profile};

/// Decode the body of a routed request into an operation.
///
/// `key` is the key from the path (`None` only for generate). A `None` key
/// for any other operation → `Invalid`.
pub fn decode_request(
    op: RouteOp,
    key: Option<KeyRef>,
    body: &SecretBody,
) -> Result<CryptoOperation, CodecError> {
    match op {
        RouteOp::Describe => {
            empty_body(body)?;
            let key = key.ok_or(CodecError::Invalid)?;
            Ok(CryptoOperation::Describe(DescribeKey { key }))
        }
        RouteOp::PublicKey => {
            empty_body(body)?;
            let key = key.ok_or(CodecError::Invalid)?;
            Ok(CryptoOperation::PublicKey(GetPublicKey { key }))
        }
        RouteOp::Rotate => {
            empty_body(body)?;
            let key = key.ok_or(CodecError::Invalid)?;
            Ok(CryptoOperation::Rotate(RotateKey { key }))
        }
        RouteOp::Disable => {
            empty_body(body)?;
            let key = key.ok_or(CodecError::Invalid)?;
            Ok(CryptoOperation::Disable(DisableKey { key }))
        }
        RouteOp::Enable => {
            empty_body(body)?;
            let key = key.ok_or(CodecError::Invalid)?;
            Ok(CryptoOperation::Enable(EnableKey { key }))
        }
        RouteOp::Destroy => {
            empty_body(body)?;
            let key = key.ok_or(CodecError::Invalid)?;
            Ok(CryptoOperation::Destroy(DestroyKey { key }))
        }
        RouteOp::Generate => {
            if key.is_some() {
                return Err(CodecError::Invalid);
            }
            let mut reader = FrameReader::new(body.as_slice())?;
            let namespace = reader.text()?;
            let id = reader.text()?;
            let profile_name = reader.text()?;
            reader.finish()?;

            let namespace = KeyNamespace::new(namespace).map_err(|_| CodecError::Invalid)?;
            let id = KeyId::new(id).map_err(|_| CodecError::Invalid)?;
            let algorithm = profile::parse(profile_name).ok_or(CodecError::Invalid)?;
            Ok(CryptoOperation::Generate(GenerateKey {
                namespace,
                id,
                algorithm,
            }))
        }
        RouteOp::Encrypt => {
            let key = key.ok_or(CodecError::Invalid)?;
            let mut reader = FrameReader::new(body.as_slice())?;
            let info = reader.field()?;
            let aad = reader.field()?;
            let plaintext = reader.field()?;
            let plaintext = SecretBytes::copy_from_slice(plaintext);
            let context = CryptoContext {
                info: Box::from(info),
                aad: Box::from(aad),
            };
            reader.finish()?;
            Ok(CryptoOperation::Encrypt(Encrypt {
                key,
                plaintext,
                context,
            }))
        }
        RouteOp::Decrypt => {
            let key = key.ok_or(CodecError::Invalid)?;
            let mut reader = FrameReader::new(body.as_slice())?;
            let info = reader.field()?;
            let aad = reader.field()?;
            let ciphertext = reader.field()?;
            let ciphertext = CiphertextBlob::new(Box::<[u8]>::from(ciphertext));
            let context = CryptoContext {
                info: Box::from(info),
                aad: Box::from(aad),
            };
            reader.finish()?;
            Ok(CryptoOperation::Decrypt(Decrypt {
                key,
                ciphertext,
                context,
            }))
        }
        RouteOp::Sign => {
            let key = key.ok_or(CodecError::Invalid)?;
            let mut reader = FrameReader::new(body.as_slice())?;
            let message = reader.field()?;
            let message = SecretBytes::copy_from_slice(message);
            reader.finish()?;
            Ok(CryptoOperation::Sign(Sign { key, message }))
        }
        RouteOp::Verify => {
            let key = key.ok_or(CodecError::Invalid)?;
            let mut reader = FrameReader::new(body.as_slice())?;
            let message = reader.field()?;
            let signature = reader.field()?;
            let message = MessageBlob::new(Box::<[u8]>::from(message));
            let signature = SignatureBlob::new(Box::<[u8]>::from(signature));
            reader.finish()?;
            Ok(CryptoOperation::Verify(Verify {
                key,
                message,
                signature,
            }))
        }
        RouteOp::Wrap => {
            let key = key.ok_or(CodecError::Invalid)?;
            let mut reader = FrameReader::new(body.as_slice())?;
            let info = reader.field()?;
            let aad = reader.field()?;
            let material = reader.field()?;
            let material = SecretBytes::copy_from_slice(material);
            let context = CryptoContext {
                info: Box::from(info),
                aad: Box::from(aad),
            };
            reader.finish()?;
            Ok(CryptoOperation::WrapKey(WrapKey {
                key,
                material,
                context,
            }))
        }
        RouteOp::Unwrap => {
            let key = key.ok_or(CodecError::Invalid)?;
            let mut reader = FrameReader::new(body.as_slice())?;
            let info = reader.field()?;
            let aad = reader.field()?;
            let wrapped = reader.field()?;
            let wrapped = CiphertextBlob::new(Box::<[u8]>::from(wrapped));
            let context = CryptoContext {
                info: Box::from(info),
                aad: Box::from(aad),
            };
            reader.finish()?;
            Ok(CryptoOperation::UnwrapKey(UnwrapKey {
                key,
                wrapped,
                context,
            }))
        }
        RouteOp::Rewrap => {
            let from = key.ok_or(CodecError::Invalid)?;
            let mut reader = FrameReader::new(body.as_slice())?;
            let from_info = reader.field()?;
            let from_aad = reader.field()?;
            let to_namespace = reader.text()?;
            let to_id = reader.text()?;
            let to_version = reader.u32()?;
            let to_info = reader.field()?;
            let to_aad = reader.field()?;
            let wrapped = reader.field()?;
            reader.finish()?;

            let to_namespace = KeyNamespace::new(to_namespace).map_err(|_| CodecError::Invalid)?;
            let to_id = KeyId::new(to_id).map_err(|_| CodecError::Invalid)?;
            let to_version = if to_version == 0 {
                None
            } else {
                Some(KeyVersion::new(to_version).map_err(|_| CodecError::Invalid)?)
            };
            let to = KeyRef {
                namespace: to_namespace,
                id: to_id,
                version: to_version,
            };
            let wrapped = CiphertextBlob::new(Box::<[u8]>::from(wrapped));

            Ok(CryptoOperation::RewrapKey(RewrapKey {
                from,
                from_context: CryptoContext {
                    info: Box::from(from_info),
                    aad: Box::from(from_aad),
                },
                to,
                to_context: CryptoContext {
                    info: Box::from(to_info),
                    aad: Box::from(to_aad),
                },
                wrapped,
            }))
        }
    }
}

fn empty_body(body: &SecretBody) -> Result<(), CodecError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(CodecError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::frame::FrameWriter;

    fn body_of(bytes: Vec<u8>) -> SecretBody {
        SecretBody::new(SecretBytes::copy_from_slice(&bytes))
    }

    fn empty() -> SecretBody {
        body_of(Vec::new())
    }

    fn some_key() -> KeyRef {
        KeyRef::latest(KeyNamespace::new("app").unwrap(), KeyId::new("k1").unwrap())
    }

    #[test]
    fn empty_body_ops_require_empty_body_and_a_key() {
        for op in [
            RouteOp::Describe,
            RouteOp::PublicKey,
            RouteOp::Rotate,
            RouteOp::Disable,
            RouteOp::Enable,
            RouteOp::Destroy,
        ] {
            let body = empty();
            assert!(decode_request(op, Some(some_key()), &body).is_ok());

            let body = empty();
            assert_eq!(
                decode_request(op, None, &body).unwrap_err(),
                CodecError::Invalid
            );

            let body = body_of(vec![1]);
            assert_eq!(
                decode_request(op, Some(some_key()), &body).unwrap_err(),
                CodecError::Invalid
            );
        }
    }

    #[test]
    fn generate_decodes_and_rejects_a_key() {
        let mut w = FrameWriter::new();
        w.field(b"app").unwrap();
        w.field(b"k1").unwrap();
        w.field(b"pq-hpke-default").unwrap();
        let body = body_of(w.finish());

        let op = decode_request(RouteOp::Generate, None, &body).unwrap();
        match op {
            CryptoOperation::Generate(g) => {
                assert_eq!(g.namespace.as_str(), "app");
                assert_eq!(g.id.as_str(), "k1");
            }
            _ => panic!("wrong operation"),
        }

        let mut w = FrameWriter::new();
        w.field(b"app").unwrap();
        w.field(b"k1").unwrap();
        w.field(b"pq-hpke-default").unwrap();
        let body = body_of(w.finish());
        assert_eq!(
            decode_request(RouteOp::Generate, Some(some_key()), &body).unwrap_err(),
            CodecError::Invalid
        );
    }

    #[test]
    fn encrypt_decodes_context_and_secret_plaintext() {
        let mut w = FrameWriter::new();
        w.field(b"info").unwrap();
        w.field(b"aad").unwrap();
        w.field(b"secret-plaintext").unwrap();
        let body = body_of(w.finish());

        let op = decode_request(RouteOp::Encrypt, Some(some_key()), &body).unwrap();
        match op {
            CryptoOperation::Encrypt(e) => {
                assert_eq!(&*e.context.info, b"info");
                assert_eq!(&*e.context.aad, b"aad");
                assert_eq!(e.plaintext.as_ref(), b"secret-plaintext");
            }
            _ => panic!("wrong operation"),
        }
    }

    #[test]
    fn sign_requires_a_key() {
        let mut w = FrameWriter::new();
        w.field(b"message").unwrap();
        let body = body_of(w.finish());
        assert_eq!(
            decode_request(RouteOp::Sign, None, &body).unwrap_err(),
            CodecError::Invalid
        );
    }

    #[test]
    fn rewrap_decodes_to_key_with_latest_on_zero_version() {
        let mut w = FrameWriter::new();
        w.field(b"from-info").unwrap();
        w.field(b"from-aad").unwrap();
        w.field(b"other").unwrap();
        w.field(b"k2").unwrap();
        w.u32(0);
        w.field(b"to-info").unwrap();
        w.field(b"to-aad").unwrap();
        w.field(b"wrapped-bytes").unwrap();
        let body = body_of(w.finish());

        let op = decode_request(RouteOp::Rewrap, Some(some_key()), &body).unwrap();
        match op {
            CryptoOperation::RewrapKey(r) => {
                assert_eq!(r.to.namespace.as_str(), "other");
                assert_eq!(r.to.id.as_str(), "k2");
                assert_eq!(r.to.version, None);
            }
            _ => panic!("wrong operation"),
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut w = FrameWriter::new();
        w.field(b"message").unwrap();
        let mut bytes = w.finish();
        bytes.push(0);
        let body = body_of(bytes);
        assert_eq!(
            decode_request(RouteOp::Sign, Some(some_key()), &body).unwrap_err(),
            CodecError::Trailing
        );
    }
}
