//! PQ HPKE operations of the in-memory provider: encrypt/decrypt and key
//! wrap/unwrap/rewrap, all through the `CGKC` binding in [`super::binding`].

use crypt_guard_core::pq_hpke::{
    generate_recipient_key_pair, HpkeEnvelope, RecipientKeyPair, Suite,
};

use crate::{
    blob::{CiphertextBlob, PublicBlob},
    error::CryptoServiceError,
    key::KeyRef,
    op::CryptoContext,
    secret::SecretBytes,
};

use super::{
    binding::{bind_info, decode_frame, encode_frame, Purpose},
    store::{KeyMaterial, KeyStore},
};

/// Generate a fresh HPKE key pair for `suite`.
///
/// Errors: suite capability not available (`suite.capability()`) →
/// `Unsupported`; core errors via `From<pq_hpke::Error>`.
pub(crate) fn generate_hpke(suite: Suite) -> Result<KeyMaterial, CryptoServiceError> {
    if let crypt_guard_core::pq_hpke::Capability::Unavailable(_) = suite.capability() {
        return Err(CryptoServiceError::Unsupported);
    }
    let keys = generate_recipient_key_pair(suite.kem())?;
    Ok(KeyMaterial::Hpke { suite, keys })
}

/// Encoded public key.
pub(crate) fn public_key(keys: &RecipientKeyPair) -> PublicBlob {
    PublicBlob::new(keys.public_key().as_bytes().to_vec())
}

/// Seal `plaintext` for `purpose` under the key version `key` resolves to
/// (primary when unversioned) and return a `CGKC` frame.
///
/// Errors: store errors as returned by `KeyStore::resolve` / `usable`;
/// non-HPKE key → `Unsupported`; core errors via `From`.
pub(crate) fn seal(
    store: &KeyStore,
    purpose: Purpose,
    key: &KeyRef,
    plaintext: &[u8],
    ctx: &CryptoContext,
) -> Result<CiphertextBlob, CryptoServiceError> {
    let entry = store.resolve(key)?;
    let material = entry.usable()?;
    let (suite, keys) = match material {
        KeyMaterial::Hpke { suite, keys } => (*suite, keys),
        #[allow(unreachable_patterns)]
        _ => return Err(CryptoServiceError::Unsupported),
    };
    let info = bind_info(
        purpose,
        &key.namespace,
        &key.id,
        entry.version,
        suite,
        &ctx.info,
    )?;
    let envelope = HpkeEnvelope::seal(suite, keys.public_key(), &info, &ctx.aad, plaintext)?;
    let frame = encode_frame(purpose, entry.version, &envelope.to_bytes());
    Ok(CiphertextBlob::new(frame))
}

/// Open a `CGKC` frame made by [`seal`] with the same `purpose`.
///
/// The key version comes from the frame. Errors:
/// - frame/envelope decoding, purpose mismatch, `key.version` set and not
///   equal to the frame's version, unknown version, suite mismatch, wrong
///   `info`/`aad`, tampering → **all** `AuthenticationFailed`;
/// - unknown key (no version exists at all) → `NotFound`;
/// - version disabled → `Conflict`; non-HPKE key → `Unsupported`.
///
/// The recovered plaintext goes straight into `SecretBytes::from_vec`.
pub(crate) fn open(
    store: &KeyStore,
    purpose: Purpose,
    key: &KeyRef,
    ciphertext: &[u8],
    ctx: &CryptoContext,
) -> Result<SecretBytes, CryptoServiceError> {
    // Existence check first: distinguishes "key never existed" (NotFound)
    // from "this specific version does not exist" (AuthenticationFailed).
    store.algorithm_of(key)?;

    let frame = decode_frame(ciphertext).map_err(|_| CryptoServiceError::AuthenticationFailed)?;
    if frame.purpose != purpose {
        return Err(CryptoServiceError::AuthenticationFailed);
    }
    if let Some(v) = key.version {
        if v != frame.key_version {
            return Err(CryptoServiceError::AuthenticationFailed);
        }
    }

    let entry = match store.resolve_version(&key.namespace, &key.id, frame.key_version) {
        Ok(entry) => entry,
        Err(CryptoServiceError::NotFound) => return Err(CryptoServiceError::AuthenticationFailed),
        Err(err) => return Err(err),
    };
    let material = match entry.usable() {
        Ok(material) => material,
        Err(CryptoServiceError::NotFound) => return Err(CryptoServiceError::AuthenticationFailed),
        Err(err) => return Err(err),
    };
    let (suite, keys) = match material {
        KeyMaterial::Hpke { suite, keys } => (*suite, keys),
        #[allow(unreachable_patterns)]
        _ => return Err(CryptoServiceError::Unsupported),
    };

    let envelope = HpkeEnvelope::from_bytes(frame.envelope)
        .map_err(|_| CryptoServiceError::AuthenticationFailed)?;
    if envelope.suite() != suite {
        return Err(CryptoServiceError::AuthenticationFailed);
    }

    let info = bind_info(
        purpose,
        &key.namespace,
        &key.id,
        frame.key_version,
        suite,
        &ctx.info,
    )
    .map_err(|_| CryptoServiceError::AuthenticationFailed)?;

    let plaintext = envelope
        .open(keys.private_key(), &info, &ctx.aad)
        .map_err(|_| CryptoServiceError::AuthenticationFailed)?;
    Ok(SecretBytes::from_vec(plaintext))
}

/// Unwrap under `from` and wrap under `to` without the key material leaving
/// this function; the intermediate secret is dropped (zeroized) before
/// returning, on success and on error.
pub(crate) fn rewrap(
    store: &KeyStore,
    from: &KeyRef,
    from_ctx: &CryptoContext,
    to: &KeyRef,
    to_ctx: &CryptoContext,
    wrapped: &[u8],
) -> Result<CiphertextBlob, CryptoServiceError> {
    let secret = open(store, Purpose::Wrap, from, wrapped, from_ctx)?;
    seal(store, Purpose::Wrap, to, secret.as_ref(), to_ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyAlgorithm, KeyId, KeyNamespace};

    fn store_with_hpke_key(suite: Suite) -> (KeyStore, KeyRef) {
        let mut store = KeyStore::new();
        let namespace = KeyNamespace::new("app").unwrap();
        let id = KeyId::new("key1").unwrap();
        let material = generate_hpke(suite).unwrap();
        let algorithm = KeyAlgorithm::Hpke { suite };
        let key_ref = store
            .insert_new(namespace, id, algorithm, material)
            .unwrap();
        (store, key_ref)
    }

    fn default_suite() -> Suite {
        crypt_guard_core::pq_hpke::DEFAULT_SUITE
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let (store, key_ref) = store_with_hpke_key(default_suite());
        let ctx = CryptoContext {
            info: Box::from(&b"info"[..]),
            aad: Box::from(&b"aad"[..]),
        };
        let blob = seal(&store, Purpose::Encrypt, &key_ref, b"hello", &ctx).unwrap();
        let plaintext = open(&store, Purpose::Encrypt, &key_ref, blob.as_bytes(), &ctx).unwrap();
        assert_eq!(plaintext.as_ref(), b"hello");
    }

    #[test]
    fn wrong_aad_is_authentication_failed() {
        let (store, key_ref) = store_with_hpke_key(default_suite());
        let seal_ctx = CryptoContext {
            info: Box::from(&b"info"[..]),
            aad: Box::from(&b"aad"[..]),
        };
        let open_ctx = CryptoContext {
            info: Box::from(&b"info"[..]),
            aad: Box::from(&b"different"[..]),
        };
        let blob = seal(&store, Purpose::Encrypt, &key_ref, b"hello", &seal_ctx).unwrap();
        let err = open(
            &store,
            Purpose::Encrypt,
            &key_ref,
            blob.as_bytes(),
            &open_ctx,
        )
        .unwrap_err();
        assert_eq!(err, CryptoServiceError::AuthenticationFailed);
    }

    #[test]
    fn encrypt_ciphertext_cannot_be_opened_as_wrap() {
        let (store, key_ref) = store_with_hpke_key(default_suite());
        let ctx = CryptoContext {
            info: Box::from(&b"info"[..]),
            aad: Box::from(&b"aad"[..]),
        };
        let blob = seal(&store, Purpose::Encrypt, &key_ref, b"hello", &ctx).unwrap();
        let err = open(&store, Purpose::Wrap, &key_ref, blob.as_bytes(), &ctx).unwrap_err();
        assert_eq!(err, CryptoServiceError::AuthenticationFailed);
    }
}
