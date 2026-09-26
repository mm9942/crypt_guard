//! In-process reference provider.
//!
//! [`InMemoryProvider`] keeps every key in process memory: HPKE recipient
//! keys for encrypt/decrypt and wrap/unwrap, and (feature `ml-dsa`) ML-DSA
//! signing keys. Private key material never leaves the provider; destroyed
//! versions are zeroized immediately. Keys do not survive a restart, so this
//! provider is meant for tests, development and as the reference for
//! persistent providers.

mod binding;
mod hpke_ops;
#[cfg(feature = "ml-dsa")]
mod sign_ops;
mod store;

use crate::{
    blob::PublicBlob,
    error::CryptoServiceError,
    key::{KeyAlgorithm, KeyRef, KeyState},
    op::{CryptoOperation, CryptoRequest, CryptoResponse},
    provider::CryptoProvider,
};

use binding::Purpose;
use store::{KeyMaterial, KeyStore};

/// In-process key provider. Not `Clone`: it owns all key material.
#[derive(Debug, Default)]
pub struct InMemoryProvider {
    store: KeyStore,
}

impl InMemoryProvider {
    /// An empty provider.
    pub fn new() -> Self {
        Self {
            store: KeyStore::new(),
        }
    }
}

fn generate(algorithm: KeyAlgorithm) -> Result<KeyMaterial, CryptoServiceError> {
    match algorithm {
        KeyAlgorithm::Hpke { suite } => hpke_ops::generate_hpke(suite),
        #[cfg(feature = "ml-dsa")]
        KeyAlgorithm::Signature(algorithm) => sign_ops::generate_ml_dsa(algorithm),
        #[allow(unreachable_patterns)]
        _ => Err(CryptoServiceError::Unsupported),
    }
}

fn public_blob(material: &KeyMaterial) -> PublicBlob {
    match material {
        KeyMaterial::Hpke { keys, .. } => hpke_ops::public_key(keys),
        #[cfg(feature = "ml-dsa")]
        KeyMaterial::MlDsa(keys) => sign_ops::public_key(keys),
    }
}

#[cfg(feature = "ml-dsa")]
fn signing_keys(material: &KeyMaterial) -> Result<&sign_ops::MlDsaKeys, CryptoServiceError> {
    match material {
        KeyMaterial::MlDsa(keys) => Ok(keys),
        _ => Err(CryptoServiceError::Unsupported),
    }
}

impl InMemoryProvider {
    fn created(&self, key: KeyRef) -> Result<CryptoResponse, CryptoServiceError> {
        let public = self.store.resolve(&key)?.usable().map(public_blob)?;
        Ok(CryptoResponse::KeyCreated {
            key,
            public: Some(public),
        })
    }

    fn dispatch(&mut self, operation: CryptoOperation) -> Result<CryptoResponse, CryptoServiceError> {
        let store = &mut self.store;
        match operation {
            CryptoOperation::Generate(op) => {
                let material = generate(op.algorithm)?;
                let key = store.insert_new(op.namespace, op.id, op.algorithm, material)?;
                self.created(key)
            }
            CryptoOperation::Rotate(op) => {
                let material = generate(store.algorithm_of(&op.key)?)?;
                let key = store.rotate(&op.key, material)?;
                self.created(key)
            }
            CryptoOperation::Disable(op) => store
                .set_state(&op.key, KeyState::Disabled)
                .map(CryptoResponse::Metadata),
            CryptoOperation::Enable(op) => store
                .set_state(&op.key, KeyState::Enabled)
                .map(CryptoResponse::Metadata),
            CryptoOperation::Destroy(op) => store.destroy(&op.key).map(CryptoResponse::Metadata),
            CryptoOperation::Describe(op) => store.metadata(&op.key).map(CryptoResponse::Metadata),
            CryptoOperation::PublicKey(op) => {
                let public = store.resolve(&op.key)?.usable().map(public_blob)?;
                Ok(CryptoResponse::PublicKey(public))
            }
            CryptoOperation::Encrypt(op) => hpke_ops::seal(
                store,
                Purpose::Encrypt,
                &op.key,
                op.plaintext.as_ref(),
                &op.context,
            )
            .map(CryptoResponse::Ciphertext),
            CryptoOperation::Decrypt(op) => hpke_ops::open(
                store,
                Purpose::Encrypt,
                &op.key,
                op.ciphertext.as_bytes(),
                &op.context,
            )
            .map(CryptoResponse::Plaintext),
            CryptoOperation::WrapKey(op) => hpke_ops::seal(
                store,
                Purpose::Wrap,
                &op.key,
                op.material.as_ref(),
                &op.context,
            )
            .map(CryptoResponse::Ciphertext),
            CryptoOperation::UnwrapKey(op) => hpke_ops::open(
                store,
                Purpose::Wrap,
                &op.key,
                op.wrapped.as_bytes(),
                &op.context,
            )
            .map(CryptoResponse::Plaintext),
            CryptoOperation::RewrapKey(op) => hpke_ops::rewrap(
                store,
                &op.from,
                &op.from_context,
                &op.to,
                &op.to_context,
                op.wrapped.as_bytes(),
            )
            .map(CryptoResponse::Ciphertext),
            #[cfg(feature = "ml-dsa")]
            CryptoOperation::Sign(op) => {
                let keys = signing_keys(store.resolve(&op.key)?.usable()?)?;
                sign_ops::sign(keys, op.message.as_ref()).map(CryptoResponse::Signature)
            }
            #[cfg(feature = "ml-dsa")]
            CryptoOperation::Verify(op) => {
                let keys = signing_keys(store.resolve(&op.key)?.usable()?)?;
                sign_ops::verify(keys, op.message.as_bytes(), op.signature.as_bytes())
                    .map(CryptoResponse::Verification)
            }
            #[allow(unreachable_patterns)]
            _ => Err(CryptoServiceError::Unsupported),
        }
    }
}

impl CryptoProvider for InMemoryProvider {
    fn execute(&mut self, request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        // The request (and any secret input it owns) is dropped, and thereby
        // zeroized, when this call returns.
        self.dispatch(request.operation)
    }
}
