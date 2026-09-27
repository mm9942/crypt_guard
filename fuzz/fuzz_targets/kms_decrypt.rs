//! Feeding arbitrary ciphertext to the in-memory KMS provider must yield an
//! error, never a panic and never a plaintext.
#![no_main]

use crypt_guard_service::{
    pq_hpke::DEFAULT_SUITE, CiphertextBlob, CryptoContext, CryptoOperation, CryptoProvider,
    CryptoRequest, Decrypt, GenerateKey, InMemoryProvider, KeyAlgorithm, KeyId, KeyNamespace,
    KeyRef, RequestId, UnwrapKey,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Mutex;

static PROVIDER: Mutex<Option<InMemoryProvider>> = Mutex::new(None);

fn key() -> KeyRef {
    KeyRef::latest(
        KeyNamespace::new("fuzz").unwrap(),
        KeyId::new("key").unwrap(),
    )
}

fuzz_target!(|data: &[u8]| {
    let mut guard = PROVIDER.lock().unwrap();
    let provider = guard.get_or_insert_with(|| {
        let mut provider = InMemoryProvider::new();
        let key = key();
        provider
            .execute(CryptoRequest::new(
                RequestId(0),
                CryptoOperation::Generate(GenerateKey {
                    namespace: key.namespace,
                    id: key.id,
                    algorithm: KeyAlgorithm::Hpke {
                        suite: DEFAULT_SUITE,
                    },
                }),
            ))
            .expect("key generation");
        provider
    });

    let decrypt = CryptoOperation::Decrypt(Decrypt {
        key: key(),
        ciphertext: CiphertextBlob::new(data),
        context: CryptoContext::default(),
    });
    assert!(provider
        .execute(CryptoRequest::new(RequestId(1), decrypt))
        .is_err());

    let unwrap = CryptoOperation::UnwrapKey(UnwrapKey {
        key: key(),
        wrapped: CiphertextBlob::new(data),
        context: CryptoContext::default(),
    });
    assert!(provider
        .execute(CryptoRequest::new(RequestId(2), unwrap))
        .is_err());
});
