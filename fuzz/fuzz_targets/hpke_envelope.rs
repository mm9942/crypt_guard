//! `HpkeEnvelope::from_bytes` must never panic, and every envelope it accepts
//! must re-encode to the same bytes. Opening it with a key must fail cleanly.
#![no_main]

use crypt_guard::pq_hpke::{
    generate_recipient_key_pair, suite_from_ids, suite_ids, HpkeEnvelope, DEFAULT_SUITE,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = HpkeEnvelope::from_bytes(data) {
        assert_eq!(envelope.to_bytes(), data);
        assert_eq!(envelope.try_to_bytes().as_deref(), Ok(data));
        let (kem, kdf, aead) = suite_ids(envelope.suite());
        assert_eq!(suite_from_ids(kem, kdf, aead), Ok(envelope.suite()));

        static KEYS: OnceLock<crypt_guard::pq_hpke::RecipientKeyPair> = OnceLock::new();
        let keys = KEYS.get_or_init(|| {
            generate_recipient_key_pair(DEFAULT_SUITE.kem()).expect("key generation")
        });
        // A random envelope can never open under a fresh key.
        assert!(envelope
            .open_zeroizing(keys.private_key(), b"", b"")
            .is_err());
        let _ = HpkeEnvelope::open_bytes_zeroizing(data, keys.private_key(), b"", b"");
    }
});
