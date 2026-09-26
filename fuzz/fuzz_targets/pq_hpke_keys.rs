//! Key, seed and encapsulation parsers of every PQ HPKE KEM must reject
//! arbitrary input without panicking.
#![no_main]

use crypt_guard::pq_hpke::{
    derive_recipient_key_pair, Encapsulation, Kem, RecipientPrivateKey, RecipientPublicKey,
};
use libfuzzer_sys::fuzz_target;

const KEMS: [Kem; 6] = [
    Kem::MlKem512,
    Kem::MlKem768,
    Kem::MlKem1024,
    Kem::MlKem768P256,
    Kem::MlKem768X25519,
    Kem::MlKem1024P384,
];

fuzz_target!(|data: &[u8]| {
    for kem in KEMS {
        if let Ok(pk) = RecipientPublicKey::from_bytes(kem, data) {
            assert_eq!(pk.as_bytes(), data);
            assert_eq!(pk.kem(), kem);
        }
        if let Ok(enc) = Encapsulation::from_bytes(kem, data) {
            assert_eq!(enc.as_bytes(), data);
        }
        if let Ok(sk) = RecipientPrivateKey::from_seed_bytes(kem, data) {
            assert_eq!(sk.as_seed_bytes(), data);
            let _ = sk.public_key();
        }
        let _ = derive_recipient_key_pair(kem, data);
    }
});
