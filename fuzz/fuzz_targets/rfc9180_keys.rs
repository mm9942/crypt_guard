//! RFC 9180 DHKEM key and encapsulation parsers must reject arbitrary input
//! without panicking, for every supported KEM including X448.
#![no_main]

use crypt_guard::hpke::{
    rfc9180::{EncapsulatedKey, PrivateKey, PublicKey},
    KemId,
};
use libfuzzer_sys::fuzz_target;

const KEMS: [KemId; 5] = [
    KemId::DhKemP256HkdfSha256,
    KemId::DhKemP384HkdfSha384,
    KemId::DhKemP521HkdfSha512,
    KemId::DhKemX25519HkdfSha256,
    KemId::DhKemX448HkdfSha512,
];

fuzz_target!(|data: &[u8]| {
    for kem in KEMS {
        let _ = PublicKey::from_bytes(kem, data);
        let _ = PrivateKey::from_bytes(kem, data);
        let _ = EncapsulatedKey::from_bytes(kem, data);
    }
});
