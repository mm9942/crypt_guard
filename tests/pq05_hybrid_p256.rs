//! Draft-05 ML-KEM-768/P-256 concrete-hybrid capability contract.
#![cfg(feature = "hpke-pq-draft-05")]

use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05_full::{Aead, Capability, Kdf, Kem, Suite};

#[test]
fn concrete_hybrid_fails_closed_until_full_vectors_are_verified() {
    let suite = Suite::new(Kem::MlKem768P256, Kdf::HkdfSha256, Aead::ExportOnly);
    assert!(matches!(suite.capability(), Capability::Unavailable(_)));
}
