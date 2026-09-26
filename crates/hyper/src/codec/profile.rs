//! Stable names of key algorithms on the wire.
//!
//! | Name | Algorithm |
//! |------|-----------|
//! | `pq-hpke-default` | `KeyAlgorithm::Hpke { suite: pq_hpke::DEFAULT_SUITE }` |
//! | `ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87` | `KeyAlgorithm::Signature(MlDsa44/65/87)` |
//!
//! (WAVE1(codec) may add further explicit HPKE suites, one fixed name per
//! suite; never parse suite ids from free text.)

use crypt_guard_service::pq_hpke::DEFAULT_SUITE;
use crypt_guard_service::{KeyAlgorithm, SignatureAlgorithm};

/// Wire name of an algorithm, or `None` if it has no stable name.
pub fn name(algorithm: KeyAlgorithm) -> Option<&'static str> {
    match algorithm {
        KeyAlgorithm::Hpke { suite } => {
            if suite == DEFAULT_SUITE {
                Some("pq-hpke-default")
            } else {
                None
            }
        }
        KeyAlgorithm::Signature(sig) => match sig {
            SignatureAlgorithm::MlDsa44 => Some("ml-dsa-44"),
            SignatureAlgorithm::MlDsa65 => Some("ml-dsa-65"),
            SignatureAlgorithm::MlDsa87 => Some("ml-dsa-87"),
            _ => None,
        },
        _ => None,
    }
}

/// Algorithm for a wire name, or `None` if unknown.
pub fn parse(name: &str) -> Option<KeyAlgorithm> {
    Some(match name {
        "pq-hpke-default" => KeyAlgorithm::Hpke {
            suite: DEFAULT_SUITE,
        },
        "ml-dsa-44" => KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa44),
        "ml-dsa-65" => KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa65),
        "ml-dsa-87" => KeyAlgorithm::Signature(SignatureAlgorithm::MlDsa87),
        _ => return None,
    })
}
