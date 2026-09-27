//! ML-DSA operations of the in-memory provider.

use crypt_guard_core::kem::backend::OsRng;
use crypt_guard_core::sign::algorithm::SignAlgorithm;
use crypt_guard_core::sign::ml_dsa::{
    MlDsa44Impl, MlDsa65Impl, MlDsa87Impl, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey,
};

use crate::{
    blob::{PublicBlob, SignatureBlob},
    error::CryptoServiceError,
    key::SignatureAlgorithm,
    op::VerificationResult,
};

use super::store::KeyMaterial;

/// An ML-DSA key pair. The signing key zeroizes on drop. Not `Clone`.
pub(crate) struct MlDsaKeys {
    /// Parameter set.
    pub(crate) algorithm: SignatureAlgorithm,
    /// Secret signing key (32-byte seed).
    pub(crate) signing: MlDsaSigningKey,
    /// Public verifying key.
    pub(crate) verifying: MlDsaVerifyingKey,
}

impl core::fmt::Debug for MlDsaKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsaKeys")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Generate a signing key pair for `algorithm` using the given RNG-backed
/// implementation.
fn keypair_for(
    algorithm: SignatureAlgorithm,
) -> Result<(MlDsaSigningKey, MlDsaVerifyingKey), CryptoServiceError> {
    let mut rng = OsRng;
    match algorithm {
        SignatureAlgorithm::MlDsa44 => {
            MlDsa44Impl::keypair(&mut rng).map_err(CryptoServiceError::from)
        }
        SignatureAlgorithm::MlDsa65 => {
            MlDsa65Impl::keypair(&mut rng).map_err(CryptoServiceError::from)
        }
        SignatureAlgorithm::MlDsa87 => {
            MlDsa87Impl::keypair(&mut rng).map_err(CryptoServiceError::from)
        }
    }
}

/// Sign `message` with `sk` for the given parameter set.
fn sign_for(
    algorithm: SignatureAlgorithm,
    sk: &MlDsaSigningKey,
    message: &[u8],
) -> Result<MlDsaSignature, CryptoServiceError> {
    match algorithm {
        SignatureAlgorithm::MlDsa44 => {
            MlDsa44Impl::sign(sk, message).map_err(CryptoServiceError::from)
        }
        SignatureAlgorithm::MlDsa65 => {
            MlDsa65Impl::sign(sk, message).map_err(CryptoServiceError::from)
        }
        SignatureAlgorithm::MlDsa87 => {
            MlDsa87Impl::sign(sk, message).map_err(CryptoServiceError::from)
        }
    }
}

/// Verify `sig` over `message` with `vk` for the given parameter set.
fn verify_for(
    algorithm: SignatureAlgorithm,
    vk: &MlDsaVerifyingKey,
    message: &[u8],
    sig: &MlDsaSignature,
) -> Result<(), ()> {
    let result = match algorithm {
        SignatureAlgorithm::MlDsa44 => MlDsa44Impl::verify(vk, message, sig),
        SignatureAlgorithm::MlDsa65 => MlDsa65Impl::verify(vk, message, sig),
        SignatureAlgorithm::MlDsa87 => MlDsa87Impl::verify(vk, message, sig),
    };
    result.map_err(|_| ())
}

/// Generate a key pair for `algorithm` using `kem::backend::OsRng`.
/// Errors: unknown parameter set → `Unsupported`; core failure → `Internal`.
pub(crate) fn generate_ml_dsa(
    algorithm: SignatureAlgorithm,
) -> Result<KeyMaterial, CryptoServiceError> {
    let (signing, verifying) = keypair_for(algorithm)?;
    Ok(KeyMaterial::MlDsa(MlDsaKeys {
        algorithm,
        signing,
        verifying,
    }))
}

/// Encoded verifying key.
pub(crate) fn public_key(keys: &MlDsaKeys) -> PublicBlob {
    PublicBlob::new(keys.verifying.as_bytes().to_vec())
}

/// Sign `message`. Errors: core failure → `Internal`.
pub(crate) fn sign(keys: &MlDsaKeys, message: &[u8]) -> Result<SignatureBlob, CryptoServiceError> {
    let sig = sign_for(keys.algorithm, &keys.signing, message)?;
    Ok(SignatureBlob::new(sig.as_ref().to_vec()))
}

/// Verify `signature` over `message`. An invalid or malformed signature is
/// `Ok(VerificationResult::Invalid)`, not an error.
pub(crate) fn verify(
    keys: &MlDsaKeys,
    message: &[u8],
    signature: &[u8],
) -> Result<VerificationResult, CryptoServiceError> {
    let sig = MlDsaSignature::from_bytes(signature.to_vec());
    match verify_for(keys.algorithm, &keys.verifying, message, &sig) {
        Ok(()) => Ok(VerificationResult::Valid),
        Err(()) => Ok(VerificationResult::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_for(algorithm: SignatureAlgorithm) -> MlDsaKeys {
        let material = generate_ml_dsa(algorithm).expect("keypair generation");
        let KeyMaterial::MlDsa(keys) = material else {
            panic!("expected MlDsa key material");
        };
        keys
    }

    #[test]
    fn sign_and_verify_roundtrip_all_algorithms() {
        for algorithm in [
            SignatureAlgorithm::MlDsa44,
            SignatureAlgorithm::MlDsa65,
            SignatureAlgorithm::MlDsa87,
        ] {
            let keys = keys_for(algorithm);
            let message = b"the message to sign";
            let sig = sign(&keys, message).unwrap();

            let result = verify(&keys, message, sig.as_bytes()).unwrap();
            assert_eq!(result, VerificationResult::Valid);
        }
    }

    #[test]
    fn tampered_message_is_invalid() {
        let keys = keys_for(SignatureAlgorithm::MlDsa65);
        let message = b"original message";
        let sig = sign(&keys, message).unwrap();

        let result = verify(&keys, b"different message", sig.as_bytes()).unwrap();
        assert_eq!(result, VerificationResult::Invalid);
    }

    #[test]
    fn garbage_signature_is_invalid_not_error() {
        let keys = keys_for(SignatureAlgorithm::MlDsa87);
        let message = b"some message";
        let garbage = vec![0xAAu8; 16];

        let result = verify(&keys, message, &garbage).unwrap();
        assert_eq!(result, VerificationResult::Invalid);
    }

    #[test]
    fn debug_output_hides_key_material() {
        let keys = keys_for(SignatureAlgorithm::MlDsa44);
        let debug = format!("{:?}", keys);
        assert!(debug.contains("MlDsaKeys"));
        assert!(debug.contains("MlDsa44"));
        // No hex dump of key material: the debug string stays short.
        assert!(debug.len() < 64);
    }
}
