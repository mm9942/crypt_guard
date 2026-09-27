use crate::cryptography::hmac_sign::{Operation, Sign, SignType, SignatureData};
use crate::error::SigningErr;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Represents a cryptographic signing operation, including data, passphrase, operational status,
/// hash type, signature length, and verification status.
impl Sign {
    /// Constructs a new `Sign` instance with specified data, passphrase, operation status, and hash type.
    ///
    /// # Parameters
    /// - `data`: The data to be signed or verified.
    /// - `passphrase`: The passphrase used for HMAC generation.
    /// - `status`: The operation status (signing or verifying).
    /// - `hash_type`: The hash algorithm to use for signing.
    ///
    /// # Returns
    /// A new `Sign` instance.
    pub fn new(data: Vec<u8>, passphrase: Vec<u8>, status: Operation, hash_type: SignType) -> Self {
        let data = SignatureData {
            data,
            passphrase,
            hmac: Vec::new(),
            concat_data: Vec::new(),
        };
        match hash_type {
            SignType::Sha512 => Sign {
                data,
                status,
                hash_type,
                length: 64,
                veryfied: false,
            },
            SignType::Sha256 => Sign {
                data,
                status,
                hash_type,
                length: 32,
                veryfied: false,
            },
            _ => Sign {
                data,
                status,
                hash_type,
                length: 64,
                veryfied: false,
            },
        }
    }

    /// Performs the HMAC operation based on the operation status: generates HMAC for signing
    /// or verifies HMAC for verification.
    ///
    /// # Returns
    /// HMAC as a `Vec<u8>` for signing or the verified data for verification.
    ///
    /// # Hazard
    /// On `Operation::Verify`, a failed verification (bad HMAC, corrupted
    /// data, wrong passphrase) is silently swallowed via
    /// `unwrap_or_default()`, returning an empty `Vec<u8>` that is
    /// indistinguishable from a legitimate empty payload. Prefer
    /// [`Sign::try_hmac`], which reports verification failure as an `Err`.
    #[deprecated(
        note = "swallows HMAC verification failures into an empty Vec<u8>; use `try_hmac` to observe verification errors"
    )]
    pub fn hmac(&mut self) -> Vec<u8> {
        match &self.status {
            Operation::Sign => self.generate_hmac(),
            Operation::Verify => self.verify_hmac().unwrap_or_default(),
        }
    }

    /// Performs the HMAC operation based on the operation status, surfacing
    /// verification failures instead of swallowing them.
    ///
    /// # Returns
    /// `Ok(hmac_or_verified_data)` for signing or a successful verification;
    /// `Err(SigningErr::SignatureVerificationFailed)` if verification fails.
    pub fn try_hmac(&mut self) -> Result<Vec<u8>, SigningErr> {
        match &self.status {
            Operation::Sign => Ok(self.generate_hmac()),
            Operation::Verify => self
                .verify_hmac()
                .map_err(|_| SigningErr::SignatureVerificationFailed),
        }
    }

    /// Generates HMAC for the data using the specified hash type and passphrase.
    ///
    /// # Returns
    /// Concatenated original data and its HMAC as a `Vec<u8>`.
    pub fn generate_hmac(&self) -> Vec<u8> {
        let data = &self.data.data;
        match &self.hash_type {
            SignType::Sha512 => {
                let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.data.passphrase)
                    // cannot fail: HMAC accepts any key length
                    .expect("HMAC can take key of any size");
                mac.update(data);
                // `hmac` is an intermediate copy of the tag; it is immediately
                // folded into `concat_data`, so wipe the standalone copy once
                // it has served its purpose.
                let hmac: Zeroizing<Vec<u8>> = Zeroizing::new(mac.finalize().into_bytes().to_vec());
                let concat_data = [&self.data.data, hmac.as_slice()].concat();
                concat_data
            }
            SignType::Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.data.passphrase)
                    // cannot fail: HMAC accepts any key length
                    .expect("HMAC can take key of any size");
                mac.update(data);
                let hmac: Zeroizing<Vec<u8>> = Zeroizing::new(mac.finalize().into_bytes().to_vec());
                let concat_data = [&self.data.data, hmac.as_slice()].concat();
                concat_data
            }
            _ => vec![],
        }
    }

    /// Verifies HMAC using SHA-512.
    ///
    /// # Parameters
    /// - `data`: The data part of the message.
    /// - `hmac`: The HMAC to verify against.
    /// - `passphrase`: The passphrase used for HMAC generation.
    ///
    /// # Returns
    /// `true` if verification is successful, `false` otherwise.
    fn verify_hmac_sha512(data: &[u8], hmac: &[u8], passphrase: &[u8]) -> bool {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(passphrase)
            // cannot fail: HMAC accepts any key length
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.verify_slice(hmac).is_ok()
    }

    /// Verifies HMAC using SHA-256.
    ///
    /// # Parameters
    /// - `data`: The data part of the message.
    /// - `hmac`: The HMAC to verify against.
    /// - `passphrase`: The passphrase used for HMAC generation.
    ///
    /// # Returns
    /// `true` if verification is successful, `false` otherwise.
    fn verify_hmac_sha256(data: &[u8], hmac: &[u8], passphrase: &[u8]) -> bool {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(passphrase)
            // cannot fail: HMAC accepts any key length
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.verify_slice(hmac).is_ok()
    }

    /// Verifies HMAC based on the hash type. Splits the provided data into the original data
    /// and HMAC, then verifies the HMAC.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the original data if verification is successful, `Err(&'static str)` otherwise.
    pub fn verify_hmac(&self) -> Result<Vec<u8>, &'static str> {
        if self.data.data.len() < self.length {
            return Err("Data is too short for HMAC verification");
        }

        let (data, hmac) = self.data.data.split_at(self.data.data.len() - self.length);

        let verification_success = match &self.hash_type {
            SignType::Sha512 => Self::verify_hmac_sha512(data, hmac, &self.data.passphrase),
            SignType::Sha256 => Self::verify_hmac_sha256(data, hmac, &self.data.passphrase),
            _ => return Err("Unsupported HMAC hash type"),
        };

        if verification_success {
            // `data.to_owned()` is the verified plaintext being returned to
            // the caller, not a spare intermediate copy — there is nothing
            // extra here to zeroize. The caller is expected to fold it into
            // a self-zeroizing type (e.g. `SignatureData`) if it needs to be
            // wiped later.
            Ok(data.to_owned())
        } else {
            Err("HMAC verification failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_hmac_surfaces_verification_failure() {
        let signer = Sign::new(
            b"hello world".to_vec(),
            b"passphrase".to_vec(),
            Operation::Sign,
            SignType::Sha256,
        );
        let signed = signer.generate_hmac();

        let mut verifier = Sign::new(
            signed,
            b"wrong-passphrase".to_vec(),
            Operation::Verify,
            SignType::Sha256,
        );
        assert!(verifier.try_hmac().is_err());
    }

    #[test]
    fn try_hmac_returns_original_data_on_success() {
        let signer = Sign::new(
            b"hello world".to_vec(),
            b"passphrase".to_vec(),
            Operation::Sign,
            SignType::Sha256,
        );
        let signed = signer.generate_hmac();

        let mut verifier = Sign::new(
            signed,
            b"passphrase".to_vec(),
            Operation::Verify,
            SignType::Sha256,
        );
        assert_eq!(verifier.try_hmac().unwrap(), b"hello world".to_vec());
    }
}
