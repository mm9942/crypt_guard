//! # CryptGuard v2
//!
//! [![Crates.io][crates-badge]][crates-url]
//! [![MIT licensed][mit-badge]][mit-url]
//! [![Documentation][doc-badge]][doc-url]
//! [![Hashnode Blog][blog-badge]][blog-url]
//! [![GitHub Library][lib-badge]][lib-link]
//!
//! [blog-badge]: https://img.shields.io/badge/blog-hashnode-lightblue.svg?style=for-the-badge
//! [blog-url]: https://blog.mm29942.com/
//! [crates-badge]: https://img.shields.io/badge/crates.io-v2-blue.svg?style=for-the-badge
//! [crates-url]: https://crates.io/crates/crypt_guard
//! [mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
//! [mit-url]: https://github.com/mm9942/crypt_guard/blob/main/LICENSE
//! [doc-badge]: https://img.shields.io/badge/docs-v2-yellow.svg?style=for-the-badge
//! [doc-url]: https://docs.rs/crypt_guard/
//! [lib-badge]: https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge
//! [lib-link]: https://github.com/mm9942/crypt_guard
//!
//! ## Introduction
//!
//! Current release status: `2.0.4`. The safe-default Phase 4 upgrade is
//! implemented, externally consumer-tested, and test-green. This release also
//! adds an opt-in, vector-gated API for two exact active-draft ML-KEM HPKE
//! profiles; it does not claim that the draft is an RFC standard.
//!
//! CryptGuard is a post-quantum sealing library built on the NIST FIPS 203/204/205
//! final standards. The primary flow is:
//!
//! ```text
//! ML-KEM (FIPS 203) -> HKDF -> CGv2 authenticated envelope
//! ```
//!
//! The v2 line replaces the old pqcrypto Kyber / Falcon / Dilithium path with
//! FIPS-final ML-KEM, ML-DSA, and SLH-DSA as the default. The old path is still
//! available behind `--features legacy-pqclean` for reading data created with v1.x.
//!
//! ## Key Features
//!
//! - **ML-KEM-512/768/1024** (FIPS 203) for key encapsulation.
//! - **HKDF-SHA-256/512** key schedule with domain-separated labels
//!   following the NIST SP 800-227 direction: the shared secret is never used raw
//!   as a cipher key.
//! - **CGv2 Authenticated Envelope**: one self-describing blob
//!   `{ header, kem_ciphertext, nonce, ciphertext }` — nonce is internal,
//!   callers never juggle it separately.
//! - **XChaCha20-Poly1305** and **AES-256-GCM-SIV** authenticated AEAD.
//! - **ML-DSA-44/65/87** (FIPS 204) and **SLH-DSA** (FIPS 205) digital signatures.
//! - **Compile-enforced content-axis typestate**: calling `encrypt_file` on a
//!   `Message` instance is a compile error (E0599).
//! - **Legacy Kyber / Falcon / Dilithium** kept behind `legacy-pqclean` feature
//!   so v1.x data remains decryptable.
//! - **Experimental draft HPKE**, behind `hpke-pq-draft-05`, at
//!   `hpke_pq::draft_ietf_hpke_pq_05`. This is a pinned
//!   `draft-ietf-hpke-pq-05` mapping, not an RFC-standardized PQ HPKE profile.
//!
//! ## Safe Default: `Encryptor` / `Decryptor`
//!
//! The primary entry point is the staged-builder pair. The safe flow has no
//! manual nonce handling and no tuple unpacking; current builders still accept
//! key bytes while the lower `kem` module keeps typed key roles.
//!
//! ```rust
//! use crypt_guard::{Encryptor, Decryptor};
//! use crypt_guard::{MlKem768, XChaCha20Poly1305};
//! # #[cfg(feature = "ml-kem-backend")] {
//! use crypt_guard::kem::{KemBackend, ml_kem::MlKem768Impl};
//! use crypt_guard::kem::backend::OsRng;
//!
//! # fn main() -> Result<(), crypt_guard::error::CryptError> {
//! let mut rng = OsRng;
//! let (public_key, secret_key) = MlKem768Impl::keypair(&mut rng)?;
//!
//! // Seal: ML-KEM encapsulate -> HKDF -> XChaCha20-Poly1305
//! let envelope = Encryptor::<MlKem768, XChaCha20Poly1305>::new()
//!     .recipient(public_key.as_ref().to_vec())
//!     .plaintext(b"hello post-quantum world")
//!     .seal()?;
//!
//! // Open: ML-KEM decapsulate -> HKDF -> AEAD verify + decrypt
//! let plaintext = Decryptor::<MlKem768, XChaCha20Poly1305>::new()
//!     .secret_key(secret_key.as_ref().to_vec())
//!     .open(&envelope)?;
//!
//! assert_eq!(plaintext, b"hello post-quantum world");
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## Protocol: CGv2 authenticated envelope (not RFC 9180 HPKE)
//!
//! The current envelope is a crate-specific CGv2 construction. Although it uses
//! a KEM, HKDF, and AEAD, it is **not** [RFC 9180 HPKE]: it does not implement
//! RFC 9180's KEM interface, labeled key schedule, AEAD nonce sequencing, or
//! wire format, and is not interoperable with RFC 9180 implementations. The
//! sender output is a single blob, not a `(ciphertext, kem_secret)` tuple:
//!
//! ```text
//! Sender:
//!   (kem_ct, shared_secret) = ML-KEM.Encapsulate(recipient_pk)
//!   session_key             = HKDF(ikm=shared_secret, salt=kem_ct,
//!                                  info="crypt_guard:v2:aead:<alg>")
//!   ciphertext              = AEAD.Seal(session_key, nonce, aad, plaintext)
//!   envelope                = { header, kem_ct, nonce, ciphertext }
//!
//! Receiver:
//!   shared_secret = ML-KEM.Decapsulate(kem_ct, recipient_sk)
//!   session_key   = HKDF(same params)
//!   plaintext     = AEAD.Open(session_key, nonce, aad, ciphertext)
//! ```
//!
//! The shared secret is zeroized immediately after key derivation
//! (NIST SP 800-227). The `header` carries `kem_id`, `kdf_id`, `aead_id`
//! so the envelope is self-describing and forwards-compatible.
//!
//! ## Typestate Design: `Kyber<Process, Size, Content, Algorithm>`
//!
//! The underlying type encodes four axes at the type level. Mismatching axes
//! (wrong process direction, wrong content kind, wrong cipher) is a **compile
//! error**, not a runtime panic:
//!
//! | Axis | Variants |
//! |---|---|
//! | Process | `Encryption`, `Decryption` |
//! | Size | `MlKem512`, `MlKem768`, `MlKem1024` |
//! | Content | `Data`, `Message`, `Files` |
//! | Algorithm | `XChaCha20Poly1305`, `AesGcmSiv`, … |
//!
//! The `Encryptor`/`Decryptor` builders expose the `Data` content path. The
//! full `Kyber<P,S,C,A>` API is available for direct use when you need
//! `Message` or `Files` content handling.
//!
//! ## Feature Flags
//!
//! | Flag | Default | Description |
//! |---|---|---|
//! | `ml-kem-backend` | yes | ML-KEM-512/768/1024 (FIPS 203) |
//! | `ml-dsa-backend` | yes | ML-DSA-44/65/87 (FIPS 204) |
//! | `sign-slhdsa` | no | SLH-DSA (FIPS 205) |
//! | `aes-ctr` | no | AES-CTR stream cipher |
//! | `aes-xts` | no | AES-XTS disk encryption |
//! | `archive` | no | tar/xz/gz archive helpers |
//! | `legacy-pqclean` | no | Legacy Kyber/Falcon/Dilithium + old tuple API |
//!
//! ## Legacy Compatibility
//!
//! Data encrypted with crypt_guard v1.x can still be decrypted by enabling
//! the `legacy-pqclean` feature. The old `Kyber<Encryption, Kyber1024, Message, AES>`
//! types, the `encryption!` / `decryption!` macros, the `kyber_keypair!` macro,
//! and the tuple-returning `encrypt_msg` / `decrypt_msg` functions are all
//! preserved under the `legacy` module.
//!
//! ```rust,ignore
//! // Legacy path — requires --features legacy-pqclean
//! use crypt_guard::{*, error::*};
//!
//! let (public_key, secret_key) = kyber_keypair!(1024);
//! let (ciphertext, kyber_secret) = encryption!(
//!     public_key.to_owned(), 1024,
//!     b"hello".to_vec(), "passphrase", AES
//! )?;
//! let plaintext = decryption!(
//!     secret_key.to_owned(), 1024,
//!     ciphertext, "passphrase", kyber_secret, AES
//! )?;
//! ```
//!
//! ## References
//!
//! - [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
//! - [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
//! - [FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
//! - [NIST SP 800-227 — Recommendations for Key-Encapsulation Mechanisms](https://csrc.nist.gov/pubs/sp/800/227/final)
//! - [RFC 9180 — Hybrid Public Key Encryption (HPKE)](https://www.rfc-editor.org/rfc/rfc9180.html)

pub use crypt_guard_proc::*;

/// Shared zero-sized-type axis markers (Encryption/Decryption, Files/Message/Data, cipher markers).
/// Re-exported here so `crate::*` continues to expose them.
pub mod markers;

/// Core functionalitys for control of Kyber keys as well as encryption and decryption
mod core;
/// Cryptographic related functionalitys, enums structs and modules
pub mod cryptography;
/// Error types
pub mod error;
/// File and Key related functionalitys, enums structs and modules
pub mod key_control;
/// Logging related functionalitys
pub mod log;

pub mod utils;

// ── Phase 2: New FIPS primitive modules ────────────────────────────────────
/// Safe default public API over the Phase 3 ML-KEM + HKDF + AEAD envelope path.
pub mod api;
/// Builder-style API for encryption/decryption, keygen, and signature flows
pub mod builder;
/// RFC 9180 HPKE suite identifiers and labeled HKDF primitives.
pub mod hpke;
/// Experimental, vector-gated `draft-ietf-hpke-pq-05` Base-mode HPKE API.
///
/// This feature-gated module is intentionally separate from CGv2 and is not
/// an RFC-standardized post-quantum HPKE profile.  Its only public surface is
/// `hpke_pq::draft_ietf_hpke_pq_05`, whose revision-specific name is part of
/// the protocol identity.
#[cfg(feature = "hpke-pq-draft-05")]
pub mod hpke_pq;
/// HKDF-SHA256/512 key schedule with domain separation.
pub mod kdf;
/// ML-KEM backend trait and ML-KEM-512/768/1024 implementations (FIPS 203).
pub mod kem;
/// CGv2 authenticated envelope protocol.
pub mod protocol;
/// SignAlgorithm trait and ML-DSA/SLH-DSA implementations (FIPS 204/205).
pub mod sign;
/// Application-layer, explicitly versioned signatures over HPKE transport bindings.
///
/// This is not RFC 9180 Auth mode. See [`signed_hpke`] for the trust-boundary
/// and verification contract.
pub mod signed_hpke;

/// Legacy pqcrypto-backed KEM + signature path (Kyber/Falcon/Dilithium).
/// Only compiled when the `legacy-pqclean` feature is active.
#[cfg(feature = "legacy-pqclean")]
pub mod legacy;

#[cfg(test)]
mod tests;

#[cfg(feature = "archive")]
pub use crate::utils::archive;
#[cfg(feature = "zip")]
pub use crate::utils::zip_manager;
pub use crate::{
    core::{
        hub::{
            DecryptData, DecryptFile, DecryptText, EncryptData, EncryptFile, EncryptText,
            MlKem1024, MlKem512, MlKem768,
        },
        kyber::*,
        *,
    },
    key_control::{file, *},
    log::*,
};

// Re-export the legacy kdf module when the feature is active so that
// existing call sites using `crypt_guard::kdf::Falcon1024` etc. keep working.
#[cfg(feature = "legacy-pqclean")]
pub use crate::core::kdf as legacy_kdf;
// Legacy CGv2 compatibility framing. These `hpke_`-prefixed re-exports are not
// RFC 9180 HPKE and retain their names only for source compatibility.
pub use api::{open as hpke_open, seal as hpke_seal};
pub use api::{
    AuthenticatedAead, Decryptor, DecryptorBuilder, Encryptor, EncryptorBuilder, MissingPlaintext,
    MissingRecipient, MissingSecretKey, WithPlaintext, WithRecipient, WithSecretKey,
};
pub use markers::{AesGcmSiv, XChaCha20Poly1305};
pub use protocol::Envelope;
use std::path::Path;
/// Function activating the log, it takes one arg: `&str` which represents the location of the logfile
pub fn activate_log<P: AsRef<Path>>(log_file: P) {
    // Initialize internal logger state and set up tracing to write to the same file
    crate::log::initialize_logger(log_file.as_ref().to_path_buf());
}

/// Macro for signing and encrypting data, a 1024 falcon secret key is required for signing
#[cfg(feature = "legacy-pqclean")]
#[macro_export]
macro_rules! encrypt_sign {
    ($key:expr, $sign:expr, $content:expr, $passphrase:expr) => {{
        let mut key = $key;
        let mut sign = $sign;
        let mut content = $content;
        let passphrase = $passphrase;
        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            let signer = Signature::<Falcon1024, Message>::new();
            let signed_message = signer
                .signature(content.to_owned(), sign.to_owned())
                .map_err($crate::error::CryptError::from)?;
            encryptor.encrypt_data(signed_message, &passphrase)
        })();
        key.zeroize();
        sign.zeroize();
        content.zeroize();
        result
    }};
}

/// Macro for decrypting and opening data, a 1024 falcon public key is required
#[cfg(feature = "legacy-pqclean")]
#[macro_export]
macro_rules! decrypt_open {
    ($key:expr, $sign:expr, $content:expr, $passphrase:expr, $cipher:expr) => {{
        let mut key = $key;
        let mut sign = $sign;
        let mut content = $content;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let out = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            let data =
                decryptor.decrypt_data(content.to_owned(), &passphrase, cipher.to_owned())?;
            let signer = Signature::<Falcon1024, Message>::new();
            signer
                .open(data, sign.to_owned())
                .map_err($crate::error::CryptError::from)
        })()
        .expect("decrypt_open failed");

        key.zeroize();
        sign.zeroize();
        content.zeroize();
        cipher.zeroize();
        out
    }};
}

/// Macro to archive a directory or file.
#[macro_export]
macro_rules! archive {
    ($source_path:expr, $delete_dir:expr) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        let source = $source_path.to_path_buf();
        let archive_operation = ArchiveOperation::Archive;
        let archive_instance = Archive::new(source, archive_operation);
        let _ = archive_instance.execute($delete_dir);
    }};
}

/// Macro to extract a `.tar.xz` archive.
#[macro_export]
macro_rules! extract {
    ($archive_path:expr, $delete_archive:expr) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        let archive = $archive_path.to_path_buf();
        let archive_operation = ArchiveOperation::Unarchive;
        let extract_instance = Archive::new(archive, archive_operation);
        let _ = extract_instance.execute($delete_archive);
    }};
}

/// Macro for archiving and extracting directories or files.
#[macro_export]
macro_rules! archive_util {
    // Variant for Archiving
    ($path:expr, $delete_dir:expr, Archive) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        // Convert the provided path to a PathBuf
        let source = $path.to_path_buf();
        // Specify the archive operation
        let archive_operation = ArchiveOperation::Archive;
        // Create a new Archive instance
        let archive_instance = Archive::new(source, archive_operation);
        // Execute the archiving process with the specified delete flag
        let _ = archive_instance.execute($delete_dir);
    }};

    // Variant for Extracting
    ($archive_path:expr, $delete_archive:expr, Extract) => {{
        use $crate::archive::{Archive, ArchiveOperation};
        // Convert the provided archive path to a PathBuf
        let archive = $archive_path.to_path_buf();
        // Specify the extraction operation
        let archive_operation = ArchiveOperation::Unarchive;
        // Create a new Archive instance
        let extract_instance = Archive::new(archive, archive_operation);
        // Execute the extraction process with the specified delete flag
        let _ = extract_instance.execute($delete_archive);
    }};
}

/// Macro for kyber keypair generation
#[cfg(feature = "legacy-pqclean")]
#[macro_export]
macro_rules! kyber_keypair {
    ($size:expr) => {{
        match $size {
            1024 => KeyControKyber1024::keypair().expect("Failed to generate keypair"),
            768 => KeyControKyber768::keypair().expect("Failed to generate keypair"),
            512 => KeyControKyber512::keypair().expect("Failed to generate keypair"),
            _ => panic!("Wrong key size!"),
        }
    }};
}

/// Macro for falcon keypair generation
#[cfg(feature = "legacy-pqclean")]
#[macro_export]
macro_rules! falcon_keypair {
    ($size:expr) => {{
        match $size {
            1024 => Falcon1024::keypair().expect("Failed to generate Falcon keypair"),
            512 => Falcon512::keypair().expect("Failed to generate Falcon keypair"),
            _ => panic!("Wrong key size!"),
        }
    }};
}

/// Macro for dilithium keypair generation
#[cfg(feature = "legacy-pqclean")]
#[macro_export]
macro_rules! dilithium_keypair {
    ($version:expr) => {{
        match $version {
            5 => Dilithium5::keypair().expect("Failed to generate Dilithium keypair"),
            3 => Dilithium3::keypair().expect("Failed to generate Dilithium keypair"),
            2 => Dilithium2::keypair().expect("Failed to generate Dilithium keypair"),
            _ => panic!("Wrong key size!"),
        }
    }};
}

#[macro_export]
macro_rules! encryption {
    // AES
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // AES_XTS
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, AesXts>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, AesXts>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, AesXts>::new(key.to_owned(), None)?;
            encryptor.encrypt_data(data.to_owned(), &passphrase)
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};

    // AES_CBC
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // AES_GCM_SIV
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, AesGcmSiv>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, AesGcmSiv>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, AesGcmSiv>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};

    // AES_CTR
    ($key:expr, 1024, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, AesCtr>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, AesCtr>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, AesCtr>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, $crate::error::CryptError>((encrypt_message, cipher, nonce.to_string()))
        };
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // XChaCha20Poly1305
    ($key:expr, 1024, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, XChaCha20Poly1305>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, XChaCha20Poly1305>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, XChaCha20Poly1305>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_data(data.to_owned(), &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
}

#[macro_export]
macro_rules! decryption {
    // AES
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AesXts>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_XTS
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor =
                Kyber::<Decryption, Kyber1024, Data, AesXts>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES_XTS) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AesXts>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_CBC
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, AES_CBC) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_GCM_SIV
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AesGcmSiv>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AesGcmSiv>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_GCM_SIV) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AesGcmSiv>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // AES_CTR
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AesCtr>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor =
                Kyber::<Decryption, Kyber768, Data, AesCtr>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, AES_CTR) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let nonce = $nonce;

        let result = (|| {
            let decryptor =
                Kyber::<Decryption, Kyber512, Data, AesCtr>::new(key.to_owned(), nonce.to_owned())?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};

    // XChaCha20
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};

    // XChaCha20Poly1305
    ($key:expr, 1024, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20Poly1305>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20Poly1305>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 512, $data:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20Poly1305) => {{
        let mut key = $key;
        let mut data = $data;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20Poly1305>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_data(data.to_owned(), &passphrase, cipher.to_owned())
        })();
        key.zeroize();
        data.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
}

/// Macro for encryption of a file, taking a Kyber decryption instance, a `PathBuf` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! encrypt_file {
    // AES
    ($key:expr, 1024, $path:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_file($path, &passphrase)
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_file($path, &passphrase)
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            encryptor.encrypt_file($path, &passphrase)
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $path:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber1024, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_file($path, &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber768, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_file($path, &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase = $passphrase;

        let result = (|| {
            let mut encryptor =
                Kyber::<Encryption, Kyber512, Data, XChaCha20>::new(key.to_owned(), None)?;
            let (encrypt_message, cipher) = encryptor.encrypt_file($path, &passphrase)?;
            let nonce = encryptor.get_nonce()?;
            Ok::<_, CryptError>((encrypt_message, cipher, nonce.to_string()))
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        result
    }};
}

/// Macro for encryption of a file, taking a Kyber decryption instance, a `PathBuf` as well as a passphrase and ciphertext as arguments
#[macro_export]
macro_rules! decrypt_file {
    // AES
    ($key:expr, 1024, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, $cipher:expr, AES) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, AES>::new(key.to_owned(), None)?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        result
    }};
    // XChaCha20
    ($key:expr, 1024, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber1024, Data, XChaCha20>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 768, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber768, Data, XChaCha20>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
    ($key:expr, 512, $path:expr, $passphrase:expr, $cipher:expr, $nonce:expr, XChaCha20) => {{
        let mut key = $key;
        let passphrase = $passphrase;
        let mut cipher = $cipher;
        let mut nonce = $nonce;

        let result = (|| {
            let decryptor = Kyber::<Decryption, Kyber512, Data, XChaCha20>::new(
                key.to_owned(),
                nonce.to_owned(),
            )?;
            decryptor.decrypt_file($path.to_owned(), &passphrase.to_owned(), cipher.to_owned())
        })();
        key.zeroize();
        passphrase.to_string().zeroize();
        cipher.zeroize();
        nonce.zeroize();
        result
    }};
}

#[macro_export]
macro_rules! signature {
    // Falcon
    // 1024
    (Falcon, $key:expr, 1024, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon1024, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon1024, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon512, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon512, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // Dilithium
    // 5
    (Dilithium, $key:expr, 5, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium5, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium5, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium3, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium3, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium2, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium2, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
}

#[macro_export]
macro_rules! verify {
    // Falcon
    // 1024
    (Falcon, $key:expr, 1024, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon1024, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon1024, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon512, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Falcon512, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // Dilithium
    // 5
    (Dilithium, $key:expr, 5, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium5, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;
        let result = (|| {
            let sign = Signature::<Dilithium5, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium3, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium3, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium2, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        })();
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = (|| {
            let sign = Signature::<Dilithium2, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        })();
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};
}
