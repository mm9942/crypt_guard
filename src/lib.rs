//! # CryptGuard v3.0.1
//!
//! CryptGuard v3 makes [`pq_hpke`] the default post-quantum encryption
//! transport. Its default profile is ML-KEM-1024/P-384, SHAKE256, and
//! ChaCha20-Poly1305. The pure-Rust KEM adapter is revision-pinned to
//! `draft-ietf-hpke-pq-05`; it must not be represented as a final IANA PQ HPKE
//! registration.
//!
//! ## Default transport
//!
//! [`pq_hpke::HpkeEnvelope`] is the versioned crypt_guard `CGH3` container. It
//! stores a suite, encapsulation, and ciphertext. Applications always supply
//! HPKE setup `info` and per-message AEAD AAD separately when opening a record.
//!
//! ```rust
//! use crypt_guard::pq_hpke::{generate_recipient_key_pair, HpkeEnvelope, DEFAULT_SUITE};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem())?;
//! let envelope = HpkeEnvelope::seal(
//!     DEFAULT_SUITE, keys.public_key(), b"service=v1", b"record=1", b"payload",
//! )?;
//! let plaintext = envelope.open(keys.private_key(), b"service=v1", b"record=1")?;
//! assert_eq!(plaintext, b"payload");
//! # Ok(())
//! # }
//! ```
//!
//! Raw Base and PSK transport APIs return a separate HPKE encapsulation (`enc`)
//! and ciphertext for RFC-style transport. The three standardized AEADs are
//! accepted by these APIs. AES-256-GCM-SIV and XChaCha20-Poly1305 are explicit
//! crypt_guard private extensions and require [`pq_hpke::HpkeEnvelope`].
//!
//! ## CGv2 migration
//!
//! CGv2 is not a v3 default API or transport. Enable `cgv2-compat` only to read
//! and migrate existing CGv2 records, then remove it. Default v3 builds neither
//! expose the legacy builders nor silently accept CGv2 ciphertext.
//!
//! ## Other cryptography
//!
//! ML-DSA and optional SLH-DSA signing remain available. `legacy-pqclean`
//! retains the historical Kyber/Falcon/Dilithium path for compatibility work.
//!
//! ## References
//!
//! - [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
//! - [RFC 9180 — HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
//! - [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq-05/)

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
/// Legacy CGv2 public API, available only for explicit compatibility migrations.
#[cfg(feature = "cgv2-compat")]
pub mod api;
/// Builder-style API for encryption/decryption, keygen, and signature flows
pub mod builder;
/// RFC 9180 HPKE suite identifiers and labeled HKDF primitives.
pub mod hpke;
/// Revision-pinned, vector-gated `draft-ietf-hpke-pq-05` HPKE APIs.
///
/// This default module is intentionally separate from CGv2 and is not an
/// RFC-standardized post-quantum HPKE profile. Its revision-specific public
/// namespaces are part of the protocol identity.
pub mod hpke_pq;
/// HKDF-SHA256/512 key schedule with domain separation.
pub mod kdf;
/// ML-KEM backend trait and ML-KEM-512/768/1024 implementations (FIPS 203).
pub mod kem;
/// Canonical v3 PQ HPKE transport API.
pub mod pq_hpke;
/// Internal CGv2 authenticated-envelope implementation for compatibility
/// migrations only.
///
/// New applications should use [`pq_hpke`].
#[cfg(feature = "cgv2-compat")]
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

#[cfg(all(test, feature = "cgv2-compat"))]
mod tests;

#[cfg(feature = "archive")]
pub use crate::utils::archive;
#[cfg(feature = "zip")]
pub use crate::utils::zip_manager;
pub use crate::{
    core::{kyber::*, *},
    key_control::{file, *},
    log::*,
};

/// Legacy CGv2 typestate API, retained only for deliberate compatibility
/// migrations. New encryption code should use [`pq_hpke`].
#[cfg(feature = "cgv2-compat")]
pub use crate::core::hub::{
    DecryptData, DecryptFile, DecryptText, EncryptData, EncryptFile, EncryptText, MlKem1024,
    MlKem512, MlKem768,
};

// Re-export the legacy kdf module when the feature is active so that
// existing call sites using `crypt_guard::kdf::Falcon1024` etc. keep working.
#[cfg(feature = "legacy-pqclean")]
pub use crate::core::kdf as legacy_kdf;
// Legacy CGv2 compatibility framing. These `hpke_`-prefixed re-exports are not
// RFC 9180 HPKE and retain their names only for source compatibility.
#[cfg(feature = "cgv2-compat")]
pub use api::{open as hpke_open, seal as hpke_seal};
#[cfg(feature = "cgv2-compat")]
pub use api::{
    AuthenticatedAead, Decryptor, DecryptorBuilder, Encryptor, EncryptorBuilder, MissingPlaintext,
    MissingRecipient, MissingSecretKey, WithPlaintext, WithRecipient, WithSecretKey,
};
pub use markers::{AesGcmSiv, XChaCha20Poly1305};
#[cfg(feature = "cgv2-compat")]
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

        let result = {
            let sign = Signature::<Falcon1024, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Falcon1024, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Falcon512, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Falcon512, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // Dilithium
    // 5
    (Dilithium, $key:expr, 5, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium5, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium5, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium3, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium3, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium2, Message>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $content:expr, Detached) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium2, Detached>::new();
            sign.signature(content.to_owned(), key.to_owned())
        };
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

        let result = {
            let sign = Signature::<Falcon1024, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 1024, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = {
            let sign = Signature::<Falcon1024, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 512
    (Falcon, $key:expr, 512, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Falcon512, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Falcon, $key:expr, 512, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = {
            let sign = Signature::<Falcon512, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        };
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

        let result = {
            let sign = Signature::<Dilithium5, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 5, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;
        let result = {
            let sign = Signature::<Dilithium5, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 3
    (Dilithium, $key:expr, 3, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium3, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 3, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium3, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};

    // 2
    (Dilithium, $key:expr, 2, $content:expr, Message) => {{
        let mut key = $key;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium2, Message>::new();
            sign.open(content.to_owned(), key.to_owned())
        };
        key.zeroize();
        content.zeroize();
        result
    }};
    (Dilithium, $key:expr, 2, $signature:expr, $content:expr, Detached) => {{
        let mut key = $key;
        let mut signature = $signature;
        let mut content = $content;

        let result = {
            let sign = Signature::<Dilithium2, Detached>::new();
            sign.verify(content.to_owned(), signature.to_owned(), key.to_owned())
        };
        key.zeroize();
        signature.zeroize();
        content.zeroize();
        result
    }};
}
