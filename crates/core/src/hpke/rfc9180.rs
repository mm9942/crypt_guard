//! Full RFC 9180 sender and receiver setup APIs.
//!
//! This module uses the pure-Rust [`hpke`](https://crates.io/crates/hpke)
//! implementation (pinned in this crate's manifest) for the RFC 9180 KEM,
//! key-schedule, AEAD, sequence-number, and exporter operations. It supports
//! `DHKEM(P-256, HKDF-SHA256)`, `DHKEM(P-384, HKDF-SHA384)`,
//! `DHKEM(P-521, HKDF-SHA512)`, `DHKEM(X25519, HKDF-SHA256)`, and
//! `DHKEM(X448, HKDF-SHA512)`.
//!
//! X448 uses the pure-Rust `crrl` backend for RFC 7748 scalar multiplication
//! and this module's RFC 9180 DHKEM/key-schedule/context implementation. No
//! KEM identifier is substituted for another.
//! The module does **not** expose a nonce API: contexts own and advance the
//! RFC 9180 sequence state exactly once after successful `seal`/`open`.

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::{error::Error, fmt};

use crate::error::ErrorKind;

use aes_gcm::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit, Payload as AesPayload},
    Aes128Gcm as DirectAes128Gcm, Aes256Gcm as DirectAes256Gcm, Nonce as DirectAesGcmNonce,
};
use chacha20poly1305::{
    aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit, Payload as ChaChaPayload},
    ChaCha20Poly1305 as DirectChaCha20Poly1305, Nonce as DirectChaChaNonce,
};
use hpke::rand_core::{OsRng, TryRngCore};
use hpke::{
    aead::{
        Aead as BackendAead, AeadCtxR, AeadCtxS, AesGcm128, AesGcm256, ChaCha20Poly1305,
        ExportOnlyAead,
    },
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as BackendKdf},
    kem::{DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512, X25519HkdfSha256},
    setup_receiver, setup_sender, Deserializable, Kem as BackendKem, OpModeR, OpModeS, PskBundle,
    Serializable,
};
use zeroize::Zeroizing;

use super::{AeadId, HpkeSuite, KdfId, KemId, Mode};

/// The role of encoded KEM material that failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemKeyKind {
    /// A recipient or authenticated sender public key.
    Public,
    /// A recipient or authenticated sender private key.
    Private,
    /// A sender's HPKE encapsulated public key.
    Encapsulated,
}

/// Typed failures from the complete RFC 9180 setup layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rfc9180Error {
    /// A key/encapsulation value belongs to a different KEM than the suite.
    KemMismatch { expected: KemId, actual: KemId },
    /// A supplied serialized KEM value did not satisfy the selected KEM's
    /// exact validation and length rules.
    InvalidKemEncoding { kem_id: KemId, kind: KemKeyKind },
    /// A PSK mode was requested without both the PSK and its identifier.
    InvalidPskInputs { has_psk: bool, has_psk_id: bool },
    /// An RFC 9180 Export-Only suite cannot create a sealing/opening context.
    ExportOnlyAead,
    /// Sender-side encapsulation failed.
    EncapsulationFailed,
    /// Receiver-side decapsulation failed.
    DecapsulationFailed,
    /// An X448 Diffie-Hellman operation produced the all-zero value.
    ///
    /// RFC 9180 §7.1.4 requires this output validation for X448.
    InvalidDhSharedSecret,
    /// Authentication of an HPKE ciphertext failed.
    AuthenticationFailed,
    /// The context exhausted its RFC 9180 message sequence space.
    MessageLimitReached,
    /// The exporter output exceeds the selected KDF's bound.
    ExportLengthTooLarge,
    /// A backend AEAD operation failed before a ciphertext could be emitted.
    SealFailed,
}

impl fmt::Display for Rfc9180Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KemMismatch { expected, actual } => write!(
                f,
                "HPKE KEM material is {actual:?}, but the suite requires {expected:?}"
            ),
            Self::InvalidKemEncoding { kem_id, kind } => {
                write!(f, "invalid {kind:?} encoding for {kem_id:?}")
            }
            Self::InvalidPskInputs {
                has_psk,
                has_psk_id,
            } => write!(
                f,
                "invalid RFC 9180 PSK inputs: psk present={has_psk}, psk_id present={has_psk_id}"
            ),
            Self::ExportOnlyAead => f.write_str("HPKE Export-Only AEAD cannot seal or open"),
            Self::EncapsulationFailed => f.write_str("HPKE KEM encapsulation failed"),
            Self::DecapsulationFailed => f.write_str("HPKE KEM decapsulation failed"),
            Self::InvalidDhSharedSecret => f.write_str(
                "RFC 9180 X448 Diffie-Hellman produced the prohibited all-zero shared secret",
            ),
            Self::AuthenticationFailed => f.write_str("HPKE ciphertext authentication failed"),
            Self::MessageLimitReached => f.write_str("HPKE message limit reached"),
            Self::ExportLengthTooLarge => f.write_str("HPKE exporter output length is too large"),
            Self::SealFailed => f.write_str("HPKE AEAD sealing failed"),
        }
    }
}

impl Error for Rfc9180Error {}

impl Rfc9180Error {
    /// Coarse [`ErrorKind`] classification for this error.
    ///
    /// `DecapsulationFailed` maps to [`ErrorKind::InvalidKey`] rather than
    /// [`ErrorKind::Authentication`]: DHKEM decapsulation failure indicates
    /// invalid key or ciphertext material, not an AEAD authentication-tag
    /// mismatch. Every AEAD authentication failure still maps to
    /// [`ErrorKind::Authentication`] and nothing finer.
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::KemMismatch { .. } => ErrorKind::InvalidInput,
            Self::InvalidKemEncoding { .. } => ErrorKind::InvalidKey,
            Self::InvalidPskInputs { .. } => ErrorKind::InvalidInput,
            Self::ExportOnlyAead => ErrorKind::Unsupported,
            Self::EncapsulationFailed => ErrorKind::Internal,
            Self::DecapsulationFailed => ErrorKind::InvalidKey,
            Self::InvalidDhSharedSecret => ErrorKind::InvalidKey,
            Self::AuthenticationFailed => ErrorKind::Authentication,
            Self::MessageLimitReached => ErrorKind::Limit,
            Self::ExportLengthTooLarge => ErrorKind::Limit,
            Self::SealFailed => ErrorKind::Internal,
        }
    }
}

/// A validated RFC 9180 DHKEM public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    kem_id: KemId,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Parse and validate an RFC 9180 KEM public key.
    pub fn from_bytes(kem_id: KemId, bytes: &[u8]) -> Result<Self, Rfc9180Error> {
        validate_public_key(kem_id, bytes)?;
        Ok(Self {
            kem_id,
            bytes: bytes.to_vec(),
        })
    }

    /// The public key's registered KEM identifier.
    pub const fn kem_id(&self) -> KemId {
        self.kem_id
    }

    /// The canonical RFC 9180 byte encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A validated RFC 9180 DHKEM private key.
///
/// Secret bytes are zeroized when this value is dropped. The type does not
/// implement `Clone` or `Debug` to avoid accidental secret duplication/logging.
pub struct PrivateKey {
    kem_id: KemId,
    bytes: Zeroizing<Vec<u8>>,
}

impl PrivateKey {
    /// Parse and validate an RFC 9180 KEM private key.
    pub fn from_bytes(kem_id: KemId, bytes: &[u8]) -> Result<Self, Rfc9180Error> {
        let bytes = canonicalize_private_key(kem_id, bytes)?;
        Ok(Self { kem_id, bytes })
    }

    /// The private key's registered KEM identifier.
    pub const fn kem_id(&self) -> KemId {
        self.kem_id
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("kem_id", &self.kem_id)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// An RFC 9180 sender's serialized KEM encapsulation value (`enc`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncapsulatedKey {
    kem_id: KemId,
    bytes: Vec<u8>,
}

impl EncapsulatedKey {
    /// Parse and validate a serialized RFC 9180 encapsulation value.
    pub fn from_bytes(kem_id: KemId, bytes: &[u8]) -> Result<Self, Rfc9180Error> {
        validate_encapsulated_key(kem_id, bytes)?;
        Ok(Self {
            kem_id,
            bytes: bytes.to_vec(),
        })
    }

    /// The encapsulation's registered KEM identifier.
    pub const fn kem_id(&self) -> KemId {
        self.kem_id
    }

    /// The canonical RFC 9180 byte encoding sent alongside ciphertexts.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A generated RFC 9180 DHKEM key pair.
pub struct KeyPair {
    /// The public half, suitable for recipients or Auth-mode identity binding.
    pub public_key: PublicKey,
    /// The secret half, zeroized on drop.
    pub private_key: PrivateKey,
}

/// Generate a DHKEM key pair using the operating system CSPRNG.
pub fn generate_key_pair(kem_id: KemId) -> Result<KeyPair, Rfc9180Error> {
    match kem_id {
        KemId::DhKemP256HkdfSha256 => generate_key_pair_for::<DhP256HkdfSha256>(kem_id),
        KemId::DhKemP384HkdfSha384 => generate_key_pair_for::<DhP384HkdfSha384>(kem_id),
        KemId::DhKemP521HkdfSha512 => generate_key_pair_for::<DhP521HkdfSha512>(kem_id),
        KemId::DhKemX25519HkdfSha256 => generate_key_pair_for::<X25519HkdfSha256>(kem_id),
        KemId::DhKemX448HkdfSha512 => generate_x448_key_pair(),
    }
}

/// RFC 9180 sender context. It owns sequence state and is intentionally not
/// cloneable, preventing accidental nonce reuse.
pub struct SenderContext {
    suite: HpkeSuite,
    inner: Box<dyn SenderOperations>,
}

impl SenderContext {
    /// The immutable suite which created this context.
    pub const fn suite(&self) -> HpkeSuite {
        self.suite
    }

    /// Seal a plaintext with the next context-managed RFC 9180 nonce.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        if self.suite.aead_id() == AeadId::ExportOnly {
            Err(Rfc9180Error::ExportOnlyAead)
        } else {
            self.inner.seal(aad, plaintext)
        }
    }

    /// Export an RFC 9180 exporter secret without consuming a message nonce.
    pub fn export(
        &self,
        exporter_context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Rfc9180Error> {
        self.inner.export(exporter_context, output_len)
    }

    /// [`Self::export`], but the returned secret is [`Zeroizing`].
    ///
    /// Prefer this over [`Self::export`] whenever the caller can keep working
    /// with a `Zeroizing` buffer, since it avoids leaving an unwiped copy of
    /// the exported secret on the heap.
    pub fn export_zeroizing(
        &self,
        exporter_context: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Rfc9180Error> {
        Ok(Zeroizing::new(self.export(exporter_context, output_len)?))
    }
}

/// RFC 9180 receiver context. It owns sequence state and is intentionally not
/// cloneable, preventing accidental nonce reuse.
pub struct ReceiverContext {
    suite: HpkeSuite,
    inner: Box<dyn ReceiverOperations>,
}

impl ReceiverContext {
    /// The immutable suite which created this context.
    pub const fn suite(&self) -> HpkeSuite {
        self.suite
    }

    /// Open a ciphertext with the next context-managed RFC 9180 nonce.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        if self.suite.aead_id() == AeadId::ExportOnly {
            Err(Rfc9180Error::ExportOnlyAead)
        } else {
            self.inner.open(aad, ciphertext)
        }
    }

    /// [`Self::open`], but the returned plaintext is [`Zeroizing`].
    ///
    /// Prefer this over [`Self::open`] whenever the caller can keep working
    /// with a `Zeroizing` buffer, since it avoids leaving an unwiped copy of
    /// the decrypted plaintext on the heap.
    pub fn open_zeroizing(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Rfc9180Error> {
        Ok(Zeroizing::new(self.open(aad, ciphertext)?))
    }

    /// Export an RFC 9180 exporter secret without consuming a message nonce.
    pub fn export(
        &self,
        exporter_context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Rfc9180Error> {
        self.inner.export(exporter_context, output_len)
    }

    /// [`Self::export`], but the returned secret is [`Zeroizing`].
    ///
    /// Prefer this over [`Self::export`] whenever the caller can keep working
    /// with a `Zeroizing` buffer, since it avoids leaving an unwiped copy of
    /// the exported secret on the heap.
    pub fn export_zeroizing(
        &self,
        exporter_context: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Rfc9180Error> {
        Ok(Zeroizing::new(self.export(exporter_context, output_len)?))
    }
}

/// RFC 9180 `SetupBaseS`.
pub fn setup_base_s(
    suite: HpkeSuite,
    recipient_public_key: &PublicKey,
    info: &[u8],
) -> Result<(EncapsulatedKey, SenderContext), Rfc9180Error> {
    setup_sender_dispatch(suite, recipient_public_key, SenderMode::Base, info)
}

/// RFC 9180 `SetupBaseR`.
pub fn setup_base_r(
    suite: HpkeSuite,
    recipient_private_key: &PrivateKey,
    enc: &EncapsulatedKey,
    info: &[u8],
) -> Result<ReceiverContext, Rfc9180Error> {
    setup_receiver_dispatch(suite, recipient_private_key, enc, ReceiverMode::Base, info)
}

/// RFC 9180 `SetupPSKS`.
pub fn setup_psk_s(
    suite: HpkeSuite,
    recipient_public_key: &PublicKey,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(EncapsulatedKey, SenderContext), Rfc9180Error> {
    setup_sender_dispatch(
        suite,
        recipient_public_key,
        SenderMode::Psk { psk, psk_id },
        info,
    )
}

/// RFC 9180 `SetupPSKR`.
pub fn setup_psk_r(
    suite: HpkeSuite,
    recipient_private_key: &PrivateKey,
    enc: &EncapsulatedKey,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<ReceiverContext, Rfc9180Error> {
    setup_receiver_dispatch(
        suite,
        recipient_private_key,
        enc,
        ReceiverMode::Psk { psk, psk_id },
        info,
    )
}

/// RFC 9180 `SetupAuthS`.
///
/// HPKE Auth mode authenticates a static DHKEM key; it is not a digital
/// signature. Use a separate signature protocol when non-repudiation is needed.
pub fn setup_auth_s(
    suite: HpkeSuite,
    recipient_public_key: &PublicKey,
    sender_static_private_key: &PrivateKey,
    info: &[u8],
) -> Result<(EncapsulatedKey, SenderContext), Rfc9180Error> {
    setup_sender_dispatch(
        suite,
        recipient_public_key,
        SenderMode::Auth {
            private_key: sender_static_private_key,
        },
        info,
    )
}

/// RFC 9180 `SetupAuthR`.
pub fn setup_auth_r(
    suite: HpkeSuite,
    recipient_private_key: &PrivateKey,
    enc: &EncapsulatedKey,
    sender_static_public_key: &PublicKey,
    info: &[u8],
) -> Result<ReceiverContext, Rfc9180Error> {
    setup_receiver_dispatch(
        suite,
        recipient_private_key,
        enc,
        ReceiverMode::Auth {
            public_key: sender_static_public_key,
        },
        info,
    )
}

/// RFC 9180 `SetupAuthPSKS`.
pub fn setup_auth_psk_s(
    suite: HpkeSuite,
    recipient_public_key: &PublicKey,
    sender_static_private_key: &PrivateKey,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(EncapsulatedKey, SenderContext), Rfc9180Error> {
    setup_sender_dispatch(
        suite,
        recipient_public_key,
        SenderMode::AuthPsk {
            private_key: sender_static_private_key,
            psk,
            psk_id,
        },
        info,
    )
}

/// RFC 9180 `SetupAuthPSKR`.
pub fn setup_auth_psk_r(
    suite: HpkeSuite,
    recipient_private_key: &PrivateKey,
    enc: &EncapsulatedKey,
    sender_static_public_key: &PublicKey,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<ReceiverContext, Rfc9180Error> {
    setup_receiver_dispatch(
        suite,
        recipient_private_key,
        enc,
        ReceiverMode::AuthPsk {
            public_key: sender_static_public_key,
            psk,
            psk_id,
        },
        info,
    )
}

enum SenderMode<'a> {
    Base,
    Psk {
        psk: &'a [u8],
        psk_id: &'a [u8],
    },
    Auth {
        private_key: &'a PrivateKey,
    },
    AuthPsk {
        private_key: &'a PrivateKey,
        psk: &'a [u8],
        psk_id: &'a [u8],
    },
}

enum ReceiverMode<'a> {
    Base,
    Psk {
        psk: &'a [u8],
        psk_id: &'a [u8],
    },
    Auth {
        public_key: &'a PublicKey,
    },
    AuthPsk {
        public_key: &'a PublicKey,
        psk: &'a [u8],
        psk_id: &'a [u8],
    },
}

// `SenderOperations`/`ReceiverOperations` are private (module-internal) traits:
// no external code can implement them, so adding a `Send + Sync` supertrait
// bound here is not a breaking change. Every concrete implementation in this
// module (the `hpke`-crate-backed `SenderBackend`/`ReceiverBackend`, and the
// hand-rolled X448 `X448SenderBackend`/`X448ReceiverBackend`) is built solely
// from `Send + Sync` primitives (byte buffers, fixed-size arrays, and the
// `hpke` crate's own AEAD/KDF/KEM marker types), so this bound costs nothing
// and lets `SenderContext`/`ReceiverContext` (which store `Box<dyn ...>`)
// be `Send + Sync` automatically. See the `assert_send`/`assert_sync` checks
// in this module's tests.
trait SenderOperations: Send + Sync {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Rfc9180Error>;
    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Rfc9180Error>;
}

trait ReceiverOperations: Send + Sync {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Rfc9180Error>;
    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Rfc9180Error>;
}

const X448_KEM_ID: KemId = KemId::DhKemX448HkdfSha512;
const X448_KEM_SUITE_ID: &[u8] = b"KEM\x00\x21";
const X448_KEY_LEN: usize = 56;
const X448_SHARED_SECRET_LEN: usize = 64;
const HPKE_NONCE_LEN: usize = 12;

/// RFC 9180 context operations for DHKEM(X448, HKDF-SHA512).
///
/// This is deliberately separate from the `hpke` crate backend contexts:
/// that backend supplies the other registered DHKEMs but has no X448 type.
/// The state remains private and non-cloneable so the sequence nonce cannot be
/// copied or externally managed.
struct X448Context {
    suite: HpkeSuite,
    aead_key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<[u8; HPKE_NONCE_LEN]>,
    exporter_secret: Zeroizing<Vec<u8>>,
    sequence: [u8; HPKE_NONCE_LEN],
}

impl X448Context {
    fn from_shared_secret(
        suite: HpkeSuite,
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, Rfc9180Error> {
        validate_x448_psk_inputs(mode, psk, psk_id)?;

        let psk_id_hash = suite.labeled_extract_zeroizing(b"", b"psk_id_hash", psk_id);
        let info_hash = suite.labeled_extract_zeroizing(b"", b"info_hash", info);
        let mut key_schedule_context =
            Zeroizing::new(Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len()));
        key_schedule_context.push(mode.as_u8());
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);

        let secret = suite.labeled_extract_zeroizing(shared_secret, b"secret", psk);
        let key_len = x448_aead_key_len(suite.aead_id())?;
        let aead_key = suite
            .labeled_expand_zeroizing(&secret, b"key", &key_schedule_context, key_len)
            .map_err(|_| Rfc9180Error::ExportLengthTooLarge)?;
        let nonce = if suite.aead_id() == AeadId::ExportOnly {
            Zeroizing::new([0_u8; HPKE_NONCE_LEN])
        } else {
            let expanded = suite
                .labeled_expand_zeroizing(
                    &secret,
                    b"base_nonce",
                    &key_schedule_context,
                    HPKE_NONCE_LEN,
                )
                .map_err(|_| Rfc9180Error::ExportLengthTooLarge)?;
            Zeroizing::new(
                expanded
                    .to_vec()
                    .try_into()
                    .map_err(|_| Rfc9180Error::SealFailed)?,
            )
        };
        let exporter_secret = suite
            .labeled_expand_zeroizing(
                &secret,
                b"exp",
                &key_schedule_context,
                x448_outer_kdf_len(suite.kdf_id()),
            )
            .map_err(|_| Rfc9180Error::ExportLengthTooLarge)?;
        Ok(Self {
            suite,
            aead_key,
            base_nonce: nonce,
            exporter_secret,
            sequence: [0_u8; HPKE_NONCE_LEN],
        })
    }

    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        if self.suite.aead_id() == AeadId::ExportOnly {
            return Err(Rfc9180Error::ExportOnlyAead);
        }
        let nonce = self.nonce_for_current_sequence()?;
        let ciphertext = match self.suite.aead_id() {
            AeadId::AesGcm128 => {
                let nonce = DirectAesGcmNonce::try_from(&nonce[..])
                    .map_err(|_| Rfc9180Error::SealFailed)?;
                DirectAes128Gcm::new_from_slice(&self.aead_key)
                    .map_err(|_| Rfc9180Error::SealFailed)?
                    .encrypt(
                        &nonce,
                        AesPayload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| Rfc9180Error::SealFailed)?
            }
            AeadId::AesGcm256 => {
                let nonce = DirectAesGcmNonce::try_from(&nonce[..])
                    .map_err(|_| Rfc9180Error::SealFailed)?;
                DirectAes256Gcm::new_from_slice(&self.aead_key)
                    .map_err(|_| Rfc9180Error::SealFailed)?
                    .encrypt(
                        &nonce,
                        AesPayload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| Rfc9180Error::SealFailed)?
            }
            AeadId::ChaCha20Poly1305 => DirectChaCha20Poly1305::new_from_slice(&self.aead_key)
                .map_err(|_| Rfc9180Error::SealFailed)?
                .encrypt(
                    DirectChaChaNonce::from_slice(&nonce),
                    ChaChaPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Rfc9180Error::SealFailed)?,
            AeadId::ExportOnly => return Err(Rfc9180Error::ExportOnlyAead),
        };
        self.advance_after_success()?;
        Ok(ciphertext)
    }

    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        if self.suite.aead_id() == AeadId::ExportOnly {
            return Err(Rfc9180Error::ExportOnlyAead);
        }
        let nonce = self.nonce_for_current_sequence()?;
        let plaintext = match self.suite.aead_id() {
            AeadId::AesGcm128 => {
                let nonce = DirectAesGcmNonce::try_from(&nonce[..])
                    .map_err(|_| Rfc9180Error::AuthenticationFailed)?;
                DirectAes128Gcm::new_from_slice(&self.aead_key)
                    .map_err(|_| Rfc9180Error::AuthenticationFailed)?
                    .decrypt(
                        &nonce,
                        AesPayload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| Rfc9180Error::AuthenticationFailed)?
            }
            AeadId::AesGcm256 => {
                let nonce = DirectAesGcmNonce::try_from(&nonce[..])
                    .map_err(|_| Rfc9180Error::AuthenticationFailed)?;
                DirectAes256Gcm::new_from_slice(&self.aead_key)
                    .map_err(|_| Rfc9180Error::AuthenticationFailed)?
                    .decrypt(
                        &nonce,
                        AesPayload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| Rfc9180Error::AuthenticationFailed)?
            }
            AeadId::ChaCha20Poly1305 => DirectChaCha20Poly1305::new_from_slice(&self.aead_key)
                .map_err(|_| Rfc9180Error::AuthenticationFailed)?
                .decrypt(
                    DirectChaChaNonce::from_slice(&nonce),
                    ChaChaPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| Rfc9180Error::AuthenticationFailed)?,
            AeadId::ExportOnly => return Err(Rfc9180Error::ExportOnlyAead),
        };
        self.advance_after_success()?;
        Ok(plaintext)
    }

    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Rfc9180Error> {
        self.suite
            .labeled_expand(&self.exporter_secret, b"sec", exporter_context, output_len)
            .map_err(|_| Rfc9180Error::ExportLengthTooLarge)
    }

    fn nonce_for_current_sequence(&self) -> Result<[u8; HPKE_NONCE_LEN], Rfc9180Error> {
        if self.sequence == [u8::MAX; HPKE_NONCE_LEN] {
            return Err(Rfc9180Error::MessageLimitReached);
        }
        let mut nonce = *self.base_nonce;
        for (nonce_byte, sequence_byte) in nonce.iter_mut().zip(self.sequence) {
            *nonce_byte ^= sequence_byte;
        }
        Ok(nonce)
    }

    fn advance_after_success(&mut self) -> Result<(), Rfc9180Error> {
        if self.sequence == [u8::MAX; HPKE_NONCE_LEN] {
            return Err(Rfc9180Error::MessageLimitReached);
        }
        for byte in self.sequence.iter_mut().rev() {
            let (incremented, carried) = byte.overflowing_add(1);
            *byte = incremented;
            if !carried {
                break;
            }
        }
        Ok(())
    }
}

struct X448SenderBackend {
    context: X448Context,
}

impl SenderOperations for X448SenderBackend {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        self.context.seal(aad, plaintext)
    }

    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Rfc9180Error> {
        self.context.export(exporter_context, output_len)
    }
}

struct X448ReceiverBackend {
    context: X448Context,
}

impl ReceiverOperations for X448ReceiverBackend {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        self.context.open(aad, ciphertext)
    }

    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Rfc9180Error> {
        self.context.export(exporter_context, output_len)
    }
}

struct SenderBackend<A: BackendAead, K: BackendKdf, Kem: BackendKem> {
    context: AeadCtxS<A, K, Kem>,
}

// The concrete `hpke` algorithm types are zero-sized markers and therefore
// `Send + Sync`; the bounds make that explicit for the boxed trait objects.
impl<A, K, Kem> SenderOperations for SenderBackend<A, K, Kem>
where
    A: BackendAead + Send + Sync,
    K: BackendKdf + Send + Sync,
    Kem: BackendKem + Send + Sync,
{
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        self.context
            .seal(plaintext, aad)
            .map_err(map_sender_context_error)
    }

    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Rfc9180Error> {
        let mut output = vec![0_u8; output_len];
        self.context
            .export(exporter_context, &mut output)
            .map_err(map_export_error)?;
        Ok(output)
    }
}

struct ReceiverBackend<A: BackendAead, K: BackendKdf, Kem: BackendKem> {
    context: AeadCtxR<A, K, Kem>,
}

impl<A, K, Kem> ReceiverOperations for ReceiverBackend<A, K, Kem>
where
    A: BackendAead + Send + Sync,
    K: BackendKdf + Send + Sync,
    Kem: BackendKem + Send + Sync,
{
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
        self.context
            .open(ciphertext, aad)
            .map_err(map_receiver_context_error)
    }

    fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, Rfc9180Error> {
        let mut output = vec![0_u8; output_len];
        self.context
            .export(exporter_context, &mut output)
            .map_err(map_export_error)?;
        Ok(output)
    }
}

fn map_sender_context_error(error: hpke::HpkeError) -> Rfc9180Error {
    match error {
        hpke::HpkeError::MessageLimitReached => Rfc9180Error::MessageLimitReached,
        hpke::HpkeError::SealError => Rfc9180Error::SealFailed,
        hpke::HpkeError::KdfOutputTooLong => Rfc9180Error::ExportLengthTooLarge,
        _ => Rfc9180Error::SealFailed,
    }
}

fn map_receiver_context_error(error: hpke::HpkeError) -> Rfc9180Error {
    match error {
        hpke::HpkeError::MessageLimitReached => Rfc9180Error::MessageLimitReached,
        hpke::HpkeError::OpenError => Rfc9180Error::AuthenticationFailed,
        _ => Rfc9180Error::AuthenticationFailed,
    }
}

fn map_export_error(_: hpke::HpkeError) -> Rfc9180Error {
    Rfc9180Error::ExportLengthTooLarge
}

fn ensure_suite_key(kem_id: KemId, key_kem_id: KemId) -> Result<(), Rfc9180Error> {
    if kem_id == key_kem_id {
        Ok(())
    } else {
        Err(Rfc9180Error::KemMismatch {
            expected: kem_id,
            actual: key_kem_id,
        })
    }
}

fn checked_psk<'a>(psk: &'a [u8], psk_id: &'a [u8]) -> Result<PskBundle<'a>, Rfc9180Error> {
    let has_psk = !psk.is_empty();
    let has_psk_id = !psk_id.is_empty();
    PskBundle::new(psk, psk_id).map_err(|_| Rfc9180Error::InvalidPskInputs {
        has_psk,
        has_psk_id,
    })
}

fn x448_aead_key_len(aead_id: AeadId) -> Result<usize, Rfc9180Error> {
    match aead_id {
        AeadId::AesGcm128 => Ok(16),
        AeadId::AesGcm256 | AeadId::ChaCha20Poly1305 => Ok(32),
        AeadId::ExportOnly => Ok(0),
    }
}

const fn x448_outer_kdf_len(kdf_id: KdfId) -> usize {
    match kdf_id {
        KdfId::HkdfSha256 => 32,
        KdfId::HkdfSha384 => 48,
        KdfId::HkdfSha512 => 64,
    }
}

fn validate_x448_psk_inputs(mode: Mode, psk: &[u8], psk_id: &[u8]) -> Result<(), Rfc9180Error> {
    let has_psk = !psk.is_empty();
    let has_psk_id = !psk_id.is_empty();
    let requires_psk = matches!(mode, Mode::Psk | Mode::AuthPsk);
    if has_psk == has_psk_id && has_psk == requires_psk {
        Ok(())
    } else {
        Err(Rfc9180Error::InvalidPskInputs {
            has_psk,
            has_psk_id,
        })
    }
}

fn as_x448_array(bytes: &[u8], kind: KemKeyKind) -> Result<[u8; X448_KEY_LEN], Rfc9180Error> {
    bytes
        .try_into()
        .map_err(|_| Rfc9180Error::InvalidKemEncoding {
            kem_id: X448_KEM_ID,
            kind,
        })
}

fn clamp_x448_private_key(mut bytes: [u8; X448_KEY_LEN]) -> [u8; X448_KEY_LEN] {
    bytes[0] &= 252;
    bytes[X448_KEY_LEN - 1] |= 128;
    bytes
}

fn x448_labeled_extract(
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Zeroizing<[u8; X448_SHARED_SECRET_LEN]> {
    use hkdf::Hkdf;
    use sha2_011::Sha512;

    let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(
        b"HPKE-v1".len() + X448_KEM_SUITE_ID.len() + label.len() + ikm.len(),
    ));
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(X448_KEM_SUITE_ID);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    Zeroizing::new(Hkdf::<Sha512>::extract(Some(salt), &labeled_ikm).0.into())
}

fn x448_labeled_expand(
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, Rfc9180Error> {
    use hkdf::Hkdf;
    use sha2_011::Sha512;

    if output_len > u16::MAX as usize || output_len > X448_SHARED_SECRET_LEN * 255 {
        return Err(Rfc9180Error::ExportLengthTooLarge);
    }
    let mut labeled_info = Vec::with_capacity(
        2 + b"HPKE-v1".len() + X448_KEM_SUITE_ID.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&(output_len as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(X448_KEM_SUITE_ID);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let hkdf = Hkdf::<Sha512>::from_prk(prk).map_err(|_| Rfc9180Error::ExportLengthTooLarge)?;
    let mut output = Zeroizing::new(vec![0_u8; output_len]);
    hkdf.expand(&labeled_info, &mut output)
        .map_err(|_| Rfc9180Error::ExportLengthTooLarge)?;
    Ok(output.to_vec())
}

fn x448_derive_key_pair(
    ikm: &[u8],
) -> Result<([u8; X448_KEY_LEN], [u8; X448_KEY_LEN]), Rfc9180Error> {
    let dkp_prk = x448_labeled_extract(b"", b"dkp_prk", ikm);
    let expanded_sk = Zeroizing::new(x448_labeled_expand(&dkp_prk[..], b"sk", b"", X448_KEY_LEN)?);
    let secret_key = as_x448_array(&expanded_sk, KemKeyKind::Private)?;
    let public_key = crrl::x448::x448_base(&secret_key);
    Ok((secret_key, public_key))
}

fn x448_extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Result<Vec<u8>, Rfc9180Error> {
    let eae_prk = x448_labeled_extract(b"", b"eae_prk", dh);
    x448_labeled_expand(
        &eae_prk[..],
        b"shared_secret",
        kem_context,
        X448_SHARED_SECRET_LEN,
    )
}

fn x448_dh(private_key: &[u8], public_key: &[u8]) -> Result<[u8; X448_KEY_LEN], Rfc9180Error> {
    use zeroize::Zeroize;

    let mut private_key = as_x448_array(private_key, KemKeyKind::Private)?;
    let public_key = as_x448_array(public_key, KemKeyKind::Public)?;
    let shared_secret = crrl::x448::x448(&public_key, &private_key);
    // Wipe the stack copy of the private scalar as soon as it has been
    // consumed; only the (non-secret) DH output is returned.
    private_key.zeroize();
    // RFC 9180 §7.1.4 requires rejecting the all-zero shared secret. Fold
    // over every byte (rather than a short-circuiting `all()`) so the check
    // does not take a data-dependent number of steps on secret material.
    let is_zero = shared_secret.iter().fold(0_u8, |acc, byte| acc | byte) == 0;
    if is_zero {
        Err(Rfc9180Error::InvalidDhSharedSecret)
    } else {
        Ok(shared_secret)
    }
}

fn generate_x448_key_pair() -> Result<KeyPair, Rfc9180Error> {
    let mut ikm = Zeroizing::new([0_u8; X448_KEY_LEN]);
    let mut rng = OsRng.unwrap_err();
    rng.try_fill_bytes(&mut *ikm)
        .map_err(|_| Rfc9180Error::EncapsulationFailed)?;
    // RFC 9180 permits GenerateKeyPair to be implemented as
    // DeriveKeyPair(random(Nsk)). Preserve the RFC derivation labels rather
    // than treating raw operating-system bytes as the private key directly.
    let (derived_private_bytes, public_bytes) = x448_derive_key_pair(&ikm[..])?;
    let derived_private_bytes = Zeroizing::new(derived_private_bytes);
    let private_bytes = Zeroizing::new(clamp_x448_private_key(*derived_private_bytes));
    Ok(KeyPair {
        public_key: PublicKey {
            kem_id: X448_KEM_ID,
            bytes: public_bytes.to_vec(),
        },
        private_key: PrivateKey {
            kem_id: X448_KEM_ID,
            bytes: Zeroizing::new(private_bytes.to_vec()),
        },
    })
}

// Every call site guards `KemId::DhKemX448HkdfSha512` before reaching this
// macro (X448 has no `hpke`-crate backend `Kem` type to dispatch to), so this
// arm is not expected to execute. It nonetheless returns a typed
// `Rfc9180Error` instead of panicking via `unreachable!`, so a future dispatch
// path that forgets the X448 guard fails safely with a normal `Result` error
// rather than aborting the process.
macro_rules! dispatch_kem {
    ($kem_id:expr, $function:ident $(, $argument:expr )* $(,)?) => {
        match $kem_id {
            KemId::DhKemP256HkdfSha256 => $function::<DhP256HkdfSha256>($kem_id $(, $argument)*),
            KemId::DhKemP384HkdfSha384 => $function::<DhP384HkdfSha384>($kem_id $(, $argument)*),
            KemId::DhKemP521HkdfSha512 => $function::<DhP521HkdfSha512>($kem_id $(, $argument)*),
            KemId::DhKemX25519HkdfSha256 => $function::<X25519HkdfSha256>($kem_id $(, $argument)*),
            KemId::DhKemX448HkdfSha512 => {
                return Err(Rfc9180Error::KemMismatch {
                    expected: $kem_id,
                    actual: KemId::DhKemX448HkdfSha512,
                })
            }
        }
    };
}

// See `dispatch_kem!`: every call site guards X448 before reaching this
// macro, since X448 is handled entirely by `setup_x448_sender`/
// `setup_x448_receiver` rather than the `hpke`-crate backend dispatched here.
macro_rules! dispatch_suite {
    ($suite:expr, $function:ident $(, $argument:expr )* $(,)?) => {{
        let suite = $suite;
        match suite.kem_id() {
            KemId::DhKemP256HkdfSha256 => dispatch_kdf_aead!(suite, $function, DhP256HkdfSha256 $(, $argument)*),
            KemId::DhKemP384HkdfSha384 => dispatch_kdf_aead!(suite, $function, DhP384HkdfSha384 $(, $argument)*),
            KemId::DhKemP521HkdfSha512 => dispatch_kdf_aead!(suite, $function, DhP521HkdfSha512 $(, $argument)*),
            KemId::DhKemX25519HkdfSha256 => dispatch_kdf_aead!(suite, $function, X25519HkdfSha256 $(, $argument)*),
            KemId::DhKemX448HkdfSha512 => {
                return Err(Rfc9180Error::KemMismatch {
                    expected: suite.kem_id(),
                    actual: KemId::DhKemX448HkdfSha512,
                })
            }
        }
    }};
}

macro_rules! dispatch_kdf_aead {
    ($suite:expr, $function:ident, $kem:ty $(, $argument:expr )* $(,)?) => {
        match $suite.kdf_id() {
            KdfId::HkdfSha256 => dispatch_aead!($suite, $function, HkdfSha256, $kem $(, $argument)*),
            KdfId::HkdfSha384 => dispatch_aead!($suite, $function, HkdfSha384, $kem $(, $argument)*),
            KdfId::HkdfSha512 => dispatch_aead!($suite, $function, HkdfSha512, $kem $(, $argument)*),
        }
    };
}

macro_rules! dispatch_aead {
    ($suite:expr, $function:ident, $kdf:ty, $kem:ty $(, $argument:expr )* $(,)?) => {
        match $suite.aead_id() {
            AeadId::AesGcm128 => $function::<AesGcm128, $kdf, $kem>($suite $(, $argument)*),
            AeadId::AesGcm256 => $function::<AesGcm256, $kdf, $kem>($suite $(, $argument)*),
            AeadId::ChaCha20Poly1305 => $function::<ChaCha20Poly1305, $kdf, $kem>($suite $(, $argument)*),
            AeadId::ExportOnly => $function::<ExportOnlyAead, $kdf, $kem>($suite $(, $argument)*),
        }
    };
}

fn generate_key_pair_for<Kem: BackendKem>(kem_id: KemId) -> Result<KeyPair, Rfc9180Error> {
    use zeroize::Zeroize;

    let mut rng = OsRng.unwrap_err();
    let (private_key, public_key) = Kem::gen_keypair(&mut rng);
    // `to_bytes()` returns a `GenericArray`, which the `zeroize` crate does
    // not implement `Zeroize` for directly (no blanket impl, and no
    // `generic-array` feature is enabled), so it cannot be held in a
    // `Zeroizing<_>` wrapper. Copy it out and wipe the temporary via its
    // slice view instead.
    let mut private_key_bytes = private_key.to_bytes();
    let private_key_vec = Zeroizing::new(private_key_bytes.to_vec());
    private_key_bytes.as_mut_slice().zeroize();
    Ok(KeyPair {
        public_key: PublicKey {
            kem_id,
            bytes: public_key.to_bytes().to_vec(),
        },
        private_key: PrivateKey {
            kem_id,
            bytes: private_key_vec,
        },
    })
}

fn validate_public_key_for<Kem: BackendKem>(
    kem_id: KemId,
    bytes: &[u8],
) -> Result<(), Rfc9180Error> {
    Kem::PublicKey::from_bytes(bytes)
        .map(|_| ())
        .map_err(|_| Rfc9180Error::InvalidKemEncoding {
            kem_id,
            kind: KemKeyKind::Public,
        })
}

fn validate_private_key_for<Kem: BackendKem>(
    kem_id: KemId,
    bytes: &[u8],
) -> Result<(), Rfc9180Error> {
    Kem::PrivateKey::from_bytes(bytes)
        .map(|_| ())
        .map_err(|_| Rfc9180Error::InvalidKemEncoding {
            kem_id,
            kind: KemKeyKind::Private,
        })
}

fn validate_encapsulated_key_for<Kem: BackendKem>(
    kem_id: KemId,
    bytes: &[u8],
) -> Result<(), Rfc9180Error> {
    Kem::EncappedKey::from_bytes(bytes)
        .map(|_| ())
        .map_err(|_| Rfc9180Error::InvalidKemEncoding {
            kem_id,
            kind: KemKeyKind::Encapsulated,
        })
}

fn validate_public_key(kem_id: KemId, bytes: &[u8]) -> Result<(), Rfc9180Error> {
    if kem_id == X448_KEM_ID {
        as_x448_array(bytes, KemKeyKind::Public).map(|_| ())
    } else {
        dispatch_kem!(kem_id, validate_public_key_for, bytes)
    }
}

fn validate_private_key(kem_id: KemId, bytes: &[u8]) -> Result<(), Rfc9180Error> {
    if kem_id == X448_KEM_ID {
        as_x448_array(bytes, KemKeyKind::Private).map(|_| ())
    } else {
        dispatch_kem!(kem_id, validate_private_key_for, bytes)
    }
}

fn canonicalize_private_key(
    kem_id: KemId,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Rfc9180Error> {
    validate_private_key(kem_id, bytes)?;
    if kem_id == X448_KEM_ID {
        let clamped = Zeroizing::new(clamp_x448_private_key(as_x448_array(
            bytes,
            KemKeyKind::Private,
        )?));
        Ok(Zeroizing::new(clamped.to_vec()))
    } else {
        Ok(Zeroizing::new(bytes.to_vec()))
    }
}

fn validate_encapsulated_key(kem_id: KemId, bytes: &[u8]) -> Result<(), Rfc9180Error> {
    if kem_id == X448_KEM_ID {
        as_x448_array(bytes, KemKeyKind::Encapsulated).map(|_| ())
    } else {
        dispatch_kem!(kem_id, validate_encapsulated_key_for, bytes)
    }
}

fn setup_sender_dispatch(
    suite: HpkeSuite,
    recipient_public_key: &PublicKey,
    mode: SenderMode<'_>,
    info: &[u8],
) -> Result<(EncapsulatedKey, SenderContext), Rfc9180Error> {
    ensure_suite_key(suite.kem_id(), recipient_public_key.kem_id())?;
    match &mode {
        SenderMode::Auth { private_key } | SenderMode::AuthPsk { private_key, .. } => {
            ensure_suite_key(suite.kem_id(), private_key.kem_id())?;
        }
        SenderMode::Base | SenderMode::Psk { .. } => {}
    }
    if suite.kem_id() == X448_KEM_ID {
        return setup_x448_sender(suite, recipient_public_key, mode, info);
    }
    dispatch_suite!(suite, setup_sender_for, recipient_public_key, mode, info)
}

fn setup_receiver_dispatch(
    suite: HpkeSuite,
    recipient_private_key: &PrivateKey,
    enc: &EncapsulatedKey,
    mode: ReceiverMode<'_>,
    info: &[u8],
) -> Result<ReceiverContext, Rfc9180Error> {
    ensure_suite_key(suite.kem_id(), recipient_private_key.kem_id())?;
    ensure_suite_key(suite.kem_id(), enc.kem_id())?;
    match &mode {
        ReceiverMode::Auth { public_key } | ReceiverMode::AuthPsk { public_key, .. } => {
            ensure_suite_key(suite.kem_id(), public_key.kem_id())?;
        }
        ReceiverMode::Base | ReceiverMode::Psk { .. } => {}
    }
    if suite.kem_id() == X448_KEM_ID {
        return setup_x448_receiver(suite, recipient_private_key, enc, mode, info);
    }
    dispatch_suite!(
        suite,
        setup_receiver_for,
        recipient_private_key,
        enc,
        mode,
        info
    )
}

fn decode_public_key<Kem: BackendKem>(
    kem_id: KemId,
    key: &PublicKey,
) -> Result<Kem::PublicKey, Rfc9180Error> {
    Kem::PublicKey::from_bytes(key.as_bytes()).map_err(|_| Rfc9180Error::InvalidKemEncoding {
        kem_id,
        kind: KemKeyKind::Public,
    })
}

fn decode_private_key<Kem: BackendKem>(
    kem_id: KemId,
    key: &PrivateKey,
) -> Result<Kem::PrivateKey, Rfc9180Error> {
    Kem::PrivateKey::from_bytes(key.bytes.as_ref()).map_err(|_| Rfc9180Error::InvalidKemEncoding {
        kem_id,
        kind: KemKeyKind::Private,
    })
}

fn decode_encapsulated_key<Kem: BackendKem>(
    kem_id: KemId,
    enc: &EncapsulatedKey,
) -> Result<Kem::EncappedKey, Rfc9180Error> {
    Kem::EncappedKey::from_bytes(enc.as_bytes()).map_err(|_| Rfc9180Error::InvalidKemEncoding {
        kem_id,
        kind: KemKeyKind::Encapsulated,
    })
}

fn setup_sender_for<A, K, Kem>(
    suite: HpkeSuite,
    recipient_public_key: &PublicKey,
    mode: SenderMode<'_>,
    info: &[u8],
) -> Result<(EncapsulatedKey, SenderContext), Rfc9180Error>
where
    A: BackendAead + Send + Sync + 'static,
    K: BackendKdf + Send + Sync + 'static,
    Kem: BackendKem + Send + Sync + 'static,
{
    let recipient = decode_public_key::<Kem>(suite.kem_id(), recipient_public_key)?;
    let mut rng = OsRng.unwrap_err();
    let setup = match mode {
        SenderMode::Base => {
            setup_sender::<A, K, Kem, _>(&OpModeS::Base, &recipient, info, &mut rng)
        }
        SenderMode::Psk { psk, psk_id } => {
            let bundle = checked_psk(psk, psk_id)?;
            setup_sender::<A, K, Kem, _>(&OpModeS::Psk(bundle), &recipient, info, &mut rng)
        }
        SenderMode::Auth { private_key } => {
            let private = decode_private_key::<Kem>(suite.kem_id(), private_key)?;
            let public = Kem::sk_to_pk(&private);
            setup_sender::<A, K, Kem, _>(
                &OpModeS::Auth((private, public)),
                &recipient,
                info,
                &mut rng,
            )
        }
        SenderMode::AuthPsk {
            private_key,
            psk,
            psk_id,
        } => {
            let bundle = checked_psk(psk, psk_id)?;
            let private = decode_private_key::<Kem>(suite.kem_id(), private_key)?;
            let public = Kem::sk_to_pk(&private);
            setup_sender::<A, K, Kem, _>(
                &OpModeS::AuthPsk((private, public), bundle),
                &recipient,
                info,
                &mut rng,
            )
        }
    }
    .map_err(|_| Rfc9180Error::EncapsulationFailed)?;

    let (enc, context) = setup;
    Ok((
        EncapsulatedKey {
            kem_id: suite.kem_id(),
            bytes: enc.to_bytes().to_vec(),
        },
        SenderContext {
            suite,
            inner: Box::new(SenderBackend { context }),
        },
    ))
}

fn setup_receiver_for<A, K, Kem>(
    suite: HpkeSuite,
    recipient_private_key: &PrivateKey,
    enc: &EncapsulatedKey,
    mode: ReceiverMode<'_>,
    info: &[u8],
) -> Result<ReceiverContext, Rfc9180Error>
where
    A: BackendAead + Send + Sync + 'static,
    K: BackendKdf + Send + Sync + 'static,
    Kem: BackendKem + Send + Sync + 'static,
{
    let private = decode_private_key::<Kem>(suite.kem_id(), recipient_private_key)?;
    let enc = decode_encapsulated_key::<Kem>(suite.kem_id(), enc)?;
    let context = match mode {
        ReceiverMode::Base => setup_receiver::<A, K, Kem>(&OpModeR::Base, &private, &enc, info),
        ReceiverMode::Psk { psk, psk_id } => {
            let bundle = checked_psk(psk, psk_id)?;
            setup_receiver::<A, K, Kem>(&OpModeR::Psk(bundle), &private, &enc, info)
        }
        ReceiverMode::Auth { public_key } => {
            let public = decode_public_key::<Kem>(suite.kem_id(), public_key)?;
            setup_receiver::<A, K, Kem>(&OpModeR::Auth(public), &private, &enc, info)
        }
        ReceiverMode::AuthPsk {
            public_key,
            psk,
            psk_id,
        } => {
            let bundle = checked_psk(psk, psk_id)?;
            let public = decode_public_key::<Kem>(suite.kem_id(), public_key)?;
            setup_receiver::<A, K, Kem>(&OpModeR::AuthPsk(public, bundle), &private, &enc, info)
        }
    }
    .map_err(|_| Rfc9180Error::DecapsulationFailed)?;

    Ok(ReceiverContext {
        suite,
        inner: Box::new(ReceiverBackend { context }),
    })
}

fn setup_x448_sender(
    suite: HpkeSuite,
    recipient_public_key: &PublicKey,
    mode: SenderMode<'_>,
    info: &[u8],
) -> Result<(EncapsulatedKey, SenderContext), Rfc9180Error> {
    let recipient_public = as_x448_array(recipient_public_key.as_bytes(), KemKeyKind::Public)?;
    let ephemeral = generate_x448_key_pair()?;
    let encapsulated = as_x448_array(ephemeral.public_key.as_bytes(), KemKeyKind::Encapsulated)?;
    let mut dh = Zeroizing::new(Vec::with_capacity(2 * X448_KEY_LEN));
    let ephemeral_dh = Zeroizing::new(x448_dh(&ephemeral.private_key.bytes, &recipient_public)?);
    dh.extend_from_slice(&ephemeral_dh[..]);
    let mut kem_context = Vec::with_capacity(X448_KEY_LEN * 3);
    kem_context.extend_from_slice(&encapsulated);
    kem_context.extend_from_slice(&recipient_public);

    let (mode_id, psk, psk_id) = match mode {
        SenderMode::Base => (Mode::Base, &[][..], &[][..]),
        SenderMode::Psk { psk, psk_id } => (Mode::Psk, psk, psk_id),
        SenderMode::Auth { private_key } => {
            use zeroize::Zeroize;
            let mut sender_private = as_x448_array(&private_key.bytes, KemKeyKind::Private)?;
            let sender_public = crrl::x448::x448_base(&sender_private);
            sender_private.zeroize();
            let static_dh = Zeroizing::new(x448_dh(&private_key.bytes, &recipient_public)?);
            dh.extend_from_slice(&static_dh[..]);
            kem_context.extend_from_slice(&sender_public);
            (Mode::Auth, &[][..], &[][..])
        }
        SenderMode::AuthPsk {
            private_key,
            psk,
            psk_id,
        } => {
            use zeroize::Zeroize;
            let mut sender_private = as_x448_array(&private_key.bytes, KemKeyKind::Private)?;
            let sender_public = crrl::x448::x448_base(&sender_private);
            sender_private.zeroize();
            let static_dh = Zeroizing::new(x448_dh(&private_key.bytes, &recipient_public)?);
            dh.extend_from_slice(&static_dh[..]);
            kem_context.extend_from_slice(&sender_public);
            (Mode::AuthPsk, psk, psk_id)
        }
    };
    let shared_secret = Zeroizing::new(x448_extract_and_expand(&dh, &kem_context)?);
    let context =
        X448Context::from_shared_secret(suite, mode_id, &shared_secret, info, psk, psk_id)?;
    Ok((
        EncapsulatedKey {
            kem_id: X448_KEM_ID,
            bytes: encapsulated.to_vec(),
        },
        SenderContext {
            suite,
            inner: Box::new(X448SenderBackend { context }),
        },
    ))
}

fn setup_x448_receiver(
    suite: HpkeSuite,
    recipient_private_key: &PrivateKey,
    enc: &EncapsulatedKey,
    mode: ReceiverMode<'_>,
    info: &[u8],
) -> Result<ReceiverContext, Rfc9180Error> {
    let recipient_private = Zeroizing::new(as_x448_array(
        &recipient_private_key.bytes,
        KemKeyKind::Private,
    )?);
    let recipient_public = crrl::x448::x448_base(&recipient_private);
    let encapsulated = as_x448_array(enc.as_bytes(), KemKeyKind::Encapsulated)?;
    let mut dh = Zeroizing::new(Vec::with_capacity(2 * X448_KEY_LEN));
    let base_dh = Zeroizing::new(x448_dh(&recipient_private[..], &encapsulated)?);
    dh.extend_from_slice(&base_dh[..]);
    let mut kem_context = Vec::with_capacity(X448_KEY_LEN * 3);
    kem_context.extend_from_slice(&encapsulated);
    kem_context.extend_from_slice(&recipient_public);

    let (mode_id, psk, psk_id) = match mode {
        ReceiverMode::Base => (Mode::Base, &[][..], &[][..]),
        ReceiverMode::Psk { psk, psk_id } => (Mode::Psk, psk, psk_id),
        ReceiverMode::Auth { public_key } => {
            let sender_public = as_x448_array(public_key.as_bytes(), KemKeyKind::Public)?;
            let static_dh = Zeroizing::new(x448_dh(&recipient_private[..], &sender_public)?);
            dh.extend_from_slice(&static_dh[..]);
            kem_context.extend_from_slice(&sender_public);
            (Mode::Auth, &[][..], &[][..])
        }
        ReceiverMode::AuthPsk {
            public_key,
            psk,
            psk_id,
        } => {
            let sender_public = as_x448_array(public_key.as_bytes(), KemKeyKind::Public)?;
            let static_dh = Zeroizing::new(x448_dh(&recipient_private[..], &sender_public)?);
            dh.extend_from_slice(&static_dh[..]);
            kem_context.extend_from_slice(&sender_public);
            (Mode::AuthPsk, psk, psk_id)
        }
    };
    let shared_secret = Zeroizing::new(x448_extract_and_expand(&dh, &kem_context)?);
    let context =
        X448Context::from_shared_secret(suite, mode_id, &shared_secret, info, psk, psk_id)?;
    Ok(ReceiverContext {
        suite,
        inner: Box::new(X448ReceiverBackend { context }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny, deterministic xorshift64 PRNG used only to generate reproducible
    /// fuzz-style byte strings for the no-panic sweeps below. It is not
    /// cryptographically secure and must never be used outside `#[cfg(test)]`.
    struct Xorshift64(u64);

    impl Xorshift64 {
        fn new(seed: u64) -> Self {
            // xorshift64 requires a non-zero state.
            Self(seed | 1)
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    const ALL_KEM_IDS: [KemId; 5] = [
        KemId::DhKemP256HkdfSha256,
        KemId::DhKemP384HkdfSha384,
        KemId::DhKemP521HkdfSha512,
        KemId::DhKemX25519HkdfSha256,
        KemId::DhKemX448HkdfSha512,
    ];

    const fn matching_kdf_id(kem_id: KemId) -> KdfId {
        match kem_id {
            KemId::DhKemP256HkdfSha256 | KemId::DhKemX25519HkdfSha256 => KdfId::HkdfSha256,
            KemId::DhKemP384HkdfSha384 => KdfId::HkdfSha384,
            KemId::DhKemP521HkdfSha512 | KemId::DhKemX448HkdfSha512 => KdfId::HkdfSha512,
        }
    }

    #[test]
    fn contexts_are_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<SenderContext>();
        assert_send::<ReceiverContext>();
        assert_sync::<SenderContext>();
        assert_sync::<ReceiverContext>();
    }

    #[test]
    fn kem_material_parsers_never_panic_across_lengths_and_random_bytes() {
        // Generously larger than every registered KEM's longest RFC 9180
        // encoding (DHKEM(P-521, ...)'s SEC1 uncompressed public key, at 133
        // bytes, is the longest of the five).
        const MAX_PROBED_LEN: usize = 160;

        for kem_id in ALL_KEM_IDS {
            let mut rng = Xorshift64::new(0x9E37_79B9_7F4A_7C15 ^ u64::from(kem_id.as_u16()));

            // Exhaustively sweep every length from empty to one past the
            // probed maximum, each time with fresh random content.
            for len in 0..=(MAX_PROBED_LEN + 1) {
                let mut bytes = vec![0_u8; len];
                rng.fill(&mut bytes);

                let _ = PublicKey::from_bytes(kem_id, &bytes);
                let _ = PrivateKey::from_bytes(kem_id, &bytes);
                let _ = EncapsulatedKey::from_bytes(kem_id, &bytes);
            }

            // A further batch of random lengths and random content, still
            // fully deterministic given the seed above.
            for _ in 0..256 {
                let len = (rng.next_u64() as usize) % (MAX_PROBED_LEN + 2);
                let mut bytes = vec![0_u8; len];
                rng.fill(&mut bytes);

                let _ = PublicKey::from_bytes(kem_id, &bytes);
                let _ = PrivateKey::from_bytes(kem_id, &bytes);
                let _ = EncapsulatedKey::from_bytes(kem_id, &bytes);
            }
        }
    }

    #[test]
    fn open_zeroizing_and_export_zeroizing_match_plain_variants_for_every_kem() {
        for kem_id in ALL_KEM_IDS {
            let suite = HpkeSuite::new(kem_id, matching_kdf_id(kem_id), AeadId::ChaCha20Poly1305);
            let recipient = generate_key_pair(kem_id).unwrap();

            let (enc, mut sender) =
                setup_base_s(suite, &recipient.public_key, b"rfc9180 zeroizing parity").unwrap();
            let mut receiver_for_open = setup_base_r(
                suite,
                &recipient.private_key,
                &enc,
                b"rfc9180 zeroizing parity",
            )
            .unwrap();
            let mut receiver_for_open_zeroizing = setup_base_r(
                suite,
                &recipient.private_key,
                &enc,
                b"rfc9180 zeroizing parity",
            )
            .unwrap();

            let ciphertext = sender.seal(b"aad", b"zeroizing parity payload").unwrap();

            let plain_open = receiver_for_open.open(b"aad", &ciphertext).unwrap();
            let zeroizing_open = receiver_for_open_zeroizing
                .open_zeroizing(b"aad", &ciphertext)
                .unwrap();
            assert_eq!(plain_open, zeroizing_open.to_vec());
            assert_eq!(plain_open, b"zeroizing parity payload");

            let plain_export = sender.export(b"export-context", 48).unwrap();
            let zeroizing_export = sender.export_zeroizing(b"export-context", 48).unwrap();
            assert_eq!(plain_export, zeroizing_export.to_vec());

            let plain_receiver_export = receiver_for_open.export(b"export-context", 48).unwrap();
            let zeroizing_receiver_export = receiver_for_open
                .export_zeroizing(b"export-context", 48)
                .unwrap();
            assert_eq!(plain_receiver_export, zeroizing_receiver_export.to_vec());
            assert_eq!(plain_export, plain_receiver_export);
        }
    }

    fn x448_bytes(encoded: &str) -> [u8; X448_KEY_LEN] {
        let mut bytes = [0_u8; X448_KEY_LEN];
        hex::decode_to_slice(encoded, &mut bytes).expect("RFC 7748 X448 hex vector");
        bytes
    }

    #[test]
    fn x448_matches_rfc7748_section_6_2() {
        let alice_private = x448_bytes(concat!(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d",
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        ));
        let bob_private = x448_bytes(concat!(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d",
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
        ));
        let alice_public = x448_bytes(concat!(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c",
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        ));
        let bob_public = x448_bytes(concat!(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430",
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        ));
        let shared_secret = x448_bytes(concat!(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b",
            "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        ));

        assert_eq!(
            crrl::x448::x448_base(&alice_private),
            alice_public,
            "Alice's RFC 7748 X448 public key"
        );
        assert_eq!(
            crrl::x448::x448_base(&bob_private),
            bob_public,
            "Bob's RFC 7748 X448 public key"
        );
        assert_eq!(
            x448_dh(&alice_private, &bob_public).unwrap(),
            shared_secret,
            "Alice's RFC 7748 X448 shared secret"
        );
        assert_eq!(
            x448_dh(&bob_private, &alice_public).unwrap(),
            shared_secret,
            "Bob's RFC 7748 X448 shared secret"
        );
    }

    #[test]
    fn authentication_failed_kind_is_authentication() {
        assert_eq!(
            Rfc9180Error::AuthenticationFailed.kind(),
            crate::error::ErrorKind::Authentication
        );
    }

    #[test]
    fn authentication_failed_display_carries_no_variable_data() {
        assert_eq!(
            Rfc9180Error::AuthenticationFailed.to_string(),
            "HPKE ciphertext authentication failed"
        );
    }
}
