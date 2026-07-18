//! RFC 9180 HPKE domain-separation, KDF, and context-core primitives.
//!
//! This module contains RFC 9180 HPKE primitives and a complete, separately
//! named [`rfc9180`] setup API. The setup API supports all five RFC 9180
//! DHKEMs, every registered encryption AEAD, and the Base, PSK, Auth, and
//! AuthPSK modes. The lower-level key-schedule/core types remain available for
//! callers that need their explicit state boundaries.

use std::{error::Error, fmt};

use aes_gcm::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit, Payload as AesPayload},
    Aes128Gcm, Aes256Gcm, Nonce as AesGcmNonce,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce as ChaCha20Poly1305Nonce,
};
use hkdf::Hkdf;
use sha2_011::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

/// Complete RFC 9180 setup APIs backed by the pure-Rust `hpke` crate.
///
/// This layer supports all five RFC 9180 DHKEMs (P-256, P-384, P-521, X25519,
/// and X448), all registered encryption AEADs, and all four setup modes.
/// P-256 through X25519 use the pure-Rust RustCrypto HPKE backend; X448 uses
/// the separately tested pure-Rust `crrl` implementation.
pub mod rfc9180;

const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

/// Errors produced by this RFC 9180 HPKE foundation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpkeError {
    /// The requested output cannot be represented by the RFC 9180 two-octet
    /// length prefix.
    OutputLengthTooLarge { requested: usize },
    /// The pseudorandom key is shorter than the hash output length required by
    /// HKDF-Expand.
    InvalidPseudorandomKeyLength { actual: usize, required: usize },
    /// The requested output exceeds RFC 5869's `255 * Nh` expansion bound.
    HkdfOutputLengthTooLarge { requested: usize, maximum: usize },
    /// The PSK and PSK identifier inputs violate RFC 9180 §5.1.
    InvalidPskInputs {
        mode: Mode,
        has_psk: bool,
        has_psk_id: bool,
    },
    /// This foundational implementation derives only Base-mode key schedules.
    UnsupportedKeyScheduleMode { mode: Mode },
    /// The RFC 9180 AEAD-sized message sequence has no remaining usable
    /// value.
    MessageLimitReached,
    /// The selected AEAD is RFC 9180's Export-Only sentinel and cannot seal
    /// or open ciphertexts.
    ExportOnlyAead,
    /// The selected AEAD has no implementation in this module.
    ///
    /// Every encryption AEAD registered by RFC 9180 is implemented. This
    /// compatibility variant is retained for a future identifier added by a
    /// later registry revision.
    UnsupportedAead { aead_id: AeadId },
    /// The context's stored AEAD key does not have the selected algorithm's
    /// mandated length.
    InvalidAeadKeyLength {
        aead_id: AeadId,
        actual: usize,
        required: usize,
    },
    /// The context's derived nonce does not have the selected algorithm's
    /// mandated length.
    InvalidAeadNonceLength {
        aead_id: AeadId,
        actual: usize,
        required: usize,
    },
    /// AEAD authentication failed.
    ///
    /// This intentionally does not distinguish invalid ciphertext, AAD, key,
    /// or tag material, avoiding an authentication oracle at this boundary.
    AuthenticationFailed,
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputLengthTooLarge { requested } => write!(
                f,
                "HPKE labeled output length {requested} exceeds the RFC 9180 u16 limit"
            ),
            Self::InvalidPseudorandomKeyLength { actual, required } => write!(
                f,
                "HPKE pseudorandom key is {actual} bytes; HKDF requires at least {required} bytes"
            ),
            Self::HkdfOutputLengthTooLarge { requested, maximum } => write!(
                f,
                "HPKE HKDF output length {requested} exceeds the RFC 5869 limit of {maximum} bytes"
            ),
            Self::InvalidPskInputs {
                mode,
                has_psk,
                has_psk_id,
            } => write!(
                f,
                "invalid HPKE PSK inputs for {mode:?}: psk present={has_psk}, psk_id present={has_psk_id}"
            ),
            Self::UnsupportedKeyScheduleMode { mode } => write!(
                f,
                "HPKE key schedule mode {mode:?} is unsupported; only Base mode is implemented"
            ),
            Self::MessageLimitReached => {
                f.write_str("HPKE message limit reached; the sequence number must not wrap")
            }
            Self::ExportOnlyAead => f.write_str(
                "HPKE Export-Only AEAD cannot seal or open ciphertexts",
            ),
            Self::UnsupportedAead { aead_id } => write!(
                f,
                "HPKE AEAD {aead_id:?} is registered but unsupported by this implementation"
            ),
            Self::InvalidAeadKeyLength {
                aead_id,
                actual,
                required,
            } => write!(
                f,
                "HPKE AEAD {aead_id:?} key is {actual} bytes; expected {required} bytes"
            ),
            Self::InvalidAeadNonceLength {
                aead_id,
                actual,
                required,
            } => write!(
                f,
                "HPKE AEAD {aead_id:?} nonce is {actual} bytes; expected {required} bytes"
            ),
            Self::AuthenticationFailed => f.write_str("HPKE AEAD authentication failed"),
        }
    }
}

impl Error for HpkeError {}

/// IANA HPKE KEM identifiers registered by RFC 9180 §7.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum KemId {
    DhKemP256HkdfSha256 = 0x0010,
    DhKemP384HkdfSha384 = 0x0011,
    DhKemP521HkdfSha512 = 0x0012,
    DhKemX25519HkdfSha256 = 0x0020,
    DhKemX448HkdfSha512 = 0x0021,
}

impl KemId {
    /// The network-order identifier assigned to this KEM.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// IANA HPKE KDF identifiers registered by RFC 9180 §7.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum KdfId {
    HkdfSha256 = 0x0001,
    HkdfSha384 = 0x0002,
    HkdfSha512 = 0x0003,
}

impl KdfId {
    /// The network-order identifier assigned to this KDF.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    const fn hash_len(self) -> usize {
        match self {
            Self::HkdfSha256 => 32,
            Self::HkdfSha384 => 48,
            Self::HkdfSha512 => 64,
        }
    }
}

/// IANA HPKE AEAD identifiers registered by RFC 9180 §7.3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AeadId {
    AesGcm128 = 0x0001,
    AesGcm256 = 0x0002,
    ChaCha20Poly1305 = 0x0003,
    ExportOnly = 0xffff,
}

impl AeadId {
    /// The network-order identifier assigned to this AEAD.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    const fn key_len(self) -> usize {
        match self {
            Self::AesGcm128 => 16,
            Self::AesGcm256 | Self::ChaCha20Poly1305 => 32,
            Self::ExportOnly => 0,
        }
    }

    const fn nonce_len(self) -> usize {
        match self {
            Self::AesGcm128 | Self::AesGcm256 | Self::ChaCha20Poly1305 => 12,
            Self::ExportOnly => 0,
        }
    }
}

/// The RFC 9180 operating mode encoded as the first octet of the
/// `key_schedule_context`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode {
    /// Base mode: neither a PSK nor an authentication key is used.
    Base = 0,
    /// PSK mode.
    Psk = 1,
    /// Authenticated mode.
    Auth = 2,
    /// Authenticated PSK mode.
    AuthPsk = 3,
}

impl Mode {
    /// The one-octet network representation mandated by RFC 9180 §5.1.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    const fn requires_psk(self) -> bool {
        matches!(self, Self::Psk | Self::AuthPsk)
    }
}

/// Validates the PSK pair according to RFC 9180 `VerifyPSKInputs`.
///
/// A PSK and its identifier must either both be present or both be absent.
/// The PSK-bearing modes require both values; Base and Auth reject both values.
pub fn verify_psk_inputs(mode: Mode, psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeError> {
    let has_psk = !psk.is_empty();
    let has_psk_id = !psk_id.is_empty();
    let valid = has_psk == has_psk_id && has_psk == mode.requires_psk();

    if valid {
        Ok(())
    } else {
        Err(HpkeError::InvalidPskInputs {
            mode,
            has_psk,
            has_psk_id,
        })
    }
}

/// Secret HPKE key-schedule material derived by RFC 9180 §5.1.
///
/// All secret-bearing values use [`Zeroizing`] storage. This is raw schedule
/// material until it is consumed into [`BaseContext`]; KEM setup remains
/// outside this module.
pub struct KeySchedule {
    suite: HpkeSuite,
    mode: Mode,
    psk_id_hash: Zeroizing<Vec<u8>>,
    info_hash: Zeroizing<Vec<u8>>,
    key_schedule_context: Zeroizing<Vec<u8>>,
    secret: Zeroizing<Vec<u8>>,
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<Vec<u8>>,
    exporter_secret: Zeroizing<Vec<u8>>,
}

impl KeySchedule {
    /// The ciphersuite that derived this schedule.
    pub const fn suite(&self) -> HpkeSuite {
        self.suite
    }

    /// The selected HPKE mode.
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// `psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)`.
    pub fn psk_id_hash(&self) -> &[u8] {
        self.psk_id_hash.as_ref()
    }

    /// `info_hash = LabeledExtract("", "info_hash", info)`.
    pub fn info_hash(&self) -> &[u8] {
        self.info_hash.as_ref()
    }

    /// `mode || psk_id_hash || info_hash`.
    pub fn key_schedule_context(&self) -> &[u8] {
        self.key_schedule_context.as_ref()
    }

    /// `LabeledExtract(shared_secret, "secret", psk)`.
    pub fn secret(&self) -> &[u8] {
        self.secret.as_ref()
    }

    /// AEAD key material with the suite's RFC 9180 `Nk` byte length.
    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// AEAD base nonce material with the suite's RFC 9180 `Nn` byte length.
    pub fn base_nonce(&self) -> &[u8] {
        self.base_nonce.as_ref()
    }

    /// Exporter secret with the suite KDF's RFC 9180 `Nh` byte length.
    pub fn exporter_secret(&self) -> &[u8] {
        self.exporter_secret.as_ref()
    }

    /// Consume this Base-mode schedule into its stateful context core.
    ///
    /// This transfers, rather than copies, the derived key, base nonce, and
    /// exporter secret into a non-`Clone` context. The resulting context has
    /// RFC 9180 `Seal` / `Open` support for every registered encryption AEAD;
    /// it has no public nonce API.
    pub fn into_base_context(self) -> BaseContext {
        BaseContext::from_key_schedule(self)
    }
}

/// Stateful RFC 9180 Base-mode context core.
///
/// A KEM integration creates a [`KeySchedule`] from its already-established
/// shared secret, then consumes it with [`KeySchedule::into_base_context`].
/// This type owns the derived AEAD key, base nonce, exporter secret, and
/// sequence number. It exposes `Seal` / `Open` for RFC 9180's registered
/// encryption AEADs and deliberately has no manual nonce API.
/// Consequently it is not `SetupBaseS` / `SetupBaseR` and is not by itself an
/// interoperable HPKE encryption context.
///
/// The type intentionally does not implement `Clone`: duplicating its sequence
/// state could cause nonce reuse once an AEAD adapter consumes the context.
pub struct BaseContext {
    suite: HpkeSuite,
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<Vec<u8>>,
    exporter_secret: Zeroizing<Vec<u8>>,
    // RFC 9180 represents `seq` as an `Nn`-octet integer. All currently
    // registered non-Export-Only AEADs have Nn = 12, so keep the full 96-bit
    // value rather than truncating it to a machine integer.
    sequence: [u8; 12],
}

impl BaseContext {
    /// Construct the context core by consuming a Base-mode [`KeySchedule`].
    pub fn from_key_schedule(schedule: KeySchedule) -> Self {
        let KeySchedule {
            suite,
            mode,
            psk_id_hash: _,
            info_hash: _,
            key_schedule_context: _,
            secret: _,
            key,
            base_nonce,
            exporter_secret,
        } = schedule;
        debug_assert_eq!(mode, Mode::Base);

        Self {
            suite,
            key,
            base_nonce,
            exporter_secret,
            sequence: [0_u8; 12],
        }
    }

    /// Derive an exported secret using RFC 9180 §5.3:
    /// `LabeledExpand(exporter_secret, "sec", exporter_context, L)`.
    ///
    /// Export does not consume a message sequence number.
    pub fn export(&self, exporter_context: &[u8], output_len: usize) -> Result<Vec<u8>, HpkeError> {
        self.suite
            .labeled_expand(&self.exporter_secret, b"sec", exporter_context, output_len)
    }

    /// Encrypt `plaintext` with RFC 9180 `Seal(seq, aad, pt)`.
    ///
    /// This context supports every registered encryption AEAD. The
    /// caller-provided `aad` is passed directly to that AEAD and is therefore
    /// authenticated but not encrypted. The context increments its sequence
    /// number only after the AEAD operation has succeeded.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        self.ensure_encrypting_aead()?;
        let nonce = self.nonce_for_current_sequence()?;
        let ciphertext = self.seal_with_aead(&nonce, aad, plaintext)?;

        self.advance_after_success()?;
        Ok(ciphertext)
    }

    /// Decrypt `ciphertext` with RFC 9180 `Open(seq, aad, ct)`.
    ///
    /// Authentication failures deliberately return the single opaque
    /// [`HpkeError::AuthenticationFailed`] error. A failed open leaves the
    /// sequence unchanged, so the caller may retry the same message with the
    /// correct ciphertext or AAD; a successful open advances it exactly once.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        self.ensure_encrypting_aead()?;
        let nonce = self.nonce_for_current_sequence()?;
        let plaintext = self.open_with_aead(&nonce, aad, ciphertext)?;

        self.advance_after_success()?;
        Ok(plaintext)
    }

    /// Return the current operation's RFC 9180 nonce internally.
    ///
    /// This remains private so callers cannot manually manage nonces. A future
    /// AEAD operation must call [`Self::ensure_message_available`] before use,
    /// and [`Self::advance_after_success`] only after a successful operation.
    fn nonce_for_current_sequence(&self) -> Result<Vec<u8>, HpkeError> {
        self.ensure_message_available()?;
        Ok(compute_nonce(&self.base_nonce, &self.sequence))
    }

    /// Reject use of the sequence value that would require wraparound.
    fn ensure_message_available(&self) -> Result<(), HpkeError> {
        if self.sequence == [u8::MAX; 12] {
            Err(HpkeError::MessageLimitReached)
        } else {
            Ok(())
        }
    }

    /// Advance the sequence after a successful AEAD operation.
    fn advance_after_success(&mut self) -> Result<(), HpkeError> {
        self.ensure_message_available()?;
        for byte in self.sequence.iter_mut().rev() {
            let (incremented, carried) = byte.overflowing_add(1);
            *byte = incremented;
            if !carried {
                break;
            }
        }
        Ok(())
    }

    /// Borrow the derived key for the in-module AEAD adapter.
    fn aead_key(&self) -> &[u8] {
        self.key.as_ref()
    }

    fn ensure_encrypting_aead(&self) -> Result<(), HpkeError> {
        if self.suite.aead_id == AeadId::ExportOnly {
            Err(HpkeError::ExportOnlyAead)
        } else {
            Ok(())
        }
    }

    /// Encrypt with the selected AEAD after exact key and nonce validation.
    /// The `ExportOnly` sentinel intentionally does not have an AEAD.
    fn seal_with_aead(
        &self,
        nonce_bytes: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        match self.suite.aead_id {
            AeadId::ExportOnly => Err(HpkeError::ExportOnlyAead),
            AeadId::AesGcm128 => {
                let cipher = self.aes128gcm()?;
                let nonce = self.aes_gcm_nonce(nonce_bytes)?;
                cipher
                    .encrypt(
                        &nonce,
                        AesPayload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| HpkeError::AuthenticationFailed)
            }
            AeadId::AesGcm256 => {
                let cipher = self.aes256gcm()?;
                let nonce = self.aes_gcm_nonce(nonce_bytes)?;
                cipher
                    .encrypt(
                        &nonce,
                        AesPayload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| HpkeError::AuthenticationFailed)
            }
            AeadId::ChaCha20Poly1305 => {
                let (cipher, nonce) = self.chacha20poly1305(nonce_bytes)?;
                cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| HpkeError::AuthenticationFailed)
            }
        }
    }

    /// Decrypt with the selected AEAD. Authentication failures are opaque.
    fn open_with_aead(
        &self,
        nonce_bytes: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        match self.suite.aead_id {
            AeadId::ExportOnly => Err(HpkeError::ExportOnlyAead),
            AeadId::AesGcm128 => {
                let cipher = self.aes128gcm()?;
                let nonce = self.aes_gcm_nonce(nonce_bytes)?;
                cipher
                    .decrypt(
                        &nonce,
                        AesPayload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| HpkeError::AuthenticationFailed)
            }
            AeadId::AesGcm256 => {
                let cipher = self.aes256gcm()?;
                let nonce = self.aes_gcm_nonce(nonce_bytes)?;
                cipher
                    .decrypt(
                        &nonce,
                        AesPayload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| HpkeError::AuthenticationFailed)
            }
            AeadId::ChaCha20Poly1305 => {
                let (cipher, nonce) = self.chacha20poly1305(nonce_bytes)?;
                cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| HpkeError::AuthenticationFailed)
            }
        }
    }

    fn aes128gcm(&self) -> Result<Aes128Gcm, HpkeError> {
        self.validate_key_length(AeadId::AesGcm128)?;
        Aes128Gcm::new_from_slice(self.aead_key()).map_err(|_| HpkeError::InvalidAeadKeyLength {
            aead_id: AeadId::AesGcm128,
            actual: self.aead_key().len(),
            required: AeadId::AesGcm128.key_len(),
        })
    }

    fn aes256gcm(&self) -> Result<Aes256Gcm, HpkeError> {
        self.validate_key_length(AeadId::AesGcm256)?;
        Aes256Gcm::new_from_slice(self.aead_key()).map_err(|_| HpkeError::InvalidAeadKeyLength {
            aead_id: AeadId::AesGcm256,
            actual: self.aead_key().len(),
            required: AeadId::AesGcm256.key_len(),
        })
    }

    fn chacha20poly1305(
        &self,
        nonce_bytes: &[u8],
    ) -> Result<(ChaCha20Poly1305, ChaCha20Poly1305Nonce), HpkeError> {
        self.validate_key_length(AeadId::ChaCha20Poly1305)?;
        let key: &chacha20poly1305::Key = self.aead_key().into();
        let nonce = self.validate_chacha20poly1305_nonce(nonce_bytes)?;
        Ok((ChaCha20Poly1305::new(key), nonce))
    }

    fn validate_key_length(&self, aead_id: AeadId) -> Result<(), HpkeError> {
        let key_bytes = self.aead_key();
        if key_bytes.len() != aead_id.key_len() {
            return Err(HpkeError::InvalidAeadKeyLength {
                aead_id,
                actual: key_bytes.len(),
                required: aead_id.key_len(),
            });
        }
        Ok(())
    }

    fn aes_gcm_nonce(
        &self,
        nonce_bytes: &[u8],
    ) -> Result<AesGcmNonce<aes_gcm::aead::consts::U12>, HpkeError> {
        self.validate_nonce_length(nonce_bytes)?;
        AesGcmNonce::try_from(nonce_bytes).map_err(|_| HpkeError::InvalidAeadNonceLength {
            aead_id: self.suite.aead_id,
            actual: nonce_bytes.len(),
            required: self.suite.aead_id.nonce_len(),
        })
    }

    fn validate_chacha20poly1305_nonce(
        &self,
        nonce_bytes: &[u8],
    ) -> Result<ChaCha20Poly1305Nonce, HpkeError> {
        self.validate_nonce_length(nonce_bytes)?;
        let nonce: &ChaCha20Poly1305Nonce = nonce_bytes.into();
        Ok(nonce.to_owned())
    }

    fn validate_nonce_length(&self, nonce_bytes: &[u8]) -> Result<(), HpkeError> {
        let aead_id = self.suite.aead_id;
        if nonce_bytes.len() != aead_id.nonce_len() {
            return Err(HpkeError::InvalidAeadNonceLength {
                aead_id,
                actual: nonce_bytes.len(),
                required: aead_id.nonce_len(),
            });
        }
        Ok(())
    }
}

/// RFC 9180 `ComputeNonce(base_nonce, seq)`.
///
/// The sequence number is encoded as an `Nn`-octet big-endian integer and
/// XORed with the base nonce. This context supports the 96-bit (`Nn = 12`)
/// nonce length used by each registered non-Export-Only RFC 9180 AEAD.
fn compute_nonce(base_nonce: &[u8], sequence: &[u8; 12]) -> Vec<u8> {
    let mut nonce = base_nonce.to_vec();
    debug_assert_eq!(nonce.len(), sequence.len());
    for (nonce_byte, sequence_byte) in nonce.iter_mut().zip(sequence) {
        *nonce_byte ^= sequence_byte;
    }

    nonce
}

/// The algorithm identifiers defining one RFC 9180 HPKE cipher suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpkeSuite {
    kem_id: KemId,
    kdf_id: KdfId,
    aead_id: AeadId,
}

impl HpkeSuite {
    /// Construct a suite from registered KEM, KDF, and AEAD identifiers.
    pub const fn new(kem_id: KemId, kdf_id: KdfId, aead_id: AeadId) -> Self {
        Self {
            kem_id,
            kdf_id,
            aead_id,
        }
    }

    /// The KEM identifier selected for this suite.
    pub const fn kem_id(self) -> KemId {
        self.kem_id
    }

    /// The KDF identifier selected for this suite.
    pub const fn kdf_id(self) -> KdfId {
        self.kdf_id
    }

    /// The AEAD identifier selected for this suite.
    pub const fn aead_id(self) -> AeadId {
        self.aead_id
    }

    /// Build `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) ||
    /// I2OSP(aead_id, 2)` as defined in RFC 9180 §4.
    pub const fn suite_id(self) -> [u8; 10] {
        let kem_id = self.kem_id.as_u16().to_be_bytes();
        let kdf_id = self.kdf_id.as_u16().to_be_bytes();
        let aead_id = self.aead_id.as_u16().to_be_bytes();
        [
            b'H', b'P', b'K', b'E', kem_id[0], kem_id[1], kdf_id[0], kdf_id[1], aead_id[0],
            aead_id[1],
        ]
    }

    /// RFC 9180 `LabeledExtract(salt, label, ikm)`.
    ///
    /// The constructed input key material is
    /// `"HPKE-v1" || suite_id || label || ikm` before the selected HKDF-Extract.
    pub fn labeled_extract(self, salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
        let labeled_ikm = self.labeled_ikm(label, ikm);
        match self.kdf_id {
            KdfId::HkdfSha256 => Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm).0.to_vec(),
            KdfId::HkdfSha384 => Hkdf::<Sha384>::extract(Some(salt), &labeled_ikm).0.to_vec(),
            KdfId::HkdfSha512 => Hkdf::<Sha512>::extract(Some(salt), &labeled_ikm).0.to_vec(),
        }
    }

    /// RFC 9180 `LabeledExpand(prk, label, info, L)`.
    ///
    /// The selected HKDF expands with the info value
    /// `I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`.
    pub fn labeled_expand(
        self,
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, HpkeError> {
        if output_len > u16::MAX as usize {
            return Err(HpkeError::OutputLengthTooLarge {
                requested: output_len,
            });
        }

        let maximum = self.kdf_id.hash_len() * 255;
        if output_len > maximum {
            return Err(HpkeError::HkdfOutputLengthTooLarge {
                requested: output_len,
                maximum,
            });
        }

        let labeled_info = self.labeled_info(label, info, output_len as u16);
        let mut output = vec![0_u8; output_len];
        match self.kdf_id {
            KdfId::HkdfSha256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| {
                    HpkeError::InvalidPseudorandomKeyLength {
                        actual: prk.len(),
                        required: 32,
                    }
                })?;
                hkdf.expand(&labeled_info, &mut output).map_err(|_| {
                    HpkeError::HkdfOutputLengthTooLarge {
                        requested: output_len,
                        maximum: 32 * 255,
                    }
                })?;
            }
            KdfId::HkdfSha384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(prk).map_err(|_| {
                    HpkeError::InvalidPseudorandomKeyLength {
                        actual: prk.len(),
                        required: 48,
                    }
                })?;
                hkdf.expand(&labeled_info, &mut output).map_err(|_| {
                    HpkeError::HkdfOutputLengthTooLarge {
                        requested: output_len,
                        maximum: 48 * 255,
                    }
                })?;
            }
            KdfId::HkdfSha512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(prk).map_err(|_| {
                    HpkeError::InvalidPseudorandomKeyLength {
                        actual: prk.len(),
                        required: 64,
                    }
                })?;
                hkdf.expand(&labeled_info, &mut output).map_err(|_| {
                    HpkeError::HkdfOutputLengthTooLarge {
                        requested: output_len,
                        maximum: 64 * 255,
                    }
                })?;
            }
        }
        Ok(output)
    }

    fn labeled_ikm(self, label: &[u8], ikm: &[u8]) -> Vec<u8> {
        let suite_id = self.suite_id();
        let mut output =
            Vec::with_capacity(HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len());
        output.extend_from_slice(HPKE_VERSION_LABEL);
        output.extend_from_slice(&suite_id);
        output.extend_from_slice(label);
        output.extend_from_slice(ikm);
        output
    }

    fn labeled_info(self, label: &[u8], info: &[u8], output_len: u16) -> Vec<u8> {
        let suite_id = self.suite_id();
        let mut output = Vec::with_capacity(
            2 + HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + info.len(),
        );
        output.extend_from_slice(&output_len.to_be_bytes());
        output.extend_from_slice(HPKE_VERSION_LABEL);
        output.extend_from_slice(&suite_id);
        output.extend_from_slice(label);
        output.extend_from_slice(info);
        output
    }
}

/// Derives the RFC 9180 Base-mode key schedule.
///
/// This implements the `KeySchedule` procedure in RFC 9180 §5.1 exactly for
/// Base mode.  The `Mode` enum and [`verify_psk_inputs`] retain the RFC's full
/// validation semantics so callers cannot accidentally accept an invalid PSK
/// pair while the remaining modes are intentionally not implemented here.
pub fn key_schedule(
    suite: HpkeSuite,
    mode: Mode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<KeySchedule, HpkeError> {
    verify_psk_inputs(mode, psk, psk_id)?;
    if mode != Mode::Base {
        return Err(HpkeError::UnsupportedKeyScheduleMode { mode });
    }

    let psk_id_hash = Zeroizing::new(suite.labeled_extract(b"", b"psk_id_hash", psk_id));
    let info_hash = Zeroizing::new(suite.labeled_extract(b"", b"info_hash", info));
    let mut key_schedule_context =
        Zeroizing::new(Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len()));
    key_schedule_context.push(mode.as_u8());
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    let secret = Zeroizing::new(suite.labeled_extract(shared_secret, b"secret", psk));
    let key = Zeroizing::new(suite.labeled_expand(
        &secret,
        b"key",
        &key_schedule_context,
        suite.aead_id.key_len(),
    )?);
    let base_nonce = Zeroizing::new(suite.labeled_expand(
        &secret,
        b"base_nonce",
        &key_schedule_context,
        suite.aead_id.nonce_len(),
    )?);
    let exporter_secret = Zeroizing::new(suite.labeled_expand(
        &secret,
        b"exp",
        &key_schedule_context,
        suite.kdf_id.hash_len(),
    )?);

    Ok(KeySchedule {
        suite,
        mode,
        psk_id_hash,
        info_hash,
        key_schedule_context,
        secret,
        key,
        base_nonce,
        exporter_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUITE: HpkeSuite = HpkeSuite::new(
        KemId::DhKemX25519HkdfSha256,
        KdfId::HkdfSha256,
        AeadId::ChaCha20Poly1305,
    );

    #[test]
    fn suite_id_uses_network_order_registered_identifiers() {
        assert_eq!(
            SUITE.suite_id(),
            [b'H', b'P', b'K', b'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x03]
        );
    }

    #[test]
    fn labeled_extract_prefix_is_exactly_rfc_9180() {
        assert_eq!(
            SUITE.labeled_ikm(b"eae_prk", b"input"),
            b"HPKE-v1HPKE\x00\x20\x00\x01\x00\x03eae_prkinput"
        );
    }

    #[test]
    fn labeled_expand_prefix_is_exactly_rfc_9180() {
        assert_eq!(
            SUITE.labeled_info(b"shared_secret", b"context", 0x0120),
            b"\x01\x20HPKE-v1HPKE\x00\x20\x00\x01\x00\x03shared_secretcontext"
        );
    }

    #[test]
    fn labeled_expand_rejects_short_prk_with_typed_error() {
        assert_eq!(
            SUITE.labeled_expand(&[0_u8; 31], b"key", b"", 16),
            Err(HpkeError::InvalidPseudorandomKeyLength {
                actual: 31,
                required: 32,
            })
        );
    }

    #[test]
    fn base_key_schedule_matches_independent_rfc_9180_construction() {
        // Generated by an independent RFC 5869 HMAC-SHA-256 construction with
        // the RFC 9180 labels and their prescribed order.
        let shared_secret: Vec<u8> = (0_u8..32).collect();
        let schedule = key_schedule(
            SUITE,
            Mode::Base,
            &shared_secret,
            b"deterministic HPKE schedule",
            b"",
            b"",
        )
        .unwrap();

        assert_eq!(schedule.mode(), Mode::Base);
        assert_eq!(
            schedule.psk_id_hash(),
            hex::decode("431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5")
                .unwrap()
        );
        assert_eq!(
            schedule.info_hash(),
            hex::decode("da8b232d7a1bb877ed42fec8d0652ad8beaa711ade34ec9c3fe31cda838722c5")
                .unwrap()
        );
        assert_eq!(
            schedule.key_schedule_context(),
            hex::decode(concat!(
                "00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5",
                "da8b232d7a1bb877ed42fec8d0652ad8beaa711ade34ec9c3fe31cda838722c5"
            ))
            .unwrap()
        );
        assert_eq!(
            schedule.secret(),
            hex::decode("ac1f1ef7435752f5b7180ef73da53b64458b717a9bd7f579747ef567d88a6b83")
                .unwrap()
        );
        assert_eq!(
            schedule.key(),
            hex::decode("02783f111d0d5ec1a06795001292a4a80ccd92cea687ba8f317851c5c66b4fd9")
                .unwrap()
        );
        assert_eq!(
            schedule.base_nonce(),
            hex::decode("567a0a58cbdf4629e88a36a4").unwrap()
        );
        assert_eq!(
            schedule.exporter_secret(),
            hex::decode("9178c5d0ea6fa8b47de305f48da71bd030339fa423047b39628cd24452368e17")
                .unwrap()
        );
    }

    #[test]
    fn verify_psk_inputs_uses_rfc_9180_presence_semantics() {
        assert_eq!(verify_psk_inputs(Mode::Base, b"", b""), Ok(()));
        assert_eq!(verify_psk_inputs(Mode::Psk, b"psk", b"psk-id"), Ok(()));
        assert_eq!(
            verify_psk_inputs(Mode::Base, b"psk", b"psk-id"),
            Err(HpkeError::InvalidPskInputs {
                mode: Mode::Base,
                has_psk: true,
                has_psk_id: true,
            })
        );
        assert_eq!(
            verify_psk_inputs(Mode::Psk, b"psk", b""),
            Err(HpkeError::InvalidPskInputs {
                mode: Mode::Psk,
                has_psk: true,
                has_psk_id: false,
            })
        );
        assert_eq!(
            verify_psk_inputs(Mode::AuthPsk, b"", b"psk-id"),
            Err(HpkeError::InvalidPskInputs {
                mode: Mode::AuthPsk,
                has_psk: false,
                has_psk_id: true,
            })
        );
        assert_eq!(
            verify_psk_inputs(Mode::Auth, b"psk", b"psk-id"),
            Err(HpkeError::InvalidPskInputs {
                mode: Mode::Auth,
                has_psk: true,
                has_psk_id: true,
            })
        );
    }

    #[test]
    fn key_schedule_rejects_non_base_modes_after_validating_psk_inputs() {
        assert_eq!(Mode::Base.as_u8(), 0);
        assert_eq!(Mode::Psk.as_u8(), 1);
        assert_eq!(Mode::Auth.as_u8(), 2);
        assert_eq!(Mode::AuthPsk.as_u8(), 3);

        assert!(matches!(
            key_schedule(SUITE, Mode::Psk, &[7_u8; 32], b"", b"psk", b"psk-id"),
            Err(HpkeError::UnsupportedKeyScheduleMode { mode: Mode::Psk })
        ));
    }

    #[test]
    fn key_schedule_uses_registered_aead_key_and_nonce_dimensions() {
        let shared_secret = [11_u8; 32];
        let aes_128 = HpkeSuite::new(
            KemId::DhKemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::AesGcm128,
        );
        let aes_256 = HpkeSuite::new(
            KemId::DhKemX25519HkdfSha256,
            KdfId::HkdfSha256,
            AeadId::AesGcm256,
        );

        let aes_128_schedule =
            key_schedule(aes_128, Mode::Base, &shared_secret, b"", b"", b"").unwrap();
        let aes_256_schedule =
            key_schedule(aes_256, Mode::Base, &shared_secret, b"", b"", b"").unwrap();
        let chacha_schedule =
            key_schedule(SUITE, Mode::Base, &shared_secret, b"", b"", b"").unwrap();

        assert_eq!(
            (
                aes_128_schedule.key().len(),
                aes_128_schedule.base_nonce().len()
            ),
            (16, 12)
        );
        assert_eq!(
            (
                aes_256_schedule.key().len(),
                aes_256_schedule.base_nonce().len()
            ),
            (32, 12)
        );
        assert_eq!(
            (
                chacha_schedule.key().len(),
                chacha_schedule.base_nonce().len()
            ),
            (32, 12)
        );
        assert_eq!(chacha_schedule.exporter_secret().len(), 32);
    }

    fn known_base_context() -> BaseContext {
        let shared_secret: Vec<u8> = (0_u8..32).collect();
        key_schedule(
            SUITE,
            Mode::Base,
            &shared_secret,
            b"deterministic HPKE schedule",
            b"",
            b"",
        )
        .unwrap()
        .into_base_context()
    }

    fn base_context_for(aead_id: AeadId) -> BaseContext {
        let suite = HpkeSuite::new(KemId::DhKemX25519HkdfSha256, KdfId::HkdfSha256, aead_id);
        key_schedule(suite, Mode::Base, &[19_u8; 32], b"", b"", b"")
            .unwrap()
            .into_base_context()
    }

    #[test]
    fn base_context_computes_rfc_9180_nonces_for_sequences_zero_and_one() {
        let mut context = known_base_context();

        assert_eq!(context.aead_key().len(), 32);
        assert_eq!(
            context.nonce_for_current_sequence().unwrap(),
            hex::decode("567a0a58cbdf4629e88a36a4").unwrap()
        );

        context.advance_after_success().unwrap();
        assert_eq!(
            context.nonce_for_current_sequence().unwrap(),
            hex::decode("567a0a58cbdf4629e88a36a5").unwrap()
        );

        // The sequence is a full 96-bit Nn-octet integer, not a truncated
        // machine counter: its high-order octet also affects the nonce.
        context.sequence = [1_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            context.nonce_for_current_sequence().unwrap(),
            hex::decode("577a0a58cbdf4629e88a36a4").unwrap()
        );
    }

    #[test]
    fn base_context_export_uses_rfc_9180_sec_label_without_consuming_sequence() {
        let context = known_base_context();

        assert_eq!(
            context.export(b"export-context", 32).unwrap(),
            hex::decode("965c10eb08cf101f0961c78689c2ef2fb2f7159c70f4bc0d3a2f1d14baa3efb5")
                .unwrap()
        );
        assert_eq!(
            context.nonce_for_current_sequence().unwrap(),
            hex::decode("567a0a58cbdf4629e88a36a4").unwrap()
        );
    }

    #[test]
    fn base_context_export_enforces_hkdf_output_limit() {
        let context = known_base_context();

        assert_eq!(
            context.export(b"", 32 * 255 + 1),
            Err(HpkeError::HkdfOutputLengthTooLarge {
                requested: 32 * 255 + 1,
                maximum: 32 * 255,
            })
        );
    }

    #[test]
    fn base_context_rejects_sequence_exhaustion_before_nonce_reuse() {
        let mut context = known_base_context();
        context.sequence = [u8::MAX; 12];

        assert_eq!(
            context.nonce_for_current_sequence(),
            Err(HpkeError::MessageLimitReached)
        );
        assert_eq!(
            context.advance_after_success(),
            Err(HpkeError::MessageLimitReached)
        );
    }

    #[test]
    fn base_context_seal_matches_rfc_8439_chacha20_poly1305_vector() {
        // RFC 8439 §2.8.2. This directly exercises HPKE's registered
        // ChaCha20-Poly1305 AEAD with a 96-bit `base_nonce` at sequence zero.
        let mut context = BaseContext {
            suite: SUITE,
            key: Zeroizing::new(
                hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                    .unwrap(),
            ),
            base_nonce: Zeroizing::new(hex::decode("070000004041424344454647").unwrap()),
            exporter_secret: Zeroizing::new(vec![0_u8; 32]),
            sequence: [0_u8; 12],
        };
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ciphertext = context.seal(&aad, plaintext).unwrap();

        assert_eq!(
            ciphertext,
            hex::decode(concat!(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
                "3ff4def08e4b7a9de576d26586cec64b6116",
                "1ae10b594f09e26a7e902ecbd0600691"
            ))
            .unwrap()
        );
        assert_eq!(context.sequence, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn base_context_open_authentication_failure_does_not_advance_sequence() {
        let mut sender = known_base_context();
        let mut receiver = known_base_context();
        let aad = b"caller supplied associated data";
        let plaintext = b"confidential HPKE payload";
        let ciphertext = sender.seal(aad, plaintext).unwrap();
        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 0x80;
        let initial_nonce = receiver.nonce_for_current_sequence().unwrap();

        assert_eq!(
            receiver.open(aad, &tampered_ciphertext),
            Err(HpkeError::AuthenticationFailed)
        );
        assert_eq!(
            receiver.nonce_for_current_sequence().unwrap(),
            initial_nonce
        );
        assert_eq!(receiver.sequence, [0_u8; 12]);

        assert_eq!(receiver.open(aad, &ciphertext).unwrap(), plaintext);
        assert_eq!(receiver.sequence, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn base_context_open_rejects_incorrect_aad_without_advancing_sequence() {
        let mut sender = known_base_context();
        let mut receiver = known_base_context();
        let ciphertext = sender.seal(b"correct AAD", b"plaintext").unwrap();

        assert_eq!(
            receiver.open(b"incorrect AAD", &ciphertext),
            Err(HpkeError::AuthenticationFailed)
        );
        assert_eq!(receiver.sequence, [0_u8; 12]);
        assert_eq!(
            receiver.open(b"correct AAD", &ciphertext).unwrap(),
            b"plaintext"
        );
        assert_eq!(receiver.sequence, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn base_context_rejects_export_only_without_consuming_sequence() {
        let mut export_only = base_context_for(AeadId::ExportOnly);
        assert_eq!(export_only.seal(b"", b""), Err(HpkeError::ExportOnlyAead));
        assert_eq!(export_only.open(b"", b""), Err(HpkeError::ExportOnlyAead));
        assert_eq!(export_only.sequence, [0_u8; 12]);
    }
}
