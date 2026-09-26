//! Versioned signatures over HPKE transport bindings.
//!
//! This module provides an application-layer signature binding for an HPKE
//! message.  It is deliberately **not** RFC 9180 Auth mode: Auth mode has a
//! KEM-authentication construction and wire contract of its own, whereas this
//! module signs a canonical representation of an already-produced HPKE
//! transport message.  Applications that use it must name this protocol
//! separately and must not advertise it as HPKE Auth mode.
//!
//! The binding is generic over [`SignAlgorithm`], so it does not select or
//! privilege a particular signature scheme.  A signature covers the protocol
//! version, all three HPKE suite identifiers, the HPKE mode, recipient key
//! identifier, `info`, encapsulation, AAD, and ciphertext.  The envelope's
//! fields are intentionally inaccessible until [`SignedHpkeEnvelope::verify`]
//! succeeds; that makes signature verification an explicit gate before the
//! caller passes the ciphertext to HPKE `Open` or performs any
//! plaintext-dependent processing.
//!
//! This is an in-memory binding layer, not a general wire codec.  A transport
//! codec may construct an envelope with [`SignedHpkeEnvelope::from_parts`],
//! but it must treat it as untrusted and call `verify` before using any bound
//! field.  The canonical transcript format below is stable for version 1 and
//! uses fixed-width, big-endian length prefixes to avoid concatenation
//! ambiguity.

use std::{error::Error, fmt, marker::PhantomData};

use crate::{
    error::CryptError,
    hpke::{HpkeSuite, Mode},
    sign::SignAlgorithm,
};

/// Domain-separation label for version 1 Signed-HPKE transcripts.
pub const SIGNED_HPKE_V1_LABEL: &[u8] = b"crypt_guard:signed-hpke";

/// The only Signed-HPKE envelope version currently emitted by this crate.
pub const SIGNED_HPKE_V1: u16 = 1;

/// Borrowed request data for producing a version-1 Signed-HPKE envelope.
///
/// This is deliberately a typed request instead of a long positional function
/// argument list. Each byte slice is copied into the returned envelope, and
/// each one is included exactly once in the canonical signed transcript.
#[derive(Clone, Copy)]
pub struct SignedHpkeBinding<'a> {
    /// HPKE KEM, KDF, and AEAD identifiers.
    pub suite: HpkeSuite,
    /// The HPKE mode marker to bind. This does not turn this layer into RFC
    /// 9180 Auth mode.
    pub mode: Mode,
    /// Application-defined identifier for the intended recipient key.
    pub recipient_key_id: &'a [u8],
    /// HPKE `info` passed during context setup.
    pub info: &'a [u8],
    /// HPKE KEM encapsulation (`enc`).
    pub encapsulation: &'a [u8],
    /// HPKE AEAD associated data.
    pub aad: &'a [u8],
    /// HPKE AEAD ciphertext, including its authentication tag.
    pub ciphertext: &'a [u8],
}

/// Transport-decoded parts for an untrusted Signed-HPKE envelope.
///
/// A codec can deserialize its own wire representation into this type and
/// pass it to [`SignedHpkeEnvelope::from_parts`]. None of its fields are
/// authenticated merely by constructing it; use [`SignedHpkeEnvelope::verify`]
/// before consuming them.
pub struct SignedHpkeEnvelopeParts<S> {
    /// Claimed Signed-HPKE protocol version.
    pub version: u16,
    /// Claimed HPKE cipher suite.
    pub suite: HpkeSuite,
    /// Claimed HPKE mode.
    pub mode: Mode,
    /// Claimed recipient key identifier.
    pub recipient_key_id: Vec<u8>,
    /// Claimed HPKE `info`.
    pub info: Vec<u8>,
    /// Claimed HPKE KEM encapsulation.
    pub encapsulation: Vec<u8>,
    /// Claimed HPKE AEAD associated data.
    pub aad: Vec<u8>,
    /// Claimed HPKE AEAD ciphertext.
    pub ciphertext: Vec<u8>,
    /// The signature decoded by the transport codec.
    pub signature: S,
}

/// Errors produced by the Signed-HPKE application binding.
#[derive(Debug)]
pub enum SignedHpkeError {
    /// A decoded envelope uses a protocol version this implementation cannot
    /// authenticate or expose.
    UnsupportedVersion { version: u16 },
    /// A field cannot be represented in the version-1 canonical transcript,
    /// which uses a four-octet length prefix for variable-sized data.
    FieldTooLong { field: &'static str, length: usize },
    /// The selected generic signature backend could not produce a signature.
    Signing(CryptError),
    /// The selected generic signature backend rejected the signature.
    SignatureVerification(CryptError),
}

impl fmt::Display for SignedHpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported Signed-HPKE envelope version {version}")
            }
            Self::FieldTooLong { field, length } => write!(
                f,
                "Signed-HPKE field {field} is {length} bytes and exceeds the version-1 u32 limit"
            ),
            Self::Signing(error) => write!(f, "Signed-HPKE signing failed: {error}"),
            Self::SignatureVerification(error) => {
                write!(f, "Signed-HPKE signature verification failed: {error}")
            }
        }
    }
}

impl Error for SignedHpkeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Signing(error) | Self::SignatureVerification(error) => Some(error),
            Self::UnsupportedVersion { .. } | Self::FieldTooLong { .. } => None,
        }
    }
}

/// A received Signed-HPKE transport envelope awaiting verification.
///
/// Its signed fields are private.  This prevents an API consumer from using
/// an attacker-controlled encapsulation, AAD, or ciphertext accidentally
/// before the associated signature is verified.
pub struct SignedHpkeEnvelope<A: SignAlgorithm> {
    version: u16,
    suite: HpkeSuite,
    mode: Mode,
    recipient_key_id: Vec<u8>,
    info: Vec<u8>,
    encapsulation: Vec<u8>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: A::Sig,
}

impl<A: SignAlgorithm> SignedHpkeEnvelope<A> {
    /// Sign a new version-1 transport binding with `A`.
    ///
    /// `binding.encapsulation` and `binding.ciphertext` must come from the
    /// same HPKE sender context. The caller supplies `recipient_key_id` as an
    /// application identifier; its semantics are intentionally
    /// application-defined, but its exact bytes are authenticated.
    pub fn sign(
        signing_key: &A::SigningKey,
        binding: SignedHpkeBinding<'_>,
    ) -> Result<Self, SignedHpkeError> {
        let transcript = canonical_transcript(SIGNED_HPKE_V1, binding)?;
        let signature = A::sign(signing_key, &transcript).map_err(SignedHpkeError::Signing)?;
        Ok(Self {
            version: SIGNED_HPKE_V1,
            suite: binding.suite,
            mode: binding.mode,
            recipient_key_id: binding.recipient_key_id.to_vec(),
            info: binding.info.to_vec(),
            encapsulation: binding.encapsulation.to_vec(),
            aad: binding.aad.to_vec(),
            ciphertext: binding.ciphertext.to_vec(),
            signature,
        })
    }

    /// Construct an untrusted envelope from transport-decoded parts.
    ///
    /// This function performs no signature verification.  It exists for a
    /// codec at a trust boundary; callers must immediately use [`Self::verify`]
    /// and only access fields through the returned [`VerifiedSignedHpkeEnvelope`].
    pub fn from_parts(parts: SignedHpkeEnvelopeParts<A::Sig>) -> Self {
        Self {
            version: parts.version,
            suite: parts.suite,
            mode: parts.mode,
            recipient_key_id: parts.recipient_key_id,
            info: parts.info,
            encapsulation: parts.encapsulation,
            aad: parts.aad,
            ciphertext: parts.ciphertext,
            signature: parts.signature,
        }
    }

    /// Borrow the opaque signature for transport serialization.
    ///
    /// The signed fields remain inaccessible until verification succeeds.
    pub fn signature(&self) -> &A::Sig {
        &self.signature
    }

    /// Verify the canonical transport binding and return the verified view.
    ///
    /// A version check occurs before invoking the signature backend.  A
    /// successful return is the sole public path to the encapsulation, AAD,
    /// ciphertext, and other signed metadata.
    pub fn verify(
        &self,
        verifying_key: &A::VerifyingKey,
    ) -> Result<VerifiedSignedHpkeEnvelope<'_, A>, SignedHpkeError> {
        if self.version != SIGNED_HPKE_V1 {
            return Err(SignedHpkeError::UnsupportedVersion {
                version: self.version,
            });
        }

        let transcript = self.canonical_transcript()?;
        A::verify(verifying_key, &transcript, &self.signature)
            .map_err(SignedHpkeError::SignatureVerification)?;
        Ok(VerifiedSignedHpkeEnvelope {
            envelope: self,
            algorithm: PhantomData,
        })
    }

    fn canonical_transcript(&self) -> Result<Vec<u8>, SignedHpkeError> {
        canonical_transcript(
            self.version,
            SignedHpkeBinding {
                suite: self.suite,
                mode: self.mode,
                recipient_key_id: &self.recipient_key_id,
                info: &self.info,
                encapsulation: &self.encapsulation,
                aad: &self.aad,
                ciphertext: &self.ciphertext,
            },
        )
    }
}

/// A signed HPKE transport envelope after successful signature verification.
///
/// This borrows the original envelope, cannot be constructed directly, and
/// exposes only authenticated values.  Pass `encapsulation`, `info`, `aad`,
/// and `ciphertext` from this value into the matching HPKE receive flow; do
/// not substitute externally supplied values after verification.
pub struct VerifiedSignedHpkeEnvelope<'a, A: SignAlgorithm> {
    envelope: &'a SignedHpkeEnvelope<A>,
    algorithm: PhantomData<A>,
}

impl<'a, A: SignAlgorithm> VerifiedSignedHpkeEnvelope<'a, A> {
    /// Authenticated Signed-HPKE protocol version.
    pub const fn version(&self) -> u16 {
        self.envelope.version
    }

    /// Authenticated HPKE cipher suite.
    pub const fn suite(&self) -> HpkeSuite {
        self.envelope.suite
    }

    /// Authenticated HPKE mode marker.
    ///
    /// This binding does not implement RFC 9180 Auth mode; it merely commits
    /// the caller-selected HPKE mode byte to the application signature.
    pub const fn mode(&self) -> Mode {
        self.envelope.mode
    }

    /// Application-defined recipient key identifier covered by the signature.
    pub fn recipient_key_id(&self) -> &[u8] {
        &self.envelope.recipient_key_id
    }

    /// HPKE `info` bytes covered by the signature.
    pub fn info(&self) -> &[u8] {
        &self.envelope.info
    }

    /// HPKE KEM encapsulation covered by the signature.
    pub fn encapsulation(&self) -> &[u8] {
        &self.envelope.encapsulation
    }

    /// HPKE AEAD associated data covered by the signature.
    pub fn aad(&self) -> &[u8] {
        &self.envelope.aad
    }

    /// HPKE AEAD ciphertext covered by the signature.
    pub fn ciphertext(&self) -> &[u8] {
        &self.envelope.ciphertext
    }
}

fn canonical_transcript(
    version: u16,
    binding: SignedHpkeBinding<'_>,
) -> Result<Vec<u8>, SignedHpkeError> {
    let mut transcript = Vec::with_capacity(
        SIGNED_HPKE_V1_LABEL.len()
            + 2
            + 10
            + 1
            + (4 * 5)
            + binding.recipient_key_id.len()
            + binding.info.len()
            + binding.encapsulation.len()
            + binding.aad.len()
            + binding.ciphertext.len(),
    );

    transcript.extend_from_slice(SIGNED_HPKE_V1_LABEL);
    transcript.extend_from_slice(&version.to_be_bytes());
    transcript.extend_from_slice(&binding.suite.suite_id());
    transcript.push(binding.mode.as_u8());
    append_field(
        &mut transcript,
        "recipient_key_id",
        binding.recipient_key_id,
    )?;
    append_field(&mut transcript, "info", binding.info)?;
    append_field(&mut transcript, "encapsulation", binding.encapsulation)?;
    append_field(&mut transcript, "aad", binding.aad)?;
    append_field(&mut transcript, "ciphertext", binding.ciphertext)?;
    Ok(transcript)
}

fn append_field(
    transcript: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
) -> Result<(), SignedHpkeError> {
    let length = u32::try_from(value.len()).map_err(|_| SignedHpkeError::FieldTooLong {
        field,
        length: value.len(),
    })?;
    transcript.extend_from_slice(&length.to_be_bytes());
    transcript.extend_from_slice(value);
    Ok(())
}
