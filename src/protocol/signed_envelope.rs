//! Versioned signatures over CGv2 envelope bindings.
//!
//! This module adds an application-layer signature over a canonical,
//! in-memory representation of an already-produced [`Envelope`]. It does not
//! change the CGv2 envelope wire format and is generic over
//! [`SignAlgorithm`], so callers select the signature scheme.
//!
//! The signature commits to the version-1 domain-separation label, the CGv2
//! envelope's validated canonical representation, an
//! application-defined recipient key identifier, and application metadata.
//! Signed fields remain private until [`SignedEnvelope::verify`] succeeds;
//! the returned [`VerifiedSignedEnvelope`] is the only public way to read
//! them.
//!
//! # Trust boundary and non-goals
//! This is an in-memory binding layer, not an outer wire codec. In particular,
//! it does not bind exact received wire bytes: a transport codec first parses
//! its input into [`SignedEnvelopeParts`], and verification signs a validated
//! canonical envelope representation. It provides neither
//! sender authorization, recipient authorization, nor replay protection.
//! Applications must define and enforce those policies, as well as transport
//! framing and persistence requirements.
//!
//! Version 1 uses big-endian four-octet length prefixes for variable-sized
//! transcript fields to avoid concatenation ambiguity.

use std::{error::Error, fmt, marker::PhantomData};

use crate::{error::CryptError, protocol::envelope::Envelope, sign::SignAlgorithm};

/// Domain-separation label for version-1 signed CGv2 envelope transcripts.
pub const SIGNED_ENVELOPE_V1_LABEL: &[u8] = b"crypt_guard:signed-envelope";

/// The only signed CGv2 envelope version currently emitted by this crate.
pub const SIGNED_ENVELOPE_V1: u16 = 1;

/// Transport-decoded, untrusted parts of a signed CGv2 envelope.
///
/// A transport codec can deserialize its own outer representation into this
/// type and pass it to [`SignedEnvelope::from_parts`]. Constructing this type
/// or a `SignedEnvelope` from it does not authenticate any field; call
/// [`SignedEnvelope::verify`] before using the envelope, recipient key ID, or
/// metadata.
pub struct SignedEnvelopeParts<S> {
    /// Claimed signed-envelope protocol version.
    pub version: u16,
    /// Claimed CGv2 envelope.
    pub envelope: Envelope,
    /// Claimed application-defined recipient key identifier.
    pub recipient_key_id: Vec<u8>,
    /// Claimed application metadata.
    pub metadata: Vec<u8>,
    /// Signature decoded by the transport codec.
    pub signature: S,
}

/// Errors produced by the signed CGv2 envelope binding.
#[derive(Debug)]
pub enum SignedEnvelopeError {
    /// A decoded envelope uses a version this implementation cannot authenticate
    /// or expose.
    UnsupportedVersion {
        /// The unsupported claimed version.
        version: u16,
    },
    /// A field cannot be represented in the version-1 canonical transcript,
    /// which uses a four-octet length prefix for variable-sized data.
    FieldTooLong {
        /// Stable canonical-transcript field name.
        field: &'static str,
        /// Field size that could not fit in a `u32` length prefix.
        length: usize,
    },
    /// The claimed CGv2 envelope could not be serialized into, or reparsed as,
    /// a canonical CGv2 envelope.
    EnvelopeSerialization(CryptError),
    /// The selected generic signature backend could not produce a signature.
    Signing(CryptError),
    /// The selected generic signature backend rejected the signature.
    SignatureVerification(CryptError),
}

impl fmt::Display for SignedEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported signed-envelope version {version}")
            }
            Self::FieldTooLong { field, length } => write!(
                f,
                "signed-envelope field {field} is {length} bytes and exceeds the version-1 u32 limit"
            ),
            Self::EnvelopeSerialization(error) => {
                write!(f, "signed-envelope canonical serialization failed: {error}")
            }
            Self::Signing(error) => write!(f, "signed-envelope signing failed: {error}"),
            Self::SignatureVerification(error) => {
                write!(f, "signed-envelope signature verification failed: {error}")
            }
        }
    }
}

impl Error for SignedEnvelopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EnvelopeSerialization(error)
            | Self::Signing(error)
            | Self::SignatureVerification(error) => Some(error),
            Self::UnsupportedVersion { .. } | Self::FieldTooLong { .. } => None,
        }
    }
}

/// A CGv2 envelope awaiting signature verification.
///
/// Its bound fields are private so that callers cannot accidentally use an
/// attacker-controlled envelope, recipient key ID, or metadata before calling
/// [`Self::verify`].
pub struct SignedEnvelope<A: SignAlgorithm> {
    version: u16,
    envelope: Envelope,
    recipient_key_id: Vec<u8>,
    metadata: Vec<u8>,
    signature: A::Sig,
}

impl<A: SignAlgorithm> SignedEnvelope<A> {
    /// Sign a new version-1 CGv2 envelope binding with `A`.
    ///
    /// `envelope` must be the same envelope the application intends to
    /// transmit or retain. `recipient_key_id` and `metadata` are
    /// application-defined, but their exact bytes are authenticated.
    ///
    /// # Errors
    /// Returns [`SignedEnvelopeError::EnvelopeSerialization`] if `envelope`
    /// cannot be represented as a parser-canonical CGv2 envelope,
    /// [`SignedEnvelopeError::FieldTooLong`] if a transcript field cannot be
    /// encoded with a version-1 `u32` length prefix, or
    /// [`SignedEnvelopeError::Signing`] if `A` rejects the signing operation.
    pub fn sign(
        signing_key: &A::SigningKey,
        envelope: Envelope,
        recipient_key_id: &[u8],
        metadata: &[u8],
    ) -> Result<Self, SignedEnvelopeError> {
        let transcript =
            canonical_transcript(SIGNED_ENVELOPE_V1, &envelope, recipient_key_id, metadata)?;
        let signature = A::sign(signing_key, &transcript).map_err(SignedEnvelopeError::Signing)?;

        Ok(Self {
            version: SIGNED_ENVELOPE_V1,
            envelope,
            recipient_key_id: recipient_key_id.to_vec(),
            metadata: metadata.to_vec(),
            signature,
        })
    }

    /// Construct an untrusted signed envelope from transport-decoded parts.
    ///
    /// This function does not validate the version or signature. Callers at a
    /// transport trust boundary must call [`Self::verify`] before reading any
    /// bound field.
    pub fn from_parts(parts: SignedEnvelopeParts<A::Sig>) -> Self {
        Self {
            version: parts.version,
            envelope: parts.envelope,
            recipient_key_id: parts.recipient_key_id,
            metadata: parts.metadata,
            signature: parts.signature,
        }
    }

    /// Borrow the opaque signature for outer transport serialization.
    ///
    /// This does not make any bound field authenticated or accessible.
    pub fn signature(&self) -> &A::Sig {
        &self.signature
    }

    /// Verify this binding and return a view of authenticated fields.
    ///
    /// The version is checked before invoking the signature backend. A
    /// successful return is the sole public path to the envelope, recipient
    /// key ID, and metadata.
    ///
    /// # Errors
    /// Returns [`SignedEnvelopeError::UnsupportedVersion`] for a version other
    /// than [`SIGNED_ENVELOPE_V1`], [`SignedEnvelopeError::EnvelopeSerialization`]
    /// for a noncanonical claimed CGv2 envelope,
    /// [`SignedEnvelopeError::FieldTooLong`] for an unrepresentable transcript
    /// field, or
    /// [`SignedEnvelopeError::SignatureVerification`] when `A` rejects the
    /// signature.
    pub fn verify(
        &self,
        verifying_key: &A::VerifyingKey,
    ) -> Result<VerifiedSignedEnvelope<'_, A>, SignedEnvelopeError> {
        if self.version != SIGNED_ENVELOPE_V1 {
            return Err(SignedEnvelopeError::UnsupportedVersion {
                version: self.version,
            });
        }

        let transcript = canonical_transcript(
            self.version,
            &self.envelope,
            &self.recipient_key_id,
            &self.metadata,
        )?;
        A::verify(verifying_key, &transcript, &self.signature)
            .map_err(SignedEnvelopeError::SignatureVerification)?;

        Ok(VerifiedSignedEnvelope {
            inner: self,
            _marker: PhantomData,
        })
    }
}

/// A signed CGv2 envelope after successful signature verification.
///
/// This borrows its source [`SignedEnvelope`] and cannot be constructed
/// directly. Its accessors expose exactly the values authenticated by
/// [`SignedEnvelope::verify`].
pub struct VerifiedSignedEnvelope<'a, A: SignAlgorithm> {
    inner: &'a SignedEnvelope<A>,
    _marker: PhantomData<A>,
}

impl<'a, A: SignAlgorithm> VerifiedSignedEnvelope<'a, A> {
    /// Return the authenticated signed-envelope protocol version.
    pub const fn version(&self) -> u16 {
        self.inner.version
    }

    /// Return the authenticated CGv2 envelope.
    pub fn envelope(&self) -> &Envelope {
        &self.inner.envelope
    }

    /// Return the authenticated application-defined recipient key identifier.
    pub fn recipient_key_id(&self) -> &[u8] {
        &self.inner.recipient_key_id
    }

    /// Return the authenticated application metadata.
    pub fn metadata(&self) -> &[u8] {
        &self.inner.metadata
    }
}

fn canonical_transcript(
    version: u16,
    envelope: &Envelope,
    recipient_key_id: &[u8],
    metadata: &[u8],
) -> Result<Vec<u8>, SignedEnvelopeError> {
    let envelope_bytes = envelope
        .try_to_bytes()
        .map_err(SignedEnvelopeError::EnvelopeSerialization)?;
    Envelope::from_bytes(&envelope_bytes).map_err(SignedEnvelopeError::EnvelopeSerialization)?;
    let mut transcript = Vec::with_capacity(
        SIGNED_ENVELOPE_V1_LABEL.len()
            + 2
            + (4 * 3)
            + envelope_bytes.len()
            + recipient_key_id.len()
            + metadata.len(),
    );

    transcript.extend_from_slice(SIGNED_ENVELOPE_V1_LABEL);
    transcript.extend_from_slice(&version.to_be_bytes());
    append_field(&mut transcript, "envelope", &envelope_bytes)?;
    append_field(&mut transcript, "recipient_key_id", recipient_key_id)?;
    append_field(&mut transcript, "metadata", metadata)?;
    Ok(transcript)
}

fn append_field(
    transcript: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
) -> Result<(), SignedEnvelopeError> {
    let length = u32::try_from(value.len()).map_err(|_| SignedEnvelopeError::FieldTooLong {
        field,
        length: value.len(),
    })?;
    transcript.extend_from_slice(&length.to_be_bytes());
    transcript.extend_from_slice(value);
    Ok(())
}
