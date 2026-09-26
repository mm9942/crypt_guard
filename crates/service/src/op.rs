//! Requests, operations and responses.
//!
//! Requests are **moved** into the service, never cloned. Every type that can
//! carry a [`SecretBytes`] is intentionally not `Clone`.

use crate::{
    blob::{CiphertextBlob, MessageBlob, PublicBlob, SignatureBlob},
    key::{KeyAlgorithm, KeyId, KeyMetadata, KeyNamespace, KeyRef},
    secret::SecretBytes,
};

/// Correlation id of one request, used for audit and idempotency records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId(pub u128);

/// HPKE `info` and AEAD `aad` bound to an encrypt/decrypt or wrap/unwrap.
///
/// Both must match exactly when opening; a mismatch surfaces as the same
/// opaque [`AuthenticationFailed`](crate::CryptoServiceError::AuthenticationFailed)
/// as tampering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CryptoContext {
    /// HPKE setup `info`.
    pub info: Box<[u8]>,
    /// Per-message additional authenticated data.
    pub aad: Box<[u8]>,
}

/// Create a new key.
#[derive(Debug)]
pub struct GenerateKey {
    /// Namespace of the new key.
    pub namespace: KeyNamespace,
    /// Identifier of the new key.
    pub id: KeyId,
    /// Algorithm / purpose.
    pub algorithm: KeyAlgorithm,
}

/// Fetch the public key of a key version.
#[derive(Debug)]
pub struct GetPublicKey {
    /// The key.
    pub key: KeyRef,
}

/// Fetch non-secret metadata of a key version.
#[derive(Debug)]
pub struct DescribeKey {
    /// The key.
    pub key: KeyRef,
}

/// Create a new primary version of a key.
#[derive(Debug)]
pub struct RotateKey {
    /// The key.
    pub key: KeyRef,
}

/// Disable a key version.
#[derive(Debug)]
pub struct DisableKey {
    /// The key.
    pub key: KeyRef,
}

/// Destroy a key version.
#[derive(Debug)]
pub struct DestroyKey {
    /// The key.
    pub key: KeyRef,
}

/// Encrypt plaintext to a key.
#[derive(Debug)]
pub struct Encrypt {
    /// The key (normally the latest version).
    pub key: KeyRef,
    /// Plaintext, moved in.
    pub plaintext: SecretBytes,
    /// `info` / `aad`.
    pub context: CryptoContext,
}

/// Decrypt a ciphertext with a key.
#[derive(Debug)]
pub struct Decrypt {
    /// The key.
    pub key: KeyRef,
    /// Ciphertext.
    pub ciphertext: CiphertextBlob,
    /// `info` / `aad`; must match the values used when encrypting.
    pub context: CryptoContext,
}

/// Sign a message.
#[derive(Debug)]
pub struct Sign {
    /// The signing key.
    pub key: KeyRef,
    /// Message to sign. Treated as secret because it may be.
    pub message: SecretBytes,
}

/// Verify a signature.
#[derive(Debug)]
pub struct Verify {
    /// The signing key whose public half verifies.
    pub key: KeyRef,
    /// Signed message.
    pub message: MessageBlob,
    /// Signature to check.
    pub signature: SignatureBlob,
}

/// Wrap (encrypt) caller-supplied key material under a key.
#[derive(Debug)]
pub struct WrapKey {
    /// The wrapping key.
    pub key: KeyRef,
    /// Key material to wrap, moved in.
    pub material: SecretBytes,
    /// `info` / `aad`.
    pub context: CryptoContext,
}

/// Unwrap previously wrapped key material.
#[derive(Debug)]
pub struct UnwrapKey {
    /// The wrapping key.
    pub key: KeyRef,
    /// Wrapped key material.
    pub wrapped: CiphertextBlob,
    /// `info` / `aad`.
    pub context: CryptoContext,
}

/// Re-wrap key material from one wrapping key to another without it
/// leaving the provider.
#[derive(Debug)]
pub struct RewrapKey {
    /// Current wrapping key.
    pub from: KeyRef,
    /// `info` / `aad` of the current wrapping.
    pub from_context: CryptoContext,
    /// Target wrapping key.
    pub to: KeyRef,
    /// `info` / `aad` of the new wrapping.
    pub to_context: CryptoContext,
    /// Wrapped key material.
    pub wrapped: CiphertextBlob,
}

/// One operation on the crypto service.
#[derive(Debug)]
#[non_exhaustive]
pub enum CryptoOperation {
    /// See [`GenerateKey`].
    Generate(GenerateKey),
    /// See [`RotateKey`].
    Rotate(RotateKey),
    /// See [`DisableKey`].
    Disable(DisableKey),
    /// See [`DestroyKey`].
    Destroy(DestroyKey),
    /// See [`DescribeKey`].
    Describe(DescribeKey),
    /// See [`GetPublicKey`].
    PublicKey(GetPublicKey),
    /// See [`Encrypt`].
    Encrypt(Encrypt),
    /// See [`Decrypt`].
    Decrypt(Decrypt),
    /// See [`Sign`].
    Sign(Sign),
    /// See [`Verify`].
    Verify(Verify),
    /// See [`WrapKey`].
    WrapKey(WrapKey),
    /// See [`UnwrapKey`].
    UnwrapKey(UnwrapKey),
    /// See [`RewrapKey`].
    RewrapKey(RewrapKey),
}

impl CryptoOperation {
    /// Stable, non-secret operation name for logs and metrics.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Generate(_) => "generate",
            Self::Rotate(_) => "rotate",
            Self::Disable(_) => "disable",
            Self::Destroy(_) => "destroy",
            Self::Describe(_) => "describe",
            Self::PublicKey(_) => "public_key",
            Self::Encrypt(_) => "encrypt",
            Self::Decrypt(_) => "decrypt",
            Self::Sign(_) => "sign",
            Self::Verify(_) => "verify",
            Self::WrapKey(_) => "wrap",
            Self::UnwrapKey(_) => "unwrap",
            Self::RewrapKey(_) => "rewrap",
        }
    }

    /// Whether the operation changes provider state.
    ///
    /// Mutations must never be retried automatically: a lost response does
    /// not mean the mutation did not happen.
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::Generate(_) | Self::Rotate(_) | Self::Disable(_) | Self::Destroy(_)
        )
    }
}

/// A request to the crypto service. Moved, never cloned.
#[derive(Debug)]
pub struct CryptoRequest {
    /// Correlation id.
    pub request_id: RequestId,
    /// The operation.
    pub operation: CryptoOperation,
}

impl CryptoRequest {
    /// Build a request.
    pub fn new(request_id: RequestId, operation: CryptoOperation) -> Self {
        Self {
            request_id,
            operation,
        }
    }
}

/// Result of a signature verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// The signature is valid for the message and key.
    Valid,
    /// The signature is not valid.
    Invalid,
}

/// A response from the crypto service.
///
/// Not `Clone`: the [`Plaintext`](Self::Plaintext) variant carries secret
/// bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum CryptoResponse {
    /// A key or key version was created.
    KeyCreated {
        /// The new key version.
        key: KeyRef,
        /// Its public key, if the algorithm has one.
        public: Option<PublicBlob>,
    },
    /// Key metadata.
    Metadata(KeyMetadata),
    /// A public key.
    PublicKey(PublicBlob),
    /// A ciphertext (encrypt, wrap, rewrap).
    Ciphertext(CiphertextBlob),
    /// Secret output (decrypt, unwrap).
    Plaintext(SecretBytes),
    /// A signature.
    Signature(SignatureBlob),
    /// A verification outcome.
    Verification(VerificationResult),
}
