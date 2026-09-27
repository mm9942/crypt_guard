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

/// An authenticated caller identity, as established by the transport.
///
/// Not secret (it is an identity, not a credential), so it may be cloned and
/// logged.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Principal(Box<str>);

impl Principal {
    /// Wrap an identity string.
    pub fn new(name: &str) -> Self {
        Self(name.into())
    }

    /// Borrow the identity string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated, non-secret context of one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    /// Correlation id.
    pub request_id: RequestId,
    /// Authenticated caller, or `None` for an anonymous request.
    pub principal: Option<Principal>,
}

impl RequestContext {
    /// Context of an anonymous request.
    pub fn anonymous(request_id: RequestId) -> Self {
        Self {
            request_id,
            principal: None,
        }
    }
}

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

/// Re-enable a disabled key version.
#[derive(Debug)]
pub struct EnableKey {
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
    /// See [`EnableKey`].
    Enable(EnableKey),
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

/// Payload-free kind of a [`CryptoOperation`], for policy decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OpKind {
    /// [`CryptoOperation::Generate`]
    Generate,
    /// [`CryptoOperation::Rotate`]
    Rotate,
    /// [`CryptoOperation::Disable`]
    Disable,
    /// [`CryptoOperation::Enable`]
    Enable,
    /// [`CryptoOperation::Destroy`]
    Destroy,
    /// [`CryptoOperation::Describe`]
    Describe,
    /// [`CryptoOperation::PublicKey`]
    PublicKey,
    /// [`CryptoOperation::Encrypt`]
    Encrypt,
    /// [`CryptoOperation::Decrypt`]
    Decrypt,
    /// [`CryptoOperation::Sign`]
    Sign,
    /// [`CryptoOperation::Verify`]
    Verify,
    /// [`CryptoOperation::WrapKey`]
    WrapKey,
    /// [`CryptoOperation::UnwrapKey`]
    UnwrapKey,
    /// [`CryptoOperation::RewrapKey`]
    RewrapKey,
}

impl OpKind {
    /// Stable, non-secret operation name for logs and metrics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Rotate => "rotate",
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::Destroy => "destroy",
            Self::Describe => "describe",
            Self::PublicKey => "public_key",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::WrapKey => "wrap",
            Self::UnwrapKey => "unwrap",
            Self::RewrapKey => "rewrap",
        }
    }

    /// Whether the operation changes provider state.
    ///
    /// Mutations must never be retried automatically: a lost response does
    /// not mean the mutation did not happen.
    pub fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::Generate | Self::Rotate | Self::Disable | Self::Enable | Self::Destroy
        )
    }

    /// Whether a successful result releases secret bytes to the caller
    /// (decrypt, unwrap). Policies should grant this explicitly.
    pub fn is_secret_egress(self) -> bool {
        matches!(self, Self::Decrypt | Self::UnwrapKey)
    }
}

impl CryptoOperation {
    /// The payload-free kind of this operation.
    pub fn kind(&self) -> OpKind {
        match self {
            Self::Generate(_) => OpKind::Generate,
            Self::Rotate(_) => OpKind::Rotate,
            Self::Disable(_) => OpKind::Disable,
            Self::Enable(_) => OpKind::Enable,
            Self::Destroy(_) => OpKind::Destroy,
            Self::Describe(_) => OpKind::Describe,
            Self::PublicKey(_) => OpKind::PublicKey,
            Self::Encrypt(_) => OpKind::Encrypt,
            Self::Decrypt(_) => OpKind::Decrypt,
            Self::Sign(_) => OpKind::Sign,
            Self::Verify(_) => OpKind::Verify,
            Self::WrapKey(_) => OpKind::WrapKey,
            Self::UnwrapKey(_) => OpKind::UnwrapKey,
            Self::RewrapKey(_) => OpKind::RewrapKey,
        }
    }

    /// Stable, non-secret operation name for logs and metrics.
    pub fn name(&self) -> &'static str {
        self.kind().name()
    }

    /// Whether the operation changes provider state.
    pub fn is_mutation(&self) -> bool {
        self.kind().is_mutation()
    }

    /// Every namespace the operation touches. A policy must authorize all of
    /// them (a rewrap reads one key and writes under another).
    pub fn namespaces(&self) -> [Option<&KeyNamespace>; 2] {
        match self {
            Self::Generate(op) => [Some(&op.namespace), None],
            Self::Rotate(op) => [Some(&op.key.namespace), None],
            Self::Disable(op) => [Some(&op.key.namespace), None],
            Self::Enable(op) => [Some(&op.key.namespace), None],
            Self::Destroy(op) => [Some(&op.key.namespace), None],
            Self::Describe(op) => [Some(&op.key.namespace), None],
            Self::PublicKey(op) => [Some(&op.key.namespace), None],
            Self::Encrypt(op) => [Some(&op.key.namespace), None],
            Self::Decrypt(op) => [Some(&op.key.namespace), None],
            Self::Sign(op) => [Some(&op.key.namespace), None],
            Self::Verify(op) => [Some(&op.key.namespace), None],
            Self::WrapKey(op) => [Some(&op.key.namespace), None],
            Self::UnwrapKey(op) => [Some(&op.key.namespace), None],
            Self::RewrapKey(op) => [Some(&op.from.namespace), Some(&op.to.namespace)],
        }
    }
}

/// A request to the crypto service. Moved, never cloned.
#[derive(Debug)]
pub struct CryptoRequest {
    /// Request id and caller.
    pub context: RequestContext,
    /// The operation.
    pub operation: CryptoOperation,
}

impl CryptoRequest {
    /// Build an anonymous request.
    pub fn new(request_id: RequestId, operation: CryptoOperation) -> Self {
        Self::with_context(RequestContext::anonymous(request_id), operation)
    }

    /// Build a request with an explicit context.
    pub fn with_context(context: RequestContext, operation: CryptoOperation) -> Self {
        Self { context, operation }
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
