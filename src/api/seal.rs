use std::marker::PhantomData;

use crate::{
    api::AuthenticatedAead,
    core::hub::{EncryptData, Kyber, KyberSizeVariant, MlKem1024},
    error::CryptError,
    markers::{Data, Encryption, XChaCha20Poly1305},
    protocol::Envelope,
};

/// Staged builder state: no recipient key has been provided yet.
pub struct MissingRecipient;

/// Staged builder state: recipient key has been provided.
pub struct WithRecipient;

/// Staged builder state: no plaintext has been provided yet.
pub struct MissingPlaintext;

/// Staged builder state: plaintext has been provided.
pub struct WithPlaintext;

/// Safe encrypt-side entry point for the default authenticated envelope API.
///
/// ```rust,no_run
/// # fn main() -> Result<(), crypt_guard::error::CryptError> {
/// use crypt_guard::{Decryptor, Encryptor};
/// use crypt_guard::{MlKem768, XChaCha20Poly1305};
/// # #[cfg(feature = "ml-kem-backend")] {
/// use crypt_guard::kem::{KemBackend, backend::OsRng, ml_kem::MlKem768Impl};
///
/// let mut rng = OsRng;
/// let (public_key, secret_key) = MlKem768Impl::keypair(&mut rng)?;
///
/// let envelope = Encryptor::<MlKem768, XChaCha20Poly1305>::new()
///     .recipient(public_key.as_ref().to_vec())
///     .plaintext(b"hello")
///     .seal()?;
///
/// let plaintext = Decryptor::<MlKem768, XChaCha20Poly1305>::new()
///     .secret_key(secret_key.as_ref().to_vec())
///     .open(&envelope)?;
///
/// assert_eq!(plaintext, b"hello");
/// # Ok::<(), crypt_guard::error::CryptError>(())?;
/// # }
/// # Ok(())
/// # }
/// ```
///
/// ```compile_fail
/// use crypt_guard::Encryptor;
/// use crypt_guard::{MlKem768, XChaCha20Poly1305};
///
/// let _ = Encryptor::<MlKem768, XChaCha20Poly1305>::new().seal();
/// ```
pub struct Encryptor<K = MlKem1024, A = XChaCha20Poly1305>(PhantomData<(K, A)>)
where
    K: KyberSizeVariant,
    A: AuthenticatedAead;

impl<K, A> Encryptor<K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    /// Start a new staged sealer builder.
    // Typestate entry point: `new` intentionally returns the staged builder, not Self.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> EncryptorBuilder<MissingRecipient, MissingPlaintext, K, A> {
        EncryptorBuilder::new()
    }
}

/// Staged encrypt-side builder.
pub struct EncryptorBuilder<R, P, K = MlKem1024, A = XChaCha20Poly1305>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    recipient: Option<Vec<u8>>,
    plaintext: Option<Vec<u8>>,
    _state: PhantomData<(R, P, K, A)>,
}

impl<K, A> EncryptorBuilder<MissingRecipient, MissingPlaintext, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    pub fn new() -> Self {
        Self {
            recipient: None,
            plaintext: None,
            _state: PhantomData,
        }
    }
}

impl<P, K, A> EncryptorBuilder<MissingRecipient, P, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    /// Set the recipient ML-KEM public key bytes.
    pub fn recipient(self, recipient: Vec<u8>) -> EncryptorBuilder<WithRecipient, P, K, A> {
        EncryptorBuilder {
            recipient: Some(recipient),
            plaintext: self.plaintext,
            _state: PhantomData,
        }
    }
}

impl<K, A> EncryptorBuilder<WithRecipient, MissingPlaintext, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
    Kyber<Encryption, K, Data, A>: EncryptData,
{
    /// Set the plaintext bytes to encrypt.
    pub fn plaintext<T: Into<Vec<u8>>>(
        self,
        plaintext: T,
    ) -> EncryptorBuilder<WithRecipient, WithPlaintext, K, A> {
        EncryptorBuilder {
            recipient: self.recipient,
            plaintext: Some(plaintext.into()),
            _state: PhantomData,
        }
    }

    /// Convenience path matching the redesign sketch: set plaintext and seal in one call.
    pub fn seal_bytes<T: Into<Vec<u8>>>(self, plaintext: T) -> Result<Envelope, CryptError> {
        self.plaintext(plaintext).seal()
    }
}

impl<K, A> EncryptorBuilder<WithRecipient, WithPlaintext, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
    Kyber<Encryption, K, Data, A>: EncryptData,
{
    /// Seal the configured plaintext into a CGv2 authenticated envelope.
    pub fn seal(self) -> Result<Envelope, CryptError> {
        let recipient = self.recipient.ok_or(CryptError::MissingPublicKey)?;
        let plaintext = self.plaintext.ok_or(CryptError::MissingData)?;
        let mut kyber = Kyber::<Encryption, K, Data, A>::new(recipient, None)?;
        kyber.encrypt_data(&plaintext, "")
    }
}

impl<K, A> Default for EncryptorBuilder<MissingRecipient, MissingPlaintext, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    fn default() -> Self {
        Self::new()
    }
}
