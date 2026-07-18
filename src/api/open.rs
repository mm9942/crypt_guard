use std::marker::PhantomData;

use zeroize::Zeroize;

use crate::{
    api::AuthenticatedAead,
    core::hub::{DecryptData, Kyber, KyberSizeVariant, MlKem1024},
    error::CryptError,
    markers::{Data, Decryption, XChaCha20Poly1305},
    protocol::Envelope,
};

/// Staged builder state: no secret key has been provided yet.
pub struct MissingSecretKey;

/// Staged builder state: secret key has been provided.
pub struct WithSecretKey;

/// Safe decrypt-side entry point for the default authenticated envelope API.
///
/// ```compile_fail
/// use crypt_guard::Decryptor;
/// use crypt_guard::{MlKem768, XChaCha20Poly1305};
/// use crypt_guard::protocol::Envelope;
///
/// let envelope = Envelope::new(
///     crypt_guard::protocol::Header::new(
///         crypt_guard::protocol::KemAlgId::MlKem768,
///         crypt_guard::protocol::AeadAlgId::XChaCha20Poly1305,
///         crypt_guard::protocol::KdfAlgId::HkdfSha256,
///     ),
///     vec![],
///     vec![],
///     vec![],
/// );
/// let _ = Decryptor::<MlKem768, XChaCha20Poly1305>::new().open(&envelope);
/// ```
pub struct Decryptor<K = MlKem1024, A = XChaCha20Poly1305>(PhantomData<(K, A)>)
where
    K: KyberSizeVariant,
    A: AuthenticatedAead;

impl<K, A> Decryptor<K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    /// Start a new staged opener builder.
    // Typestate entry point: `new` intentionally returns the staged builder, not Self.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> DecryptorBuilder<MissingSecretKey, K, A> {
        DecryptorBuilder::new()
    }
}

/// Staged decrypt-side builder.
pub struct DecryptorBuilder<S, K = MlKem1024, A = XChaCha20Poly1305>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    secret_key: Option<Vec<u8>>,
    _state: PhantomData<(S, K, A)>,
}

/// Owns the key-bearing `Kyber` value for one terminal decrypt operation.
///
/// The builder moves its recipient secret key here before decryption. Dropping
/// this session clears that owned key after either a successful open or an
/// error, without changing the behavior of encryption-side public keys.
struct DecryptSession<K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    kyber: Kyber<Decryption, K, Data, A>,
}

impl<K, A> DecryptSession<K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
    Kyber<Decryption, K, Data, A>: DecryptData,
{
    fn open(&self, envelope: &Envelope) -> Result<Vec<u8>, CryptError> {
        self.kyber.decrypt_data(&envelope.ciphertext, "", envelope)
    }
}

impl<K, A> Drop for DecryptSession<K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    fn drop(&mut self) {
        self.kyber.zeroize_key();
    }
}

/// Zeroizes the recipient ML-KEM secret key when the builder is dropped, so a
/// partially configured or discarded builder does not leave key material in
/// freed heap memory.
impl<S, K, A> Drop for DecryptorBuilder<S, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    fn drop(&mut self) {
        if let Some(secret_key) = self.secret_key.as_mut() {
            secret_key.zeroize();
        }
    }
}

impl<K, A> DecryptorBuilder<MissingSecretKey, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    pub fn new() -> Self {
        Self {
            secret_key: None,
            _state: PhantomData,
        }
    }

    /// Set the recipient ML-KEM secret key bytes.
    pub fn secret_key(self, secret_key: Vec<u8>) -> DecryptorBuilder<WithSecretKey, K, A> {
        DecryptorBuilder {
            secret_key: Some(secret_key),
            _state: PhantomData,
        }
    }
}

impl<K, A> DecryptorBuilder<WithSecretKey, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
    Kyber<Decryption, K, Data, A>: DecryptData,
{
    /// Open and authenticate a CGv2 envelope, returning the plaintext bytes.
    pub fn open(mut self, envelope: &Envelope) -> Result<Vec<u8>, CryptError> {
        let secret_key = self.secret_key.take().ok_or(CryptError::MissingSecretKey)?;
        let session = DecryptSession {
            kyber: Kyber::<Decryption, K, Data, A>::new(secret_key, None)?,
        };
        session.open(envelope)
    }
}

impl<K, A> Default for DecryptorBuilder<MissingSecretKey, K, A>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
{
    fn default() -> Self {
        Self::new()
    }
}
