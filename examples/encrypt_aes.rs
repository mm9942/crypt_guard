use crypt_guard::kem::{backend::OsRng, ml_kem::MlKem768Impl, KemBackend};
use crypt_guard::{AesGcmSiv, Decryptor, Encryptor, MlKem768};

fn main() -> Result<(), crypt_guard::error::CryptError> {
    let mut rng = OsRng;
    let (public_key, secret_key) = MlKem768Impl::keypair(&mut rng)?;

    let envelope = Encryptor::<MlKem768, AesGcmSiv>::new()
        .recipient(public_key.as_ref().to_vec())
        .plaintext(b"Hello from AesGcmSiv")
        .seal()?;

    let plaintext = Decryptor::<MlKem768, AesGcmSiv>::new()
        .secret_key(secret_key.as_ref().to_vec())
        .open(&envelope)?;

    assert_eq!(plaintext, b"Hello from AesGcmSiv");
    Ok(())
}
