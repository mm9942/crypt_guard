use crypt_guard::Decryptor;
use crypt_guard::{MlKem768, XChaCha20Poly1305};
use crypt_guard::protocol::{AeadAlgId, Envelope, Header, KdfAlgId, KemAlgId};

fn main() {
    let envelope = Envelope::new(
        Header::new(
            KemAlgId::MlKem768,
            AeadAlgId::XChaCha20Poly1305,
            KdfAlgId::HkdfSha256,
        ),
        vec![],
        vec![],
        vec![],
    );

    let _ = Decryptor::<MlKem768, XChaCha20Poly1305>::new().open(&envelope);
}
