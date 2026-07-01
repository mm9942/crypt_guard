use crypt_guard::Encryptor;
use crypt_guard::{MlKem768, XChaCha20Poly1305};

fn main() {
    let _ = Encryptor::<MlKem768, XChaCha20Poly1305>::new()
        .plaintext(b"hello")
        .seal();
}
