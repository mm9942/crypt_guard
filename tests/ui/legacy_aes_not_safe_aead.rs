use crypt_guard::{Encryptor, MlKem768};
use crypt_guard::markers::AES;

fn main() {
    let _ = Encryptor::<MlKem768, AES>::new();
}
