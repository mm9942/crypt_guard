// Content-axis typestate enforcement: `encrypt_data` must NOT exist on a
// `Kyber<Encryption, _, Files, _>` instance in the default (non-legacy) build.
//
// `EncryptData::encrypt_data` is implemented only for the `Data` content marker;
// the `Files` instance has `EncryptFile::encrypt_file` instead. With the legacy
// `KyberFunctions` trait gated out of the default build, calling `encrypt_data`
// on a `Files` instance is a compile error.
use crypt_guard::hub::{Kyber, MlKem768, EncryptData};
use crypt_guard::{Encryption, Files, XChaCha20Poly1305};

fn main() {
    let mut enc = Kyber::<Encryption, MlKem768, Files, XChaCha20Poly1305>::new(vec![0u8; 1184], None).unwrap();
    let _ = enc.encrypt_data(b"bytes", "passphrase");
}
