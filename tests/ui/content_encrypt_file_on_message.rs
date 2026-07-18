// Content-axis typestate enforcement: `encrypt_file` must NOT exist on a
// `Kyber<Encryption, _, Message, _>` instance in the default (non-legacy) build.
//
// In the default build the legacy `KyberFunctions` trait (which provided
// encrypt_file/encrypt_msg/encrypt_data on EVERY content marker) is gated out,
// so the only `encrypt_file` is `EncryptFile`, implemented solely for the
// `Files` content marker. Calling it on a `Message` instance is a compile error.
use std::path::PathBuf;
use crypt_guard::hub::{Kyber, MlKem768, EncryptFile};
use crypt_guard::{Encryption, Message, XChaCha20Poly1305};

fn main() {
    let mut enc = Kyber::<Encryption, MlKem768, Message, XChaCha20Poly1305>::new(vec![0u8; 1184], None).unwrap();
    let _ = enc.encrypt_file(PathBuf::from("/tmp/x"), "passphrase");
}
