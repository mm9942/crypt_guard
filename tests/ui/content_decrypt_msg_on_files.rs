// Content-axis typestate enforcement: `decrypt_msg` must NOT exist on a
// `Kyber<Decryption, _, Files, _>` instance in the default (non-legacy) build.
//
// `DecryptText::decrypt_msg` is implemented only for the `Message` content
// marker; the `Files` instance has `DecryptFile::decrypt_file` instead. With the
// legacy `KyberFunctions` trait gated out of the default build, calling
// `decrypt_msg` on a `Files` instance is a compile error.
use crypt_guard::hub::{Kyber, MlKem768, DecryptText};
use crypt_guard::{Decryption, Files, XChaCha20Poly1305};
use crypt_guard::protocol::{AeadAlgId, Envelope, Header, KdfAlgId, KemAlgId};

fn main() {
    let dec = Kyber::<Decryption, MlKem768, Files, XChaCha20Poly1305>::new(vec![0u8; 2400], None).unwrap();
    let envelope = Envelope::new(
        Header::new(KemAlgId::MlKem768, AeadAlgId::XChaCha20Poly1305, KdfAlgId::HkdfSha256),
        vec![],
        vec![],
        vec![],
    );
    let _ = dec.decrypt_msg(&envelope.ciphertext, "passphrase", &envelope);
}
