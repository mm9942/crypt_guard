use crypt_guard::{
    decryption, encryption, error::Zeroize, kyber_keypair, Data, Decryption, Encryption,
    KeyControKyber1024, KeyControKyber512, KeyControKyber768, Kyber, Kyber1024, KyberFunctions,
    AES,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"legacy macro compatibility".to_vec();
    let passphrase = "Test Passphrase";

    let (public_key, secret_key) = kyber_keypair!(1024);

    let (encrypted_payload, kem_ciphertext) =
        encryption!(public_key, 1024, message.clone(), passphrase, AES)?;

    let decrypted = decryption!(
        secret_key,
        1024,
        encrypted_payload,
        passphrase,
        kem_ciphertext,
        AES
    )?;

    assert_eq!(decrypted, message);
    Ok(())
}
