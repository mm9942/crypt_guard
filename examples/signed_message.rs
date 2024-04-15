use crypt_guard::KDF::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon1024::keypair()?;
    let _ = Falcon1024::save_public(&public_key);
    let _ = Falcon1024::save_secret(&secret_key);

    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Falcon1024, Message>::new();

    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key)?;

    let message = String::from_utf8(opened_message).expect("Failed to convert decrypted message to string");
    println!("{:?}", message);
    Ok(())
}