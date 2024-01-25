# CryptGuard programming library

## Introduction
Embark on a journey through the cryptic realms of cyberspace with CryptGuard, a fortress of cryptographic wisdom. In an era where the fabric of digital security is relentlessly tested by the looming specter of quantum supremacy, CryptGuard stands as a bulwark, melding the arcane secrets of traditional cryptography with the enigmatic art of post-quantum ciphers. It is a beacon for developers, a herald of a new epoch, who seek to imbue their creations with the power to withstand the tempests of tomorrow's uncertainties. Let CryptGuard be the sentinel in the silent war of ones and zeroes, a vigilant guardian weaving the unbreakable shield of privacy.

## Prerequisites
Before integrating CryptGuard into your project, ensure your system includes:
- Rust and Cargo (latest stable version)
- Tokio runtime environment

## Usage

### Encrypting Data
Encrypt data using `encrypt`, `encrypt_msg`, or `encrypt_file` functions from the `Encrypt` struct.

#### Encrypt a Message
```rust
use crypt_guard::encrypt::Encrypt;
use crypt_guard::keychain::Keychain;

#[tokio::main]
async fn main() {
    let encrypt = Encrypt::new();
    let keychain = Keychain::new().unwrap();
    let message = "This is a secret message!";
    let hmac_key = b"encryption_test_key";

    let encrypted_message = encrypt.encrypt_msg(message, keychain.shared_secret.as_ref().unwrap(), hmac_key)
        .await
        .expect("Failed to encrypt message");
}
```

#### Encrypt a File
```rust
use crypt_guard::encrypt::Encrypt;
use crypt_guard::keychain::Keychain;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let encrypt = Encrypt::new();
    let keychain = Keychain::new().unwrap();
    let file_path = PathBuf::from("path/to/your/file.txt");
    let hmac_key = b"encryption_test_key";

    let _ = encrypt.encrypt_file(file_path, keychain.shared_secret.as_ref().unwrap(), hmac_key)
        .await
        .expect("Failed to encrypt file");
}
```

### Decrypting Data
Decrypt data using `decrypt`, `decrypt_msg`, or `decrypt_file` functions from the `Decrypt` struct.

```rust
use crypt_guard::decrypt::Decrypt;
use crypt_guard::keychain::Keychain;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let decrypt = Decrypt::new();
    let keychain = Keychain::new().unwrap();
    let encrypted_data = ...; // Load your encrypted data here
    let hmac_key = b"encryption_test_key";

    let decrypted_message = decrypt.decrypt_msg(encrypted_data, keychain.shared_secret.as_ref().unwrap(), hmac_key)
        .await
        .expect("Failed to decrypt message");

    let file_path = PathBuf::from("path/to/your/encrypted_file.txt");
    let _ = decrypt.decrypt_file(file_path, keychain.shared_secret.as_ref().unwrap(), hmac_key)
        .await
        .expect("Failed to decrypt file");
}
```

### Keychain Usage
The `Keychain` struct in CryptGuard facilitates key management. It supports loading and saving public keys, secret keys, shared secrets, and ciphertexts. For example:

```rust
use crypt_guard::keychain::Keychain;

fn main() {
    let keychain = Keychain::new().unwrap();
    // Load or generate keys as required
    // ...
}
```

### Signing a Message
To sign a message, you can use the `Sign` struct from the `sign` module. Here's how you can sign a message:

```rust
use crypt_guard::sign::Sign;

#[tokio::main]
async fn main() {
    let mut sign = Sign::new().unwrap();
    let message = b"Hello, this is a test message";

    // Sign the message
    let signed_message = sign.sign_msg(message).await.expect("Failed to sign message");

    // Print the signed message
    println!("Signed message: {:?}", signed_message);
}
```

In this example, `Sign::new()` initializes the `Sign` struct, and `sign.sign_msg(message)` is used to sign the provided message.

### Signing a File
For signing a file, you can use the `sign_file` method from the `Sign` struct. This method signs the content of the file and saves the signature. Here's an example:

```rust
use crypt_guard::sign::Sign;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut sign = Sign::new().unwrap();
    let file_path = PathBuf::from("path/to/your/file.txt");

    // Sign the file
    let signed_file = sign.sign_file(file_path.clone()).await.expect("Failed to sign file");

    // Print the result
    println!("Signed file content: {:?}", signed_file);
}
```

In this example, `sign.sign_file(file_path)` is used to sign the content of the specified file.

### Additional Features
The `Sign` struct also provides functionalities like `verify_msg` and `verify_detached` for verifying signed messages and detached signatures, respectively.

Remember to handle the results and errors appropriately in a production environment, and ensure that the paths and keys used in these examples match your specific use case.

## Dependencies
CryptGuard depends on several external crates, specified in `Cargo.toml`:

- `aes`: Latest stable version for AES encryption.
- `tokio`: Latest stable version with the `full` feature for asynchronous programming.
- `colored`: Latest stable version for colorful terminal output.
- `hex`: Latest stable version for encoding/decoding data in hex format.
- `hmac`: Latest stable version for HMAC functionality.
- `indicatif`: Latest stable version for progress bar in terminal applications.
- `pqcrypto`: Latest stable version, with serialization features, for post-quantum cryptography algorithms.
- `pqcrypto-falcon`: Latest stable version, with serialization features, for Falcon post-quantum signature scheme.
- `pqcrypto-kyber`: Latest stable version, with serialization features, for Kyber post-quantum key encapsulation mechanism.
- `pqcrypto-traits`: Latest stable version for common traits in post-quantum cryptography.
- `rand`: Latest stable version for generating random numbers.
- `sha2`: Latest stable version for SHA-2 cryptographic hash functions.
- `tempfile`: Latest stable version for creating temporary files and directories.

## Resources
- CryptGuard on Crates.io: [https://crates.io/crates/crypt_guard](https://crates.io/crates/crypt_guard)
- CryptGuard Documentation: [https://docs.rs/crypt_guard/](https://docs.rs/crypt_guard/)
- CryptGuard CLI Application: [https://github.com/mm9942/CryptGuard](https://github.com/mm9942/CryptGuard)
- CryptGuard Library Source

: [https://github.com/mm9942/CryptGuardLib](https://github.com/mm9942/CryptGuardLib)

## License
CryptGuard is licensed under the MIT LICENSE. The full license text can be found in the `LICENSE` file in the repository.
