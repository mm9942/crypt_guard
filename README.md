# CryptGuard programming library

## Introduction
Embark on a journey through the cryptic realms of cyberspace with CryptGuard, a fortress of cryptographic wisdom. In an era where the fabric of digital security is relentlessly tested by the looming specter of quantum supremacy, CryptGuard stands as a bulwark, melding the arcane secrets of traditional cryptography with the enigmatic art of post-quantum ciphers. It is a beacon for developers, a herald of a new epoch, who seek to imbue their creations with the power to withstand the tempests of tomorrow's uncertainties. Let CryptGuard be the sentinel in the silent war of ones and zeroes, a vigilant guardian weaving the unbreakable shield of privacy.

## Prerequisites
Before integrating CryptGuard into your project, ensure your system includes:
- Rust and Cargo (latest stable version)
- Tokio runtime environment

## Installation
To include CryptGuard in your Rust project, follow these steps:
1. Clone the GitHub repository:
   ```bash
   git clone https://github.com/mm9942/CryptGuardLib.git
   ```
2. Navigate to the CryptGuardLib directory:
   ```bash
   cd CryptGuardLib
   ```
3. Compile the project using Cargo:
   ```bash
   cargo build --release
   ```

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

## Dependencies
CryptGuard depends on several external crates, specified in `Cargo.toml`:
- `aes`: Version 0.8.3 for AES encryption.
- `tokio`: Version 1.35.1 with the `full` feature for asynchronous programming.
- Additional dependencies as per the previous README.

## Resources
- CryptGuard on Crates.io: [https://crates.io/crates/crypt_guard](https://crates.io/crates/crypt_guard)
- CryptGuard Documentation: [https://docs.rs/crypt_guard/](https://docs.rs/crypt_guard/)
- CryptGuard CLI Application: [https://github.com/mm9942/CryptGuard](https://github.com/mm9942/CryptGuard)
- CryptGuard Library Source

: [https://github.com/mm9942/CryptGuardLib](https://github.com/mm9942/CryptGuardLib)

## License
CryptGuard is licensed under the MIT LICENSE. The full license text can be found in the `LICENSE` file in the repository.
