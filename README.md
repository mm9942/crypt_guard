# CryptGuard programming library

## Introduction
CryptGuard is a robust Rust library for encryption and decryption, integrating traditional and post-quantum cryptographic methods. It's designed for developers who need sophisticated cryptographic capabilities in their applications, particularly with the advent of quantum computing.

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

#### Decrypt a Message
```rust
use crypt_guard::decrypt::Decrypt;
use crypt_guard::keychain::Keychain;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let decrypt = Decrypt::new();
    let keychain = Keychain::new().unwrap();
    let encrypted_data_with_hmac = /* your encrypted data */;
    let hmac_key = b"encryption_test_key";

    let decrypted_message = decrypt.decrypt_msg(encrypted_data_with_hmac, keychain.shared_secret.as_ref().unwrap(), hmac_key, false)
        .await
        .expect("Failed to decrypt message");
}
```

#### Decrypt a File
```rust
use crypt_guard::decrypt::Decrypt;
use crypt_guard::keychain::Keychain;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let decrypt = Decrypt::new();
    let keychain = Keychain::new().unwrap();
    let encrypted_file_path = PathBuf::from("path/to/your/encrypted/file.txt.enc");
    let hmac_key = b"encryption_test_key";

    let _ = decrypt.decrypt_file(&encrypted_file_path, keychain.shared_secret.as_ref().unwrap(), hmac_key)
        .await
        .expect("Failed to decrypt file");
}
```

### Keychain Usage
The `Keychain` struct provides functionalities for key management, including loading and saving public keys, secret keys, shared secrets, and ciphertexts.

#### Generating New Keychain
```rust
use crypt_guard::keychain::Keychain;

#[tokio::main]
async fn main() {
    let keychain = Keychain::new().unwrap();
}
```

## Dependencies
This project depends on several external crates, which need to be included in your `Cargo.toml` file:

```toml
[dependencies]
aes = "0.8.3"
clap = { version = "4.4.18", features = ["cargo", "derive"] }
env = "0.0.0"
hex = "0.4.3"
hmac = "0.12.1"
pqcrypto = { version = "0.17.0", features = ["serialization"] }
pqcrypto-kyber = { version = "0.8.0", features = ["serialization"] }
pqcrypto-traits = "0.3.5"
sha2 = "0.10.8"
tempfile = "3.9.0"
tokio = { version = "1.35.1", features = ["full"] }
```
The dependencies include cryptographic libraries like `aes`, `pqcrypto`, and `hmac` which are essential for the encryption and decryption functionalities provided by CryptGuard.