# CryptGuard programming library

## Introduction
CryptGuardLib is a Rust library providing robust encryption and decryption functionalities. Utilizing advanced cryptographic algorithms, including the post-quantum Kyber1024, it's designed to secure data against quantum-computing threats. This library is ideal for developers looking to integrate strong cryptographic features into their Rust applications.

## Prerequisites
To use CryptGuardLib, ensure your development environment includes:
- Rust (latest stable version)
- Cargo for Rust package management

## Installation
Add CryptGuardLib to your Rust project by including it in your `Cargo.toml` file:
```toml
[dependencies]
crypt_guard = { git = "https://github.com/mm9942/CryptGuardLib.git" }
```

## Usage
CryptGuardLib provides modules for key management (`keychain`), encryption (`encrypt`), and decryption (`decrypt`). Here's a basic usage example:

```rust
use crypt_guard::{encrypt, decrypt, keychain};

// Example: Encrypting and Decrypting a message
let keychain = keychain::Keychain::new().unwrap();
let encrypted_message = encrypt::Encrypt::encrypt_msg("Your message", keychain.shared_secret.as_ref().unwrap(), your_hmac_key)
    .await
    .expect("Encryption failed");
let decrypted_message = decrypt::Decrypt::decrypt_msg(&encrypted_message, keychain.shared_secret.as_ref().unwrap(), your_hmac_key, false)
    .await
    .expect("Decryption failed");
```

## Features
- **Keychain Management**: Generate and manage cryptographic keys.
- **Encryption**: Encrypt data using state-of-the-art cryptographic algorithms.
- **Decryption**: Securely decrypt data back to its original form.

## Testing
CryptGuardLib includes a suite of tests to ensure functionality. Run tests with:
```bash
cargo test
```

## Dependencies
CryptGuardLib uses the following dependencies:
- `aes`: AES encryption.
- `clap`: Command-line argument parsing.
- `pqcrypto-kyber`: Post-quantum Kyber1024 algorithm.
- `tokio`: Asynchronous programming support.

Ensure these dependencies are included in your `Cargo.toml` when using CryptGuardLib.

## License
CryptGuardLib is licensed under the GNU GENERAL PUBLIC LICENSE Version 3. The full license text is available in the `LICENSE` file within the repository.
