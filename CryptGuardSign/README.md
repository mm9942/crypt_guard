# CryptGuard: Sign Programming Library

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![GitHub Library][lib-badge]][lib-link]
[![GitHub CLI][cli-badge]][cli-link]
[![GitHub CLI][API-badge]][API-link]

[crates-badge]: https://img.shields.io/badge/crates.io-v0.2-blue.svg
[crates-url]: https://crates.io/crates/crypt_guard_sign
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg
[mit-url]: https://github.com/mm9942/CryptGuardLib/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v0.2-yellow.svg
[doc-url]: https://docs.rs/crypt_guard_sign/
[lib-badge]: https://img.shields.io/badge/github-lib-black.svg
[lib-link]: https://github.com/mm9942/CryptGuardSign
[cli-badge]: https://img.shields.io/badge/github-cli-white.svg
[cli-link]: https://github.com/mm9942/CryptGuard
[API-badge]: https://img.shields.io/badge/github-API-white.svg
[API-link]: https://github.com/mm9942/CryptGuardAPI

## Introduction
CryptGuard: Sign is a comprehensive cryptographic library, offering robust signing and verification capabilities. Designed for developers, CryptGuard: Sign empowers applications to withstand future digital security challenges. Embrace CryptGuard: Sign as your trusted ally in safeguarding privacy in the digital realm.

## Prerequisites
Ensure your system has the latest stable versions of Rust, Cargo, and the Tokio runtime environment.

## Usage

### New Feature: Dilithium

The `dilithium` feature in CryptGuard: Sign introduces the Dilithium algorithm, a post-quantum cryptographic signing method. This feature is optional and can be enabled in your `Cargo.toml`.

#### Signing a Message with Dilithium
To sign a message using Dilithium,
```rust
#[cfg(feature = "dilithium")]

#[tokio::main]
async fn main() {
    #[cfg(feature = "dilithium")]
    {
        let mut sign = SignDilithium::new().unwrap();
        let message = b"Hello, this is a test message";

        // Sign the message
        let signed_message = sign.sign_msg(message).await.expect("Failed to sign message with Dilithium");

        // Print the signed message
        println!("Signed message with Dilithium: {:?}", signed_message);
    }
}
```

#### Verifying a Signed Message with Dilithium
To verify a signed message,
```rust
#[cfg(feature = "dilithium")]

#[tokio::main]
async fn main() {
    #[cfg(feature = "dilithium")]
    {
        let mut sign = SignDilithium::new().unwrap();
        let message = b"Hello, this is a test message";

        // Sign the message
        let signed_message = sign.sign_msg(message).await.expect("Failed to sign message");

        // Verify the signed message
        let verification_result = sign.verify_msg(message).await.expect("Failed to verify message");

        // Check the verification result
        assert!(verification_result, "Verification failed for the signed message with Dilithium");
    }
}
```

#### Signing a File with Dilithium
For signing a file using Dilithium,
```rust
#[cfg(feature = "dilithium")]

#[tokio::main]
async fn main() {
    #[cfg(feature = "dilithium")]
    {
        let mut sign = SignDilithium::new().unwrap();
        let file_path = PathBuf::from("path/to/your/file.txt");

        // Sign the file
        let signed_file = sign.sign_file(file_path.clone()).await.expect("Failed to sign file with Dilithium");

        // Print the result
        println!("Signed file with Dilithium: {:?}", signed_file);
    }
}
```

These examples demonstrate the usage of the `dilithium` feature in CryptGuard: Sign for signing and verifying messages and files, showcasing the library's capabilities with post-quantum cryptography.

### Signing a Message
To sign a message,

```rust

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

### Signing a File
For signing a file,

```rust

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

## Dependencies
CryptGuard: Sign depends on several external crates, specified in `Cargo.toml`:

- `aes`: 0.8.3
- `tokio`: 1.35.1 (with `full` feature)
- `colored`: 2.1.0
- `env`: 0.0.0
- `hex`: 0.4.3
- `hmac`: 0.12.1
- `indicatif`: 0.17.7
- `pqcrypto-falcon`: 0.3.0
- `pqcrypto-dilithium`: 0.5.0
- `pqcrypto-kyber`: 0.8.0
- `pqcrypto-traits`: 0.3.5
- `rand`: 0.8.5
- `sha2`: 0.10.8
- `tempfile`: 3.9.0

## License
CryptGuard: Sign is licensed under the MIT LICENSE. The full license text is available in the `LICENSE` file in the repository.
```

You now have the complete README.md content with the updated examples for CryptGuard.