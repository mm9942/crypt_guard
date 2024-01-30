# CryptGuard Programming Library

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![GitHub Library][lib-badge]][lib-link]
[![GitHub CLI][cli-badge]][cli-link]

[crates-badge]: https://img.shields.io/badge/crates.io-v0.2-blue.svg
[crates-url]: https://crates.io/crates/crypt_guard
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg
[mit-url]: https://github.com/mm9942/CryptGuardLib/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v0.2-yellow.svg
[doc-url]: https://docs.rs/crypt_guard/
[lib-badge]: https://img.shields.io/badge/github-lib-black.svg
[lib-link]: https://github.com/mm9942/CryptGuardLib
[cli-badge]: https://img.shields.io/badge/github-cli-white.svg
[cli-link]: https://github.com/mm9942/CryptGuard

## Introduction
CryptGuard is a comprehensive cryptographic library, offering robust encryption and decryption capabilities. It integrates traditional cryptography with post-quantum algorithms, ensuring resilience against quantum computing threats. Designed for developers, CryptGuard empowers applications to withstand future digital security challenges. Embrace CryptGuard as your trusted ally in safeguarding privacy in the digital realm.

## Prerequisites
Ensure your system has the latest stable versions of Rust, Cargo, and the Tokio runtime environment.

## Usage

To add usage examples for the new `dilithium` feature in the CryptGuard Rust library, we can focus on demonstrating how to utilize the `SignDilithium` struct for signing and verifying messages and files. Below are updated sections for the README.md, illustrating how to use the `dilithium` feature.

### New Feature: Dilithium

The `dilithium` feature in CryptGuard introduces the Dilithium algorithm, a post-quantum cryptographic signing method. This feature is optional and can be enabled in your `Cargo.toml`.

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

These examples demonstrate the usage of the `dilithium` feature in CryptGuard for signing and verifying messages and files, showcasing the library's capabilities with post-quantum cryptography.

### Encrypting Data
Encrypt data using `encrypt`, `encrypt_msg`, or `encrypt_file` functions from the `Encrypt` struct.

#### Encrypt a Message
```rust
use crypt_guard::{
    File,
    Encrypt,
    Decrypt,
    Keychain,
    FileRemover,
    Signing,
    Sign,
    ActionType,
};

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
The `Keychain` struct in CryptGuard facilitates key management. It supports loading and saving public keys, secret keys, shared secrets, and ciphertexts.

```rust

fn main() {
    let keychain = Keychain::new().unwrap();
    // Load or generate keys as required
}
```

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

### New Feature: xchacha20
The `xchacha20` feature in CryptGuard introduces the XChaCha20 encryption algorithm, providing an additional layer of security for your cryptographic needs. This feature is optional and can be enabled in your `Cargo.toml`.

#### Encrypting Data with XChaCha20
```rust
#[cfg(feature = "xchacha20")]

#[tokio::main]
async fn main() {
    #[cfg(feature = "xchacha20")]
    {
        let encrypt = Encrypt::new();
        let keychain = Keychain::new().unwrap();
        let message = "This is a secret message!";
        let nonce = generate_nonce();
        let hmac_key = b"encryption_test_key";

        let encrypted_message = encrypt.encrypt_msg_xchacha20(message, keychain.shared_secret.as_ref().unwrap(), &nonce, hmac_key)
            .await
            .expect("Failed to encrypt message with XChaCha20");
    }
}
```

#### Decrypting Data with XChaCha20
```rust
#[cfg(feature = "xchacha20")]

;

#[tokio::main]
async fn main() {
    #[cfg(feature = "xchacha20")]
    {
        let decrypt = Decrypt::new();
        let keychain = Keychain::new().unwrap();
        let nonce = ...; // Load your nonce here
        let hmac_key = b"encryption_test_key";
        let encrypted_data = ...; // Load your encrypted data here

        let decrypted_message = decrypt.decrypt_msg_xchacha20(encrypted_data, keychain.shared_secret.as_ref().unwrap(), &nonce, hmac_key, false)
            .await
            .expect("Failed to decrypt message with XChaCha20");
    }
}
```

### Removing a Single File

```rust

#[tokio::main]
async fn main() {
    let file_path = PathBuf::from("path/to/your/file.txt");
    let remover = FileRemover::new(5, file_path, false).unwrap();
    remover.delete().await.unwrap();
}
```

### Removing a Directory and Its Contents

```rust

#[tokio::main]
async fn main() {
    let dir_path = PathBuf::from("path/to/your/directory");
    let remover = FileRemover::new(5, dir_path, true).unwrap();
    remover.delete().await.unwrap();
}
```

### Removing Multiple Files with Unique Filenames

```rust

#[tokio::main]
async fn main() {
    // Generate 10 files with unique names in a temporary directory
    let dir = tempfile::TempDir::new().unwrap();
    for i in 0..10 {
        let file_name = format!("file{}.txt", i);
        let file_path = dir.path().join(file_name);
        let mut file = File::create(file_path).unwrap();
        write!(file, "File {} contents", i).unwrap();
    }

    // Remove all files from the temporary directory
    let remover = FileRemover::new(5, dir.path().to_path_buf(), false).unwrap();
    remover.delete().await.unwrap();
}
```

### Customize Overwrite Times

Increase the overwrite times to enhance the security of file removal.

```rust

#[tokio::main]
async fn main() {
    let file_path = PathBuf::from("path/to/your/file.txt");
    let remover = FileRemover::new(100, file_path, false).unwrap();
    remover.delete().await.unwrap();
}
```

### File Remover

**New Feature: File Remover**

The `file_remover` module in CryptGuard introduces a new feature for securely removing files and directories. This module includes the FileRemover struct, which provides several methods for removing files and directories, including:

- `delete()`: Deletes a single file or directory recursively (if recursive is set to true).
- `overwrite_file()`: Overwrites a file multiple times with random data to prevent data recovery.
- `new()`: Creates a new FileRemover instance with customizable overwrite times and recursive deletion options.

**File Remover Usage**

The following code demonstrates how to

**File Remover with Unique Filenames**

The FileRemover can also be used to remove multiple files with unique filenames.

## Dependencies
CryptGuard depends on several external crates, specified in `Cargo.toml`:

- `aes`: 0.8.3
- `tokio`: 1.35.1 (with `full` feature)
- `colored`: 2.1.0
- `env`: 0.0.0
- `hex`: 0.4.3
- `hmac`: 0.12.1
- `indicatif`: 0.17.7
- `pqcrypto-falcon`: 0.3.0
- `pqcrypto-kyber`: 0.8.0
- `pqcrypto-traits`: 0.3.5
- `rand`: 0.8.5
- `sha2`: 0.10.8
- `tempfile`: 3.9.0
- `chacha20`: 0.9.1 (optional, enabled with `xchacha20` feature)
- `cipher`: 0.4.4 (optional, enabled with `xchacha20` feature)

## License
CryptGuard is licensed under the MIT LICENSE. The full license text is available in the `LICENSE` file in the repository.
```

You now have the complete README.md content with the updated examples for CryptGuard.