# CryptGuard Programming Library

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![GitHub Library][lib-badge]][lib-link]

[crates-badge]: https://img.shields.io/badge/crates.io-v1.1-blue.svg?style=for-the-badge
[crates-url]: https://crates.io/crates/crypt_guard
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
[mit-url]: https://github.com/mm9942/CryptGuardLib/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v1.1-yellow.svg?style=for-the-badge
[doc-url]: https://docs.rs/crypt_guard/
[lib-badge]: https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge
[lib-link]: https://github.com/mm9942/CryptGuardLib

## Introduction

CryptGuard is a comprehensive cryptographic library, offering robust encryption and decryption capabilities. It integrates traditional cryptography with post-quantum algorithms, ensuring resilience against quantum computing threats. Designed for developers, CryptGuard empowers applications to withstand future digital security challenges. Embrace CryptGuard as your trusted ally in safeguarding privacy in the digital realm.

## Key Features and Capabilities

This library supports AES-256 and XChaCha20 encryption algorithms, providing a secure means to protect data. To cater to a variety of security requirements and operational contexts, CryptGuard integrates seamlessly with Kyber512, Kyber768, and Kyber1024 for encryption, ensuring compatibility with post-quantum cryptography standards.

For developers who require digital signing capabilities, CryptGuard incorporates Falcon and Dilithium algorithms, offering robust options for creating and verifying digital signatures. This feature is particularly crucial for applications that necessitate authenticity and integrity of data, ensuring that digital communications remain secure and verifiable.

An additional layer of security is provided through the appending of a HMAC (Hash-Based Message Authentication Code) to encrypted data. This critical feature enables the authentication of encrypted information, ensuring that any tampering with the data can be reliably detected. This HMAC attachment underscores CryptGuard's commitment to comprehensive data integrity and security, offering developers and end-users peace of mind regarding the authenticity and safety of their data.

## Syntax Overhaul and Version Information

### Upcoming Changes

Our library is undergoing a syntax overhaul to enhance detail and clarity, addressing feedback for a more intuitive user experience. The current syntax focuses on providing a comprehensive understanding of the cryptographic processes, albeit with a different complexity level.

### Newest Features

- **Simplified Syntax**: We've re-engineered the use of Dilithium and Falcon, adopting a straightforward, modular, and flexible approach akin to our encryption and decryption syntax. This enhancement aims to streamline operations for developers.

- **Designed for Versatility**: Our library now accommodates various key sizes beyond Falcon1024 and Dilithium5. Specifically, we've introduced Falcon512 for those needing a 512-bit key size. For Dilithium users, we've added support for Dilithium2 and Dilithium3, expanding the range of cryptographic strengths available.

- **Flexibility and Modularity**: The recent changes to our implementation for Dilithium and Falcon emphasize a generic and unified interface. This approach not only simplifies usage but also grants developers the flexibility to integrate different algorithms and signature modes seamlessly into their projects. By abstracting the complexity, we ensure that you can focus on what matters most - securing your applications efficiently.

- **Logging Functionality**: CryptGuard now includes a new logging feature designed to enhance operational transparency and assist in debugging processes. This logging functionality meticulously records every significant step in the cryptographic process without compromising security. Specifically, it logs the initiation and completion of key generation, message encryption, and decryption processes, including the cryptographic algorithm used (e.g., AES, XChaCha20) and the key encapsulation mechanism (e.g., Kyber1024). Importantly, to uphold the highest standards of security and privacy, CryptGuard's logging mechanism is carefully designed to exclude sensitive information such as encryption keys, unencrypted data, file paths, or any personally identifiable information. This ensures that while users benefit from detailed logs that can aid in troubleshooting and verifying cryptographic operations, there is no risk of exposing sensitive data.

### Current Release

The present version, **1.2**, emphasizes detailed cryptographic operations. This version is ideal for those who want a fast but not too complicated, elaborate approach to cryptography and don't want to use asynchronous code. Asynchronous capabilities will be reimplemented in a later update (but this time as a feature). For those who prefer using async implementation, use version 1.0.3 until a later update is released. This version's syntax is more user-friendly and does not require the definition of too many structs like in 1.1.X or 1.1.0 but allows for precise control over the encryption and decryption algorithm as well as the Kyber key size. It allows the usage of Kyber1024, Kyber768, and Kyber512. Now you also can use logging cappabilitys.

## Usage Examples

### The new Logging feature

CryptGuard's latest release introduces a logging feature, meticulously designed to offer comprehensive insights into cryptographic operations while prioritizing security and privacy.

#### Activating the log is enough

Upon activation, CryptGuard logs each significant cryptographic operation, including key generation, encryption, and decryption processes. These logs are stored in log.txt and, for enhanced organization and accessibility, are also split into individual process logs within an automatically created directory named after the log file (log).

```rust
use crypt_guard::*;

// Activate the log
activate_log("log.txt");

// Define message and passphrase
let message = "Hey, how are you doing?";
let passphrase = "Test Passphrase";

// Generate key pair
let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

// Instantiate Kyber for encryption with Kyber1024
let mut encryptor = Kyber::<Encryption, Kyber1024, File, AES>::new(public_key.clone(), None)?;

// Encrypt message
let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

// Instantiate Kyber for decryption with Kyber1024
let mut decryptor = Kyber::<Decryption, Kyber1024, File, AES>::new(secret_key, None)?;

// Decrypt message
let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

// Convert Vec<u8> to String for comparison
let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");
println!("{}", decrypted_text);
```

### New signature syntax for dilithium and falcon

#### Signing and opening with Falcon

```rust
use crypt_guard::KDF::*;

// Create a new keypair
let (public_key, secret_key) = Falcon1024::keypair();
let data = b"Hello, world!".to_vec();
let sign = Signature::<Falcon1024, Message>::new();
// Sign the message
let signed_message = sign.signature(data.clone(), secret_key);

// Open the message
let opened_message = sign.open(signed_message, public_key);
```

#### Signing and verifying detached with Dilithium

```rust
use crypt_guard::KDF::*;

// Create a new keypair
let (public_key, secret_key) = Dilithium5::keypair();
let data = b"Hello, world!".to_vec();

let sign = Signature::<Dilithium5, Detached>::new();

// Create a detached signature
let signature = sign.signature(data.clone(), secret_key);

// Verify the detached signature
let is_valid = sign.verify(data, signature, public_key);
```

### Cryptographic Operations

#### Generating and Saving a Key Pair

This example illustrates generating a key pair and saving it to files, leveraging the `KeyControKyber1024::keypair()` method for key pair generation and the `KeyControl::<KeyControKyber1024>` instance for setting and saving the keys.

```rust
// Generate a keypair
let (public_key, secret_key) = KeyControKyber1024::keypair().unwrap();

let keycontrol = KeyControl::<KeyControKyber1024>::new();

// Save Public and Secret key while defining the folder (./key).
keycontrol.set_public_key(public_key.clone()).unwrap();
keycontrol.save(KeyTypes::PublicKey, "./key".into()).unwrap();

keycontrol.set_secret_key(secret_key.clone()).unwrap();
keycontrol.save(KeyTypes::SecretKey, "./key".into()).unwrap();
```

### Encryption of a File using AES

```rust
let message = "Hey, how are you doing?";
let passphrase = "Test Passphrase";

// Instantiate Kyber for encryption of a message with Kyber1024 and AES
// Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
let mut encryptor = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None)?;

// Encrypt message
let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

// Save the ciphertext for decryption in folder ./key
key_control.set_ciphertext(cipher.clone()).unwrap();
key_control.save(KeyTypes::Ciphertext, "./key".into()).unwrap();
```

### Decryption of a File using AES

```rust
let cipher = key_control.load(KeyTypes::Ciphertext, Path::new("./key/ciphertext.ct"));
let secret_key = key_control.load(KeyTypes::SecretKey, Path::new("./key/secret_key.sec"));

// Instantiate Kyber for decryption of a message with Kyber1024 and AES
// Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
let mut decryptor = Kyber::<Decryption, Kyber1024, File, AES>::new(secret_key, None)?;

// Decrypt message
let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

// Print the decrypted text
println!("{:?}", String::from_utf8(decrypt_message));
```

#### Encryption and decryption of a message written into a file with XChaCha20

```rust
let message = "Hey, how are you doing?";

let tmp_dir = TempDir::new().map_err(|e| CryptError::from(e))?;
let tmp_dir = Builder::new().prefix("messages").tempdir().map_err(|e| CryptError::from(e))?;

let enc_path = tmp_dir.path().clone().join("message.txt");
let dec_path = tmp_dir.path().clone().join("message.txt.enc"); 

fs::write(&enc_path, message.as_bytes())?;

let passphrase = "Test Passphrase";

// Generate key pair
let (public_key, secret_key) = KeyControKyber768::keypair().expect("Failed to generate keypair");

// Instantiate Kyber for encryption of a file with Kyber768 and XChaCha20
// Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
let mut encryptor = Kyber::<Encryption, Kyber768, File, XChaCha20>::new(public_key.clone(), None)?;

// Encrypt message
let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

let nonce = encryptor.get_nonce();

fs::remove_file(enc_path.clone());

// Instantiate Kyber for decryption of a file with Kyber768 and XChaCha20
// Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
let mut decryptor = Kyber::<Decryption, Kyber768, File, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;

// Decrypt message
let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;
```

### Conclusion and Looking Forward

We appreciate your engagement with our cryptographic library. As we strive to improve and evolve, your feedback and contributions are invaluable. The anticipated update promises to make cryptography more accessible and straightforward for everyone.

Thank you for your support and for making security a priority in your projects.

## License
CryptGuard is licensed under the MIT LICENSE. The full license text is available in the `LICENSE` file in the repository.