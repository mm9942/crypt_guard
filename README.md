# CryptGuard Programming Library

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![GitHub Library][lib-badge]][lib-link]
[![GitHub CLI][cli-badge]][cli-link]

[crates-badge]: https://img.shields.io/badge/crates.io-v1.1-blue.svg
[crates-url]: https://crates.io/crates/crypt_guard
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg
[mit-url]: https://github.com/mm9942/CryptGuardLib/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v1.1-yellow.svg
[doc-url]: https://docs.rs/crypt_guard/
[lib-badge]: https://img.shields.io/badge/github-lib-black.svg
[lib-link]: https://github.com/mm9942/CryptGuardLib
[cli-badge]: https://img.shields.io/badge/github-cli-white.svg
[cli-link]: https://github.com/mm9942/CryptGuard

## Introduction

CryptGuard is a comprehensive cryptographic library, offering robust encryption and decryption capabilities. It integrates traditional cryptography with post-quantum algorithms, ensuring resilience against quantum computing threats. Designed for developers, CryptGuard empowers applications to withstand future digital security challenges. Embrace CryptGuard as your trusted ally in safeguarding privacy in the digital realm.

## Key Features and Capabilities

This library supports AES-256 and XChaCha20 encryption algorithms, providing a secure means to protect data. To cater to a variety of security requirements and operational contexts, CryptGuard integrates seamlessly with Kyber512, Kyber768, and Kyber1024 for encryption, ensuring compatibility with post-quantum cryptography standards.

For developers who require digital signing capabilities, CryptGuard incorporates Falcon and Dilithium algorithms, offering robust options for creating and verifying digital signatures. This feature is particularly crucial for applications that necessitate authenticity and integrity of data, ensuring that digital communications remain secure and verifiable.

An additional layer of security is provided through the appending of a HMAC (Hash-Based Message Authentication Code) to encrypted data. This critical feature enables the authentication of encrypted information, ensuring that any tampering with the data can be reliably detected. This HMAC attachment underscores CryptGuard's commitment to comprehensive data integrity and security, offering developers and end-users peace of mind regarding the authenticity and safety of their data.

## Syntax Overhaul and Version Information

### Upcoming Changes

Our library is undergoing a syntax overhaul to enhance detail and clarity, addressing feedback for a more intuitive user experience. The current syntax focuses on providing a comprehensive understanding of the cryptographic processes, albeit with a different complexity level.

### Current Release

The present version, **1.1.4**, emphasizes detailed cryptographic operations. This version is ideal for those who want a fast but not too complicated, elaborate approach to cryptography and don't want to use asynchronous code. Asynchronous capabilities will be reimplemented in a later update (but this time as a feature). For those who prefer an easier syntax, they should just use version 1.0.3 until a later update is released. This version's syntax is more user-friendly and does not require the definition of too many structs like in 1.1.1 or 1.1.0 but allows for precise control over the encryption and decryption algorithm as well as the Kyber key size. It allows the usage of Kyber1024, Kyber768, and Kyber512.

### Future Release

A forthcoming update will introduce other bit sizes for Falcon and Dilithium. It will also introduce logging capabilities, not logging keys or original data, but rather information about which encryption algorithm (AES or XChaCha20) was used, whether it was a File or a Message, as well as the time it was used. Stay tuned for its release!

## Important Considerations

### Transition to the New Version

For those considering the transition to the updated version upon its release, familiarizing yourself with the current documentation and examples is recommended. This preparation will facilitate a smoother adaptation to the new syntax and features. The next upcoming versions will gradually change the syntax and often implement things you don't need to use in the next version anymore, but these structs and methods don't cease to exist; rather, they are now automatically implemented for easier usage. If you want to use them, don't hesitate to do so!

## Usage Examples

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

#### Signing and Verifying with Falcon

```rust
    use crate::signature::{falcon, SignatureKey, SignatureMechanism, Mechanism};

    // Generate a keypair using Falcon
    let falcon_keypair = falcon::keypair();

    // Sign a message
    let message = "This is a secret message";
    let signature = falcon::sign_msg(&falcon_keypair.secret_key, message.as_bytes()).expect("Signing failed");

    // Verify the signature
    let verified = falcon::verify_msg(&falcon_keypair.public_key, &signature, message.as_bytes()).expect("Verification failed");´
```

#### Signing and Verifying with Dilithium

```rust
    use crate::signature::{dilithium, SignatureKey, SignatureMechanism, Mechanism};

    // Generate a keypair using Dilithium
    let dilithium_keypair = dilithium::keypair();

    // Sign a message
    let message = "Another secret message";
    let signature = dilithium::sign_msg(&dilithium_keypair.secret_key, message.as_bytes()).expect("Signing failed");

    // Verify the signature
    let verified = dilithium::verify_msg(&dilithium_keypair.public_key, &signature, message.as_bytes()).expect("Verification failed");´
```


### Conclusion and Looking Forward

We appreciate your engagement with our cryptographic library. As we strive to improve and evolve, your feedback and contributions are invaluable. The anticipated update promises to make cryptography more accessible and straightforward for everyone.

Thank you for your support and for making security a priority in your projects.

## License
CryptGuard is licensed under the MIT LICENSE. The full license text is available in the `LICENSE` file in the repository.