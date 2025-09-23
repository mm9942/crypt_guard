# CryptGuard Programming Library

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![GitHub Library][lib-badge]][lib-link]

[crates-badge]: https://img.shields.io/badge/crates.io-v1.4.1-blue.svg?style=for-the-badge
[crates-url]: https://crates.io/crates/crypt_guard
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
[mit-url]: https://github.com/mm9942/crypt_guard/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v1.4.1-yellow.svg?style=for-the-badge
[doc-url]: https://docs.rs/crypt_guard/
[lib-badge]: https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge
[lib-link]: https://github.com/mm9942/crypt_guard

## Introduction

CryptGuard is a comprehensive cryptographic library, offering robust encryption and decryption capabilities. It integrates traditional cryptography with post-quantum algorithms, ensuring resilience against quantum computing threats. Designed for developers, CryptGuard empowers applications to withstand future digital security challenges. Embrace CryptGuard as your trusted ally in safeguarding privacy in the digital realm.

## Key Features and Capabilities

 - **Symmetric Encryption:** AES-256 and XChaCha20 for robust data protection.
 - **Post-Quantum Key Exchange:** Kyber512, Kyber768, and Kyber1024 for future-proof security.
 - **Digital Signatures:** Falcon and Dilithium to ensure authenticity and integrity.
 - **Data Integrity:** HMAC (Hash-Based Message Authentication Code) appended to encrypted data to detect tampering.

## Version Information

### What’s New in v1.4.2

- New builder API for encryption/decryption, key generation, and signatures.
- Macros and examples now use snake_case names (e.g., `encryption!`, `decrypt_file!`).
- Added AES_GCM_SIV and AES_CTR; AES_XTS for data-at-rest.
- Added XChaCha20Poly1305 authenticated cipher.
- Updated docs and examples to match the new API and naming.

### Latest Features

**New AES Modes:** We added AES_GCM_SIV and AES_CTR as secure alternatives to the legacy AES (ECB) path. Both use securely generated nonces/IVs and integrate with the same macros you already use.

**Added AES_XTS:** AES-XTS is now available for data-at-rest scenarios. It derives two subkeys internally and provides sector-based encryption with HMAC authentication. Access it via the same `encryption!`/`decryption!` macros or by using `Kyber<..., AES_XTS>`.

**Added XChaCha20Poly1305:** Alongside XChaCha20, the authenticated XChaCha20-Poly1305 variant is now supported. Nonces are generated automatically on encryption and required for decryption (returned by the macro and stored on the Kyber instance).

**Removed Legacy Module:** The obsolete storage component has been eliminated to streamline the core library.

**AES Modes Overview:** We now provide AES_GCM_SIV, AES_CTR, and AES_XTS as secure alternatives to AES-ECB. These modes use randomly generated Initialization Vectors (IVs) for enhanced security. We are also planning to add CBC and other modes for greater versatility.

#### Summary of AES Modes

1. **AES_GCM_SIV**: A variant of Galois Counter Mode (GCM) that includes a Synthetic Initialization Vector (SIV) to mitigate misuse vulnerabilities. It ensures data security even if IVs are reused and provides authenticated encryption, combining confidentiality and integrity. Suitable for distributed systems with lower entropy.

2. **AES_CTR**: Operates as a stream cipher using a counter for each block, making it efficient for parallel processing. It lacks inherent data authentication, so it is often paired with a MAC. AES_CTR is ideal for secure data transmission where speed and parallelizability are crucial.

3. **XChaCha20Poly1305**: A variant of ChaCha20 with a 192-bit extended nonce, which provides increased security against nonce reuse. It is combined with the Poly1305 message authentication code to ensure data integrity and confidentiality. XChaCha20Poly1305 offers better performance than AES, especially in software-based implementations, and is highly secure due to the larger nonce size.

#### Comparison with XChaCha20 and AES-ECB

**XChaCha20**: A stream cipher that offers security equivalent to AES but with better performance and ease of use. It uses a 192-bit nonce to minimize nonce reuse risks and provides authenticated encryption. XChaCha20 is ideal for high-performance applications like encrypted messaging.

**AES (ECB)**: Encrypts each plaintext block separately, making it insecure as identical blocks produce identical ciphertext. It reveals data patterns, which makes it unsuitable for most secure contexts.

#### General Differences

- **Security**: AES_GCM_SIV, AES_CTR, and XChaCha20Poly1305 mitigate the security flaws of AES-ECB by adding randomness and integrity checks, whereas ECB exposes data patterns.
- **Performance**: AES_CTR and XChaCha20Poly1305 offer fast, parallelizable encryption, with XChaCha20Poly1305 being particularly resistant to nonce reuse issues. AES_GCM_SIV provides additional integrity checks.
- **Complexity**: AES_GCM_SIV and XChaCha20Poly1305 are more complex to implement but offer significant security improvements over ECB.

In summary, AES_GCM_SIV, AES_CTR, AES_XTS, and XChaCha20Poly1305 provide stronger security properties than AES-ECB, with XChaCha20Poly1305 offering efficient AEAD for scenarios where performance and nonce management are crucial, and AES_XTS being suited for data-at-rest.

**Encryption Macro for AES_GCM_SIV:** `let (encrypt_message, cipher, iv) = encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_GCM_SIV);`

**Decryption Macro for AES_GCM_SIV:** `let decrypted_data = decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, Some(iv): Option<String>, AES_GCM_SIV)`

**Encryption Macro for AES_CTR:** `let (encrypt_message, cipher, iv) = encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_CTR);`

**Decryption Macro for AES_CTR:** `let decrypted_data = decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, Some(iv): Option<String>, AES_CTR)`

**Encryption Macro for AES_XTS:** `let (encrypt_message, cipher) = encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_XTS);`

**Decryption Macro for AES_XTS:** `let decrypted_data = decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, AES_XTS)`


**Encryption Macro for XChaCha20Poly1305:** `let (encrypt_message, cipher, nonce) = encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, XChaCha20Poly1305);`

**Decryption Macro for XChaCha20Poly1305:** `let decrypted_data = decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, Some(nonce): Option<String>, XChaCha20Poly1305)`

The macros now automatically zero out the used values to enhance data security during execution. For other execution methods, ensure data safety by manually addressing confidentiality. Developers using this crate are responsible for securely storing, hiding, and zeroing out keys in memory to protect encrypted information. As these values are generated, they fall outside my control for adding security measures. Note that the macros now require data ownership; to ensure safety, avoid cloning and instead use `.to_owned()`.

**Regarding the transfer of ownership, please take a look at the `src` folder in the Git repository. It contains the `tests` module folder and the test file `MacroTests.rs`, which uses the approach mentioned. The same is true for `KyberTests` and parts of the example `encrypt_aes.rs`.**

### Current Release

The current version, **1.4.1**, focuses on detailed cryptographic operations with enhanced data handling through automated macros. These macros simplify execution by wrapping up the necessary steps of definition, leveraging generic types and trait definitions. This version avoids asynchronous code, which will be reintroduced as a feature in future updates. Users preferring async implementation should use version 1.0.3. Note that version 1.0.3 uses the old syntax and has indirect documentation through the README, lacking Cargo's auto-generated documentation due to missing comments. The new version offers user-friendly syntax, reducing the need for extensive struct definitions, and supports Kyber1024, Kyber768, and Kyber512, along with logging capabilities.

### Simplifying Encryption and Decryption with Macros

We've introduced new macros to make the encryption and decryption processes more straightforward since we only separate into encryption of bytes and automated encryption of files, thus providing an alternative to the need of manually invoking specific functions such as `encrypt_msg`, `encrypt_file`, `encrypt_data`, and their decryption equivalents. Here’s a guide on how to effectively utilize these macros:

- **Encryption Macro**: Use the `encryption!` macro for seamless encryption tasks. Provide it with a Kyber public key and its size, the data you want to encrypt (as a `Vec<u8>`), a passphrase (as a string slice `&str`), and finally declare which encryption algorithm should be used.

  **Syntax**:
  ```rust
  encryption!(public_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase, [ AES | XChaCha20 ])
  ```

- **Decryption Macro**: The `decryption!` macro simplifies the decryption process. Supply it with a secret Kyber key, the key size, the encrypted data (as `Vec<u8>`), the passphrase, the ciphertext, and finally declare which encryption algorithm should be used.

  **Syntax**:
  ```rust
  decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase, cipher, | add nonce here, when using XChaCha20 | , [ AES | XChaCha20 ])
  ```

- **File Encryption Macro**: We've also implemented a macro specifically for file encryption, `encrypt_file!()`. This macro is similar to `encryption!` but takes a `PathBuf` for file paths instead of `Vec<u8>`.

  **Syntax**:
  ```rust
  encrypt_file!(public_key, [ 1024 | 768 | 512 ], data: PathBuf, passphrase, [ AES | XChaCha20 ])
  ```

- **File Decryption Macro**: Corresponding to the file encryption macro, the `decrypt_file!()` macro is designed for file decryption, accepting a `PathBuf` instead of `Vec<u8>`.

  **Syntax**:
  ```rust
  decrypt_file!(secret_key, [ 1024 | 768 | 512 ], data: PathBuf, passphrase, cipher, | add nonce here, when using XChaCha20 | , [ AES | XChaCha20 ])
  ```

These macros are intended to make your cryptographic operations more intuitive and less prone to errors, by removing the complexities associated with selecting the appropriate function for different data types. Note that with these macros, it is necessary to convert messages into `Vec<u8>` before encryption.

#### Other Changes

- **Simplified Syntax**: We've re-engineered the use of Dilithium and Falcon, adopting a straightforward, modular, and flexible approach akin to our encryption and decryption syntax. This enhancement aims to streamline operations for developers.

- **Designed for Versatility**: Our library now accommodates various key sizes beyond Falcon1024 and Dilithium5. Specifically, we've introduced Falcon512 for those needing a 512-bit key size. For Dilithium users, we've added support for Dilithium2 and Dilithium3, expanding the range of cryptographic strengths available.

- **Flexibility and Modularity**: The recent changes to our implementation for Dilithium and Falcon emphasize a generic and unified interface. This approach not only simplifies usage but also grants developers the flexibility to integrate different algorithms and signature modes seamlessly into their projects. By abstracting the complexity, we ensure that you can focus on what matters most - securing your applications efficiently.

- **Logging Functionality**: CryptGuard now includes a new logging feature designed to enhance operational transparency and assist in debugging processes. This logging functionality meticulously records every significant step in the cryptographic process without compromising security. Specifically, it logs the initiation and completion of key generation, message encryption, and decryption processes, including the cryptographic algorithm used (e.g., AES, XChaCha20) and the key encapsulation mechanism (e.g., Kyber1024). Importantly, to uphold the highest standards of security and privacy, CryptGuard's logging mechanism is carefully designed to exclude sensitive information such as encryption keys, unencrypted data, file paths, or any personally identifiable information. This ensures that while users benefit from detailed logs that can aid in troubleshooting and verifying cryptographic operations, there is no risk of exposing sensitive data.

The logging functionality can be activated via the attribute `#[activate_log("LogFilename.txt")]` and requires calling `initialize_logger();`.

## Code Style

Starting with v1.4.1, public macros and functions use snake_case:

- Macros: `encryption!`, `decryption!`, `encrypt_file!`, `decrypt_file!`, `kyber_keypair!`, `falcon_keypair!`, `dilithium_keypair!`, `signature!`, `verify!`, `archive_util!`.
- Methods: builder methods like `key`, `key_size`, `data`, `file`, `passphrase`, `algorithm`, `run` use snake_case.
- Types remain CamelCase per Rust conventions (e.g., `Kyber`, `Encryption`, `Kyber1024`, `AES`).

## Usage Examples

### Encrypt+Sign and Decrypt+Open (macros)

The `encrypt_sign!` and `decrypt_open!` macros combine Kyber encryption with Falcon signing. They expect Kyber-1024 for KEM and Falcon-1024 for signatures by default.

```rust
use crypt_guard::{*, kdf::*};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"hey, how are you doing?".to_vec();

    // Falcon-1024 (512 also available)
    let (falcon_pub, falcon_sec) = falcon_keypair!(1024);

    // Kyber-1024 (768 and 512 also available)
    let (kyber_pub, kyber_sec) = kyber_keypair!(1024);

    // Encrypt and sign (returns Result<(content, cipher), CryptError>)
    let (ciphertext, cipher) = encrypt_sign!(kyber_pub, falcon_sec, message.clone(), "passphrase")?;

    // Decrypt and open (returns the verified plaintext directly)
    let plaintext = decrypt_open!(kyber_sec, falcon_pub, ciphertext, "passphrase", cipher);
    assert_eq!(plaintext, message);
    Ok(())
}
```

### New signature and verify macros

##### Detached Signature

```rust
use crypt_guard::{*, kdf::*};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"hey, how are you?".to_vec();
    let (public_key, secret_key) = falcon_keypair!(1024);

    let sig = signature!(Falcon, secret_key, 1024, data.clone(), Detached)?;
    let ok = verify!(Falcon, public_key, 1024, sig, data.clone(), Detached)?;
    assert!(ok);
    Ok(())
}
```

##### Signed Message

```rust
use crypt_guard::{*, kdf::*};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"hey, how are you?".to_vec();
    let (public_key, secret_key) = dilithium_keypair!(5);

    let signed = signature!(Dilithium, secret_key, 5, data.clone(), Message)?;
    let opened = verify!(Dilithium, public_key, 5, signed, Message)?;
    assert_eq!(opened, data);
    Ok(())
}
```

### Encryption and decryption (macros)

Data (Vec<u8>) with AES-256 using Kyber-1024:

```rust
use crypt_guard::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let msg = b"Hey, how are you?".to_vec();
    let pass = "Test Passphrase";
    let (pk, sk) = kyber_keypair!(1024);

    let (enc, cipher) = encryption!(pk, 1024, msg.clone(), pass, AES)?;
    let dec = decryption!(sk, 1024, enc, pass, cipher, AES)?;
    assert_eq!(dec, msg);
    Ok(())
}
```

#### File encryption/decryption (macros)

```rust
use crypt_guard::*;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pass = "Test Passphrase";
    let (pk, sk) = kyber_keypair!(1024);

    // Prepare a file to encrypt
    let path = PathBuf::from("./message.txt");
    fs::write(&path, b"Hello file!")?;

    // Encrypt file with AES
    let (_content, cipher) = encrypt_file!(pk, 1024, path.clone(), pass, AES)?;

    // Decrypt file back; input is the generated .enc file
    let dec = decrypt_file!(sk, 1024, PathBuf::from("./message.txt.enc"), pass, cipher, AES)?;
    assert_eq!(String::from_utf8(dec)?, "Hello file!");
    Ok(())
}
```

XChaCha20 requires handling a nonce (returned by the encrypt macro and required on decrypt):

```rust
use crypt_guard::*;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pass = "Test Passphrase";
    let (pk, sk) = kyber_keypair!(768);

    let p = PathBuf::from("./note.txt");
    fs::write(&p, b"XC20!")?;

    let (_enc, cipher, nonce) = encrypt_file!(pk, 768, p.clone(), pass, XChaCha20)?;

    // remove plaintext to mimic typical flow
    let _ = fs::remove_file(&p);

    let dec = decrypt_file!(sk, 768, PathBuf::from("./note.txt.enc"), pass, cipher, Some(nonce), XChaCha20)?;
    assert_eq!(String::from_utf8(dec)?, "XC20!");
    Ok(())
}
```

### Logging

CryptGuard recently introduced a new logging feature, meticulously designed to offer comprehensive insights into cryptographic operations while prioritizing security and privacy.

#### Activating the log is enough

Upon activation, CryptGuard logs each significant cryptographic operation, including key generation, encryption, and decryption processes. These logs are stored in log.txt and, for enhanced organization and accessibility, are also split into individual process logs within an automatically created directory named after the log file (log).

```rust
use crypt_guard::*;

#[activate_log("log.txt")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Make the helper from the proc-macro available
    let _ = initialize_logger();

    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    let (public_key, secret_key) = kyber_keypair!(1024);
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None)?;
    let (encrypted, cipher) = encryptor.encrypt_msg(message, passphrase)?;

    let decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?;
    let decrypted = decryptor.decrypt_msg(encrypted, passphrase, cipher)?;
    assert_eq!(String::from_utf8(decrypted)?, message);
    Ok(())
}
```

### New signature syntax for dilithium and falcon

#### Signing and opening (Falcon)

```rust
use crypt_guard::kdf::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon1024::keypair()?;
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Falcon1024, Message>::new();
    let signed_message = sign.signature(data.clone(), secret_key)?;
    let opened_message = sign.open(signed_message, public_key)?;
    assert_eq!(opened_message, data);
    Ok(())
}
```

#### Creating and verifying detached signature with Dilithium 5

```rust
use crypt_guard::kdf::*;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load previously-saved keys
    let public_key = Dilithium5::load(&PathBuf::from("./Dilithium5/key.pub"))?;
    let secret_key = Dilithium5::load(&PathBuf::from("./Dilithium5/key.sec"))?;

    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Dilithium5, Detached>::new();
    let sig = sign.signature(data.clone(), secret_key)?;
    let ok = sign.verify(data, sig, public_key)?;
    assert!(ok);
    Ok(())
}
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

### Encryption of a Message using AES

For the low-level API, instantiate the correct `Kyber<...>` type and call the method that matches your content shape.

```rust
use crypt_guard::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = kyber_keypair!(1024);
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Encrypt a message string
    let mut enc = Kyber::<Encryption, Kyber1024, Message, AES>::new(public_key.clone(), None)?;
    let (encrypted, cipher) = enc.encrypt_msg(message, passphrase)?;

    // Decrypt back
    let dec = Kyber::<Decryption, Kyber1024, Message, AES>::new(secret_key, None)?
        .decrypt_msg(encrypted, passphrase, cipher)?;
    assert_eq!(String::from_utf8(dec)?, message);
    Ok(())
}
```

### Encryption of Data (bytes) using AES

```rust
use crypt_guard::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = kyber_keypair!(1024);
    let data = b"Hey, how are you doing?".to_vec();
    let passphrase = "Test Passphrase";

    let mut enc = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.clone(), None)?;
    let (encrypted, cipher) = enc.encrypt_data(data.clone(), passphrase)?;

    let dec = Kyber::<Decryption, Kyber1024, Data, AES>::new(secret_key, None)?
        .decrypt_data(encrypted, passphrase, cipher)?;
    assert_eq!(dec, data);
    Ok(())
}
```

### Decryption of a File using AES

```rust
use crypt_guard::*;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kc = KeyControl::<KeyControKyber1024>::new();
    let cipher = kc.load(KeyTypes::Ciphertext, Path::new("./key/ciphertext.ct"))?;
    let secret_key = kc.load(KeyTypes::SecretKey, Path::new("./key/secret_key.sec"))?;

    let dec = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?
        .decrypt_file(PathBuf::from("./message.txt.enc"), "pass", cipher)?;
    println!("{}", String::from_utf8(dec)?);
    Ok(())
}
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
let mut encryptor = Kyber::<Encryption, Kyber768, Files, XChaCha20>::new(public_key.clone(), None)?;

// Encrypt message
let (encrypt_message, cipher) = encryptor.encrypt_file(enc_path.clone(), passphrase.clone())?;

let nonce = encryptor.get_nonce();

fs::remove_file(enc_path.clone());

// Instantiate Kyber for decryption of a file with Kyber768 and XChaCha20
// Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
let mut decryptor = Kyber::<Decryption, Kyber768, Files, XChaCha20>::new(secret_key, Some(nonce?.to_string()))?;

// Decrypt message
let decrypt_message = decryptor.decrypt_file(dec_path.clone(), passphrase.clone(), cipher)?;
```

#### Zipping Files and Directories Using the ZipManager

CryptGuard introduces the `ZipManager`, a utility for archiving multiple files and directories into a single ZIP archive. This tool simplifies the process of creating ZIP files by providing an easy-to-use API. Macros for zipping will be added later.

##### Example 1: Zipping Both Files and Directories

In this example, we'll demonstrate how to zip multiple files and directories into one ZIP archive.

```rust
use crypt_guard::zip_manager::*;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("sample_dir/nested_dir")?;
    fs::write("file1.txt", "content1")?;
    fs::write("sample_dir/file2.txt", "content2")?;

    let output_zip = "archive_with_dirs.zip";
    let mut manager = ZipManager::new(output_zip);
    manager.add_file("file1.txt");
    manager.add_directory("sample_dir");
    manager.create_zip(Compression::Deflated)?;
    println!("ZIP archive created at {}", output_zip);

    // cleanup
    fs::remove_file("file1.txt")?;
    fs::remove_dir_all("sample_dir")?;
    fs::remove_file(output_zip)?;
    Ok(())
}
```

##### Example 2: Zipping Multiple Files Only

Here's how to zip multiple individual files into a single ZIP archive.

```rust
use crypt_guard::zip_manager::*;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setting up sample files
    fs::write("file1.txt", "Content of file1")?;
    fs::write("file2.txt", "Content of file2")?;
    fs::write("file3.txt", "Content of file3")?;
    
    // Specify the output ZIP file path
    let output_zip = "archive_with_files.zip";
    
    // Create a new ZipManager instance
    let mut manager = ZipManager::new(output_zip);
    
    // Add files to zip
    manager.add_file("file1.txt");
    manager.add_file("file2.txt");
    manager.add_file("file3.txt");
    
    // Create the ZIP archive with Deflated compression
    manager.create_zip(Compression::Deflated)?;
    
    println!("ZIP archive created at {}", output_zip);
    
    // Cleanup sample files
    fs::remove_file("file1.txt")?;
    fs::remove_file("file2.txt")?;
    fs::remove_file("file3.txt")?;
    
    Ok(())
}
```

##### Compression Methods

The `ZipManager` allows you to choose from different compression methods depending on your needs. The available options are:

- **`Compression::stored()`**: No compression is applied. Use this option for faster archiving when compression is unnecessary.
- **`Compression::deflated()`**: Standard ZIP compression. Offers a good balance between compression ratio and speed.
- **`Compression::zip2()`**: Uses Bzip2 compression. Provides higher compression ratios but may be slower.
- **`Compression::zstd()`**: Uses Zstandard compression. Offers high compression ratios and speed. Note that to use Zstandard compression, you need to enable the `zstd` feature in the `zip` crate.

### Archiving and Extracting with Macros

##### 1. `archive!` Macro

**Syntax:**
```rust
archive!(source_path, delete_dir);
```

- **`$source_path`**: The path to the directory or file you wish to archive. It can be provided as a `&str` or a `PathBuf`.
- **`$delete_dir`**: A boolean flag indicating whether to delete the original directory or file after archiving (`true` to delete, `false` to retain).

**Example:**
```rust
use crypt_guard::archive;
use std::path::PathBuf;

fn main() {
    let source = PathBuf::from("/path/to/source_directory");
    
    // Archive the directory without deleting the source
    archive!(source, false);
    
    // Archive the directory and delete the source after archiving
    archive!(source, true);
}
```

##### 2. `extract!` Macro

**Syntax:**
```rust
extract!(archive_path, delete_archive);
```

- **`$archive_path`**: The path to the `.tar.xz` archive you intend to extract. It can be a `&str` or a `PathBuf`.
- **`$delete_archive`**: A boolean flag indicating whether to delete the archive file after extraction (`true` to delete, `false` to retain).

**Example:**
```rust
use crypt_guard::extract;
use std::path::PathBuf;

fn main() {
    let archive = PathBuf::from("/path/to/archive.tar.xz");
    
    // Extract the archive without deleting the archive file
    extract!(archive, false);
    
    // Extract the archive and delete the archive file after extraction
    extract!(archive, true);
}
```

## Builder API (v1.4.1)

The builder-style API simplifies common workflows. End-to-end example for data with AES:

```rust
use crypt_guard::{EncryptBuilder, DecryptBuilder, KyberKeygenBuilder, SymmetricAlg};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (public, secret) = KyberKeygenBuilder::new().size(1024).generate()?;
    let enc = EncryptBuilder::new()
        .key(public)
        .key_size(1024)
        .data(b"hello".to_vec())
        .passphrase("pass")
        .algorithm(SymmetricAlg::Aes)
        .run()?;

    let dec = DecryptBuilder::new()
        .key(secret)
        .key_size(1024)
        .data(enc.content)
        .passphrase("pass")
        .cipher(enc.cipher)
        .algorithm(SymmetricAlg::Aes)
        .run()?;

    assert_eq!(dec, b"hello".to_vec());
    Ok(())
}
```

Using XChaCha20 (note the nonce handling):

```rust
use crypt_guard::{EncryptBuilder, DecryptBuilder, KyberKeygenBuilder, SymmetricAlg};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (public, secret) = KyberKeygenBuilder::new().size(1024).generate()?;
    let enc = EncryptBuilder::new()
        .key(public)
        .key_size(1024)
        .data(b"hello".to_vec())
        .passphrase("pass")
        .algorithm(SymmetricAlg::XChaCha20)
        .run()?;

    let nonce = enc.nonce.expect("nonce required for XChaCha20");
    let dec = DecryptBuilder::new()
        .key(secret)
        .key_size(1024)
        .data(enc.content)
        .passphrase("pass")
        .cipher(enc.cipher)
        .nonce(nonce)
        .algorithm(SymmetricAlg::XChaCha20)
        .run()?;

    assert_eq!(dec, b"hello".to_vec());
    Ok(())
}
```

Signing and verification via builders:

```rust
use crypt_guard::{SignBuilder, VerifyBuilder, SignAlgorithm, SignMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"hello".to_vec();
    let (public, secret) = crypt_guard::kdf::Falcon1024::keypair()?;

    let signed = SignBuilder::new()
        .algorithm(SignAlgorithm::Falcon1024)
        .mode(SignMode::Message)
        .key(secret)
        .data(data.clone())
        .sign()?;

    let opened = VerifyBuilder::new()
        .algorithm(SignAlgorithm::Falcon1024)
        .mode(SignMode::Message)
        .key(public)
        .signed_message(signed)
        .open()?;

    assert_eq!(opened, data);
    Ok(())
}
```

##### 3. `archive_util!` Macro

**Syntax:**
```rust
archive_util!(path, delete_flag, Variant);
```

- **`$path`**: The path to the directory/file to archive or the archive file to extract. Accepts a `&str` or a `PathBuf`.
- **`$delete_flag`**: A boolean indicating whether to delete the original directory/file or the archive file after the operation.
- **`Variant`**: Specifies the operation type. Use `Archive` to compress and `Extract` to decompress.

**Variants:**
- **`Archive`**: Compresses the specified directory or file.
- **`Extract`**: Decompresses the specified archive file.

**Example:**
```rust
use crypt_guard::archive_util;
use std::path::PathBuf;

fn main() {
    let source = PathBuf::from("/path/to/source_directory");
    let archive = PathBuf::from("/path/to/archive.tar.xz");
    
    // Using archive_util! to archive without deleting the source
    archive_util!(source, false, Archive);
    
    // Using archive_util! to extract and delete the archive file after extraction
    archive_util!(archive, true, Extract);
}
```

#### News regarding the CLI version [![Crates.io][cli-badge]][cli-link]
[cli-badge]: https://img.shields.io/badge/github-cli-black.svg
[cli-link]: https://github.com/mm9942/crypt_guard_cli

I have almost finished each subcommand, with only the verify subcommand remaining. After completing this, I will test signing and verification. The pre-release is now available on GitHub, and the finished product should be released within a few days or by the end of the month at the latest!

### Conclusion and Looking Forward

We appreciate your engagement with our cryptographic library. As we strive to improve and evolve, your feedback and contributions are invaluable. The anticipated update promises to make cryptography more accessible and straightforward for everyone.

Thank you for your support and for making security a priority in your projects.

## License
CryptGuard is licensed under the MIT LICENSE. The full license text is available in the `LICENSE` file in the repository.
