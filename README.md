# CryptGuard Programming Library

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![Hashnode Blog][blog-badge]][blog-url]
[![GitHub Library][lib-badge]][lib-link]

[blog-badge]: https://img.shields.io/badge/blog-hashnode-lightblue.svg?style=for-the-badge
[blog-url]: https://blog.mm29942.com/
[crates-badge]: https://img.shields.io/badge/crates.io-v1.3-blue.svg?style=for-the-badge
[crates-url]: https://crates.io/crates/crypt_guard
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
[mit-url]: https://github.com/mm9942/crypt_guard/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v1.3-yellow.svg?style=for-the-badge
[doc-url]: https://docs.rs/crypt_guard/
[lib-badge]: https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge
[lib-link]: https://github.com/mm9942/crypt_guard

## Introduction

CryptGuard is a comprehensive cryptographic library, offering robust encryption and decryption capabilities. It integrates traditional cryptography with post-quantum algorithms, ensuring resilience against quantum computing threats. Designed for developers, CryptGuard empowers applications to withstand future digital security challenges. Embrace CryptGuard as your trusted ally in safeguarding privacy in the digital realm.

## Key Features and Capabilities

This library supports AES-256 and XChaCha20 encryption algorithms, providing a secure means to protect data. To cater to a variety of security requirements and operational contexts, CryptGuard integrates seamlessly with Kyber512, Kyber768, and Kyber1024 for encryption, ensuring compatibility with post-quantum cryptography standards.

For developers who require digital signing capabilities, CryptGuard incorporates Falcon and Dilithium algorithms, offering robust options for creating and verifying digital signatures. This feature is particularly crucial for applications that necessitate authenticity and integrity of data, ensuring that digital communications remain secure and verifiable.

An additional layer of security is provided through the appending of a HMAC (Hash-Based Message Authentication Code) to encrypted data. This critical feature enables the authentication of encrypted information, ensuring that any tampering with the data can be reliably detected. This HMAC attachment underscores CryptGuard's commitment to comprehensive data integrity and security, offering developers and end-users peace of mind regarding the authenticity and safety of their data.

## Version Information

### Latest Features

**New AES Modes:** We have implemented the block modes AES_GCM_SIV and AES_CTR as secure alternatives to the pure AES implementation based on the ECB block mode. The new GCM_SIV and CTR block mode implementations work with randomly generated IVs. We also added functions for device lookup and implemented AES with the XTS block mode and system command device handling for Linux to handle device encryption. Device control is currently in a beta stage and may contain some bugs. Use the AES_GCM_SIV implementation via the macro in the same way you use XChaCha20.

**AES Modes Overview:** We have implemented AES_GCM_SIV and AES_CTR as secure alternatives to AES in ECB mode. These new modes use randomly generated Initialization Vectors (IVs) for enhanced security. We are also planning to add AES_XTS, CBC, and other modes for greater versatility.

#### Summary of AES Modes

1. **AES_GCM_SIV**: A variant of Galois Counter Mode (GCM) that includes a Synthetic Initialization Vector (SIV) to mitigate misuse vulnerabilities. It ensures data security even if IVs are reused and provides authenticated encryption, combining confidentiality and integrity. Suitable for distributed systems with lower entropy.

2. **AES_CTR**: Operates as a stream cipher using a counter for each block, making it efficient for parallel processing. It lacks inherent data authentication, so it is often paired with a MAC. AES_CTR is ideal for secure data transmission where speed and parallelizability are crucial.

3. **AES_XTS**: Designed for encrypting data on disk, using two keys to resist attacks targeting ciphertext patterns. It ensures different encryption of identical blocks based on their locations, making it ideal for storage-based encryption.

4. **XChaCha20Poly1305**: A variant of ChaCha20 with a 192-bit extended nonce, which provides increased security against nonce reuse. It is combined with the Poly1305 message authentication code to ensure data integrity and confidentiality. XChaCha20Poly1305 offers better performance than AES, especially in software-based implementations, and is highly secure due to the larger nonce size.

#### Comparison with XChaCha20 and AES-ECB

**XChaCha20**: A stream cipher that offers security equivalent to AES but with better performance and ease of use. It uses a 192-bit nonce to minimize nonce reuse risks and provides authenticated encryption. XChaCha20 is ideal for high-performance applications like encrypted messaging.

**AES (ECB)**: Encrypts each plaintext block separately, making it insecure as identical blocks produce identical ciphertext. It reveals data patterns, which makes it unsuitable for most secure contexts.

#### General Differences

- **Security**: AES_GCM_SIV, AES_CTR, AES_XTS, and XChaCha20Poly1305 mitigate the security flaws of AES-ECB by adding randomness and integrity checks, whereas ECB exposes data patterns.
- **Performance**: AES_CTR and XChaCha20Poly1305 offer fast, parallelizable encryption, with XChaCha20Poly1305 being particularly resistant to nonce reuse issues. AES_GCM_SIV provides additional integrity checks.
- **Complexity**: AES_GCM_SIV and XChaCha20Poly1305 are more complex to implement but offer significant security improvements over ECB.

In summary, AES_GCM_SIV, AES_CTR, AES_XTS, and XChaCha20Poly1305 provide better security than AES-ECB, with XChaCha20Poly1305 being an efficient alternative for scenarios where performance and nonce management are crucial.

**Encryption Macro for AES_GCM_SIV:** `let (encrypt_message, cipher, iv) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_GCM_SIV);`

**Decryption Macro for AES_GCM_SIV:** `let decrypted_data = Decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, Some(iv): Option<String>, AES_GCM_SIV)`

**Encryption Macro for AES_CTR:** `let (encrypt_message, cipher, iv) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_CTR);`

**Decryption Macro for AES_CTR:** `let decrypted_data = Decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, Some(iv): Option<String>, AES_CTR)`

**Encryption Macro for AES_XTS:** `let (encrypt_message, cipher) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, AES_XTS);`

**Decryption Macro for AES_XTS:** `let decrypted_data = Decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, AES_XTS)`

**Encryption Macro for XChaCha20Poly1305:** `let (encrypt_message, cipher, nonce) = Encryption!(key.to_owned(), 1024, message.to_vec(), passphrase, XChaCha20Poly1305);`

**Decryption Macro for XChaCha20Poly1305:** `let decrypted_data = Decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, Some(nonce): Option<String>, XChaCha20Poly1305)`

The macros now automatically zero out the used values to enhance data security during execution. For other execution methods, ensure data safety by manually addressing confidentiality. Developers using this crate are responsible for securely storing, hiding, and zeroing out keys in memory to protect encrypted information. As these values are generated, they fall outside my control for adding security measures. Note that the macros now require data ownership; to ensure safety, avoid cloning and instead use `.to_owned()`.

**Regarding the transfer of ownership, please take a look at the `src` folder in the Git repository. It contains the `tests` module folder and the test file `MacroTests.rs`, which uses the approach mentioned. The same is true for `KyberTests` and parts of the example `encrypt_aes.rs`.**

### Current Release

The current version, **1.3.10**, focuses on detailed cryptographic operations with enhanced data handling through automated macros. These macros simplify execution by wrapping up the necessary steps of definition, leveraging generic types and trait definitions. This version avoids asynchronous code, which will be reintroduced as a feature in future updates. Users preferring async implementation should use version 1.0.3. Note that version 1.0.3 uses the old syntax and has indirect documentation through the README, lacking Cargo's auto-generated documentation due to missing comments. The new version offers user-friendly syntax, reducing the need for extensive struct definitions, and supports Kyber1024, Kyber768, and Kyber512, along with logging capabilities.

### Simplifying Encryption and Decryption with Macros

We've introduced new macros to make the encryption and decryption processes more straightforward since we only separate into encryption of bytes and automated encryption of files, thus providing an alternative to the need of manually invoking specific functions such as `encrypt_msg`, `encrypt_file`, `encrypt_data`, and their decryption equivalents. Here’s a guide on how to effectively utilize these macros:

- **Encryption Macro**: Use the `Encryption!` macro for seamless encryption tasks. Provide it with a Kyber public key and it's size, the data you want to encrypt (as a `Vec<u8>`), a passphrase (as a string slice `&str`), and finally declarate which encryption algorithm should be used.

  **Syntax**:
  ```rust
  Encryption!(public_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase, [ AES | XChaCha20 ])
  ```

- **Decryption Macro**: The `Decryption!` macro simplifies the decryption process. Supply it with an secret_key of Kyber, the key size, the encrypted data (as `Vec<u8>`), the passphrase, the ciphertext, and finally declarate which encryption algorithm should be used.

  **Syntax**:
  ```rust
  Decryption!(secret_key, [ 1024 | 768 | 512 ], data: Vec<u8>, passphrase, cipher, | add nonce here, when using XChaCha20 | , [ AES | XChaCha20 ])
  ```

- **File Encryption Macro**: We've also implemented a macro specifically for file encryption, `EncryptFile!()`. This macro is similar to `Encryption!` but takes a `PathBuf` for file paths instead of `Vec<u8>`.

  **Syntax**:
  ```rust
  EncryptFile!(public_key, [ 1024 | 768 | 512 ], data: PathBuf, passphrase, [ AES | XChaCha20 ])
  ```

- **File Decryption Macro**: Corresponding to the file encryption macro, the `DecryptFile!()` macro is designed for file decryption, accepting a `PathBuf` instead of `Vec<u8>`.

  **Syntax**:
  ```rust
  DecryptFile!(secret_key, [ 1024 | 768 | 512 ], data: PathBuf, passphrase, cipher, | add nonce here, when using XChaCha20 | , [ AES | XChaCha20 ])
  ```

These macros are intended to make your cryptographic operations more intuitive and less prone to errors, by removing the complexities associated with selecting the appropriate function for different data types. Note that with these macros, it is necessary to convert messages into `Vec<u8>` before encryption.

#### Other Changes

- **Simplified Syntax**: We've re-engineered the use of Dilithium and Falcon, adopting a straightforward, modular, and flexible approach akin to our encryption and decryption syntax. This enhancement aims to streamline operations for developers.

- **Designed for Versatility**: Our library now accommodates various key sizes beyond Falcon1024 and Dilithium5. Specifically, we've introduced Falcon512 for those needing a 512-bit key size. For Dilithium users, we've added support for Dilithium2 and Dilithium3, expanding the range of cryptographic strengths available.

- **Flexibility and Modularity**: The recent changes to our implementation for Dilithium and Falcon emphasize a generic and unified interface. This approach not only simplifies usage but also grants developers the flexibility to integrate different algorithms and signature modes seamlessly into their projects. By abstracting the complexity, we ensure that you can focus on what matters most - securing your applications efficiently.

- **Logging Functionality**: CryptGuard now includes a new logging feature designed to enhance operational transparency and assist in debugging processes. This logging functionality meticulously records every significant step in the cryptographic process without compromising security. Specifically, it logs the initiation and completion of key generation, message encryption, and decryption processes, including the cryptographic algorithm used (e.g., AES, XChaCha20) and the key encapsulation mechanism (e.g., Kyber1024). Importantly, to uphold the highest standards of security and privacy, CryptGuard's logging mechanism is carefully designed to exclude sensitive information such as encryption keys, unencrypted data, file paths, or any personally identifiable information. This ensures that while users benefit from detailed logs that can aid in troubleshooting and verifying cryptographic operations, there is no risk of exposing sensitive data.

The logging functionality got restructured to be defined by a procedual macro, so it now gets activated using `#[crypt_guard::activate_log("LogFilename.txt")]`, it also requires the user to call `initialize_logger();`.

## Usage Examples

### New encrypt and signing as well as decrypt and open macros 

CryptGuard's newest release, introduced new macros for encryption and decryption with AES using a kyber1024 key as well as signing and opening of the data with falcon1024. Since these macros are provided for fast usage, the keysizes and the signing key type is already set by default. CryptGuard also introduced new macros for keypair generation.


```rust
use crate::{
    cryptography::{
        CryptographicInformation,
        CipherAES,
        hmac_sign::*, 
    },
    Core::kyber::KyberFunctions,
    KDF::*,
    *
}

let message = b"hey, how are you doing?".to_vec();

// Generate falcon1024 keys, alternativly available is the keysize 512.
// You can use for dilithium keypair generation DilithiumKeypair!( [ 2 | 3 | 5 ] )
let (public, secret) = FalconKeypair!(1024);

// Generate kyber1024 keys, alternativly available are the keysizes 768 and 512.
let (public_key, secret_key) = KyberKeypair!(1024);

// Encrypt and sign the data using the new EncryptSign macro, the first key is the public kyber key and the seccond is the secret falcon key.
let (encrypt_message, cipher) = EncryptSign!(public_key, secret, message.clone(), "hey, how are you?").unwrap();

// Decrypt and open the data using the new DecryptOpen macro, the first key is the secret kyber key and the seccond is the public falcon key.
let decrypt_message = DecryptOpen!(secret_key, public, encrypt_message, "hey, how are you?", cipher);
```

### New signature and verify macros

##### Detached Signature

```rust
use crypt_guard::{
    *,
    KDF::*,
    error::*,
}
    
let data = b"hey, how are you?".to_vec();
let (public_key, secret_key) = FalconKeypair!(1024);
let sign = Signature!(Falcon, secret_key, 1024, data.clone(), Detached);
let verified = Verify!(Falcon, public_key, 1024, sign.clone(), data.clone(), Detached);
```

##### Signed Message


```rust
use crypt_guard::{
    *,
    KDF::*,
    error::*,
}
    
let data = b"hey, how are you?".to_vec();
let (public_key, secret_key) = DilithiumKeypair!(5);
let sign = Signature!(Dilithium, secret_key, 5, data.clone(), Message);
let verified = Verify!(Dilithium, public_key, 5, sign.clone(), Message);
```

### New encryption and decryption macros

```rust
use crypt_guard::{
    KyberFunctions,
    KeyControKyber1024,
    KyberKeyFunctions,
    error::*,
    Encryption, 
    Decryption, 
    Kyber1024, 
    Message, 
    AES,
    Kyber,
};

// Since we only allow encryption/ decryption of Vec<u8> or files through selecting a path as &str, please use 
let message = "Hey, how are you doing?".as_bytes().to_owned();
let passphrase = "Test Passphrase";

// Generate key pair
let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

// Encrypt message with new encryption macro
// Provide it with an instance of Kyber configured for encryption, the data you want to encrypt (this can be a `PathBuf`, a string slice `&str`, or a byte vector `Vec<u8>`), a passphrase (as a string slice `&str`) and the declarator for the symmetric algorithm
let (encrypt_message, cipher) = Encryption!(public_key.clone(), 1024, message, passphrase, AES)?;

// Decrypt message with new decryption macro
// Provide it with a Kyber1024 secret_key for decryption, the data you want to decrypt (this can be a `PathBuf`, a string slice `&str`, or a byte vector `Vec<u8>`), a passphrase (as a string slice `&str`) as well as a ciphertext and the declarator for the symmetric algorithm
let decrypt_message = Decryption!(secret_key, 1024, encrypt_message, passphrase, cipher, AES);
println!("{}", String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string"));
Ok(())

```

#### Usage of the new macros with a file

```rust
use crypt_guard::{
    KyberFunctions,
    KeyControKyber1024,
    KyberKeyFunctions,
    error::*,
    Encryption, 
    Decryption, 
    Kyber1024, 
    Message, 
    AES,
    Kyber,
};

// Since we only allow encryption/ decryption of Vec<u8> or files through selecting a path as &str
let path = "./message.txt";
let passphrase = "Test Passphrase";

// Generate key pair
let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

// Encrypt message with new encryption macro
// Provide it with an instance of Kyber configured for encryption, the data you want to encrypt (this can be a `PathBuf`, a string slice `&str`, or a byte vector `Vec<u8>`), a passphrase (as a string slice `&str`) and boolean checking if it is a file
let (encrypt_message, cipher) = EncryptFile!(public_key.clone(), 1024, PathBuf::from(&path), passphrase, AES)?;

// Decrypt message with new decryption macro
// Provide it with an instance of Kyber configured for decryption, the data you want to decrypt (this can be a `PathBuf`, a string slice `&str`, or a byte vector `Vec<u8>`), a passphrase (as a string slice `&str`) as well as a ciphertext and boolean checking if it is a file
let decrypt_message = DecryptFile!(secret_key, 1024, PathBuf::from(format!("{}.enc", path)), passphrase, cipher, AES);
println!("{}", String::from_utf8(decrypt_message?).expect("Failed to convert decrypted message to string"));
Ok(())

```

### The Logging feature

CryptGuard recently introduced a new logging feature, meticulously designed to offer comprehensive insights into cryptographic operations while prioritizing security and privacy.

#### Activating the log is enough

Upon activation, CryptGuard logs each significant cryptographic operation, including key generation, encryption, and decryption processes. These logs are stored in log.txt and, for enhanced organization and accessibility, are also split into individual process logs within an automatically created directory named after the log file (log).

```rust
use crypt_guard::*;

#[activate_log("log.txt")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the logger struct which in the lib is defined through lazzy_static!
    let _ = initialize_logger(); 

    // Define message and passphrase
    let message = "Hey, how are you doing?";
    let passphrase = "Test Passphrase";

    // Generate key pair
    let (public_key, secret_key) = KeyControKyber1024::keypair().expect("Failed to generate keypair");

    // Instantiate Kyber for encryption with Kyber1024
    let mut encryptor = Kyber::<Encryption, Kyber1024, Files, AES>::new(public_key.clone(), None)?;

    // Encrypt message
    let (encrypt_message, cipher) = encryptor.encrypt_msg(message.clone(), passphrase.clone())?;

    // Instantiate Kyber for decryption with Kyber1024
    let mut decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?;

    // Decrypt message
    let decrypt_message = decryptor.decrypt_msg(encrypt_message.clone(), passphrase.clone(), cipher)?;

    // Convert Vec<u8> to String for comparison
    let decrypted_text = String::from_utf8(decrypt_message).expect("Failed to convert decrypted message to string");
    println!("{}", decrypted_text);
}
```

### New signature syntax for dilithium and falcon

#### Signing and opening from "messages" with Falcon

```rust
use crypt_guard::KDF::*;

// Create a new keypair
let (public_key, secret_key) = Falcon1024::keypair();

// Save the keys, in the case of Falcon1024, they are saved in the folder ./Falcon1024/key(.pub & .sec)
let _ = Falcon1024::save_public(&public_key);
let _ = Falcon1024::save_secret(&secret_key);

let data = b"Hello, world!".to_vec();
let sign = Signature::<Falcon1024, Message>::new();
// Sign the message
let signed_message = sign.signature(data.clone(), secret_key);

// Open the message
let opened_message = sign.open(signed_message, public_key);
```

#### Creating and verifying detached signature with Dilithium 5

```rust
use crypt_guard::KDF::*;

// Load the public and secret dilithium 5 key
let public_key = Dilithium5::load(&PathBuf::from("./Dilithium5/key.pub"))?;
let secret_key = Dilithium5::load(&PathBuf::from("./Dilithium5/key.sec"))?;

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

### Encryption of a Message using AES

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

### Encryption of a Data using AES

```rust
let message = "Hey, how are you doing?".as_bytes().to_owned();
let passphrase = "Test Passphrase";

// Instantiate Kyber for encryption of a message with Kyber1024 and AES
// Fails when not using either of these properties since it would be the wrong type of algorithm, data, keysize or process!
let mut encryptor = Kyber::<Encryption, Kyber1024, Data, AES>::new(public_key.clone(), None)?;

// Encrypt message
let (encrypt_message, cipher) = encryptor.encrypt_data(message.clone(), passphrase.clone())?;

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
let mut decryptor = Kyber::<Decryption, Kyber1024, Files, AES>::new(secret_key, None)?;

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
use std::path::PathBuf;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setting up sample files and directories
    // Create a sample directory
    fs::create_dir_all("sample_dir")?;
    fs::create_dir_all("sample_dir/nested_dir")?;
    
    // Create sample files
    fs::write("file1.txt", "This is the content of file1.")?;
    fs::write("file2.txt", "This is the content of file2.")?;
    fs::write("sample_dir/file3.txt", "This is the content of file3 in sample_dir.")?;
    fs::write("sample_dir/nested_dir/file4.txt", "This is the content of file4 in nested_dir.")?;
    
    // Specify the output ZIP file path
    let output_zip = "archive_with_dirs.zip";
    
    // Create a new ZipManager instance
    let mut manager = ZipManager::new(output_zip);
    
    // Add individual files to the zip
    manager.add_file("file1.txt");
    manager.add_file("file2.txt");
    
    // Add directories to the zip
    manager.add_directory("sample_dir");
    
    // Create the ZIP archive with Deflated compression
    manager.create_zip(Compression::Deflated)?;
    
    println!("ZIP archive created at {}", output_zip);
    
    // Cleanup sample files and directories
    fs::remove_file("file1.txt")?;
    fs::remove_file("file2.txt")?;
    fs::remove_dir_all("sample_dir")?;
    
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

##### 3. `ArchiveUtil!` Macro

**Syntax:**
```rust
ArchiveUtil!(path, delete_flag, Variant);
```

- **`$path`**: The path to the directory/file to archive or the archive file to extract. Accepts a `&str` or a `PathBuf`.
- **`$delete_flag`**: A boolean indicating whether to delete the original directory/file or the archive file after the operation.
- **`Variant`**: Specifies the operation type. Use `Archive` to compress and `Extract` to decompress.

**Variants:**
- **`Archive`**: Compresses the specified directory or file.
- **`Extract`**: Decompresses the specified archive file.

**Example:**
```rust
use crypt_guard::ArchiveUtil;
use std::path::PathBuf;

fn main() {
    let source = PathBuf::from("/path/to/source_directory");
    let archive = PathBuf::from("/path/to/archive.tar.xz");
    
    // Using ArchiveUtil! to archive without deleting the source
    ArchiveUtil!(source, false, Archive);
    
    // Using ArchiveUtil! to extract and delete the archive file after extraction
    ArchiveUtil!(archive, true, Extract);
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
