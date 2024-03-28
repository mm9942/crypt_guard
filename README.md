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

## Syntax Overhaul and Version Information

### Upcoming Changes

Our library is undergoing a syntax overhaul to enhance detail and clarity, addressing feedback for a more intuitive user experience. The current syntax focuses on providing a comprehensive understanding of the cryptographic processes, albeit with a higher complexity level.

### Current Release

The present version, **1.1.0**, emphasizes detailed cryptographic operations, catering to users who require a deep dive into cryptographic functionalities. This version is ideal for those who prefer an elaborate approach to cryptography and don't want to use async code, async capabilites will on a later updated reimplemented (but this time as a feature). For those who prefer an rather easy syntax should just use version 1.0.3 until the next updates are released.

### Future Release

A forthcoming update will introduce a more streamlined and user-friendly interface. This version aims to simplify cryptographic operations, making the library more accessible to a broader audience. Stay tuned for its release!

## Important Considerations

### Data Handling in CryptographicInformation

Users should note that providing an existing file path to `FileMetadata` for encryption/decryption operations will overwrite the `data` field within `CryptographicInformation` with the file's content. This ensures the use of current data but replaces any existing data in the field. Caution is advised to prevent data loss.

### Transition to the New Version

For those considering the transition to the updated version upon its release, familiarizing yourself with the current documentation and examples is recommended. This preparation will facilitate a smoother adaptation to the new syntax and features.

## Usage Examples

#### Generating and Saving a Key Pair

This example illustrates generating a key pair and saving it to files, leveraging the `KeyPair::new()` method for key pair generation and `FileMetadata::save()` for persisting keys.

```rust
use crate::KeyControl::{FileMetadata, KeyPair};
use crate::KeyControl::FileTypes;

let key_pair = KeyPair::new();

// Public key saving
let public_key_file_metadata = FileMetadata::from(
    "path/to/save/public_key.pub".into(),
    FileTypes::PublicKey,
    FileState::Other,
);
public_key_file_metadata.save(key_pair.public_key.content().unwrap()).expect("Failed to save public key");

// Secret key saving
let secret_key_file_metadata = FileMetadata::from(
    "path/to/save/secret_key.sec".into(),
    FileTypes::SecretKey,
    FileState::Other,
);
secret_key_file_metadata.save(key_pair.secret_key.content().unwrap()).expect("Failed to save secret key");
```

### Encrypting a Message using AES

```rust
let keyp = KeyPair::new();

let file1 = FileMetadata::from(
    PathBuf::from("key.pub"),
    FileTypes::PublicKey,
    FileState::Other
);

let file2 = FileMetadata::from(
    PathBuf::from("key.sec"),
    FileTypes::SecretKey,
    FileState::Other
);

let mut pubk = keyp.public_key().unwrap();
let mut seck = keyp.secret_key().unwrap();
let _ = file1.save(pubk.content().unwrap());
let _ = file2.save(seck.content().unwrap());

let crypt_metadata1 = CryptographicMetadata::from(
    Process::encryption(),
    CryptographicMechanism::aes(),
    KeyEncapMechanism::kyber1024(),
    ContentType::message(),
);

let crypt_info1 = CryptographicInformation::from(
    "This is a test message".as_bytes().to_vec(),
    "passphrase".as_bytes().to_vec(),
    crypt_metadata1,
    false,
    None,
);
let mut aes1 = CipherAES::new(crypt_info1);

let pubkey = Key::new(KeyTypes::PublicKey, keyp.public_key().unwrap().content().unwrap().to_vec());
let seckey = Key::new(KeyTypes::SecretKey, keyp.secret_key().unwrap().content().unwrap().to_vec());

let (data, cipher) = aes1.encrypt(pubkey).unwrap();

```

#### Decrypting a File with XChaCha20

```rust
let ciphertext = FileMetadata::from(
    PathBuf::from("key.ct"),
    FileTypes::Ciphertext,
    FileState::Other
);

let cipher_vec = ciphertext.load().unwrap();
let cipher = Key::new(KeyTypes::Ciphertext, cipher_vec);

let secret_key = FileMetadata::from(
    PathBuf::from("key.sec"),
    FileTypes::SecretKey,
    FileState::Other
);

let seckey_vec = secret_key.load().unwrap();
let seckey = Key::new(KeyTypes::SecretKey, seckey_vec);

let crypt_metadata2 = CryptographicMetadata::from(
    Process::decryption(),
    CryptographicMechanism::xchacha20(),
    KeyEncapMechanism::kyber1024(),
    ContentType::file(),
);

let crypt_info2 = CryptographicInformation::from(
    data,
    "test key".as_bytes().to_vec(),
    crypt_metadata2,
    true,
    location: Some(
    	FileMetadata::from(
    		PathBuf::from("./example.pdf.enc"), 
    		FileTypes::File, 
    		FileState::Decrypted
		)
	),
);

let nonce_vec = ... // Use the nonce used for encryption

let mut ChaCha1 = CipherChaCha::new(crypt_info1, Some(hex::encode(nonce_vec)));
let decrypted = ChaCha1.decrypt(seckey, cipher).unwrap();
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
let verified = falcon::verify_msg(&falcon_keypair.public_key, &signature, message.as_bytes()).expect("Verification failed");
assert!(verified, "Signature verification failed");
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
let verified = dilithium::verify_msg(&dilithium_keypair.public_key, &signature, message.as_bytes()).expect("Verification failed");
assert!(verified, "Signature verification failed with Dilithium");
```


### Conclusion and Looking Forward

We appreciate your engagement with our cryptographic library. As we strive to improve and evolve, your feedback and contributions are invaluable. The anticipated update promises to make cryptography more accessible and straightforward for everyone.

Thank you for your support and for making security a priority in your projects.

## License
CryptGuard is licensed under the MIT LICENSE. The full license text is available in the `LICENSE` file in the repository.