mod cryptography; /// Cryptographic related functionalitys, enums structs and modules
mod KeyControl;
pub mod error;

pub use crate::{
    KeyControl::{
        *,
        file::*, 
        keychain::*,
    },
    cryptography::*
};

use KeyControl::*;
use cryptography::*;


use pqcrypto_falcon::falcon1024::{self, *};
use pqcrypto_kyber::kyber1024::{self, *};
use std::{
    error::Error,
    fmt::{self, *},
    io,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyControl::*,
        signature::{
            sign_falcon::*,
            sign_dilithium::*,
            *
        },
        cryptography::{
            *,
        },
    };
    use pqcrypto_traits::kem::PublicKey;
    use std::{
        path::PathBuf,
        str,
        fs::{self, File},
        io::{Write, Read},
    };
    use tempfile::tempdir;

    #[test]
    fn encrypt_decrypt_aes() {
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

        let passphrase = "test key";
        let original_data = "This is a test message".as_bytes().to_vec();

        let crypt_metadata1 = CryptographicMetadata::from(
            Process::encryption(),
            CryptographicMechanism::aes(),
            KeyEncapMechanism::kyber1024(),
            ContentType::message(),
        );
        let crypt_info1 = CryptographicInformation::from(
            original_data.clone(),
            passphrase.as_bytes().to_vec(),
            crypt_metadata1,
            false,
            None,
        );
        let mut aes1 = CipherAES::new(crypt_info1);
        let pubkey = Key::new(KeyTypes::PublicKey, keyp.public_key().unwrap().content().unwrap().to_vec());
        let seckey = Key::new(KeyTypes::SecretKey, keyp.secret_key().unwrap().content().unwrap().to_vec());
        let (data, cipher) = aes1.encrypt(pubkey).unwrap();

        let seckey_file = FileMetadata::from(
            PathBuf::from("key.sec"),
            FileTypes::SecretKey,
            FileState::Other
        );


        let crypt_metadata2 = CryptographicMetadata::from(
            Process::decryption(),
            CryptographicMechanism::aes(),
            KeyEncapMechanism::kyber1024(),
            ContentType::message(),
        );
        let passphrase = "test key";
        let crypt_info2 = CryptographicInformation::from(
            data.clone(),
            passphrase.as_bytes().to_vec(),
            crypt_metadata2,
            false,
            None,
        );
        let mut aes2 = CipherAES::new(crypt_info2);
        let decrypted = aes2.decrypt(seckey, cipher).unwrap();
        assert_eq!(original_data, decrypted);
    }

    #[test]
    fn test_file_encryption_and_decryption() {
        let keyp = KeyPair::new();
        let original_message = "This is a secret message.";
        let passphrase = "This is a secret message.".as_bytes().to_vec();
        let original_file_path = PathBuf::from("original_message.txt");
        let encrypted_file_path = PathBuf::from("original_message.txt.enc");
        let decrypted_file_path = PathBuf::from("original_message.txt");

        // Write the original message to a file
        let mut file = fs::File::create(&original_file_path).unwrap();
        writeln!(file, "{}", original_message).unwrap();

        // Assume these are obtained securely
        let public_key = Key::new(KeyTypes::PublicKey, keyp.public_key().unwrap().content().unwrap().to_vec());
        let secret_key = Key::new(KeyTypes::SecretKey, keyp.secret_key().unwrap().content().unwrap().to_vec());

        // Setup CryptographicInformation for encryption
        let crypt_info = CryptographicInformation {
            // Just needs to be defined when encrypting a message, when encrypting a file, the value will later on automatically replaced with the data readed from the file, only needs to be setted when file that should be encrypted/ decrypted does beforehand not exist and should only be safed while not existing.
            content: Vec::new(), 
            passphrase: passphrase.clone(),
            metadata: CryptographicMetadata {
                process: Process::Encryption,
                encryption_type: CryptographicMechanism::AES,
                key_type: KeyEncapMechanism::Kyber1024,
                content_type: ContentType::File,
            },
            safe: true,
            location: Some(FileMetadata::from(original_file_path.clone(), FileTypes::Ciphertext, FileState::Encrypted)),
        };

        // Encrypt the file content
        let mut aes_cipher = CipherAES::new(crypt_info);
        let (encrypted_data, ciphertext) = aes_cipher.encrypt(public_key).unwrap();

        // Save the encrypted data using the location specified in CryptographicInformation
        if let Some(file_metadata) = &aes_cipher.infos.location {
            file_metadata.save(&encrypted_data).unwrap();
        }

        // Setup CryptographicInformation for decryption
        let crypt_info_for_decryption = CryptographicInformation {
            // Just needs to be defined when encrypting a message, when encrypting a file, the value will later on automatically replaced with the data readed from the file, only needs to be setted when file that should be encrypted/ decrypted does beforehand not exist and should only be safed while not existing.
            content: Vec::new(), 
            passphrase: passphrase.clone(),
            metadata: CryptographicMetadata {
                process: Process::Decryption,
                encryption_type: CryptographicMechanism::AES,
                key_type: KeyEncapMechanism::Kyber1024,
                content_type: ContentType::File,
            },
            safe: true,
            location: Some(FileMetadata::from(encrypted_file_path.clone(), FileTypes::Message, FileState::Decrypted)),
        };

        // Decrypt the file content
        let mut aes_decipher = CipherAES::new(crypt_info_for_decryption);
        let decrypted_data = aes_decipher.decrypt(secret_key, ciphertext).unwrap();

        // Optionally, save the decrypted data using the location specified in CryptographicInformation
        if let Some(file_metadata) = &aes_decipher.infos.location {
            fs::write(file_metadata.location().unwrap(), &decrypted_data).unwrap();
        }

        // Verify the decrypted content matches the original message
        let decrypted_message = fs::read_to_string(decrypted_file_path).unwrap();
        assert_eq!(original_message, decrypted_message.trim());
        fs::remove_file(PathBuf::from("original_message.txt"));
        fs::remove_file(PathBuf::from("original_message.txt.enc"));
    }

    #[test]
    fn encrypt_decrypt_chacha() {
        let passphrase = "test key";
        let keyp = KeyPair::new();

        let crypt_metadata1 = CryptographicMetadata::from(
            Process::encryption(),
            CryptographicMechanism::xchacha20(),
            KeyEncapMechanism::kyber1024(),
            ContentType::message(),
        );
        let crypt_info1 = CryptographicInformation::from(
            "test message".as_bytes().to_vec(),
            "test key".as_bytes().to_vec(),
            crypt_metadata1,
            false,
            None,
        );
        let mut ChaCha1 = CipherChaCha::new(crypt_info1, None);

        {
            let nonce = ChaCha1.nonce();
        }

        let mut pubkey = Key::new(KeyTypes::PublicKey, keyp.public_key().unwrap().content().unwrap().to_vec());
        let mut seckey = Key::new(KeyTypes::SecretKey, keyp.secret_key().unwrap().content().unwrap().to_vec());
        let (data, cipher) = ChaCha1.encrypt(pubkey).unwrap();

        let crypt_metadata2 = CryptographicMetadata::from(
            Process::decryption(),
            CryptographicMechanism::xchacha20(),
            KeyEncapMechanism::kyber1024(),
            ContentType::message(),
        );
        let crypt_info2 = CryptographicInformation::from(
            data,
            "test key".as_bytes().to_vec(),
            crypt_metadata2,
            false,
            None,
        );

        let nonce_vec = ChaCha1.nonce().to_vec();
        let mut ChaCha2 = CipherChaCha::new(crypt_info2, Some(hex::encode(nonce_vec)));
        let decrypted = ChaCha2.decrypt(seckey, cipher).unwrap();
        assert_eq!(decrypted, "test message".as_bytes());
        assert_eq!(str::from_utf8(decrypted.as_slice()).unwrap(), "test message");
    }


    #[test]
    fn test_key() {
        let keyp = KeyPair::new();
        let pubkey_file = FileMetadata::from(
            PathBuf::from("key.pub"),
            FileTypes::PublicKey,
            FileState::Other
        );
        let seckey_file = FileMetadata::from(
            PathBuf::from("key.sec"),
            FileTypes::SecretKey,
            FileState::Other
        );
        let mut pubk = keyp.public_key().unwrap();
        let mut seck = keyp.secret_key().unwrap();
        let _ = pubkey_file.save(pubk.content().unwrap());
        let _ = seckey_file.save(seck.content().unwrap());
        let (ciphertext, sharedsecret) = pubk.encap().unwrap();

        let ciphersafe = FileMetadata::from(
            PathBuf::from("key.ct"),
            FileTypes::Ciphertext,
            FileState::Other
        );
        let _ = ciphersafe.save(ciphertext.content().unwrap());
        
        let seckey_vec = seckey_file.load().unwrap();
        let seckey = Key::new(KeyTypes::SecretKey, seckey_vec);
        let cipher_vec = ciphersafe.load().unwrap();
        let cipher = Key::new(KeyTypes::Ciphertext, cipher_vec);

        let ss = seckey.decap(ciphertext).unwrap();
        assert_eq!(sharedsecret.content().unwrap(), ss.content().unwrap());
    }

    #[test]
    fn files() {
        let keyp = KeyPair::new();
        let file = FileMetadata::from(
            PathBuf::from("key.pub"),
            FileTypes::PublicKey,
            FileState::Other
        );
        let mut pubk = keyp.public_key().unwrap();
        let _ = file.save(pubk.content().unwrap());
        assert!(file.location.exists());

    }

    #[test]
    fn test_keypair_new() {
        let kpair = KeyPair::new();
        assert_eq!(kpair.public_key.key_type, KeyTypes::PublicKey);
        assert_eq!(kpair.secret_key.key_type, KeyTypes::SecretKey);
    }

    #[test]
    fn test_keypair_from() {
        let public_key = Key::new_public_key(vec![1, 2, 3]);
        let secret_key = Key::new_secret_key(vec![4, 5, 6]);
        let kpair = KeyPair::from(Key::new_public_key(vec![1, 2, 3]), Key::new_secret_key(vec![4, 5, 6]));
        assert_eq!(kpair.secret_key, secret_key);
    }

    #[test]
    fn test_keypair_get_public_key() {
        let kpair = KeyPair::new();
        let result = kpair.get_public_key();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), kpair.public_key.content().unwrap());
    }

    #[test]
    fn test_keypair_get_secret_key() {
        let kpair = KeyPair::new();
        let result = kpair.get_secret_key();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), kpair.secret_key.content().unwrap());
    }

    #[test]
    fn test_keypair_public_key() {
        let kpair = KeyPair::new();
        let result = kpair.public_key();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &kpair.public_key);
    }

    #[test]
    fn test_keypair_secret_key() {
        let kpair = KeyPair::new();
        let result = kpair.secret_key();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &kpair.secret_key);
    }

    #[test]
    fn test_keypair_encap_decap() {
        let kpair = KeyPair::new();
        let keys = kpair.encap().unwrap();
        let ciphertext = keys[0].content().unwrap();
        let shared_secret = keys[1].content().unwrap();

        let decapsulated_shared_secret = kpair.decap(ciphertext).unwrap();
        assert_eq!(shared_secret, decapsulated_shared_secret.content().unwrap());
    }

    #[test]
    fn test_sign_and_verify_message() {
        let mut instance = falcon::keypair();
        let message = b"Test message".to_vec();
        instance.set_data(message.clone()).unwrap();
        let signature = instance.sign_msg().expect("Failed to sign message");
        instance.set_signed_msg(signature).expect("Failed to set signed message");
        let verified_message = instance.verify_msg().expect("Failed to verify message");
        assert_eq!(verified_message, message, "The verified message does not match the original message");
    }

    #[test]
    fn test_sign_and_verify_detached_signature() {
        let mut instance = falcon::keypair();
        let message = b"Test message for detached signature".to_vec();
        instance.set_data(message.clone()).unwrap();
        let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
        instance.set_detached(detached_signature).expect("Failed to set detached signature");
        let verification_result = instance.verify_detached().expect("Failed to verify detached signature");
        assert!(verification_result, "Detached signature verification failed");
    }

    #[test]
    fn test_save_signed_msg() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("signed_message.sig");

        let mut instance = falcon::keypair();
        let message = b"This is a test message.".to_vec();
        instance.set_data(message.clone()).unwrap();

        // Sign the message
        let signature = instance.sign_msg().expect("Failed to sign message");
        instance.set_signed_msg(signature.clone()).expect("Failed to set signed message");

        // Save the signed message
        assert!(instance.save_signed_msg(file_path.clone()).is_ok(), "Failed to save signed message");

        // Read and verify the contents of the saved file
        let mut saved_file = File::open(file_path).unwrap();
        let mut saved_signature = Vec::new();
        saved_file.read_to_end(&mut saved_signature).unwrap();
        assert_eq!(signature, saved_signature, "The saved signed message does not match the expected signature");
    }

    #[test]
    fn test_save_detached() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("detached_signature.sig");

        let mut instance = falcon::keypair();
        let message = b"This is a test message for detached signature.".to_vec();
        instance.set_data(message.clone()).unwrap();

        // Sign with a detached signature
        let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
        instance.set_detached(detached_signature.clone()).expect("Failed to set detached signature");

        // Save the detached signature
        assert!(instance.save_detached(file_path.clone()).is_ok(), "Failed to save detached signature");

        // Read and verify the contents of the saved file
        let mut saved_file = File::open(file_path).unwrap();
        let mut saved_detached_signature = Vec::new();
        saved_file.read_to_end(&mut saved_detached_signature).unwrap();
        assert_eq!(detached_signature, saved_detached_signature, "The saved detached signature does not match the expected signature");
    }

    #[test]
    fn test_sign_and_verify_message_dilithium() {
        let mut instance = dilithium::keypair();
        let message = b"Test message".to_vec();
        instance.set_data(message.clone()).unwrap();
        let signature = instance.sign_msg().expect("Failed to sign message");
        instance.set_signed_msg(signature).expect("Failed to set signed message");
        let verified_message = instance.verify_msg().expect("Failed to verify message");
        assert_eq!(verified_message, message, "The verified message does not match the original message");
    }

    #[test]
    fn test_sign_and_verify_detached_signature_dilithium() {
        let mut instance = dilithium::keypair();
        let message = b"Test message for detached signature".to_vec();
        instance.set_data(message.clone()).unwrap();
        let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
        instance.set_detached(detached_signature).expect("Failed to set detached signature");
        let verification_result = instance.verify_detached().expect("Failed to verify detached signature");
        assert!(verification_result, "Detached signature verification failed");
    }

    #[test]
    fn test_save_signed_msg_dilithium() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("signed_message.sig");

        let mut instance = dilithium::keypair();
        let message = b"This is a test message.".to_vec();
        instance.set_data(message.clone()).unwrap();

        // Sign the message
        let signature = instance.sign_msg().expect("Failed to sign message");
        instance.set_signed_msg(signature.clone()).expect("Failed to set signed message");

        // Save the signed message
        assert!(instance.save_signed_msg(file_path.clone()).is_ok(), "Failed to save signed message");

        // Read and verify the contents of the saved file
        let mut saved_file = File::open(file_path).unwrap();
        let mut saved_signature = Vec::new();
        saved_file.read_to_end(&mut saved_signature).unwrap();
        assert_eq!(signature, saved_signature, "The saved signed message does not match the expected signature");
    }

    #[test]
    fn test_save_detached_dilithium() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("detached_signature.sig");

        let mut instance = dilithium::keypair();
        let message = b"This is a test message for detached signature.".to_vec();
        instance.set_data(message.clone()).unwrap();

        // Sign with a detached signature
        let detached_signature = instance.sign_detached().expect("Failed to sign with a detached signature");
        instance.set_detached(detached_signature.clone()).expect("Failed to set detached signature");

        // Save the detached signature
        assert!(instance.save_detached(file_path.clone()).is_ok(), "Failed to save detached signature");

        // Read and verify the contents of the saved file
        let mut saved_file = File::open(file_path).unwrap();
        let mut saved_detached_signature = Vec::new();
        saved_file.read_to_end(&mut saved_detached_signature).unwrap();
        assert_eq!(detached_signature, saved_detached_signature, "The saved detached signature does not match the expected signature");
    }


    #[test]
    fn test_generate_and_verify_sha256_hmac() {
        let data = b"Example data for SHA256".to_vec();
        let passphrase = b"secret key".to_vec();

        let mut sign = Sign::new(data.clone(), passphrase.clone(), Operation::Sign, SignType::Sha256);
        let concat_data = sign.hmac();
        let mut verify_sign = Sign::new(concat_data, passphrase, Operation::Verify, SignType::Sha256);
        let verified_data = verify_sign.verify_hmac().expect("HMAC verification failed");

        assert_eq!(verified_data, data, "Verified data does not match the original data for SHA256");
    }

    #[test]
    fn test_generate_and_verify_sha512_hmac() {
        let data = b"Example data for SHA512".to_vec();
        let passphrase = b"secret key".to_vec();

        let mut sign = Sign::new(data.clone(), passphrase.clone(), Operation::Sign, SignType::Sha512);
        let concat_data = sign.hmac();
        let mut verify_sign = Sign::new(concat_data, passphrase, Operation::Verify, SignType::Sha512);
        let verified_data = verify_sign.verify_hmac().expect("HMAC verification failed");

        assert_eq!(verified_data, data, "Verified data does not match the original data for SHA512");
    }
}