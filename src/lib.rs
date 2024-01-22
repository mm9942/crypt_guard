mod keychain;
mod decrypt;
mod encrypt;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}


#[cfg(test)]
mod tests {
    extern crate tempfile;
    use super::*;
    use crate::keychain::*;
    use crate::encrypt::*;
    use crate::decrypt::*;
    use std::{
        path::{PathBuf, Path},
        fs,
        env::current_dir,
        io::Write,
        ffi::OsStr
    };
    use pqcrypto::kem::kyber1024::decapsulate;
    use pqcrypto_traits::kem::{SharedSecret as SharedSecretTrait, SecretKey as SecretKeyTrait};
    use hex;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn keychain_new_works() {
        let keychain = Keychain::new().unwrap();

        assert!(keychain.public_key.is_some());
        assert!(keychain.secret_key.is_some());
        assert!(keychain.shared_secret.is_some());
        assert!(keychain.ciphertext.is_some());

        if let (Some(ct), Some(sk)) = (&keychain.ciphertext, &keychain.secret_key) {
            let ss = decapsulate(ct, sk);
            assert_eq!(keychain.shared_secret.as_ref().unwrap().as_bytes(), ss.as_bytes());
        }
    }

    #[tokio::test]
    async fn generate_unique_filename_works() {
        let base_path = "test_file";
        let extension = "txt";
        let unique_path = Keychain::generate_unique_filename(base_path, extension);

        // Create a file at the unique path for the test
        fs::write(&unique_path, "Test content").unwrap();

        assert!(Path::new(&unique_path).is_file());

        assert_eq!(Path::new(&unique_path).extension().unwrap().to_str().unwrap(), extension);

        // Cleanup
        fs::remove_file(unique_path).unwrap();
    }


    #[tokio::test]
    async fn generate_original_filename_works() {
        let encrypt_filename1 = "./test_file.txt_1.enc";
        let encrypt_filename2 = "./test_file.txt.enc";

        let original1 = Decrypt::generate_original_filename(encrypt_filename1).await;
        let original2 = Decrypt::generate_original_filename(encrypt_filename2).await;
        assert_eq!("./test_file.txt", original1);
        assert_eq!("./test_file.txt", original2);
    }


    #[tokio::test]
    async fn generate_and_verify_hmac() {
        let key = b"Hello, how are you?";
        let data = b"Ai#31415926535*";

        // Generate HMAC
        let hmac = Encrypt::generate_hmac(key, data);

        // Prepare data for verification (append hmac to original data)
        let data_with_hmac = [data.as_ref(), hmac.as_ref()].concat();

        // Verify HMAC
        let hmac_len = 64; // Length of HMAC (depends on the hash function used, SHA512 produces 64 bytes)
        let verification_result = Decrypt::verify_hmac(key, &data_with_hmac, hmac_len);

        // Assertions
        assert!(verification_result.is_ok(), "HMAC verification failed");
        let verified_data = verification_result.unwrap();
        assert_eq!(verified_data, data, "Verified data does not match original data");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_file() {
        let keychain = Keychain::new().unwrap();

        // Setup - create a sample message
        let message = "This is a test message.";
        let message_bytes = message.as_bytes();

        // Create temporary directory for test files
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_message.txt");
        let encrypted_file_path = dir.path().join("test_message_encrypted.txt");
        let decrypted_file_path = dir.path().join("test_message_decrypted.txt");

        fs::write(&file_path, message_bytes).expect("Failed to write test file");

        // Encrypt the file
        let encrypted_data = Encrypt::encrypt_file(
            file_path.clone(), 
            keychain.shared_secret.as_ref().unwrap(), 
            b"hmackey"
        ).await.expect("Encryption failed");

        // Verify that encrypted data is different
        assert_ne!(message_bytes, encrypted_data);

        // Write encrypted data to file
        fs::write(&encrypted_file_path, &encrypted_data).expect("Failed to write encrypted file");

        // Decrypt the file
        let decrypted_data = Decrypt::decrypt_file(
            &encrypted_file_path, 
            keychain.shared_secret.as_ref().unwrap(), 
            b"hmackey"
        ).await.expect("Decryption failed");

        // Write decrypted data to file
        fs::write(&decrypted_file_path, &decrypted_data).expect("Failed to write decrypted file");

        // Verify that decrypted data matches original message
        assert_eq!(message_bytes, decrypted_data);

        // Clean up - remove temporary files and directory
        dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_message() {
        let message = "This is a secret message!";
        let hmac_key = b"encryption_test_key";

        // Initialize Keychain
        let keychain = Keychain::new().unwrap();

        // Encrypt the message
        let encrypted_message = Encrypt::encrypt_msg(message, keychain.shared_secret.as_ref().unwrap(), hmac_key)
            .await
            .expect("Failed to encrypt message");

        // Decrypt the message
        let decrypted_message_result = Decrypt::decrypt_msg(&encrypted_message, keychain.shared_secret.as_ref().unwrap(), hmac_key, false)
            .await;

        // Assert that the decrypted message matches the original message
        assert_eq!(decrypted_message_result.unwrap(), message, "Decrypted message does not match the original message");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let pubkey = PathBuf::from("/Users/mm29942/EncryptCommunication/EncryptMod/keychain/key/key.pub");
        let secret_key = PathBuf::from("/Users/mm29942/EncryptCommunication/EncryptMod/keychain/key/key.sec");
        let ciphertext = PathBuf::from("/Users/mm29942/EncryptCommunication/EncryptMod/keychain/cipher/cipher.ct");

        // Create temporary directory for test files
        let dir = tempdir().unwrap();
        let original_file_path = dir.path().join("test.txt");
        let encrypted_file_path = dir.path().join("test.txt.enc");

        // Create a sample file with content to encrypt
        let original_file_contents = "this is a test file";
        fs::write(&original_file_path, original_file_contents).expect("Failed to write original file");

        // Encrypt the file
        let _ = Encrypt::encrypt(pubkey, None, Some(&original_file_path), b"secret").await;

        // Decrypt the file
        let _ = Decrypt::decrypt(secret_key, ciphertext, Some(&encrypted_file_path), None, b"secret").await;

        // Read decrypted file contents
        let decrypted_file_contents = fs::read_to_string(&original_file_path).expect("Failed to read decrypted file");

        // Verify that decrypted content matches the original content
        assert_eq!(decrypted_file_contents, original_file_contents);

        // Clean up - remove temporary files and directory
        dir.close().unwrap();
        fs::remove_file("/Users/mm29942/EncryptCommunication/EncryptMod/keychain/cipher/cipher.ct").unwrap();
    }



}