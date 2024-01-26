pub mod keychain;
pub mod decrypt;
pub mod encrypt;
pub mod file_remover;
pub mod sign;

use crate::{
    keychain::*,
    encrypt::*,
    decrypt::*,
    file_remover::*,
    sign::{Sign, *},
};

enum ActionType {
    FileAction,
    MessageAction,
}

#[cfg(test)]
mod tests {
    extern crate tempfile;
    use super::*;
    use crate::{
        keychain::*,
        encrypt::*,
        decrypt::*,
        file_remover::*,
        sign::{Sign, *},
        ActionType,
    };
    use std::{
        path::{PathBuf, Path},
        fs,
        env::current_dir,
        io::Write,
        ffi::OsStr
    };
    use pqcrypto_kyber::kyber1024::*;
    use pqcrypto_traits::kem::{SharedSecret as SharedSecretTrait, SecretKey as SecretKeyTrait};
    use hex;
    use tempfile::tempdir;
    use pqcrypto_traits::sign::{SignedMessage as SignedMessageSign, SecretKey as SecretKeySign, PublicKey as PublicKeySign, DetachedSignature as DetachedSignatureSign};

    
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
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
        let original1 = decrypt.generate_original_filename(encrypt_filename1).await;
        let original2 = decrypt.generate_original_filename(encrypt_filename2).await;
        assert_eq!("./test_file.txt", original1);
        assert_eq!("./test_file.txt", original2);
    }


    #[tokio::test]
    async fn generate_and_verify_hmac() {
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
        let key = b"Hello, how are you?";
        let data = b"Ax23526";

        // Generate HMAC
        let hmac = encrypt.generate_hmac(key, data);

        // Prepare data for verification (append hmac to original data)
        let data_with_hmac = [data.as_ref(), hmac.as_ref()].concat();

        // Verify HMAC
        let hmac_len = 64; // Length of HMAC (depends on the hash function used, SHA512 produces 64 bytes)
        let verification_result = decrypt.verify_hmac(key, &data_with_hmac, hmac_len);

        // Assertions
        assert!(verification_result.is_ok(), "HMAC verification failed");
        let verified_data = verification_result.unwrap();
        assert_eq!(verified_data, data, "Verified data does not match original data");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_file() {
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
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
        let encrypted_data = encrypt.encrypt_file(
            file_path.clone(), 
            keychain.shared_secret.as_ref().unwrap(), 
            b"hmackey"
        ).await.expect("Encryption failed");

        // Verify that encrypted data is different
        assert_ne!(message_bytes, encrypted_data);

        // Write encrypted data to file
        fs::write(&encrypted_file_path, &encrypted_data).expect("Failed to write encrypted file");

        // Decrypt the file
        let decrypted_data = decrypt.decrypt_file(
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
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
        let message = "This is a secret message!";
        let hmac_key = b"encryption_test_key";

        // Initialize Keychain
        let keychain = Keychain::new().unwrap();

        // Encrypt the message
        let encrypted_message = encrypt.encrypt_msg(message, keychain.shared_secret.as_ref().unwrap(), hmac_key)
            .await
            .expect("Failed to encrypt message");

        // Decrypt the message
        let decrypted_message_result = decrypt.decrypt_msg(&encrypted_message, keychain.shared_secret.as_ref().unwrap(), hmac_key, false)
            .await;

        // Assert that the decrypted message matches the original message
        assert_eq!(decrypted_message_result.unwrap(), message, "Decrypted message does not match the original message");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let keychain = Keychain::new().unwrap();
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
        let pubkey = PathBuf::from("./keychain/key/key.pub");
        let secret_key = PathBuf::from("./keychain/key/key.sec");
        let ciphertext = PathBuf::from("./keychain/cipher/cipher.ct");

        // Create temporary directory for test files
        let dir = tempdir().unwrap();
        let original_file_path = dir.path().join("test.txt");
        let encrypted_file_path = dir.path().join("test.txt.enc");

        // Create a sample file with content to encrypt
        let original_file_contents = "this is a test file";
        fs::write(&original_file_path, original_file_contents).expect("Failed to write original file");

        // Encrypt the file
        let _ = encrypt.encrypt(pubkey, &original_file_path.as_os_str().to_str().unwrap(), ActionType::FileAction, b"secret", None).await;

        // Decrypt the file
        let _ = decrypt.decrypt(secret_key, ciphertext, encrypted_file_path.as_os_str().to_str().unwrap(), ActionType::FileAction, b"secret", None).await;

        // Read decrypted file contents
        let decrypted_file_contents = fs::read_to_string(&original_file_path).expect("Failed to read decrypted file");

        // Verify that decrypted content matches the original content
        assert_eq!(decrypted_file_contents, original_file_contents);

        // Clean up - remove temporary files and directory
        dir.close().unwrap();
        fs::remove_file("./keychain/cipher/cipher.ct");
    }

   #[tokio::test]
    async fn test_file_removal() -> Result<(), Box<dyn std::error::Error>> {
        let keychain = Keychain::new().unwrap();
        //keychain.save("./keychain", "key").await?;

        let keychain_path = PathBuf::from("./keychain/key");
        let duplicated_path = PathBuf::from("./keychain/key_duplicate");

        // Duplicate the directory
        fs::create_dir_all(&duplicated_path)?; // Create the target directory
        for entry in fs::read_dir(&keychain_path)? {
            let entry = entry?;
            let dest_path = duplicated_path.join(entry.file_name());
            fs::copy(entry.path(), dest_path)?;
        }

        // Use FileRemover on the duplicated directory
        match FileRemover::new(5, duplicated_path.clone(), true) {
            Ok(mut file_remover) => {
                if let Err(e) = file_remover.delete() {
                    eprintln!("Error while deleting file: {}", e);
                } else {
                    println!("File successfully deleted.");
                }
            }
            Err(e) => eprintln!("Failed to initialize file remover: {}", e),
        }

        // Check that the duplicated folder does not exist anymore
        assert!(!duplicated_path.exists(), "The duplicated folder still exists after deletion");

        Ok(())
    }
    #[tokio::test]
    async fn test_sign_msg() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        let result = sign.sign_msg(message).await;
        println!("{:?}", result);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_signing_detached() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        let result = sign.signing_detached(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_msg() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        sign.sign_msg(message).await.unwrap();
        let result = sign.verify_msg(message).await;
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_detached() {
        let mut sign = Sign::new().unwrap();
        let message = b"Test message";
        let detached_signature = sign.signing_detached(message).await.unwrap();
        let result = sign.verify_detached(message).await;
        println!("{:?}", result);
        assert_eq!(result, Ok(true));
    }


    #[tokio::test]
    async fn test_sign_file() {
        // Initialize Signature struct
        let mut sign = Sign::new().unwrap();
        let _ = sign.save_keys("keychain", "sign");

        // Perform the sign_file operation
        let file_path = PathBuf::from("./README.md");
        let sign_result = sign.sign_file(file_path.clone()).await;
        assert!(sign_result.is_ok(), "Signing the file failed");

        // Reading the file content for verification
        let file_content = fs::read(&file_path).expect("Failed to read the file");
        
        // Verify the signature
        let verify_result = sign.verify_detached(&file_content).await;
        assert!(verify_result.is_ok(), "Signature verification failed");
        assert_eq!(verify_result.unwrap(), true, "The file signature verification failed");
    }

    #[tokio::test]
    #[cfg(feature = "xchacha20")]
    async fn test_encrypt_decrypt_message_xchacha() {
        let keychain = Keychain::new().expect("Failed to create keychain");
        let encrypt = Encrypt::new();
        let decrypt = Decrypt::new();

        // Use the shared secret from Keychain
        let shared_secret = keychain.get_shared_secret().await.expect("Failed to get shared secret");
        let nonce = generate_nonce(); // Generate a nonce for xchacha20

        let message = "This is a secret message!";

        // Encrypt the message
        let encrypted_message = encrypt.encrypt_msg_xchacha20(message, &shared_secret, &nonce, "encryption_test_key".as_bytes())
            .await
            .expect("Failed to encrypt message");

        // Decrypt the message
        let decrypted_message = decrypt.decrypt_msg_xchacha20(&encrypted_message, &shared_secret, &nonce, "encryption_test_key".as_bytes(), false)
            .await
            .expect("Failed to decrypt message");

        // Verify that the decrypted message matches the original message
        assert_eq!(message, decrypted_message);
    }


    #[tokio::test]
    #[cfg(feature = "xchacha20")]
    async fn test_encrypt_decrypt_data_xchacha20() {
        let keychain = Keychain::new().expect("Failed to create keychain");
        let encrypt = Encrypt::new();
        let decrypt = Decrypt::new();
        let key = keychain.get_shared_secret().await.expect("Failed to get shared secret").as_bytes().to_owned(); // Example key
        let hmac_key = "encryption_test_key".as_bytes();
        let data = b"Example plaintext data";
        let nonce = generate_nonce(); // Generate a nonce

        println!("Original Data: {:?}", data);

        // Encrypt the data
        let encrypted_data = encrypt.encrypt_data_xchacha20(data.as_ref(), &key, &nonce, &hmac_key)
            .await
            .expect("Encryption failed");
        println!("Encrypted Data: {:?}", encrypted_data);

        // Verify HMAC
        let hmac_len = 64; // Length of HMAC (depends on the hash function used, SHA512 produces 64 bytes)
        match decrypt.verify_hmac(&hmac_key, &encrypted_data, hmac_len) {
            Ok(data_with_hmac) => {
                // Decrypt the data
                let decrypted_data = decrypt.decrypt_data_xchacha20(&data_with_hmac, &nonce, &key)
                    .await
                    .expect("Decryption failed");
                println!("Decrypted Data: {:?}", decrypted_data);

                // Assert that the decrypted data matches the original data
                assert_eq!(data, &decrypted_data[..]);
            },
            Err(e) => panic!("HMAC verification failed: {}", e),
        }
    }

    #[tokio::test]
    #[cfg(feature = "xchacha20")]
    async fn test_encrypt_decrypt_file_xchacha20() {
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
        let keychain = Keychain::new().unwrap();
        let nonce = generate_nonce(); // Generate a nonce

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
        let encrypted_data = encrypt.encrypt_file_xchacha20(file_path.clone(), &keychain.get_shared_secret().await.unwrap(), &nonce, b"hmackeyaergfdgrfgswgs<edgsf")
            .await
            .expect("Encryption failed");

        assert_ne!(message_bytes, encrypted_data);

        fs::write(&encrypted_file_path, &encrypted_data).expect("Failed to write encrypted file");

        // Decrypt the file
        let decrypted_data = decrypt.decrypt_file_xchacha20(&encrypted_file_path, &keychain.get_shared_secret().await.unwrap(), &nonce, b"hmackeyaergfdgrfgswgs<edgsf")
            .await
            .expect("Decryption failed");

        // Verify that decrypted data matches original content
        assert_eq!(message.as_bytes().to_vec(), decrypted_data, "Decrypted data does not match original content");
    }

        #[tokio::test]
    #[cfg(feature = "xchacha20")]
    async fn test_encrypt_decrypt_msg_xchacha20() {
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
        let keychain = Keychain::new().unwrap();
        let nonce = generate_nonce(); // Generate a nonce

        // Setup - create a sample message
        let message = "This is a test message.";

        // Encrypt the file
        let encrypted_data = encrypt.encrypt_msg_xchacha20(message.as_ref(), &keychain.get_shared_secret().await.unwrap(), &nonce, b"hmackeyaergfdgrfgswgs<edgsf")
            .await
            .expect("Encryption failed");

        assert_ne!(message.as_bytes(), encrypted_data);

        // Decrypt the file
        let decrypted_data = decrypt.decrypt_msg_xchacha20(&encrypted_data, &keychain.get_shared_secret().await.unwrap(), &nonce, b"hmackeyaergfdgrfgswgs<edgsf", false)
            .await
            .expect("Decryption failed");

        // Verify that decrypted data matches original content
        assert_eq!(message, decrypted_data, "Decrypted data does not match original content");
    }

    #[tokio::test]
    #[cfg(feature = "xchacha20")]
    async fn test_encrypt_decrypt_xchacha20() {
        let nonce = generate_nonce(); // Generate a nonce
        let keychain = Keychain::new().unwrap();
        let decrypt: Decrypt = Decrypt::new();
        let encrypt: Encrypt = Encrypt::new();
        let pubkey = PathBuf::from("./keychain/key/key.pub");
        let secret_key = PathBuf::from("./keychain/key/key.sec");
        let ciphertext = PathBuf::from("./keychain/cipher/cipher.ct");

        // Create temporary directory for test files
        let dir = tempdir().unwrap();
        let original_file_path = dir.path().join("test.txt");
        let encrypted_file_path = dir.path().join("test.txt.enc");

        // Create a sample file with content to encrypt
        let original_file_contents = "this is a test file";
        fs::write(&original_file_path, original_file_contents).expect("Failed to write original file");

        // Encrypt the file
        let _ = encrypt.encrypt(pubkey, &original_file_path.as_os_str().to_str().unwrap(), ActionType::FileAction, b"secret", Some(&nonce)).await;

        // Decrypt the file
        let _ = decrypt.decrypt(secret_key, ciphertext, encrypted_file_path.as_os_str().to_str().unwrap(), ActionType::FileAction, b"secret", Some(&nonce)).await;

        // Read decrypted file contents
        let decrypted_file_contents = fs::read_to_string(&original_file_path).expect("Failed to read decrypted file");

        // Verify that decrypted content matches the original content
        assert_eq!(decrypted_file_contents, original_file_contents);

        // Clean up - remove temporary files and directory
        dir.close().unwrap();
        fs::remove_file("./keychain/cipher/cipher.ct");
    }
}
