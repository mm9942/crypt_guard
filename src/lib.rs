mod keychain;
mod decrypt;
mod encrypt;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::*;
    use crate::encrypt::*;
    use crate::decrypt::*;
    use std::path::{PathBuf, Path};
    use std::fs;
    use std::env::current_dir;
    use pqcrypto::kem::kyber1024::decapsulate;
    use pqcrypto_traits::kem::{SharedSecret as SharedSecretTrait, SecretKey as SecretKeyTrait};
    use hex;

    #[tokio::test]
    async fn keychain_new_works() {
        let keychain = Keychain::new().unwrap();
        let _ = keychain.save("./keychain", "key");

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
        let base_path = PathBuf::from("test_file");
        let extension = "txt";
        let unique_path = Keychain::generate_unique_filename(base_path.as_os_str().to_str().unwrap(), extension);

        // Create a file at the unique path for the test
        fs::write(&unique_path, "Test content").unwrap();

        assert!(Path::new(&unique_path).is_file());

        assert_eq!(Path::new(&unique_path).extension().unwrap().to_str().unwrap(), extension);

        // Cleanup
        fs::remove_file(unique_path).unwrap();
    }

    #[tokio::test]
    async fn encrypt_decrypt_msg_works() {
        let keychain = Keychain::new().unwrap();

        let pubkey = PathBuf::from("/Users/mm29942/EncryptMod/keychain/key/key.pub");
        let secret_key = PathBuf::from("/Users/mm29942/EncryptMod/keychain/key/key.sec");
        let ciphertext = PathBuf::from("/Users/mm29942/EncryptMod/keychain/cipher/cipher.ct");

        let original_message = "Hello, world!";

        // Encrypt the message
        let encrypted_message = Encrypt::encrypt_msg(original_message, keychain.shared_secret.as_ref().unwrap(), b"secret").await.unwrap();

        // Decrypt the message
        let decrypted_message = Decrypt::decrypt_msg(&encrypted_message, keychain.shared_secret.as_ref().unwrap(), b"secret").await.unwrap();

        // Compare the original and decrypted message
        assert_eq!(original_message, decrypted_message);


        fs::remove_file(&ciphertext).unwrap();
    }

    #[tokio::test]
    async fn encrypt_decrypt_file_works() {
        let keychain = Keychain::new().unwrap();

        let pubkey = PathBuf::from("/Users/mm29942/EncryptMod/keychain/key/key.pub");
        let secret_key = PathBuf::from("/Users/mm29942/EncryptMod/keychain/key/key.sec");
        let ciphertext = PathBuf::from("/Users/mm29942/EncryptMod/keychain/cipher/cipher.ct");

        // Ensure the test file exists
        let original_file_path = PathBuf::from("test_file.txt");
        let encrypted_file_path = PathBuf::from("./test_file.txt.enc");
        let original_file_contents = fs::read_to_string(&original_file_path).unwrap();


        fs::write(&original_file_path, "Test file content").unwrap();
        let original_file_contents = fs::read_to_string(&original_file_path).unwrap();

        // Encrypt the file
        let _ = Encrypt::encrypt(pubkey, None, Some(original_file_path.clone()), b"secret").await;
        
        // Decrypt the file
        let _ = Decrypt::decrypt(secret_key, ciphertext.clone(), Some(&encrypted_file_path), None, b"secret").await;

        // Compare the original and decrypted file contents
        let decrypted_file_contents = fs::read_to_string(&original_file_path).unwrap();
        assert_eq!(original_file_contents, decrypted_file_contents);

        // Cleanup
        fs::remove_file(&original_file_path).unwrap();
        fs::remove_file(&encrypted_file_path).unwrap();

        fs::remove_file(&ciphertext).unwrap();
    }

}