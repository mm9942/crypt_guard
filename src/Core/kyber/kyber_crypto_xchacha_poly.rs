use super::*;

/// Provides Kyber encryption functions for XChaCha20Poly1305 algorithm.
impl<KyberSize, ContentStatus> KyberFunctions for Kyber<Encryption, KyberSize, ContentStatus, XChaCha20Poly1305>
where
    KyberSize: KyberSizeVariant,
{   
    /// Encrypts a file with XChaCha20Poly1305 algorithm, given a path and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_file(&mut self, path: PathBuf, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        if !Path::new(&path).exists() {
            log_activity!(format!("Error: {}.", CryptError::FileNotFound).as_str(), "");
            return Err(CryptError::FileNotFound);
        }

        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };
        let crypt_metadata = CryptographicMetadata::from(
            Process::encryption(),
            CryptographicMechanism::xchacha20(),
            key_encap_mechanism,
            ContentType::file(),
        );
        let file = FileMetadata::from(path, FileTypes::other(), FileState::not_encrypted());
        let infos = CryptographicInformation::from(Vec::new(), passphrase.as_bytes().to_vec(), crypt_metadata, true, Some(file));
        let mut xchacha = CipherChaCha_Poly::new(infos, None);
        log_activity!("Creating a new cipher instance of XChaCha20Poly1305.", "");

        let _ = self.kyber_data.set_nonce(hex::encode(xchacha.nonce()));

        let (data, cipher) = xchacha.encrypt(self.kyber_data.key()?).unwrap();
        log_activity!("Finished:\n\t\tAlgorithm:\t\tXChaCha20Poly1305,\n\t\tContent Type:\tFile\n\t\tProcess:\t\tEncryption\n\t\tKEM:\t\t\t", format!("Kyber{}", kybersize).as_str());
        
        write_log!();
        Ok((data, cipher))
    }
    /// Encrypts a message with XChaCha20Poly1305 algorithm, given the message and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_msg(&mut self, message: &str, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };
        let crypt_metadata = CryptographicMetadata::from(
            Process::encryption(),
            CryptographicMechanism::xchacha20(),
            key_encap_mechanism,
            ContentType::message(),
        );
        let infos = CryptographicInformation::from(message.as_bytes().to_owned(), passphrase.as_bytes().to_vec(), crypt_metadata, false, None);
        let mut xchacha = CipherChaCha_Poly::new(infos, None);
        log_activity!("Creating a new cipher instance of XChaCha20Poly1305.", "");

        let _ = self.kyber_data.set_nonce(hex::encode(xchacha.nonce()));

        let (data, cipher) = xchacha.encrypt(self.kyber_data.key()?).unwrap();
        log_activity!("Finished:\n\t\tAlgorithm:\t\tXChaCha20Poly1305,\n\t\tContent Type:\tMessage\n\t\tProcess:\t\tEncryption\n\t\tKEM:\t\t\t", format!("Kyber{}", kybersize).as_str());
        
        write_log!();
        Ok((data, cipher))
    }
    /// Encrypts a data with XChaCha20Poly1305 algorithm, given the data and a passphrase.
    /// Returns the encrypted data and cipher.
    fn encrypt_data(&mut self, data: Vec<u8>, passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };
        let crypt_metadata = CryptographicMetadata::from(
            Process::encryption(),
            CryptographicMechanism::xchacha20(),
            key_encap_mechanism,
            ContentType::message(),
        );
        let infos = CryptographicInformation::from(data, passphrase.as_bytes().to_vec(), crypt_metadata, false, None);
        let mut xchacha = CipherChaCha_Poly::new(infos, None);
        log_activity!("Creating a new cipher instance of XChaCha20Poly1305.", "");

        let _ = self.kyber_data.set_nonce(hex::encode(xchacha.nonce()));

        let (data, cipher) = xchacha.encrypt(self.kyber_data.key()?).unwrap();
        log_activity!("Finished:\n\t\tAlgorithm:\t\tXChaCha20Poly1305,\n\t\tContent Type:\tMessage\n\t\tProcess:\t\tEncryption\n\t\tKEM:\t\t\t", format!("Kyber{}", kybersize).as_str());
        
        write_log!();
        Ok((data, cipher))
    }
    /// Placeholder for decrypt_file, indicating operation not allowed in encryption mode.
    fn decrypt_file(&self, _path: PathBuf, _passphrase: &str, _ciphertext:Vec<u8>) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of files isn't allowed!"))
    }
    /// Placeholder for decrypt_msg, indicating operation not allowed in encryption mode.
    fn decrypt_msg(&self, _message: Vec<u8>, _passphrase: &str, _ciphertext:Vec<u8>) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }
    /// Placeholder for decrypt_data, indicating operation not allowed in encryption mode.
    fn decrypt_data(&self, _data: Vec<u8>, _passphrase: &str, _ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of data isn't allowed!"))
    }
}


/// Provides Kyber decryption functions for XChaCha20Poly1305 algorithm.
impl<KyberSize, ContentStatus> KyberFunctions for Kyber<Decryption, KyberSize, ContentStatus, XChaCha20Poly1305>
where
    KyberSize: KyberSizeVariant,
{   
    /// Placeholder for encrypt_file, indicating operation not allowed in decryption mode.
    fn encrypt_file(&mut self, _path: PathBuf, _passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of files isn't allowed!"))
    }
    /// Placeholder for encrypt_msg, indicating operation not allowed in decryption mode.
    fn encrypt_msg(&mut self, _message: &str, _passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }
    /// Placeholder for encrypt_data, indicating operation not allowed in decryption mode.
    fn encrypt_data(&mut self, _data: Vec<u8>, _passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        Err(CryptError::new("You're currently in the process state of encryption. Decryption of messanges isn't allowed!"))
    }
    /// Decrypts a file with XChaCha20Poly1305 algorithm, given a path, passphrase, and ciphertext.
    /// Returns the decrypted data.
    fn decrypt_file(&self, path: PathBuf, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        if !Path::new(&path).exists() {
            log_activity!(format!("Error: {}.", CryptError::FileNotFound).as_str(), "");
            return Err(CryptError::FileNotFound);
        }

        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };
        let crypt_metadata = CryptographicMetadata::from(
            Process::decryption(),
            CryptographicMechanism::xchacha20(),
            key_encap_mechanism,
            ContentType::file(),
        );
        let file = FileMetadata::from(path, FileTypes::other(), FileState::encrypted());
        let infos = CryptographicInformation::from(Vec::new(), passphrase.as_bytes().to_vec(), crypt_metadata, true, Some(file));
        let mut xchacha = CipherChaCha_Poly::new(infos, Some(self.kyber_data.nonce()?.to_string()));
        log_activity!("Creating a new cipher instance of XChaCha20Poly1305.", "");

        let data = xchacha.decrypt(self.kyber_data.key()?, ciphertext).unwrap();
        log_activity!("Finished:\n\t\tAlgorithm:\t\tXChaCha20Poly1305,\n\t\tContent Type:\tFile\n\t\tProcess:\t\tDecryption\n\t\tKEM:\t\t\t", format!("Kyber{}", kybersize).as_str());
        
        write_log!();
        Ok(data)
    }
    /// Decrypts a message with XChaCha20Poly1305 algorithm, given the message, passphrase, and ciphertext.
    /// Returns the decrypted data.
    fn decrypt_msg(&self, message: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };
        let crypt_metadata = CryptographicMetadata::from(
            Process::decryption(),
            CryptographicMechanism::xchacha20(),
            key_encap_mechanism,
            ContentType::message(),
        );
        let infos = CryptographicInformation::from(message, passphrase.as_bytes().to_vec(), crypt_metadata, false, None);
        let mut xchacha = CipherChaCha_Poly::new(infos, Some(self.kyber_data.nonce()?.to_string()));
        log_activity!("Creating a new cipher instance of XChaCha20Poly1305.", "");

        let data = xchacha.decrypt(self.kyber_data.key()?, ciphertext).unwrap();
        log_activity!("Finished:\n\t\tAlgorithm:\t\tXChaCha20Poly1305,\n\t\tContent Type:\tMessage\n\t\tProcess:\t\tDecryption\n\t\tKEM:\t\t\t", format!("Kyber{}", kybersize).as_str());
        
        // println!("data: {:?}", data);
        write_log!();
        Ok(data)
    }
    /// Decrypts a message with XChaCha20Poly1305 algorithm, given the message, passphrase, and ciphertext.
    /// Returns the decrypted data.
    fn decrypt_data(&self, data: Vec<u8>, passphrase: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptError> {
        let (key_encap_mechanism, kybersize) = match KyberSize::variant() {
            KyberVariant::Kyber512 => {        
                (KeyEncapMechanism::kyber512(), 512 as usize)
            },
            KyberVariant::Kyber768 => {        
                (KeyEncapMechanism::kyber768(), 768 as usize)
            },
            KyberVariant::Kyber1024 => {        
                (KeyEncapMechanism::kyber1024(), 1024 as usize)
            },
        };
        let crypt_metadata = CryptographicMetadata::from(
            Process::decryption(),
            CryptographicMechanism::xchacha20(),
            key_encap_mechanism,
            ContentType::message(),
        );
        let infos = CryptographicInformation::from(data, passphrase.as_bytes().to_vec(), crypt_metadata, false, None);
        let mut xchacha = CipherChaCha_Poly::new(infos, Some(self.kyber_data.nonce()?.to_string()));
        log_activity!("Creating a new cipher instance of XChaCha20Poly1305.", "");

        let data = xchacha.decrypt(self.kyber_data.key()?, ciphertext).unwrap();
        log_activity!("Finished:\n\t\tAlgorithm:\t\tXChaCha20Poly1305,\n\t\tContent Type:\tMessage\n\t\tProcess:\t\tDecryption\n\t\tKEM:\t\t\t", format!("Kyber{}", kybersize).as_str());
        
        // println!("data: {:?}", data);
        write_log!();
        Ok(data)
    }
}
