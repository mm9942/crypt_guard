use crate::{
    KeyControl::*,
    cryptography::{
        *,
    },
};
use std::{
	fs::File,
	io::Write,
};

/// Enum defining cryptographic mechanisms supported by the system.
impl CryptographicMechanism {
    /// Creates a new instance defaulting to AES.
    pub fn new() -> Self {
        Self::AES
    }
    /// Specifies AES as the cryptographic mechanism.
    pub fn aes() -> Self {
        Self::AES
    }

    /// Specifies AES as the cryptographic mechanism.
    pub fn aes_gcm_siv() -> Self {
        Self::AES_GCM_SIV
    }

    /// Specifies AES as the cryptographic mechanism.
    pub fn aes_ctr() -> Self {
        Self::AES_CTR
    }

    /// Specifies XChaCha20 as the cryptographic mechanism.
    pub fn aes_xts() -> Self {
        Self::AES_XTS
    }

    /// Specifies XChaCha20 as the cryptographic mechanism.
    pub fn xchacha20() -> Self {
        Self::XChaCha20
    }
}

/// Enum defining the process type (encryption or decryption).
impl Process {
    /// Specifies the process as encryption.
    pub fn encryption() -> Self {
        Self::Encryption
    }
    /// Specifies the process as decryption.
    pub fn decryption() -> Self {
        Self::Decryption
    }
}

/// Enum defining key encapsulation mechanisms supported.
impl KeyEncapMechanism {
    /// Creates a new instance defaulting to Kyber1024.
    pub fn new() -> Self {
        Self::Kyber1024
    }
    /// Specifies Kyber1024 as the key encapsulation mechanism.
    pub fn kyber1024() -> Self {
        Self::Kyber1024
    }
    /// Specifies Kyber768 as the key encapsulation mechanism.
    pub fn kyber768() -> Self {
        Self::Kyber768
    }
    /// Specifies Kyber512 as the key encapsulation mechanism.
    pub fn kyber512() -> Self {
        Self::Kyber512
    }
}

/// Enum defining the type of content being encrypted or decrypted.
impl ContentType {
    /// Creates a new instance defaulting to file.
    pub fn new() -> Self {
        Self::File
    }
    /// Specifies the content as a file.
    pub fn file() -> Self {
        Self::File
    }
    /// Specifies the content as a message.
    pub fn message() -> Self {
        Self::Message
    }
    /// Specifies the content as a RawData.
    pub fn raw_data() -> Self {
        Self::RawData
    }
}

/// Stores cryptographic settings for an operation.
impl CryptographicMetadata {
    /// Constructs a new instance with default values.
	pub fn new() -> Self {
		CryptographicMetadata {
			process: Process::encryption(),
			encryption_type: CryptographicMechanism::new(),
			key_type: KeyEncapMechanism::new(),
			content_type: ContentType::new(),
		}
	}
	
    /// Constructs a new instance with specified values.
	pub fn from(
		process: Process,
		encryption_type: CryptographicMechanism,
		key_type: KeyEncapMechanism,
		content_type: ContentType,
	) -> Self {
		CryptographicMetadata {
			process,
			encryption_type,
			key_type,
			content_type,
		}
	}

    /// Accessor method for process property
	pub fn process(&self) -> Result<Process, CryptError> {
		Ok(self.process)
	}

    /// Accessor method for encryption_type property
	pub fn encryption_type(self) -> Result<CryptographicMechanism, CryptError> {
		Ok(self.encryption_type)
	}

    /// Accessor method for key_type property
	pub fn key_type(self) -> Result<KeyEncapMechanism, CryptError> {
		Ok(self.key_type)
	}

    /// Accessor method for content_type property
	pub fn content_type(self) -> Result<ContentType, CryptError> {
		Ok(self.content_type)
	}
}

/// Holds all cryptographic information for an encryption/decryption operation.
impl CryptographicInformation {
    /// Constructs a new instance with empty values and default metadata.
	pub fn new() -> Self {
		CryptographicInformation {
			content: Vec::new(),
			passphrase: Vec::new(),
			metadata: CryptographicMetadata::new(),
			safe: false,
			location: None
		}
	}

    /// Checks if the cryptographic information contains a file.
	pub fn contains_file(&self) -> Result<bool, CryptError> {
		let contains_file = match &self.location {
			Some(_) => true,
			None => false
		};
		Ok(contains_file)
	}

    /// Sets the content to be encrypted or decrypted.
	pub fn set_data(&mut self, data: &[u8]) -> Result<(), CryptError> {
		let data = data.to_vec();
		self.content = data;
		Ok(())
	}

    /// Prepares a file name for saving, considering its extension.
	fn prepare_file_name_for_saving(&self, file_path: &PathBuf) -> Result<PathBuf, CryptError> {
        let mut new_file_path = file_path.clone();
        
        // Check if the file extension is .enc
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            if extension == "enc" {
                // If the extension is .enc, remove it to get the original file name
                new_file_path.set_extension("");
            } else {
                // If the file does not have an .enc extension, append .enc to the file name
                let file_name_with_enc = format!("{}.enc", file_path.to_string_lossy());
                new_file_path = file_path.with_file_name(file_name_with_enc);
            }
        } else {
            // If the file has no extension, simply append .enc
            let file_name_with_enc = format!("{}.enc", file_path.to_string_lossy());
            new_file_path = file_path.with_file_name(file_name_with_enc);
        }

        Ok(new_file_path)
    }

    /// Safely saves the content to a file at the specified location.
    pub fn safe_file(&mut self) -> Result<(), CryptError> {
        let file_path = self.location().map_err(|_| CryptError::PathError)?;

        // Use the new function to prepare the file name
        let file_path_with_enc = self.prepare_file_name_for_saving(&file_path)?;

        if let Some(parent_dir) = file_path_with_enc.parent() {
            if !parent_dir.is_dir() {
                std::fs::create_dir_all(parent_dir).map_err(|_| CryptError::WriteError)?;
            }
        }

        let mut buffer = File::create(&file_path_with_enc).map_err(|_| CryptError::WriteError)?;
        buffer.write_all(&self.content).map_err(|_| CryptError::WriteError)?;

        Ok(())
    }

    /// Indicates whether the cryptographic operation is considered safe.
	pub fn safe(&self) -> Result<bool, CryptError> {
		Ok(self.safe)
	}

    /// Returns the file location.
	pub fn location(&self) -> Result<PathBuf, CryptError> {
		let file = match &self.location {
			Some(path) => Ok(path.location()?),
			_ => Err(CryptError::PathError)
		};
		file
	}

    /// Constructs a new instance with specified values.
	pub fn from(
		content: Vec<u8>,
		passphrase: Vec<u8>,
		metadata: CryptographicMetadata,
		safe: bool,
		location: Option<FileMetadata>
	) -> Self {
		CryptographicInformation {
			content,
			passphrase,
			metadata,
			safe,
			location
		}
	}

	// Accessor method for content.
	pub fn content(&self) -> Result<&[u8], CryptError> {
		Ok(&self.content)
	}

	// Accessor method for passphrase
	pub fn passphrase(&self) -> Result<&[u8], CryptError> {
		Ok(&self.passphrase)
	}
}