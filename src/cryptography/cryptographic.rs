use crate::{
    KeyControl::*,
    cryptography::{
        CipherAES,
        *,
    },
};
use std::{
	fs::File,
	io::Write,
};

impl CryptographicMechanism {
	pub fn new() -> Self {
		Self::AES
	}
	pub fn aes() -> Self {
		Self::AES
	}
	pub fn xchacha20() -> Self {
		Self::XChaCha20
	}
}

impl Process {
	pub fn encryption() -> Self {
		Self::Encryption
	}
	pub fn decryption() -> Self {
		Self::Decryption
	}
}
impl KeyEncapMechanism {
	pub fn new() -> Self {
		Self::Kyber1024
	}
	pub fn kyber1024() -> Self {
		Self::Kyber1024
	}
}

impl ContentType {
	pub fn new() -> Self {
		Self::File
	}
	pub fn file() -> Self {
		Self::File
	}
	pub fn message() -> Self {
		Self::Message
	}
}

impl CryptographicMetadata {
	pub fn new() -> Self {
		CryptographicMetadata {
			process: Process::encryption(),
			encryption_type: CryptographicMechanism::new(),
			key_type: KeyEncapMechanism::new(),
			content_type: ContentType::new(),
		}
	}
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

	pub fn process(&self) -> Result<Process, CryptError> {
		Ok(self.process)
	}
}


impl CryptographicInformation {
	pub fn new() -> Self {
		CryptographicInformation {
			content: Vec::new(),
			passphrase: Vec::new(),
			metadata: CryptographicMetadata::new(),
			safe: false,
			location: None
		}
	}
	pub fn contains_file(&self) -> Result<bool, CryptError> {
		let contains_file = match &self.location {
			Some(_) => true,
			None => false
		};
		Ok(contains_file)
	}
	pub fn set_data(&mut self, data: &[u8]) -> Result<(), CryptError> {
		let mut data = data.to_vec();
		self.content = data;
		Ok(())
	}

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
	pub fn safe(&self) -> Result<bool, CryptError> {
		Ok(self.safe)
	}
	pub fn location(&self) -> Result<PathBuf, CryptError> {
		let file = match &self.location {
			Some(path) => Ok(path.location()?),
			_ => Err(CryptError::PathError)
		};
		file
	}
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

	pub fn content(&self) -> Result<&[u8], CryptError> {
		Ok(&self.content)
	}
	pub fn passphrase(&self) -> Result<&[u8], CryptError> {
		Ok(&self.passphrase)
	}
}