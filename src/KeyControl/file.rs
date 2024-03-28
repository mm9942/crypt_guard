use std::{
	path::{Path, PathBuf},
	io::{Seek, Write},
	fs::{self, File},
};
use crate::error::CryptError;

use crate::KeyControl::*;

/// Manages metadata and operations for cryptographic files, including key files, messages, and ciphertexts.
///
/// Provides functionality for loading, saving, and manipulating file paths and contents according to the cryptographic context.
impl FileMetadata {
    /// Creates a new `FileMetadata` instance with default values.
    ///
    /// # Returns
    /// A new instance of `FileMetadata` with empty location, and default types set to `Other`.
	pub fn new() -> Self {
		FileMetadata {
			location: PathBuf::new(),
			file_type: FileTypes::Other,
			file_state: FileState::Other,
		}
	}

    /// Constructs a `FileMetadata` instance from specified parameters.
    ///
    /// # Parameters
    /// - `location`: The filesystem path where the file is located.
    /// - `file_type`: The type of file, determining how it is processed and labeled.
    /// - `file_state`: The state of the file, influencing how it should be treated in cryptographic operations.
    ///
    /// # Returns
    /// A new instance of `FileMetadata` configured with the provided details.
	pub fn from(location: PathBuf, file_type: FileTypes, file_state: FileState) -> Self {
		FileMetadata {
			location,
			file_type,
			file_state,
		}
	}    

    /// Retrieves the file's location as a `PathBuf`.
    ///
    /// # Returns
    /// The path to the file encapsulated within this `FileMetadata` instance.
    pub fn location(&self) -> Result<PathBuf, CryptError> {
        let dir_str = &self.location.as_os_str().to_str().unwrap();
        let dir = PathBuf::from(dir_str);
        Ok(dir)
    }

    /// Generates start and end tags based on the file's type, used for wrapping content in specific file formats.
    ///
    /// # Returns
    /// A tuple containing start and end tags as strings, or a `CryptError` if the operation fails.
	pub fn tags(&self) -> Result<(String, String), CryptError> {
		let (start_label, end_label) = match self.file_type {
            FileTypes::PublicKey => ("-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----"),
            FileTypes::SecretKey => ("-----BEGIN SECRET KEY-----\n", "\n-----END SECRET KEY-----"),
            FileTypes::Message => ("-----BEGIN MESSAGE-----\n", "\n-----END MESSAGE-----"),
            FileTypes::Ciphertext => ("-----BEGIN CIPHERTEXT-----\n", "\n-----END CIPHERTEXT-----"),
            FileTypes::File => unreachable!(),
            FileTypes::Other => unreachable!(),
        };
        Ok((start_label.to_string(), end_label.to_string()))
	}

    /// Loads the file's content, decoding it if necessary and stripping any encapsulation tags.
    ///
    /// # Returns
    /// The raw content of the file as a byte vector, or a `CryptError` if loading or processing fails.
    pub fn load(&self) -> Result<Vec<u8>, CryptError> {
        let file_content = fs::read_to_string(&self.location).map_err(|_| CryptError::IOError)?;
        let (start_label, end_label) = self.tags()?;

        let start = file_content.find(&start_label)
            .ok_or(CryptError::InvalidMessageFormat)? + start_label.len();
        let end = file_content.rfind(&end_label)
            .ok_or(CryptError::InvalidMessageFormat)?;

        let content = &file_content[start..end].trim();
        hex::decode(content).map_err(|_| CryptError::HexDecodingError("Invalid hex format".into()))
    }

    /// Retrieves the parent directory of the file's location.
    ///
    /// # Returns
    /// The path to the parent directory as a `PathBuf`, or an empty path if the location is root or unset.
    pub fn parent(&self) -> Result<PathBuf, CryptError> {
        let parent = self.location.parent();
        let parent = match parent {
            Some(parent) => PathBuf::from(parent),
            _ => {PathBuf::new()}
        };
        Ok(parent)
    }

    /// Saves content to the file's location, wrapping it with appropriate start and end tags.
    ///
    /// # Parameters
    /// - `content`: The raw content to save to the file.
    ///
    /// # Returns
    /// An `Ok(())` upon successful save or a `CryptError` if the operation fails.
    pub fn save(&self, content: &[u8]) -> Result<(), CryptError> {
        if let Some(parent_dir) = self.location.parent() {
            if !parent_dir.is_dir() {
                std::fs::create_dir_all(parent_dir).map_err(|_| CryptError::WriteError)?;
            }
        }

        let (start_label, end_label) = self.tags()?;
        let content = format!("{}{}{}", start_label, hex::encode(content), end_label);
        let mut buffer = File::create(&self.location).map_err(|_| CryptError::WriteError)?;
        let _ = buffer.write(content.as_bytes());
        Ok(())
    }
    
    /// Reads the raw content of the file without processing.
    ///
    /// # Returns
    /// The raw content of the file as a byte vector, or a `CryptError` if the read operation fails.
    pub fn read(&self) -> Result<Vec<u8>, CryptError> {
    	Ok(fs::read(&self.location).map_err(|_| CryptError::IOError)?)
    }
}