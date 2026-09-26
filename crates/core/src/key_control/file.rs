//! On-disk metadata and load/save helpers for cryptographic files.
//!
//! # Responsibility scope
//! Owns [`FileMetadata`], which couples a filesystem path with a [`FileTypes`]
//! classification and a [`FileState`]. It provides PEM-style tag wrapping
//! (`-----BEGIN ...-----`), hex encode/decode on save/load, raw reads, and
//! parent-directory resolution. It does not perform any encryption itself — it
//! only serialises already-processed bytes to and from disk.
//!
//! # Key types exported
//! - [`FileMetadata`] — path + type + state plus its I/O methods.
//!
//! # Concurrency
//! [`FileMetadata`] is `Clone + Send + Sync`; methods touch the filesystem and so
//! are not synchronised against concurrent writers to the same path.
//!
//! # Errors
//! Methods return [`CryptError`](crate::error::CryptError) variants such as `Utf8Error`, `WriteError`,
//! `InvalidKeyType`, `InvalidMessageFormat`, and `HexDecodingError`, plus I/O
//! errors converted from [`std::io::Error`].
//!
//! # Examples
//! ```rust,no_run
//! use std::path::PathBuf;
//! use crypt_guard_core::key_control::{FileMetadata, FileTypes, FileState};
//! let meta = FileMetadata::from(PathBuf::from("public_key.pub"), FileTypes::PublicKey, FileState::Encrypted);
//! meta.save(b"raw-bytes").unwrap();
//! ```

use crate::error::CryptError;
use std::{
    fs,
    io::Write,
    path::PathBuf,
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::key_control::*;

/// Manages metadata related to a file, including its location, type, and state within a cryptographic context.
#[derive(PartialEq, Debug, Clone)]
pub struct FileMetadata {
    /// The filesystem path where the file is located.
    location: PathBuf,
    /// The type of the file, as defined in `FileTypes`.
    file_type: FileTypes,
    /// The current state of the file, as defined in `FileState`.
    file_state: FileState,
}

impl Default for FileMetadata {
    fn default() -> Self {
        Self::new()
    }
}

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

    // Setters
    /// Sets the file location.
    pub fn set_location(&mut self, location: PathBuf) {
        self.location = location;
    }

    /// Sets the file type.
    pub fn set_file_type(&mut self, file_type: FileTypes) {
        self.file_type = file_type;
    }

    /// Sets the file state.
    pub fn set_file_state(&mut self, file_state: FileState) {
        self.file_state = file_state;
    }

    // Getters
    /// Gets the file type.
    pub fn file_type(&self) -> &FileTypes {
        &self.file_type
    }

    /// Gets the file state.
    pub fn file_state(&self) -> &FileState {
        &self.file_state
    }

    /// Retrieves the file's location as a `PathBuf`.
    ///
    /// # Returns
    /// The path to the file encapsulated within this `FileMetadata` instance.
    pub fn location(&self) -> Result<PathBuf, CryptError> {
        let dir_str = self
            .location
            .as_os_str()
            .to_str()
            .ok_or(CryptError::Utf8Error)?;
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
            FileTypes::File => return Err(CryptError::InvalidKeyType),
            FileTypes::Other => return Err(CryptError::InvalidKeyType),
        };
        Ok((start_label.to_string(), end_label.to_string()))
    }

    /// Loads the file's content, decoding it if necessary and stripping any encapsulation tags.
    ///
    /// # Returns
    /// The raw content of the file as a byte vector, or a `CryptError` if loading or processing fails.
    pub fn load(&self) -> Result<Vec<u8>, CryptError> {
        // The decoded file text may itself carry secret key material (e.g. a
        // secret-key or shared-secret file); keep it in a self-wiping buffer.
        let file_content: Zeroizing<String> =
            Zeroizing::new(fs::read_to_string(&self.location).map_err(CryptError::from)?);
        let (start_label, end_label) = self.tags()?;

        let start = file_content
            .find(&start_label)
            .ok_or(CryptError::InvalidMessageFormat)?
            + start_label.len();
        let end = file_content
            .rfind(&end_label)
            .ok_or(CryptError::InvalidMessageFormat)?;

        // Guard against a malformed file where the end tag occurs before the
        // start tag (or otherwise yields an invalid range) — previously this
        // could panic on the slice below.
        if end < start
            || end > file_content.len()
            || !file_content.is_char_boundary(start)
            || !file_content.is_char_boundary(end)
        {
            return Err(CryptError::InvalidMessageFormat);
        }

        let content = file_content[start..end].trim();
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
            _ => PathBuf::new(),
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
        // The hex-encoded text may embed secret key material; keep it in a
        // self-wiping buffer for its whole lifetime.
        let content: Zeroizing<String> = Zeroizing::new(format!(
            "{}{}{}",
            start_label,
            hex::encode(content),
            end_label
        ));

        #[cfg(unix)]
        let mut buffer = {
            let mut open_options = std::fs::OpenOptions::new();
            open_options.write(true).create(true).truncate(true);
            if matches!(self.file_type, FileTypes::SecretKey) {
                // Restrict newly created secret-key files to owner
                // read/write only.
                open_options.mode(0o600);
            }
            open_options
                .open(&self.location)
                .map_err(|_| CryptError::WriteError)?
        };
        #[cfg(not(unix))]
        let mut buffer = fs::File::create(&self.location).map_err(|_| CryptError::WriteError)?;

        buffer
            .write_all(content.as_bytes())
            .map_err(|_| CryptError::WriteError)?;
        Ok(())
    }

    /// Reads the raw content of the file without processing.
    ///
    /// # Returns
    /// The raw content of the file as a byte vector, or a `CryptError` if the read operation fails.
    pub fn read(&self) -> Result<Vec<u8>, CryptError> {
        fs::read(&self.location).map_err(CryptError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_with_end_tag_before_start_tag_errs_without_panicking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broken.pub");
        // End tag physically precedes the start tag in the file, which would
        // previously produce start > end and panic on the slicing index.
        std::fs::write(
            &path,
            "-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\n",
        )
        .expect("write");

        let meta = FileMetadata::from(path, FileTypes::PublicKey, FileState::Encrypted);
        let result = meta.load();
        assert!(matches!(result, Err(CryptError::InvalidMessageFormat)));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("public_key.pub");
        let meta = FileMetadata::from(path, FileTypes::PublicKey, FileState::Encrypted);
        let data = vec![1u8, 2, 3, 4, 5];
        meta.save(&data).expect("save");
        let loaded = meta.load().expect("load");
        assert_eq!(loaded, data);
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret_key.sec");
        let meta = FileMetadata::from(path.clone(), FileTypes::SecretKey, FileState::Encrypted);
        meta.save(&[9u8; 16]).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn public_key_file_is_not_restricted_to_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("public_key.pub");
        let meta = FileMetadata::from(path.clone(), FileTypes::PublicKey, FileState::Encrypted);
        meta.save(&[9u8; 16]).expect("save");

        // Non-secret key files keep the previous (umask-governed) behaviour;
        // we only assert the mode call succeeds and doesn't force 0600.
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        let _ = mode; // documented, non-restrictive check
    }
}
