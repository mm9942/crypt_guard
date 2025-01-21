//! # Archive Utilities Library
//!
//! [![Crates.io][crates-badge]][crates-url]
//! [![Documentation][doc-badge]][doc-url]
//!
//! [crates-badge]: https://img.shields.io/badge/crates.io-v0.1.0-blue.svg?style=for-the-badge
//! [crates-url]: https://crates.io/crates/your_crate_name
//! [doc-badge]: https://img.shields.io/badge/docs-latest-yellow.svg?style=for-the-badge
//! [doc-url]: https://docs.rs/your_crate_name/
//!
//! ## Introduction
//!
//! This library provides utilities for creating ZIP archives in Rust. It offers a convenient interface
//! to add files and directories to a ZIP archive with various compression methods.
//! The `ZipManager` struct allows you to specify the files and directories you want to include
//! in your archive, and then create the ZIP file with the desired compression method.
//!
//! ## Key Features
//!
//! - Add individual files or entire directories to the ZIP archive.
//! - Support for multiple compression methods: Stored (no compression), Deflated, Bzip2, and Zstd.
//! - Automatically handles directory traversal and adds all nested files and subdirectories.
//! - Ensures correct relative paths inside the ZIP archive.
//!
//! ## Examples
//!
//! ### Creating a ZIP Archive with Files and Directories
//!
//! ```rust
//! use std::path::PathBuf;
//! use crypt_guard::zip_manager::*;
//!
//! fn main() {
//!     // Specify the path where the ZIP archive will be created
//!     let output_zip = "archive.zip";
//!
//!     // Create a new ZipManager instance
//!     let mut zip_manager = ZipManager::new(output_zip);
//!
//!     // Add individual files to the archive
//!     zip_manager.add_file("/home/mm29942/Desktop/crypt_guard-main/Cargo.toml");
//!
//!     // Add an entire directory to the archive
//!     zip_manager.add_directory("/home/mm29942/Desktop/crypt_guard-main/src/Core");
//!
//!     // Create the ZIP archive with the desired compression method
//!     zip_manager.create_zip(Compression::Deflated).expect("Failed to create ZIP archive");
//!
//!     println!("ZIP archive created at {}", output_zip);
//!     std::fs::remove_file(&output_zip).expect("Failed to remove ZIP archive");
//! }
//! ```
//!
//! ### Compression Methods
//!
//! The `Compression` enum defines the available compression methods:
//!
//! - `Compression::stored()`: No compression.
//! - `Compression::deflated()`: Standard DEFLATE compression.
//! - `Compression::bzip2()`: Bzip2 compression. **Note**: Requires the `bzip2` feature in the `zip` crate.
//! - `Compression::zstd()`: Zstandard compression. **Note**: Requires the `zstd` feature in the `zip` crate.
//!
//! ### Notes
//!
//! - Make sure to handle errors appropriately in a real application.
//! - The paths added to the `ZipManager` should exist; otherwise, an error will occur when creating the ZIP archive.
//! - The `create_zip` function writes the ZIP file to the specified `output_path`.
//!
//! ## Crate Features
//!
//! Depending on the compression methods you intend to use, ensure that the `zip` crate is configured with the necessary features in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! zip = { version = "0.6", features = ["deflate", "bzip2", "zstd"] }
//! walkdir = "2.3"
//! ```
//!
//! ## License
//!
//! This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


use std::{
    fs::File,
    io::{BufWriter, Seek, Write},
    path::{Path, PathBuf},
};

use walkdir::WalkDir;
use zip::{
    write::{FileOptions, ZipWriter},
    CompressionMethod,
    result::ZipResult,
};

/// Represents the type of a path (file or directory).
#[derive(Debug)]
pub enum PathType {
    File,
    Dir,
}

#[derive(Debug)]
pub enum Compression {
    Stored,
    Deflated,
    Bzip2,
    Zstd,
}

impl Compression {
    pub fn stored() -> Self {
        Compression::Stored
    }
    pub fn deflated() -> Self {
        Compression::Deflated
    }
    pub fn bzip2() -> Self {
        Compression::Bzip2
    }
    pub fn zstd() -> Self {
        Compression::Zstd
    }
}

/// Represents an item to be added to the ZIP archive.
#[derive(Debug)]
pub struct ZipItem {
    source_path: PathBuf,
    path_type: PathType,
}

/// Manages the creation of a ZIP input vector.
pub struct ZipManager {
    items: Vec<ZipItem>,
    output_path: PathBuf,
}

impl ZipManager {
    /// Creates a new `ZipManager` instance.
    pub fn new(output_path: &str) -> Self {
        Self {
            items: Vec::new(),
            output_path: PathBuf::from(output_path),
        }
    }

    /// Adds a file to the ZIP archive.
    pub fn add_file(&mut self, source: &str) {
        self.items.push(ZipItem {
            source_path: PathBuf::from(source),
            path_type: PathType::File,
        });
    }

    /// Adds a directory to the ZIP archive.
    pub fn add_directory(&mut self, source: &str) {
        self.items.push(ZipItem {
            source_path: PathBuf::from(source),
            path_type: PathType::Dir,
        });
    }

    /// Compress the added items into a ZIP file.
    pub fn create_zip(&self, compression: Compression) -> ZipResult<()> {
        let file = File::create(&self.output_path)?;
        let buf_writer = BufWriter::new(file);
        let mut zip_writer = ZipWriter::new(buf_writer);

        let options: FileOptions<()> = match compression {
            Compression::Deflated => {
                FileOptions::default()
                    .compression_method(CompressionMethod::Deflated)
                    .unix_permissions(0o755)
            }
            Compression::Stored => {
                FileOptions::default()
                    .compression_method(CompressionMethod::Stored)
                    .unix_permissions(0o755)
            }
            Compression::Bzip2 => {
                FileOptions::default()
                    .compression_method(CompressionMethod::Bzip2)
                    .unix_permissions(0o755)
            }
            Compression::Zstd => {
                FileOptions::default()
                    .compression_method(CompressionMethod::Zstd)
                    .unix_permissions(0o755)
            }
        };

        for item in &self.items {
            match item.path_type {
                PathType::File => {
                    let base_path = item.source_path.parent().unwrap_or(Path::new(""));
                    self.compress_file(
                        &mut zip_writer,
                        &item.source_path,
                        base_path,
                        &options,
                    )?;
                }
                PathType::Dir => {
                    let base_path = &item.source_path;
                    self.compress_directory(&mut zip_writer, base_path, &options)?;
                }
            }
        }

        zip_writer.finish()?;
        println!("ZIP archive created successfully at {:?}", self.output_path);

        Ok(())
    }

    pub fn compress_file<W>(
        &self,
        zip_writer: &mut ZipWriter<W>,
        file_path: &Path,
        base_path: &Path,
        options: &FileOptions<()>,
    ) -> ZipResult<()>
    where
        W: Write + Seek,
    {
        let relative_path = file_path.strip_prefix(base_path).unwrap_or(file_path);
        let zip_path = relative_path.to_string_lossy().replace("\\", "/");
        zip_writer.start_file(&zip_path, options.clone())?;
        let mut f = File::open(file_path)?;
        std::io::copy(&mut f, zip_writer)?;
        Ok(())
    }

    pub fn compress_directory<W>(
        &self,
        zip_writer: &mut ZipWriter<W>,
        dir_path: &Path,
        options: &FileOptions<()>,
    ) -> ZipResult<()>
    where
        W: Write + Seek,
    {
        for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            // Ensure relative paths are correctly calculated
            let relative_path = path.strip_prefix(dir_path).unwrap_or(path);
            let zip_path = relative_path.to_string_lossy().replace("\\", "/");

            if path.is_file() {
                self.compress_file(zip_writer, path, dir_path, options)?;
            } else if path.is_dir() {
                let dir_name = if zip_path.ends_with('/') || zip_path.ends_with('\\') {
                    zip_path.to_owned()
                } else {
                    format!("{}/", zip_path)
                };
                zip_writer.add_directory(dir_name, options.clone())?;
            }
        }

        Ok(())
    }
}
