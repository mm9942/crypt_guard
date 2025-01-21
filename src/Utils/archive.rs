use std::{
    error::Error,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};
use tar::{Archive as TarArchive, Builder as TarBuilder};
use xz2::write::XzEncoder;

#[derive(Debug)]
pub enum ArchiveOperation {
    Archive,
    Unarchive,
}

#[derive(Debug)]
pub struct Archive {
    /// For `Archive`, `source_path` is the directory (or file) you want to compress.
    /// For `Unarchive`, `source_path` is the `.tar.xz` file you want to decompress.
    source_path: PathBuf,
    operation: ArchiveOperation,
}

impl Archive {
    /// Creates a new `Archive` instance.
    /// 
    /// - `source_path`:
    ///   - For `Archive`, the directory (or file) that you want to compress.
    ///   - For `Unarchive`, the `.tar.xz` file that you want to extract.
    /// - `operation`: `ArchiveOperation::Archive` or `ArchiveOperation::Unarchive`.
    ///
    /// This version automatically determines the `.tar.xz` name or the extracted
    /// directory name based on `source_path`.
    pub fn new(source_path: PathBuf, operation: ArchiveOperation) -> Self {
        Self {
            source_path,
            operation,
        }
    }

    /// Executes the archiving or unarchiving operation.
    ///
    /// If `delete_dir` is `true`:
    /// - For `Archive`, removes the original `source_path` after creating the `.tar.xz`.
    /// - For `Unarchive`, removes the `.tar.xz` file after extracting.
    pub fn execute(&self, delete_dir: bool) -> Result<(), Box<dyn Error>> {
        match self.operation {
            ArchiveOperation::Archive => {
                self.create_archive()?;
                if delete_dir {
                    fs::remove_dir_all(&self.source_path)?;
                }
            }
            ArchiveOperation::Unarchive => {
                self.extract_archive()?;
                if delete_dir {
                    fs::remove_file(&self.source_path)?;
                }
            }
        }
        Ok(())
    }

    /// Archives the directory (or file) given by `source_path` into `[source_path].tar.xz`.
    fn create_archive(&self) -> Result<(), Box<dyn Error>> {
        // Example:
        //   source_path = /path/to/some_dir
        //   => archive_path = /path/to/some_dir.tar.xz
        let parent_dir = self.source_path.parent().unwrap_or_else(|| Path::new("."));
        let file_stem = self
            .source_path
            .file_name()
            .ok_or("Source path has no file name!")?;
        let archive_name = format!("{}.tar.xz", file_stem.to_string_lossy());
        let archive_path = parent_dir.join(archive_name);

        // Create the final `.tar.xz` file
        let tar_xz_file = File::create(&archive_path)?;
        // Wrap it in an XZ encoder
        let xz_encoder = XzEncoder::new(tar_xz_file, 6); // 6 = compression level
        let mut tar_builder = TarBuilder::new(xz_encoder);

        // Append the entire directory (or file) into the archive
        tar_builder.append_dir_all(".", &self.source_path)?;

        // Finish writing the tar
        let xz_encoder = tar_builder.into_inner()?;
        xz_encoder.finish()?;
        Ok(())
    }

    /// Unarchives the file `[source_path].tar.xz` into `[source_path].tar.xz` (minus `.tar.xz`).
    ///
    /// For example:
    ///   /path/to/some_dir.tar.xz
    ///   => extracts into /path/to/some_dir
    fn extract_archive(&self) -> Result<(), Box<dyn Error>> {
        // 1. Open the `.tar.xz` file
        let tar_xz_file = File::open(&self.source_path)?;
        let buf_reader = BufReader::new(tar_xz_file);

        // 2. Wrap in an XZ decoder
        let xz_decoder = xz2::read::XzDecoder::new(buf_reader);

        // 3. Build a tar archive reader
        let mut tar_archive = TarArchive::new(xz_decoder);

        // 4. Decide the output directory by stripping ".tar.xz" from the source_path
        let parent_dir = self.source_path.parent().unwrap_or_else(|| Path::new("."));
        let source_file_stem = self
            .source_path
            .file_stem()
            .ok_or("Could not determine file stem from .tar.xz")?;

        // Some files might have a stem like "foo.tar" if the file is "foo.tar.xz"
        // so let's trim `.tar` if it exists.
        let mut out_dir_name = source_file_stem.to_os_string();
        if out_dir_name.to_string_lossy().ends_with(".tar") {
            let trimmed = out_dir_name
                .to_string_lossy()
                .trim_end_matches(".tar")
                .to_string();
            out_dir_name = trimmed.into();
        }
        let destination = parent_dir.join(out_dir_name);

        // 5. Create the directory if needed, then unpack
        fs::create_dir_all(&destination)?;
        tar_archive.unpack(&destination)?;

        Ok(())
    }
}