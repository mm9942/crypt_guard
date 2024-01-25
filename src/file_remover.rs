use indicatif::{ProgressBar, ProgressStyle};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{
    error::Error,
    fmt::{self, Display},
    fs::{self, remove_file, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::PathBuf,
};

#[derive(Debug)]
pub enum FileRemoverErr {
    FileOpenError(io::Error),
    MetadataError(io::Error),
    WriteError(io::Error),
    SeekError(io::Error),
    DeletionError(io::Error),
    FilePathNotFound,
    InvalidOverwriteCount,
    DirectoryOperationError(io::Error),
    RecursiveDeletionNotAllowed,
}
use colored::*;

impl Display for FileRemoverErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FileRemoverErr::FileOpenError(err) => write!(f, "Failed to open file: {}", err),
            FileRemoverErr::MetadataError(err) => {
                write!(f, "Failed to read file metadata: {}", err)
            }
            FileRemoverErr::WriteError(err) => write!(f, "Failed to write to file: {}", err),
            FileRemoverErr::SeekError(err) => write!(f, "Failed to seek in file: {}", err),
            FileRemoverErr::DeletionError(err) => write!(f, "Failed to delete the file: {}", err),
            FileRemoverErr::FilePathNotFound => write!(f, "The file path does not exist"),
            FileRemoverErr::InvalidOverwriteCount => {
                write!(f, "Invalid overwrite count; it must be greater than 0")
            }
            FileRemoverErr::DirectoryOperationError(err) => {
                write!(f, "Directory operation failed: {}", err)
            }
            FileRemoverErr::RecursiveDeletionNotAllowed => {
                write!(f, "Recursive deletion is not allowed")
            }
        }
    }
}

impl Error for FileRemoverErr {}

pub struct FileRemover {
    overwrite_times: u32,
    file_path: PathBuf,
    recursive: bool,
    progress_bar: ProgressBar,
}

impl FileRemover {
    pub fn new(
        overwrite_times: u32,
        file_path: PathBuf,
        recursive: bool,
    ) -> Result<Self, FileRemoverErr> {
        if overwrite_times == 0 {
            return Err(FileRemoverErr::InvalidOverwriteCount);
        }

        if !file_path.exists() {
            return Err(FileRemoverErr::FilePathNotFound);
        }

        let mut pb = ProgressBar::new(0 as u64);
        if !file_path.is_dir() {
            let file_name = file_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("Unknown"))
                .to_string_lossy();

            let pb_style = ProgressStyle::default_bar()
                .template("{msg} {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-");

            pb = ProgressBar::new(overwrite_times as u64);
            pb.set_message(file_name.to_string());
            pb.set_style(pb_style);
        }

        Ok(Self {
            overwrite_times,
            file_path,
            recursive,
            progress_bar: pb,
        })
    }

    pub fn delete_file(&mut self) -> Result<(), FileRemoverErr> {
        let total_size = self.get_file_size().unwrap_or(0);

        for i in 0..self.overwrite_times {
            self.initialize_progress_bar(i + 1, total_size);
            self.overwrite_file()?;
            let filename = self.file_path.file_name().unwrap().to_str();
            self.progress_bar.finish_with_message(format!(
                "Overwriting {:?} {} times completed",
                filename,
                i + 1
            ));
        }

        remove_file(&self.file_path).map_err(FileRemoverErr::DeletionError)?;
        Ok(())
    }

    fn get_file_size(&self) -> Result<u64, FileRemoverErr> {
        let metadata = fs::metadata(&self.file_path).map_err(FileRemoverErr::MetadataError)?;
        Ok(metadata.len())
    }

    fn initialize_progress_bar(&mut self, iteration: u32, total_size: u64) {
        let pb_style = ProgressStyle::default_bar()
            .template("{msg} {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-");

        self.progress_bar = ProgressBar::new(total_size);
        self.progress_bar.set_style(pb_style);
        let text = "\nOverwriting: ".italic().cyan();
        let filename = self.file_path.file_name().unwrap().to_str();
        self.progress_bar.set_message(format!(
            "{}{}\nOverwriting ({} of {})",
            text,
            filename.unwrap().italic().bright_cyan(),
            iteration,
            self.overwrite_times
        ));
    }

    pub fn overwrite_file(&self) -> Result<(), FileRemoverErr> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)
            .map_err(FileRemoverErr::FileOpenError)?;

        let file_size = file
            .metadata()
            .map_err(FileRemoverErr::MetadataError)?
            .len();

        let chunk_size = (file_size / 100).max(1);
        let mut written: u64 = 0;

        while written < file_size {
            let remaining_size = file_size - written;
            let data_size = chunk_size.min(remaining_size);
            let random_data: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(data_size as usize)
                .map(char::from)
                .collect();

            file.write_all(random_data.as_bytes())
                .map_err(FileRemoverErr::WriteError)?;

            written += data_size as u64;
            self.progress_bar.set_position(written.min(file_size));
        }

        Ok(())
    }

    pub fn delete(&mut self) -> Result<(), FileRemoverErr> {
        if self.file_path.is_dir() {
            if !self.recursive {
                return Err(FileRemoverErr::RecursiveDeletionNotAllowed);
            }
            let path_color = self.file_path.to_string_lossy().italic().bright_cyan();
            let text = format!(
                "{}: {}",
                "\n\nProcessing directory".italic().cyan(),
                path_color
            );
            println!("{}", text);

            for entry in
                fs::read_dir(&self.file_path).map_err(FileRemoverErr::DirectoryOperationError)?
            {
                let entry = entry.map_err(FileRemoverErr::DirectoryOperationError)?;
                let path = entry.path();
                let mut remover = FileRemover::new(self.overwrite_times, path, self.recursive)?;
                remover.delete()?;
            }
            fs::remove_dir(&self.file_path).map_err(FileRemoverErr::DeletionError)
        } else {
            self.delete_file()
        }
    }
}
