use std::{
    path::{PathBuf, Path}, 
    result::Result, 
    io::{Write}, 
    fs::{self, OpenOptions},
    sync::Arc
};
use chrono::Local;
use tracing_subscriber::prelude::*;
use crate::error::CryptError;
use std::sync::Mutex;

lazy_static! {
    pub static ref LOGGER: Mutex<Log> = Mutex::new(Log {
        activated: false,
        log: String::new(),
        location: None,
    });
}

/// Struct used for logging 
pub struct Log {
    pub activated: bool,
    pub log: String,
    pub location: Option<PathBuf>,
}

pub fn initialize_logger(log_file: PathBuf) {
    let mut logger = LOGGER.lock().unwrap();
    logger.activated = true;
    logger.location = Some(log_file.clone());

    // Set up tracing subscriber to write to the provided file path.
    // We avoid printing time/level because our messages already contain the timestamp.
    if let (Some(parent), Some(file_name)) = (log_file.parent(), log_file.file_name().and_then(|s| s.to_str())) {
        let _ = std::fs::create_dir_all(parent);
        let appender = tracing_appender::rolling::never(parent, file_name);
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .without_time()
            .with_level(false)
            .with_writer(appender);

        // Try setting as global subscriber; ignore error if already set.
        let subscriber = tracing_subscriber::registry().with(fmt_layer);
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}

impl Log {
    /// Activate the log and define the log files path.
    pub fn activate(log_file: PathBuf) -> Self {
        Log {
            activated: true,
            log: String::new(),
            location: Some(log_file),
        }
    }
    /// Clear the structs String element.
    pub fn clear(&mut self) {
        self.log.clear();
    }
    /// Append two &str to the log. When manually impementing it please regard that the format used is:
    ///     "{}:\n\t{}{}\n", process(&str), detail(&str)
    pub fn append_log(&mut self, process: &str, detail: &str) -> Result<(), CryptError> {
        if self.activated {
            let timestamp = Local::now();
            let log_entry = format!("{}:\n\t{}{}\n", timestamp.format("%m/%d/%y %H:%M"), process, detail);

            // Prepend a newline to the log entry if the log is not empty
            let log_entry: String = if !self.log.is_empty() {
                format!("\n{}", log_entry)
            } else {
                log_entry
            };

            self.log.push_str(&log_entry);
            // Emit via tracing as the primary logging backend
            tracing::info!(target: "crypt_guard", "{}", log_entry);
        }
        Ok(())
    }
    /// Create a new splitted log file
    pub fn write_log_file(&mut self) -> Result<(), CryptError> {
        if !self.activated {
            return Ok(());
        }
        if let Some(ref location) = self.location {
            let parent_dir = location.parent().unwrap_or_else(|| Path::new(""));
            let file_stem = location.file_stem().unwrap().to_str().unwrap();
            let extension = location.extension().unwrap_or_default().to_str().unwrap();

            let log_dir = parent_dir.join(file_stem);
            if !log_dir.exists() {
                fs::create_dir_all(&log_dir).map_err(|e| CryptError::IOError(Arc::new(e)))?;
            }

            let mut file_path = log_dir.join(format!("{}.{}", file_stem, extension));
            let mut counter = 1;
            while file_path.exists() {
                file_path = log_dir.join(format!("{}_{}.{}", file_stem, counter, extension));
                counter += 1;
            }

            let mut file = OpenOptions::new().create(true).write(true).open(file_path)?;
            write!(file, "{}", self.log)?;
            
            // Clear the log content after writing to file
            self.log.clear();
        } else {
            return Err(CryptError::CustomError("Log location not set.".to_string()));
        }

        Ok(())
    }
}
