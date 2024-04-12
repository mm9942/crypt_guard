use std::fs::{self, File};
use std::io::Read;
use tempfile::tempdir;
use crate::{log::*, log_activity, write_log, activate_log, LOGGER};

#[test]
fn test_logger_activation() {
    let log_dir = tempdir().unwrap();
    let log_file_path = log_dir.path().join("test_log.txt");

    // Activate the logger with a temporary directory
    activate_log(log_file_path.to_str().unwrap());

    // Your logic to verify logger activation
    // For example, check if the `activated` flag is set to true, which might require making the flag accessible or checking for side effects of activation.
}

#[test]
fn test_log_directory_creation() {
    let log_dir = tempdir().unwrap();
    let log_file_path = log_dir.path().join("test_log.txt");

    activate_log(log_file_path.to_str().unwrap());
    log_activity!("Test log entry", "\nSeccond part"); // Use the macro to generate a log entry
    write_log!(); // Attempt to write the log file

    // Verify the log directory and file are created correctly
    assert!(log_dir.path().join("test_log").exists(), "Log directory should exist");
}

#[test]
fn test_unique_log_file_naming() {
    let log_dir = tempdir().unwrap();
    let log_file_path = log_dir.path().join("test_log.txt");

    activate_log(log_file_path.to_str().unwrap());

    // Generate and write multiple log entries to ensure unique naming
    for _ in 0..3 {
        log_activity!("Test log entry", "\nSeccond part");
        write_log!();
    }

    let log_files = fs::read_dir(log_dir.path().join("test_log")).unwrap();

    // Ensure that there are exactly 3 log files with expected naming pattern
    let mut file_count = 0;
    for entry in log_files {
        let entry = entry.unwrap();
        let path = entry.path();
        let filename = path.file_name().unwrap().to_str().unwrap();

        assert!(filename.starts_with("test_log_") || filename == "test_log.txt", "Unexpected file name: {}", filename);
        file_count += 1;
    }

    assert_eq!(file_count, 3, "There should be exactly 3 log files");
}