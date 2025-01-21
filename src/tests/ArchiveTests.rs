use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use crate::{*, archive::{Archive, ArchiveOperation}, zip_manager::*};
use ::zip::read::ZipArchive;

#[test]
fn test_archive_util_archive_without_deletion() {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();

    // Create a file inside the temp directory
    let test_file_path = temp_dir_path.join("test_file.txt");
    {
        let mut test_file = File::create(&test_file_path).expect("Failed to create test file");
        writeln!(test_file, "This is a test file for archiving.").expect("Failed to write to test file");
    }

    // Ensure the file exists
    assert!(test_file_path.exists());

    // Archive the directory without deleting the source
    ArchiveUtil!(temp_dir_path, false, Archive);

    // Verify the archive file exists
    let archive_path = temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists(), "Archive file was not created.");

    // Verify the original directory still exists
    assert!(temp_dir_path.exists(), "Original directory was deleted despite delete_dir=false.");

    // Cleanup: Remove the archive file
    fs::remove_file(archive_path).expect("Failed to remove archive file.");
}

#[test]
fn test_archive_util_archive_with_deletion() {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path().to_path_buf();

    // Create a file inside the temp directory
    let test_file_path = temp_dir_path.join("test_file.txt");
    {
        let mut test_file = File::create(&test_file_path).expect("Failed to create test file");
        writeln!(test_file, "This is a test file for archiving with deletion.").expect("Failed to write to test file");
    }

    // Ensure the file exists
    assert!(test_file_path.exists());

    // Archive the directory and delete the source
    ArchiveUtil!(temp_dir_path.clone(), true, Archive);

    // Verify the archive file exists
    let archive_path = temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists(), "Archive file was not created.");

    // Verify the original directory has been deleted
    assert!(!temp_dir_path.exists(), "Original directory was not deleted despite delete_dir=true.");

    // Cleanup: Remove the archive file
    fs::remove_file(archive_path).expect("Failed to remove archive file.");
}

#[test]
fn test_archive_util_extract_without_deletion() {
    // Create a temporary directory for archiving
    let archive_temp_dir = tempdir().expect("Failed to create archive temp directory");
    let archive_temp_dir_path = archive_temp_dir.path();

    // Create a file inside the archive temp directory
    let test_file_path = archive_temp_dir_path.join("test_file.txt");
    {
        let mut test_file = File::create(&test_file_path).expect("Failed to create test file");
        writeln!(test_file, "This is a test file for extraction.").expect("Failed to write to test file");
    }

    // Archive the directory without deleting the source
    ArchiveUtil!(archive_temp_dir_path, false, Archive);

    // Path to the archive
    let archive_path = archive_temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists(), "Archive file was not created.");

    // Extract the archive without deleting the archive file
    ArchiveUtil!(archive_path.clone(), false, Extract);

    // Determine the extraction directory
    let extraction_dir = archive_temp_dir_path.clone();
    assert!(extraction_dir.exists(), "Extraction directory does not exist.");

    // Verify the extracted file exists
    let extracted_file_path = extraction_dir.join("test_file.txt");
    assert!(extracted_file_path.exists(), "Extracted file does not exist.");

    // Verify the contents of the extracted file
    let mut contents = String::new();
    let mut extracted_file = File::open(&extracted_file_path).expect("Failed to open extracted file.");
    extracted_file.read_to_string(&mut contents).expect("Failed to read extracted file.");
    assert_eq!(contents.trim(), "This is a test file for extraction.", "Extracted file contents do not match.");

    // Verify the archive file still exists
    assert!(archive_path.exists(), "Archive file was deleted despite delete_archive=false.");

    // Cleanup: Remove the archive file
    fs::remove_file(archive_path).expect("Failed to remove archive file.");
}

#[test]
fn test_archive_util_extract_with_deletion() {
    // Create a temporary directory for archiving
    let archive_temp_dir = tempdir().expect("Failed to create archive temp directory");
    let archive_temp_dir_path = archive_temp_dir.path().to_path_buf();

    // Create a file inside the archive temp directory
    let test_file_path = archive_temp_dir_path.join("test_file.txt");
    {
        let mut test_file = File::create(&test_file_path).expect("Failed to create test file");
        writeln!(test_file, "This is a test file for extraction with deletion.").expect("Failed to write to test file");
    }

    // Archive the directory and delete the source
    ArchiveUtil!(archive_temp_dir_path.clone(), true, Archive);

    // Path to the archive
    let archive_path = archive_temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists(), "Archive file was not created.");

    // Extract the archive and delete the archive file
    ArchiveUtil!(archive_path.clone(), true, Extract);

    // Determine the extraction directory
    let extraction_dir = archive_temp_dir_path.clone();
    assert!(extraction_dir.exists(), "Extraction directory does not exist.");

    // Verify the extracted file exists
    let extracted_file_path = extraction_dir.join("test_file.txt");
    assert!(extracted_file_path.exists(), "Extracted file does not exist.");

    // Verify the contents of the extracted file
    let mut contents = String::new();
    let mut extracted_file = File::open(&extracted_file_path).expect("Failed to open extracted file.");
    extracted_file.read_to_string(&mut contents).expect("Failed to read extracted file.");
    assert_eq!(contents.trim(), "This is a test file for extraction with deletion.", "Extracted file contents do not match.");

    // Verify the archive file has been deleted
    assert!(!archive_path.exists(), "Archive file was not deleted despite delete_archive=true.");
}

#[test]
fn test_archive_and_extract() {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();

    // Create a file inside the temp directory
    let temp_file_path = temp_dir_path.join("test_file.txt");
    {
        let mut temp_file = File::create(&temp_file_path).expect("Failed to create temp file");
        writeln!(temp_file, "This is a test file.").expect("Failed to write to temp file");
    }

    // Verify the file exists
    assert!(temp_file_path.exists());

    // 1) ARCHIVE
    let archive = Archive::new(temp_dir_path.to_path_buf(), ArchiveOperation::Archive);
    // false => don't delete the original directory after archiving
    archive.execute(false).expect("Archiving failed");

    // Verify the archive file was created.
    let archive_path = temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists());

    // 2) UNARCHIVE
    let unarchive = Archive::new(archive_path.clone(), ArchiveOperation::Unarchive);
    // false => don't delete the .tar.xz file after extraction
    unarchive.execute(false).expect("Extraction failed");

    // Since the extraction path is the same as the original temp_dir_path,
    // we set extracted_dir directly to temp_dir_path.
    let extracted_dir = temp_dir_path.to_path_buf();

    // Assert that the extracted directory exists (it already did, but ensure it's still there)
    assert!(extracted_dir.exists());

    // Verify the original file is now in the extracted directory
    let extracted_file_path = extracted_dir.join("test_file.txt");
    assert!(extracted_file_path.exists());

    let mut contents = String::new();
    let mut extracted_file = File::open(&extracted_file_path).expect("Failed to open extracted file");
    extracted_file
        .read_to_string(&mut contents)
        .expect("Failed to read extracted file");
    assert_eq!(contents.trim(), "This is a test file.");
}

#[test]
fn test_archive_subdirectory() {
    // Create a top-level temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();

    // Create a subdirectory inside it
    let sub_dir_path = temp_dir_path.join("sub_dir");
    fs::create_dir(&sub_dir_path).expect("Failed to create subdirectory");

    // Create a file in the subdirectory
    let file_in_subdir_path = sub_dir_path.join("test_file.txt");
    {
        let mut temp_file = File::create(&file_in_subdir_path).expect("Failed to create temp file");
        writeln!(temp_file, "This is a test file in a subdirectory.")
            .expect("Failed to write to temp file");
    }
    assert!(file_in_subdir_path.exists());

    // 1) ARCHIVE
    let archive = Archive::new(sub_dir_path.clone(), ArchiveOperation::Archive);
    archive.execute(false).expect("Archiving failed");

    // Check that the archive file exists
    let archive_path = sub_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists());

    // 2) UNARCHIVE
    let extract_archive = Archive::new(archive_path.clone(), ArchiveOperation::Unarchive);
    extract_archive.execute(false).expect("Extraction failed");

    // Correctly determine the extracted directory by removing both ".tar" and ".xz"
    let extracted_dir = archive_path
        .with_extension("") // Removes ".xz", resulting in "sub_dir.tar"
        .with_extension(""); // Removes ".tar", resulting in "sub_dir"

    assert!(extracted_dir.exists());

    // Confirm the file is inside the extracted folder
    let extracted_file_path = extracted_dir.join("test_file.txt");
    assert!(extracted_file_path.exists());

    let mut contents = String::new();
    let mut extracted_file =
        File::open(&extracted_file_path).expect("Failed to open extracted file");
    extracted_file
        .read_to_string(&mut contents)
        .expect("Failed to read extracted file");
    assert_eq!(contents.trim(), "This is a test file in a subdirectory.");
}

#[test]
fn test_archive_and_extract_with_delete_dir() {
    // Create a temporary directory for the source
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path().to_path_buf();

    // Create a file inside the temp directory
    let temp_file_path = temp_dir_path.join("test_file_delete.txt");
    {
        let mut temp_file = File::create(&temp_file_path)
            .expect("Failed to create temp file for delete_dir=true test");
        writeln!(temp_file, "This file will be archived and then the directory deleted.")
            .expect("Failed to write to temp file");
    }

    // Verify the file exists
    assert!(temp_file_path.exists());

    // 1) ARCHIVE with delete_dir=true
    let archive = Archive::new(temp_dir_path.clone(), ArchiveOperation::Archive);
    // true => delete the original directory after archiving
    archive.execute(true).expect("Archiving with delete_dir=true failed");

    // Verify the archive file was created.
    let archive_path = temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists());

    // Verify the original directory has been deleted
    assert!(!temp_dir_path.exists(), "Source directory was not deleted after archiving with delete_dir=true");

    // 2) UNARCHIVE with delete_dir=true
    let unarchive = Archive::new(archive_path.clone(), ArchiveOperation::Unarchive);
    // true => delete the archive file after extraction
    unarchive.execute(true).expect("Unarchiving with delete_dir=true failed");

    // The extraction should restore the original directory
    let extracted_dir = temp_dir_path.clone();
    assert!(extracted_dir.exists(), "Extracted directory does not exist after unarchiving with delete_dir=true");

    // Verify the archive file has been deleted
    assert!(!archive_path.exists(), "Archive file was not deleted after unarchiving with delete_dir=true");

    // Verify the extracted file exists and has correct contents
    let extracted_file_path = extracted_dir.join("test_file_delete.txt");
    assert!(extracted_file_path.exists(), "Extracted file does not exist");

    let mut contents = String::new();
    let mut extracted_file = File::open(&extracted_file_path)
        .expect("Failed to open extracted file after unarchiving with delete_dir=true");
    extracted_file
        .read_to_string(&mut contents)
        .expect("Failed to read extracted file after unarchiving with delete_dir=true");
    assert_eq!(
        contents.trim(),
        "This file will be archived and then the directory deleted.",
        "Extracted file contents do not match expected value"
    );
}

#[test]
fn test_archive_macro_without_delete() {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();

    // Create a file inside the temp directory
    let temp_file_path = temp_dir_path.join("test_file.txt");
    {
        let mut temp_file = File::create(&temp_file_path).expect("Failed to create temp file");
        writeln!(temp_file, "Test content").expect("Failed to write to temp file");
    }

    // Ensure the file exists
    assert!(temp_file_path.exists());

    // Use the archive! macro without deleting the source
    archive!(temp_dir_path, false);

    // Verify the archive exists
    let archive_path = temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists());

    // Verify the original directory still exists
    assert!(temp_dir_path.exists());

    // Cleanup
    fs::remove_file(archive_path).expect("Failed to remove archive file");
}

#[test]
fn test_extract_macro_with_delete() {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();

    // Create a file inside the temp directory
    let temp_file_path = temp_dir_path.join("test_file.txt");
    {
        let mut temp_file = File::create(&temp_file_path).expect("Failed to create temp file");
        writeln!(temp_file, "Test content").expect("Failed to write to temp file");
    }

    // Archive the directory and delete the source
    archive!(temp_dir_path, true);

    // Verify the archive exists
    let archive_path = temp_dir_path.with_extension("tar.xz");
    assert!(archive_path.exists());

    // Verify the original directory has been deleted
    assert!(!temp_dir_path.exists(), "Source directory was not deleted after archiving");

    // Extract the archive and delete the archive file
    extract!(archive_path, true);

    // Verify the extracted directory exists
    assert!(temp_dir_path.exists(), "Extraction failed: Directory does not exist");

    // Verify the archive file has been deleted
    assert!(!archive_path.exists(), "Archive file was not deleted after extraction");

    // Verify the extracted file exists
    let extracted_file_path = temp_dir_path.join("test_file.txt");
    assert!(extracted_file_path.exists());

    // Read and verify the file contents
    let mut contents = String::new();
    let mut extracted_file = File::open(&extracted_file_path).expect("Failed to open extracted file");
    extracted_file
        .read_to_string(&mut contents)
        .expect("Failed to read extracted file");
    assert_eq!(contents.trim(), "Test content");
}

#[test]
fn test_zip_creation() {
    // Create a temporary directory for testing
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();

    // Create a test file inside the temporary directory
    let test_file_path = temp_dir_path.join("test_file.txt");
    {
        let mut test_file = File::create(&test_file_path).expect("Failed to create test file");
        writeln!(test_file, "This is a test file.").expect("Failed to write to test file");
    }

    assert!(test_file_path.exists(), "Test file does not exist");

    // Create a ZIP archive
    let archive_path = temp_dir_path.join("test_archive.zip");
    let mut manager = ZipManager::new(archive_path.to_str().unwrap());
    manager.add_file(test_file_path.to_str().unwrap());
    manager.create_zip(Compression::deflated()).expect("Failed to create ZIP archive");

    // Verify the ZIP archive was created
    assert!(archive_path.exists(), "ZIP archive was not created");

    // Open the ZIP archive and list its contents for debugging
    let file = File::open(&archive_path).expect("Failed to open ZIP archive");
    let mut zip_archive = ZipArchive::new(file).expect("Failed to read ZIP archive");

    println!("Files in ZIP archive:");
    for i in 0..zip_archive.len() {
        let file = zip_archive.by_index(i).expect("Failed to access file in ZIP archive");
        println!("Found file in ZIP: {}", file.name());
    }

    // Attempt to locate the test file in the ZIP archive
    // Ensure the path matches exactly how it's stored in the ZIP
    let file_name_in_zip = "test_file.txt"; // Adjust if the path includes directories

    let mut extracted_file = zip_archive
        .by_name(file_name_in_zip)
        .unwrap();

    let mut contents = String::new();
    extracted_file.read_to_string(&mut contents).expect("Failed to read extracted file");
    assert_eq!(contents.trim(), "This is a test file.", "Extracted file contents do not match");

    // Cleanup: Remove the ZIP file
    fs::remove_file(&archive_path).expect("Failed to remove ZIP archive");
}

#[test]
fn test_zip_folder() {
    // Create a temporary directory for testing
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();

    // Create subdirectories and files inside the temporary directory
    let sub_dir_path = temp_dir_path.join("sub_dir");
    let nested_sub_dir_path = sub_dir_path.join("nested");
    fs::create_dir_all(&nested_sub_dir_path).expect("Failed to create nested subdirectory");

    let test_file1_path = temp_dir_path.join("file1.txt");
    let test_file2_path = sub_dir_path.join("file2.txt");
    let test_file3_path = nested_sub_dir_path.join("file3.txt");

    {
        let mut test_file1 = File::create(&test_file1_path).expect("Failed to create test file1");
        writeln!(test_file1, "Content of file1").expect("Failed to write to test file1");

        let mut test_file2 = File::create(&test_file2_path).expect("Failed to create test file2");
        writeln!(test_file2, "Content of file2").expect("Failed to write to test file2");

        let mut test_file3 = File::create(&test_file3_path).expect("Failed to create test file3");
        writeln!(test_file3, "Content of file3").expect("Failed to write to test file3");
    }

    // Verify the created directory and files exist
    assert!(test_file1_path.exists(), "Test file1 does not exist");
    assert!(test_file2_path.exists(), "Test file2 does not exist");
    assert!(test_file3_path.exists(), "Test file3 does not exist");

    // Create a ZIP archive of the whole directory
    let archive_path = temp_dir_path.join("test_folder_archive.zip");
    let mut manager = ZipManager::new(archive_path.to_str().unwrap());
    manager.add_directory(temp_dir_path.to_str().unwrap());
    manager.create_zip(Compression::Deflated).expect("Failed to create ZIP archive");

    // Verify the ZIP archive was created
    assert!(archive_path.exists(), "ZIP archive was not created");

    // Open the ZIP archive and validate its contents
    let file = File::open(&archive_path).expect("Failed to open ZIP archive");
    let mut zip_archive = ZipArchive::new(file).expect("Failed to read ZIP archive");

    println!("Files in ZIP archive:");
    let mut found_files = Vec::new();
    for i in 0..zip_archive.len() {
        let file = zip_archive.by_index(i).expect("Failed to access file in ZIP archive");
        println!("Found file in ZIP: {}", file.name());
        found_files.push(file.name().to_string());
    }

    // Search for files dynamically in the archive structure, ignoring the temp folder name
    let sub_dir_entry = found_files
        .iter()
        .find(|path| path.ends_with("sub_dir/"))
        .expect("Failed to find sub_dir/ in ZIP archive");

    let expected_file2_path = format!("{}/file2.txt", sub_dir_entry.trim_end_matches('/'));
    let expected_file3_path = format!("{}/nested/file3.txt", sub_dir_entry.trim_end_matches('/'));

    // Locate and read the contents of the files
    {
        let mut extracted_file2 = zip_archive
            .by_name(&expected_file2_path)
            .expect("Failed to find sub_dir/file2.txt in ZIP archive");

        let mut contents2 = String::new();
        extracted_file2.read_to_string(&mut contents2).expect("Failed to read extracted file2");
        assert_eq!(contents2.trim(), "Content of file2", "Extracted file2 content mismatch");
    }

    {
        let mut extracted_file3 = zip_archive
            .by_name(&expected_file3_path)
            .expect("Failed to find sub_dir/nested/file3.txt in ZIP archive");

        let mut contents3 = String::new();
        extracted_file3.read_to_string(&mut contents3).expect("Failed to read extracted file3");
        assert_eq!(contents3.trim(), "Content of file3", "Extracted file3 content mismatch");
    }

    // Cleanup: Remove the ZIP file
    fs::remove_file(&archive_path).expect("Failed to remove ZIP archive");
}
