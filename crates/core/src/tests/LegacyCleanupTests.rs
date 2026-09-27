use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

#[test]
fn test_no_diskmanagement_or_storage_references() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_path = crate_root.join("src");

    const DISK_MANAGEMENT: &str = concat!("Disk", "Management");
    const STORAGE_COMPONENT: &str = concat!("Contain", "er");

    for entry in WalkDir::new(&src_path) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => panic!("WalkDir error: {}", e),
        };
        if entry.file_type().is_file() {
            let content = match fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(e) => panic!("Failed to read {}: {}", entry.path().display(), e),
            };
            assert!(
                !content.contains(DISK_MANAGEMENT),
                "Found '{}' in {}",
                DISK_MANAGEMENT,
                entry.path().display()
            );
            assert!(
                !content.contains(STORAGE_COMPONENT),
                "Found '{}' in {}",
                STORAGE_COMPONENT,
                entry.path().display()
            );
        }
    }
}
