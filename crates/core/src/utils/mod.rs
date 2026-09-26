#[cfg(feature = "archive")]
pub mod archive;

#[cfg(feature = "zip")]
pub mod zip_manager;

// Scaffolding kept for the upcoming archive/zip path-handling helpers; not yet
// wired into a caller. Gated rather than deleted to preserve the intended API.
#[allow(dead_code)]
enum TargetType {
    Dir,
    File,
    Symlink,
}

#[allow(dead_code)]
impl TargetType {
    pub fn dir() -> Self {
        Self::Dir
    }
    pub fn file() -> Self {
        Self::File
    }
    pub fn symlink() -> Self {
        Self::Symlink
    }
}

// Reserved namespace struct for future utility associated functions.
#[allow(dead_code)]
struct Utils;
