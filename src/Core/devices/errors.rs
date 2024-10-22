use std::fmt;
use std::io;
use std::error::Error;  // Add this import for the Error trait

#[derive(Debug)]
pub enum DiskManagerError {
    IoError(io::Error),
    SysInfoError(String),
    NixError(nix::Error),
    EncryptionError(String),
    // Add other error variants as needed
}

impl fmt::Display for DiskManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiskManagerError::IoError(e) => write!(f, "IO Error: {}", e),
            DiskManagerError::SysInfoError(e) => write!(f, "SysInfo Error: {}", e),
            DiskManagerError::NixError(e) => write!(f, "Nix Error: {}", e),
            DiskManagerError::EncryptionError(e) => write!(f, "Encryption Error: {}", e),
        }
    }
}

// Implement the std::error::Error trait for DiskManagerError
impl Error for DiskManagerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DiskManagerError::IoError(e) => Some(e),
            DiskManagerError::NixError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for DiskManagerError {
    fn from(error: io::Error) -> Self {
        DiskManagerError::IoError(error)
    }
}

impl From<nix::Error> for DiskManagerError {
    fn from(error: nix::Error) -> Self {
        DiskManagerError::NixError(error)
    }
}
