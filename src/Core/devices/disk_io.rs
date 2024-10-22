use nix::fcntl::{open, OFlag};
use nix::libc::{c_void, lseek64, read as nix_read, write as nix_write, SEEK_SET};
use nix::sys::stat::Mode;
use std::path::Path;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex;
use crate::Core::devices::{BLOCK_SIZE, errors::DiskManagerError};  // Adjusted imports
use aes::{Aes256, cipher::KeyInit};
use xts_mode::{Xts128, get_tweak_default};

pub struct DiskIO {
    fd: RawFd,
    path: String,
}

impl DiskIO {
    /// Opens a disk for reading and writing
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DiskManagerError> {
        let fd = open(
            path.as_ref(),
            OFlag::O_RDWR | OFlag::O_DIRECT,
            Mode::empty(),
        )?;
        Ok(DiskIO {
            fd,
            path: path.as_ref().to_string_lossy().to_string(),
        })
    }

    /// Reads a block from the disk
    pub fn read_block(&self, block_number: u64) -> Result<Vec<u8>, DiskManagerError> {
        let block_size = self.get_block_size();
        let mut buf: Vec<u8> = vec![0u8; block_size];
        let offset = (block_number * block_size as u64) as i64;

        // Seek to the block and read data
        unsafe {
            lseek64(self.fd, offset, SEEK_SET);
            let bytes_read = nix_read(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                block_size,
            );

            if bytes_read < 0 {
                return Err(DiskManagerError::IoError(
                    std::io::Error::last_os_error(),
                ));
            } else if bytes_read as usize != block_size {
                return Err(DiskManagerError::IoError(
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Incomplete block read",
                    )
                ));
            }
        }

        Ok(buf)
    }

    /// Writes a block to the disk
    pub fn write_block(&self, block_number: u64, data: &[u8]) -> Result<(), DiskManagerError> {
        let block_size = self.get_block_size();
        if data.len() != block_size {
            return Err(DiskManagerError::IoError(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Data length does not match block size",
                )
            ));
        }

        let offset = (block_number * block_size as u64) as i64;

        // Seek to the block and write data
        unsafe {
            lseek64(self.fd, offset, SEEK_SET);
            let bytes_written = nix_write(
                self.fd,
                data.as_ptr() as *const c_void,
                block_size,
            );

            if bytes_written < 0 {
                return Err(DiskManagerError::IoError(
                    std::io::Error::last_os_error(),
                ));
            } else if bytes_written as usize != block_size {
                return Err(DiskManagerError::IoError(
                    std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Failed to write complete block",
                    )
                ));
            }
        }

        Ok(())
    }

    /// Retrieves the current block size
    pub fn get_block_size(&self) -> usize {
        let block_size = BLOCK_SIZE.lock().unwrap();
        *block_size
    }
}

impl Drop for DiskIO {
    fn drop(&mut self) {
        let _ = nix::unistd::close(self.fd);
    }
}
