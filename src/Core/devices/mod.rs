#![cfg(target_os = "linux")]

pub mod device;
pub mod disk_io;
pub mod errors;
mod virtual_disk;
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};

// A lazy_static block size with Mutex for dynamic modification
lazy_static! {
    pub static ref BLOCK_SIZE: Arc<Mutex<usize>> = Arc::new(Mutex::new(512)); // Default to 512 bytes
}

#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux operating systems.");