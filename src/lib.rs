#[macro_use]
extern crate lazy_static;

/// Core functionalitys for control of Kyber keys as well as encryption and decryption
mod Core;
/// Cryptographic related functionalitys, enums structs and modules
mod cryptography;
/// File and Key related functionalitys, enums structs and modules
mod KeyControl;
/// Logging related functionalitys
pub mod log;
/// Error types
pub mod error;

#[cfg(test)]
mod tests;

pub use crate::{
    log::*,
    Core::KDF,
    KeyControl::{
        *,
        file::*, 
    },
    Core::{
        *,
        kyber::{
            *,
            KeyControler::{self, *},
        },
    },
    cryptography::{
        *,
    },

};

use KeyControl::*;
use cryptography::*;


use pqcrypto_falcon::falcon1024::{self, *};
use pqcrypto_kyber::kyber1024::{self, *};
use std::{
    error::Error,
    fmt::{self, *},
    iter::repeat,
    path::{PathBuf, Path}, 
    marker::PhantomData, 
    result::Result, 
    io::{Read, Write}, 
    sync::Mutex,
    fs
};

lazy_static! {
    static ref LOGGER: Mutex<Log> = Mutex::new(Log {
        activated: false,
        log: String::new(),
        location: None,
    });
}

pub fn activate_log<P: AsRef<Path>>(log_file: P) {
    let mut logger = LOGGER.lock().unwrap();
    logger.activated = true;
    logger.location = Some(log_file.as_ref().to_path_buf());
}

#[macro_export]
macro_rules! log_activity {
    ($process:expr, $kyber_size:expr) => {
        match LOGGER.lock() {
            Ok(mut logger) => {
                let _ = logger.append_log($process, $kyber_size);
            },
            Err(e) => eprintln!("Logger lock error: {}", e),
        }
    };
}

#[macro_export]
macro_rules! write_log {
    () => {
        {
            let mut logger = $crate::LOGGER.lock().expect("Logger lock failed");
            if let Err(e) = logger.write_log_file() {
                eprintln!("Failed to write log file: {:?}", e);
            }
            logger.log.clear();
        }
    };
}