use std::path::{PathBuf, Path};
use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::process::Command;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::error::Error;
use sudo;
use crypt_guard::{*, KDF::{*, self}, error::*};
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret, PublicKey, SecretKey};

use aes::{Aes256, cipher::KeyInit};
use xts_mode::{Xts128, get_tweak_default};
use indicatif::{ProgressBar, ProgressStyle};
use gptman::{GPT, GPTPartitionEntry};

pub struct Drive {
    file_system: Option<String>,
    disk_space: u64,
    used_space: u64,
    available_space: u64,
    sector_size: u64,
}

impl Drive {
    fn from(
        file_system: Option<String>,
        disk_space: u64,
        used_space: u64,
        available_space: u64,
        sector_size: u64,
    ) -> Self {
        Self { 
            file_system,
            disk_space,
            used_space,
            available_space,
            sector_size,
        }
    }
    fn file_system(&self) -> &Option<String> {
        &self.file_system
    }
    fn disk_space(&self) -> &u64 {
        &self.disk_space
    }
    fn used_space(&self) -> &u64 {
        &self.used_space
    }
    fn available_space(&self) -> &u64 {
        &self.available_space
    }
    fn sector_size(&self) -> &u64 {
        &self.sector_size
    }
}

pub struct Container {
    location: PathBuf,
    mount_point: PathBuf,
    drive: Drive,
}

