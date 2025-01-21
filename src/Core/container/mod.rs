use std::path::PathBuf;
use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::process::Command;
use std::fs::OpenOptions;

use sudo;
use crypt_guard::{*, KDF::{*, self}, error::*};
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret, PublicKey, SecretKey};

use aes::{Aes256, cipher::KeyInit};
use xts_mode::{Xts128, get_tweak_default};
use indicatif::{ProgressBar, ProgressStyle};
use gptman::{GPT, GPTPartitionEntry};

pub struct DiskManagement {
    location: PathBuf,         // Path to the disk image
    mount_point: PathBuf,      // Current mount point
    exists: bool,              // Whether the disk image file exists
    mounted: bool,              // Whether the disk image is mounted
    encrypted: bool,           // Whether the disk image is encrypted
    file_system: Option<String>, // File system type (e.g., ext4)
    disk_space: u64,           // Total disk space in bytes
    used_space: u64,           // Used space in bytes
    available_space: u64,      // Available space in bytes
    size: Option<String>,      // User-provided size string (e.g., "1GB")
    sector_size: u64,          // Sector size used by GPT or 0 if unknown
}

impl DiskManagement {
    /// Constructs a new `DiskManagement` object and initializes its fields.
    /// If the file exists, we attempt to detect the sector size from GPT. 
    /// If it doesn’t exist or GPT detection fails, `sector_size` is set to 0 until `create_disk(...)`.
    pub fn new(location: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let exists = location.exists();
        let mut mount_point = PathBuf::new();
        let mut encrypted = false;
        let mut file_system = None;
        let mut disk_space = 0;
        let mut used_space = 0;
        let mut available_space = 0;
        let mut sector_size = 0;

        // If the file exists, attempt GPT read.
        if exists {
            if let Some(mp) = Self::check_mount_point(&location)? {
                mount_point = mp;
                let fs_info = Self::fetch_filesystem_info(&mount_point)?;
                file_system = Some(fs_info.0);
                disk_space = fs_info.1;
                used_space = fs_info.2;
                available_space = fs_info.3;
            }

            match Self::detect_sector_size_via_gpt(&location) {
                Ok(sz) => {
                    sector_size = sz;
                    println!("Detected existing GPT with sector size = {} bytes.", sz);
                }
                Err(e) => {
                    println!("Could not detect GPT sector size: {e}. Setting sector_size=0.");
                }
            }
        }

        Ok(Self {
            location,
            mount_point,
            exists,
            encrypted,
            file_system,
            disk_space,
            used_space,
            available_space,
            size: None,
            sector_size,
        })
    }

    /// Helper to detect the sector size from the **existing** GPT on disk.
    /// Returns an error if GPT is not found.
    fn detect_sector_size_via_gpt(location: &PathBuf) -> Result<u64, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new().read(true).open(location)?;
        let gpt = GPT::find_from(&mut file)?;
        Ok(gpt.sector_size)
    }

    /// Creates a new disk image file with a GPT if it doesn't exist,
    /// then formats it with `mkfs.ext4`. Sets `self.sector_size` to `sector_size`.
    pub fn create_disk(&mut self, size_str: &str, sector_size: u64) -> Result<(), Box<dyn std::error::Error>> {
        if self.exists {
            return Err("Disk already exists.".into());
        }

        // Convert "600MB", "1GB", etc. to bytes
        let size_bytes = Self::parse_size(size_str)?;

        // 1) Create or truncate the file
        {
            let mut f = File::create(&self.location)?;
            f.set_len(size_bytes)?;
        }

        // 2) Write a GPT table using `gptman` with given sector_size
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&self.location)?;

            let random_guid = [0xab; 16]; // or truly random
            let mut gpt = GPT::new_from(&mut f, sector_size, random_guid)?;

            // Single partition from first_usable..last_usable
            let first_usable = gpt.header.first_usable_lba;
            let last_usable = gpt.header.last_usable_lba;
            gpt[1] = GPTPartitionEntry {
                partition_type_guid: [0xff; 16],
                unique_partition_guid: [0xaa; 16],
                starting_lba: first_usable,
                ending_lba: last_usable,
                attribute_bits: 0,
                partition_name: "PrimaryPartition".into(),
            };

            // Write GPT to the file
            gpt.write_into(&mut f)?;
        }

        // 3) Format the entire `.img` with ext4
        Command::new("mkfs.ext4")
            .arg(self.location.to_str().unwrap())
            .status()?;

        // Mark the disk as existing
        self.exists = true;
        self.size = Some(size_str.to_string());
        self.sector_size = sector_size;
        println!(
            "Created new GPT-based disk with sector_size = {} bytes. ({} total)",
            sector_size, size_str
        );
        Ok(())
    }

    /// Encrypt the entire disk image with XTS encryption, using self.sector_size.
    pub fn encrypt_with_xts(&self, key1: &[u8], key2: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if self.sector_size == 0 {
            return Err("Sector size is 0; GPT not initialized or not detected.".into());
        }

        let mut disk_file = File::open(&self.location)?;
        let mut buffer = Vec::new();
        disk_file.read_to_end(&mut buffer)?;

        let total_size = buffer.len() as u64;

        let cipher_1 = Aes256::new_from_slice(key1)?;
        let cipher_2 = Aes256::new_from_slice(key2)?;
        let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

        let pb_encrypt = ProgressBar::new(total_size);
        pb_encrypt.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} Encrypting [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
                .progress_chars("#>-"),
        );

        let sector_size = self.sector_size as usize;
        for (i, chunk) in buffer.chunks_mut(sector_size).enumerate() {
            // i as u128 for tweak
            xts.encrypt_area(chunk, sector_size, i as u128, get_tweak_default);
            pb_encrypt.inc(chunk.len() as u64);
        }
        pb_encrypt.finish_with_message("Encryption complete");

        let encrypted_path = self.location;
        let mut enc_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&encrypted_path)?;

        let pb_write = ProgressBar::new(total_size);
        pb_write.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} Writing [{bar:40.yellow/blue}] {bytes}/{total_bytes} ({eta})")?
                .progress_chars("#>-"),
        );

        for chunk in buffer.chunks(sector_size) {
            enc_file.write_all(chunk)?;
            pb_write.inc(chunk.len() as u64);
        }
        pb_write.finish_with_message("File written successfully");

        println!("Disk encrypted and saved to {:?}", encrypted_path);
        Ok(())
    }


	/// Decrypts a file encrypted with XTS mode and saves the decrypted data to a new file.
	///
	/// # Arguments
	/// * `key1` - The first key for XTS mode (256-bit).
	/// * `key2` - The second key for XTS mode (256-bit).
	/// * `sector_size` - The sector size used during encryption.
	pub fn decrypt_with_xts(
		&self,
	    key1: &[u8],
	    key2: &[u8],
	    sector_size: usize,
	) -> Result<(), Box<dyn std::error::Error>> {
	    // Open the encrypted file
	    let mut encrypted_file = File::open(&self.location)?;
	    let mut buffer = Vec::new();
	    encrypted_file.read_to_end(&mut buffer)?;

	    let total_size = buffer.len() as u64;

	    // Initialize the AES-XTS cipher
	    let cipher_1 = Aes256::new_from_slice(key1)?;
	    let cipher_2 = Aes256::new_from_slice(key2)?;
	    let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

	    // Progress bar for decryption
	    let pb_decrypt = ProgressBar::new(total_size);
	    pb_decrypt.set_style(
	        ProgressStyle::default_bar()
	            .template("{spinner:.green} Decrypting [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
	            .progress_chars("#>-"),
	    );

	    // Decrypt sector by sector
	    for (i, chunk) in buffer.chunks_mut(sector_size).enumerate() {
	        xts.decrypt_area(chunk, sector_size, i as u128, get_tweak_default);
	        pb_decrypt.inc(chunk.len() as u64);
	    }
	    pb_decrypt.finish_with_message("Decryption complete");

	    // Write decrypted data to the output file
	    let mut decrypted_file = File::create(&self.location)?;
	    decrypted_file.write_all(&buffer)?;

	    println!("Decrypted file saved to {:?}", &self.location);
	    Ok(())
	}
    /// Attempt to parse a user-friendly size string (e.g. "600MB", "1GB") into bytes.
    fn parse_size(size_str: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let normalized = size_str.trim().to_lowercase().replace(' ', "");
        if let Some(size) = normalized.strip_suffix("kb") {
            Ok(size.trim().parse::<u64>()? * 1024)
        } else if let Some(size) = normalized.strip_suffix("mb") {
            Ok(size.trim().parse::<u64>()? * 1024 * 1024)
        } else if let Some(size) = normalized.strip_suffix("gb") {
            Ok(size.trim().parse::<u64>()? * 1024 * 1024 * 1024)
        } else if let Some(size) = normalized.strip_suffix("gib") {
            Ok(size.trim().parse::<u64>()? * 1024 * 1024 * 1024)
        } else {
            // fallback: treat as MB
            Ok(normalized.parse::<u64>()? * 1024 * 1024)
        }
    }

    /// Mounts the disk image with `-o loop`
    pub fn mount(&mut self, mount_point: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        if !self.exists {
            return Err("Disk image does not exist.".into());
        }
        if !mount_point.exists() {
            fs::create_dir_all(&mount_point)?;
        }
        Command::new("mount")
            .args(&["-o", "loop", self.location.to_str().unwrap(), mount_point.to_str().unwrap()])
            .status()?;
        self.mount_point = mount_point;
        Ok(())
    }

    /// Unmounts the disk image.
    pub fn umount(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.mount_point.exists() {
            return Err("Disk is not mounted.".into());
        }
        Command::new("umount")
            .arg(self.mount_point.to_str().unwrap())
            .status()?;
        self.mount_point = PathBuf::new();
        Ok(())
    }

    /// Checks if a given disk is mounted.
    fn check_mount_point(location: &PathBuf) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
        let output = Command::new("mount").output()?;
        let output_str = String::from_utf8(output.stdout)?;
        for line in output_str.lines() {
            if line.contains(location.to_str().unwrap()) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    return Ok(Some(PathBuf::from(parts[2])));
                }
            }
        }
        Ok(None)
    }

    /// Fetches filesystem information for a mounted disk using `df -T`.
    fn fetch_filesystem_info(mount_point: &PathBuf) -> Result<(String, u64, u64, u64), Box<dyn std::error::Error>> {
        let output = Command::new("df").args(&["-T", mount_point.to_str().unwrap()]).output()?;
        let output_str = String::from_utf8(output.stdout)?;
        let lines: Vec<&str> = output_str.lines().collect();
        if lines.len() > 1 {
            let fields: Vec<&str> = lines[1].split_whitespace().collect();
            if fields.len() >= 6 {
                let file_system = fields[1].to_string();
                let disk_space = fields[2].parse::<u64>()? * 1024;
                let used_space = fields[3].parse::<u64>()? * 1024;
                let available_space = fields[4].parse::<u64>()? * 1024;
                return Ok((file_system, disk_space, used_space, available_space));
            }
        }
        Err("Failed to fetch filesystem information.".into())
    }
}

/// Combine two ciphertexts of equal length into a single Vec<u8>.
/// Returns an error if lengths differ.
pub fn combine_ciphertexts(
    ct1: &[u8],
    ct2: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if ct1.len() != ct2.len() {
        return Err("Ciphertext length mismatch!".into());
    }
    let mut combined = Vec::with_capacity(ct1.len() + ct2.len());
    combined.extend_from_slice(ct1);
    combined.extend_from_slice(ct2);
    Ok(combined)
}

/// Split a combined ciphertext Vec<u8> back into (ct1, ct2).
/// Assumes the combined length is 2*n, where n = len(ct1) = len(ct2).
pub fn split_ciphertexts(
    combined: &[u8]
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if combined.len() % 2 != 0 {
        return Err("Combined ciphertext length is not even!".into());
    }
    let half = combined.len() / 2;
    let ct1 = combined[..half].to_vec();
    let ct2 = combined[half..].to_vec();
    Ok((ct1, ct2))
}

fn save_combined_ciphertext(cipher_1: &[u8], cipher_2: &[u8], disk_location: &PathBuf) {
	let combined_ciphertext = combine_ciphertexts(ciphertext1.as_bytes(), ciphertext2.as_bytes())?;
    let ciphertext_path = disk.location.with_extension("c");
    {
        let mut c_file = File::create(disk_location)?;
        c_file.write_all(&combined_ciphertext)?;
        println!("Combined ciphertext saved to {:?}", ciphertext_path);
    }
}