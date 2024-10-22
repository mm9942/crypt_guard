use std::collections::HashMap;
use std::path::PathBuf;
use crate::Core::devices::errors::DiskManagerError;
use sysinfo::{
    Components, Disks, Networks, System,
};
pub struct Device {
    pub device_name: String,
    pub file_system: String,
    pub mount_point: PathBuf,
    pub total_space: u64,
    pub available_space: u64,
    pub is_removable: bool,
}
use std::error::Error;

impl Device {
    /// Creates a new Device instance from a sysinfo Disk reference
    pub fn from_sys_disk(disk: &sysinfo::Disk) -> Result<Self, DiskManagerError> {
        Ok(Device {
            device_name: disk.name().to_string_lossy().to_string(),
            file_system: disk.file_system().to_string_lossy().to_string(),
            mount_point: disk.mount_point().to_path_buf(),
            total_space: disk.total_space(),
            available_space: disk.available_space(),
            is_removable: disk.is_removable(),
        })
    }
}

pub struct SystemInfo {
    system: System,
}

impl SystemInfo {
    /// Initializes and refreshes system information
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        SystemInfo { system: sys }
    }

    /// Retrieves all connected disks as a vector of Device structs
    pub fn get_devices() -> Result<Vec<HashMap<String, String>>, Box<dyn Error>> {
        let mut sys = System::new_all();
    
        sys.refresh_all();
    
        println!("=> disks:");
        let disks = Disks::new_with_refreshed_list();
        let mut disks_vec = Vec::new();
    
        for disk in &disks {
            let mut disks_map = HashMap::new();
    
            disks_map.insert(String::from("name"), disk.name().to_str().unwrap().to_string());
            disks_map.insert(String::from("file_system"), disk.file_system().to_str().unwrap().to_string());
            disks_map.insert(String::from("mount_point"), disk.mount_point().to_str().unwrap().to_string());
            disks_map.insert(String::from("total_space"), disk.total_space().to_string());
            disks_map.insert(String::from("available_space"), disk.available_space().to_string());
            disks_map.insert(String::from("is_removable"), disk.is_removable().to_string());
    
            disks_vec.push(disks_map);
        }
        disks_vec.sort_by(|a, b| a.get("name").unwrap().cmp(b.get("name").unwrap()));
        Ok(disks_vec)
    }
    
    pub fn print_devices() -> Result<(), Box<dyn Error>> {
        let mut sys = System::new_all();
    
        sys.refresh_all();
    
        println!("=> disks:");
        let disks = Disks::new_with_refreshed_list();
        let mut disks_vec = Vec::new();
    
        for disk in &disks {
            let mut disks_map = HashMap::new();
    
            disks_map.insert("name".to_string(), disk.name().to_str().unwrap().to_string());
            disks_map.insert("file_system".to_string(), disk.file_system().to_str().unwrap().to_string());
            disks_map.insert("mount_point".to_string(), disk.mount_point().to_str().unwrap().to_string());
            disks_map.insert("total_space".to_string(), disk.total_space().to_string());
            disks_map.insert("available_space".to_string(), disk.available_space().to_string());
            disks_map.insert(String::from("is_removable"), disk.is_removable().to_string());
    
            disks_vec.push(disks_map);
        }
    
        disks_vec.sort_by(|a, b| a.get("name").unwrap().cmp(b.get("name").unwrap()));
        for (i, disk_map) in disks_vec.iter().enumerate() {
            println!("Disk {}:", i + 1);
            println!("\tName: {}", disk_map.get("name").unwrap());
            println!("\tFile System: {}", disk_map.get("file_system").unwrap());
            println!("\tMount Point: {}", disk_map.get("mount_point").unwrap());
            println!("\tTotal Space: {} bytes", disk_map.get("total_space").unwrap());
            println!("\tAvailable Space: {} bytes", disk_map.get("available_space").unwrap());
            println!("\tRemovable: {}", disk_map.get("is_removable").unwrap());
            println!();
        }
    
        Ok(())
    }
}