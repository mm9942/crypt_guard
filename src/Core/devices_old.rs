use sysinfo::{
    Components, Disks, Networks, System,
};
use std::{
	fs::File,
	io::{self, Read, Seek, SeekFrom},
	error::Error,
	collections::HashMap,
	process::Command,
	path::{PathBuf, Path},
};

pub struct Device {
	device_name: String,
	mount_point: PathBuf,
	raw_blocks: Vec<u8>, 

}

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