use super::*;
use std::collections::HashMap;
use crate::{
    Encryption,
    Decryption,
    EncryptFile,
    DecryptFile,
    Core::{kyber::{KyberFunctions, *}, *},
    error::*,
    devices::*,
};

#[test]
fn test_get_devices() {
    let result = device::SystemInfo::get_devices();
    assert!(result.is_ok());
    
    let devices = result.unwrap();

    for device in devices {
        assert!(device.contains_key("name"));
        assert!(device.contains_key("file_system"));
        assert!(device.contains_key("mount_point"));
        assert!(device.contains_key("total_space"));
        assert!(device.contains_key("available_space"));
    }
}

#[test]
fn test_print_devices() {
    let result = device::SystemInfo::print_devices();
    assert!(result.is_ok());
}