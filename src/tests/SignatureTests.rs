use crate::{KDF::*, error::*, FalconKeypair, Signature, Verify};
use std::{
    fs,
    path::{Path, PathBuf}
};


#[test]
fn test_falcon1024_signature_message_macro() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"hey, how are you?".to_vec();
    let (public_key, secret_key) = FalconKeypair!(1024);
    let sign = Signature!(Falcon, secret_key.to_owned(), 1024, data.clone(), Message);
    let verified = Verify!(Falcon, public_key.to_owned(), 1024, sign.clone(), Message);
    assert_eq!(data, verified);

    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");

    Ok(())
}


#[test]
fn test_falcon1024_signature_detached_macro() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"hey, how are you?".to_vec();
    let (public_key, secret_key) = FalconKeypair!(1024);
    let sign = Signature!(Falcon, secret_key.to_owned(), 1024, data.clone(), Detached);
    let verified = Verify!(Falcon, public_key.to_owned(), 1024, sign.clone(), data.clone(), Detached);
    assert!(verified);

    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    
    Ok(())
}

#[test]
fn test_save_Falcon1024_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon1024::keypair().unwrap();
    let _ = Falcon1024::save_public(&public_key);
    let _ = Falcon1024::save_secret(&secret_key);

    let loaded_pub = Falcon1024::load(&PathBuf::from("./Falcon1024/key.pub"))?;
    let _loaded_sec = Falcon1024::load(&PathBuf::from("./Falcon1024/key.sec"))?;
    assert_eq!(public_key, loaded_pub);
    assert!(Path::new("./Falcon1024/key.pub").exists(), "File does not exist: {}", "./Falcon1024/key.pub");
    assert!(Path::new("./Falcon1024/key.sec").exists(), "File does not exist: {}", "./Falcon1024/key.sec");
    
    let _ = fs::remove_dir_all("./Falcon1024")?;
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}
#[test]
fn test_save_Falcon512_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon512::keypair().unwrap();
    let _ = Falcon512::save_public(&public_key);
    let _ = Falcon512::save_secret(&secret_key);    

    let loaded_pub = Falcon512::load(&PathBuf::from("./Falcon512/key.pub"))?;
    let _loaded_sec = Falcon512::load(&PathBuf::from("./Falcon512/key.sec"))?;
    assert_eq!(public_key, loaded_pub);
    assert!(Path::new("./Falcon512/key.pub").exists(), "File does not exist: {}", "./Falcon512/key.pub");
    assert!(Path::new("./Falcon512/key.sec").exists(), "File does not exist: {}", "./Falcon512/key.sec");

    let _ = fs::remove_dir_all("./Falcon512")?;
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}

#[test]
fn test_save_Dilithium2_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium2::keypair().unwrap();
    let _ = Dilithium2::save_public(&public_key);
    let _ = Dilithium2::save_secret(&secret_key);

    let loaded_pub = Dilithium2::load(&PathBuf::from("./Dilithium2/key.pub"))?;
    let _loaded_sec = Dilithium2::load(&PathBuf::from("./Dilithium2/key.sec"))?;
    assert_eq!(public_key, loaded_pub);
    assert!(Path::new("./Dilithium2/key.pub").exists(), "File does not exist: {}", "./Dilithium2/key.pub");
    assert!(Path::new("./Dilithium2/key.sec").exists(), "File does not exist: {}", "./Dilithium2/key.sec");

    let _ = fs::remove_dir_all("./Dilithium2")?;
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}
#[test]
fn test_save_Dilithium3_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium3::keypair().unwrap();    
    let _ = Dilithium3::save_public(&public_key);
    let _ = Dilithium3::save_secret(&secret_key);

    let loaded_pub = Dilithium3::load(&PathBuf::from("./Dilithium3/key.pub"))?;
    let _loaded_sec = Dilithium3::load(&PathBuf::from("./Dilithium3/key.sec"))?;
    assert_eq!(public_key, loaded_pub);
    assert!(Path::new("./Dilithium3/key.pub").exists(), "File does not exist: {}", "./Dilithium3/key.pub");
    assert!(Path::new("./Dilithium3/key.sec").exists(), "File does not exist: {}", "./Dilithium3/key.sec");

    let _ = fs::remove_dir_all("./Dilithium3")?;
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}
#[test]
fn test_save_Dilithium5_keys() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium5::keypair().unwrap();    
    let _ = Dilithium5::save_public(&public_key);
    let _ = Dilithium5::save_secret(&secret_key);

    let loaded_pub = Dilithium5::load(&PathBuf::from("./Dilithium5/key.pub"))?;
    let _loaded_sec = Dilithium5::load(&PathBuf::from("./Dilithium5/key.sec"))?;
    assert_eq!(public_key, loaded_pub);
    assert!(Path::new("./Dilithium5/key.pub").exists(), "File does not exist: {}", "./Dilithium5/key.pub");
    assert!(Path::new("./Dilithium5/key.sec").exists(), "File does not exist: {}", "./Dilithium5/key.sec");
    
    let _ = fs::remove_dir_all("./Dilithium5")?;
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}
#[test]
fn test_falcon1024_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon1024::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Falcon1024, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key.to_owned())?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_falcon1024_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon1024::keypair().unwrap();

    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Falcon1024, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key.to_owned())?;

    assert!(is_valid);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}

#[test]
fn test_falcon512_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon512::keypair().unwrap();

    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Falcon512, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key.to_owned())?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_falcon512_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Falcon512::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Falcon512, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key.to_owned())?;

    assert!(is_valid);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_dilithium2_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium2::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Dilithium2, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key.to_owned())?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_dilithium2_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium2::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Dilithium2, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key.to_owned())?;

    assert!(is_valid);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_dilithium3_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium3::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Dilithium3, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key.to_owned())?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_dilithium3_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium3::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Dilithium3, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key.to_owned())?;

    assert!(is_valid);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_dilithium5_signature_message() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium5::keypair().unwrap();
    let data = b"Hello, world!".to_vec();
    let sign = Signature::<Dilithium5, Message>::new();
    // Sign the message
    let signed_message = sign.signature(data.clone(), secret_key)?;

    // Open the message
    let opened_message = sign.open(signed_message, public_key.to_owned())?;

    // Verify the opened message matches the original data
    assert_eq!(data, opened_message);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}


#[test]
fn test_dilithium5_detached_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = Dilithium5::keypair().unwrap();
    let data = b"Hello, world!".to_vec();

    let sign = Signature::<Dilithium5, Detached>::new();

    // Create a detached signature
    let signature = sign.signature(data.clone(), secret_key)?;

    // Verify the detached signature
    let is_valid = sign.verify(data, signature, public_key.to_owned())?;

    assert!(is_valid);
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
    Ok(())
}

#[test]
fn end2() {
    use std::fs;
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
}