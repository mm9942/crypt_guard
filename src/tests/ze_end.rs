use std::fs;

#[test]
fn end() {
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("log.txt");
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
    let _ = fs::remove_dir_all("./key");
    let _ = fs::remove_dir_all("./log");
}