





#[test]
fn end() {
    use std::fs;
    let _ = fs::remove_file("crypt_tests.log");
    let _ = fs::remove_file("message.txt");
    let _ = fs::remove_file("message.txt.enc");
    let _ = fs::remove_dir_all("./crypt_tests");
}