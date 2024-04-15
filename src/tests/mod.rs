use crate::activate_log;

#[cfg(test)]
#[test]
fn begin() {
	activate_log("crypt_tests.log")
}

#[cfg(test)]
mod KyberKeyTest;

#[cfg(test)]
mod kyber_tests;

#[cfg(test)]
mod SignatureTests;

#[cfg(test)]
mod LoggingTests;

#[cfg(test)]
#[test]
fn end() {
	use std::fs;
	let _ = fs::remove_file("crypt_tests.log");
	let _ = fs::remove_dir_all("./crypt_tests");
}