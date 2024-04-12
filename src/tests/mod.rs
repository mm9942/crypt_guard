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

