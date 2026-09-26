//! CryptGuard v3 default transport: PQ HPKE envelopes.
//!
//! Run with `cargo run --example pq_hpke`.
//!
//! Shows the recommended, zeroizing API surface:
//! - deterministic recipient keys from a 32-byte provenance seed kept in
//!   zeroizing memory,
//! - sealing with separate `info` (setup context) and `aad` (per record),
//! - opening into `Zeroizing<Vec<u8>>` so the plaintext is wiped on drop,
//! - the opaque failure for a wrong `aad`.

use crypt_guard::pq_hpke::{derive_recipient_key_pair, HpkeEnvelope, DEFAULT_SUITE};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In production the seed comes from a KMS/HSM or a sealed store. Keep it
    // in zeroizing memory and never log it.
    let seed = Zeroizing::new([7u8; 32]);
    let keys = derive_recipient_key_pair(DEFAULT_SUITE.kem(), seed.as_slice())?;

    let info = b"service=billing;v=1";
    let aad = b"record=42";
    let envelope = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        info,
        aad,
        b"card ending 4242",
    )?;
    let wire = envelope.try_to_bytes()?;
    println!("sealed {} bytes (CGH3 envelope)", wire.len());

    // Receiver side: parse, open into zeroizing memory.
    let received = HpkeEnvelope::from_bytes(&wire)?;
    let plaintext = received.open_zeroizing(keys.private_key(), info, aad)?;
    assert_eq!(plaintext.as_slice(), b"card ending 4242");
    println!("opened {} plaintext bytes", plaintext.len());

    // A different `aad` (or `info`, or any tampering) is an opaque failure.
    let wrong = received.open_zeroizing(keys.private_key(), info, b"record=43");
    assert!(wrong.is_err());
    println!("wrong aad rejected: {}", wrong.unwrap_err());

    // The same seed always re-derives the same key pair.
    let again = derive_recipient_key_pair(DEFAULT_SUITE.kem(), seed.as_slice())?;
    assert_eq!(again.public_key().as_bytes(), keys.public_key().as_bytes());
    Ok(())
}
