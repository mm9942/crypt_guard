//! Wire-format version constants for the CGv2 envelope.
//!
//! # Responsibility scope
//! Owns the magic bytes and the current envelope version constant. Both are
//! embedded in every [`super::Header`] and are the first thing checked during
//! deserialization.
//!
//! # Key types exported
//! - [`MAGIC`] — four-byte file magic `b"CGv2"`
//! - [`VERSION_V2`] — current envelope version number (`2u16`)
//!
//! # Concurrency
//! Compile-time constants; no runtime state.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::protocol::version::{MAGIC, VERSION_V2};
//! assert_eq!(&MAGIC, b"CGv2");
//! assert_eq!(VERSION_V2, 2);
//! ```

/// Four-byte magic number that identifies a CGv2 envelope.
///
/// # Description
/// Placed at the very beginning of every serialized envelope so that parsers
/// can reject non-envelope byte streams before attempting further parsing.
pub const MAGIC: [u8; 4] = *b"CGv2";

/// Current envelope version number.
///
/// # Description
/// Stored as a little-endian `u16` in bytes 4–5 of the serialized header.
/// Parsers that encounter an unknown version must return
/// [`crate::error::CryptError::UnsupportedEnvelopeVersion`].
pub const VERSION_V2: u16 = 2;
