//! The `CGK1` frame.
//!
//! ```text
//! magic "CGK1" (4) | version u8 = 1 | fields…
//! field    = len u32 BE | bytes
//! u8/u16/u32 scalars are written raw, big-endian, without a length prefix
//! ```
//!
//! The reader never panics and never allocates: every accessor borrows from
//! the input and checks bounds with `get`/`checked_*`.

/// Media type of `CGK1` bodies.
pub const CONTENT_TYPE: &str = "application/vnd.cryptguard.kms.v1";
/// Frame magic.
pub const MAGIC: [u8; 4] = *b"CGK1";
/// Frame version.
pub const VERSION: u8 = 1;

/// Frame decoding / encoding errors. Deliberately payload-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Input ended inside a header, length or field.
    Truncated,
    /// Wrong magic.
    BadMagic,
    /// Unknown frame version.
    UnsupportedVersion,
    /// A field is longer than `u32::MAX` (writer) or the declared length
    /// exceeds the remaining input (reader).
    TooLong,
    /// Bytes left after the last expected field.
    Trailing,
    /// A field has an invalid value (bad UTF-8 name, unknown profile, …).
    Invalid,
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated frame",
            Self::BadMagic => "bad magic",
            Self::UnsupportedVersion => "unsupported version",
            Self::TooLong => "field too long",
            Self::Trailing => "trailing bytes",
            Self::Invalid => "invalid field",
        })
    }
}

impl std::error::Error for CodecError {}

/// Borrowing frame reader.
#[derive(Debug)]
pub struct FrameReader<'a> {
    rest: &'a [u8],
}

impl<'a> FrameReader<'a> {
    /// Check magic and version and position after them.
    pub fn new(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let magic = bytes.first_chunk::<4>().ok_or(CodecError::Truncated)?;
        if *magic != MAGIC {
            return Err(CodecError::BadMagic);
        }
        let version = bytes.get(4).ok_or(CodecError::Truncated)?;
        if *version != VERSION {
            return Err(CodecError::UnsupportedVersion);
        }
        let rest = bytes.get(5..).ok_or(CodecError::Truncated)?;
        Ok(Self { rest })
    }

    /// Next length-prefixed field.
    pub fn field(&mut self) -> Result<&'a [u8], CodecError> {
        let len_bytes = self.rest.first_chunk::<4>().ok_or(CodecError::Truncated)?;
        let len = u32::from_be_bytes(*len_bytes) as usize;
        let after_len = self.rest.get(4..).ok_or(CodecError::Truncated)?;
        let (value, rest) = after_len.split_at_checked(len).ok_or(CodecError::TooLong)?;
        self.rest = rest;
        Ok(value)
    }

    /// Next field as UTF-8 text (`Invalid` if not UTF-8).
    pub fn text(&mut self) -> Result<&'a str, CodecError> {
        let field = self.field()?;
        core::str::from_utf8(field).map_err(|_| CodecError::Invalid)
    }

    /// Next raw `u8`.
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        let (byte, rest) = self.rest.split_first().ok_or(CodecError::Truncated)?;
        self.rest = rest;
        Ok(*byte)
    }

    /// Next raw big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let chunk = self.rest.first_chunk::<4>().ok_or(CodecError::Truncated)?;
        self.rest = self.rest.get(4..).ok_or(CodecError::Truncated)?;
        Ok(u32::from_be_bytes(*chunk))
    }

    /// Require that the whole input was consumed.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(CodecError::Trailing)
        }
    }
}

/// Frame writer. **Only for non-secret output** (metadata, public values);
/// its buffer is a plain `Vec<u8>`.
#[derive(Debug)]
pub struct FrameWriter {
    buf: Vec<u8>,
}

impl FrameWriter {
    /// Start a frame (writes magic and version).
    pub fn new() -> Self {
        let mut buf = Vec::with_capacity(MAGIC.len() + 1);
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        Self { buf }
    }

    /// Append a length-prefixed field. `TooLong` if `bytes.len() > u32::MAX`.
    pub fn field(&mut self, bytes: &[u8]) -> Result<&mut Self, CodecError> {
        let len = u32::try_from(bytes.len()).map_err(|_| CodecError::TooLong)?;
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
        Ok(self)
    }

    /// Append a raw `u8`.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Append a raw big-endian `u32`.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// The encoded frame.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for FrameWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut w = FrameWriter::new();
        w.field(b"hello").unwrap();
        w.u8(7);
        w.u32(0xdead_beef);
        w.field(b"").unwrap();
        let bytes = w.finish();

        let mut r = FrameReader::new(&bytes).unwrap();
        assert_eq!(r.field().unwrap(), b"hello");
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.field().unwrap(), b"");
        r.finish().unwrap();
    }

    #[test]
    fn text_field_roundtrips() {
        let mut w = FrameWriter::new();
        w.field("héllo".as_bytes()).unwrap();
        let bytes = w.finish();
        let mut r = FrameReader::new(&bytes).unwrap();
        assert_eq!(r.text().unwrap(), "héllo");
    }

    #[test]
    fn text_invalid_utf8_is_invalid() {
        let mut w = FrameWriter::new();
        w.field(&[0xff, 0xfe]).unwrap();
        let bytes = w.finish();
        let mut r = FrameReader::new(&bytes).unwrap();
        assert_eq!(r.text().unwrap_err(), CodecError::Invalid);
    }

    #[test]
    fn new_rejects_short_bad_magic_and_bad_version() {
        assert_eq!(FrameReader::new(b"CG").unwrap_err(), CodecError::Truncated);
        assert_eq!(
            FrameReader::new(b"XXXX\x01").unwrap_err(),
            CodecError::BadMagic
        );
        assert_eq!(
            FrameReader::new(b"CGK1\x02").unwrap_err(),
            CodecError::UnsupportedVersion
        );
        assert!(FrameReader::new(b"CGK1\x01").is_ok());
    }

    #[test]
    fn field_truncated_length_prefix() {
        let mut r = FrameReader::new(b"CGK1\x01\x00\x00").unwrap();
        assert_eq!(r.field().unwrap_err(), CodecError::Truncated);
    }

    #[test]
    fn field_declared_length_exceeds_remaining() {
        let mut buf = b"CGK1\x01".to_vec();
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        let mut r = FrameReader::new(&buf).unwrap();
        assert_eq!(r.field().unwrap_err(), CodecError::TooLong);
    }

    #[test]
    fn finish_rejects_trailing_bytes() {
        let mut buf = b"CGK1\x01".to_vec();
        buf.push(0);
        let r = FrameReader::new(&buf).unwrap();
        assert_eq!(r.finish().unwrap_err(), CodecError::Trailing);
    }

    #[test]
    fn u8_and_u32_truncated() {
        let mut r = FrameReader::new(b"CGK1\x01").unwrap();
        assert_eq!(r.u8().unwrap_err(), CodecError::Truncated);

        let mut r = FrameReader::new(b"CGK1\x01\x00\x00\x00").unwrap();
        assert_eq!(r.u32().unwrap_err(), CodecError::Truncated);
    }

    /// Deterministic xorshift64 PRNG; no external dependency needed for the
    /// fuzz-style loop below.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn reader_never_panics_on_arbitrary_input() {
        let mut state: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..10_000 {
            let len = (xorshift(&mut state) % 64) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| (xorshift(&mut state) % 256) as u8)
                .collect();
            if let Ok(mut r) = FrameReader::new(&bytes) {
                let _ = r.field();
                let _ = r.u8();
                let _ = r.u32();
                let _ = r.finish();
            }
        }
    }
}
