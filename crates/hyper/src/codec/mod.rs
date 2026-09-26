//! Wire codec of the reference KMS HTTP surface.
//!
//! Request and response bodies that carry more than one value use the
//! length-prefixed `CGK1` frame ([`frame`]); single opaque values (public
//! keys, ciphertexts, signatures, plaintext) travel as raw
//! `application/octet-stream`. See [`request`] for the per-operation field
//! layout.

pub mod frame;
pub mod profile;
pub mod request;
pub mod response;

pub use frame::{CodecError, FrameReader, FrameWriter, CONTENT_TYPE};
pub use request::decode_request;
pub use response::encode_response;
