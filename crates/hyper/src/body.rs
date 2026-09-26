//! Zeroization-aware request body collection.
//!
//! `http_body_util::BodyExt::collect().to_bytes()` concatenates chunks into a
//! fresh, non-zeroizing buffer, leaving an extra copy of a plaintext body in
//! freed memory. [`collect_secret`] instead keeps the received chunks as they
//! are (no copy) and makes exactly one copy into an exactly sized, zeroizing
//! [`SecretBytes`].
//!
//! Limitation: the chunk buffers themselves are owned by Hyper and the OS and
//! are outside this crate's control; they are not zeroized.

use core::fmt;

use bytes::Bytes;
use http_body::Body;

use crypt_guard_service::SecretBytes;

/// A fully received request body, held as zeroizing secret bytes.
/// Not `Clone`; `Debug` shows only the length.
pub struct SecretBody {
    inner: SecretBytes,
}

impl SecretBody {
    /// Wrap already collected secret bytes.
    pub fn new(inner: SecretBytes) -> Self {
        Self { inner }
    }

    /// Body length in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Borrow the body bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl fmt::Debug for SecretBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBody([REDACTED; {}])", self.len())
    }
}

/// Why a body could not be collected.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// The body exceeded the limit (checked before any copy is made).
    TooLarge,
    /// The transport reported an error while streaming the body.
    Invalid,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "request body too large",
            Self::Invalid => "invalid request body",
        })
    }
}

impl fmt::Debug for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BodyError({self})")
    }
}

impl std::error::Error for BodyError {}

/// Collect `body` into a [`SecretBody`], rejecting it as soon as the
/// accumulated length exceeds `limit`.
///
/// Implementation contract (WAVE1(body)):
/// - poll frames with `http_body_util::BodyExt::frame`; keep data chunks in a
///   `Vec<Bytes>` (cloning `Bytes` handles is fine, they are refcounted views);
///   ignore trailers;
/// - track the total with `checked_add`; overflow or `> limit` → `TooLarge`
///   immediately (drop the chunks, do not keep reading);
/// - any body error → `Invalid`;
/// - finally `SecretBytes::concat(&chunks)` (one exact copy) →
///   `SecretBody::new`. Never build an intermediate `Vec<u8>`/`BytesMut`.
pub async fn collect_secret<B>(body: B, limit: usize) -> Result<SecretBody, BodyError>
where
    B: Body<Data = Bytes>,
{
    use http_body_util::BodyExt;

    let mut body = core::pin::pin!(body);
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut total = 0usize;

    while let Some(frame) = body.as_mut().frame().await {
        let frame = frame.map_err(|_| BodyError::Invalid)?;
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(_trailers) => continue,
        };
        total = total
            .checked_add(data.len())
            .filter(|&total| total <= limit)
            .ok_or(BodyError::TooLarge)?;
        chunks.push(data);
    }

    let secret = SecretBytes::concat(&chunks).ok_or(BodyError::TooLarge)?;
    Ok(SecretBody::new(secret))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use http_body::{Frame, SizeHint};

    use super::*;

    /// A minimal test body that yields a fixed queue of pre-built frames (or
    /// errors), one per `poll_frame` call, without ever pending.
    struct TestBody {
        frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
    }

    impl TestBody {
        fn new(chunks: Vec<&'static [u8]>) -> Self {
            Self {
                frames: chunks
                    .into_iter()
                    .map(|chunk| Ok(Frame::data(Bytes::from_static(chunk))))
                    .collect(),
            }
        }

        fn with_trailer(mut self) -> Self {
            self.frames
                .push_back(Ok(Frame::trailers(http::HeaderMap::new())));
            self
        }

        fn erroring() -> Self {
            let mut frames = VecDeque::new();
            frames.push_back(Err(io::Error::other("boom")));
            Self { frames }
        }
    }

    impl Body for TestBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.frames.pop_front())
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    #[tokio::test]
    async fn multi_chunk_concat_equals_input() {
        let body = TestBody::new(vec![b"hello, ", b"world", b"!"]);
        let collected = collect_secret(body, 1024).await.expect("collects");
        assert_eq!(collected.as_slice(), b"hello, world!");
    }

    #[tokio::test]
    async fn exactly_at_limit_ok() {
        let body = TestBody::new(vec![b"12345"]);
        let collected = collect_secret(body, 5).await.expect("fits exactly");
        assert_eq!(collected.len(), 5);
    }

    #[tokio::test]
    async fn one_over_limit_is_too_large() {
        let body = TestBody::new(vec![b"123456"]);
        let err = collect_secret(body, 5).await.expect_err("exceeds limit");
        assert_eq!(err, BodyError::TooLarge);
    }

    #[tokio::test]
    async fn over_limit_across_chunks_is_too_large() {
        let body = TestBody::new(vec![b"123", b"456"]);
        let err = collect_secret(body, 5).await.expect_err("exceeds limit");
        assert_eq!(err, BodyError::TooLarge);
    }

    #[tokio::test]
    async fn erroring_body_is_invalid() {
        let body = TestBody::erroring();
        let err = collect_secret(body, 1024).await.expect_err("body errors");
        assert_eq!(err, BodyError::Invalid);
    }

    #[tokio::test]
    async fn empty_body_is_empty_secret_body() {
        let body = TestBody::new(vec![]);
        let collected = collect_secret(body, 1024).await.expect("collects");
        assert!(collected.is_empty());
    }

    #[tokio::test]
    async fn trailers_are_ignored() {
        let body = TestBody::new(vec![b"data"]).with_trailer();
        let collected = collect_secret(body, 1024).await.expect("collects");
        assert_eq!(collected.as_slice(), b"data");
    }

    #[test]
    fn debug_is_redacted() {
        let secret = SecretBytes::copy_from_slice(b"top secret");
        let body = SecretBody::new(secret);
        let rendered = format!("{body:?}");
        assert_eq!(rendered, "SecretBody([REDACTED; 10])");
        assert!(!rendered.contains("top secret"));
    }
}
