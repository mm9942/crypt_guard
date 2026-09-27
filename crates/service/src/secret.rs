//! Secret byte ownership.
//!
//! [`SecretBytes`] is the only container the service layer uses for secret
//! input and output (plaintext, key material to wrap, unwrapped keys). It is
//! deliberately **not** `Clone`: a secret moves through the service, it is
//! never duplicated implicitly. `zeroize::Zeroizing<Vec<u8>>` is not used as
//! the public type because `Zeroizing<Z>` is `Clone` whenever `Z` is.
//!
//! Storage is a `Box<[u8]>`, which never reallocates, so zeroizing on drop
//! erases the only user-space copy the service owns.

use core::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Owned, zeroize-on-drop, non-`Clone` secret bytes.
pub struct SecretBytes {
    inner: Zeroizing<Box<[u8]>>,
}

impl SecretBytes {
    /// Copy secret bytes from a borrowed slice.
    ///
    /// This is the explicit secret-ingress boundary: it allocates exactly
    /// once. Prefer it over `.to_owned()` so that secret copies stay visible
    /// in review.
    pub fn copy_from_slice(secret: &[u8]) -> Self {
        Self {
            inner: Zeroizing::new(Box::from(secret)),
        }
    }

    /// Take ownership of an already boxed secret without copying.
    pub fn from_boxed(secret: Box<[u8]>) -> Self {
        Self {
            inner: Zeroizing::new(secret),
        }
    }

    /// Take ownership of a `Vec<u8>`.
    ///
    /// If the vector has spare capacity, `into_boxed_slice` would reallocate
    /// and leave the secret behind, unzeroized, in the old allocation. So in
    /// that case the bytes are copied into an exact allocation and the whole
    /// source allocation (including spare capacity) is zeroized before it is
    /// freed. Memory left behind by *earlier* reallocations of the vector
    /// cannot be erased; build secret vectors with their final capacity.
    pub fn from_vec(mut secret: Vec<u8>) -> Self {
        if secret.capacity() == secret.len() {
            // Exact fit: converting moves the allocation without copying.
            return Self::from_boxed(secret.into_boxed_slice());
        }
        let exact = Self::copy_from_slice(&secret);
        // `Vec<u8>::zeroize` clears the initialized bytes and the spare
        // capacity of the allocation.
        secret.zeroize();
        exact
    }

    /// Concatenate chunks into one exactly sized secret, copying each byte
    /// exactly once and never reallocating. Returns `None` if the total
    /// length overflows `usize`.
    ///
    /// This is the ingress path for chunked network bodies: the chunks stay
    /// where they are and only one zeroizing copy is made.
    pub fn concat<C: AsRef<[u8]>>(chunks: &[C]) -> Option<Self> {
        let total = chunks
            .iter()
            .try_fold(0usize, |acc, chunk| acc.checked_add(chunk.as_ref().len()))?;
        let mut inner = Zeroizing::new(vec![0u8; total].into_boxed_slice());
        let mut offset = 0;
        for chunk in chunks {
            let chunk = chunk.as_ref();
            let end = offset + chunk.len();
            inner[offset..end].copy_from_slice(chunk);
            offset = end;
        }
        Some(Self { inner })
    }

    /// Number of secret bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Consume the secret for a one-way transfer out of the service layer,
    /// for example into an owner-backed network buffer.
    pub fn into_egress(self) -> SecretEgress {
        SecretEgress { inner: self.inner }
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {}])", self.len())
    }
}

/// A secret leaving the service layer.
///
/// It is still non-`Clone` and zeroizes on drop. It implements
/// `AsRef<[u8]> + Send + 'static`, which is exactly what an owner-backed
/// network buffer (e.g. `bytes::Bytes::from_owner`) needs: every network
/// clone then shares this single owner, and the plaintext is erased when the
/// last clone is dropped. Never convert it back into a crypto-side buffer.
pub struct SecretEgress {
    inner: Zeroizing<Box<[u8]>>,
}

impl AsRef<[u8]> for SecretEgress {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl fmt::Debug for SecretEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretEgress([REDACTED; {}])", self.inner.len())
    }
}
