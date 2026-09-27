//! Non-secret owned byte blobs.
//!
//! Public keys, ciphertexts and signatures are not secret, so these types are
//! `Clone`. They are distinct types so a ciphertext can never be passed where
//! a public key or signature is expected.

macro_rules! public_blob {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(Box<[u8]>);

        impl $name {
            /// Wrap owned bytes.
            pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
                Self(bytes.into())
            }

            /// Borrow the bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Return the owned bytes.
            pub fn into_inner(self) -> Box<[u8]> {
                self.0
            }

            /// Number of bytes.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Whether the blob is empty.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "({} bytes)"), self.0.len())
            }
        }
    };
}

public_blob!(
    /// An encoded public key.
    PublicBlob
);
public_blob!(
    /// A ciphertext, e.g. an encoded `CGH3` envelope or a wrapped key.
    CiphertextBlob
);
public_blob!(
    /// An encoded signature.
    SignatureBlob
);
public_blob!(
    /// A non-secret message, e.g. the input of a signature verification.
    MessageBlob
);
