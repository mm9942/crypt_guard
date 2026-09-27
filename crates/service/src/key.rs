//! Key references and metadata.
//!
//! The service is handle-oriented: callers name keys with a [`KeyRef`], never
//! with private key bytes.

use core::{fmt, num::NonZeroU32};

use crypt_guard_core::pq_hpke::Suite;

use crate::error::CryptoServiceError;

/// Maximum length of a [`KeyNamespace`] or [`KeyId`] in bytes.
pub const MAX_NAME_LEN: usize = 128;

fn validate_name(name: &str) -> Result<(), CryptoServiceError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.starts_with('.');
    if valid {
        Ok(())
    } else {
        Err(CryptoServiceError::Malformed)
    }
}

macro_rules! key_name {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// Non-empty, at most [`MAX_NAME_LEN`] bytes of `[A-Za-z0-9._-]`, not
        /// starting with `.`, so it is safe to embed in paths and logs.
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Box<str>);

        impl $name {
            /// Validate and wrap a name.
            pub fn new(name: &str) -> Result<Self, CryptoServiceError> {
                validate_name(name)?;
                Ok(Self(name.into()))
            }

            /// Borrow the name.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

key_name!(
    /// Tenant / application namespace of a key.
    KeyNamespace
);
key_name!(
    /// Identifier of a key within its namespace.
    KeyId
);

/// A key version, starting at 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyVersion(NonZeroU32);

impl KeyVersion {
    /// The first version of every key.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// Wrap a version number; `0` is rejected.
    pub fn new(version: u32) -> Result<Self, CryptoServiceError> {
        NonZeroU32::new(version)
            .map(Self)
            .ok_or(CryptoServiceError::Malformed)
    }

    /// The version number.
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A reference to a key held by a provider.
///
/// `version: None` means "the current primary version", which is what
/// encrypt/sign normally use.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyRef {
    /// Namespace the key lives in.
    pub namespace: KeyNamespace,
    /// Key identifier within the namespace.
    pub id: KeyId,
    /// Specific version, or `None` for the current primary version.
    pub version: Option<KeyVersion>,
}

impl KeyRef {
    /// Reference the current primary version of a key.
    pub fn latest(namespace: KeyNamespace, id: KeyId) -> Self {
        Self {
            namespace,
            id,
            version: None,
        }
    }

    /// Reference one specific version of a key.
    pub fn versioned(namespace: KeyNamespace, id: KeyId, version: KeyVersion) -> Self {
        Self {
            namespace,
            id,
            version: Some(version),
        }
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.id)?;
        match self.version {
            Some(v) => write!(f, "@{v}"),
            None => Ok(()),
        }
    }
}

/// Signature algorithms a key can be generated for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ML-DSA-44 (FIPS 204).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
}

/// What a key is used for and with which algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// PQ HPKE recipient key (encrypt/decrypt, wrap/unwrap).
    Hpke {
        /// The HPKE suite, e.g. `pq_hpke::DEFAULT_SUITE`.
        suite: Suite,
    },
    /// Signing key.
    Signature(SignatureAlgorithm),
}

/// Lifecycle state of a key version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyState {
    /// Usable for all operations.
    Enabled,
    /// Temporarily unusable; can be re-enabled.
    Disabled,
    /// Scheduled for destruction.
    PendingDestruction,
    /// Key material is gone.
    Destroyed,
}

/// Non-secret metadata about a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMetadata {
    /// The key (with a concrete version).
    pub key: KeyRef,
    /// Algorithm / purpose.
    pub algorithm: KeyAlgorithm,
    /// Lifecycle state.
    pub state: KeyState,
}
