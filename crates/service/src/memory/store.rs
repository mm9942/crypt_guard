//! In-memory key table and lifecycle state machine.
//!
//! Lifecycle per key version:
//!
//! ```text
//! Enabled ⇄ Disabled
//!    │         │
//!    └────┬────┘
//!         ▼
//!     Destroyed   (material dropped + zeroized immediately; terminal)
//! ```
//!
//! `PendingDestruction` is reserved for providers with delayed deletion and
//! is never entered by this store.

use std::collections::{BTreeMap, HashMap};

use crypt_guard_core::pq_hpke::{RecipientKeyPair, Suite};

use crate::{
    error::CryptoServiceError,
    key::{KeyAlgorithm, KeyId, KeyMetadata, KeyNamespace, KeyRef, KeyState, KeyVersion},
};

/// Secret key material of one key version. Never `Clone`, never printed.
pub(crate) enum KeyMaterial {
    /// PQ HPKE recipient key pair.
    Hpke {
        /// Suite the key was generated for.
        suite: Suite,
        /// The key pair (private half zeroizes on drop).
        keys: RecipientKeyPair,
    },
    /// ML-DSA signing key pair.
    #[cfg(feature = "ml-dsa")]
    MlDsa(super::sign_ops::MlDsaKeys),
}

impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redacted: print only the variant name, never any key bytes.
        let variant = match self {
            Self::Hpke { .. } => "Hpke",
            #[cfg(feature = "ml-dsa")]
            Self::MlDsa(_) => "MlDsa",
        };
        write!(f, "KeyMaterial::{variant}([REDACTED])")
    }
}

/// One version of a key.
#[derive(Debug)]
pub(crate) struct VersionEntry {
    /// This version.
    pub(crate) version: KeyVersion,
    /// Lifecycle state.
    pub(crate) state: KeyState,
    /// `None` once destroyed.
    pub(crate) material: Option<KeyMaterial>,
}

impl VersionEntry {
    /// The material, if this version may be used for cryptographic operations.
    ///
    /// Errors: `Disabled` → [`CryptoServiceError::Conflict`];
    /// `Destroyed` / no material → [`CryptoServiceError::NotFound`].
    pub(crate) fn usable(&self) -> Result<&KeyMaterial, CryptoServiceError> {
        match self.state {
            KeyState::Enabled => self.material.as_ref().ok_or(CryptoServiceError::NotFound),
            KeyState::Disabled | KeyState::PendingDestruction => Err(CryptoServiceError::Conflict),
            KeyState::Destroyed => Err(CryptoServiceError::NotFound),
        }
    }
}

/// All versions of one key.
#[derive(Debug)]
pub(crate) struct KeyEntry {
    /// Algorithm shared by all versions.
    pub(crate) algorithm: KeyAlgorithm,
    /// Current primary version (used when a `KeyRef` has no version).
    pub(crate) primary: KeyVersion,
    /// All versions, including destroyed ones (as tombstones).
    pub(crate) versions: BTreeMap<KeyVersion, VersionEntry>,
}

/// The key table.
#[derive(Debug, Default)]
pub(crate) struct KeyStore {
    keys: HashMap<(KeyNamespace, KeyId), KeyEntry>,
}

impl KeyStore {
    /// An empty store.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Create a new key with version 1 as primary.
    ///
    /// Errors: key already exists → [`CryptoServiceError::Conflict`].
    /// Returns the versioned `KeyRef` of the new version.
    pub(crate) fn insert_new(
        &mut self,
        namespace: KeyNamespace,
        id: KeyId,
        algorithm: KeyAlgorithm,
        material: KeyMaterial,
    ) -> Result<KeyRef, CryptoServiceError> {
        use std::collections::hash_map::Entry;

        let version = KeyVersion::FIRST;
        match self.keys.entry((namespace.clone(), id.clone())) {
            Entry::Occupied(_) => Err(CryptoServiceError::Conflict),
            Entry::Vacant(slot) => {
                let mut versions = BTreeMap::new();
                versions.insert(
                    version,
                    VersionEntry {
                        version,
                        state: KeyState::Enabled,
                        material: Some(material),
                    },
                );
                slot.insert(KeyEntry {
                    algorithm,
                    primary: version,
                    versions,
                });
                Ok(KeyRef::versioned(namespace, id, version))
            }
        }
    }

    /// Add a new version (highest + 1) and make it primary. `key.version` is
    /// ignored. Errors: unknown key → `NotFound`; version overflow → `Conflict`.
    /// Returns the versioned `KeyRef` of the new version.
    pub(crate) fn rotate(
        &mut self,
        key: &KeyRef,
        material: KeyMaterial,
    ) -> Result<KeyRef, CryptoServiceError> {
        let entry = self
            .keys
            .get_mut(&(key.namespace.clone(), key.id.clone()))
            .ok_or(CryptoServiceError::NotFound)?;

        let highest = entry
            .versions
            .keys()
            .next_back()
            .copied()
            .unwrap_or(KeyVersion::FIRST);
        let new_version = highest
            .get()
            .checked_add(1)
            .and_then(|v| KeyVersion::new(v).ok())
            .ok_or(CryptoServiceError::Conflict)?;

        entry.versions.insert(
            new_version,
            VersionEntry {
                version: new_version,
                state: KeyState::Enabled,
                material: Some(material),
            },
        );
        entry.primary = new_version;

        Ok(KeyRef::versioned(
            key.namespace.clone(),
            key.id.clone(),
            new_version,
        ))
    }

    /// Algorithm of a key (any version). Errors: unknown key → `NotFound`.
    pub(crate) fn algorithm_of(&self, key: &KeyRef) -> Result<KeyAlgorithm, CryptoServiceError> {
        self.keys
            .get(&(key.namespace.clone(), key.id.clone()))
            .map(|entry| entry.algorithm)
            .ok_or(CryptoServiceError::NotFound)
    }

    /// Move a version (primary when `key.version` is `None`) between
    /// `Enabled` and `Disabled`. Any other target state or a destroyed
    /// version → `Conflict`; unknown key/version → `NotFound`.
    pub(crate) fn set_state(
        &mut self,
        key: &KeyRef,
        state: KeyState,
    ) -> Result<KeyMetadata, CryptoServiceError> {
        if !matches!(state, KeyState::Enabled | KeyState::Disabled) {
            return Err(CryptoServiceError::Conflict);
        }

        let entry = self
            .keys
            .get_mut(&(key.namespace.clone(), key.id.clone()))
            .ok_or(CryptoServiceError::NotFound)?;
        let version = key.version.unwrap_or(entry.primary);
        let algorithm = entry.algorithm;
        let version_entry = entry
            .versions
            .get_mut(&version)
            .ok_or(CryptoServiceError::NotFound)?;

        if matches!(version_entry.state, KeyState::Destroyed) {
            return Err(CryptoServiceError::Conflict);
        }

        version_entry.state = state;

        Ok(KeyMetadata {
            key: KeyRef::versioned(key.namespace.clone(), key.id.clone(), version),
            algorithm,
            state: version_entry.state,
        })
    }

    /// Destroy one explicit version: drop its material (zeroizing it) right
    /// now and leave a `Destroyed` tombstone. `key.version == None` →
    /// `Malformed` (destruction must name a version); unknown → `NotFound`;
    /// already destroyed → `Conflict`.
    pub(crate) fn destroy(&mut self, key: &KeyRef) -> Result<KeyMetadata, CryptoServiceError> {
        let version = key.version.ok_or(CryptoServiceError::Malformed)?;

        let entry = self
            .keys
            .get_mut(&(key.namespace.clone(), key.id.clone()))
            .ok_or(CryptoServiceError::NotFound)?;
        let algorithm = entry.algorithm;
        let version_entry = entry
            .versions
            .get_mut(&version)
            .ok_or(CryptoServiceError::NotFound)?;

        if matches!(version_entry.state, KeyState::Destroyed) {
            return Err(CryptoServiceError::Conflict);
        }

        // Drop the material immediately; the core types zeroize on drop.
        // Note: if `version` is the current primary, the primary pointer is
        // left as-is (a destroyed primary makes encrypt/etc. fail with
        // `NotFound` via `VersionEntry::usable`), rather than silently
        // repointing to a different version.
        version_entry.material = None;
        version_entry.state = KeyState::Destroyed;

        Ok(KeyMetadata {
            key: KeyRef::versioned(key.namespace.clone(), key.id.clone(), version),
            algorithm,
            state: KeyState::Destroyed,
        })
    }

    /// Resolve a `KeyRef` (primary when unversioned) to its version entry,
    /// whatever its state. Errors: unknown key/version → `NotFound`.
    pub(crate) fn resolve(&self, key: &KeyRef) -> Result<&VersionEntry, CryptoServiceError> {
        let entry = self
            .keys
            .get(&(key.namespace.clone(), key.id.clone()))
            .ok_or(CryptoServiceError::NotFound)?;
        let version = key.version.unwrap_or(entry.primary);
        entry
            .versions
            .get(&version)
            .ok_or(CryptoServiceError::NotFound)
    }

    /// Resolve an explicit version. Errors: unknown → `NotFound`.
    pub(crate) fn resolve_version(
        &self,
        namespace: &KeyNamespace,
        id: &KeyId,
        version: KeyVersion,
    ) -> Result<&VersionEntry, CryptoServiceError> {
        self.keys
            .get(&(namespace.clone(), id.clone()))
            .and_then(|entry| entry.versions.get(&version))
            .ok_or(CryptoServiceError::NotFound)
    }

    /// Metadata of a version (primary when unversioned), with a versioned
    /// `KeyRef`. Errors: unknown → `NotFound`.
    pub(crate) fn metadata(&self, key: &KeyRef) -> Result<KeyMetadata, CryptoServiceError> {
        let entry = self
            .keys
            .get(&(key.namespace.clone(), key.id.clone()))
            .ok_or(CryptoServiceError::NotFound)?;
        let version = key.version.unwrap_or(entry.primary);
        let version_entry = entry
            .versions
            .get(&version)
            .ok_or(CryptoServiceError::NotFound)?;

        Ok(KeyMetadata {
            key: KeyRef::versioned(key.namespace.clone(), key.id.clone(), version),
            algorithm: entry.algorithm,
            state: version_entry.state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypt_guard_core::pq_hpke::{generate_recipient_key_pair, DEFAULT_SUITE};

    fn material() -> KeyMaterial {
        KeyMaterial::Hpke {
            suite: DEFAULT_SUITE,
            keys: generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap(),
        }
    }

    fn algorithm() -> KeyAlgorithm {
        KeyAlgorithm::Hpke {
            suite: DEFAULT_SUITE,
        }
    }

    fn ns(s: &str) -> KeyNamespace {
        KeyNamespace::new(s).unwrap()
    }

    fn id(s: &str) -> KeyId {
        KeyId::new(s).unwrap()
    }

    #[test]
    fn insert_new_creates_enabled_primary_v1() {
        let mut store = KeyStore::new();
        let key_ref = store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        assert_eq!(key_ref.version, Some(KeyVersion::FIRST));

        let meta = store.metadata(&KeyRef::latest(ns("t"), id("k"))).unwrap();
        assert_eq!(meta.state, KeyState::Enabled);
        assert_eq!(meta.key.version, Some(KeyVersion::FIRST));
    }

    #[test]
    fn insert_new_conflict_on_existing() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let err = store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::Conflict);
    }

    #[test]
    fn rotate_unknown_key_not_found() {
        let mut store = KeyStore::new();
        let err = store
            .rotate(&KeyRef::latest(ns("t"), id("k")), material())
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::NotFound);
    }

    #[test]
    fn rotate_bumps_version_and_primary() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let rotated = store
            .rotate(&KeyRef::latest(ns("t"), id("k")), material())
            .unwrap();
        assert_eq!(rotated.version, Some(KeyVersion::new(2).unwrap()));

        let meta = store.metadata(&KeyRef::latest(ns("t"), id("k"))).unwrap();
        assert_eq!(meta.key.version, Some(KeyVersion::new(2).unwrap()));

        // The old version keeps its (Enabled) state and is still resolvable.
        let old = store
            .metadata(&KeyRef::versioned(ns("t"), id("k"), KeyVersion::FIRST))
            .unwrap();
        assert_eq!(old.state, KeyState::Enabled);
    }

    #[test]
    fn algorithm_of_unknown_not_found() {
        let store = KeyStore::new();
        let err = store
            .algorithm_of(&KeyRef::latest(ns("t"), id("k")))
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::NotFound);
    }

    #[test]
    fn set_state_disable_then_enable_roundtrip() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let key = KeyRef::latest(ns("t"), id("k"));

        let meta = store.set_state(&key, KeyState::Disabled).unwrap();
        assert_eq!(meta.state, KeyState::Disabled);
        assert_eq!(
            store.resolve(&key).unwrap().usable().unwrap_err(),
            CryptoServiceError::Conflict
        );

        let meta = store.set_state(&key, KeyState::Enabled).unwrap();
        assert_eq!(meta.state, KeyState::Enabled);
        assert!(store.resolve(&key).unwrap().usable().is_ok());
    }

    #[test]
    fn set_state_rejects_non_enabled_disabled_targets() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let key = KeyRef::latest(ns("t"), id("k"));

        let err = store
            .set_state(&key, KeyState::PendingDestruction)
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::Conflict);
    }

    #[test]
    fn set_state_on_destroyed_version_is_conflict() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let key = KeyRef::versioned(ns("t"), id("k"), KeyVersion::FIRST);
        store.destroy(&key).unwrap();

        let err = store.set_state(&key, KeyState::Enabled).unwrap_err();
        assert_eq!(err, CryptoServiceError::Conflict);
    }

    #[test]
    fn destroy_requires_explicit_version() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let err = store
            .destroy(&KeyRef::latest(ns("t"), id("k")))
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::Malformed);
    }

    #[test]
    fn destroy_unknown_not_found() {
        let mut store = KeyStore::new();
        let err = store
            .destroy(&KeyRef::versioned(ns("t"), id("k"), KeyVersion::FIRST))
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::NotFound);
    }

    #[test]
    fn destroy_drops_material_and_is_terminal() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let key = KeyRef::versioned(ns("t"), id("k"), KeyVersion::FIRST);

        let meta = store.destroy(&key).unwrap();
        assert_eq!(meta.state, KeyState::Destroyed);

        let entry = store.resolve(&key).unwrap();
        assert!(entry.material.is_none());
        assert_eq!(entry.usable().unwrap_err(), CryptoServiceError::NotFound);

        // Destroying again is a conflict.
        let err = store.destroy(&key).unwrap_err();
        assert_eq!(err, CryptoServiceError::Conflict);
    }

    #[test]
    fn destroyed_primary_makes_latest_unusable() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let versioned = KeyRef::versioned(ns("t"), id("k"), KeyVersion::FIRST);
        store.destroy(&versioned).unwrap();

        // Primary still points at v1, which is destroyed: usable() fails,
        // but resolve()/metadata() on the (unversioned) primary still work.
        let latest = KeyRef::latest(ns("t"), id("k"));
        let entry = store.resolve(&latest).unwrap();
        assert_eq!(entry.usable().unwrap_err(), CryptoServiceError::NotFound);

        let meta = store.metadata(&latest).unwrap();
        assert_eq!(meta.state, KeyState::Destroyed);
        assert_eq!(meta.key.version, Some(KeyVersion::FIRST));
    }

    #[test]
    fn resolve_version_unknown_not_found() {
        let mut store = KeyStore::new();
        store
            .insert_new(ns("t"), id("k"), algorithm(), material())
            .unwrap();
        let err = store
            .resolve_version(&ns("t"), &id("k"), KeyVersion::new(7).unwrap())
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::NotFound);
    }

    #[test]
    fn metadata_unknown_not_found() {
        let store = KeyStore::new();
        let err = store
            .metadata(&KeyRef::latest(ns("t"), id("k")))
            .unwrap_err();
        assert_eq!(err, CryptoServiceError::NotFound);
    }

    #[test]
    fn debug_of_key_material_is_redacted() {
        let debug = format!("{:?}", material());
        assert_eq!(debug, "KeyMaterial::Hpke([REDACTED])");
    }
}
