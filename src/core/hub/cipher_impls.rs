//! Per-cipher `SymmetricCipher` implementations plus the single generic wiring of
//! `EncryptFunctions` / `DecryptFunctions` for the FIPS path.
//!
//! # Responsibility scope
//! This module owns the [`SymmetricCipher`] trait abstraction and one implementation per
//! symmetric cipher marker. The ML-KEM encapsulation, HKDF key schedule, nonce generation,
//! and authenticated `Envelope` assembly live in **one** generic impl each of the
//! encrypt/decrypt capability traits — no per-cipher copy-paste.
//!
//! # Trait design
//! Each cipher marker (`XChaCha20Poly1305`, `AesGcmSiv`, `AES` (CBC), `AesCtr`, `XChaCha20`,
//! `AesXts`) implements `SymmetricCipher` exactly once. A cipher fully owns its own key
//! schedule (deriving session/MAC keys from the raw KEM shared secret), its AAD construction,
//! and — for non-AEAD modes — its HMAC tag. The generic encrypt impls only do the
//! KEM + nonce + envelope orchestration that is identical for every cipher:
//!
//! **Encrypt path** (generic):
//! 1. ML-KEM encapsulate → `(kem_ciphertext, shared_secret)`
//! 2. Build the `Header` from the size marker + `C::AEAD_ID`
//! 3. Generate a `C::NONCE_LEN`-byte nonce (empty when the cipher embeds its IV in the ciphertext)
//! 4. `C::seal(shared_secret, header, kem_ct, nonce, plaintext)` → ciphertext bytes
//! 5. Assemble `Envelope { header, kem_ciphertext, nonce, ciphertext }`; zeroize the shared secret
//!
//! **Decrypt path** (generic):
//! 1. ML-KEM decapsulate using `secret_key` + `envelope.kem_ciphertext` → `shared_secret`
//! 2. `C::open(shared_secret, header, kem_ct, nonce, ciphertext)` → plaintext; zeroize the shared secret
//!
//! Adding a new cipher is now a single `impl SymmetricCipher` — no new `EncryptFunctions`
//! or `DecryptFunctions` block.
//!
//! # AEAD vs non-AEAD handling
//! - **AEAD ciphers** (`AesGcmSiv`, `XChaCha20Poly1305`): the built-in tag authenticates
//!   `build_aad(header, kem_ct, nonce, b"")` as associated data. No extra HMAC.
//! - **Non-AEAD ciphers** (AES-CBC, AES-CTR, `XChaCha20`, AES-XTS): an HMAC-SHA256 over
//!   `aad || ciphertext` (keyed by an independently HKDF-derived MAC key) is appended on seal
//!   and verified-then-stripped on open. `AuthenticationFailed` is returned on mismatch.
//!
//! # AES-XTS deviation
//! AES-XTS needs a 64-byte key (two AES-256 keys). Two HKDF derivations with distinct labels
//! (`LABEL_AES_XTS_K1`, `LABEL_AES_XTS_K2`) produce K1/K2 from the single shared secret; one
//! encapsulation only. The original plaintext length is stored as an 8-byte LE prefix so the
//! sector padding can be trimmed on decrypt.
//!
//! # Concurrency
//! Shared secrets are zeroized after use; session keys are `ZeroizeOnDrop`. No global state.
//!
//! # Errors
//! See the individual trait methods; common errors: `CryptError::EncapsulationError` /
//! `CryptError::DecapsulationError`, `CryptError::AuthenticationFailed`,
//! `CryptError::EncryptionFailed` / `CryptError::DecryptionFailed`, `CryptError::InvalidNonce`.

#[cfg(feature = "ml-kem-backend")]
mod inner {

    use crate::core::hub::{
        DecryptData, DecryptFile, DecryptText, EncryptData, EncryptFile, EncryptText, Kyber,
        KyberSizeVariant, KyberVariant,
    };
    use crate::error::CryptError;
    use crate::kdf::{
        derive_session_key,
        types::{HkdfSalt, SessionKey},
        LABEL_AESGCMSIV, LABEL_XCHACHA20, LABEL_XCHACHA20POLY1305,
    };
    use crate::markers::{AesGcmSiv, Decryption, Encryption, XChaCha20, XChaCha20Poly1305};
    use crate::markers::{Data, Files, Message};
    use crate::protocol::{
        aad::build_aad,
        header::{AeadAlgId, Header, KdfAlgId, KemAlgId},
        Envelope,
    };
    // Cipher markers and KDF labels used only by the optional legacy/extra AES modes.
    #[cfg(feature = "legacy-aes")]
    use crate::kdf::LABEL_AES;
    #[cfg(feature = "aes-ctr")]
    use crate::kdf::LABEL_GENERIC;
    #[cfg(feature = "aes-ctr")]
    use crate::markers::AesCtr;
    #[cfg(feature = "aes-xts")]
    use crate::markers::AesXts;
    #[cfg(feature = "legacy-aes")]
    use crate::markers::AES;

    use std::path::PathBuf;
    use zeroize::Zeroize;

    // ══════════════════════════════════════════════════════════════════════════════
    // SymmetricCipher — the per-cipher abstraction
    // ══════════════════════════════════════════════════════════════════════════════

    /// A symmetric cipher backend for the CGv2 envelope path.
    ///
    /// # Description
    /// Each cipher marker implements this trait exactly once. The implementation owns its full
    /// key schedule (deriving any session and MAC keys it needs from the raw KEM `shared_secret`
    /// plus the `kem_ct` salt), its AAD construction, and — for non-AEAD modes — its HMAC tag.
    /// The generic `EncryptFunctions` / `DecryptFunctions` impls below handle everything that is
    /// identical across ciphers (KEM, header, nonce generation, envelope assembly).
    ///
    /// # Concurrency
    /// All methods are pure associated functions with no shared state; safe to call from any thread.
    pub trait SymmetricCipher {
        /// AEAD/cipher identifier written into the envelope header.
        const AEAD_ID: AeadAlgId;
        /// Number of random nonce bytes the generic encrypt path must generate, or `0` for
        /// ciphers that embed their IV inside the ciphertext (AES-CBC, AES-XTS).
        const NONCE_LEN: usize;

        /// Seal `plaintext` into cipher output bytes (tag/MAC included as the cipher requires).
        ///
        /// # Arguments
        /// - `shared_secret` (`&[u8]`): raw ML-KEM shared secret; the impl derives its own keys.
        /// - `header` (`&Header`): the envelope header, authenticated as part of the AAD.
        /// - `kem_ct` (`&[u8]`): KEM ciphertext, used as HKDF salt and bound into the AAD.
        /// - `nonce` (`&[u8]`): `NONCE_LEN` random bytes (empty when `NONCE_LEN == 0`).
        /// - `plaintext` (`&[u8]`): the data to encrypt.
        ///
        /// # Returns
        /// `Ok(Vec<u8>)` — the ciphertext bytes to place in `Envelope::ciphertext`.
        ///
        /// # Errors
        /// [`CryptError::EncryptionFailed`] on cipher failure.
        fn seal(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptError>;

        /// Open and authenticate `ciphertext`, returning the plaintext.
        ///
        /// # Arguments
        /// - `shared_secret` (`&[u8]`): raw ML-KEM shared secret.
        /// - `header` (`&Header`): the envelope header.
        /// - `kem_ct` (`&[u8]`): KEM ciphertext (HKDF salt + AAD binding).
        /// - `nonce` (`&[u8]`): the nonce stored in the envelope (empty for IV-embedding ciphers).
        /// - `ciphertext` (`&[u8]`): the sealed bytes from `Envelope::ciphertext`.
        ///
        /// # Returns
        /// `Ok(Vec<u8>)` — the recovered plaintext.
        ///
        /// # Errors
        /// [`CryptError::AuthenticationFailed`] on tag/HMAC mismatch, [`CryptError::InvalidNonce`]
        /// on wrong nonce length, [`CryptError::DecryptionFailed`] on cipher failure.
        fn open(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptError>;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // Generic EncryptFunctions / DecryptFunctions — wired ONCE over any SymmetricCipher
    // ══════════════════════════════════════════════════════════════════════════════

    /// Shared encrypt worker: KEM-encapsulate, generate the nonce, run `C::seal`, assemble the
    /// envelope. Called by all three encrypt capability traits so the orchestration lives once.
    fn seal_envelope<K: KyberSizeVariant, C: SymmetricCipher>(
        pk: &[u8],
        data: &[u8],
    ) -> Result<Envelope, CryptError> {
        let (kem_ct, mut shared_secret) = mlkem_encapsulate(K::variant(), pk)?;
        let hdr = Header::new(
            kem_alg_from_variant(K::variant()),
            C::AEAD_ID,
            KdfAlgId::HkdfSha256,
        );
        let nonce = gen_nonce(C::NONCE_LEN);
        let sealed = C::seal(&shared_secret, &hdr, &kem_ct, &nonce, data);
        shared_secret.zeroize();
        Ok(Envelope::new(hdr, kem_ct, nonce, sealed?))
    }

    /// Shared decrypt worker: KEM-decapsulate and run `C::open`. Called by all three decrypt
    /// capability traits.
    fn open_envelope<K: KyberSizeVariant, C: SymmetricCipher>(
        sk: &[u8],
        envelope: &Envelope,
    ) -> Result<Vec<u8>, CryptError> {
        let mut shared_secret = mlkem_decapsulate(K::variant(), sk, &envelope.kem_ciphertext)?;
        let opened = C::open(
            &shared_secret,
            &envelope.header,
            &envelope.kem_ciphertext,
            &envelope.nonce,
            &envelope.ciphertext,
        );
        shared_secret.zeroize();
        opened
    }

    // ── Encrypt capability impls — each gated on its ContentStatus marker ─────────

    impl<K: KyberSizeVariant, C: SymmetricCipher> EncryptData for Kyber<Encryption, K, Data, C> {
        fn encrypt_data(&mut self, data: &[u8], _passphrase: &str) -> Result<Envelope, CryptError> {
            seal_envelope::<K, C>(&self.kyber_data.key()?, data)
        }
    }

    impl<K: KyberSizeVariant, C: SymmetricCipher> EncryptText for Kyber<Encryption, K, Message, C> {
        fn encrypt_msg(
            &mut self,
            message: &str,
            _passphrase: &str,
        ) -> Result<Envelope, CryptError> {
            seal_envelope::<K, C>(&self.kyber_data.key()?, message.as_bytes())
        }
    }

    impl<K: KyberSizeVariant, C: SymmetricCipher> EncryptFile for Kyber<Encryption, K, Files, C> {
        fn encrypt_file(
            &mut self,
            path: PathBuf,
            _passphrase: &str,
        ) -> Result<Envelope, CryptError> {
            let data = read_file(&path)?;
            seal_envelope::<K, C>(&self.kyber_data.key()?, &data)
        }
    }

    // ── Decrypt capability impls — each gated on its ContentStatus marker ─────────

    impl<K: KyberSizeVariant, C: SymmetricCipher> DecryptData for Kyber<Decryption, K, Data, C> {
        fn decrypt_data(
            &self,
            _data: &[u8],
            _passphrase: &str,
            envelope: &Envelope,
        ) -> Result<Vec<u8>, CryptError> {
            open_envelope::<K, C>(&self.kyber_data.key()?, envelope)
        }
    }

    impl<K: KyberSizeVariant, C: SymmetricCipher> DecryptText for Kyber<Decryption, K, Message, C> {
        fn decrypt_msg(
            &self,
            _message: &[u8],
            _passphrase: &str,
            envelope: &Envelope,
        ) -> Result<Vec<u8>, CryptError> {
            open_envelope::<K, C>(&self.kyber_data.key()?, envelope)
        }
    }

    impl<K: KyberSizeVariant, C: SymmetricCipher> DecryptFile for Kyber<Decryption, K, Files, C> {
        fn decrypt_file(
            &self,
            path: PathBuf,
            _passphrase: &str,
            envelope: &Envelope,
        ) -> Result<Vec<u8>, CryptError> {
            // The ciphertext lives in the envelope; reading the file preserves FileNotFound semantics.
            let _ = read_file(&path)?;
            open_envelope::<K, C>(&self.kyber_data.key()?, envelope)
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // KEM dispatch helpers
    // ══════════════════════════════════════════════════════════════════════════════

    /// Encapsulate using the ML-KEM parameter set selected by the `KyberSize` marker.
    ///
    /// Returns `(kem_ciphertext_bytes, shared_secret_bytes)`. The caller must zeroize the
    /// shared secret after deriving keys from it.
    fn mlkem_encapsulate(
        variant: KyberVariant,
        pk_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        use crate::kem::ml_kem::{MlKem1024Impl, MlKem512Impl, MlKem768Impl};
        use crate::kem::ml_kem::{Size1024, Size512, Size768};
        use crate::kem::types::MlKemPublicKey;
        use crate::kem::{backend::OsRng, KemBackend};

        let mut rng = OsRng;
        match variant {
            KyberVariant::Kyber512 => {
                let pk = MlKemPublicKey::<Size512>::from_bytes(pk_bytes.to_vec());
                let (ct, ss) = MlKem512Impl::encapsulate(&pk, &mut rng)?;
                Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
            }
            KyberVariant::Kyber768 => {
                let pk = MlKemPublicKey::<Size768>::from_bytes(pk_bytes.to_vec());
                let (ct, ss) = MlKem768Impl::encapsulate(&pk, &mut rng)?;
                Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
            }
            KyberVariant::Kyber1024 => {
                let pk = MlKemPublicKey::<Size1024>::from_bytes(pk_bytes.to_vec());
                let (ct, ss) = MlKem1024Impl::encapsulate(&pk, &mut rng)?;
                Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
            }
        }
    }

    /// Decapsulate using the ML-KEM parameter set selected by the `KyberSize` marker.
    fn mlkem_decapsulate(
        variant: KyberVariant,
        sk_bytes: &[u8],
        ct_bytes: &[u8],
    ) -> Result<Vec<u8>, CryptError> {
        use crate::kem::ml_kem::{MlKem1024Impl, MlKem512Impl, MlKem768Impl};
        use crate::kem::ml_kem::{Size1024, Size512, Size768};
        use crate::kem::types::{KemCiphertext, MlKemSecretKey};
        use crate::kem::KemBackend;

        match variant {
            KyberVariant::Kyber512 => {
                let sk = MlKemSecretKey::<Size512>::from_bytes(sk_bytes.to_vec());
                let ct = KemCiphertext::from_bytes(ct_bytes.to_vec());
                Ok(MlKem512Impl::decapsulate(&sk, &ct)?.as_ref().to_vec())
            }
            KyberVariant::Kyber768 => {
                let sk = MlKemSecretKey::<Size768>::from_bytes(sk_bytes.to_vec());
                let ct = KemCiphertext::from_bytes(ct_bytes.to_vec());
                Ok(MlKem768Impl::decapsulate(&sk, &ct)?.as_ref().to_vec())
            }
            KyberVariant::Kyber1024 => {
                let sk = MlKemSecretKey::<Size1024>::from_bytes(sk_bytes.to_vec());
                let ct = KemCiphertext::from_bytes(ct_bytes.to_vec());
                Ok(MlKem1024Impl::decapsulate(&sk, &ct)?.as_ref().to_vec())
            }
        }
    }

    /// Map a runtime KEM size variant to the header algorithm id.
    fn kem_alg_from_variant(v: KyberVariant) -> KemAlgId {
        match v {
            KyberVariant::Kyber512 => KemAlgId::MlKem512,
            KyberVariant::Kyber768 => KemAlgId::MlKem768,
            KyberVariant::Kyber1024 => KemAlgId::MlKem1024,
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // Shared key-schedule / MAC / nonce helpers
    // ══════════════════════════════════════════════════════════════════════════════

    /// Derive a 32-byte session key, binding it to this KEM ciphertext via the HKDF salt.
    fn derive_key(
        shared_secret: &[u8],
        kem_ct: &[u8],
        label: &[u8],
    ) -> Result<SessionKey, CryptError> {
        derive_session_key(shared_secret, &HkdfSalt::from_bytes(kem_ct.to_vec()), label)
    }

    /// Derive an independent 32-byte MAC key (distinct label) for non-AEAD modes.
    fn derive_mac_key(ikm: &[u8], kem_ct: &[u8]) -> Result<SessionKey, CryptError> {
        derive_session_key(
            ikm,
            &HkdfSalt::from_bytes(kem_ct.to_vec()),
            b"crypt_guard:v2:mac",
        )
    }

    /// Compute HMAC-SHA256 over `data`.
    fn hmac_compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        // HMAC accepts any key length; new_from_slice cannot fail for this type.
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify HMAC-SHA256 over `data` without leaking prefix matches through timing.
    fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), CryptError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(data);
        mac.verify_slice(tag)
            .map_err(|_| CryptError::AuthenticationFailed)
    }

    /// Generate `len` random bytes (empty when `len == 0`).
    fn gen_nonce(len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut n = vec![0u8; len];
        if len != 0 {
            rand::rngs::OsRng.fill_bytes(&mut n);
        }
        n
    }

    /// Read a file, mapping a missing path to [`CryptError::FileNotFound`].
    fn read_file(path: &PathBuf) -> Result<Vec<u8>, CryptError> {
        if !path.exists() {
            return Err(CryptError::FileNotFound);
        }
        std::fs::read(path).map_err(CryptError::from)
    }

    /// AES-XTS key-1 label (first AES-256 key of the 512-bit XTS key).
    #[cfg(feature = "aes-xts")]
    const LABEL_AES_XTS_K1: &[u8] = b"crypt_guard:v2:aead:aes-xts-k1";
    /// AES-XTS key-2 label (second AES-256 key / tweak key).
    #[cfg(feature = "aes-xts")]
    const LABEL_AES_XTS_K2: &[u8] = b"crypt_guard:v2:aead:aes-xts-k2";

    // ══════════════════════════════════════════════════════════════════════════════
    // XChaCha20Poly1305 (AEAD)
    // ══════════════════════════════════════════════════════════════════════════════

    impl SymmetricCipher for XChaCha20Poly1305 {
        const AEAD_ID: AeadAlgId = AeadAlgId::XChaCha20Poly1305;
        const NONCE_LEN: usize = 24;

        fn seal(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use chacha20poly1305::aead::generic_array::GenericArray;
            use chacha20poly1305::{
                aead::{Aead, KeyInit, Payload},
                XChaCha20Poly1305 as ChaChaP, XNonce,
            };
            let session_key = derive_key(shared_secret, kem_ct, LABEL_XCHACHA20POLY1305)?;
            let aad = build_aad(header, kem_ct, nonce, b"");
            let cipher = ChaChaP::new(GenericArray::from_slice(session_key.as_ref()));
            cipher
                .encrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptError::EncryptionFailed)
        }

        fn open(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use chacha20poly1305::aead::generic_array::GenericArray;
            use chacha20poly1305::{
                aead::{Aead, KeyInit, Payload},
                XChaCha20Poly1305 as ChaChaP, XNonce,
            };
            if nonce.len() != Self::NONCE_LEN {
                return Err(CryptError::InvalidNonce);
            }
            let session_key = derive_key(shared_secret, kem_ct, LABEL_XCHACHA20POLY1305)?;
            let aad = build_aad(header, kem_ct, nonce, b"");
            let cipher = ChaChaP::new(GenericArray::from_slice(session_key.as_ref()));
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptError::AuthenticationFailed)
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // AES-256-GCM-SIV (AEAD)
    // ══════════════════════════════════════════════════════════════════════════════

    impl SymmetricCipher for AesGcmSiv {
        const AEAD_ID: AeadAlgId = AeadAlgId::AesGcmSiv;
        const NONCE_LEN: usize = 12;

        fn seal(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            use aes_gcm_siv::{
                aead::{Aead, KeyInit, Payload},
                Aes256GcmSiv, Nonce as GcmSivNonce,
            };
            let session_key = derive_key(shared_secret, kem_ct, LABEL_AESGCMSIV)?;
            let aad = build_aad(header, kem_ct, nonce, b"");
            let cipher = Aes256GcmSiv::new(GenericArray::from_slice(session_key.as_ref()));
            cipher
                .encrypt(
                    GcmSivNonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptError::EncryptionFailed)
        }

        fn open(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes_gcm_siv::aead::generic_array::GenericArray;
            use aes_gcm_siv::{
                aead::{Aead, KeyInit, Payload},
                Aes256GcmSiv, Nonce as GcmSivNonce,
            };
            if nonce.len() != Self::NONCE_LEN {
                return Err(CryptError::InvalidNonce);
            }
            let session_key = derive_key(shared_secret, kem_ct, LABEL_AESGCMSIV)?;
            let aad = build_aad(header, kem_ct, nonce, b"");
            let cipher = Aes256GcmSiv::new(GenericArray::from_slice(session_key.as_ref()));
            cipher
                .decrypt(
                    GcmSivNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptError::AuthenticationFailed)
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // AES-256-CBC + HMAC-SHA256 (non-AEAD; IV is prepended inside the ciphertext)
    // ══════════════════════════════════════════════════════════════════════════════

    #[cfg(feature = "legacy-aes")]
    impl SymmetricCipher for AES {
        const AEAD_ID: AeadAlgId = AeadAlgId::AesCbc;
        const NONCE_LEN: usize = 0; // IV embedded in ciphertext

        fn seal(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            _nonce: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes::{cipher::generic_array::GenericArray, Aes256};
            use block_padding::Pkcs7;
            use cbc::{
                cipher::{BlockEncryptMut, KeyIvInit},
                Encryptor as CbcEncryptor,
            };
            type Aes256CbcEnc = CbcEncryptor<Aes256>;

            let session_key = derive_key(shared_secret, kem_ct, LABEL_AES)?;
            let mut iv = [0u8; 16];
            {
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut iv);
            }
            let cipher = Aes256CbcEnc::new(
                GenericArray::from_slice(session_key.as_ref()),
                GenericArray::from_slice(&iv),
            );
            let mut buf = plaintext.to_vec();
            let body = cipher
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
                .map_err(|_| CryptError::EncryptionFailed)?
                .to_vec();

            // ciphertext = iv || aes-cbc(body); then append HMAC over aad || ciphertext.
            let mut out = iv.to_vec();
            out.extend_from_slice(&body);
            let aad = build_aad(header, kem_ct, b"", b"");
            let mac_key = derive_mac_key(session_key.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(&out);
            out.extend_from_slice(&hmac_compute(mac_key.as_ref(), &mac_input));
            Ok(out)
        }

        fn open(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            _nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes::{cipher::generic_array::GenericArray, Aes256};
            use block_padding::Pkcs7;
            use cbc::{
                cipher::{BlockDecryptMut, KeyIvInit},
                Decryptor as CbcDecryptor,
            };
            type Aes256CbcDec = CbcDecryptor<Aes256>;

            let session_key = derive_key(shared_secret, kem_ct, LABEL_AES)?;
            if ciphertext.len() < 32 + 16 + 1 {
                return Err(CryptError::AuthenticationFailed);
            }
            let (body_with_iv, tag) = ciphertext.split_at(ciphertext.len() - 32);
            let aad = build_aad(header, kem_ct, b"", b"");
            let mac_key = derive_mac_key(session_key.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(body_with_iv);
            hmac_verify(mac_key.as_ref(), &mac_input, tag)?;

            let (iv, body) = body_with_iv.split_at(16);
            let cipher = Aes256CbcDec::new(
                GenericArray::from_slice(session_key.as_ref()),
                GenericArray::from_slice(iv),
            );
            let mut buf = body.to_vec();
            Ok(cipher
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| CryptError::DecryptionFailed)?
                .to_vec())
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // AES-256-CTR + HMAC-SHA256 (non-AEAD; 16-byte IV stored in the envelope nonce)
    // ══════════════════════════════════════════════════════════════════════════════

    #[cfg(feature = "aes-ctr")]
    impl SymmetricCipher for AesCtr {
        const AEAD_ID: AeadAlgId = AeadAlgId::AesCtr;
        const NONCE_LEN: usize = 16;

        fn seal(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
            type Aes256Ctr64LE = ctr::Ctr64LE<aes::Aes256>;
            let session_key = derive_key(shared_secret, kem_ct, LABEL_GENERIC)?;
            let mut buf = plaintext.to_vec();
            Aes256Ctr64LE::new(
                GenericArray::from_slice(session_key.as_ref()),
                GenericArray::from_slice(nonce),
            )
            .apply_keystream(&mut buf);

            let aad = build_aad(header, kem_ct, nonce, b"");
            let mac_key = derive_mac_key(session_key.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(&buf);
            buf.extend_from_slice(&hmac_compute(mac_key.as_ref(), &mac_input));
            Ok(buf)
        }

        fn open(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
            type Aes256Ctr64LE = ctr::Ctr64LE<aes::Aes256>;
            if ciphertext.len() < 32 {
                return Err(CryptError::AuthenticationFailed);
            }
            let session_key = derive_key(shared_secret, kem_ct, LABEL_GENERIC)?;
            let (body, tag) = ciphertext.split_at(ciphertext.len() - 32);
            let aad = build_aad(header, kem_ct, nonce, b"");
            let mac_key = derive_mac_key(session_key.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(body);
            hmac_verify(mac_key.as_ref(), &mac_input, tag)?;
            if nonce.len() != Self::NONCE_LEN {
                return Err(CryptError::InvalidNonce);
            }
            let mut buf = body.to_vec();
            Aes256Ctr64LE::new(
                GenericArray::from_slice(session_key.as_ref()),
                GenericArray::from_slice(nonce),
            )
            .apply_keystream(&mut buf);
            Ok(buf)
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // XChaCha20 (raw stream) + HMAC-SHA256 (non-AEAD; 24-byte nonce)
    // ══════════════════════════════════════════════════════════════════════════════

    impl SymmetricCipher for XChaCha20 {
        const AEAD_ID: AeadAlgId = AeadAlgId::XChaCha20;
        const NONCE_LEN: usize = 24;

        fn seal(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use chacha20::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
            use chacha20::XChaCha20 as ChaCha;
            let session_key = derive_key(shared_secret, kem_ct, LABEL_XCHACHA20)?;
            let mut buf = plaintext.to_vec();
            ChaCha::new(
                GenericArray::from_slice(session_key.as_ref()),
                GenericArray::from_slice(nonce),
            )
            .apply_keystream(&mut buf);

            let aad = build_aad(header, kem_ct, nonce, b"");
            let mac_key = derive_mac_key(session_key.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(&buf);
            buf.extend_from_slice(&hmac_compute(mac_key.as_ref(), &mac_input));
            Ok(buf)
        }

        fn open(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use chacha20::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
            use chacha20::XChaCha20 as ChaCha;
            if ciphertext.len() < 32 {
                return Err(CryptError::AuthenticationFailed);
            }
            let session_key = derive_key(shared_secret, kem_ct, LABEL_XCHACHA20)?;
            let (body, tag) = ciphertext.split_at(ciphertext.len() - 32);
            let aad = build_aad(header, kem_ct, nonce, b"");
            let mac_key = derive_mac_key(session_key.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(body);
            hmac_verify(mac_key.as_ref(), &mac_input, tag)?;
            if nonce.len() != Self::NONCE_LEN {
                return Err(CryptError::InvalidNonce);
            }
            let mut buf = body.to_vec();
            ChaCha::new(
                GenericArray::from_slice(session_key.as_ref()),
                GenericArray::from_slice(nonce),
            )
            .apply_keystream(&mut buf);
            Ok(buf)
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // AES-256-XTS + HMAC-SHA256 (non-AEAD; 512-bit key, IV-free; len-prefixed)
    // ══════════════════════════════════════════════════════════════════════════════

    #[cfg(feature = "aes-xts")]
    impl SymmetricCipher for AesXts {
        const AEAD_ID: AeadAlgId = AeadAlgId::AesXts;
        const NONCE_LEN: usize = 0;

        fn seal(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            _nonce: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes::{cipher::generic_array::GenericArray, cipher::KeyInit, Aes256};
            use xts_mode::{get_tweak_default, Xts128};
            let salt = HkdfSalt::from_bytes(kem_ct.to_vec());
            let k1 = derive_session_key(shared_secret, &salt, LABEL_AES_XTS_K1)?;
            let k2 = derive_session_key(shared_secret, &salt, LABEL_AES_XTS_K2)?;
            let xts = Xts128::<Aes256>::new(
                Aes256::new(GenericArray::from_slice(k1.as_ref())),
                Aes256::new(GenericArray::from_slice(k2.as_ref())),
            );

            const SECTOR: usize = 0x200;
            let orig_len = plaintext.len();
            let mut buf = plaintext.to_vec();
            let rem = buf.len() % SECTOR;
            if rem != 0 {
                buf.resize(buf.len() + (SECTOR - rem), 0);
            }
            xts.encrypt_area(&mut buf, SECTOR, 0, get_tweak_default);

            let mut out = (orig_len as u64).to_le_bytes().to_vec();
            out.extend_from_slice(&buf);
            let aad = build_aad(header, kem_ct, b"", b"");
            let mac_key = derive_mac_key(k2.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(&out);
            out.extend_from_slice(&hmac_compute(mac_key.as_ref(), &mac_input));
            Ok(out)
        }

        fn open(
            shared_secret: &[u8],
            header: &Header,
            kem_ct: &[u8],
            _nonce: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, CryptError> {
            use aes::{cipher::generic_array::GenericArray, cipher::KeyInit, Aes256};
            use xts_mode::{get_tweak_default, Xts128};
            let salt = HkdfSalt::from_bytes(kem_ct.to_vec());
            let k1 = derive_session_key(shared_secret, &salt, LABEL_AES_XTS_K1)?;
            let k2 = derive_session_key(shared_secret, &salt, LABEL_AES_XTS_K2)?;

            if ciphertext.len() < 32 + 8 {
                return Err(CryptError::AuthenticationFailed);
            }
            let (body_with_len, tag) = ciphertext.split_at(ciphertext.len() - 32);
            let aad = build_aad(header, kem_ct, b"", b"");
            let mac_key = derive_mac_key(k2.as_ref(), kem_ct)?;
            let mut mac_input = aad;
            mac_input.extend_from_slice(body_with_len);
            hmac_verify(mac_key.as_ref(), &mac_input, tag)?;

            let orig_len = u64::from_le_bytes(
                body_with_len[..8]
                    .try_into()
                    .map_err(|_| CryptError::InvalidEnvelope)?,
            ) as usize;
            let xts = Xts128::<Aes256>::new(
                Aes256::new(GenericArray::from_slice(k1.as_ref())),
                Aes256::new(GenericArray::from_slice(k2.as_ref())),
            );
            let mut buf = body_with_len[8..].to_vec();
            const SECTOR: usize = 0x200;
            xts.decrypt_area(&mut buf, SECTOR, 0, get_tweak_default);
            buf.truncate(orig_len);
            Ok(buf)
        }
    }
} // mod inner

// Re-export the trait + impls when the ml-kem backend is active.
#[cfg(feature = "ml-kem-backend")]
pub use inner::*;
