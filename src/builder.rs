use std::path::PathBuf;

use crate::error::{CryptError, SigningErr};
use zeroize::Zeroize;
// bring exported macros into scope
use crate::{encryption, decryption, encrypt_file, decrypt_file, signature, verify, kyber_keypair};
// Macro expansions require these types in scope at the callsite
use crate::core::{
    kdf::{Signature, Falcon1024, Falcon512, Dilithium2, Dilithium3, Dilithium5, Message, Detached},
    kyber::key_controler::{KeyControKyber1024, KeyControKyber768, KeyControKyber512},
};
// Types required by macro expansions
use crate::core::kyber::{
    Kyber, Encryption, Decryption, Kyber1024, Kyber768, Kyber512, Data, AES, AesGcmSiv, AesCtr, AesXts,
    XChaCha20, XChaCha20Poly1305,
};
use crate::core::kyber::KyberFunctions;

/// Symmetric algorithms supported by the builders
#[derive(Clone, Copy, Debug)]
pub enum SymmetricAlg {
    Aes,
    AesXts,
    AesCbc,
    AesGcmSiv,
    AesCtr,
    XChaCha20,
    XChaCha20Poly1305,
}

/// Output of an encryption operation
#[derive(Clone, Debug)]
pub struct EncryptionOutput {
    pub content: Vec<u8>,
    pub cipher: Vec<u8>,
    pub nonce: Option<String>,
}

#[derive(Clone, Debug)]
enum Content {
    Data(Vec<u8>),
    File(PathBuf),
}

#[derive(Default)]
pub struct EncryptBuilder {
    key: Option<Vec<u8>>,       // Kyber public key
    key_size: Option<u16>,      // 1024 | 768 | 512
    content: Option<Content>,   // Data or File
    passphrase: Option<String>,
    algorithm: Option<SymmetricAlg>,
}

impl EncryptBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn key(mut self, key: Vec<u8>) -> Self { self.key = Some(key); self }
    pub fn key_size(mut self, size: u16) -> Self { self.key_size = Some(size); self }

    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.content = Some(Content::Data(data.into()));
        self
    }

    pub fn file(mut self, path: PathBuf) -> Self {
        self.content = Some(Content::File(path));
        self
    }

    pub fn passphrase<S: Into<String>>(mut self, passphrase: S) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }

    pub fn algorithm(mut self, alg: SymmetricAlg) -> Self {
        self.algorithm = Some(alg);
        self
    }

    pub fn run(self) -> Result<EncryptionOutput, CryptError> {
        let key = self.key.ok_or_else(|| CryptError::new("missing public key"))?;
        let size = self.key_size.ok_or_else(|| CryptError::new("missing key size"))?;
        let pass = self.passphrase.ok_or_else(|| CryptError::new("missing passphrase"))?;
        let alg = self.algorithm.ok_or_else(|| CryptError::new("missing algorithm"))?;
        let content = self.content.ok_or_else(|| CryptError::new("missing content (data or file)"))?;

        match content {
            Content::Data(data) => match alg {
                SymmetricAlg::Aes => {
                    let (content, cipher) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: None })
                }
                SymmetricAlg::AesXts => {
                    let (content, cipher) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_XTS)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_XTS)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_XTS)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: None })
                }
                SymmetricAlg::AesCbc => {
                    let (content, cipher) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_CBC)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_CBC)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_CBC)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: None })
                }
                SymmetricAlg::AesGcmSiv => {
                    let (content, cipher, nonce) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_GCM_SIV)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_GCM_SIV)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_GCM_SIV)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: Some(nonce) })
                }
                SymmetricAlg::AesCtr => {
                    let (content, cipher, nonce) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), AES_CTR)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), AES_CTR)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), AES_CTR)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: Some(nonce) })
                }
                SymmetricAlg::XChaCha20 => {
                    let (content, cipher, nonce) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), XChaCha20)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), XChaCha20)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), XChaCha20)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: Some(nonce) })
                }
                SymmetricAlg::XChaCha20Poly1305 => {
                    let (content, cipher, nonce) = match size {
                        1024 => encryption!(key.clone(), 1024, data.clone(), pass.clone(), XChaCha20Poly1305)?,
                        768 => encryption!(key.clone(), 768, data.clone(), pass.clone(), XChaCha20Poly1305)?,
                        512 => encryption!(key.clone(), 512, data.clone(), pass.clone(), XChaCha20Poly1305)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: Some(nonce) })
                }
            },
            Content::File(path) => match alg {
                SymmetricAlg::Aes => {
                    let (content, cipher) = match size {
                        1024 => encrypt_file!(key.clone(), 1024, path.clone(), pass.clone(), AES)?,
                        768 => encrypt_file!(key.clone(), 768, path.clone(), pass.clone(), AES)?,
                        512 => encrypt_file!(key.clone(), 512, path.clone(), pass.clone(), AES)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    Ok(EncryptionOutput { content, cipher, nonce: None })
                }
                SymmetricAlg::XChaCha20 => {
                    // Returns a nonce (as Option<String>) in macro; normalize to Option<String>
                    let (content, cipher, nonce_str) = match size {
                        1024 => encrypt_file!(key.clone(), 1024, path.clone(), pass.clone(), XChaCha20)?,
                        768 => encrypt_file!(key.clone(), 768, path.clone(), pass.clone(), XChaCha20)?,
                        512 => encrypt_file!(key.clone(), 512, path.clone(), pass.clone(), XChaCha20)?,
                        _ => return Err(CryptError::new("invalid Kyber size")),
                    };
                    let nonce = Some(nonce_str);
                    Ok(EncryptionOutput { content, cipher, nonce })
                }
                _ => Err(CryptError::new("file encryption supported only for AES and XChaCha20")),
            },
        }
    }
}

#[derive(Default)]
pub struct DecryptBuilder {
    key: Option<Vec<u8>>,       // Kyber secret key
    key_size: Option<u16>,      // 1024 | 768 | 512
    content: Option<Content>,   // Data (encrypted bytes) or File (.enc path)
    passphrase: Option<String>,
    cipher: Option<Vec<u8>>,
    nonce: Option<String>,
    algorithm: Option<SymmetricAlg>,
}

impl DecryptBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn key(mut self, key: Vec<u8>) -> Self { self.key = Some(key); self }
    pub fn key_size(mut self, size: u16) -> Self { self.key_size = Some(size); self }
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self { self.content = Some(Content::Data(data.into())); self }
    pub fn file(mut self, path: PathBuf) -> Self { self.content = Some(Content::File(path)); self }
    pub fn passphrase<S: Into<String>>(mut self, passphrase: S) -> Self { self.passphrase = Some(passphrase.into()); self }
    pub fn cipher<T: Into<Vec<u8>>>(mut self, cipher: T) -> Self { self.cipher = Some(cipher.into()); self }
    pub fn nonce<S: Into<String>>(mut self, nonce: S) -> Self { self.nonce = Some(nonce.into()); self }
    pub fn algorithm(mut self, alg: SymmetricAlg) -> Self { self.algorithm = Some(alg); self }

    pub fn run(self) -> Result<Vec<u8>, CryptError> {
        let key = self.key.ok_or_else(|| CryptError::new("missing secret key"))?;
        let size = self.key_size.ok_or_else(|| CryptError::new("missing key size"))?;
        let pass = self.passphrase.ok_or_else(|| CryptError::new("missing passphrase"))?;
        let alg = self.algorithm.ok_or_else(|| CryptError::new("missing algorithm"))?;
        let content = self.content.ok_or_else(|| CryptError::new("missing content (data or file)"))?;

        match content {
            Content::Data(data) => {
                let cipher = self.cipher.ok_or_else(|| CryptError::new("missing cipher"))?;
                match alg {
                    SymmetricAlg::Aes => match size { 1024 => decryption!(key.clone(), 1024, data.clone(), pass.clone(), cipher.clone(), AES), 768 => decryption!(key.clone(), 768, data.clone(), pass.clone(), cipher.clone(), AES), 512 => decryption!(key.clone(), 512, data.clone(), pass.clone(), cipher.clone(), AES), _ => Err(CryptError::new("invalid Kyber size")), },
                    SymmetricAlg::AesXts => match size { 1024 => decryption!(key.clone(), 1024, data.clone(), pass.clone(), cipher.clone(), AES_XTS), 768 => decryption!(key.clone(), 768, data.clone(), pass.clone(), cipher.clone(), AES_XTS), 512 => decryption!(key.clone(), 512, data.clone(), pass.clone(), cipher.clone(), AES_XTS), _ => Err(CryptError::new("invalid Kyber size")), },
                    SymmetricAlg::AesCbc => match size { 1024 => decryption!(key.clone(), 1024, data.clone(), pass.clone(), cipher.clone(), AES_CBC), 768 => decryption!(key.clone(), 768, data.clone(), pass.clone(), cipher.clone(), AES_CBC), 512 => decryption!(key.clone(), 512, data.clone(), pass.clone(), cipher.clone(), AES_CBC), _ => Err(CryptError::new("invalid Kyber size")), },
                    SymmetricAlg::AesGcmSiv => {
                        let n = self.nonce.ok_or_else(|| CryptError::new("missing nonce for AES_GCM_SIV"))?;
                        match size { 1024 => decryption!(key.clone(), 1024, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), AES_GCM_SIV), 768 => decryption!(key.clone(), 768, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), AES_GCM_SIV), 512 => decryption!(key.clone(), 512, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), AES_GCM_SIV), _ => Err(CryptError::new("invalid Kyber size")), }
                    }
                    SymmetricAlg::AesCtr => {
                        let n = self.nonce.ok_or_else(|| CryptError::new("missing nonce for AES_CTR"))?;
                        match size { 1024 => decryption!(key.clone(), 1024, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), AES_CTR), 768 => decryption!(key.clone(), 768, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), AES_CTR), 512 => decryption!(key.clone(), 512, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), AES_CTR), _ => Err(CryptError::new("invalid Kyber size")), }
                    }
                    SymmetricAlg::XChaCha20 => {
                        let n = self.nonce.ok_or_else(|| CryptError::new("missing nonce for XChaCha20"))?;
                        match size { 1024 => decryption!(key.clone(), 1024, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20), 768 => decryption!(key.clone(), 768, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20), 512 => decryption!(key.clone(), 512, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20), _ => Err(CryptError::new("invalid Kyber size")), }
                    }
                    SymmetricAlg::XChaCha20Poly1305 => {
                        let n = self.nonce.ok_or_else(|| CryptError::new("missing nonce for XChaCha20Poly1305"))?;
                        match size { 1024 => decryption!(key.clone(), 1024, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20Poly1305), 768 => decryption!(key.clone(), 768, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20Poly1305), 512 => decryption!(key.clone(), 512, data.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20Poly1305), _ => Err(CryptError::new("invalid Kyber size")), }
                    }
                }
            }
            Content::File(path) => match alg {
                SymmetricAlg::Aes => {
                    let cipher = self.cipher.ok_or_else(|| CryptError::new("missing cipher"))?;
                    match size { 1024 => decrypt_file!(key.clone(), 1024, path.clone(), pass.clone(), cipher.clone(), AES), 768 => decrypt_file!(key.clone(), 768, path.clone(), pass.clone(), cipher.clone(), AES), 512 => decrypt_file!(key.clone(), 512, path.clone(), pass.clone(), cipher.clone(), AES), _ => Err(CryptError::new("invalid Kyber size")), }
                }
                SymmetricAlg::XChaCha20 => {
                    let cipher = self.cipher.ok_or_else(|| CryptError::new("missing cipher"))?;
                    let n = self.nonce.ok_or_else(|| CryptError::new("missing nonce for XChaCha20"))?;
                    match size { 1024 => decrypt_file!(key.clone(), 1024, path.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20), 768 => decrypt_file!(key.clone(), 768, path.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20), 512 => decrypt_file!(key.clone(), 512, path.clone(), pass.clone(), cipher.clone(), Some(n.clone()), XChaCha20), _ => Err(CryptError::new("invalid Kyber size")), }
                }
                _ => Err(CryptError::new("file decryption supported only for AES and XChaCha20")),
            },
        }
    }
}

#[derive(Default)]
pub struct KyberKeygenBuilder { size: Option<u16> }
impl KyberKeygenBuilder {
    pub fn new() -> Self { Self::default() }
    pub fn size(mut self, size: u16) -> Self { self.size = Some(size); self }
    pub fn generate(self) -> Result<(Vec<u8>, Vec<u8>), CryptError> {
        let size = self.size.ok_or_else(|| CryptError::new("missing kyber size"))?;
        let (pk, sk) = kyber_keypair!(size);
        Ok((pk, sk))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SignAlgorithm { Falcon1024, Falcon512, Dilithium2, Dilithium3, Dilithium5 }

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum SignMode { Message, Detached }

#[derive(Default)]
pub struct SignBuilder {
    alg: Option<SignAlgorithm>,
    mode: Option<SignMode>,
    key: Option<Vec<u8>>,   // secret key for signing
    data: Option<Vec<u8>>,
}

impl SignBuilder {
    pub fn new() -> Self { Self::default() }
    pub fn algorithm(mut self, alg: SignAlgorithm) -> Self { self.alg = Some(alg); self }
    pub fn mode(mut self, mode: SignMode) -> Self { self.mode = Some(mode); self }
    pub fn key(mut self, key: Vec<u8>) -> Self { self.key = Some(key); self }
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self { self.data = Some(data.into()); self }

    pub fn sign(self) -> Result<Vec<u8>, SigningErr> {
        let alg = self.alg.ok_or_else(|| SigningErr::new("missing algorithm"))?;
        let mode = self.mode.ok_or_else(|| SigningErr::new("missing sign mode"))?;
        let key = self.key.ok_or_else(|| SigningErr::new("missing key"))?;
        let data = self.data.ok_or_else(|| SigningErr::new("missing data"))?;

        let res = match (alg, mode) {
            (SignAlgorithm::Falcon1024, SignMode::Message) => signature!(Falcon, key.clone(), 1024, data.clone(), Message),
            (SignAlgorithm::Falcon1024, SignMode::Detached) => signature!(Falcon, key.clone(), 1024, data.clone(), Detached),
            (SignAlgorithm::Falcon512, SignMode::Message) => signature!(Falcon, key.clone(), 512, data.clone(), Message),
            (SignAlgorithm::Falcon512, SignMode::Detached) => signature!(Falcon, key.clone(), 512, data.clone(), Detached),
            (SignAlgorithm::Dilithium5, SignMode::Message) => signature!(Dilithium, key.clone(), 5, data.clone(), Message),
            (SignAlgorithm::Dilithium5, SignMode::Detached) => signature!(Dilithium, key.clone(), 5, data.clone(), Detached),
            (SignAlgorithm::Dilithium3, SignMode::Message) => signature!(Dilithium, key.clone(), 3, data.clone(), Message),
            (SignAlgorithm::Dilithium3, SignMode::Detached) => signature!(Dilithium, key.clone(), 3, data.clone(), Detached),
            (SignAlgorithm::Dilithium2, SignMode::Message) => signature!(Dilithium, key.clone(), 2, data.clone(), Message),
            (SignAlgorithm::Dilithium2, SignMode::Detached) => signature!(Dilithium, key.clone(), 2, data.clone(), Detached),
        };
        Ok(res?)
    }
}

#[derive(Default)]
pub struct VerifyBuilder {
    alg: Option<SignAlgorithm>,
    mode: Option<SignMode>,
    key: Option<Vec<u8>>,           // public key for verification
    signed_message: Option<Vec<u8>>, // for Message mode
    data: Option<Vec<u8>>,          // for Detached mode
    signature: Option<Vec<u8>>,     // for Detached mode
}

impl VerifyBuilder {
    pub fn new() -> Self { Self::default() }
    pub fn algorithm(mut self, alg: SignAlgorithm) -> Self { self.alg = Some(alg); self }
    pub fn mode(mut self, mode: SignMode) -> Self { self.mode = Some(mode); self }
    pub fn key(mut self, key: Vec<u8>) -> Self { self.key = Some(key); self }
    pub fn signed_message<T: Into<Vec<u8>>>(mut self, msg: T) -> Self { self.signed_message = Some(msg.into()); self }
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self { self.data = Some(data.into()); self }
    pub fn signature<T: Into<Vec<u8>>>(mut self, sig: T) -> Self { self.signature = Some(sig.into()); self }

    pub fn open(self) -> Result<Vec<u8>, SigningErr> {
        let alg = self.alg.ok_or_else(|| SigningErr::new("missing algorithm"))?;
        let mode = self.mode.ok_or_else(|| SigningErr::new("missing sign mode"))?;
        if mode != SignMode::Message {
            return Err(SigningErr::new("open() requires Message mode"));
        }
        let key = self.key.ok_or_else(|| SigningErr::new("missing key"))?;
        let msg = self.signed_message.ok_or_else(|| SigningErr::new("missing signed message"))?;
        let res = match alg {
            SignAlgorithm::Falcon1024 => verify!(Falcon, key.clone(), 1024, msg.clone(), Message),
            SignAlgorithm::Falcon512 => verify!(Falcon, key.clone(), 512, msg.clone(), Message),
            SignAlgorithm::Dilithium5 => verify!(Dilithium, key.clone(), 5, msg.clone(), Message),
            SignAlgorithm::Dilithium3 => verify!(Dilithium, key.clone(), 3, msg.clone(), Message),
            SignAlgorithm::Dilithium2 => verify!(Dilithium, key.clone(), 2, msg.clone(), Message),
        };
        Ok(res?)
    }

    pub fn verify(self) -> Result<bool, SigningErr> {
        let alg = self.alg.ok_or_else(|| SigningErr::new("missing algorithm"))?;
        let mode = self.mode.ok_or_else(|| SigningErr::new("missing sign mode"))?;
        if mode != SignMode::Detached {
            return Err(SigningErr::new("verify() requires Detached mode"));
        }
        let key = self.key.ok_or_else(|| SigningErr::new("missing key"))?;
        let data = self.data.ok_or_else(|| SigningErr::new("missing data"))?;
        let signature = self.signature.ok_or_else(|| SigningErr::new("missing signature"))?;
        let res = match alg {
            SignAlgorithm::Falcon1024 => verify!(Falcon, key.clone(), 1024, signature.clone(), data.clone(), Detached),
            SignAlgorithm::Falcon512 => verify!(Falcon, key.clone(), 512, signature.clone(), data.clone(), Detached),
            SignAlgorithm::Dilithium5 => verify!(Dilithium, key.clone(), 5, signature.clone(), data.clone(), Detached),
            SignAlgorithm::Dilithium3 => verify!(Dilithium, key.clone(), 3, signature.clone(), data.clone(), Detached),
            SignAlgorithm::Dilithium2 => verify!(Dilithium, key.clone(), 2, signature.clone(), data.clone(), Detached),
        };
        Ok(res?)
    }
}
