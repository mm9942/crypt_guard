use pqcrypto_falcon::falcon1024::{self, *};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    fs,
    path::{Path, PathBuf},
};
use tokio::io;
use pqcrypto_traits::sign::{SignedMessage as SignedMessageSign, SecretKey as SecretKeySign, PublicKey as PublicKeySign, DetachedSignature as DetachedSignatureSign};
use hex;
use crate::keychain::*;

#[derive(Debug)]
pub enum SigningErr {
    SecretKeyMissing,
    PublicKeyMissing,
    SignatureVerificationFailed,
    SigningMessageFailed,
    IOError(io::Error),
}

impl Display for SigningErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SigningErr::SecretKeyMissing => write!(f, "Secret key is missing"),
            SigningErr::PublicKeyMissing => write!(f, "Public key is missing"),
            SigningErr::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            SigningErr::SigningMessageFailed => write!(f, "Failed to sign message"),
            SigningErr::IOError(err) => write!(f, "IOError occurred: {}", err),
        }
    }
}

impl PartialEq for SigningErr {
    fn eq(&self, other: &Self) -> bool {
        use SigningErr::*;
        match (self, other) {
            (SecretKeyMissing, SecretKeyMissing)
            | (PublicKeyMissing, PublicKeyMissing)
            | (SignatureVerificationFailed, SignatureVerificationFailed)
            | (SigningMessageFailed, SigningMessageFailed) => true,
            (IOError(_), IOError(_)) => false,
            _ => false,
        }
    }
}

impl From<pqcrypto_traits::Error> for SigningErr {
    fn from(_: pqcrypto_traits::Error) -> Self {
        SigningErr::SignatureVerificationFailed
    }
}

impl Error for SigningErr {}

impl From<io::Error> for SigningErr {
    fn from(err: io::Error) -> Self {
        SigningErr::IOError(err)
    }
}

pub struct Sign {
    public_key: Option<PublicKey>,
    secret_key: Option<SecretKey>,
    signed_msg: Option<SignedMessage>,
    signature: Option<DetachedSignature>,
}

impl Sign {
    pub fn new() -> Result<Self, SigningErr> {
        let (pk, sk) = keypair();
        Ok(Self {
            public_key: Some(pk),
            secret_key: Some(sk),
            signed_msg: None,
            signature: None,
        })
    }

    // Setters
    pub fn set_public_key(&mut self, public_key: PublicKey) {
        self.public_key = Some(public_key);
    }

    pub fn set_secret_key(&mut self, secret_key: SecretKey) {
        self.secret_key = Some(secret_key);
    }

    pub fn set_signed_msg(&mut self, signed_msg: SignedMessage) {
        self.signed_msg = Some(signed_msg);
    }

    pub fn set_signature(&mut self, signature: DetachedSignature) {
        self.signature = Some(signature);
    }

    pub async fn save_signed_msg(&self, base_path: &str, title: &str) -> Result<(), SigningErr> {
        if let Some(signed_msg) = &self.signed_msg {
            let dir_path = format!("{}/{}", base_path, title);
            let dir = std::path::Path::new(&dir_path);
            if !dir.exists() {
                std::fs::create_dir_all(&dir).map_err(|_| SigningErr::IOError);
            }

            let signed_message_path = Keychain::generate_unique_filename(&format!("{}/{}", dir_path, title), "msg");

            fs::write(
                &signed_message_path,
                format!(
                    "-----BEGIN SIGNED MESSAGE-----\n{}\n-----END SIGNED MESSAGE-----",
                    hex::encode(SignedMessageSign::as_bytes(signed_msg))
                )
            ).map_err(|_| SigningErr::IOError);
            Ok(())
        } else {
            Err(SigningErr::SigningMessageFailed)
        }
    }

    pub async fn save_keys(&self, base_path: &str, title: &str) -> Result<(), CryptError> {
        let dir_path = format!("{}/{}", base_path, title);
        let dir = std::path::Path::new(&dir_path);
        if !dir.exists() {
            std::fs::create_dir_all(&dir).map_err(|_| SigningErr::IOError);
        }

        let public_key_path = Keychain::generate_unique_filename(&format!("{}/{}", dir_path, title), "pub");
        let secret_key_path = Keychain::generate_unique_filename(&format!("{}/{}", dir_path, title), "sec");

        fs::write(
            &public_key_path, 
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                hex::encode(self.public_key().expect("Public key is missing").as_bytes())
            )
        ).map_err(|_| SigningErr::IOError);

        fs::write(
            &secret_key_path, 
            format!(
                "-----BEGIN SECRET KEY-----\n{}\n-----END SECRET KEY-----",
                hex::encode(self.secret_key().expect("Secret key is missing").as_bytes())
            )
        ).map_err(|_| SigningErr::IOError);
        
        Ok(())
    }

    // Getters
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    pub fn secret_key(&self) -> Option<&SecretKey> {
        self.secret_key.as_ref()
    }

    pub fn signed_msg(&self) -> Option<&SignedMessage> {
        self.signed_msg.as_ref()
    }

    pub fn signature(&self) -> Option<&DetachedSignature> {
        self.signature.as_ref()
    }

    pub async fn sign_msg(&mut self, message: &[u8]) -> Result<&[u8], SigningErr> {
        if let Some(sk) = &self.secret_key {
            let signed_message = sign(message, sk);
            self.signed_msg = Some(signed_message);
            let signed_bytes = SignedMessageSign::as_bytes(self.signed_msg().unwrap());
            Ok(signed_bytes)
        } else {
            Err(SigningErr::SigningMessageFailed)
        }
    }

    pub async fn sign_file(&mut self, file_path: PathBuf) -> Result<Vec<u8>, SigningErr> {
        let signed_path = file_path.with_extension("sig");
        let data = fs::read(&file_path)?;
        let signed_data = self.signing_detached(&data).await?; 
        fs::write(&signed_path, signed_data.clone().as_bytes().to_vec())?;
        Ok(signed_data.as_bytes().to_owned())
    }

    pub async fn signing_detached(&mut self, message: &[u8]) -> Result<DetachedSignature, SigningErr> {
        if let Some(sk) = &self.secret_key {
            let signature = detached_sign(message, sk);
            self.signature = Some(signature);
            println!("{:?}", hex::encode(DetachedSignatureSign::as_bytes(self.signature().unwrap())));
            Ok(self.signature.unwrap())
        } else {
            Err(SigningErr::SecretKeyMissing)
        }
    }

    pub async fn verify_msg(&self, message: &[u8]) -> Result<Vec<u8>, SigningErr> {
        if let (Some(pk), Some(signed_msg)) = (&self.public_key, &self.signed_msg) {
            let msg_verification = open(signed_msg, pk)
                .map_err(|_| SigningErr::SignatureVerificationFailed);

            msg_verification
        } else {
            Err(SigningErr::PublicKeyMissing)
        }
    }

    pub async fn verify_detached(
        &self,
        message: &[u8], 
    ) -> Result<bool, SigningErr> {
        let signature = match self.signature() {
            Some(sig) => sig,
            None => {
                eprintln!("No signature found for verification");
                return Err(SigningErr::SignatureVerificationFailed);
            }
        };

        let public_key = match self.public_key() {
            Some(pk) => pk,
            None => {
                eprintln!("Public key not found for verification");
                return Err(SigningErr::PublicKeyMissing);
            }
        };

        match verify_detached_signature(signature, message, public_key) {
            Ok(_) => Ok(true),
            Err(_) => {
                eprintln!("Signature verification failed");
                Err(SigningErr::SignatureVerificationFailed)
            },
        }
    }
}
