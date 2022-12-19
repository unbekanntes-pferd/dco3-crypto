#![allow(non_camel_case_types, dead_code)]
use openssl::base64;
use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter as OpenSSLCrypter, Mode};
use serde::Serialize;
use std::str::Utf8Error;

const DEFAULT_CHUNKSIZE: usize = 33554432;

#[derive(Serialize)]
pub enum FileKeyVersion {
    #[serde(rename = "A")]
    RSA2048_AES256GCM,
    #[serde(rename = "RSA-4096/AES-256-GCM")]
    RSA4096_AES256GCM,
}

#[derive(Serialize)]
pub enum PlainFileKeyVersion {
    #[serde(rename = "AES-256-GCM")]
    AES256CM,
}

#[derive(Serialize, Clone, PartialEq, Debug)]
pub enum UserKeyPairVersion {
    #[serde(rename = "A")]
    RSA2048,
    #[serde(rename = "RSA-4096")]
    RSA4096,
}

#[derive(Serialize)]
pub struct FileKey {
    pub key: String,
    pub iv: String,
    pub version: FileKeyVersion,
    pub tag: Option<String>,
}

#[derive(Serialize)]
pub struct PlainFileKey {
    pub key: String,
    pub iv: String,
    pub version: PlainFileKeyVersion,
    pub tag: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyContainer {
    pub version: UserKeyPairVersion,
    pub public_key: String,
    pub created_at: Option<String>,
    pub expire_at: Option<String>,
    pub created_by: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyContainer {
    pub version: UserKeyPairVersion,
    pub private_key: String,
    pub created_at: Option<String>,
    pub expire_at: Option<String>,
    pub created_by: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyPairContainer {
    pub private_key_container: PrivateKeyContainer,
    pub public_key_container: PublicKeyContainer,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlainUserKeyPairContainer {
    pub private_key_container: PrivateKeyContainer,
    pub public_key_container: PublicKeyContainer,
}

impl PrivateKeyContainer {
    pub fn new(private_key_pem: String, version: UserKeyPairVersion) -> Self {
        Self {
            private_key: private_key_pem,
            version,
            created_at: None,
            expire_at: None,
            created_by: None,
        }
    }
}

impl PublicKeyContainer {
    pub fn new(public_key_pem: String, version: UserKeyPairVersion) -> Self {
        Self {
            public_key: public_key_pem,
            version,
            created_at: None,
            expire_at: None,
            created_by: None,
        }
    }
}

impl PlainUserKeyPairContainer {
    pub fn new(
        private_key_pem: String,
        public_key_pem: String,
        version: UserKeyPairVersion,
    ) -> Self {
        let public_key_container = PublicKeyContainer::new(public_key_pem, version.clone());
        let private_key_container = PrivateKeyContainer::new(private_key_pem, version);

        Self {
            private_key_container,
            public_key_container,
        }
    }

    pub fn new_from_keypair(
        enc_keypair: UserKeyPairContainer,
        plain_private_key_pem: &str,
    ) -> Self {
        let version = enc_keypair.private_key_container.version;
        let private_key_container =
            PrivateKeyContainer::new(plain_private_key_pem.to_string(), version);
        Self {
            private_key_container,
            public_key_container: enc_keypair.public_key_container,
        }
    }
}

impl UserKeyPairContainer {
    pub fn new_from_plain_keypair(
        plain_keypair: PlainUserKeyPairContainer,
        enc_private_key_pem: &str,
    ) -> Self {
        let version = plain_keypair.private_key_container.version;

        let private_key_container =
            PrivateKeyContainer::new(enc_private_key_pem.to_string(), version);

        Self {
            private_key_container,
            public_key_container: plain_keypair.public_key_container,
        }
    }
}

impl FileKey {
    pub fn new_from_plain_key(
        plain_file_key: PlainFileKey,
        enc_key: &str,
        version: FileKeyVersion,
    ) -> Self {
        Self {
            key: enc_key.to_string(),
            iv: plain_file_key.iv,
            tag: plain_file_key.tag,
            version,
        }
    }
}

impl PlainFileKey {
    pub fn new_from_file_key(enc_file_key: FileKey, plain_file_key: &str) -> Self {
        Self {
            key: plain_file_key.to_string(),
            iv: enc_file_key.iv,
            tag: enc_file_key.tag,
            version: PlainFileKeyVersion::AES256CM,
        }
    }

    pub fn try_new_for_encryption() -> Result<Self, DracoonCryptoError> {
        let mut key: [u8; 32] = [0; 32];
        rand_bytes(&mut key)?;

        let mut iv: [u8; 12] = [0; 12];
        rand_bytes(&mut iv)?;

        let key = base64::encode_block(&key);
        let iv = base64::encode_block(&iv);

        let plain_file_key = PlainFileKey {
            key,
            iv,
            tag: None,
            version: PlainFileKeyVersion::AES256CM,
        };

        Ok(plain_file_key)
    }

    pub fn set_tag(&mut self, tag: String) {
        self.tag = Some(tag);
    }
}

#[derive(Serialize)]
pub enum KeyState {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "available")]
    Available,
    #[serde(rename = "pending")]
    Pending,
}

#[derive(Serialize)]
pub struct EncryptionInfo {
    user_key_state: KeyState,
    room_key_state: KeyState,
    dataspace_key_state: KeyState,
}

#[derive(Debug)]
pub enum DracoonCryptoError {
    RsaOperationFailed,
    ByteParseError,
    CrypterOperationFailed,
    InvalidKeypairVersion,
    InvalidTag,
    Unknown,
}

impl From<ErrorStack> for DracoonCryptoError {
    fn from(_: ErrorStack) -> Self {
        Self::RsaOperationFailed
    }
}

impl From<Utf8Error> for DracoonCryptoError {
    fn from(_: Utf8Error) -> Self {
        Self::ByteParseError
    }
}

pub type EncryptionResult = (Vec<u8>, PlainFileKey);
pub type ChunkedEncryptionResult = (Vec<u8>, Option<PlainFileKey>);

pub trait PublicKey {
    fn get_public_key(&self) -> &PublicKeyContainer;
}

impl PublicKey for PlainUserKeyPairContainer {
    fn get_public_key(&self) -> &PublicKeyContainer {
        &self.public_key_container
    }
}

impl PublicKey for PublicKeyContainer {
    fn get_public_key(&self) -> &PublicKeyContainer {
        &self
    }
}

pub trait DracoonRSACrypto {
    fn create_plain_user_keypair(
        version: UserKeyPairVersion,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError>;

    fn encrypt_private_key(
        secret: &str,
        plain_keypair: PlainUserKeyPairContainer,
    ) -> Result<UserKeyPairContainer, DracoonCryptoError>;

    fn decrypt_private_key(
        secret: &str,
        keypair: UserKeyPairContainer,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError>;

    fn encrypt_file_key(
        plain_file_key: PlainFileKey,
        public_key: impl PublicKey,
    ) -> Result<FileKey, DracoonCryptoError>;

    fn decrypt_file_key(
        file_key: FileKey,
        keypair: PlainUserKeyPairContainer,
    ) -> Result<PlainFileKey, DracoonCryptoError>;
}

pub trait Encrypt {
    fn encrypt(data: Vec<u8>) -> Result<EncryptionResult, DracoonCryptoError>;

    fn get_encrypter(buffer: &mut Vec<u8>) -> Result<Crypter, DracoonCryptoError>;
}

pub trait Decrypt {
    fn decrypt(data: Vec<u8>, plain_file_key: PlainFileKey) -> Result<Vec<u8>, DracoonCryptoError>;

    fn get_decrypter(plain_file_key: PlainFileKey, buffer: &mut Vec<u8>) -> Result<Crypter, DracoonCryptoError>;
}

pub struct Crypter <'b> {
    crypter: OpenSSLCrypter,
    buffer: &'b mut Vec<u8>,
    count: usize,
    plain_file_key: PlainFileKey,
    mode: Mode
}

impl <'b> Crypter<'b> {
    pub fn try_new_for_decryption(plain_file_key: PlainFileKey, buffer: &'b mut Vec<u8>) -> Result<Self, DracoonCryptoError> {
        let cipher = Cipher::aes_256_gcm();
        let key = base64::decode_block(&plain_file_key.key)?;
        let iv = base64::decode_block(&plain_file_key.iv)?;
        let tag = plain_file_key.tag.clone().ok_or(DracoonCryptoError::CrypterOperationFailed)?;
        let tag = base64::decode_block(&tag)?;

        let mut crypter = OpenSSLCrypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;

        crypter.aad_update(&[0u8; 8])?;
        crypter.set_tag(&tag)?;

        Ok(Crypter { crypter, buffer, count: 0, plain_file_key, mode: Mode::Decrypt })
    }

    pub fn try_new_for_encryption(buffer: &'b mut Vec<u8>) -> Result<Self, DracoonCryptoError> {
        let cipher = Cipher::aes_256_gcm();
        let plain_file_key = PlainFileKey::try_new_for_encryption()?;
        let key = base64::decode_block(&plain_file_key.key)?;
        let iv = base64::decode_block(&plain_file_key.iv)?;

        let mut crypter = OpenSSLCrypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;
        crypter.aad_update(&[0u8; 8])?;

        Ok(Crypter { crypter, buffer, count: 0, plain_file_key, mode: Mode::Encrypt })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<usize, DracoonCryptoError> {

        match self.crypter.update(data, &mut self.buffer[self.count..]) {
            Ok(count) => {self.count += count; Ok(count)},
            Err(_) => Err(DracoonCryptoError::CrypterOperationFailed)
        }

    }

    pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), DracoonCryptoError> {
        Ok(self.crypter.set_tag(tag)?)
    }

    pub fn finalize(&mut self) -> Result<usize, DracoonCryptoError> {

        let count = self.crypter.finalize(&mut self.buffer[self.count..])?;

        match self.mode {
            Mode::Encrypt => {
                let mut buf = [0u8; 16];
                self.crypter.get_tag(&mut buf)?; 
                let tag = base64::encode_block(&buf);
                self.plain_file_key.tag = Some(tag);
            },
            Mode::Decrypt => ()
        };

        Ok(count)
    }

    pub fn get_message(&mut self) -> &Vec<u8> {

        self.buffer.truncate(self.count);

        &self.buffer
    }

    pub fn get_plain_file_key(self) -> PlainFileKey {
        self.plain_file_key
    }

}
