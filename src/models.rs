#![allow(non_camel_case_types)]
use openssl::base64;
use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};
use std::str::Utf8Error;

/// Version of the wrapped file key.
///
/// The value encodes the required RSA key pair version together with AES-256-GCM as the file
/// content cipher.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum FileKeyVersion {
    #[serde(rename = "A")]
    RSA2048_AES256GCM,
    #[serde(rename = "RSA-4096/AES-256-GCM")]
    RSA4096_AES256GCM,
}

/// Version of the plain file key.
///
/// DRACOON currently uses AES-256-GCM only.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum PlainFileKeyVersion {
    #[serde(rename = "AES-256-GCM")]
    AES256CM,
}

/// Version of the user key pair.
///
/// RSA-4096 is the default. RSA-2048 is kept for compatibility.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum UserKeyPairVersion {
    #[serde(rename = "A")]
    RSA2048,
    #[serde(rename = "RSA-4096")]
    RSA4096,
}

/// Wrapped file key used to decrypt AES-256-GCM file content.
///
/// `key`, `iv`, and `tag` are base64-encoded. `key` is wrapped with the receiver's public key.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileKey {
    pub key: String,
    pub iv: String,
    pub version: FileKeyVersion,
    pub tag: Option<String>,
}

/// Plain file key used for AES-256-GCM file content encryption and decryption.
///
/// `key`, `iv`, and `tag` are base64-encoded.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PlainFileKey {
    pub key: String,
    pub iv: String,
    pub version: PlainFileKeyVersion,
    pub tag: Option<String>,
}

/// Public key container used to wrap file keys.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyContainer {
    pub version: UserKeyPairVersion,
    pub public_key: String,
    pub created_at: Option<String>,
    pub expire_at: Option<String>,
    pub created_by: Option<u64>,
}

/// Private key container used to unwrap file keys.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyContainer {
    pub version: UserKeyPairVersion,
    pub private_key: String,
    pub created_at: Option<String>,
    pub expire_at: Option<String>,
    pub created_by: Option<u64>,
}

/// Encrypted user key pair container.
///
/// The private key is protected with a passphrase.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyPairContainer {
    pub private_key_container: PrivateKeyContainer,
    pub public_key_container: PublicKeyContainer,
}

/// Plain user key pair container.
///
/// The private key is unencrypted and ready for cryptographic operations.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlainUserKeyPairContainer {
    pub private_key_container: PrivateKeyContainer,
    pub public_key_container: PublicKeyContainer,
}

impl PrivateKeyContainer {
    /// Creates a private key container from a PEM-encoded private key.
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
    /// Creates a public key container from a PEM-encoded public key.
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
    /// Creates a plain user key pair container from PEM-encoded key material.
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

    /// Rebuilds a plain user key pair container from an encrypted key pair and decrypted private
    /// key PEM.
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
    /// Rebuilds an encrypted user key pair container from a plain key pair and encrypted private
    /// key PEM.
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
    /// Creates a wrapped file key from plain file key material and wrapped key bytes.
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
    /// Creates plain file key material from a wrapped file key and base64-encoded key bytes.
    pub fn new_from_file_key(enc_file_key: FileKey, plain_file_key: &str) -> Self {
        Self {
            key: plain_file_key.to_string(),
            iv: enc_file_key.iv,
            tag: enc_file_key.tag,
            version: PlainFileKeyVersion::AES256CM,
        }
    }

    /// Creates fresh random file key material for AES-256-GCM encryption.
    pub(crate) fn try_new_for_encryption() -> Result<Self, DracoonCryptoError> {
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

    /// Stores the GCM authentication tag on the file key.
    pub fn set_tag(&mut self, tag: String) {
        self.tag = Some(tag);
    }
}

/// State of rescue keys in a room.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Debug, Clone, PartialEq)]
pub enum KeyState {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "available")]
    Available,
    #[serde(rename = "pending")]
    Pending,
}

/// Rescue-key state for a room.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct EncryptionInfo {
    user_key_state: KeyState,
    room_key_state: KeyState,
    dataspace_key_state: KeyState,
}

/// Errors returned by the DRACOON crypto API.
#[derive(Debug, Clone, PartialEq)]
pub enum DracoonCryptoError {
    /// RSA encryption or decryption failed.
    RsaOperationFailed,
    /// RSA key import failed.
    RsaImportFailed,
    /// Byte-to-string conversion failed.
    ByteParseError,
    /// OpenSSL crypter setup or processing failed.
    CrypterOperationFailed(String),
    /// RSA key pair versions do not match the requested operation.
    InvalidKeypairVersion,
    /// OpenSSL returned invalid data.
    BadData,
    /// Wrapped file key data is malformed.
    InvalidFileKeyFormat(String),
    /// Tag validation failed.
    InvalidTag,
    /// Fallback error for unmapped failures.
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

/// Result of one-shot file encryption.
///
/// The tuple contains `(ciphertext, wrapped_file_key)`.
pub type EncryptionResult = (Vec<u8>, FileKey);

/// Exposes a public key container.
pub trait PublicKey {
    /// Returns the public key container.
    fn get_public_key(&self) -> &PublicKeyContainer;
}

/// Exposes a private key container.
pub trait PrivateKey {
    /// Returns the private key container.
    fn get_private_key(&self) -> &PrivateKeyContainer;
}

/// Exposes the public key container of a plain user key pair.
impl PublicKey for PlainUserKeyPairContainer {
    fn get_public_key(&self) -> &PublicKeyContainer {
        &self.public_key_container
    }
}

/// Exposes the public key container directly.
impl PublicKey for PublicKeyContainer {
    fn get_public_key(&self) -> &PublicKeyContainer {
        self
    }
}

/// Exposes the private key container of a plain user key pair.
impl PrivateKey for PlainUserKeyPairContainer {
    fn get_private_key(&self) -> &PrivateKeyContainer {
        &self.private_key_container
    }
}

/// Exposes the private key container directly.
impl PrivateKey for PrivateKeyContainer {
    fn get_private_key(&self) -> &PrivateKeyContainer {
        self
    }
}

/// Asymmetric DRACOON crypto operations.
pub trait DracoonRSACrypto {
    /// Generates a plain user key pair.
    ///
    /// # Examples
    ///
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};
    ///
    /// let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// assert!(keypair.private_key_container.private_key.contains("BEGIN RSA PRIVATE KEY"));
    /// assert!(keypair.public_key_container.public_key.contains("BEGIN PUBLIC KEY"));
    /// ```
    fn create_plain_user_keypair(
        version: UserKeyPairVersion,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError>;

    /// Encrypts the private key of a user key pair with a passphrase.
    ///
    /// # Examples
    ///
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};
    ///
    /// let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let encrypted = DracoonCrypto::encrypt_private_key("secret", keypair).unwrap();
    ///
    /// assert!(encrypted.private_key_container.private_key.contains("BEGIN ENCRYPTED PRIVATE KEY"));
    /// ```
    fn encrypt_private_key(
        secret: &str,
        plain_keypair: PlainUserKeyPairContainer,
    ) -> Result<UserKeyPairContainer, DracoonCryptoError>;

    /// Decrypts an encrypted user key pair with the passphrase.
    fn decrypt_keypair(
        secret: &str,
        keypair: UserKeyPairContainer,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError>;

    /// Decrypts only the private key container with the passphrase.
    fn decrypt_private_key(
        secret: &str,
        plain_private_key: &PrivateKeyContainer,
    ) -> Result<PrivateKeyContainer, DracoonCryptoError>;

    /// Wraps a plain file key with the public key.
    fn encrypt_file_key(
        plain_file_key: PlainFileKey,
        public_key: impl PublicKey,
    ) -> Result<FileKey, DracoonCryptoError>;

    /// Unwraps a file key with the private key.
    fn decrypt_file_key(
        file_key: FileKey,
        keypair: impl PrivateKey,
    ) -> Result<PlainFileKey, DracoonCryptoError>;
}

/// Symmetric file encryption.
pub trait Encrypt {
    /// Encrypts file content in one shot with a fresh internal file key.
    ///
    /// # Examples
    ///
    /// ```
    /// use dco3_crypto::{Decrypt, DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};
    ///
    /// let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let (ciphertext, file_key) = DracoonCrypto::encrypt(b"hello DRACOON", keypair.clone()).unwrap();
    /// let decrypted = DracoonCrypto::decrypt(&ciphertext, file_key, keypair).unwrap();
    ///
    /// assert_eq!(decrypted, b"hello DRACOON");
    /// ```
    fn encrypt(
        data: impl AsRef<[u8]>,
        public_key: impl PublicKey,
    ) -> Result<EncryptionResult, DracoonCryptoError>;
}

/// Symmetric file decryption.
pub trait Decrypt {
    /// Decrypts file content in one shot with the wrapped file key and private key.
    ///
    /// # Examples
    ///
    /// ```
    /// use dco3_crypto::{Decrypt, DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};
    ///
    /// let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let (ciphertext, file_key) = DracoonCrypto::encrypt(b"hello DRACOON", keypair.clone()).unwrap();
    /// let decrypted = DracoonCrypto::decrypt(&ciphertext, file_key, keypair).unwrap();
    ///
    /// assert_eq!(decrypted, b"hello DRACOON");
    /// ```
    fn decrypt(
        data: &impl AsRef<[u8]>,
        file_key: FileKey,
        private_key: impl PrivateKey,
    ) -> Result<Vec<u8>, DracoonCryptoError>;
}
