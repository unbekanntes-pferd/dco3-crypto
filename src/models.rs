#![allow(non_camel_case_types)]
use openssl::base64;
use openssl::error::ErrorStack;
use openssl::rand::rand_bytes;
use openssl::symm::Mode;
use serde::{Deserialize, Serialize};
use std::str::Utf8Error;

/// Represents the version of the encrypted file key
/// Indicates which asymmetric keypair version is required
/// Standard is 4096 bit (2048 bit for compatibility only)
#[derive(Serialize, Deserialize, Debug)]
pub enum FileKeyVersion {
    #[serde(rename = "A")]
    RSA2048_AES256GCM,
    #[serde(rename = "RSA-4096/AES-256-GCM")]
    RSA4096_AES256GCM,
}

/// Represents the used cipher for the plain file key used
/// for symmetric encryption / decryption
/// Only AES256 GCM is currently used
#[derive(Serialize, Deserialize, Debug)]
pub enum PlainFileKeyVersion {
    #[serde(rename = "AES-256-GCM")]
    AES256CM,
}

/// Represents the user keypair version
/// Standard is 4096 bit (2048 bit for compatibility only)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum UserKeyPairVersion {
    #[serde(rename = "A")]
    RSA2048,
    #[serde(rename = "RSA-4096")]
    RSA4096,
}

/// Represents the encrypted file key
/// Contains key, iv and tag used for decryption
/// key, iv, and tag are base64 encoded bytes
/// The key is additonally encrypted with public keypair encryption
#[derive(Serialize, Deserialize, Debug)]
pub struct FileKey {
    pub key: String,
    pub iv: String,
    pub version: FileKeyVersion,
    pub tag: Option<String>,
}

/// Represents the encrypted file key
/// Contains key, iv and tag used for decryption
/// key, iv, and tag are base64 encoded bytes
/// key is the plain base64 encoded random bytes used
#[derive(Serialize, Deserialize, Debug)]
pub struct PlainFileKey {
    pub key: String,
    pub iv: String,
    pub version: PlainFileKeyVersion,
    pub tag: Option<String>,
}

/// Container holding only the public key used for file key encryption
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyContainer {
    pub version: UserKeyPairVersion,
    pub public_key: String,
    pub created_at: Option<String>,
    pub expire_at: Option<String>,
    pub created_by: Option<String>,
}

/// Container holding only the private key used for file key decryption
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyContainer {
    pub version: UserKeyPairVersion,
    pub private_key: String,
    pub created_at: Option<String>,
    pub expire_at: Option<String>,
    pub created_by: Option<String>,
}

/// Asymmetric user keypair container
/// The private key is protected via secret and needs to be decrypted for usage
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyPairContainer {
    pub private_key_container: PrivateKeyContainer,
    pub public_key_container: PublicKeyContainer,
}

/// Asymmetric plain user keypair container
/// The private key is in plain and can be used for decryption
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PlainUserKeyPairContainer {
    pub private_key_container: PrivateKeyContainer,
    pub public_key_container: PublicKeyContainer,
}

impl PrivateKeyContainer {
    /// Create a new private key container from PEM
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
    /// Create a new public key container from PEM
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
    /// Create a new plain user keypair container without private key encryption
    /// Accepts private and public key PEM and the desired version (4096 bit is recommended)
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

    /// Create a new plain user keypair container without private key encryption
    /// Accepts existing encrypted keypair and a plain private key PEM
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
    /// Create a plain file key used for symmetric encryption / decryption (AES256 GCM)
    /// Accepts the encrypted file key and the plain file key (base64 encoded)
    /// Returns the plain file key
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

/// Possible states of rescue keys in a room
#[derive(Serialize, Debug)]
pub enum KeyState {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "available")]
    Available,
    #[serde(rename = "pending")]
    Pending,
}

/// Represents the state of the rescue keys in a room
#[derive(Serialize, Debug)]
pub struct EncryptionInfo {
    user_key_state: KeyState,
    room_key_state: KeyState,
    dataspace_key_state: KeyState,
}

#[derive(Debug)]
pub enum DracoonCryptoError {
    RsaOperationFailed,
    RsaImportFailed,
    ByteParseError,
    CrypterOperationFailed(String),
    InvalidKeypairVersion,
    BadData,
    InvalidFileKeyFormat(String),
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

/// Trait to get only the public key container of either a public key
/// or a user keypair container
pub trait PublicKey {
    fn get_public_key(&self) -> &PublicKeyContainer;
}

/// Returns only the public key container as reference of a plain
/// user keypair container
impl PublicKey for PlainUserKeyPairContainer {
    fn get_public_key(&self) -> &PublicKeyContainer {
        &self.public_key_container
    }
}

/// Returns the public key of a public key container as reference
impl PublicKey for PublicKeyContainer {
    fn get_public_key(&self) -> &PublicKeyContainer {
        self
    }
}

/// Trait representing all functions required for asymmetric encryption
/// - generate a new (plain) keypair
/// - encrypt / decrypt the private key of a keypair
/// - encrypt a file key using the public key of a keypair
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

    fn decrypt_private_key_only(
        secret: &str,
        plain_private_key: PrivateKeyContainer,
    ) -> Result<PrivateKeyContainer, DracoonCryptoError>;

    fn encrypt_file_key(
        plain_file_key: PlainFileKey,
        public_key: impl PublicKey,
    ) -> Result<FileKey, DracoonCryptoError>;

    fn decrypt_file_key(
        file_key: FileKey,
        keypair: PlainUserKeyPairContainer,
    ) -> Result<PlainFileKey, DracoonCryptoError>;
}

/// Trait representing necessary functions for symmetric encryption
/// - encrypt on the fly
/// - return an encrypter for chunked encryption
pub trait Encrypt {
    fn encrypt(data: impl AsRef<[u8]>) -> Result<EncryptionResult, DracoonCryptoError>;
}

/// Trait representing necessary functions for symmetric decryption
/// - decrypt on the fly
/// - return a decrypter for chunked decryption
pub trait Decrypt {
    fn decrypt(
        data: &impl AsRef<[u8]>,
        plain_file_key: PlainFileKey,
    ) -> Result<Vec<u8>, DracoonCryptoError>;
}

pub struct Open;
pub struct Finalized;

/// Allows chunked en- and decryption.
/// Holds a reference to a buffer to store the mssage, processed bytes as count and
/// the used plain file key and mode.
/// Requires generic type annotation
/// The type 'C' represents an internal handler for the encryption functions with chunking
pub struct Crypter<'b, C, State = Open> {
    // this is a generic type representing the internal handler for chunked encryption
    // example implementation see lib.rs for openssl Crypter
    pub crypter: C,
    pub buffer: &'b mut Vec<u8>,
    pub count: usize,
    pub plain_file_key: PlainFileKey,
    pub mode: Mode,
    pub state: std::marker::PhantomData<State>
}

/// Represents methods to return an enrypter over a generic internal C
/// See usage of Crypter and relevant chunked encryption for Crypter<OpenSslCrypter)
pub trait Encrypter<C> {
    /// Returns an encrypter by passing a mutable buffer to write the encrypted message to
    fn encrypter(buffer: &mut Vec<u8>) -> Result<Crypter<C>, DracoonCryptoError>;
}

/// Represents methods to return a decrypter over a generic internal C
/// See usage of Crypter and relevant chunked encryption for Crypter<OpenSslCrypter)
pub trait Decrypter<C> {
    /// Returns a decrypter by passing the plain file key used for the file
    /// and a mutable buffer to write the plain message to
    fn decrypter(
        plain_file_key: PlainFileKey,
        buffer: &mut Vec<u8>,
    ) -> Result<Crypter<C>, DracoonCryptoError>;
}

/// Represents all functions required for a Crypter to perform chunked encryption / decryption
pub trait ChunkedEncryption<'b, C> {
    /// Finalize decryption / encryption
    fn finalize(&mut self) -> Result<usize, DracoonCryptoError>;
    /// Get the message (result of encryption / decryption) from buffer
    fn get_message(&mut self) -> &Vec<u8>;
    /// Get the plain file key used for either encryption or decryption
    fn get_plain_file_key(self) -> PlainFileKey;
    /// Set the tag before finalizing the encryption
    fn set_tag(&mut self, tag: &[u8]) -> Result<(), DracoonCryptoError>;
    /// Returns a Crypter for decryption by passing the plain file key and a writable (mutable) buffer
    fn try_new_for_decryption(
        plain_file_key: PlainFileKey,
        buffer: &'b mut Vec<u8>,
    ) -> Result<Crypter<C>, DracoonCryptoError>;
    /// Returns a Crypter for enryption by passing a writable (mutable) buffer
    fn try_new_for_encryption(buffer: &'b mut Vec<u8>) -> Result<Crypter<C>, DracoonCryptoError>;
    /// Update the Crypter with given data
    fn update(&mut self, data: &[u8]) -> Result<usize, DracoonCryptoError>;
}
