#![allow(non_camel_case_types, dead_code)]
use serde::Serialize;

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

#[derive(Serialize)]
pub enum UserKeyPairVersion {
    #[serde(rename = "A")]
    RSA2048,
    #[serde(rename = "RSA-4096")]
    RSA4096,
}

#[derive(Serialize)]
pub struct FileKey<'a> {
    key: &'a str,
    iv: &'a str,
    version: FileKeyVersion,
    tag: Option<&'a str>,
}

#[derive(Serialize)]
pub struct PlainFileKey<'a> {
    key: &'a str,
    iv: &'a str,
    version: PlainFileKeyVersion,
    tag: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyContainer<'a> {
    version: UserKeyPairVersion,
    public_key: &'a str,
    created_at: &'a str,
    expire_at: &'a str,
    created_by: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyContainer<'a> {
    version: UserKeyPairVersion,
    private_key: &'a str,
    created_at: &'a str,
    expire_at: &'a str,
    created_by: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyPairContainer<'a> {
    private_key_container: PrivateKeyContainer<'a>,
    public_key_container: PublicKeyContainer<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlainUserKeyPairContainer<'a> {
    private_key_container: PrivateKeyContainer<'a>,
    public_key_container: PublicKeyContainer<'a>,
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

pub enum DracoonCryptoError {
    InvalidKeypairVersion,
    InvalidTag,
    Unknown
}

pub trait DracoonRSACrypto<'a> {
    fn create_plain_user_keypair() -> PlainUserKeyPairContainer<'a>;

    fn encrypt_private_key(secret: &str, plain_keypair: PlainUserKeyPairContainer) -> UserKeyPairContainer<'a>;

    fn decrypt_prviate_key(secret: &str, keypair: UserKeyPairContainer) -> PlainUserKeyPairContainer<'a>;

    fn encrypt_file_key_public(plain_file_key: PlainFileKey, public_key: PublicKeyContainer) -> FileKey<'a>;

    fn encrypt_file_key(plain_file_key: PlainFileKey, keypair: PlainUserKeyPairContainer) -> FileKey<'a>;

    fn get_file_key_version_public(public_key: &PublicKeyContainer) -> FileKeyVersion;

    fn get_file_key_version(keypair: &PlainUserKeyPairContainer) -> FileKeyVersion;

}

pub trait DracoonEncrypt {
    fn encrypt_bytes<'a>(data: Vec<u8>) -> (Vec<u8>, PlainFileKey<'a>);

    fn encrypt_bytes_in_chunks<'a>(data: Vec<u8>) -> (Vec<u8>, PlainFileKey<'a>);
}

pub trait DracoonDecrypt {
    fn decrypt_bytes(data: Vec<u8>, plain_file_key: PlainFileKey) -> Vec<u8>;

    fn decrypt_bytes_in_chunks(data: Vec<u8>, plain_file_key: PlainFileKey) -> Vec<u8>;
}