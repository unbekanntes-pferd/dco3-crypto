//! # dco3-crypto
//!
//! `dco3-crypto` implements the DRACOON crypto protocol.
//!
//! Files are encrypted with AES-256-GCM and a fresh file key per file.
//! User key pairs use RSA-4096 by default. The public key wraps the file key and the private
//! key unwraps it again.
//!
//! # Examples
//!
//! One-shot file encryption:
//!
//! ```
//! use dco3_crypto::{Decrypt, DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};
//!
//! let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
//! let plaintext = b"hello DRACOON";
//!
//! let (ciphertext, file_key) = DracoonCrypto::encrypt(plaintext, keypair.clone()).unwrap();
//! let decrypted = DracoonCrypto::decrypt(&ciphertext, file_key, keypair).unwrap();
//!
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! Streaming file encryption:
//!
//! ```
//! use dco3_crypto::{Decrypt, DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};
//!
//! let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
//! let mut encryptor = DracoonCrypto::file_encryptor(keypair.clone()).unwrap();
//! let mut ciphertext = Vec::new();
//!
//! ciphertext.extend_from_slice(&encryptor.update(b"hello ").unwrap());
//! ciphertext.extend_from_slice(&encryptor.update(b"DRACOON").unwrap());
//! let finalized = encryptor.finalize().unwrap();
//! ciphertext.extend_from_slice(&finalized.final_chunk);
//!
//! let mut decryptor = DracoonCrypto::file_decryptor(finalized.file_key, keypair).unwrap();
//! let mut plaintext = Vec::new();
//! plaintext.extend_from_slice(&decryptor.update(&ciphertext[..3]).unwrap());
//! plaintext.extend_from_slice(&decryptor.update(&ciphertext[3..]).unwrap());
//! plaintext.extend_from_slice(&decryptor.finalize().unwrap());
//!
//! assert_eq!(plaintext, b"hello DRACOON");
//! ```

use openssl::base64;
use openssl::md::Md;
use openssl::pkey::{PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter as OpenSslCrypter, Mode};

use tracing::{debug, error};

mod models;

pub use models::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum StreamingMode {
    Encrypt,
    Decrypt,
}

struct OpenSslFileCrypter {
    crypter: OpenSslCrypter,
    cipher: Cipher,
    plain_file_key: PlainFileKey,
    mode: StreamingMode,
}

/// Result returned by [`FileEncryptor::finalize`].
pub struct StreamingEncryptionResult {
    /// Final ciphertext bytes emitted during `finalize`.
    pub final_chunk: Vec<u8>,
    /// Wrapped file key required for decryption.
    pub file_key: FileKey,
}

/// Incremental file encryptor for AES-256-GCM file content.
///
/// The file key is generated internally and is only exposed as wrapped [`FileKey`] data when the
/// stream is finalized.
pub struct FileEncryptor {
    inner: OpenSslFileCrypter,
    public_key: PublicKeyContainer,
}

/// Incremental file decryptor for AES-256-GCM file content.
///
/// The plain file key is resolved internally from the wrapped [`FileKey`].
pub struct FileDecryptor {
    inner: OpenSslFileCrypter,
}

/// OpenSSL-backed implementation of the DRACOON crypto protocol.
pub struct DracoonCrypto;

impl DracoonCrypto {
    /// Creates a streaming encryptor for file content.
    ///
    /// A fresh file key is generated internally. Call [`FileEncryptor::finalize`] to receive the
    /// wrapped [`FileKey`] for transport or storage.
    ///
    /// # Examples
    ///
    /// ```
    /// use dco3_crypto::{Decrypt, DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};
    ///
    /// let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let mut encryptor = DracoonCrypto::file_encryptor(keypair.clone()).unwrap();
    /// let mut ciphertext = Vec::new();
    ///
    /// ciphertext.extend_from_slice(&encryptor.update(b"part one ").unwrap());
    /// ciphertext.extend_from_slice(&encryptor.update(b"part two").unwrap());
    /// let finalized = encryptor.finalize().unwrap();
    /// ciphertext.extend_from_slice(&finalized.final_chunk);
    ///
    /// let plaintext = DracoonCrypto::decrypt(&ciphertext, finalized.file_key, keypair).unwrap();
    /// assert_eq!(plaintext, b"part one part two");
    /// ```
    pub fn file_encryptor(public_key: impl PublicKey) -> Result<FileEncryptor, DracoonCryptoError> {
        Ok(FileEncryptor {
            inner: OpenSslFileCrypter::new_for_encryption()?,
            public_key: public_key.get_public_key().clone(),
        })
    }

    /// Creates a streaming decryptor for file content.
    ///
    /// The wrapped [`FileKey`] is unwrapped internally with the provided private key before
    /// AES-256-GCM decryption starts.
    ///
    /// # Examples
    ///
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};
    ///
    /// let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let plaintext = b"hello from DRACOON";
    /// let (ciphertext, file_key) = DracoonCrypto::encrypt(plaintext, keypair.clone()).unwrap();
    ///
    /// let mut decryptor = DracoonCrypto::file_decryptor(file_key, keypair).unwrap();
    /// let mut decrypted = Vec::new();
    /// decrypted.extend_from_slice(&decryptor.update(&ciphertext[..5]).unwrap());
    /// decrypted.extend_from_slice(&decryptor.update(&ciphertext[5..]).unwrap());
    /// decrypted.extend_from_slice(&decryptor.finalize().unwrap());
    ///
    /// assert_eq!(decrypted, plaintext);
    /// ```
    pub fn file_decryptor(
        file_key: FileKey,
        private_key: impl PrivateKey,
    ) -> Result<FileDecryptor, DracoonCryptoError> {
        let plain_file_key = Self::decrypt_file_key(file_key, private_key)?;
        Ok(FileDecryptor {
            inner: OpenSslFileCrypter::new_for_decryption(plain_file_key)?,
        })
    }

    #[cfg(test)]
    fn encrypt_with_plain_file_key(
        data: &[u8],
        plain_file_key: PlainFileKey,
    ) -> Result<(Vec<u8>, PlainFileKey), DracoonCryptoError> {
        let mut crypter = OpenSslFileCrypter::new_for_encryption_with_key(plain_file_key)?;
        let mut out = crypter.update(data)?;
        out.extend_from_slice(&crypter.finalize()?);
        Ok((out, crypter.plain_file_key))
    }

    #[cfg(test)]
    fn decrypt_with_plain_file_key(
        data: &[u8],
        plain_file_key: PlainFileKey,
    ) -> Result<Vec<u8>, DracoonCryptoError> {
        let mut crypter = OpenSslFileCrypter::new_for_decryption(plain_file_key)?;
        let mut out = crypter.update(data)?;
        out.extend_from_slice(&crypter.finalize()?);
        Ok(out)
    }

    /// Decodes base64-encoded file key material and maps parse failures to a domain error.
    fn decode_key_material(value: &str, label: &str) -> Result<Vec<u8>, DracoonCryptoError> {
        base64::decode_block(value)
            .map_err(|_| DracoonCryptoError::InvalidFileKeyFormat(format!("Cannot parse {label}.")))
    }

    /// Builds password candidates for encrypted PKCS#8 private keys.
    ///
    /// DRACOON fixtures require UTF-8 first and ISO-8859-1 fallback for legacy compatibility.
    fn password_candidates(secret: &str) -> Vec<Vec<u8>> {
        let utf8 = secret.as_bytes().to_vec();
        let mut candidates = vec![utf8.clone()];

        if let Some(iso) = iso_8859_1_bytes(secret) {
            if iso != utf8 {
                candidates.push(iso);
            }
        }

        candidates
    }

    /// Imports an encrypted private key with the supported password encodings.
    fn decrypt_private_key_pkey(
        private_key_pem: &[u8],
        secret: &str,
    ) -> Result<PKey<Private>, DracoonCryptoError> {
        let mut last_error = DracoonCryptoError::RsaOperationFailed;

        for candidate in Self::password_candidates(secret) {
            match PKey::private_key_from_pem_passphrase(private_key_pem, &candidate) {
                Ok(key) => return Ok(key),
                Err(_) => {
                    last_error = DracoonCryptoError::RsaOperationFailed;
                }
            }
        }

        Err(last_error)
    }

}

impl FileEncryptor {
    /// Encrypts one chunk and returns the produced ciphertext bytes.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, DracoonCryptoError> {
        self.inner.update(data)
    }

    /// Finalizes the stream and returns the last ciphertext bytes plus the wrapped file key.
    pub fn finalize(mut self) -> Result<StreamingEncryptionResult, DracoonCryptoError> {
        let final_chunk = self.inner.finalize()?;
        let file_key =
            DracoonCrypto::encrypt_file_key(self.inner.plain_file_key.clone(), self.public_key)?;

        Ok(StreamingEncryptionResult {
            final_chunk,
            file_key,
        })
    }
}

impl FileDecryptor {
    /// Decrypts one chunk and returns the produced plaintext bytes.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, DracoonCryptoError> {
        self.inner.update(data)
    }

    /// Finalizes the stream and returns the last plaintext bytes.
    pub fn finalize(mut self) -> Result<Vec<u8>, DracoonCryptoError> {
        self.inner.finalize()
    }
}

impl OpenSslFileCrypter {
    /// Creates an encrypting AES-256-GCM crypter with a fresh file key.
    fn new_for_encryption() -> Result<Self, DracoonCryptoError> {
        Self::new_for_encryption_with_key(PlainFileKey::try_new_for_encryption()?)
    }

    /// Creates an encrypting AES-256-GCM crypter with existing file key material.
    ///
    /// Internal tests use this to compare chunking behavior with deterministic key material.
    fn new_for_encryption_with_key(
        plain_file_key: PlainFileKey,
    ) -> Result<Self, DracoonCryptoError> {
        let cipher = Cipher::aes_256_gcm();
        let key = DracoonCrypto::decode_key_material(&plain_file_key.key, "key")?;
        let iv = DracoonCrypto::decode_key_material(&plain_file_key.iv, "iv")?;

        let mut crypter =
            OpenSslCrypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).map_err(|e| {
                error!("Initializing encrypting Crypter failed.");
                debug!("{:?}", e);
                DracoonCryptoError::CrypterOperationFailed(
                    "Initializing Crypter failed.".to_string(),
                )
            })?;

        crypter.aad_update(b"").map_err(|e| {
            error!("Skipping AAD failed during encryption setup.");
            debug!("{:?}", e);
            DracoonCryptoError::CrypterOperationFailed("Skipping AAD failed.".to_string())
        })?;

        Ok(Self {
            crypter,
            cipher,
            plain_file_key,
            mode: StreamingMode::Encrypt,
        })
    }

    /// Creates a decrypting AES-256-GCM crypter from resolved file key material.
    fn new_for_decryption(plain_file_key: PlainFileKey) -> Result<Self, DracoonCryptoError> {
        let cipher = Cipher::aes_256_gcm();
        let key = DracoonCrypto::decode_key_material(&plain_file_key.key, "key")?;
        let iv = DracoonCrypto::decode_key_material(&plain_file_key.iv, "iv")?;
        let tag = plain_file_key
            .tag
            .clone()
            .ok_or_else(|| DracoonCryptoError::InvalidFileKeyFormat("Invalid tag.".to_string()))?;
        let tag = DracoonCrypto::decode_key_material(&tag, "tag")?;

        let mut crypter =
            OpenSslCrypter::new(cipher, Mode::Decrypt, &key, Some(&iv)).map_err(|e| {
                error!("Initializing decrypting Crypter failed.");
                debug!("{:?}", e);
                DracoonCryptoError::CrypterOperationFailed(
                    "Initializing Crypter failed.".to_string(),
                )
            })?;

        crypter.aad_update(b"").map_err(|e| {
            error!("Skipping AAD failed during decryption setup.");
            debug!("{:?}", e);
            DracoonCryptoError::CrypterOperationFailed("Skipping AAD failed.".to_string())
        })?;

        crypter.set_tag(&tag).map_err(|e| {
            error!("Setting tag failed during decryption setup.");
            debug!("{:?}", e);
            DracoonCryptoError::CrypterOperationFailed("Setting tag failed.".to_string())
        })?;

        Ok(Self {
            crypter,
            cipher,
            plain_file_key,
            mode: StreamingMode::Decrypt,
        })
    }

    /// Processes one chunk and returns the produced bytes.
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, DracoonCryptoError> {
        let mut out = vec![0u8; data.len() + self.cipher.block_size()];
        let count = self.crypter.update(data, &mut out).map_err(|e| {
            error!("Updating Crypter failed.");
            debug!("{:?}", e);
            DracoonCryptoError::CrypterOperationFailed("Updating buffer failed.".to_string())
        })?;
        out.truncate(count);
        Ok(out)
    }

    /// Finalizes the crypter and stores the GCM tag on encrypt.
    fn finalize(&mut self) -> Result<Vec<u8>, DracoonCryptoError> {
        let mut out = vec![0u8; self.cipher.block_size()];
        let count = self.crypter.finalize(&mut out).map_err(|e| {
            error!("Finalizing Crypter failed.");
            debug!("{:?}", e);
            DracoonCryptoError::CrypterOperationFailed("Finalizing Crypter failed.".to_string())
        })?;
        out.truncate(count);

        if self.mode == StreamingMode::Encrypt {
            let mut tag = [0u8; 16];
            self.crypter.get_tag(&mut tag).map_err(|e| {
                error!("Getting tag failed.");
                debug!("{:?}", e);
                DracoonCryptoError::CrypterOperationFailed("Getting tag failed.".to_string())
            })?;
            self.plain_file_key.set_tag(base64::encode_block(&tag));
        }

        Ok(out)
    }
}

impl DracoonRSACrypto for DracoonCrypto {
    fn create_plain_user_keypair(
        version: UserKeyPairVersion,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError> {
        let bits = match version {
            UserKeyPairVersion::RSA2048 => 2048,
            UserKeyPairVersion::RSA4096 => 4096,
        };

        let rsa = Rsa::generate(bits)?;
        let private_key_pem = rsa
            .private_key_to_pem()
            .iter()
            .flat_map(|buf| std::str::from_utf8(buf))
            .collect::<String>();
        let public_key_pem = rsa
            .public_key_to_pem()
            .iter()
            .flat_map(|buf| std::str::from_utf8(buf))
            .collect::<String>();

        debug!("Keypair (version: {:?}) generated.", version);

        Ok(PlainUserKeyPairContainer::new(
            private_key_pem,
            public_key_pem,
            version,
        ))
    }

    fn encrypt_private_key(
        secret: &str,
        plain_keypair: PlainUserKeyPairContainer,
    ) -> Result<UserKeyPairContainer, DracoonCryptoError> {
        if plain_keypair.private_key_container.version != plain_keypair.public_key_container.version
        {
            return Err(DracoonCryptoError::InvalidKeypairVersion);
        }

        let secret = secret.as_bytes();
        let private_key_pem = plain_keypair.private_key_container.private_key.as_bytes();

        let private_key_pem = Rsa::private_key_from_pem(private_key_pem)?
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), secret)?;
        let private_key_pem = std::str::from_utf8(&private_key_pem)?.to_string();

        debug!(
            "Keypair (private key version: {:?}) encrypted.",
            plain_keypair.private_key_container.version
        );

        Ok(UserKeyPairContainer::new_from_plain_keypair(
            plain_keypair,
            &private_key_pem,
        ))
    }

    fn decrypt_keypair(
        secret: &str,
        keypair: UserKeyPairContainer,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError> {
        if keypair.private_key_container.version != keypair.public_key_container.version {
            return Err(DracoonCryptoError::InvalidKeypairVersion);
        }

        let private_key_pem = keypair.private_key_container.private_key.as_bytes();

        let rsa = Self::decrypt_private_key_pkey(private_key_pem, secret)?.rsa()?;
        let private_key_pem = rsa
            .private_key_to_pem()
            .iter()
            .flat_map(|buf| std::str::from_utf8(buf))
            .collect::<String>();

        debug!(
            "Keypair (private key version: {:?}) decrypted.",
            keypair.private_key_container.version
        );

        Ok(PlainUserKeyPairContainer::new_from_keypair(
            keypair,
            &private_key_pem,
        ))
    }

    fn decrypt_private_key(
        secret: &str,
        private_key: &PrivateKeyContainer,
    ) -> Result<PrivateKeyContainer, DracoonCryptoError> {
        let private_key_pem = private_key.private_key.as_bytes();

        let rsa = Self::decrypt_private_key_pkey(private_key_pem, secret)?.rsa()?;
        let private_key_pem = rsa
            .private_key_to_pem()
            .iter()
            .flat_map(|buf| std::str::from_utf8(buf))
            .collect::<String>();

        Ok(PrivateKeyContainer::new(
            private_key_pem,
            private_key.version.clone(),
        ))
    }

    fn encrypt_file_key(
        plain_file_key: PlainFileKey,
        public_key: impl PublicKey,
    ) -> Result<FileKey, DracoonCryptoError> {
        let public_key = public_key.get_public_key();
        let public_key_pem = public_key.public_key.as_bytes();
        let rsa = Rsa::public_key_from_pem(public_key_pem)
            .map_err(|_| DracoonCryptoError::RsaImportFailed)?;
        let pkey = PKey::from_rsa(rsa).map_err(|_| DracoonCryptoError::RsaImportFailed)?;

        let file_key = DracoonCrypto::decode_key_material(&plain_file_key.key, "key")?;

        let file_key_version = match public_key.version {
            UserKeyPairVersion::RSA2048 => FileKeyVersion::RSA2048_AES256GCM,
            UserKeyPairVersion::RSA4096 => FileKeyVersion::RSA4096_AES256GCM,
        };

        let mut key_ctx = PkeyCtx::new(&pkey)?;
        let mgf1_md = match public_key.version {
            UserKeyPairVersion::RSA2048 => Md::sha1(),
            UserKeyPairVersion::RSA4096 => Md::sha256(),
        };

        key_ctx.encrypt_init()?;
        key_ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        key_ctx.set_rsa_oaep_md(Md::sha256())?;
        key_ctx.set_rsa_mgf1_md(mgf1_md)?;

        let mut buf = Vec::new();
        key_ctx.encrypt_to_vec(&file_key, &mut buf)?;

        Ok(FileKey::new_from_plain_key(
            plain_file_key,
            &base64::encode_block(&buf),
            file_key_version,
        ))
    }

    fn decrypt_file_key(
        file_key: FileKey,
        private_key: impl PrivateKey,
    ) -> Result<PlainFileKey, DracoonCryptoError> {
        let private_key = private_key.get_private_key();
        let compatible = matches!(
            (&file_key.version, &private_key.version),
            (
                FileKeyVersion::RSA2048_AES256GCM,
                UserKeyPairVersion::RSA2048
            ) | (
                FileKeyVersion::RSA4096_AES256GCM,
                UserKeyPairVersion::RSA4096
            )
        );
        if !compatible {
            return Err(DracoonCryptoError::InvalidKeypairVersion);
        }

        let private_key_pem = private_key.private_key.as_bytes();
        let rsa = Rsa::private_key_from_pem(private_key_pem)
            .map_err(|_| DracoonCryptoError::RsaImportFailed)?;
        let pkey = PKey::from_rsa(rsa).map_err(|_| DracoonCryptoError::RsaImportFailed)?;

        let enc_file_key = DracoonCrypto::decode_key_material(&file_key.key, "key")?;

        let mut key_ctx = PkeyCtx::new(&pkey)?;
        let mgf1_md = match private_key.version {
            UserKeyPairVersion::RSA2048 => Md::sha1(),
            UserKeyPairVersion::RSA4096 => Md::sha256(),
        };

        key_ctx.decrypt_init()?;
        key_ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        key_ctx.set_rsa_oaep_md(Md::sha256())?;
        key_ctx.set_rsa_mgf1_md(mgf1_md)?;

        let mut buf = Vec::new();
        key_ctx.decrypt_to_vec(&enc_file_key, &mut buf)?;

        Ok(PlainFileKey::new_from_file_key(
            file_key,
            &base64::encode_block(&buf),
        ))
    }
}

impl Encrypt for DracoonCrypto {
    /// Encrypts file content in one shot with a fresh internal file key.
    fn encrypt(
        data: impl AsRef<[u8]>,
        public_key: impl PublicKey,
    ) -> Result<EncryptionResult, DracoonCryptoError> {
        let mut encryptor = Self::file_encryptor(public_key)?;
        let mut encrypted = encryptor.update(data.as_ref())?;
        let final_result = encryptor.finalize()?;
        encrypted.extend_from_slice(&final_result.final_chunk);

        Ok((encrypted, final_result.file_key))
    }
}

impl Decrypt for DracoonCrypto {
    /// Decrypts file content in one shot with the wrapped file key and private key.
    fn decrypt(
        data: &impl AsRef<[u8]>,
        file_key: FileKey,
        private_key: impl PrivateKey,
    ) -> Result<Vec<u8>, DracoonCryptoError> {
        let mut decryptor = Self::file_decryptor(file_key, private_key)?;
        let mut plain = decryptor.update(data.as_ref())?;
        plain.extend_from_slice(&decryptor.finalize()?);
        Ok(plain)
    }
}

/// Converts a Rust `str` to ISO-8859-1 bytes when every code point fits into one byte.
fn iso_8859_1_bytes(secret: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(secret.len());

    for ch in secret.chars() {
        let value = ch as u32;
        if value > u8::MAX as u32 {
            return None;
        }
        out.push(value as u8);
    }

    Some(out)
}

#[cfg(test)]
mod tests;
