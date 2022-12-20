//! # dco3-crypto
//!
//! `dco3-crypto` is a wrapper around symmetric and asymmetric encryption used in DRACOON.
//! DRACOON is a cloud service provider - more information can be found on https://dracoon.com
//! Files are encrypted with AES 256 GCM using random bytes as individual key for each file.
//! Users have a symmetric RSA keypair (4096bit) and use the public key to encrypt the file keys for 
//! file en- and decryption. The private key is used to decrypt file keys.
//! 
//! The crate is based on openssl, which allows to generate keypairs and to perform desired en- and decryption
//! operations.
//! 

//use models::*;
use openssl::base64;
use openssl::md::Md;
use openssl::pkey::PKey;
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

mod models;

pub use models::*;

/// Implements symmetric and asymmetric encryption for DRACOON by implementing traits
/// using the openssl crate
/// - [DracoonRSACrypto]
/// - [Encrypt]
/// - [Decrypt]
/// 
pub struct DracoonCrypto;

impl DracoonRSACrypto for DracoonCrypto {
    /// Creates a plain RSA keypair required for DRACOON to encrypt 
    /// and decrypt file keys.
    /// Using a 4096 bit keypair is recommended - 2048 bit is for legacy support and usage
    /// is discouraged.
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};
    /// let plain_4096_keypair =
    /// DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// ```
    /// 
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

        Ok(PlainUserKeyPairContainer::new(
            private_key_pem,
            public_key_pem,
            version,
        ))
    }
    /// Encrypts a plain keypair container - specifically the private key - using 
    /// a secret provided as parameter.
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};
    /// let secret = "VerySecret123!";
    /// let plain_4096_keypair =
    /// DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let enc_4096_keypair = DracoonCrypto::encrypt_private_key(secret, plain_4096_keypair).unwrap();
    /// ```
    /// 
    fn encrypt_private_key(
        secret: &str,
        plain_keypair: PlainUserKeyPairContainer,
    ) -> Result<UserKeyPairContainer, DracoonCryptoError> {
        let secret = secret.as_bytes();
        let private_key_pem = plain_keypair.private_key_container.private_key.as_bytes();

        let rsa = Rsa::private_key_from_pem(&private_key_pem)?;
        let rsa = PKey::from_rsa(rsa)?;

        let private_key_pem =
            rsa.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), &secret)?;
        let private_key_pem = std::str::from_utf8(&private_key_pem)?;

        Ok(UserKeyPairContainer::new_from_plain_keypair(
            plain_keypair,
            private_key_pem,
        ))
    }
    /// Decrypts an encrypted keypair container - specifically the private key - using 
    /// a secret provided as parameter.
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};
    /// let secret = "VerySecret123!";
    /// let plain_4096_keypair =
    /// DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let enc_4096_keypair = DracoonCrypto::encrypt_private_key(secret, plain_4096_keypair).unwrap();
    /// 
    /// let plain_keypair = DracoonCrypto::decrypt_private_key(secret, enc_4096_keypair).unwrap();
    /// ```
    /// 
    fn decrypt_private_key(
        secret: &str,
        keypair: UserKeyPairContainer,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError> {
        let secret = secret.as_bytes();
        let private_key_pem = keypair.private_key_container.private_key.as_bytes();

        let rsa = PKey::private_key_from_pem_passphrase(&private_key_pem, &secret)?;
        let rsa = rsa.rsa()?;
        let private_key_pem = rsa
            .private_key_to_pem()
            .iter()
            .flat_map(|buf| std::str::from_utf8(buf))
            .collect::<String>();

        Ok(PlainUserKeyPairContainer::new_from_keypair(
            keypair,
            &private_key_pem,
        ))
    }
    /// Encrypts a file key used for file encryption using either the public key or a plain keypair 
    /// container.
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, PlainFileKey, UserKeyPairVersion};
    /// 
    /// let plain_4096_keypair =
    /// DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// 
    /// let plain_file_key = PlainFileKey::try_new_for_encryption().unwrap();
    /// let enc_file_key = DracoonCrypto::encrypt_file_key(plain_file_key, plain_4096_keypair).unwrap();
    /// 
    /// 
    /// ```
    /// 
    fn encrypt_file_key(
        plain_file_key: PlainFileKey,
        public_key: impl PublicKey,
    ) -> Result<FileKey, DracoonCryptoError> {
        let public_key_pem = public_key.get_public_key().public_key.as_bytes();
        let rsa = Rsa::public_key_from_pem(public_key_pem)?;

        let pkey = PKey::from_rsa(rsa)?;

        let file_key = &plain_file_key.key;
        let file_key = base64::decode_block(file_key)?;

        let file_key_version: FileKeyVersion = match public_key.get_public_key().version {
            UserKeyPairVersion::RSA2048 => FileKeyVersion::RSA2048_AES256GCM,
            UserKeyPairVersion::RSA4096 => FileKeyVersion::RSA4096_AES256GCM,
        };

        let mut key_ctx = PkeyCtx::new(&pkey)?;
        let mgf1_md = Md::sha256();

        let md = match public_key.get_public_key().version {
            UserKeyPairVersion::RSA2048 => Md::sha1(),
            UserKeyPairVersion::RSA4096 => Md::sha256(),
        };

        key_ctx.encrypt_init()?;
        key_ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        key_ctx.set_rsa_oaep_md(&md)?;
        key_ctx.set_rsa_mgf1_md(&mgf1_md)?;

        let mut buf: Vec<u8> = Vec::new();
        key_ctx.encrypt_to_vec(&file_key, &mut buf)?;

        let enc_file_key = base64::encode_block(&buf);

        Ok(FileKey::new_from_plain_key(
            plain_file_key,
            &enc_file_key,
            file_key_version,
        ))
    }

    /// Decrypts a file key used for file encryption using a plain keypair 
    /// container.
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, PlainFileKey, UserKeyPairVersion, PublicKeyContainer};
    /// 
    /// let plain_4096_keypair =
    /// DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
    /// let public_key_container = PublicKeyContainer {
    /// public_key: plain_4096_keypair.public_key_container.public_key.clone(),
    /// version: UserKeyPairVersion::RSA4096,
    /// created_at: None,
    /// created_by: None,
    /// expire_at: None,
    ///};
    /// let plain_file_key = PlainFileKey::try_new_for_encryption().unwrap();
    /// let enc_file_key = DracoonCrypto::encrypt_file_key(plain_file_key, public_key_container).unwrap();

    /// let plain_file_key = DracoonCrypto::decrypt_file_key(enc_file_key, plain_4096_keypair).unwrap();
    /// 
    /// ```
    /// 
    fn decrypt_file_key(
        file_key: FileKey,
        keypair: PlainUserKeyPairContainer,
    ) -> Result<PlainFileKey, DracoonCryptoError> {
        let private_key_pem = keypair.private_key_container.private_key.as_bytes();
        let rsa = Rsa::private_key_from_pem(private_key_pem)?;

        let pkey = PKey::from_rsa(rsa)?;

        let enc_file_key = base64::decode_block(&file_key.key)?;

        let mut key_ctx = PkeyCtx::new(&pkey)?;
        let mgf1_md = Md::sha256();

        let md = match keypair.get_public_key().version {
            UserKeyPairVersion::RSA2048 => Md::sha1(),
            UserKeyPairVersion::RSA4096 => Md::sha256(),
        };

        key_ctx.decrypt_init()?;
        key_ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
        key_ctx.set_rsa_oaep_md(&md)?;
        key_ctx.set_rsa_mgf1_md(&mgf1_md)?;

        let mut buf: Vec<u8> = Vec::new();
        key_ctx.decrypt_to_vec(&enc_file_key, &mut buf)?;

        let plain_file_key = base64::encode_block(&buf);

        Ok(PlainFileKey::new_from_file_key(file_key, &plain_file_key))
    }
}

/// Implements encryption based on AES256 GCM.
/// Provides function to encrypt on the fly and another one to create a Crypter in order
/// to encrypt in chunks. 
impl Encrypt for DracoonCrypto {
    /// Encrypts bytes on the fly - full message is expected and passed as data.
    /// 
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, Encrypt};
    /// let message = b"Encrypt me please";
    /// let enc_message = DracoonCrypto::encrypt(message.to_vec()).unwrap();
    /// 
    /// ```
    fn encrypt(data: Vec<u8>) -> Result<EncryptionResult, DracoonCryptoError> {
        let cipher = Cipher::aes_256_gcm();

        let mut plain_file_key = PlainFileKey::try_new_for_encryption()?;

        let key = base64::decode_block(&plain_file_key.key)?;
        let iv = base64::decode_block(&plain_file_key.iv)?;

        let aad: [u8; 8] = [0; 8];
        let mut tag = [0; 16];

        let res = encrypt_aead(cipher, &key, Some(&iv), &aad, &data, &mut tag)?;

        let tag = base64::encode_block(&tag);
        plain_file_key.set_tag(tag);

        Ok((res, plain_file_key))
    }
    /// Returns a Crypter for chunked encryption
    /// 
    /// Accepts a buffer to store the encrypted message to.
    /// In order to encrypt in chunks, you need to
    /// - get an encrypter and pass a buffer
    /// - update the encrypter by passing the chunks
    /// - finalize the encryption once all chunks were read
    /// - get the message (as bytes) from the encrypter
    /// - get the plain file key from the encrypter
    /// 
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, Encrypt};
    /// use openssl::symm::Cipher;
    /// use std::io::Read;
    /// 
    /// let message = b"Encrypt this very long message in chunks and decrypt it";
    /// let buff_len = message.len() + Cipher::aes_256_gcm().block_size();
    /// let mut chunk = [0u8; 5];
    /// let mut buf = vec![0u8; buff_len];
    /// let mut encrypter =
    /// DracoonCrypto::get_encrypter(&mut buf).unwrap();
    /// let mut count: usize = 0;
    /// let mut cursor = std::io::Cursor::new(&message);
    /// 
    /// while cursor.read_exact(&mut chunk).is_ok() {
    /// count += encrypter.update(&chunk).unwrap();
    /// }
    /// count += encrypter.finalize().unwrap();
    /// 
    /// let enc_message = encrypter.get_message();
    /// let plain_file_key = encrypter.get_plain_file_key();
    /// 
    /// ```
    fn get_encrypter(buffer: &mut Vec<u8>) -> Result<Crypter, DracoonCryptoError> {
        Crypter::try_new_for_encryption(buffer)
    }
}

/// Implements decryption based on AES256 GCM.
/// Provides function to decrypt on the fly and another one to create a Crypter in order
/// to decrypt in chunks. 
impl Decrypt for DracoonCrypto {
    /// Decrypts bytes on the fly - full message is expected and passed as data.
    /// 
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, Decrypt, Encrypt};
    /// let message = b"Encrypt me please";
    /// let enc_message = DracoonCrypto::encrypt(message.to_vec()).unwrap();
    /// let plain_message = DracoonCrypto::decrypt(enc_message.0, enc_message.1);
    /// 
    /// ```
    fn decrypt(data: Vec<u8>, plain_file_key: PlainFileKey) -> Result<Vec<u8>, DracoonCryptoError> {
        let cipher = Cipher::aes_256_gcm();

        let key = base64::decode_block(&plain_file_key.key)?;
        let iv = base64::decode_block(&plain_file_key.iv)?;
        let tag = base64::decode_block(
            &plain_file_key
                .tag
                .ok_or(DracoonCryptoError::ByteParseError)?,
        )?;

        let aad: [u8; 8] = [0; 8];

        let res = decrypt_aead(cipher, &key, Some(&iv), &aad, &data, &tag)?;

        Ok(res)
    }

    /// Returns a Crypter for chunked decryption
    /// 
    /// Accepts a buffer to store the decrypted message to.
    /// In order to decrypt in chunks, you need to
    /// - get a decrypter and pass a buffer and the plain file key
    /// - update the decrypter by passing the chunks
    /// - finalize the decryption once all chunks were read
    /// - get the message (as bytes) from the encrypter
    /// 
    /// # Example
    /// ```
    /// use dco3_crypto::{DracoonCrypto, Encrypt, Decrypt};
    /// use openssl::symm::Cipher;
    /// use std::io::Read;
    /// let message = b"Encrypt this very long message in chunks and decrypt it";
    /// 
    /// /// returns a tuple containing the message and the plain file key
    /// let message = DracoonCrypto::encrypt(message.to_vec()).unwrap();
    /// let buff_len = message.0.len() + Cipher::aes_256_gcm().block_size();
    /// 
    /// /// chunks of 5
    /// let mut chunk = [0u8; 5];
    /// let mut buf = vec![0u8; buff_len];
    /// let mut decrypter = DracoonCrypto::get_decrypter(message.1, &mut buf).unwrap();
    /// let mut count: usize = 0;
    /// let mut cursor = std::io::Cursor::new(&message.0);
    /// while cursor.read_exact(&mut chunk).is_ok() {
    ///    count += decrypter.update(&chunk).unwrap();
    ///}
    /// count += decrypter.finalize().unwrap();
    /// 
    /// let plain_message = std::str::from_utf8(decrypter.get_message()).unwrap();
    /// ```
    /// 
    fn get_decrypter(
        plain_file_key: PlainFileKey,
        buffer: &mut Vec<u8>,
    ) -> Result<models::Crypter, DracoonCryptoError> {
        Crypter::try_new_for_decryption(plain_file_key, buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_plain_user_keypair_generation_2048() {
        let plain_2048_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA2048)
                .expect("Should not fail");

        assert_eq!(
            plain_2048_keypair.private_key_container.version,
            UserKeyPairVersion::RSA2048
        );
        assert_eq!(
            plain_2048_keypair.public_key_container.version,
            UserKeyPairVersion::RSA2048
        );
    }

    #[test]
    fn test_plain_user_keypair_generation_4096() {
        let plain_4096_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096)
                .expect("Should not fail");

        assert_eq!(
            plain_4096_keypair.private_key_container.version,
            UserKeyPairVersion::RSA4096
        );
        assert_eq!(
            plain_4096_keypair.public_key_container.version,
            UserKeyPairVersion::RSA4096
        );
    }

    #[test]
    fn test_keypair_encryption_4096() {
        let plain_4096_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096)
                .expect("Should not fail");

        let secret = "VerySecret123!";
        let plain_private_key = plain_4096_keypair.private_key_container.private_key.clone();

        let enc_4096_keypair = DracoonCrypto::encrypt_private_key(secret, plain_4096_keypair)
            .expect("Should not fail");

        assert_ne!(
            &enc_4096_keypair.private_key_container.private_key,
            &plain_private_key
        );

        let plain_4096_keypair =
            DracoonCrypto::decrypt_private_key(secret, enc_4096_keypair).expect("Should not fail");

        assert_eq!(
            plain_4096_keypair.private_key_container.private_key,
            plain_private_key
        );
    }

    #[test]
    fn test_keypair_encryption_2048() {
        let plain_2048_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA2048)
                .expect("Should not fail");

        let secret = "VerySecret123!";
        let plain_private_key = plain_2048_keypair.private_key_container.private_key.clone();

        let enc_2048_keypair = DracoonCrypto::encrypt_private_key(secret, plain_2048_keypair)
            .expect("Should not fail");

        assert_ne!(
            &enc_2048_keypair.private_key_container.private_key,
            &plain_private_key
        );

        let plain_2048_keypair =
            DracoonCrypto::decrypt_private_key(secret, enc_2048_keypair).expect("Should not fail");

        assert_eq!(
            plain_2048_keypair.private_key_container.private_key,
            plain_private_key
        );
    }

    #[test]
    fn test_file_key_encryption_4096() {
        let plain_4096_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096)
                .expect("Should not fail");

        let public_key_container = PublicKeyContainer {
            public_key: plain_4096_keypair.public_key_container.public_key.clone(),
            version: UserKeyPairVersion::RSA4096,
            created_at: None,
            created_by: None,
            expire_at: None,
        };

        let key = base64::encode_block("abcdefgh".as_bytes());

        let plain_file_key = PlainFileKey {
            key: key.clone(),
            iv: "123456".to_string(),
            tag: None,
            version: PlainFileKeyVersion::AES256CM,
        };

    

        let enc_file_key = DracoonCrypto::encrypt_file_key(plain_file_key, public_key_container)
            .expect("Should not fail");

        assert_ne!(key.clone(), enc_file_key.key);
        assert_eq!("123456", enc_file_key.iv);

        let plain_file_key = DracoonCrypto::decrypt_file_key(enc_file_key, plain_4096_keypair)
            .expect("Should not fail");

        assert_eq!(key, plain_file_key.key);
    }

    #[test]
    fn test_file_key_encryption_2048() {
        let plain_2048_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA2048)
                .expect("Should not fail");

        let public_key_container = PublicKeyContainer {
            public_key: plain_2048_keypair.public_key_container.public_key.clone(),
            version: UserKeyPairVersion::RSA2048,
            created_at: None,
            created_by: None,
            expire_at: None,
        };

        let key = base64::encode_block("abcdefgh".as_bytes());

        let plain_file_key = PlainFileKey {
            key: key.clone(),
            iv: "123456".to_string(),
            tag: None,
            version: PlainFileKeyVersion::AES256CM,
        };

        let enc_file_key = DracoonCrypto::encrypt_file_key(plain_file_key, public_key_container)
            .expect("Should not fail");

        assert_ne!(key.clone(), enc_file_key.key);
        assert_eq!("123456", enc_file_key.iv);

        let plain_file_key = DracoonCrypto::decrypt_file_key(enc_file_key, plain_2048_keypair)
            .expect("Should not fail");

        assert_eq!(key, plain_file_key.key);
    }

    #[test]
    fn test_message_encryption() {
        let message = b"Encrypt me please";

        let enc_message = DracoonCrypto::encrypt(message.to_vec()).expect("Should not fail");

        assert_ne!(b"Encrypt me please".to_vec(), enc_message.0);
        assert!(enc_message.1.tag != None);

        let plain_message =
            DracoonCrypto::decrypt(enc_message.0, enc_message.1).expect("Should not fail");
        assert_eq!(b"Encrypt me please".to_vec(), plain_message);
    }
    #[test]
    fn test_chunked_message_decryption() {
        let message = b"Encrypt this very long message and decrypt it in chunks";

        let message = DracoonCrypto::encrypt(message.to_vec()).expect("Should not fail");

        let mut cursor = std::io::Cursor::new(&message.0);

        let buff_len = message.0.len() + Cipher::aes_256_gcm().block_size();

        let mut chunk = [0u8; 5];
        let mut buf = vec![0u8; buff_len];

        let mut decrypter =
            DracoonCrypto::get_decrypter(message.1, &mut buf).expect("Should not fail");
        let mut count: usize = 0;

    
        while cursor.read_exact(&mut chunk).is_ok() {
            count += decrypter.update(&chunk).expect("Should not fail");
        }

        count += decrypter
            .finalize()
            .expect("Should not fail");

        let plain_message = std::str::from_utf8(decrypter.get_message()).expect("Should not fail");

        assert_eq!(count, message.0.len());
        assert_eq!(
            plain_message,
            "Encrypt this very long message and decrypt it in chunks"
        );
    }

    
    #[test]
    fn test_chunked_message_encryption() {
        let message = b"Encrypt this very long message in chunks and decrypt it";

        let buff_len = message.len() + Cipher::aes_256_gcm().block_size();

        let mut chunk = [0u8; 5];
        let mut buf = vec![0u8; buff_len];

        let mut encrypter =
        DracoonCrypto::get_encrypter(&mut buf).expect("Should not fail");

        let mut cursor = std::io::Cursor::new(&message);

        let mut count: usize = 0;

        while cursor.read_exact(&mut chunk).is_ok() {
            count += encrypter.update(&chunk).expect("Should not fail");
        }

        count += encrypter
            .finalize()
            .expect("Should not fail");

        assert_eq!(count, message.len());

        let enc_message = encrypter.get_message().to_vec();
        let plain_file_key = encrypter.get_plain_file_key();
        let plain_message = DracoonCrypto::decrypt(enc_message, plain_file_key).expect("Should not fail");

        assert_eq!(plain_message, b"Encrypt this very long message in chunks and decrypt it");


    }



}
