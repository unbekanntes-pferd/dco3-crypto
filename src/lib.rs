use models::*;
use openssl::base64;
use openssl::md::Md;
use openssl::pkey::PKey;
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

mod models;

struct DracoonCrypto;

impl DracoonRSACrypto for DracoonCrypto {
    fn create_plain_user_keypair(
        version: UserKeyPairVersion,
    ) -> Result<PlainUserKeyPairContainer, DracoonCryptoError> {
        match version {
            UserKeyPairVersion::RSA2048 => {
                let rsa = Rsa::generate(2048)?;
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
            UserKeyPairVersion::RSA4096 => {
                let rsa = Rsa::generate(4096)?;
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
        }
    }

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

    fn encrypt_file_key(
        plain_file_key: PlainFileKey,
        public_key: impl PublicKey,
    ) -> Result<FileKey, DracoonCryptoError> {
        let public_key_pem = public_key.get_public_key().public_key.as_bytes();
        let rsa = Rsa::public_key_from_pem(public_key_pem)?;

        let rsa_size = rsa.size();
        let pkey = PKey::from_rsa(rsa)?;

        let file_key = &plain_file_key.key;
        let file_key = base64::decode_block(file_key)?;
        let mut buf: Vec<u8> = vec![0; rsa_size as usize];

        let file_key_version: FileKeyVersion = match public_key.get_public_key().version {
            UserKeyPairVersion::RSA2048 => FileKeyVersion::RSA2048_AES256GCM,
            UserKeyPairVersion::RSA4096 => FileKeyVersion::RSA4096_AES256GCM,
        };

        let mut key_ctx = PkeyCtx::new(&pkey)?;
        let mgf1_md = Md::sha256();
        key_ctx.set_rsa_mgf1_md(&mgf1_md)?;

        match public_key.get_public_key().version {
            UserKeyPairVersion::RSA2048 => {
                let md = Md::sha1();
                key_ctx.set_rsa_oaep_md(&md)?;
                key_ctx.encrypt_init()?;
            }
            UserKeyPairVersion::RSA4096 => {
                let md = Md::sha256();
                key_ctx.set_rsa_oaep_md(&md)?;
                key_ctx.encrypt_init()?;
            }
        };

        key_ctx.encrypt_to_vec(&file_key, &mut buf)?;

        let enc_file_key = base64::encode_block(&buf);

        Ok(FileKey::new_from_plain_key(
            plain_file_key,
            &enc_file_key,
            file_key_version,
        ))
    }

    fn decrypt_file_key(
        file_key: FileKey,
        keypair: PlainUserKeyPairContainer,
    ) -> Result<PlainFileKey, DracoonCryptoError> {
        let private_key_pem = keypair.private_key_container.private_key.as_bytes();
        let rsa = Rsa::private_key_from_pem(private_key_pem)?;
        let rsa_size = rsa.size();
        let mut buf: Vec<u8> = vec![0; rsa_size as usize];
        let pkey = PKey::from_rsa(rsa)?;

        let enc_file_key = base64::decode_block(&file_key.key)?;

        let mut key_ctx = PkeyCtx::new(&pkey)?;
        let mgf1_md = Md::sha256();
        key_ctx.set_rsa_mgf1_md(&mgf1_md)?;

        match keypair.get_public_key().version {
            UserKeyPairVersion::RSA2048 => {
                let md = Md::sha1();
                key_ctx.set_rsa_oaep_md(&md)?;
                key_ctx.decrypt_init()?;
            }
            UserKeyPairVersion::RSA4096 => {
                let md = Md::sha256();
                key_ctx.set_rsa_oaep_md(&md)?;
                key_ctx.decrypt_init()?;
            }
        };

        key_ctx.decrypt_to_vec(&enc_file_key, &mut buf)?;

        let plain_file_key = base64::encode_block(&buf);

        Ok(PlainFileKey::new_from_file_key(file_key, &plain_file_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_user_keypair_generation_2048() {
        let plain_2048_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA2048)
                .expect("Should not fail");
        

        assert_eq!(plain_2048_keypair.private_key_container.version, UserKeyPairVersion::RSA2048);
        assert_eq!(plain_2048_keypair.public_key_container.version, UserKeyPairVersion::RSA2048);
    }

    #[test]
    fn test_plain_user_keypair_generation_4096() {
        let plain_4096_keypair =
            DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096)
                .expect("Should not fail");
        
        assert_eq!(plain_4096_keypair.private_key_container.version, UserKeyPairVersion::RSA4096);
        assert_eq!(plain_4096_keypair.public_key_container.version, UserKeyPairVersion::RSA4096);
    }
}
