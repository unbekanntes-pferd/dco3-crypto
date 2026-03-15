use super::*;

use openssl::base64;
use openssl::pkey::{PKey, Private, Public};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

const TEST_PASSWORD: &str = "Qwer1234!";

#[derive(Deserialize)]
struct AsyncKeypairFixture {
    #[serde(rename = "plainUserKeyPairContainer")]
    plain_user_key_pair_container: PlainUserKeyPairContainer,
    #[serde(rename = "encryptedUserKeyPairContainer")]
    encrypted_user_key_pair_container: UserKeyPairContainer,
    config: AsyncKeypairConfig,
}

#[derive(Deserialize)]
struct AsyncKeypairConfig {
    password: String,
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn fixture_path(relative: &str) -> PathBuf {
    fixtures_root().join(relative)
}

fn load_json<T: DeserializeOwned>(relative: &str) -> T {
    let path = fixture_path(relative);
    let content = fs::read_to_string(path).expect("fixture should be readable");
    serde_json::from_str(&content).expect("fixture should deserialize")
}

fn load_json_value(relative: &str) -> serde_json::Value {
    let path = fixture_path(relative);
    let content = fs::read_to_string(path).expect("fixture should be readable");
    serde_json::from_str(&content).expect("fixture should deserialize as json value")
}

fn load_text(relative: &str) -> String {
    let path = fixture_path(relative);
    fs::read_to_string(path)
        .expect("fixture should be readable")
        .trim()
        .to_string()
}

fn decode_b64_file(relative: &str) -> Vec<u8> {
    let b64 = load_text(relative);
    base64::decode_block(&b64).expect("base64 file should decode")
}

fn normalize_pem(pem: &str) -> String {
    pem.replace("\r\n", "\n")
}

fn load_plain_file_key_fixture(relative: &str) -> PlainFileKey {
    let mut value = load_json_value(relative);
    if value.get("version").and_then(serde_json::Value::as_str) == Some("A") {
        value["version"] = serde_json::Value::String("AES-256-GCM".to_string());
    }
    serde_json::from_value(value).expect("plain file key fixture should deserialize")
}

fn load_cross_sdk_private_key(language: &str, version: UserKeyPairVersion) -> PrivateKeyContainer {
    match (language, version) {
        ("javascript", UserKeyPairVersion::RSA2048) => {
            load_json("keys/javascript/kp_rsa2048/plain_private_key.json")
        }
        ("javascript", UserKeyPairVersion::RSA4096) => {
            load_json("keys/javascript/kp_rsa4096/plain_private_key.json")
        }
        (language, version) => {
            let fixture_name = match version {
                UserKeyPairVersion::RSA2048 => "kp_rsa2048",
                UserKeyPairVersion::RSA4096 => "kp_rsa4096",
            };
            let root = format!("keys/{language}/{fixture_name}");
            let decrypted = DracoonCrypto::decrypt_keypair(
                &load_text(&format!("{root}/password.txt")),
                UserKeyPairContainer {
                    private_key_container: load_json(&format!("{root}/private_key.json")),
                    public_key_container: load_json(&format!("{root}/public_key.json")),
                },
            )
            .unwrap();
            decrypted.private_key_container
        }
    }
}

fn load_cross_sdk_public_key(language: &str, version: UserKeyPairVersion) -> PublicKeyContainer {
    let fixture_name = match version {
        UserKeyPairVersion::RSA2048 => "kp_rsa2048",
        UserKeyPairVersion::RSA4096 => "kp_rsa4096",
    };
    load_json(&format!("keys/{language}/{fixture_name}/public_key.json"))
}

fn cross_sdk_file_key_cases() -> Vec<(&'static str, &'static str, PrivateKeyContainer)> {
    vec![
        (
            "javascript",
            "fk_rsa2048_aes256gcm",
            load_cross_sdk_private_key("javascript", UserKeyPairVersion::RSA2048),
        ),
        (
            "javascript",
            "fk_rsa4096_aes256gcm",
            load_cross_sdk_private_key("javascript", UserKeyPairVersion::RSA4096),
        ),
        (
            "csharp",
            "fk_rsa2048_aes256gcm",
            load_cross_sdk_private_key("csharp", UserKeyPairVersion::RSA2048),
        ),
        (
            "csharp",
            "fk_rsa4096_aes256gcm",
            load_cross_sdk_private_key("csharp", UserKeyPairVersion::RSA4096),
        ),
        (
            "java",
            "fk_rsa2048_aes256gcm",
            load_cross_sdk_private_key("java", UserKeyPairVersion::RSA2048),
        ),
        (
            "java",
            "fk_rsa4096_aes256gcm",
            load_cross_sdk_private_key("java", UserKeyPairVersion::RSA4096),
        ),
        (
            "swift",
            "fk_rsa2048_aes256gcm",
            load_cross_sdk_private_key("swift", UserKeyPairVersion::RSA2048),
        ),
        (
            "swift",
            "fk_rsa4096_aes256gcm",
            load_cross_sdk_private_key("swift", UserKeyPairVersion::RSA4096),
        ),
    ]
}

fn sample_plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn chunk_slices<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    assert!(!sizes.is_empty(), "chunk sizes must not be empty");

    let mut chunks = Vec::new();
    let mut offset = 0;
    let mut index = 0;

    while offset < data.len() {
        let size = sizes[index % sizes.len()];
        let end = (offset + size).min(data.len());
        chunks.push(&data[offset..end]);
        offset = end;
        index += 1;
    }

    chunks
}

fn tamper_base64(value: &str) -> String {
    let mut bytes = base64::decode_block(value).expect("base64 should decode");
    if bytes.is_empty() {
        bytes.push(1);
    } else {
        bytes[0] ^= 0x01;
    }
    base64::encode_block(&bytes)
}

fn generate_keypair(version: UserKeyPairVersion) -> PlainUserKeyPairContainer {
    DracoonCrypto::create_plain_user_keypair(version).unwrap()
}

fn parse_private_key(private_key: &PrivateKeyContainer) -> PKey<Private> {
    PKey::private_key_from_pem(private_key.private_key.as_bytes()).unwrap()
}

fn parse_public_key(public_key: &PublicKeyContainer) -> PKey<Public> {
    PKey::public_key_from_pem(public_key.public_key.as_bytes()).unwrap()
}

fn encrypt_streaming(
    data: &[u8],
    public_key: impl PublicKey,
    chunk_sizes: &[usize],
) -> Result<(Vec<u8>, FileKey), DracoonCryptoError> {
    let mut encryptor = DracoonCrypto::file_encryptor(public_key)?;
    let mut ciphertext = Vec::new();
    for chunk in chunk_slices(data, chunk_sizes) {
        ciphertext.extend_from_slice(&encryptor.update(chunk)?);
    }
    let finalized = encryptor.finalize()?;
    ciphertext.extend_from_slice(&finalized.final_chunk);
    Ok((ciphertext, finalized.file_key))
}

fn decrypt_streaming(
    ciphertext: &[u8],
    file_key: FileKey,
    private_key: impl PrivateKey,
    chunk_sizes: &[usize],
) -> Result<Vec<u8>, DracoonCryptoError> {
    let mut decryptor = DracoonCrypto::file_decryptor(file_key, private_key)?;
    let mut plaintext = Vec::new();
    for chunk in chunk_slices(ciphertext, chunk_sizes) {
        plaintext.extend_from_slice(&decryptor.update(chunk)?);
    }
    plaintext.extend_from_slice(&decryptor.finalize()?);
    Ok(plaintext)
}

fn encrypt_streaming_with_plain_file_key(
    data: &[u8],
    plain_file_key: PlainFileKey,
    chunk_sizes: &[usize],
) -> Result<(Vec<u8>, PlainFileKey), DracoonCryptoError> {
    let mut crypter = OpenSslFileCrypter::new_for_encryption_with_key(plain_file_key)?;
    let mut ciphertext = Vec::new();
    for chunk in chunk_slices(data, chunk_sizes) {
        ciphertext.extend_from_slice(&crypter.update(chunk)?);
    }
    ciphertext.extend_from_slice(&crypter.finalize()?);
    Ok((ciphertext, crypter.plain_file_key))
}

fn decrypt_streaming_with_plain_file_key(
    ciphertext: &[u8],
    plain_file_key: PlainFileKey,
    chunk_sizes: &[usize],
) -> Result<Vec<u8>, DracoonCryptoError> {
    let mut crypter = OpenSslFileCrypter::new_for_decryption(plain_file_key)?;
    let mut plaintext = Vec::new();
    for chunk in chunk_slices(ciphertext, chunk_sizes) {
        plaintext.extend_from_slice(&crypter.update(chunk)?);
    }
    plaintext.extend_from_slice(&crypter.finalize()?);
    Ok(plaintext)
}

mod generate_user_key_pair {
    use super::*;

    #[test]
    fn generates_expected_rsa_modulus_size() {
        for (version, expected_bits) in [
            (UserKeyPairVersion::RSA2048, 2048),
            (UserKeyPairVersion::RSA4096, 4096),
        ] {
            let keypair = generate_keypair(version.clone());
            let private_key = parse_private_key(&keypair.private_key_container);
            let public_key = parse_public_key(&keypair.public_key_container);
            let private_rsa = private_key.rsa().unwrap();
            let public_rsa = public_key.rsa().unwrap();

            assert_eq!(keypair.private_key_container.version, version);
            assert_eq!(keypair.public_key_container.version, version);
            assert_eq!(private_rsa.n().num_bits(), expected_bits);
            assert_eq!(public_rsa.n().num_bits(), expected_bits);
            assert_eq!(private_rsa.n(), public_rsa.n());
            assert_eq!(private_rsa.e(), public_rsa.e());
        }
    }
}

mod encrypt_private_key {
    use super::*;

    #[test]
    fn javascript_roundtrip() {
        let cases = [
            (
                "keys/javascript/kp_rsa2048/plain_private_key.json",
                "keys/javascript/kp_rsa2048/public_key.json",
                UserKeyPairVersion::RSA2048,
            ),
            (
                "keys/javascript/kp_rsa4096/plain_private_key.json",
                "keys/javascript/kp_rsa4096/public_key.json",
                UserKeyPairVersion::RSA4096,
            ),
        ];

        for (plain_private_path, public_key_path, expected_version) in cases {
            let plain_private: PrivateKeyContainer = load_json(plain_private_path);
            let public_key: PublicKeyContainer = load_json(public_key_path);
            let encrypted = DracoonCrypto::encrypt_private_key(
                TEST_PASSWORD,
                PlainUserKeyPairContainer {
                    private_key_container: plain_private.clone(),
                    public_key_container: public_key.clone(),
                },
            )
            .unwrap();

            assert_eq!(encrypted.private_key_container.version, expected_version);
            assert_eq!(encrypted.public_key_container.version, expected_version);
            assert!(encrypted
                .private_key_container
                .private_key
                .contains("BEGIN ENCRYPTED PRIVATE KEY"));
            assert_eq!(
                encrypted.public_key_container.public_key,
                public_key.public_key
            );

            let decrypted = DracoonCrypto::decrypt_keypair(TEST_PASSWORD, encrypted).unwrap();
            assert_eq!(
                normalize_pem(&decrypted.private_key_container.private_key),
                normalize_pem(&plain_private.private_key)
            );
        }
    }

    #[test]
    fn generates_randomized_pkcs8_output() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);

        let encrypted_a =
            DracoonCrypto::encrypt_private_key(TEST_PASSWORD, keypair.clone()).unwrap();
        let encrypted_b =
            DracoonCrypto::encrypt_private_key(TEST_PASSWORD, keypair.clone()).unwrap();

        assert_ne!(
            encrypted_a.private_key_container.private_key,
            encrypted_b.private_key_container.private_key
        );
        assert_eq!(
            encrypted_a.public_key_container.public_key,
            keypair.public_key_container.public_key
        );
        assert_eq!(
            encrypted_b.public_key_container.public_key,
            keypair.public_key_container.public_key
        );

        let decrypted_a = DracoonCrypto::decrypt_keypair(TEST_PASSWORD, encrypted_a).unwrap();
        let decrypted_b = DracoonCrypto::decrypt_keypair(TEST_PASSWORD, encrypted_b).unwrap();

        assert_eq!(
            normalize_pem(&decrypted_a.private_key_container.private_key),
            normalize_pem(&keypair.private_key_container.private_key)
        );
        assert_eq!(
            normalize_pem(&decrypted_b.private_key_container.private_key),
            normalize_pem(&keypair.private_key_container.private_key)
        );
    }

}

mod decrypt_private_key {
    use super::*;

    #[test]
    fn javascript_fixtures() {
        let cases = [
            (
                "keys/javascript/kp_rsa2048/private_key.json",
                "keys/javascript/kp_rsa2048/public_key.json",
                TEST_PASSWORD,
                "keys/javascript/kp_rsa2048/plain_private_key.json",
            ),
            (
                "keys/javascript/kp_rsa4096/private_key.json",
                "keys/javascript/kp_rsa4096/public_key.json",
                TEST_PASSWORD,
                "keys/javascript/kp_rsa4096/plain_private_key.json",
            ),
            (
                "keys/javascript/kp_rsa2048_old/kp_rsa2048_old.json",
                "",
                "",
                "",
            ),
            (
                "keys/javascript/kp_rsa4096_old/kp_rsa4096_old.json",
                "",
                "",
                "",
            ),
            ("keys/javascript/kp_rsa2048_2/kp_rsa2048_2.json", "", "", ""),
            ("keys/javascript/kp_rsa4096_2/kp_rsa4096_2.json", "", "", ""),
        ];

        for (private_key_path, public_key_path, password, plain_private_key_path) in cases {
            if private_key_path.ends_with(".json") && public_key_path.is_empty() {
                let fixture: AsyncKeypairFixture = load_json(private_key_path);
                let plain = DracoonCrypto::decrypt_keypair(
                    &fixture.config.password,
                    fixture.encrypted_user_key_pair_container.clone(),
                )
                .unwrap();

                assert_eq!(
                    normalize_pem(&plain.private_key_container.private_key),
                    normalize_pem(
                        &fixture
                            .plain_user_key_pair_container
                            .private_key_container
                            .private_key
                    )
                );
                continue;
            }

            let private_key: PrivateKeyContainer = load_json(private_key_path);
            let public_key: PublicKeyContainer = load_json(public_key_path);
            let expected_plain: PrivateKeyContainer = load_json(plain_private_key_path);

            let decrypted = DracoonCrypto::decrypt_keypair(
                password,
                UserKeyPairContainer {
                    private_key_container: private_key,
                    public_key_container: public_key,
                },
            )
            .unwrap();

            assert_eq!(
                normalize_pem(&decrypted.private_key_container.private_key),
                normalize_pem(&expected_plain.private_key)
            );
        }
    }

    #[test]
    fn corrupted_and_mismatched_keypairs() {
        let private_key_bad_pem: PrivateKeyContainer =
            load_json("keys/corrupted/private_key_bad_pem.json");
        let private_key_bad_asn1: PrivateKeyContainer =
            load_json("keys/corrupted/private_key_bad_asn1.json");
        let private_key_bad_key: PrivateKeyContainer =
            load_json("keys/corrupted/private_key_bad_key.json");
        let public_key_2048: PublicKeyContainer =
            load_json("keys/javascript/kp_rsa2048/public_key.json");
        let public_key_4096: PublicKeyContainer =
            load_json("keys/javascript/kp_rsa4096/public_key.json");
        let private_key_2048: PrivateKeyContainer =
            load_json("keys/javascript/kp_rsa2048/private_key.json");
        let private_key_bad_version =
            load_json_value("keys/corrupted/private_key_bad_version.json");
        let public_key_bad_version = load_json_value("keys/corrupted/public_key_bad_version.json");

        let err = DracoonCrypto::decrypt_keypair(
            TEST_PASSWORD,
            UserKeyPairContainer {
                private_key_container: private_key_2048.clone(),
                public_key_container: public_key_4096,
            },
        )
        .unwrap_err();
        assert_eq!(err, DracoonCryptoError::InvalidKeypairVersion);

        for bad_private_key in [
            private_key_bad_pem,
            private_key_bad_asn1,
            private_key_bad_key,
        ] {
            let err = DracoonCrypto::decrypt_keypair(
                TEST_PASSWORD,
                UserKeyPairContainer {
                    private_key_container: bad_private_key,
                    public_key_container: public_key_2048.clone(),
                },
            )
            .unwrap_err();
            assert_eq!(err, DracoonCryptoError::RsaOperationFailed);
        }

        assert!(serde_json::from_value::<PrivateKeyContainer>(private_key_bad_version).is_err());
        assert!(serde_json::from_value::<PublicKeyContainer>(public_key_bad_version).is_err());
    }

    #[test]
    fn password_encoding_fixtures() {
        let java_umlaut_root = "keys/java/kp_rsa4096_umlaut";
        let java_umlaut_private: PrivateKeyContainer =
            load_json(&format!("{java_umlaut_root}/private_key.json"));
        let java_umlaut_public: PublicKeyContainer =
            load_json(&format!("{java_umlaut_root}/public_key.json"));
        let java_umlaut_password = load_text(&format!("{java_umlaut_root}/password.txt"));
        assert!(DracoonCrypto::decrypt_keypair(
            &java_umlaut_password,
            UserKeyPairContainer {
                private_key_container: java_umlaut_private,
                public_key_container: java_umlaut_public,
            }
        )
        .is_ok());

        let emoji_root = "keys/java/kp_rsa4096_emoticon";
        let emoji_private: PrivateKeyContainer =
            load_json(&format!("{emoji_root}/private_key.json"));
        let emoji_public: PublicKeyContainer = load_json(&format!("{emoji_root}/public_key.json"));
        let emoji_password = load_text(&format!("{emoji_root}/password.txt"));
        let decrypted = DracoonCrypto::decrypt_keypair(
            &emoji_password,
            UserKeyPairContainer {
                private_key_container: emoji_private,
                public_key_container: emoji_public,
            },
        )
        .unwrap();
        assert!(decrypted
            .private_key_container
            .private_key
            .contains("BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn wrong_password_fails() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let encrypted = DracoonCrypto::encrypt_private_key(TEST_PASSWORD, keypair).unwrap();

        let err = DracoonCrypto::decrypt_keypair("wrong-password", encrypted).unwrap_err();
        assert_eq!(err, DracoonCryptoError::RsaOperationFailed);
    }
}

mod cross_crypto_sdk {
    use super::*;

    #[test]
    fn decrypt_private_key_fixtures() {
        let cases = [
            ("csharp", "kp_rsa2048"),
            ("csharp", "kp_rsa4096"),
            ("csharp", "kp_rsa4096_2"),
            ("csharp", "kp_rsa4096_special"),
            ("java", "kp_rsa2048"),
            ("java", "kp_rsa4096"),
            ("java", "kp_rsa4096_2"),
            ("java", "kp_rsa4096_umlaut"),
            ("swift", "kp_rsa2048"),
            ("swift", "kp_rsa4096"),
            ("swift", "kp_rsa4096_2"),
            ("swift", "kp_rsa4096_special"),
        ];

        for (language, fixture_name) in cases {
            let root = format!("keys/{language}/{fixture_name}");
            let private_key: PrivateKeyContainer = load_json(&format!("{root}/private_key.json"));
            let public_key: PublicKeyContainer = load_json(&format!("{root}/public_key.json"));
            let password = load_text(&format!("{root}/password.txt"));

            let decrypted = DracoonCrypto::decrypt_keypair(
                &password,
                UserKeyPairContainer {
                    private_key_container: private_key,
                    public_key_container: public_key,
                },
            )
            .unwrap();

            assert!(decrypted
                .private_key_container
                .private_key
                .contains("BEGIN RSA PRIVATE KEY"));
            assert!(decrypted
                .private_key_container
                .private_key
                .contains("END RSA PRIVATE KEY"));
        }
    }
}

mod encrypt_file_key {
    use super::*;

    #[test]
    fn cross_sdk_fixtures() {
        for (language, version, private_key) in cross_sdk_file_key_cases() {
            let root = format!("keys/{language}/{version}");
            let enc_file_key: FileKey = load_json(&format!("{root}/enc_file_key.json"));
            let plain_file_key =
                load_plain_file_key_fixture(&format!("{root}/plain_file_key.json"));

            let public_key = load_cross_sdk_public_key(language, private_key.version.clone());
            let encrypted = DracoonCrypto::encrypt_file_key(plain_file_key, public_key).unwrap();

            assert_eq!(encrypted.version, enc_file_key.version);
            assert_eq!(encrypted.iv, enc_file_key.iv);
            assert_eq!(encrypted.tag, enc_file_key.tag);

            let bit_len = base64::decode_block(&encrypted.key).unwrap().len() * 8;
            assert_eq!(
                bit_len,
                match encrypted.version {
                    FileKeyVersion::RSA2048_AES256GCM => 2048,
                    FileKeyVersion::RSA4096_AES256GCM => 4096,
                }
            );
        }
    }

    #[test]
    fn uses_randomized_oaep_ciphertext() {
        for version in [UserKeyPairVersion::RSA2048, UserKeyPairVersion::RSA4096] {
            let keypair = generate_keypair(version.clone());
            let mut plain_file_key = PlainFileKey::try_new_for_encryption().unwrap();
            plain_file_key.set_tag(base64::encode_block(&[7u8; 16]));

            let encrypted_a =
                DracoonCrypto::encrypt_file_key(plain_file_key.clone(), keypair.clone()).unwrap();
            let encrypted_b =
                DracoonCrypto::encrypt_file_key(plain_file_key.clone(), keypair.clone()).unwrap();

            assert_eq!(encrypted_a.version, encrypted_b.version);
            assert_eq!(encrypted_a.iv, encrypted_b.iv);
            assert_eq!(encrypted_a.tag, encrypted_b.tag);
            assert_ne!(encrypted_a.key, encrypted_b.key);
        }
    }
}

mod decrypt_file_key {
    use super::*;

    #[test]
    fn cross_sdk_fixtures() {
        for (language, version, private_key) in cross_sdk_file_key_cases() {
            let root = format!("keys/{language}/{version}");
            let enc_file_key: FileKey = load_json(&format!("{root}/enc_file_key.json"));
            let plain_file_key =
                load_plain_file_key_fixture(&format!("{root}/plain_file_key.json"));

            let decrypted = DracoonCrypto::decrypt_file_key(enc_file_key, private_key).unwrap();
            assert_eq!(decrypted, plain_file_key);
        }
    }

    #[test]
    fn generated_file_key_roundtrip() {
        for version in [UserKeyPairVersion::RSA2048, UserKeyPairVersion::RSA4096] {
            let keypair = generate_keypair(version.clone());
            let mut plain_file_key = PlainFileKey::try_new_for_encryption().unwrap();
            plain_file_key.set_tag(base64::encode_block(&[3u8; 16]));

            let encrypted =
                DracoonCrypto::encrypt_file_key(plain_file_key.clone(), keypair.clone()).unwrap();
            let decrypted = DracoonCrypto::decrypt_file_key(encrypted, keypair).unwrap();

            assert_eq!(decrypted, plain_file_key);
        }
    }

    #[test]
    fn corrupted_and_mismatched_inputs() {
        let plain_private_key_2048: PrivateKeyContainer =
            load_json("keys/javascript/kp_rsa2048/plain_private_key.json");
        let enc_file_key_bad_key: FileKey = load_json("keys/corrupted/enc_file_key_bad_key.json");
        let enc_file_key_bad_version =
            load_json_value("keys/corrupted/enc_file_key_bad_version.json");
        let plain_private_key_bad_pem: PrivateKeyContainer =
            load_json("keys/corrupted/plain_private_key_bad_pem.json");
        let plain_private_key_bad_asn1: PrivateKeyContainer =
            load_json("keys/corrupted/plain_private_key_bad_asn1.json");
        let enc_file_key_2048: FileKey =
            load_json("keys/javascript/fk_rsa2048_aes256gcm/enc_file_key.json");
        let plain_private_key_4096: PrivateKeyContainer =
            load_json("keys/javascript/kp_rsa4096/plain_private_key.json");

        assert_eq!(
            DracoonCrypto::decrypt_file_key(enc_file_key_bad_key, plain_private_key_2048.clone())
                .unwrap_err(),
            DracoonCryptoError::RsaOperationFailed
        );
        assert!(serde_json::from_value::<FileKey>(enc_file_key_bad_version).is_err());
        assert_eq!(
            DracoonCrypto::decrypt_file_key(enc_file_key_2048.clone(), plain_private_key_bad_pem)
                .unwrap_err(),
            DracoonCryptoError::RsaImportFailed
        );
        assert_eq!(
            DracoonCrypto::decrypt_file_key(enc_file_key_2048.clone(), plain_private_key_bad_asn1)
                .unwrap_err(),
            DracoonCryptoError::RsaImportFailed
        );
        assert_eq!(
            DracoonCrypto::decrypt_file_key(enc_file_key_2048, plain_private_key_4096).unwrap_err(),
            DracoonCryptoError::InvalidKeypairVersion
        );
    }
}

mod file_encryption {
    use super::*;

    #[test]
    fn cross_sdk_fixtures() {
        for language in ["javascript", "csharp", "java", "swift"] {
            let plain_file_key = load_plain_file_key_fixture(&format!(
                "keys/{language}/fk_rsa2048_aes256gcm/plain_file_key.json"
            ));
            let plaintext = decode_b64_file(&format!("files/{language}/plain_file.b64"));
            let expected_ciphertext = decode_b64_file(&format!("files/{language}/enc_file.b64"));

            let (ciphertext, finalized_key) =
                DracoonCrypto::encrypt_with_plain_file_key(&plaintext, plain_file_key.clone())
                    .unwrap();

            assert_eq!(ciphertext, expected_ciphertext);
            assert_eq!(finalized_key.tag, plain_file_key.tag);
        }
    }
}

mod file_decryption {
    use super::*;

    #[test]
    fn cross_sdk_fixtures() {
        for language in ["javascript", "csharp", "java", "swift"] {
            let plain_file_key = load_plain_file_key_fixture(&format!(
                "keys/{language}/fk_rsa2048_aes256gcm/plain_file_key.json"
            ));
            let ciphertext = decode_b64_file(&format!("files/{language}/enc_file.b64"));
            let expected_plaintext = decode_b64_file(&format!("files/{language}/plain_file.b64"));

            let plaintext =
                DracoonCrypto::decrypt_with_plain_file_key(&ciphertext, plain_file_key.clone())
                    .unwrap();
            assert_eq!(plaintext, expected_plaintext);

            let chunked =
                decrypt_streaming_with_plain_file_key(&ciphertext, plain_file_key, &[5]).unwrap();
            assert_eq!(chunked, expected_plaintext);
        }
    }

    #[test]
    fn corrupted_plain_file_key() {
        let ciphertext = decode_b64_file("files/javascript/enc_file.b64");
        let bad_key: PlainFileKey = load_json("keys/corrupted/plain_file_key_bad_key.json");
        let bad_iv: PlainFileKey = load_json("keys/corrupted/plain_file_key_bad_iv.json");
        let bad_tag: PlainFileKey = load_json("keys/corrupted/plain_file_key_bad_tag.json");
        let bad_version = load_json_value("keys/corrupted/plain_file_key_bad_version.json");

        for bad_file_key in [bad_key, bad_iv, bad_tag] {
            let err =
                DracoonCrypto::decrypt_with_plain_file_key(&ciphertext, bad_file_key).unwrap_err();
            assert!(matches!(
                err,
                DracoonCryptoError::CrypterOperationFailed(_) | DracoonCryptoError::BadData
            ));
        }

        assert!(serde_json::from_value::<PlainFileKey>(bad_version).is_err());
    }
}

mod encrypt {
    use super::*;

    #[test]
    fn generates_distinct_file_keys_for_same_plaintext() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let message = b"internal file key generation must stay private";

        let (ciphertext_a, file_key_a) = DracoonCrypto::encrypt(message, keypair.clone()).unwrap();
        let (ciphertext_b, file_key_b) = DracoonCrypto::encrypt(message, keypair.clone()).unwrap();

        assert_ne!(file_key_a.iv, file_key_b.iv);
        assert_ne!(file_key_a.key, file_key_b.key);
        assert_ne!(ciphertext_a, ciphertext_b);

        let plaintext_a =
            DracoonCrypto::decrypt(&ciphertext_a, file_key_a, keypair.clone()).unwrap();
        let plaintext_b = DracoonCrypto::decrypt(&ciphertext_b, file_key_b, keypair).unwrap();

        assert_eq!(plaintext_a, message);
        assert_eq!(plaintext_b, message);
    }

    #[test]
    fn supports_empty_input() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let (ciphertext, file_key) = DracoonCrypto::encrypt([], keypair.clone()).unwrap();
        let plaintext = DracoonCrypto::decrypt(&ciphertext, file_key, keypair).unwrap();

        assert!(ciphertext.is_empty());
        assert!(plaintext.is_empty());
    }
}

mod decrypt {
    use super::*;

    #[test]
    fn rejects_mismatched_file_key() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let plaintext = sample_plaintext(2048);

        let (ciphertext_a, _) = DracoonCrypto::encrypt(&plaintext, keypair.clone()).unwrap();
        let (_, file_key_b) = DracoonCrypto::encrypt(&plaintext, keypair.clone()).unwrap();

        let err = DracoonCrypto::decrypt(&ciphertext_a, file_key_b, keypair).unwrap_err();
        assert!(matches!(
            err,
            DracoonCryptoError::CrypterOperationFailed(_) | DracoonCryptoError::BadData
        ));
    }
}

mod streaming_encrypt {
    use super::*;

    #[test]
    fn finalize_without_update() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let mut encryptor = DracoonCrypto::file_encryptor(keypair.clone()).unwrap();
        let first_chunk = encryptor.update(&[]).unwrap();
        let finalized = encryptor.finalize().unwrap();
        let plaintext = DracoonCrypto::decrypt(&first_chunk, finalized.file_key, keypair).unwrap();

        assert!(first_chunk.is_empty());
        assert!(finalized.final_chunk.is_empty());
        assert!(plaintext.is_empty());
    }

    #[test]
    fn matches_one_shot_encrypt_for_same_file_key() {
        let plaintext = sample_plaintext(8192);
        let schedules: &[&[usize]] = &[&[1], &[2, 15, 16, 17], &[31, 33, 7, 1024]];

        for schedule in schedules {
            let plain_file_key = PlainFileKey::try_new_for_encryption().unwrap();
            let (expected_ciphertext, expected_key) =
                DracoonCrypto::encrypt_with_plain_file_key(&plaintext, plain_file_key.clone())
                    .unwrap();
            let (actual_ciphertext, actual_key) =
                encrypt_streaming_with_plain_file_key(&plaintext, plain_file_key, schedule)
                    .unwrap();

            assert_eq!(actual_ciphertext, expected_ciphertext);
            assert_eq!(actual_key, expected_key);
        }
    }

    #[test]
    fn single_byte_chunks() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let plaintext = sample_plaintext(4096);

        let (ciphertext, file_key) = encrypt_streaming(&plaintext, keypair.clone(), &[1]).unwrap();
        let decrypted = DracoonCrypto::decrypt(&ciphertext, file_key, keypair).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn large_irregular_chunks() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let plaintext = sample_plaintext(256 * 1024);

        let (ciphertext, file_key) =
            encrypt_streaming(&plaintext, keypair.clone(), &[1, 17, 3, 64, 2, 1024, 33]).unwrap();
        let decrypted = DracoonCrypto::decrypt(&ciphertext, file_key, keypair).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}

mod streaming_decrypt {
    use super::*;

    #[test]
    fn finalize_without_update() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let (ciphertext, file_key) = DracoonCrypto::encrypt([], keypair.clone()).unwrap();
        let plaintext = decrypt_streaming(&ciphertext, file_key, keypair, &[1]).unwrap();

        assert!(plaintext.is_empty());
    }

    #[test]
    fn matches_one_shot_decrypt_for_same_file_key() {
        let plaintext = sample_plaintext(8192);
        let schedules: &[&[usize]] = &[&[1], &[2, 15, 16, 17], &[31, 33, 7, 1024]];

        for schedule in schedules {
            let plain_file_key = PlainFileKey::try_new_for_encryption().unwrap();
            let (ciphertext, finalized_key) =
                DracoonCrypto::encrypt_with_plain_file_key(&plaintext, plain_file_key).unwrap();
            let expected_plaintext =
                DracoonCrypto::decrypt_with_plain_file_key(&ciphertext, finalized_key.clone())
                    .unwrap();
            let actual_plaintext =
                decrypt_streaming_with_plain_file_key(&ciphertext, finalized_key, schedule)
                    .unwrap();

            assert_eq!(actual_plaintext, expected_plaintext);
        }
    }

    #[test]
    fn single_byte_chunks() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let plaintext = sample_plaintext(4096);
        let (ciphertext, file_key) = DracoonCrypto::encrypt(&plaintext, keypair.clone()).unwrap();

        let decrypted = decrypt_streaming(&ciphertext, file_key, keypair, &[1]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_tag_fails_on_finalize() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let plaintext = sample_plaintext(4096);
        let (ciphertext, mut file_key) =
            DracoonCrypto::encrypt(&plaintext, keypair.clone()).unwrap();
        file_key.tag = file_key.tag.as_ref().map(|tag| tamper_base64(tag));

        let mut decryptor = DracoonCrypto::file_decryptor(file_key, keypair).unwrap();
        for chunk in chunk_slices(&ciphertext, &[17, 31]) {
            let _ = decryptor.update(chunk).unwrap();
        }

        let err = decryptor.finalize().unwrap_err();
        assert!(matches!(err, DracoonCryptoError::CrypterOperationFailed(_)));
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let plaintext = sample_plaintext(4096);
        let (ciphertext, file_key) = DracoonCrypto::encrypt(&plaintext, keypair.clone()).unwrap();

        let err = decrypt_streaming(
            &ciphertext[..ciphertext.len() - 1],
            file_key,
            keypair,
            &[15, 16, 17],
        )
        .unwrap_err();

        assert!(matches!(err, DracoonCryptoError::CrypterOperationFailed(_)));
    }

    #[test]
    fn extra_ciphertext_fails() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let plaintext = sample_plaintext(4096);
        let (mut ciphertext, file_key) =
            DracoonCrypto::encrypt(&plaintext, keypair.clone()).unwrap();
        ciphertext.push(0);

        let err = decrypt_streaming(&ciphertext, file_key, keypair, &[7, 29]).unwrap_err();
        assert!(matches!(err, DracoonCryptoError::CrypterOperationFailed(_)));
    }

    #[test]
    fn invalid_wrapped_file_key_fails_on_creation() {
        let keypair = generate_keypair(UserKeyPairVersion::RSA4096);
        let (_, mut file_key) =
            DracoonCrypto::encrypt(sample_plaintext(128), keypair.clone()).unwrap();
        file_key.key = "%%%".to_string();

        let err = match DracoonCrypto::file_decryptor(file_key, keypair) {
            Ok(_) => panic!("creating decryptor with invalid wrapped file key should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            DracoonCryptoError::InvalidFileKeyFormat(_) | DracoonCryptoError::RsaOperationFailed
        ));
    }
}
