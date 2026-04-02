  <h1 align="center">dco3-crypto</h1>

  <p align="center">
    DRACOON Crypto utils in Rust
    <br />
    <a href="https://docs.rs/dco3_crypto/latest/dco3_crypto"><strong>Documentation »</strong></a>
    <br />
    <a href="https://github.com/unbekanntes-pferd/dco3-crypto/issues">Report Bug</a>
  </p>
</p>

# dco3-crypto

## What is this?

Work in progress Crypto library for DRACOON based on openssl crate.

**Breaking changes** are most likely at this early stage - the library is under heavy development and depends on requirements from `dco3` (currently private API wrapper for DRACOON).
Changes will be documented in the [release notes](https://github.com/unbekanntes-pferd/dco3-crypto/releases).

### What does work?

- Asymmetric encryption / decryption of file keys (RSA)
- Keypair generation (RSA)
- Keypair encryption / decryption (RSA)
- Symmetric encryption / decryption of files (AES256 GCM)
  - one-shot encryption / decryption
  - streaming encryption / decryption

### What is planned?

- Refactor asymmetric encryption (split keypair generation from other operations)
- Use other libraries like ring as alternative to openssl bindings
- Add feature flags to cargo build
- Add e2e tests using encryption data from other SDKs / libs and ensure compatibility in pipeline

### What is shipped?
Using the crate currently binds to the latest openssl version and is compiled in vendored mode (see [openssl](https://crates.io/crates/openssl) for details). 

### How to use?

See [crates.io](https://crates.io/crates/dco3_crypto)
TL;DR Add the following line to your Cargo.toml file (dependencies):
```toml
dco3_crypto = "0.10.0"
```

## Documentation

[Documentation](https://docs.rs/dco3_crypto/latest/dco3_crypto)
All detailed documentation is provided via docs on [docs.rs](https://docs.rs/dco3_crypto/latest/dco3_crypto)

## TL; DR usage

### Required imports

The lib exposes traits for one-shot operations and inherent methods for streaming operations.
Import `DracoonCrypto` and add `DracoonRSACrypto`, `Encrypt`, and `Decrypt` as needed.

#### Asymmetric encryption

In order to 
- generate a (plain) user keypair 
- en/decrypt a user keypair
- decrypt a private only
- encrypt a file key with a public key (user keypair)
- decrypt a file key with a private key (user keypair)


Generate a plain user keypair:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};

// RSA2048 is only supported for legacy compatibility 
// always use UserKeyPairVersion::RSA4096
let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();

```

Encrypt a plain user keypair:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};

let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let secret ="VerySecret123!";
let enc_keypair = DracoonCrypto::encrypt_private_key(secret, new_keypair).unwrap();

```

Decrypt a private key only (for public share use):

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};

let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let secret ="VerySecret123!";
let enc_keypair = DracoonCrypto::encrypt_private_key(secret, new_keypair).unwrap();
let plain_private_key =
    DracoonCrypto::decrypt_private_key(secret, &enc_keypair.private_key_container).unwrap();

```

Decrypt a protected user keypair:
```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};

let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let secret ="VerySecret123!";
let enc_keypair = DracoonCrypto::encrypt_private_key(secret, new_keypair).unwrap();
let plain_keypair = DracoonCrypto::decrypt_keypair(secret, enc_keypair).unwrap();

```

Wrap a file key with a public key:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};

let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let mut encryptor = DracoonCrypto::file_encryptor().unwrap();
let _ = encryptor.update(b"Secret message").unwrap();
let finalized = encryptor.finalize().unwrap();

let file_key = DracoonCrypto::encrypt_file_key(finalized.plain_file_key, keypair).unwrap();
```

Unwrap a file key with a private key:
```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};

let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let (_ciphertext, file_key) = DracoonCrypto::encrypt(b"Secret message", keypair.clone()).unwrap();

let plain_file_key = DracoonCrypto::decrypt_file_key(file_key, keypair).unwrap();
```

#### Symmetric encryption

Symmetric encryption is available as:

- `Encrypt`: in-memory encryption
- `Decrypt`: in-memory decryption
- `DracoonCrypto::file_encryptor()`: streaming encryption
- `DracoonCrypto::file_decryptor()`: streaming decryption

Encrypt a message on the fly:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};

let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let (ciphertext, file_key) = DracoonCrypto::encrypt(b"Secret message", keypair.clone()).unwrap();

// `file_key` is already wrapped for `keypair`
```

Decrypt a message on the fly:

```rust
use dco3_crypto::{Decrypt, DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};

let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let (ciphertext, file_key) = DracoonCrypto::encrypt(b"Secret message", keypair.clone()).unwrap();

let plaintext = DracoonCrypto::decrypt(&ciphertext, file_key, keypair).unwrap();
```

Encrypt in chunks:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeyPairVersion};

let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let message = b"Encrypt this very long message in chunks and decrypt it";
let mut encryptor = DracoonCrypto::file_encryptor().unwrap();
let mut ciphertext = Vec::new();

// chunks of 8 bytes
for chunk in message.chunks(8) {
    ciphertext.extend_from_slice(&encryptor.update(chunk).unwrap());
}

let finalized = encryptor.finalize().unwrap();
ciphertext.extend_from_slice(&finalized.final_chunk);

// wrap the plain file key for the intended recipients
let file_key = DracoonCrypto::encrypt_file_key(finalized.plain_file_key, keypair).unwrap();
```


Decrypt in chunks:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, Encrypt, UserKeyPairVersion};

let keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let message = b"Encrypt this very long message in chunks and decrypt it";
let (ciphertext, file_key) = DracoonCrypto::encrypt(message, keypair.clone()).unwrap();

let mut decryptor = DracoonCrypto::file_decryptor(file_key, keypair).unwrap();
let mut plaintext = Vec::new();

for chunk in ciphertext.chunks(5) {
    plaintext.extend_from_slice(&decryptor.update(chunk).unwrap());
}

plaintext.extend_from_slice(&decryptor.finalize().unwrap());
```
