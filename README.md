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
- Symmetric encryption / decryption of messages (AES256 GCM)
  - on the fly encryption / decryption 
  - chunked encryption / decryption

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
dco3_crypto = "0.4.0"
```

## Documentation

[Documentation](https://docs.rs/dco3_crypto/latest/dco3_crypto)
All detailed documentation is provided via docs on [docs.rs](https://docs.rs/dco3_crypto/latest/dco3_crypto)

## TL; DR usage

### Required imports

The lib consists of several traits that are all (currently only) implemented by the `DracoonCrypto` struct.
Therefore, the minimum required import is *always* `DracoonCrypto` and the relevant required trait (`DracoonRSACrypto`, `Encrypt`, `Decrypt`, `ChunkedEncryption`, `Encrypter`, `Decrypter`).

#### Asymmetric encryption

In order to 
- generate a (plain) user keypair 
- en/decrypt a user keypair
- encrypt a private only
- encrypt a file key with a public key (user keypair)
- decrypt a file key with a private key (user keypair)


Generate a plain user keypair:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeypairVersion};

// RSA2048 is only supported for legacy compatibility 
// always use UserKeypairVersion::RSA4096
let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();

```

Encrypt a plain user keypair:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeypairVersion};

let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let secret ="VerySecret123!";
let enc_keypair = DracoonCrypto::encrypt_private_key(secret, new_keypair).unwrap();

```

Encrypt a private key only:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeypairVersion};

let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let secret ="VerySecret123!";
let enc_private_key = DracoonCrypto::encrypt_private_key_only(secret, new_keypair.private_key_container).unwrap();

```

Decrypt a protected user keypair:
```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeypairVersion};

let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();
let secret ="VerySecret123!";
let enc_keypair = DracoonCrypto::encrypt_private_key(secret, new_keypair).unwrap();
let plain_keypair = DracoonCrypto::decrypt_private_key(secret, enc_keypair).unwrap();

```

Encrypt a file key using either a plain user keypair or a public key container:

```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeypairVersion, Encrypt};
let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();

// encrypt a message to get a plain file key for demo purposes
let message = b"Secret message";
let (enc_message, plain_file_key) = DracoonCrypto::encrypt(message.to_vec()).unwrap();

// the function also accepts a public key container as argument
let enc_file_key = DracoonCrypto::encrypt_file_key(plain_file_key, plain_keypair).unwrap();
```

Decrypt the file key using a plain user keypair:
```rust
use dco3_crypto::{DracoonCrypto, DracoonRSACrypto, UserKeypairVersion, Encrypt};
let new_keypair = DracoonCrypto::create_plain_user_keypair(UserKeyPairVersion::RSA4096).unwrap();

// encrypt a message to get a plain file key for demo purposes
let message = b"Secret message";
let (enc_message, plain_file_key) = DracoonCrypto::encrypt(message.to_vec()).unwrap();

// the function also accepts a public key container as argument
let enc_file_key = DracoonCrypto::encrypt_file_key(plain_file_key, plain_keypair).unwrap();

// this code is for demo purposes - plain_keypair is consumed above and needs to be 
// instantiated again
let plain_file_key = DracoonCrypto::decrypt_file_key(enc_file_key, plain_keypair).unwrap();
```

#### Symmetric encryption

Symmetric encryption is represented by the following traits:

- Encrypt: needed for in-memory encryption
- Decrypt: needed for in-memory decryption
- Decrypter: needed to build a decrypter capable of chunked decryption
- Encrypter: needed to build an encrypter capable of chunked encryption
- ChunkedEncryption: needed for both en- and decryption when using a decrypter / encrypter

Encrypt a message on the fly:

```rust
use dco3_crypto::{DracoonCrypto, Encrypt};

// encrypt a message to get a plain file key for demo purposes
let message = b"Secret message";
let (enc_message, plain_file_key) = DracoonCrypto::encrypt(message.to_vec()).unwrap();

// to encrypt the file key, see asymmetric encryption above
```

Decrypt a message on the fly:

```rust
use dco3_crypto::{DracoonCrypto, Encrypt, Decrypt};

// encrypt a message to get a plain file key for demo purposes
let message = b"Secret message";
let (enc_message, plain_file_key) = DracoonCrypto::encrypt(message.to_vec()).unwrap();

// to decrypt / encrypt the file key, see asymmetric encryption above
let plain_message = DracoonCrypto::decrypt(&enc_message, plain_file_key);
```

Encrypt in chunks:

```rust
use dco3_crypto::{DracoonCrypto, Encrypter, ChunkedEncryption};
let mut message = b"Encrypt this very long message in chunks and decrypt it";
let buff_len = message.len() + 1;
let mut buf = vec![0u8; buff_len];
let mut encrypter = DracoonCrypto::encrypter(&mut buf).unwrap();
let mut count: usize = 0;

// chunks of 8 bytes
const CHUNKSIZE: usize = 8;
let mut chunks = message.chunks(CHUNKSIZE);
while let Some(chunk) = chunks.next() {
  count += encrypter.update(&chunk).unwrap();
  };

count += encrypter.finalize().unwrap();
let enc_message = encrypter.get_message();
let plain_file_key = encrypter.get_plain_file_key();

```


Decrypt in chunks:

```rust
// importing Encrypt is only necessary for the inital message encryption
use dco3_crypto::{DracoonCrypto, Encrypt, Decrypter, ChunkedEncryption};
use openssl::symm::Cipher;
let message = b"Encrypt this very long message in chunks and decrypt it";
    
let (message, plain_file_key) = DracoonCrypto::encrypt(message.to_vec()).unwrap();
let buff_len = message.len() + 1;
    
let mut chunks = message.chunks(5);
let mut buf = vec![0u8; buff_len];
let mut decrypter = DracoonCrypto::decrypter(plain_file_key, &mut buf).unwrap();
let mut count: usize = 0;
while let Some(chunk) = chunks.next() {
  count += decrypter.update(&chunk).unwrap();
  }

count += decrypter.finalize().unwrap();
    
let plain_message = std::str::from_utf8(decrypter.get_message()).unwrap();
  
```