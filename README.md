  <h3 align="center">dco3-crypto</h3>

  <p align="center">
    DRACOON Crypto utils in Rust
    <br />
    <a href="https://github.com/unbekanntes-pferd/dco3-crypto"><strong>Explore the docs »</strong></a>
    <br />
    <a href="https://github.com/unbekanntes-pferd/dco3-crypto/issues">Report Bug</a>
  </p>
</p>

# dco3-crypto

## What is this?

Work in progress Crypto library for DRACOON based on openssl crate.

### What does work?

- Asymmetric encryption / decryption of file keys (RSA)
- Symmetric encryption / decryption of messages (AES256 GCM)
  - on the fly encryption / decryption 
  - chunked encryption / decryption

### What is planned?

- Chunked encryption / decryption is currently not generic and requires openssl crate
  - make Crypter generic, so that other libraries can be used

### What is shipped?
Using the crate binds to the latest openssl version and is compiled in vendored mode (see [openssl](https://crates.io/crates/openssl) for details). 

### How to use?

See [crates.io](https://crates.io/crates/dco3_crypto)
TL;DR Add the following line to your Cargo.toml file (dependencies):
```toml
dco3_crypto = "0.2.0"
```

## Documentation

[Documentation](https://docs.rs/dco3_crypto/latest/dco3_crypto)
All documentation is provided via docs on [docs.rs](https://docs.rs/dco3_crypto/latest/dco3_crypto)
