# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2023-07-04
- accept any 32 byte array as X25519 public key per RFC 7748
- bump edition to 2021 throughout
- cargo clippy + fmt
- bump dependency versions
- make dependency on RustCrypto/ed25519 a feature
- run wycheproof on signing, not just verification (#28)
- check more in ci.yml
