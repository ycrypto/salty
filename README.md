# Salty

[![Build Status][build-image]][build-link] 
[![Salty][crate-image]][crate-link]
![Apache 2.0 OR MIT licensed][license-image]

[build-image]: https://img.shields.io/circleci/build/github/nickray/salty/master.svg
[build-link]: https://circleci.com/gh/nickray/salty/tree/master
[crate-image]: https://img.shields.io/crates/v/salty.svg
[crate-link]: https://crates.io/crates/salty
[license-image]: https://img.shields.io/badge/license-Apache2.0%2FMIT-blue.svg

Small sweet Ed25519 for microcontrollers.  
With optimizations for Cortex-M4.

## Goals

From highest to lowest priority:
- [understandable](https://blog.filippo.io/a-literate-go-implementation-of-poly1305/) code
- timing side-channel free
- design for easy integration in embedded projects
- small compiled code size
- speed

## The Plan

### v0.1.0

Basic signature functionality

- allocation free API for signatures
- transcription of Ed25519 from [TweetNaCl](https://tweetnacl.cr.yp.to/20140427/tweetnacl.c)

### v0.2.0

Tests!

- integrate [subtle](https://github.com/dalek-cryptography/subtle) 
- fuzzing to test correctness against known good implementation
- [side-fuzzing](https://tweetnacl.cr.yp.to/20140427/tweetnacl.c) to test timing side-channels (or lack thereof, see v0.2.0)

### v0.3.0

Faster!

- Bjoern Haase's [field arithmetic optimizations](https://github.com/BjoernMHaase/fe25519/tree/master/STM32F407/crypto/asm)

### v0.4.0

Completion! The rest of NaCl

- X22519
- authenticated encryption
- asymmetric cryptography 

## License

Salty is licensed under either of

- Apache License v2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
