<h1 align="center">salty</h1>
<div align="center">
 <strong>
   Ed25519 signatures for microcontrollers
 </strong>
</div>

<br />

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/salty">
    <img src="https://img.shields.io/crates/v/salty.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/salty">
    <img src="https://img.shields.io/crates/d/salty.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- main branch API docs -->
  <a href="https://salty-api.netlify.com">
    <img src="https://img.shields.io/badge/docs-main_branch-blue.svg?style=flat-square"
      alt="main branch API docs" />
  </a>
  <!-- main branch book -->
  <a href="https://salty-book.netlify.com">
    <img src="https://img.shields.io/badge/book-main_branch-blue.svg?style=flat-square"
      alt="main branch book" />
  </a>
</div>

<div align="center">
  <h3>
    <a href="https://docs.rs/salty">
      API Docs
    </a>
    <span> | </span>
    <a href="https://github.com/nickray/salty/blob/main/.github/CONTRIBUTING.md">
      Contributing
    </a>
  </h3>
</div>

## Overview

[![Build Status][build-image]][build-link] 

[build-image]: https://builds.sr.ht/~nickray/salty.svg
[build-link]: https://builds.sr.ht/~nickray/salty
[crate-image]: https://img.shields.io/crates/v/salty.svg
[crate-link]: https://crates.io/crates/salty
[license-image]: https://img.shields.io/badge/license-Apache2.0%2FMIT-blue.svg
[docs-image]: https://docs.rs/salty/badge.svg?style=flat-square
[docs-link]: https://docs.rs/salty
[docs-main-image]: https://img.shields.io/badge/docs-main-blue?style=flat-square
[docs-main-link]: https://salty-api.netlify.com
[solokeys-img]: .github/images/solokeys-120-40.png
[solokeys-url]: https://solokeys.com
[yamnord-img]: .github/images/yamnord-120-40-alt.png
[yamnord-url]: https://yamnord.com

Small, sweet, swift: Ed25519 signatures for microcontrollers.  
With assembly optimizations for Cortex-M4 and Cortex-M33.

**NOTE: This is work-in-progress and not audited! The usual warnings apply: Your hamster will explode, etc. etc.**

Work on salty is sponsored by

[![SoloKeys][solokeys-img]][solokeys-url]
[![yamnord][yamnord-img]][yamnord-url]

## Goals

From highest to lowest priority:
- [understandable](https://blog.filippo.io/a-literate-go-implementation-of-poly1305/) code
- timing side-channel free
- design for easy integration in embedded projects
- sufficiently small compiled code size
- useful speed

## The Plan

None of these releases exist quite yet.

### v0.1.0

Basic signature functionality

- allocation free API for signatures
- transcription of Ed25519 from [TweetNaCl](https://tweetnacl.cr.yp.to/20140427/tweetnacl.c)
- Bjoern Haase's [field arithmetic optimizations](https://github.com/BjoernMHaase/fe25519/tree/master/STM32F407/crypto/asm)
- use [subtle](https://github.com/dalek-cryptography/subtle) 

### v0.2.0

More tests!

- fuzzing to test correctness against known good implementation
- [side-fuzzing](https://tweetnacl.cr.yp.to/20140427/tweetnacl.c) to test for timing side-channels

### v0.3.0

Completion! The rest of NaCl.

- X22519
- authenticated encryption

#### License

<sup>The `scalar29` implementation is from `curve25519-daleks`'s u32 backend: [LICENSE](https://github.com/dalek-cryptography/curve25519-dalek/blob/master/LICENSE).
<br>
Salty is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.</sup>
<br>
<sub>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.</sub>
<br>
<sub>[TweetNaCl](https://tweetnacl.cr.yp.to/) is a public-domain library.</sub>
<br>
<sub>[fe25519](https://github.com/BjoernMHaase/fe25519) is licensed under Creative Commons Zero v1.0 Universal.</sub>
