# Testing

The `tweetnacl` implementation can be tested on desktop via `cargo test`.

For the `haase` implementation, we make use of the `musca-b1` Cortex-M33 microcontroller,
which is emulated in QEMU starting with version 4.
The subdirectory [qemu-tests](https://github.com/nickray/salty/tree/main/qemu-tests)
contains tests for all the RFC 8032 test vectors, they can be run via
`cargo run --release`.

All of these tests run as part of [continuous integration](https://builds.sr.ht/~nickray/salty).

In the future, we intend to test for timing side-channels.

The [C API](./c-api.md) has its own tests.
