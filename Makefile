TARGET ?= thumbv7em-none-eabihf

build build-release:
	cargo build --release

build-debug:
	cargo build

fmt:
	cargo fmt

rustup:
	rustup target add $(TARGET)
	rustup component add rustfmt

test:
	cargo test

watch:
	cargo watch -x 'build --release'

