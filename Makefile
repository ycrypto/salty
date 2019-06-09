TARGET ?= thumbv7em-none-eabihf

build build-release:
	cargo build --release

build-debug:
	cargo build

rustup:
	rustup target add $(TARGET)
	rustup component add rustfmt

fmt:
	cargo fmt
