TARGET ?= thumbv7em-none-eabihf

build build-release:
	cargo build --release
	cargo build --release --target thumbv7em-none-eabi
	cargo build --release --features slow-motion --target thumbv7em-none-eabi

build-debug:
	cargo build

c-bindings:
	cbindgen --config cbindgen.toml --output auto_salty.h

local-docs:
	cargo doc --document-private-items

fmt:
	cargo fmt

rustup:
	rustup target add $(TARGET)
	rustup component add rustfmt

test:
	cargo test

.PHONY: venv
# re-run as necessary
venv:
	python3 -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r requirements.txt

watch:
	cargo watch -x 'build --release'

