TARGET ?= thumbv7em-none-eabihf

build build-release:
	cargo build --release --features tweetnacl # --target x86_64-unknown-linux-gnu
	cargo build --release --features tweetnacl --target thumbv7em-none-eabihf
	cargo build --release --features haase --target thumbv7em-none-eabihf

build-debug:
	cargo build

c-bindings:
	cbindgen --config cbindgen.toml --output auto_salty.h

local-docs:
	cargo doc --document-private-items --features tweetnacl

fmt:
	cargo fmt

rustup:
	rustup target add $(TARGET)
	rustup component add rustfmt

test:
	cargo test --features tweetnacl

.PHONY: venv
# re-run as necessary
venv:
	python3 -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r requirements.txt

watch:
	cargo watch -x 'build --release'

