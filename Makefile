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

.PHONY: venv
# re-run as necessary
venv:
	python3 -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r requirements.txt

watch:
	cargo watch -x 'build --release'

