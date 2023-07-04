TARGET ?= thumbv7em-none-eabihf
WYCHEPROOF_EDDSA_TEST_JSON_URL  ?= https://raw.githubusercontent.com/google/wycheproof/master/testvectors/eddsa_test.json
WYCHEPROOF_X25519_TEST_JSON_URL ?= https://raw.githubusercontent.com/google/wycheproof/master/testvectors/x25519_test.json

build build-release:
	cargo build --release
	cargo build --release --target thumbv7em-none-eabi
	cargo build --release --features slow-motion --target thumbv7em-none-eabi

build-debug:
	cargo build

local-docs:
	cargo doc --document-private-items

fmt:
	cargo fmt

rustup:
	rustup target add $(TARGET)
	rustup component add rustfmt

tests/eddsa_test.json:
	curl -sSf "$(WYCHEPROOF_EDDSA_TEST_JSON_URL)" -o $@

tests/x25519_test.json:
	curl -sSf "$(WYCHEPROOF_X25519_TEST_JSON_URL)" -o $@

test: tests/eddsa_test.json tests/x25519_test.json
	cargo test
	make -C qemu-tests test

.PHONY: venv
# re-run as necessary
venv:
	python3 -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r requirements.txt

watch:
	cargo watch -x 'build --release'

clean:
	rm -f tests/eddsa_test.json
	rm -f tests/x25519_test.json
	cargo clean
