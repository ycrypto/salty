build:
	cargo build --release
	cargo build --release --target thumbv7em-none-eabi

clean:
	cargo clean
	make -C c-api clean

test:
	# Test on PC
	cargo test
	# Test on QEMU
	make -C qemu-tests test
	# Test C API
	make -C c-api test

fmt:
	cargo fmt --all

fix: fmt
	cargo clippy --fix --workspace --allow-staged

# used in CI
check:
	# cargo check --all
	cargo check -p salty
	cargo check -p salty-c-api --target thumbv7em-none-eabi
	cargo check -p qemu-tests
	cargo check -p wycheproof-macros
	cargo check -p wycheproof-parser
	cargo check -p wycheproof-types

# used in CI
lint:
	cargo fmt --check --all
	# cargo clippy --workspace
	cargo clippy -p salty
	cargo clippy -p salty-c-api --target thumbv7em-none-eabi
	cargo clippy -p qemu-tests
	cargo clippy -p wycheproof-macros
	cargo clippy -p wycheproof-parser
	cargo clippy -p wycheproof-types

local-docs:
	cargo doc --document-private-items

rustup-targets:
	rustup target add thumbv7em-none-eabi
	rustup target add thumbv8m.main-none-eabi

WP_VECTOR_SOURCE = https://raw.githubusercontent.com/google/wycheproof/master/testvectors
WP_SCHEMA_SOURCE = https://raw.githubusercontent.com/google/wycheproof/master/schemas
WP_DATA = wycheproof/data
update-wycheproof-data:
	curl -sSf $(WP_VECTOR_SOURCE)/eddsa_test.json -o $(WP_DATA)/eddsa_test.json
	curl -sSf $(WP_SCHEMA_SOURCE)/eddsa_verify_schema.json -o $(WP_DATA)/eddsa_verify_schema.json
	curl -sSf $(WP_VECTOR_SOURCE)/x25519_test.json -o $(WP_DATA)/x25519_test.json
	curl -sSf $(WP_SCHEMA_SOURCE)/xdh_comp_schema.json -o $(WP_DATA)/xdh_comp_schema.json
