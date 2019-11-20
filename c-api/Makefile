build:
	cargo build --release --features haase --target thumbv7em-none-eabi
	cp target/thumbv7em-none-eabi/release/libsalty_c_api.a libsalty.a
	cargo build --features haase --target thumbv7em-none-eabi
	cp target/thumbv7em-none-eabi/debug/libsalty_c_api.a libsalty-debug.a
