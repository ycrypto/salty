TARGET = thumbv7em-none-eabihf
build:
	cargo build --release --target $(TARGET)
	cp target/$(TARGET)/release/build/salty-*/out/libsalty-asm.a libsalty-asm.a
	cp target/$(TARGET)/release/libsalty_c_api.a libsalty.a
	cargo build --target $(TARGET)
	cp target/$(TARGET)/debug/libsalty_c_api.a libsalty-debug.a

deep-clean: clean
	rm -rf example/libopencm3

clean:
	cargo clean
	make -C example clean

prepare-example:
	-git clone https://github.com/libopencm3/libopencm3 example/libopencm3
	# FP_FLAGS="-mfloat-abi=soft" $(MAKE) -C example/libopencm3
	$(MAKE) -C example/libopencm3
	# for some reason, libopencm3 overwrites our nice `link.x`
	git checkout example/link.x

build-example:
	$(MAKE) -C example

SEMIHOSTING = -semihosting-config enable=on,target=native
SPEC = -cpu cortex-m33 -machine musca-b1 -nographic
run-example:
	# Get out via Ctrl-A X
	qemu-system-arm $(SPEC) $(SEMIHOSTING) -kernel example/example.elf

run-example-gdb:
	# Get out via Ctrl-A X
	qemu-system-arm $(SPEC) $(SEMIHOSTING) -kernel example/example.elf -gdb tcp::1234 -S

gdb-example:
	arm-none-eabi-gdb -q -x ../qemu-tests/qemu.gdb example/example.elf
	qemu-system-arm $(SPEC) $(SEMIHOSTING) -kernel example/example.elf -gdb tcp::1234 -S
