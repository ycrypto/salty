TARGET = thumbv7em-none-eabihf
build:
	cargo build --release --target $(TARGET)
	cp target/$(TARGET)/release/build/salty-*/out/libsalty-asm.a libsalty-asm.a
	cp target/$(TARGET)/release/libsalty_c_api.a libsalty.a
	cargo build --target $(TARGET)
	cp target/$(TARGET)/debug/libsalty_c_api.a libsalty-debug.a

deep-clean: clean

clean:
	cargo clean
	make -C example clean

libopencm3/lib/libopencm3_stm32f4.a:
	$(MAKE) -C libopencm3

example/example.elf: libopencm3/lib/libopencm3_stm32f4.a
	$(MAKE) -C example

build-example: example/example.elf

SEMIHOSTING = -semihosting-config enable=on,target=native
SPEC = -cpu cortex-m33 -machine musca-b1 -nographic
run-example: build-example
	# Get out via Ctrl-A X in case QEMU does not return
	qemu-system-arm $(SPEC) $(SEMIHOSTING) -kernel example/example.elf

run-example-gdb:
	# Get out via Ctrl-A X
	qemu-system-arm $(SPEC) $(SEMIHOSTING) -kernel example/example.elf -gdb tcp::1234 -S

gdb-example:
	arm-none-eabi-gdb -q -x ../qemu-tests/qemu.gdb example/example.elf
	qemu-system-arm $(SPEC) $(SEMIHOSTING) -kernel example/example.elf -gdb tcp::1234 -S

.PHONY: build clean deep-clean build-example run-example run-example-gdb gdb-example
