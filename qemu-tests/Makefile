.PHONY: build run
build:
	cargo build

run:
	cargo run

SEMIHOSTING = -semihosting-config enable=on,target=native
KERNEL = target/thumbv8m.main-none-eabi/debug/qemu-tests
CPU = cortex-m33
MACHINE = musca-b1
QEMU = ../../qemu/arm-softmmu/qemu-system-arm
# QEMU_DEBUG = -d in_asm,int,exec,cpu,guest_errors,unimp

qemu: build
	$(QEMU) -cpu $(CPU) -machine $(MACHINE) -nographic $(SEMIHOSTING) -kernel $(KERNEL) $(QEMU_DEBUG)

qemu-gdb: build
	# Exit with <Ctrl-A X>
	$(QEMU) -cpu $(CPU) -machine $(MACHINE) -nographic $(SEMIHOSTING) -kernel $(KERNEL) -gdb tcp::1234 -S $(QEMU_DEBUG)

# assume gcc-arm-none-eabi-8-2019-q3-update
gdb:
	arm-none-eabi-gdb -q -x qemu.gdb target/thumbv8m.main-none-eabi/debug/qemu-tests

