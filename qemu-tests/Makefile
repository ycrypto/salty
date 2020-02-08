main-test:
	cargo run --release

test:
	@echo "\nTesting Haase field implementation, debug build\n"
	time cargo run
	@echo "\nTesting Haase field implementation, release build\n"
	time cargo run --release
	# @echo "\nTesting TweetNaCl field implementation, debug build"
	# @echo "Patience please, this is veeery slow :)\n"
	time cargo run --features slow
	@echo "\nTesting TweetNaCl field implementation, release build\n"
	time cargo run --features slow --release

size: build
	arm-none-eabi-size $(KERNEL)

build:
	cargo build

build-release:
	cargo build --release

size-release: build-release
	arm-none-eabi-size $(KERNEL_RELEASE)
	arm-none-eabi-size $(KERNEL_RELEASE) -A

run:
	cargo run

run-release:
	# cargo size --features $(IMPL) --release
	arm-none-eabi-size $(KERNEL_RELEASE)
	cargo run --release

SEMIHOSTING = -semihosting-config enable=on,target=native
KERNEL = target/thumbv8m.main-none-eabi/debug/qemu-tests
KERNEL_RELEASE = target/thumbv8m.main-none-eabi/release/qemu-tests
CPU = cortex-m33
MACHINE = musca-b1
QEMU = ../../qemu/arm-softmmu/qemu-system-arm
# QEMU_DEBUG = -d in_asm,int,exec,cpu,guest_errors,unimp

qemu: #build
	$(QEMU) -cpu $(CPU) -machine $(MACHINE) -nographic $(SEMIHOSTING) -kernel $(KERNEL) $(QEMU_DEBUG)

qemu-gdb: #build
	# Exit with <Ctrl-A X>
	$(QEMU) -cpu $(CPU) -machine $(MACHINE) -nographic $(SEMIHOSTING) -kernel $(KERNEL) -gdb tcp::1234 -S $(QEMU_DEBUG)

# assume gcc-arm-none-eabi-8-2019-q3-update
gdb:
	arm-none-eabi-gdb -q -x qemu.gdb target/thumbv8m.main-none-eabi/debug/qemu-tests

