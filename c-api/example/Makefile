PROJECT = example
BUILD_DIR = bin

CFILES = $(PROJECT).c

# TODO - you will need to edit these two lines!
### DEVICE=stm32f407vgt6
### OOCD_FILE = board/stm32f4discovery.cfg

# use 'manual' board setup to avoid linker script generation
# this is a hybrid setup for running an STM32F4 targeted binary on the ARM
# musca B1 evaluation board, which is the only working cortex M4 compatible
# platform found in QEMU
LDSCRIPT     = musca-b1.ld
OPENCM3_LIB  = opencm3_stm32f4
OPENCM3_DEFS = -DSTM32F4 -DSTM32F4CCM -DSTM32F407VGT6
ARCH_FLAGS   = -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16

# SEMIHOSTING
LDFLAGS += -specs=rdimon.specs
LDLIBS  += -lrdimon

OPENCM3_DIR=../libopencm3

INCLUDES += -I..
LDLIBS += ../libsalty.a
LDLIBS += ../libsalty-asm.a

###include $(OPENCM3_DIR)/mk/genlink-config.mk
include rules.mk
###include $(OPENCM3_DIR)/mk/genlink-rules.mk
