PROJECT = example
BUILD_DIR = bin

CFILES = $(PROJECT).c

# TODO - you will need to edit these two lines!
DEVICE=stm32f407vgt6
OOCD_FILE = board/stm32f4discovery.cfg

VPATH += $(SHARED_DIR)
INCLUDES += $(patsubst %,-I%, . $(SHARED_DIR))
OPENCM3_DIR=libopencm3

INCLUDES += -I..
LDLIBS += ../libsalty.a
LDLIBS += ../libsalty-asm.a
LDSCRIPT = link.x
LDFLAGS	+= --specs=rdimon.specs
LDLIBS+= -lrdimon

include $(OPENCM3_DIR)/mk/genlink-config.mk
include rules.mk
include $(OPENCM3_DIR)/mk/genlink-rules.mk
