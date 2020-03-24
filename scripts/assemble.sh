#!/bin/sh

set -eux

crate=salty

# arm-none-eabi-as -march=armv7e-m asm/add.s -o bin/$crate-add.o
arm-none-eabi-as asm/fe25519_add.s -o bin/$crate-add.o
arm-none-eabi-as -march=armv7e-m haase/cortex_m4_mpy_fe25519.S -o bin/$crate-mpy.o
arm-none-eabi-as -march=armv7e-m haase/cortex_m4_sqr_fe25519.S -o bin/$crate-sqr.o

rm -f bin/*.a
ar crs bin/salty-asm.a bin/$crate-add.o bin/$crate-mpy.o bin/$crate-sqr.o

rm bin/*.o
