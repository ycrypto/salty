// Implementation of squaring function for cortex M4
//
// The code is derived from the register-allocating code generator
// for performance and correctness reasons. Do not edit by hand!
//
// Author: Björn Haase (bjoern.m.haase@web.de) 
// 
// License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// Code is tested on various targets and on Qemu.

#include "attributesForCortexM4.inc"

	.code	16
	
	.file	"cortex_m4_sqr_fe25519.S"
	
	.text
	.align	2

// ****************************************************
// Implementation of fe25519 square.
// uses packed non-redundant representation.
// 
// 
// implements the interface
//
// void
// fe25519_square_asm (fe25519 *pResult, const fe25519 *pVal1);
//	
// in:
//    r0 == ptr to Result word
//    r1 == prt to value to square
//
// Reduces modulo such that the result fits in 256 bits, i.e. not necessarily fully
// reduced!

	.global	fe25519_square_asm
	.type	fe25519_square_asm, %function
fe25519_square_asm:

// ######################
// ASM fe25519 Square and reduce for M4:
// ######################
 // START: fe25519 squaring for M4 (MPY + partial reduce)
 // r0 = result ptr, r1 = operand ptr.

     .syntax unified
    push {r0,r4,r5,r6,r7,r8,r9,r10,r11,r12,r14}
   .syntax divided
    add SP,#-20

    .syntax unified
    ldr r0,[r1,#0]
    .syntax divided
    .syntax unified
    ldr r2,[r1,#4]
    .syntax divided
    .syntax unified
    ldr r3,[r1,#8]
    .syntax divided
    .syntax unified
    ldr r4,[r1,#12]
    .syntax divided
    .syntax unified
    ldr r5,[r1,#16]
    .syntax divided
    .syntax unified
    ldr r6,[r1,#20]
    .syntax divided
    .syntax unified
    umull r7,r8,r0,r2
   .syntax divided
    .syntax unified
    umull r9,r10,r0,r0
   .syntax divided
    .syntax unified
    umaal r7,r10,r0,r2
   .syntax divided
    .syntax unified
    umaal r8,r10,r2,r2
   .syntax divided
    .syntax unified
    str r9,[SP,#0]
   .syntax divided
    .syntax unified
    str r7,[SP,#4]
   .syntax divided
    .syntax unified
    umull r7,r9,r0,r4
   .syntax divided
    .syntax unified
    umull r11,r12,r0,r3
   .syntax divided
    .syntax unified
    adds r11,r11
   .syntax divided
    .syntax unified
    eor r14,r14
   .syntax divided
    .syntax unified
    umaal r8,r11,r8,r14
   .syntax divided
    .syntax unified
    umaal r10,r11,r10,r14
   .syntax divided
    .syntax unified
    str r8,[SP,#8]
   .syntax divided
    .syntax unified
    umaal r7,r12,r2,r3
   .syntax divided
    .syntax unified
    adcs r7,r7
   .syntax divided
    .syntax unified
    umaal r7,r10,r7,r14
   .syntax divided
    .syntax unified
    str r7,[SP,#12]
   .syntax divided
    .syntax unified
    .syntax unified
    add r10,r11
    .syntax divided
   .syntax divided
    .syntax unified
    ldr r7,[r1,#24]
    .syntax divided
    .syntax unified
    ldr r8,[r1,#28]
    .syntax divided
    .syntax unified
    umull r1,r11,r0,r6
   .syntax divided
    .syntax unified
    umaal r9,r12,r0,r5
   .syntax divided
    .syntax unified
    umaal r1,r12,r2,r5
   .syntax divided
    .syntax unified
    umaal r11,r12,r0,r7
   .syntax divided
    .syntax unified
    umlal r9,r14,r2,r4
   .syntax divided
    .syntax unified
    umaal r1,r14,r3,r4
   .syntax divided
    .syntax unified
    umaal r11,r14,r2,r6
   .syntax divided
    .syntax unified
    umaal r12,r14,r0,r8
   .syntax divided
    .syntax unified
    adcs r9,r9
   .syntax divided
    .syntax unified
    adcs r1,r1
   .syntax divided
    .syntax unified
    eor r0,r0
   .syntax divided
    .syntax unified
    umaal r9,r10,r3,r3
   .syntax divided
    .syntax unified
    str r9,[SP,#16]
   .syntax divided
    .syntax unified
    umaal r1,r10,r1,r0
   .syntax divided
    .syntax unified
    umlal r11,r0,r3,r5
   .syntax divided
    .syntax unified
    umaal r0,r12,r2,r7
   .syntax divided
    .syntax unified
    umaal r12,r14,r2,r8
   .syntax divided
    .syntax unified
    adcs r11,r11
   .syntax divided
    .syntax unified
    umaal r10,r11,r4,r4
   .syntax divided
    .syntax unified
    eor r2,r2
   .syntax divided
    .syntax unified
    umlal r0,r2,r3,r6
   .syntax divided
    .syntax unified
    umaal r2,r12,r3,r7
   .syntax divided
    .syntax unified
    umaal r12,r14,r3,r8
   .syntax divided
    .syntax unified
    eor r3,r3
   .syntax divided
    .syntax unified
    umlal r0,r3,r4,r5
   .syntax divided
    .syntax unified
    umaal r2,r3,r4,r6
   .syntax divided
    .syntax unified
    umaal r3,r12,r4,r7
   .syntax divided
    .syntax unified
    umaal r12,r14,r4,r8
   .syntax divided
    .syntax unified
    adcs r0,r0
   .syntax divided
    .syntax unified
    eor r9,r9
   .syntax divided
    .syntax unified
    umaal r0,r11,r0,r9
   .syntax divided
    .syntax unified
    adcs r2,r2
   .syntax divided
    .syntax unified
    umlal r3,r9,r5,r6
   .syntax divided
    .syntax unified
    umaal r9,r12,r5,r7
   .syntax divided
    .syntax unified
    umaal r12,r14,r5,r8
   .syntax divided
    .syntax unified
    eor r4,r4
   .syntax divided
    .syntax unified
    umlal r12,r4,r6,r7
   .syntax divided
    .syntax unified
    umaal r4,r14,r6,r8
   .syntax divided
    .syntax unified
    umaal r2,r11,r5,r5
   .syntax divided
    .syntax unified
    eor r5,r5
   .syntax divided
    .syntax unified
    adcs r3,r3
   .syntax divided
    .syntax unified
    umaal r3,r11,r3,r5
   .syntax divided
    .syntax unified
    umlal r14,r5,r7,r8
   .syntax divided
    .syntax unified
    adcs r9,r9
   .syntax divided
    .syntax unified
    adcs r12,r12
   .syntax divided
    .syntax unified
    adcs r4,r4
   .syntax divided
    .syntax unified
    adcs r14,r14
   .syntax divided
    .syntax unified
    adcs r5,r5
   .syntax divided
    .syntax unified
    umaal r9,r11,r6,r6
   .syntax divided
    .syntax unified
    eor r6,r6
   .syntax divided
    .syntax unified
    umaal r11,r12,r11,r6
   .syntax divided
    .syntax unified
    umaal r4,r12,r7,r7
   .syntax divided
    .syntax unified
    umaal r12,r14,r12,r6
   .syntax divided
    .syntax unified
    umaal r5,r14,r8,r8
   .syntax divided
    .syntax unified
    adcs r14,r6
   .syntax divided
    .syntax unified
    mov r7,#38
    .syntax divided
    .syntax unified
    umlal r0,r6,r14,r7
   .syntax divided
    .syntax unified
    mov r8,#19
    .syntax divided
    .syntax unified
    lsr r14,r0,#31
    .syntax divided
    .syntax unified
    mul r8,r14
    .syntax divided
    .syntax unified
    lsl r0,r0,#1
    .syntax divided
    .syntax unified
    lsr r0,r0,#1
    .syntax divided
    .syntax unified
    ldr r14,[SP,#0]
   .syntax divided
    .syntax unified
    umaal r8,r14,r2,r7
   .syntax divided
    .syntax unified
    eor r2,r2
   .syntax divided
    .syntax unified
    umlal r8,r2,r6,r7
   .syntax divided
    .syntax unified
    .syntax unified
    add r2,r14
    .syntax divided
   .syntax divided
    .syntax unified
    ldr r6,[SP,#20]
   .syntax divided
    .syntax unified
    ldr r14,[SP,#4]
   .syntax divided
    .syntax unified
    str r8,[r6,#0]
    .syntax divided
    .syntax unified
    umaal r2,r14,r3,r7
   .syntax divided
    .syntax unified
    str r2,[r6,#4]
    .syntax divided
    .syntax unified
    ldr r2,[SP,#8]
   .syntax divided
    .syntax unified
    ldr r3,[SP,#12]
   .syntax divided
    .syntax unified
    ldr r8,[SP,#16]
   .syntax divided
    .syntax unified
    umaal r2,r14,r9,r7
   .syntax divided
    .syntax unified
    str r2,[r6,#8]
    .syntax divided
    .syntax unified
    umaal r3,r14,r11,r7
   .syntax divided
    .syntax unified
    str r3,[r6,#12]
    .syntax divided
    .syntax unified
    umaal r8,r14,r4,r7
   .syntax divided
    .syntax unified
    str r8,[r6,#16]
    .syntax divided
    .syntax unified
    umaal r1,r14,r12,r7
   .syntax divided
    .syntax unified
    str r1,[r6,#20]
    .syntax divided
    .syntax unified
    umaal r10,r14,r5,r7
   .syntax divided
    .syntax unified
    str r10,[r6,#24]
    .syntax divided
    .syntax unified
    .syntax unified
    add r0,r14
    .syntax divided
   .syntax divided
    .syntax unified
    str r0,[r6,#28]
    .syntax divided
    add SP,#24
   .syntax unified
    pop {r4,r5,r6,r7,r8,r9,r10,r11,r12,r15}
   .syntax divided

	.size	fe25519_square_asm, .-fe25519_square_asm
	
