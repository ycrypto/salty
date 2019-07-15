// Implementation of multiplication function for cortex M0
//
// Author: bjoern haase bjoern.m.haase@web.de 
//
// License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// Code is now tested on various target and on QEmu testsuites.

    .text
    .syntax unified
    
#include "attributesForCortexM4.inc"    

.macro QUARTERROUND A, B, C, R, T1, T2
    adds \T1, \B, \C
    movs \T2, #(32 - \R)
    rors \T1, \T2
    eors \A,\T1
.endm

.macro ROUND A,B,C,D,T1,T2
    QUARTERROUND \A,\B,\C,7,\T1,\T2
    QUARTERROUND \D,\A,\B,9,\T1,\T2
    QUARTERROUND \C,\D,\A,13,\T1,\T2
    QUARTERROUND \B,\C,\D,18,\T1,\T2	
.endm

.macro ROUND_WITH_LOAD nA,nB,nC,nD
    ldr	r1, [r0, #(4 * \nA)]
    ldr	r2, [r0, #(4 * \nB)]
    ldr	r3, [r0, #(4 * \nC)]
    ldr	r4, [r0, #(4 * \nD)]
    
    ROUND r1,r2,r3,r4,r5,r6
    
    str	r1, [r0, #(4 * \nA)]
    str	r2, [r0, #(4 * \nB)]
    str	r3, [r0, #(4 * \nC)]
    str	r4, [r0, #(4 * \nD)]
.endm

.macro ALL_ROUNDS
    ROUND_WITH_LOAD 4,0,12,8
    ROUND_WITH_LOAD 9,5,1,13
    ROUND_WITH_LOAD 14,10,6,2
    ROUND_WITH_LOAD 3,15,11,7
    
    ROUND_WITH_LOAD 1,0,3,2
    ROUND_WITH_LOAD 6,5,4,7
    ROUND_WITH_LOAD 11,10,9,8
    ROUND_WITH_LOAD 12,15,14,13
.endm

    .globl	crypto_core_hsalsa20_block_asm
    .align	1
    .type	crypto_core_hsalsa20_block_asm,%function
    .code	16                      @ @crypto_core_hsalsa20_block
    .thumb_func
crypto_core_hsalsa20_block_asm:
    .fnstart
@ BB#0:                                 @ %entry
    .save	{r4, r5, r6, r7, lr}
    push	{r4, r5, r6, r7, lr}

    movs	r7, #10
.LBB0_1:                                @ %for.body

    ALL_ROUNDS 

    subs	r7, r7, #1
    beq	.LBB0_2
    b	.LBB0_1
.LBB0_2:                                @ %for.end

    pop	{r4, r5, r6, r7, pc}
.Lfunc_end0:
    .size	crypto_core_hsalsa20_block_asm, .Lfunc_end0-crypto_core_hsalsa20_block_asm
    .cantunwind
    .fnend

