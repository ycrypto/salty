// https://stackoverflow.com/questions/22396214/understanding-this-part-arm-assembly-code

    .arch armv7e-m
    .syntax unified
    .thumb

	.global	fe25519_add_asm
	.type	fe25519_add_asm, %function

fe25519_add_asm:
// fe25519 add for Cortex-M4
// output partially reduced

 // r0 = result ptr, r1,r2 = operand ptr.

    push {r4-r7}

    // constant 1, lets us sum three words via UMAAL
    mov r7, #1

    ldr r4, [r1, 7*4]
    ldr r3, [r2, 7*4]

    mov r5, r3
    umaal r4, r5, r4, r7 // (r5, r4) = r4 + r5 + r4*r7 = left[7] + right[7] + left[7] = 2*left[7] + right[7]
    umlal r4, r5, r3, r7 // (r5, r4) = (r5, r4) + r3*r7 = ... = 2*left[7] + 2*right[7]

    mov r3, #19
    mul r3, r5 // r3 = 19*bits 255 and higher, add to output[0]

    // for the remainder, r4 stores `output[7] << 1`,
    // we don't touch/use it

    ldr r5, [r1, 0*4]
    ldr r6, [r2, 0*4]
    umaal r5, r6, r7, r3 // r5 = lo(r5 + r6 + r7*r3)
    str r5, [r0, 0*4]

    ldr r3, [r1, 1*4]
    ldr r5, [r2, 1*4]
    umaal r5, r6, r7, r3
    str r5, [r0, 1*4]

    ldr r3, [r1, 2*4]
    ldr r5, [r2, 2*4]
    umaal r5, r6, r7, r3
    str r5, [r0, 2*4]

    ldr r3, [r1, 3*4]
    ldr r5, [r2, 3*4]
    umaal r5, r6, r7, r3
    str r5, [r0, 3*4]

    ldr r3, [r1, 4*4]
    ldr r5, [r2, 4*4]
    umaal r5, r6, r7, r3
    str r5, [r0, 4*4]

    ldr r3, [r1, 5*4]
    ldr r5, [r2, 5*4]
    umaal r5, r6, r7, r3
    str r5, [r0, 5*4]

    ldr r3, [r1, 6*4]
    ldr r5, [r2, 6*4]
    umaal r5, r6, r7, r3
    str r5, [r0, 6*4]

    add r6, r6, r4, LSR #1
    str r6, [r0, 7*4]

    pop {r4-r7}

    // don't forget this or you'll get weird values ;)
    bx lr

	/* .size	fe25519_add_asm, .-fe25519_add_asm */

