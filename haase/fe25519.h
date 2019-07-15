/*                          =======================
  ============================ C/C++ HEADER FILE =============================
                            =======================

    \file fe25519.h

    Defines the fe25519 type used for both, edwards curve arithmetic
    and curve25519 diffie hellman.
    Provides the same interface as the corresponding header in avrnacl of
    Michael Hutter and Peter Schwabe.

    \Author: B. Haase, Endress + Hauser Conducta GmbH & Co. KG

    License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
  ============================================================================*/

#ifndef FE25519_HEADER_
#define FE25519_HEADER_

#include "bigint.h"


typedef UN_256bitValue fe25519;

void
fe25519_cpy(
    fe25519*       result,
    const fe25519* in
);

void
fe25519_cmov(
    fe25519*       inoutTarget,
    const fe25519* in,
    int            condition
);

void
fe25519_cswap(
    fe25519* in1,
    fe25519* in2,
    int      condition
);

void
fe25519_setone(
    fe25519* out
);

void
fe25519_setzero(
    fe25519* out
);

/// Note that the operands will be reduced completely. For this reason, the
/// inputs may not be const.
/// WARNING: This function uses positive logic (1 if equal)
int32_t
fe25519_iseq_vartime(
    fe25519* in1,
    fe25519* in2
);

// WARNING: This function uses negative logic (0 if zero)
int32_t
fe25519_iszero(
    fe25519* in
);

int32_t
fe25519_getparity(
    fe25519* in
);

#if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)

inline void fe25519_sub(
    fe25519*       out,
    const fe25519* baseValue,
    const fe25519* valueToSubstract) __attribute__ ((always_inline));

/// Note that out and baseValue members are allowed to overlap.
inline void fe25519_sub(
    fe25519*       out,
    const fe25519* baseValue,
    const fe25519* valueToSubstract)
{
    int32_t zero = 0;
    int32_t clobberReg1;
    int32_t clobberReg2;
    int32_t clobberReg3;

    asm volatile (
        "LDR %[cR1], [%[baseValue],#28] \n\t"
        "LDR %[cR2], [%[valueToSubstract],#28] \n\t"
        "subs %[cR1],%[cR1],%[cR2] \n\t" // Result word #7
        "sbcs %[cR2],%[cR2],%[cR2] \n\t" // Carry word #8

        "adds %[cR3],%[cR1],%[cR1] \n\t" // double word #7 and #8, keep the un-doubled word #7 in cR1
        "adcs %[cR2],%[cR2],%[cR2] \n\t"

        "orr %[cR1],%[cR1],#(1 << 31) \n\t" // set bit #31

        "STR %[cR1], [%[out],#28] \n\t" // temporarily store the value for word #7

        "sub %[cR1],%[cR2],#1 \n\t"

        "mov %[cR2],#(-19) \n\t"
        "mul %[cR1],%[cR1],%[cR2] \n\t" // negative reduction value for result word #0

        "LDR %[cR2], [%[valueToSubstract],#0] \n\t"
        "LDR %[cR3], [%[baseValue],#0] \n\t"
        "umaal %[cR2],%[cR1],%[zero],%[zero]\n\t" // accumulate values to subtract.

        "subs %[cR3],%[cR3],%[cR2] \n\t"
        "STR %[cR3], [%[out],#0] \n\t"

            "LDR %[cR2], [%[valueToSubstract],#4] \n\t"
            "LDR %[cR3], [%[baseValue],#4] \n\t"
            "umaal %[cR2],%[cR1],%[zero],%[zero]\n\t" // accumulate values to subtract.

            "sbcs %[cR3],%[cR3],%[cR2] \n\t"
            "STR %[cR3], [%[out],#4] \n\t"

        "LDR %[cR2], [%[valueToSubstract],#8] \n\t"
        "LDR %[cR3], [%[baseValue],#8] \n\t"
        "umaal %[cR2],%[cR1],%[zero],%[zero]\n\t" // accumulate values to subtract.

        "sbcs %[cR3],%[cR3],%[cR2] \n\t"
        "STR %[cR3], [%[out],#8] \n\t"

            "LDR %[cR2], [%[valueToSubstract],#12] \n\t"
            "LDR %[cR3], [%[baseValue],#12] \n\t"
            "umaal %[cR2],%[cR1],%[zero],%[zero]\n\t" // accumulate values to subtract.

            "sbcs %[cR3],%[cR3],%[cR2] \n\t"
            "STR %[cR3], [%[out],#12] \n\t"

        "LDR %[cR2], [%[valueToSubstract],#16] \n\t"
        "LDR %[cR3], [%[baseValue],#16] \n\t"
        "umaal %[cR2],%[cR1],%[zero],%[zero]\n\t" // accumulate values to subtract.

        "sbcs %[cR3],%[cR3],%[cR2] \n\t"
        "STR %[cR3], [%[out],#16] \n\t"

                "LDR %[cR2], [%[valueToSubstract],#20] \n\t"
                "LDR %[cR3], [%[baseValue],#20] \n\t"
                "umaal %[cR2],%[cR1],%[zero],%[zero]\n\t" // accumulate values to subtract.

                "sbcs %[cR3],%[cR3],%[cR2] \n\t"
                "STR %[cR3], [%[out],#20] \n\t"

        "LDR %[cR2], [%[valueToSubstract],#24] \n\t"
        "LDR %[cR3], [%[baseValue],#24] \n\t"
        "umaal %[cR2],%[cR1],%[zero],%[zero]\n\t" // accumulate values to subtract.

        "sbcs %[cR3],%[cR3],%[cR2] \n\t"
        "STR %[cR3], [%[out],#24] \n\t"

        "LDR %[cR3], [%[out],#28] \n\t"
        "sbcs %[cR3],%[cR1] \n\t"
        "STR %[cR3], [%[out],#28] \n\t"

            : [cR1] "=r" (clobberReg1),
              [cR2] "=r" (clobberReg2),
              [cR3] "=r" (clobberReg3) ,
              [out] "+r" (out),
              [baseValue] "+r" (baseValue),
              [valueToSubstract] "+r" (valueToSubstract),
              [zero] "+r" (zero)
            :
            : "memory", "cc");
}

#else

void
fe25519_sub(
    fe25519*       out,
    const fe25519* baseValue,
    const fe25519* valueToSubstract
);

#endif

void
fe25519_neg(
    fe25519*       out,
    const fe25519* valueToNegate
);


#if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)

#define CRYPTO_HAS_ASM_FE25519_ADD

inline void fe25519_add(
    fe25519*       out,
    const fe25519* baseValue,
    const fe25519* valueToSubstract) __attribute__ ((always_inline));

/// Note that out and baseValue members are allowed to overlap.
inline void fe25519_add(
    fe25519*       out,
    const fe25519* baseValue,
    const fe25519* valueToAdd)
{
    int32_t one = 1;
    int32_t clobberReg1;
    int32_t clobberReg2;
    int32_t clobberReg3;
    int32_t clobberReg4;

    asm volatile (
            "ldr %[cR2],[%[baseValue],#(7*4)] \n\t"
            "ldr %[cR1],[%[valueToAdd],#(7*4)] \n\t"

            "mov %[cR3],%[cR1] \n\t"
            "umaal %[cR2],%[cR3],%[cR2],%[one]\n\t" // 2 * %[cR2] + %[cR3]
            "umlal %[cR2],%[cR3],%[cR1],%[one]\n\t" // 2 * %[cR2] + %[cR3] + 1*%[cR1]

            // cR2 holds the contents for the word #7
            "mov %[cR1],#19\n\t"
            "mul %[cR1],%[cR3]\n\t"

            "ldr %[cR3],[%[baseValue],#(0*4)]\n\t"
            "ldr %[cR4],[%[valueToAdd],#(0*4)]\n\t"

            "umaal %[cR3],%[cR4],%[one],%[cR1]\n\t"
            "str %[cR3],[%[out],#(0*4)]\n\t"

            "ldr %[cR1],[%[baseValue],#(1*4)]\n\t"
            "ldr %[cR3],[%[valueToAdd],#(1*4)]\n\t"
            "umaal %[cR3],%[cR4],%[one],%[cR1]\n\t"
            "str %[cR3],[%[out],#(1*4)]\n\t"

            "ldr %[cR1],[%[baseValue],#(2*4)]\n\t"
            "ldr %[cR3],[%[valueToAdd],#(2*4)]\n\t"
            "umaal %[cR3],%[cR4],%[one],%[cR1]\n\t"
            "str %[cR3],[%[out],#(2*4)]\n\t"

            "ldr %[cR1],[%[baseValue],#(3*4)]\n\t"
            "ldr %[cR3],[%[valueToAdd],#(3*4)]\n\t"
            "umaal %[cR3],%[cR4],%[one],%[cR1]\n\t"
            "str %[cR3],[%[out],#(3*4)]\n\t"

            "ldr %[cR1],[%[baseValue],#(4*4)]\n\t"
            "ldr %[cR3],[%[valueToAdd],#(4*4)]\n\t"
            "umaal %[cR3],%[cR4],%[one],%[cR1]\n\t"
            "str %[cR3],[%[out],#(4*4)]\n\t"

            "ldr %[cR1],[%[baseValue],#(5*4)]\n\t"
            "ldr %[cR3],[%[valueToAdd],#(5*4)]\n\t"
            "umaal %[cR3],%[cR4],%[one],%[cR1]\n\t"
            "str %[cR3],[%[out],#(5*4)]\n\t"

            "ldr %[cR1],[%[baseValue],#(6*4)]\n\t"
            "ldr %[cR3],[%[valueToAdd],#(6*4)]\n\t"
            "umaal %[cR3],%[cR4],%[one],%[cR1]\n\t"
            "str %[cR3],[%[out],#(6*4)]\n\t"

            "add %[cR4],%[cR4], %[cR2], LSR #1\n\t"
            "str %[cR4],[%[out],#(7*4)]\n\t"

            : [cR1] "=r" (clobberReg1),
              [cR2] "=r" (clobberReg2),
              [cR3] "=r" (clobberReg3),
              [cR4] "=r" (clobberReg4),
              [out] "+r" (out),
              [baseValue] "+r" (baseValue),
              [valueToAdd] "+r" (valueToAdd),
              [one] "+r" (one)
            :
            : "memory", "cc");
}

#else // #if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)


#ifdef CRYPTO_HAS_ASM_FE25519_ADD

void
fe25519_add_asm(
    fe25519*       out,
    const fe25519* in1,
    const fe25519* in2
);

#define fe25519_add fe25519_add_asm

#else // #ifdef CRYPTO_HAS_ASM_FE25519_ADD

void
fe25519_add(
    fe25519*       out,
    const fe25519* in1,
    const fe25519* in2
);

#endif // #else #ifdef CRYPTO_HAS_ASM_FE25519_ADD
#endif //#else #if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)


#ifdef CRYPTO_HAS_ASM_FE25519_MPY121666

/// Note that out and in are allowed to overlap!
void
fe25519_mpyWith121666_asm(
    fe25519*       out,
    const fe25519* in
);
#define fe25519_mpyWith121666 fe25519_mpyWith121666_asm

#else

/// Note that out and in are allowed to overlap!
void
fe25519_mpyWith121666(
    fe25519*       out,
    const fe25519* in
);
#endif



#if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)

inline void fe25519_mpy121666add(
    fe25519*       out,
    const fe25519* valueToAdd,
    const fe25519* valueToMpy) __attribute__ ((always_inline));

/// Note that out and baseValue members are allowed to overlap.
inline void fe25519_mpy121666add(
    fe25519*       out,
    const fe25519* valueToAdd,
    const fe25519* valueToMpy)
{
    int32_t clobberReg1;
    int32_t clobberReg2;
    int32_t clobberReg3;
    int32_t clobberReg4;

    int32_t v121666 = 121666;

    asm volatile (
            "ldr %[cR1],[%[valueToAdd],#(7*4)] \n\t"
            "ldr %[cR3],[%[valueToMpy],#(7*4)] \n\t"
            "add %[cR4], %[v121666], %[v121666]  \n\t"

            "mov %[cR2], %[cR1] \n\t"
            "umaal %[cR1],%[cR2],%[cR4],%[cR3]\n\t" // cR1:cR2 = a7 + a7 + 2 * 121666 * b7

            "mov %[cR3], #19 \n\t"
            "mul %[cR2],%[cR3]  \n\t"

            // cR1 holds twice the value of saved contents for result word #7.
            // CR2 holds reduction vaue for word 0
            "ldr %[cR4],[%[valueToMpy],#(0*4)] \n\t"
            "ldr %[cR3],[%[valueToAdd],#(0*4)] \n\t"
            "umaal %[cR3],%[cR2],%[v121666],%[cR4]\n\t" // cR3:cR2 =  a0 + 121666 * b0 + reductionValue
            "str %[cR3],[%[out],#(0*4)] \n\t"

            "ldr %[cR4],[%[valueToMpy],#(1*4)] \n\t"
            "ldr %[cR3],[%[valueToAdd],#(1*4)] \n\t"
            "umaal %[cR3],%[cR2],%[v121666],%[cR4]\n\t" // cR3:cR2 =  a0 + 121666 * b0 + carries
            "str %[cR3],[%[out],#(1*4)] \n\t"

            "ldr %[cR4],[%[valueToMpy],#(2*4)] \n\t"
            "ldr %[cR3],[%[valueToAdd],#(2*4)] \n\t"
            "umaal %[cR3],%[cR2],%[v121666],%[cR4]\n\t" // cR3:cR2 =  a0 + 121666 * b0 + carries
            "str %[cR3],[%[out],#(2*4)] \n\t"

            "ldr %[cR4],[%[valueToMpy],#(3*4)] \n\t"
            "ldr %[cR3],[%[valueToAdd],#(3*4)] \n\t"
            "umaal %[cR3],%[cR2],%[v121666],%[cR4]\n\t" // cR3:cR2 =  a0 + 121666 * b0 + carries
            "str %[cR3],[%[out],#(3*4)] \n\t"

            "ldr %[cR4],[%[valueToMpy],#(4*4)] \n\t"
            "ldr %[cR3],[%[valueToAdd],#(4*4)] \n\t"
            "umaal %[cR3],%[cR2],%[v121666],%[cR4]\n\t" // cR3:cR2 =  a0 + 121666 * b0 + carries
            "str %[cR3],[%[out],#(4*4)] \n\t"

            "ldr %[cR4],[%[valueToMpy],#(5*4)] \n\t"
            "ldr %[cR3],[%[valueToAdd],#(5*4)] \n\t"
            "umaal %[cR3],%[cR2],%[v121666],%[cR4]\n\t" // cR3:cR2 =  a0 + 121666 * b0 + carries
            "str %[cR3],[%[out],#(5*4)] \n\t"

            "ldr %[cR4],[%[valueToMpy],#(6*4)] \n\t"
            "ldr %[cR3],[%[valueToAdd],#(6*4)] \n\t"
            "umaal %[cR3],%[cR2],%[v121666],%[cR4]\n\t" // cR3:cR2 =  a0 + 121666 * b0 + carries
            "str %[cR3],[%[out],#(6*4)] \n\t"

            "add %[cR1],%[cR2], %[cR1], LSR #1\n\t"
            "str %[cR1],[%[out],#(7*4)]\n\t"

            : [cR1] "=r" (clobberReg1),
              [cR2] "=r" (clobberReg2),
              [cR3] "=r" (clobberReg3),
              [cR4] "=r" (clobberReg4),
              [out] "+r" (out),
              [valueToMpy] "+r" (valueToMpy),
              [valueToAdd] "+r" (valueToAdd),
              [v121666] "+r" (v121666)
            :
            : "memory", "cc");
}

#define CRYPTO_HAS_ASM_COMBINED_MPY121666ADD_FE25519 1

#endif //(defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)




#ifdef CRYPTO_HAS_ASM_REDUCE_25519

#define fe25519_reduceTo256Bits fe25519_reduceTo256Bits_asm

extern void
fe25519_reduceTo256Bits_asm(
    fe25519              *res,
    const UN_512bitValue *in
);

#endif

/// Used for fast randomization of field elements. Use 16 bit randomization constant
/// since it's easy and fast to implement and it's repeated application is still considered
/// to make statistical analysis very hard.
void
fe25519_mpyWith_uint16(
    fe25519*       inOut,
    const uint16_t   valU16
);

/// Used for fast randomization of field elements. Use 31 bit randomization constant
/// since it's easy and fast to implement and it's repeated application is still considered
/// to make statistical analysis very hard.
/// Note that bit #31 is implicitly cleared.
/// For a zero multiplier, the return value is undefined! This allows for some optimizations
/// and does not actually generate any problem when using the function for projective
/// randomization.
//void
//fe25519_mpyWith_uint31(
//    fe25519*         inOut,
//    const uint32_t   valU31
//);


#if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)

inline void fe25519_mpyWith_uint31(
    fe25519*       inOut,
    uint32_t       mpyVal) __attribute__ ((always_inline));

inline void fe25519_mpyWith_uint31(
    fe25519*       inOut,
    uint32_t       mpyVal)
{
    int32_t clobberReg1;
    int32_t clobberReg2;
    int32_t clobberReg3;
    int32_t clobberReg4;

    asm volatile (
            "add %[mv],%[mv],%[mv]\n\t" // double the mpy value
            "ldr %[cR1],[%[io],#(7*4)] \n\t" // load the most significant word.

            "umull %[cR1],%[cR2],%[cR1],%[mv]\n\t"
            "lsr %[cR1],%[cR1],#1\n\t" // Shift back the result word. cR1 holds now result word #7

            "lsr %[mv],%[mv],#1\n\t" // Shift back the multiplicand value. This way also bit #31 is cleared.
            "sub %[mv],%[mv],#1\n\t" // Subtract one from the multiplicand value.

            "mov %[cR3], #19 \n\t"
            "umull %[cR2],%[cR3],%[cR3],%[cR2]\n\t" // cR2 now holds word #0 and cR3 word #1 of the result word component stemming from reduction.

            "ldr %[cR4],[%[io],#(0*4)] \n\t" // load word #0.
            "umaal %[cR4],%[cR2],%[cR4],%[mv]\n\t" // multiply word
            "add %[cR2],%[cR2],%[cR3]\n\t" // add the remaining reduction word #1. We know that cR3 is smaller than 19 and cR2 has bit #31 cleared. No overflow possible.
            "str %[cR4],[%[io],#(0*4)] \n\t" // store word

            "ldr %[cR4],[%[io],#(1*4)] \n\t" // load next word.
            "umaal %[cR4],%[cR2],%[cR4],%[mv]\n\t" // multiply word
            "str %[cR4],[%[io],#(1*4)] \n\t" // store word

            "ldr %[cR4],[%[io],#(2*4)] \n\t" // load next word.
            "umaal %[cR4],%[cR2],%[cR4],%[mv]\n\t" // multiply word
            "str %[cR4],[%[io],#(2*4)] \n\t" // store word

            "ldr %[cR4],[%[io],#(3*4)] \n\t" // load next word.
            "umaal %[cR4],%[cR2],%[cR4],%[mv]\n\t" // multiply word
            "str %[cR4],[%[io],#(3*4)] \n\t" // store word

            "ldr %[cR4],[%[io],#(4*4)] \n\t" // load next word.
            "umaal %[cR4],%[cR2],%[cR4],%[mv]\n\t" // multiply word
            "str %[cR4],[%[io],#(4*4)] \n\t" // store word

            "ldr %[cR4],[%[io],#(5*4)] \n\t" // load next word.
            "umaal %[cR4],%[cR2],%[cR4],%[mv]\n\t" // multiply word
            "str %[cR4],[%[io],#(5*4)] \n\t" // store word

            "ldr %[cR4],[%[io],#(6*4)] \n\t" // load next word.
            "umaal %[cR4],%[cR2],%[cR4],%[mv]\n\t" // multiply word
            "str %[cR4],[%[io],#(6*4)] \n\t" // store word

            "add %[cR1],%[cR1],%[cR2] \n\t"
            "str %[cR1],[%[io],#(7*4)]\n\t" // store word

            : [cR1] "=r" (clobberReg1),
              [cR2] "=r" (clobberReg2),
              [cR3] "=r" (clobberReg3),
              [cR4] "=r" (clobberReg4),
              [io] "+r" (inOut),
              [mv] "+r" (mpyVal)
            :
            : "memory", "cc");
}

#define CRYPTO_HAS_ASM_FE25519_MPY_UINT31

#endif //(defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)



void
fe25519_unpack(
    fe25519*            out,
    const uint8_t in[32]
);

/// This will also reduce completele the input val. For this reason
/// the in parameter is non-const.
void
fe25519_pack(
    uint8_t out[32],
    fe25519*      in
);

/// Note that all of the other operations on fe25519 are guaranteed to reduce to
/// 2^256-38 instead of 2^255-19 only.
void
fe25519_reduceCompletely(
    fe25519* inout
);

#ifdef CRYPTO_HAS_ASM_FE25519_MUL

void
fe25519_mul_asm(
    fe25519*       result,
    const fe25519* in1,
    const fe25519* in2
);

#define fe25519_mul fe25519_mul_asm

#else

void
fe25519_mul(
    fe25519*       result,
    const fe25519* in1,
    const fe25519* in2
);

#endif

#ifdef CRYPTO_HAS_ASM_FE25519_SQUARE

void
fe25519_square_asm(
    fe25519*       result,
    const fe25519* in
);
#define fe25519_square fe25519_square_asm

#else
void
fe25519_square(
    fe25519*       result,
    const fe25519* in
);

#endif

void
fe25519_invert(
    fe25519*       r,
    const fe25519* x
);

void
fe25519_invert_useProvidedScratchBuffers(
    fe25519*       r,
    const fe25519* x,
    fe25519*       t1,
    fe25519*       t2,
    fe25519*       t3
);

void
fe25519_pow2523_useProvidedScratchBuffers(
    fe25519*       r,
    const fe25519* x,
    fe25519*       t1,
    fe25519*       t2,
    fe25519*       t3
);

void
fe25519_elligator2x_useProvidedScratchBuffers(
    fe25519*       x,
    const fe25519* r,
    // Scratch buffers
    fe25519*       t0,
    fe25519*       t1,
    fe25519*       t2,
    fe25519*       t3,
    fe25519*       v
    );

void
fe25519_generateRandomValue(
    fe25519*       result
);


void
fe25519_elligator2(
    fe25519*       x,
    const fe25519* r);

void
fe25519_elligator2_useProvidedScratchBuffers(
    fe25519*       x,
    const fe25519* r,
    // Scratch buffers
    fe25519*       t0,
    fe25519*       t1,
    fe25519*       t2,
    fe25519*       t3,
    fe25519*       v
    );

void
fe25519_squareroot(
    fe25519*        result,
    const fe25519*  in
);

extern const fe25519 fe25519_one;
extern const fe25519 fe25519_minusA;
extern const fe25519 fe25519_minusAdiv2;


#endif // #ifndef FE25519_HEADER_
