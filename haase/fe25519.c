/*                          =======================
  ============================ C/C++ HEADER FILE =============================
                            =======================

    \file fe25519.c

    modulo 2^255 - 19 arithmetic in a packed representation.

    \Author: B. Haase, Endress + Hauser Conducta GmbH & Co. KG

    License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
  ============================================================================*/

#include "fe25519.h"

#ifndef OPTIMIZE_MPY_WITH_121666
#define OPTIMIZE_MPY_WITH_121666 1
#endif

/// We are already using a packed radix 16 representation for fe25519. The real use for this function
/// is for architectures that use more bits for storing a fe25519 in a representation where multiplication
/// may be calculated more efficiently.
/// Here we simply copy the data.
void
fe25519_unpack(
    fe25519*            out,
    const uint8_t in[32]
)
{
    uint8_t ctr;

    for (ctr = 0; ctr < 32; ctr++)
    {
        out->as_uint8_t[ctr] = in[ctr];
    }
    out->as_uint8_t[31] &= 0x7f; // make sure that the last bit is cleared.
}

/// We are already using a packed radix 16 representation for fe25519. The real use for this function
/// is for architectures that use more bits for storing a fe25519 in a representation where multiplication
/// may be calculated more efficiently.
/// Here we simply copy the data.
void
fe25519_pack(
    uint8_t out[32],
    fe25519*      in
)
{
    uint8_t ctr;

    fe25519_reduceCompletely(in);

    for (ctr = 0; ctr < 32; ctr++)
    {
        out[ctr] = in->as_uint8_t[ctr];
    }
}

void
fe25519_cpy(
    fe25519*       result,
    const fe25519* in
)
{
    uint8_t ctr;

    for (ctr = 0; ctr < 8; ctr++)
    {
        result->as_uint32_t[ctr] = in->as_uint32_t[ctr];
    }
}

void
fe25519_cmov(
    fe25519*       result,
    const fe25519* in,
    int            condition
)
{
    conditionalMove_256bitValue(result, in, (uint8_t)condition);
}

void
fe25519_cswap(
    fe25519* in1,
    fe25519* in2,
    int      condition
)
{
    int32_t mask = condition;
    uint32_t ctr;

    mask = -mask;

    for (ctr = 0; ctr < 8; ctr++)
    {
        uint32_t val1 = in1->as_uint32_t[ctr];
        uint32_t val2 = in2->as_uint32_t[ctr];
        uint32_t temp = val1;

        val1 ^= mask & (val2 ^ val1);
        val2 ^= mask & (val2 ^ temp);


        in1->as_uint32_t[ctr] = val1;
        in2->as_uint32_t[ctr] = val2;
    }
}

void
fe25519_setzero(
    fe25519* out
)
{
    uint8_t ctr;

    for (ctr = 0; ctr < 8; ctr++)
    {
        out->as_uint32_t[ctr] = 0;
    }
}

void
fe25519_setone(
    fe25519* out
)
{
    uint8_t ctr;

    out->as_uint32_t[0] = 1;

    for (ctr = 1; ctr < 8; ctr++)
    {
        out->as_uint32_t[ctr] = 0;
    }
}

int32_t
fe25519_is_equal_vartime(
    fe25519* in1,
    fe25519* in2
)
{
    uint8_t ctr;

    // check most significant word.
    if (in1->as_uint32_t[7] != in2->as_uint32_t[7])
    {
        // The most significant word does not match.
        // It may be that both operands are still equal, since
        // one or both might be only partly reduced to 2^256 - 38.
        fe25519_reduceCompletely(in1);
        fe25519_reduceCompletely(in2);

        // OK, now the most significant words should match.
        if (in1->as_uint32_t[7] != in2->as_uint32_t[7])
        {
            return 0;
        }
    }

    // Check remaining words.
    for (ctr = 0; ctr < 7; ctr++)
    {
        if (in1->as_uint32_t[ctr] != in2->as_uint32_t[ctr])
        {
            return 0;
        }
    }
    return 1;
}

int32_t
fe25519_iszero(
    fe25519* in
)
{
    uint8_t  ctr;
    uint32_t bitsSetMask;

    fe25519_reduceCompletely(in);

    bitsSetMask = 0;

    for (ctr = 1; ctr < 8; ctr++)
    {
        bitsSetMask |= in->as_uint32_t[ctr];
    }
    {
        int32_t result = -1;
        result ^= ~bitsSetMask;

        return result;
    }
}

int32_t
fe25519_getparity(
    fe25519* in
)
{
    fe25519_reduceCompletely(in);
    return in->as_uint8_t[0] & 1;
}

#if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)

// We are using the inline assembly function defined in fe25519.h header

#else

/// Note that out and baseValue members are allowed to overlap.
void
fe25519_sub(
    fe25519*       out,
    const fe25519* baseValue,
    const fe25519* valueToSubstract
)
{
    int64_t  accu = 0;

    // First subtract the most significant word, so that we may
    // reduce the result "on the fly".
    accu = baseValue->as_uint32_t[7];
    accu -= valueToSubstract->as_uint32_t[7];

    // We always set bit #31, and compensate this by subtracting 1 from the reduction
    // value.
    out->as_uint32_t[7] = ((uint32_t)accu) | 0x80000000ul;

    accu = 19 * ((int32_t)(accu >> 31) - 1);
    // ^ "-1" is the compensation for the "| 0x80000000ul" above.
    // This choice makes sure, that the result will be positive!

#define LOOP_SUB(ctr) \
    { \
        \
            accu += baseValue->as_uint32_t[ctr]; \
            accu -= valueToSubstract->as_uint32_t[ctr]; \
            \
            out->as_uint32_t[ctr] = (uint32_t)accu; \
            accu >>= 32; \
    }

    // force loop unrolling irrespective of the optimizer settings.
    LOOP_SUB(0); LOOP_SUB(1); LOOP_SUB(2); LOOP_SUB(3);
    LOOP_SUB(4); LOOP_SUB(5); LOOP_SUB(6);

    accu += out->as_uint32_t[7];
    out->as_uint32_t[7] = (uint32_t)accu;
}

#endif // #else #if (defined(__clang__) || defined(__GNUC__)) && defined (CORTEX_M4)

void
fe25519_neg(
    fe25519*       out,
    const fe25519* valueToNegate
)
{
    uint16_t ctr;
    int64_t  accu = 0;

    // First subtract the most significant word, so that we may
    // reduce the result "on the fly".
    accu -= valueToNegate->as_uint32_t[7];

    // We always set bit #31, and compensate this by substracting 1 from the reduction
    // value.
    out->as_uint32_t[7] = ((uint32_t)accu) | 0x80000000ul;

    accu = 19 * ((int32_t)(accu >> 31) - 1);
    // ^ "-1" is the compensation for the "| 0x80000000ul" above.
    // This choice makes sure, that the result will be positive!

    for (ctr = 0; ctr < 7; ctr += 1)
    {
        accu -= valueToNegate->as_uint32_t[ctr];

        out->as_uint32_t[ctr] = (uint32_t)accu;
        accu >>= 32;
    }
    accu += out->as_uint32_t[7];
    out->as_uint32_t[7] = (uint32_t)accu;
}

#ifdef CRYPTO_HAS_ASM_FE25519_ADD

#else

void
fe25519_add(
    fe25519*       out,
    const fe25519* baseValue,
    const fe25519* valueToAdd
)
{
    uint64_t accu = 0;

    // We first add the most significant word, so that we may reduce
    // "on the fly".
    accu = baseValue->as_uint32_t[7];
    accu += valueToAdd->as_uint32_t[7];
    out->as_uint32_t[7] = ((uint32_t)accu) & 0x7ffffffful;

    accu = ((uint32_t)(accu >> 31)) * 19;

#define LOOP_ADD(ctr) \
    { \
        accu += baseValue->as_uint32_t[ctr]; \
        accu += valueToAdd->as_uint32_t[ctr]; \
      \
        out->as_uint32_t[ctr] = (uint32_t)accu; \
        accu >>= 32; \
    }

    // force loop unrolling.
    LOOP_ADD(0); LOOP_ADD(1); LOOP_ADD(2); LOOP_ADD(3);
    LOOP_ADD(4); LOOP_ADD(5); LOOP_ADD(6);

    accu += out->as_uint32_t[7];
    out->as_uint32_t[7] = (uint32_t)accu;
}
#endif

#ifndef CRYPTO_HAS_ASM_FE25519_MPY121666

/// Note that out and are allowed to overlap!
void
fe25519_mpyWith121666(
    fe25519*       out,
    const fe25519* in
)
{
    #if OPTIMIZE_MPY_WITH_121666
    uint16_t ctr;

    // 121666 is hex 0x1db42ul.
    // Unfortunately, this value does not fit completely in one single 16 bit word.
    // We split the operation to one 16 bit multiply and one "<<16 and add" operation.

    uint64_t       accu = 0;
    const uint32_t truncated121666 = 121666 & 0xffff;

    // We want to avoid an explicit reduction step.
    // Therefore, we first calculate the most significant word
    // in an approximate way. Then we reduce the result so, that bit #31 of
    // the most significant word is zero, so that subsequent carries
    // that will be rippling into the most significant word #7 may not
    // result in an overflow.
    {
        // The next block will calculate
        // accu = ((uint64) in->as_uint32_t[7]) * 0x1db42ul;
        // without requiring a full 64x64 bit multiplication.
        {
            uint32_t tmp = in->as_uint32_t[7];
            uint32_t lowerWord = tmp & 0xffff;
            uint32_t upperWord = tmp >> 16;

            accu = tmp;
            accu += upperWord * truncated121666;
            accu <<= 16;
            accu += lowerWord * truncated121666;
        }
        out->as_uint32_t[7] = ((uint32_t)accu) & 0x7ffffffful;

        // reduce the most significant bits on the fly.
        accu = ((uint32_t)(accu >> 31)) * 19;
    }

    // Now multiply the other words.
    for (ctr = 0; ctr < 7; ctr += 1)
    {
        {
            uint32_t lowValue;
            uint32_t highValue;
            {
                uint32_t tmp = in->as_uint32_t[ctr];
                highValue = tmp >> 16;
                lowValue = tmp & 0xfffful;
            }

            accu += lowValue * truncated121666;
            accu += ((uint64_t)(highValue * truncated121666)) << 16;
            accu += ((uint64_t)highValue) << 32 | lowValue << 16;
            out->as_uint32_t[ctr] = (uint32_t)accu;
            accu >>= 32;
        }
    }
    // ripple in the last carry into the most significant word.
    accu += out->as_uint32_t[7];
    out->as_uint32_t[7] = (uint32_t)accu;

    #else
    static const uint32_t value[8] = { 121666, 0, 0, 0, 0, 0, 0, 0 };
    fe25519_mul(out, in, (UN_256bitValue*)&value);
    #endif
}

#endif


void
fe25519_mpyWith_uint16(
    fe25519*       inOut,
    const uint16_t   valU16
)
{
    uint16_t ctr;
    uint64_t accu;

    // We want to avoid an explicit reduction step.
    // Therefore, we first calculate the most significant word
    // in an approximate way. Then we reduce the result so, that bit #31 of
    // the most significant word is zero, so that subsequent carries
    // that will be rippling into the most significant word #7 may not
    // result in an overflow.
    {
        // The next block will calculate
        // accu = ((uint64) in->as_uint32_t[7]) * u16Value;
        // without requiring a full 64x64 bit multiplication.
        {
            uint32_t tmp = inOut->as_uint32_t[7];
            uint32_t lowerWord = tmp & 0xffff;
            uint32_t upperWord = tmp >> 16;

            accu = upperWord * valU16;
            accu <<= 16;
            accu += lowerWord * valU16;
        }
        inOut->as_uint32_t[7] = ((uint32_t)accu) & 0x7ffffffful;

        // reduce the most significant bits on the fly.
        accu = ((uint32_t)(accu >> 31)) * 19;
    }

    // Now multiply the other words.
    for (ctr = 0; ctr < 7; ctr += 1)
    {
        {
            uint32_t lowValue;
            uint32_t highValue;
            {
                uint32_t tmp = inOut->as_uint32_t[ctr];
                highValue = tmp >> 16;
                lowValue = tmp & 0xfffful;
            }

            accu += lowValue * valU16;
            accu += ((uint64_t)(highValue * valU16)) << 16;
            inOut->as_uint32_t[ctr] = (uint32_t)accu;
            accu >>= 32;
        }
    }
    // ripple in the last carry into the most significant word.
    inOut->as_uint32_t[7] += (uint32_t)accu;
}

void
fe25519_reduceCompletely(
    fe25519* inout
)
{
    uint32_t numberOfTimesToSubstractPrime;
    uint32_t initialGuessForNumberOfTimesToSubstractPrime
        = inout->as_uint32_t[7] >> 31;
    uint64_t accu;
    uint8_t  ctr;

    // add one additional 19 to the estimated number of reductions.
    // Do the calculation without writing back the results to memory.
    //
    // The initial guess of required numbers of reductions is based
    // on bit #32 of the most significant word.
    // This initial guess may be wrong, since we might have a value
    // v in the range
    // 2^255 - 19 <= v < 2^255
    // . After adding 19 to the value, we will be having the correct
    // Number of required subtractions.
    accu = initialGuessForNumberOfTimesToSubstractPrime * 19 + 19;

    for (ctr = 0; ctr < 7; ctr++)
    {
        accu += inout->as_uint32_t[ctr];
        accu >>= 32;
    }
    accu += inout->as_uint32_t[7];

    numberOfTimesToSubstractPrime = (uint32_t)(accu >> 31);

    // Do the reduction.
    accu = numberOfTimesToSubstractPrime * 19;

    for (ctr = 0; ctr < 7; ctr++)
    {
        accu += inout->as_uint32_t[ctr];
        inout->as_uint32_t[ctr] = (uint32_t)accu;
        accu >>= 32;
    }
    accu += inout->as_uint32_t[7];
    inout->as_uint32_t[7] = accu & 0x7ffffffful;
}

#ifdef CRYPTO_HAS_ASM_REDUCE_25519

#else

/// Return the result in the lower 256 bits of the operand.
void
fe25519_reduceTo256Bits(
    fe25519              *res,
    const UN_512bitValue *in
);

/// Return the result in the lower 256 bits of the operand.
void
fe25519_reduceTo256Bits(
    fe25519              *res,
    const UN_512bitValue *in
)
{
    // Inform the compiler that there is no point holding the values in
    // registers by defining the variables to be volatile.
    volatile UN_512bitValue* result = (volatile UN_512bitValue*)res;
    uint64_t                   accu;

    // Let's first reduce the uppermost word #15.
    accu = in->as_uint32_t[7];
    accu += multiply16x32(38, in->as_uint32_t[15]);
    result->as_uint32_t[7] = ((uint32_t)accu) & (0x7ffffffful);

    // Now let's reduce bit #31 of word 31 and possibly the remnants of the reduction
    // of word #15.
    // As a consequence at most 38 may be added to word #7 within the next reduction
    // steps. Since bit #31 of word #7 is already reduced in the step to come,
    // we may not get any overflow
    accu = ((uint32_t)(accu >> 31)) * 19;
    {
        accu += multiply16x32(38, in->as_uint32_t[8]);
        accu += in->as_uint32_t[0];
        result->as_uint32_t[0] = (uint32_t)accu;
        accu >>= 32;

        accu += multiply16x32(38, in->as_uint32_t[9]);
        accu += in->as_uint32_t[1];
        result->as_uint32_t[1] = (uint32_t)accu;
        accu >>= 32;

        accu += multiply16x32(38, in->as_uint32_t[10]);
        accu += in->as_uint32_t[2];
        result->as_uint32_t[2] = (uint32_t)accu;
        accu >>= 32;

        accu += multiply16x32(38, in->as_uint32_t[11]);
        accu += in->as_uint32_t[3];
        result->as_uint32_t[3] = (uint32_t)accu;
        accu >>= 32;

        accu += multiply16x32(38, in->as_uint32_t[12]);
        accu += in->as_uint32_t[4];
        result->as_uint32_t[4] = (uint32_t)accu;
        accu >>= 32;

        accu += multiply16x32(38, in->as_uint32_t[13]);
        accu += in->as_uint32_t[5];
        result->as_uint32_t[5] = (uint32_t)accu;
        accu >>= 32;

        accu += multiply16x32(38, in->as_uint32_t[14]);
        accu += in->as_uint32_t[6];
        result->as_uint32_t[6] = (uint32_t)accu;
        accu >>= 32;

        accu += result->as_uint32_t[7];
        result->as_uint32_t[7] = (uint32_t)accu;
    }
}
#endif

#ifndef CRYPTO_HAS_ASM_FE25519_MUL

void
fe25519_mul(
    fe25519*       result,
    const fe25519* in1,
    const fe25519* in2
)
{
    UN_512bitValue tmp;

    multiply256x256(&tmp, in1, in2);
    fe25519_reduceTo256Bits(result,&tmp);
}

#endif // #ifndef CRYPTO_HAS_ASM_FE25519_MPY

#ifndef CRYPTO_HAS_ASM_FE25519_SQUARE

void
fe25519_square(
    fe25519*       result,
    const fe25519* in
)
{
    UN_512bitValue tmp;
    square256(&tmp, in);
    fe25519_reduceTo256Bits(result,&tmp);
}

#endif // #ifndef CRYPTO_HAS_ASM_FE25519_SQUARE

void
fe25519_generateRandomValue(
    fe25519*       result
)
{
    randombytes (result->as_uint8_t, 32);
}

// Algorithm 3.37 from the Handbook of Applied Cryptography
void
fe25519_squareroot(
    fe25519*        result,
    const fe25519*  in
)
{
    fe25519 d, b, one;
    int i;
    fe25519_cpy(&d, in);
    fe25519_setone(&one);
    fe25519_cpy(&b, in);
    // Compute d=a^((p-1)/4)

    fe25519_square(&d, &d);
    fe25519_mul(&b, &d, &b);

    fe25519_square(&d, &d);

    for(i=0;i<250;i++) {
        fe25519_square(&d, &d);
        fe25519_mul(&b, &d, &b);
    }

    fe25519 r;
    if(fe25519_iseq_vartime(&b, &one)) {
        // b=1
        // r=a^((p+3)/8)
        fe25519_cpy(&d, in);
        fe25519_setone(result);
        for(i=0;i<251;i++) {
            // square and multiply
            fe25519_square(&d, &d);
            fe25519_mul(result, result, &d);
        }
    } else {
        // b=p-1
        // r=2a(4a)^((p-5)/8)
        fe25519_add(&r, in, in);
        fe25519_add(result, &r, &r);

        fe25519_cpy(&d, result);

        fe25519_square(&d, &d);

        for(i=0;i<250;i++) {
            fe25519_square(&d, &d);
            fe25519_mul(result, result, &d);
        }
        fe25519_mul(result, result, &r);
    }
}




