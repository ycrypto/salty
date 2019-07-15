/*                          =======================
  ============================ C/C++ HEADER FILE =============================
                            =======================

    \file bigint_types.h

    \Author B. Haase, Endress + Hauser Conducta GmbH & Co. KG

    License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
  ============================================================================*/

#ifndef BIGINT_NUM_TYPES_HEADER_
#define BIGINT_NUM_TYPES_HEADER_

/*---------------------------------------------------------------------------*/
/*                               INCLUDES                                    */
/*---------------------------------------------------------------------------*/

#include "crypto_target_config.h"


/*---------------------------------------------------------------------------*/
/*                         DEFINITIONS AND MACROS                            */
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/*                         TYPEDEFS AND STRUCTURES                           */
/*---------------------------------------------------------------------------*/

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_64bitValue_
{
    uint8_t  as_uint8_t  [8];
    uint16_t as_uint16_t [4];
    uint32_t as_uint32_t [2];
    uint64_t as_uint64_t [1];
} UN_64bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_96bitValue_
{
    uint8_t  as_uint8_t[12];
    uint16_t as_uint16_t[6];
    uint32_t as_uint32_t[3];
    uint64_t as_uint64_t[1];
} UN_96bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_128bitValue_
{
    uint8_t         as_uint8_t[16];
    uint16_t        as_uint16_t[8];
    uint32_t        as_uint32_t[4];
    uint64_t        as_uint64_t[2];
    UN_64bitValue as_64_bitValue[2];
} UN_128bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_136bitValue_
{
    uint8_t          as_uint8_t[17];
    uint16_t         as_uint16_t[8];
    uint32_t         as_uint32_t[4];
    uint64_t         as_uint64_t[2];
    UN_64bitValue  as_64_bitValue[2];
    UN_128bitValue as_128_bitValue[1];
} UN_136bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_192bitValue_
{
    uint8_t          as_uint8_t[24];
    uint16_t         as_uint16_t[12];
    uint32_t         as_uint32_t[6];
    uint64_t         as_uint64_t[3];
    UN_64bitValue  as_64_bitValue[3];
    UN_128bitValue as_128_bitValue[1];
} UN_192bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_256bitValue_
{
    uint8_t          as_uint8_t[32];
    uint16_t         as_uint16_t[16];
    uint32_t         as_uint32_t[8];
    UN_64bitValue  as_64_bitValue_t[4];
    uint64_t         as_uint64_t[4];
    UN_128bitValue as_128_bitValue[2];
} UN_256bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_272bitValue_
{
    uint8_t          as_uint8_t[34];
    uint16_t         as_uint16_t[17];
    uint32_t         as_uint32_t[8];
    UN_64bitValue  as_64_bitValue[4];
    uint64_t         as_uint64_t[4];
    UN_128bitValue as_128_bitValue[2];
    UN_256bitValue as_256_bitValue[1];
} UN_272bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_288bitValue_
{
    uint8_t          as_uint8_t[36];
    uint16_t         as_uint16_t[18];
    uint32_t         as_uint32_t[9];
    UN_64bitValue  as_64_bitValue[4];
    uint64_t         as_uint64_t[4];
    UN_128bitValue as_128_bitValue[2];
    UN_256bitValue as_256_bitValue[1];
} UN_288bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_384bitValue_
{
    uint8_t          as_uint8_t[48];
    uint16_t         as_uint16_t[24];
    uint32_t         as_uint32_t[12];
    UN_64bitValue  as_64_bitValue[6];
    uint64_t         as_uint64_t[6];
    UN_128bitValue as_128_bitValue[3];
    UN_256bitValue as_256_bitValue[1];
} UN_384bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_512bitValue_
{
    uint8_t          as_uint8_t[64];
    uint16_t         as_uint16_t[32];
    uint32_t         as_uint32_t[16];
    uint64_t         as_uint64_t[8];
    UN_128bitValue as_128_bitValue[4];
    UN_256bitValue as_256_bitValue[2];
} UN_512bitValue;

// Note that it's important to define the unit8 as first union member, so that
// an array of uint8_t may be used as initializer.
typedef union UN_576bitValue_
{
    uint8_t          as_uint8_t[72];
    uint16_t         as_uint16_t[36];
    uint32_t         as_uint32_t[18];
    uint64_t         as_uint64_t[9];
    UN_128bitValue as_128_bitValue[4];
    UN_256bitValue as_256_bitValue[2];
    UN_512bitValue as_512_bitValue[1];
} UN_576bitValue;

#ifdef CRYPTO_HAS_ASM_MPY_96
#define multiply96x96 multiply96x96_asm
#else
#define multiply96x96 multiply96x96_c
#endif

void
multiply96x96(
    UN_192bitValue*      result,
    const UN_96bitValue* x,
    const UN_96bitValue* y
);

#ifdef CRYPTO_HAS_ASM_SQR_96
#define square96 square96_asm
#else
#define square96 square96_c
#endif

void
square96(
    UN_192bitValue*      result,
    const UN_96bitValue* x
);

#ifdef CRYPTO_HAS_ASM_MPY_128
#define multiply128x128 multiply128x128_asm
#else
#define multiply128x128 multiply128x128_c
#endif

void
multiply128x128(
    UN_256bitValue*       result,
    const UN_128bitValue* x,
    const UN_128bitValue* y
);

void
multiply288x288(
    UN_576bitValue*       r,
    const UN_288bitValue* x,
    const UN_288bitValue* y
);

void
multiply136x136(
    UN_272bitValue*       r,
    const UN_136bitValue* x,
    const UN_136bitValue* y
);

void
conditionalMove_192bitValue(
    UN_192bitValue*       r,
    const UN_192bitValue* x,
    uint8_t                 b
);

FORCE_INLINE static uint64_t
multiply16x32(
    uint16_t x,
    uint32_t y
)
{
    uint64_t r = ((uint32_t)x) * ((uint16_t)y);

    r += ((uint64_t)(((uint16_t)x) * (y >> 16))) << 16;
    return r;
}

void
cpy_192bitvalue(
    UN_192bitValue*       dest,
    const UN_192bitValue* source
);

#ifdef CRYPTO_HAS_ASM_SQR_128
#define square128 square128_asm
#else
#define square128 square128_c
#endif

void
square128(
    UN_256bitValue*       result,
    const UN_128bitValue* x
);


#ifdef CRYPTO_HAS_ASM_SQR_192
#define square192 square192_asm
#else
#define square192 square192_c
#endif

void square192 (
    UN_384bitValue* result,
    const UN_192bitValue* x);


#ifdef CRYPTO_HAS_ASM_MPY_192
#define multiply192x192 multiply192x192_asm
#else
#define multiply192x192 multiply192x192_c
#endif

void
multiply192x192(
    UN_384bitValue*       result,
    const UN_192bitValue* x,
    const UN_192bitValue* y
);


#ifdef CRYPTO_HAS_ASM_MPY_256
#define multiply256x256 multiply256x256_asm
#else
#define multiply256x256 multiply256x256_c
#endif

void
multiply256x256(
    UN_512bitValue*       result,
    const UN_256bitValue* x,
    const UN_256bitValue* y
);

#ifdef CRYPTO_HAS_ASM_SQR_256
#define square256 square256_asm
#else
#define square256 square256_c
#endif

void
square256(
    UN_512bitValue*       result,
    const UN_256bitValue* x
);

void
setone_256bitvalue(
    UN_256bitValue* dest
);

void
setzero_256bitvalue(
    UN_256bitValue* dest
);

void
cpy_256bitvalue(
    UN_256bitValue*       dest,
    const UN_256bitValue* source
);

/// Gets an uint8_t as third parameter that shall be zero or one.
void
conditionalMove_256bitValue(
    UN_256bitValue*       r,
    const UN_256bitValue* x,
    uint8_t                 b
);

FORCE_INLINE static void
swapPointersConditionally(
    void **p1,
    void **p2,
    uint8_t condition
);

FORCE_INLINE static void
swapPointersConditionally (void **p1, void **p2, uint8_t condition)
{
    // Secure version of this code:
    //
    // if (condition)
    // {
    //     void *temp;
    //     temp = *p2;
    //     *p2 = *p1;
    //     *p1 = temp;
    // }

    uintptr_t val1 = (uintptr_t) *p1;
    uintptr_t val2 = (uintptr_t) *p2;
    uintptr_t temp = val2 ^ val1;

    val1 ^= condition * temp;
    val2 ^= condition * temp;
    *p1 = (void *) val1;
    *p2 = (void *) val2;
}


FORCE_INLINE static uint8_t
isNegative(
    signed char b
)
{
    // use a sequence that is constant time and not optimized away by the compiler.
    volatile uint16_t x = b;
    x >>= 15; /* 1: yes; 0: no */
    return (uint8_t) x;
};

void shiftLeftOne(UN_256bitValue* val);
void shiftRightOne(UN_256bitValue* val);
uint32_t isEqual_256bitvalue(const UN_256bitValue* x, const UN_256bitValue* y);
int greaterThan(const UN_256bitValue* x, const UN_256bitValue* y);


#endif // NUM_TYPES_HEADER_
